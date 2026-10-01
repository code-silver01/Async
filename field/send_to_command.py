#!/usr/bin/env python3
"""
Q-SHIELD field gateway v2 - reads GPS + MPU6050 + MAX30100 (raw) + DS18B20,
runs the trained NORMAL/STRAIN/CRITICAL classifier, and POSTs a packet in
the EXACT schema the deployed command center (code-silver01/Async) expects.

Run:
    python3 send_to_command.py --server https://async-2cuj.onrender.com --model qshield_status_classifier.pkl
    python3 send_to_command.py --sim --server http://localhost:5000 --model qshield_status_classifier.pkl   (no hardware)

Deps:
    pip install requests joblib numpy smbus2 pyserial
"""
import argparse, glob, hashlib, hmac, json, math, random, statistics, time
from collections import deque
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import requests

SESSION_KEY = "qshield-demo-session-key"   # matches app.py's placeholder key
UNIT_ID = "UNIT_01"
FEATURES = ["ax","ay","az","gyro_w","gyro_x","gyro_y","gyro_z",
            "droll","dpitch","dyaw","heart_raw","accel_mag","motion_intensity","temp_c"]


# ---------------------------------------------------------------- sensors
class GPS:
    def __init__(self, port="/dev/serial0", sim=False, fallback=None):
        self.sim, self.fallback, self.ser = sim, fallback, None
        self.last = {"fix": False, "lat": None, "lon": None, "sats": 0, "src": "NONE"}
        if not sim:
            try:
                import serial
                self.ser = serial.Serial(port, 9600, timeout=0.5)
            except Exception as e:
                print(f"[GPS] init failed: {e}")

    @staticmethod
    def _deg(v, hemi):
        d = int(float(v) // 100)
        r = d + (float(v) - d * 100) / 60
        return -r if hemi in ("S", "W") else r

    def read(self):
        if self.sim:
            return {"fix": True, "lat": round(33.7548 + random.uniform(-1e-4, 1e-4), 6),
                    "lon": round(78.6834 + random.uniform(-1e-4, 1e-4), 6), "sats": 9, "src": "SIM"}
        if self.ser:
            end = time.time() + 1.5
            while time.time() < end:
                ln = self.ser.readline().decode("ascii", "ignore").strip()
                if ln.startswith(("$GPGGA", "$GNGGA")):
                    p = ln.split(",")
                    if len(p) > 7 and p[6] not in ("", "0") and p[2] and p[4]:
                        self.last = {"fix": True, "lat": round(self._deg(p[2], p[3]), 6),
                                     "lon": round(self._deg(p[4], p[5]), 6),
                                     "sats": int(p[7] or 0), "src": "GPS"}
                    else:
                        self.last = {**self.last, "fix": False, "sats": int(p[7] or 0) if len(p) > 7 else 0}
                    break
        if not self.last["fix"] and self.fallback:
            return {"fix": False, "lat": self.fallback[0], "lon": self.fallback[1],
                    "sats": self.last["sats"], "src": "MANUAL"}
        return self.last


class IMU:
    """MPU6050 - returns one instantaneous sample, not a windowed summary."""
    def __init__(self, bus=1, addr=0x68, sim=False):
        self.sim, self.bus, self.addr = sim, None, addr
        if not sim:
            try:
                from smbus2 import SMBus
                self.bus = SMBus(bus)
                self.bus.write_byte_data(addr, 0x6B, 0)
            except Exception as e:
                print(f"[IMU] init failed: {e}")

    def _w(self, reg):
        h, l = self.bus.read_i2c_block_data(self.addr, reg, 2)
        v = (h << 8) | l
        return v - 65536 if v > 32767 else v

    def read(self):
        if self.sim:
            return dict(ax=random.uniform(-0.05, 0.05), ay=random.uniform(-0.05, 0.05), az=1 + random.uniform(-0.05, 0.05),
                        gyro_w=random.uniform(-1, 1), gyro_x=random.uniform(-1, 1), gyro_y=random.uniform(-1, 1), gyro_z=random.uniform(-1, 1),
                        droll=random.uniform(-1, 1), dpitch=random.uniform(-1, 1), dyaw=random.uniform(-1, 1))
        if not self.bus:
            return dict.fromkeys(["ax","ay","az","gyro_w","gyro_x","gyro_y","gyro_z","droll","dpitch","dyaw"], 0.0)
        ax, ay, az = (self._w(r) / 16384.0 for r in (0x3B, 0x3D, 0x3F))
        gx, gy, gz = (self._w(r) / 131.0 for r in (0x43, 0x45, 0x47))   # deg/s, stand-in for droll/dpitch/dyaw
        return dict(ax=ax, ay=ay, az=az, gyro_w=0.0, gyro_x=gx, gyro_y=gy, gyro_z=gz,
                    droll=gx, dpitch=gy, dyaw=gz)


class Pulse:
    """MAX30100/30102 - returns RAW IR count, matching heart_raw in training data, NOT bpm."""
    def __init__(self, bus=1, addr=0x57, sim=False):
        self.sim, self.addr, self.bus = sim, addr, None
        if not sim:
            try:
                from smbus2 import SMBus
                self.bus = SMBus(bus)
            except Exception as e:
                print(f"[PULSE] init failed: {e}")

    def read(self):
        if self.sim:
            return random.randint(900, 1100)
        if not self.bus:
            return 0
        try:
            d = self.bus.read_i2c_block_data(self.addr, 0x07, 6)
            return ((d[3] << 16) | (d[4] << 8) | d[5]) & 0x3FFFF
        except Exception:
            return 0


class TempDS18B20:
    """Reads the kernel w1 driver file, e.g. /sys/bus/w1/devices/28-xxxx/w1_slave."""
    def __init__(self, sim=False):
        self.sim, self.path = sim, None
        if not sim:
            paths = glob.glob("/sys/bus/w1/devices/28-*/w1_slave")
            if paths:
                self.path = paths[0]
            else:
                print("[TEMP] no DS18B20 found under /sys/bus/w1/devices/28-*")

    def read(self):
        if self.sim:
            return round(28 + random.uniform(-0.5, 1.5), 2)
        if not self.path:
            return 26.0
        try:
            with open(self.path) as f:
                lines = f.readlines()
            if lines[0].strip()[-3:] != "YES":
                return None
            return float(lines[1].split("t=")[-1]) / 1000.0
        except Exception:
            return None


# ---------------------------------------------------------------- classifier glue
class MotionWindow:
    """Rolling 0.5s buffer of accel magnitude, for motion_intensity = std(window)."""
    def __init__(self, hz=20):
        self.buf = deque(maxlen=max(3, int(0.5 * hz)))

    def push_get(self, ax, ay, az):
        mag = math.sqrt(ax**2 + ay**2 + az**2)
        self.buf.append(mag)
        intensity = statistics.pstdev(self.buf) if len(self.buf) > 1 else 0.0
        return mag, intensity


LABEL_TO_STATUS = {
    "NORMAL":   ("ACTIVE", "ROUTINE"),
    "STRAIN":   ("DISTRESS", "HIGH"),
    "CRITICAL": ("INJURED_SUSPECTED", "CRITICAL"),
}


def classify(clf, imu, heart_raw, accel_mag, motion_intensity, temp_c):
    row = [[imu["ax"], imu["ay"], imu["az"], imu["gyro_w"], imu["gyro_x"], imu["gyro_y"], imu["gyro_z"],
            imu["droll"], imu["dpitch"], imu["dyaw"], heart_raw, accel_mag, motion_intensity,
            temp_c if temp_c is not None else 26.0]]
    label = clf.predict(pd.DataFrame(row, columns=FEATURES))[0]
    return LABEL_TO_STATUS.get(label, ("ACTIVE", "ROUTINE")), label


# ---------------------------------------------------------------- packet + send
def sign(packet: dict) -> str:
    body = {k: v for k, v in packet.items() if k != "sig"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hmac.new(SESSION_KEY.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def build_packet(seq, gps, status, priority, bpm_display, motion_state, accel_g, peak_g):
    pkt = {
        "unit_id": UNIT_ID,
        "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "location": gps,
        "motion": {"state": motion_state, "accel_g": round(accel_g, 2), "peak_g": round(peak_g, 2)},
        "vitals": {"finger": True, "bpm": bpm_display},
        "status": status,
        "priority": priority,
        "security": {"mode": "HMAC-SHA256", "note": "ML-KEM planned - using pre-shared demo key"},
        "digest": "",
    }
    pkt["sig"] = sign(pkt)
    pkt["digest"] = hashlib.sha256(json.dumps(pkt, sort_keys=True).encode()).hexdigest()[:16]
    return pkt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="e.g. https://async-2cuj.onrender.com")
    ap.add_argument("--model", default="../models/qshield_status_classifier.pkl", help="path to qshield_status_classifier.pkl")
    ap.add_argument("--sim", action="store_true")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--fallback-loc", default=None, help="lat,lon when GPS has no fix (indoors)")
    args = ap.parse_args()

    clf = joblib.load(args.model)
    fb = tuple(float(x) for x in args.fallback_loc.split(",")) if args.fallback_loc else None
    gps, imu, pulse, temp = GPS(sim=args.sim, fallback=fb), IMU(sim=args.sim), Pulse(sim=args.sim), TempDS18B20(sim=args.sim)
    window = MotionWindow()

    print(f"model loaded, posting to {args.server}/api/packet  (sim={args.sim})")
    seq = 0
    while True:
        seq += 1
        g = gps.read()
        m = imu.read()
        heart_raw = pulse.read()
        temp_c = temp.read()
        accel_mag, motion_intensity = window.push_get(m["ax"], m["ay"], m["az"])

        (status, priority), label = classify(clf, m, heart_raw, accel_mag, motion_intensity, temp_c)
        motion_state = "IMPACT" if label == "CRITICAL" else ("MOVING" if motion_intensity > 0.08 else "STILL")
        bpm_display = max(40, min(180, int(60 + (heart_raw % 40))))  # heart_raw is a raw ADC count, not bpm - display placeholder only

        pkt = build_packet(seq, g, status, priority, bpm_display, motion_state, accel_mag, max(accel_mag, 1.0))

        try:
            r = requests.post(f"{args.server}/api/packet", json=pkt, timeout=5)
            print(f"#{seq:04d} label={label:9s} status={status:18s} prio={priority:8s} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"#{seq:04d} send failed: {e}")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
