"""
Q-SHIELD COMMAND CENTER — Flask backend
Security layer (HMAC-SHA256), channel monitor (IsolationForest),
jamming simulation, LoRa failover, and attack console.
"""

import hashlib
import hmac
import json
import random
import threading
import time
from collections import deque
from datetime import datetime, timezone

import numpy as np
from flask import Flask, jsonify, render_template, request

try:
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("[WARN] scikit-learn not installed — channel monitor disabled")

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
# replace with ML-KEM-derived key + AES-256-GCM
SESSION_KEY = "qshield-demo-session-key"

MAX_PACKETS        = 200
MAX_EVENTS         = 200
CALIBRATION_NEED   = 25   # accepted packets before IsolationForest fits
MONITOR_INTERVAL   = 5    # seconds per monitor window
FAILOVER_DELAY     = 4    # seconds of ATTACKED before switching to LoRa
REVERT_CLEAN_WINS  = 2    # consecutive clean windows (=10 s) to revert to PRIMARY
FLOOD_THRESHOLD    = 10   # packets in 2 s to count as flood
FLOOD_WINDOW       = 2.0  # seconds

# ══════════════════════════════════════════════════════════════════════════════
# SHARED STATE (protected by _lock)
# ══════════════════════════════════════════════════════════════════════════════
_lock = threading.RLock()

# Packet store
_packets: list[dict] = []

# Event log
_events: list[dict] = []
_last_status: dict[str, str] = {}

# Security counters
_stats = {
    "accepted": 0,
    "rejected": 0,
    "replays": 0,
    "invalid_sigs": 0,
    "seq_gaps": 0,
    "floods": 0,
    "channel_drops": 0,
}
_last_seq: dict[str, int] = {}        # unit_id -> last accepted seq
_last_seq_ts: dict[str, str] = {}     # unit_id -> ISO timestamp of last accepted
_latest_verified = False               # was the latest stored packet verified?

# Channel / jamming
_jamming_active = False
_active_channel = "PRIMARY"            # PRIMARY | LORA
_channel_state  = "CALIBRATING"        # CALIBRATING | SECURE | SUSPICIOUS | ATTACKED
_attacked_since: float | None = None   # monotonic time when ATTACKED started
_lora_routine_ctr = 0

# Shared sequence counter (demo + attack console share this)
_next_seq = 0

# Monitor window accumulators (reset every MONITOR_INTERVAL by monitor thread)
_win_arrival_times: list[float] = []   # monotonic timestamps of all arrivals
_win_accepted_times: list[float] = []  # monotonic timestamps of accepted arrivals
_win_seq_gaps   = 0
_win_rejections = 0
_win_attempts   = 0

# IsolationForest state
_total_accepted    = 0
_cal_features: list[list[float]] = []
_baseline_mean: np.ndarray | None = None
_baseline_std:  np.ndarray | None = None
_iso_forest = None
_cal_scores_mean: float | None = None
_cal_scores_std:  float | None = None
_consecutive_clean = 0

# Flood detection
_recent_arrivals: deque = deque(maxlen=200)
_flood_burst_logged = False

# Demo mode
_demo_running = False
_demo_thread: threading.Thread | None = None


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mono() -> float:
    return time.monotonic()


def _get_next_seq() -> int:
    global _next_seq
    _next_seq += 1
    return _next_seq


def _compute_digest(pkt: dict) -> str:
    """SHA-256 digest of packet (for display)."""
    raw = {k: v for k, v in pkt.items() if k not in ("sig", "digest", "server_rx", "anomaly_score", "verified")}
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _compute_sig(pkt: dict) -> str:
    """HMAC-SHA256 signature.  replace with ML-KEM-derived key + AES-256-GCM"""
    payload = {k: v for k, v in pkt.items() if k != "sig"}
    canonical = json.dumps(payload, sort_keys=True)
    return hmac.new(
        SESSION_KEY.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()


def _verify_sig(pkt: dict) -> bool:
    """Verify HMAC-SHA256 signature.  PQC verify here"""
    sig = pkt.get("sig", "")
    if not sig:
        return False
    expected = _compute_sig(pkt)
    return hmac.compare_digest(sig, expected)


def _add_event(level: str, msg: str, unit_id: str = "SYSTEM"):
    _events.append({
        "ts": _now_utc(),
        "level": level,
        "msg": msg,
        "unit_id": unit_id,
    })
    if len(_events) > MAX_EVENTS:
        _events[:] = _events[-MAX_EVENTS:]


# ══════════════════════════════════════════════════════════════════════════════
# CHANNEL IMPAIRMENT
# ══════════════════════════════════════════════════════════════════════════════
def _apply_channel(pkt: dict) -> tuple[bool, float]:
    """
    Returns (deliver, delay_sec).
    deliver=False means packet is dropped by channel impairment.
    """
    global _lora_routine_ctr

    if _active_channel == "LORA":
        # LoRa backup: 400 ms fixed latency
        if pkt.get("priority", "ROUTINE") == "ROUTINE":
            _lora_routine_ctr += 1
            if _lora_routine_ctr % 3 != 0:
                return False, 0        # ROUTINE down-sampled 1-in-3
        return True, 0.4

    # PRIMARY channel
    if _jamming_active:
        if random.random() < 0.5:
            return False, 0            # 50 % drop
        return True, random.uniform(0.5, 2.0)

    return True, 0                     # clean PRIMARY


# ══════════════════════════════════════════════════════════════════════════════
# PACKET INGESTION PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def _ingest(pkt: dict, *, apply_channel: bool = True) -> dict:
    """
    Full pipeline: channel impairment → sig verify → seq check → store.
    Returns a result dict: {ok, reason, code}.
    """
    global _latest_verified, _total_accepted
    global _win_seq_gaps, _win_rejections, _win_attempts
    global _flood_burst_logged

    uid = pkt.get("unit_id", "UNKNOWN")

    with _lock:
        # ── 0. Channel impairment ────────────────────────────────────────
        if apply_channel:
            deliver, delay = _apply_channel(pkt)
            if not deliver:
                _stats["channel_drops"] += 1
                return {"ok": False, "reason": "channel_drop", "code": 200}
        else:
            delay = 0

    # Apply delay outside lock so we don't block everything
    if delay > 0:
        time.sleep(delay)

    with _lock:
        now = _mono()

        # Record arrival for monitor
        _win_arrival_times.append(now)
        _win_attempts += 1
        _recent_arrivals.append(now)

        # ── Flood detection ──────────────────────────────────────────────
        cutoff = now - FLOOD_WINDOW
        recent_count = sum(1 for t in _recent_arrivals if t > cutoff)
        if recent_count > FLOOD_THRESHOLD:
            if not _flood_burst_logged:
                _stats["floods"] += 1
                _add_event("CRITICAL",
                           f"Flood detected: {recent_count} packets in {FLOOD_WINDOW}s window",
                           uid)
                _flood_burst_logged = True
        else:
            _flood_burst_logged = False

        # ── 1. Signature verification ────────────────────────────────────
        if not _verify_sig(pkt):
            _stats["rejected"] += 1
            _stats["invalid_sigs"] += 1
            _win_rejections += 1
            _add_event("CRITICAL",
                       f"INVALID_SIGNATURE: packet seq #{pkt.get('seq','?')} "
                       f"failed HMAC-SHA256 — forged or corrupted, packet dropped",
                       uid)
            _latest_verified = False
            return {"ok": False, "reason": "INVALID_SIGNATURE", "code": 400}

        # ── 2. Sequence check ────────────────────────────────────────────
        seq = pkt.get("seq", 0)
        last = _last_seq.get(uid, 0)
        last_ts = _last_seq_ts.get(uid, "never")

        if seq <= last:
            _stats["rejected"] += 1
            _stats["replays"] += 1
            _win_rejections += 1
            _add_event("WARNING",
                       f"REPLAY: seq #{seq} already accepted at "
                       f"{last_ts} — packet dropped",
                       uid)
            _latest_verified = False
            return {"ok": False, "reason": "REPLAY", "code": 400}

        # Accepted — check for gap
        gap = seq - last - 1
        if gap > 0 and last > 0:
            _stats["seq_gaps"] += gap
            _win_seq_gaps += gap
            _add_event("INFO",
                       f"Sequence gap: expected #{last+1}, got #{seq} "
                       f"({gap} packet{'s' if gap > 1 else ''} missing)",
                       uid)

        # ── 3. Accept & store ────────────────────────────────────────────
        _stats["accepted"] += 1
        _total_accepted += 1
        _last_seq[uid] = seq
        _last_seq_ts[uid] = _now_utc()
        _win_accepted_times.append(now)

        pkt["server_rx"] = _now_utc()
        pkt["verified"] = True
        pkt["anomaly_score"] = None   # ML anomaly score here

        # Digest for display
        if not pkt.get("digest"):
            pkt["digest"] = _compute_digest(pkt)

        # Generate status-change events
        _generate_status_events(pkt)

        _packets.append(pkt)
        if len(_packets) > MAX_PACKETS:
            _packets[:] = _packets[-MAX_PACKETS:]

        _latest_verified = True

        return {"ok": True, "reason": "accepted", "code": 201, "seq": seq}


def _generate_status_events(pkt: dict):
    """Create human-readable event-log entries from accepted packets."""
    uid = pkt.get("unit_id", "UNKNOWN")
    status = pkt.get("status", "ACTIVE")
    priority = pkt.get("priority", "ROUTINE")
    motion = pkt.get("motion", {})
    vitals = pkt.get("vitals", {})

    # Status change
    prev = _last_status.get(uid)
    if prev and prev != status:
        reason = ""
        if status == "INJURED_SUSPECTED" and motion.get("peak_g", 0) > 2.5:
            reason = (f": impact {motion['peak_g']:.1f}g detected by IMU, "
                      f"packet marked {priority}")
        elif status == "DISTRESS":
            reason = f": elevated stress indicators, priority {priority}"
        elif status == "ACTIVE" and prev != "ACTIVE":
            reason = ": operator returned to normal parameters"
        lvl = ("CRITICAL" if status == "INJURED_SUSPECTED"
               else "WARNING" if status == "DISTRESS" else "INFO")
        _add_event(lvl, f"Status changed {prev} → {status}{reason}", uid)
    _last_status[uid] = status

    # Impact
    if motion.get("state") == "IMPACT":
        _add_event("WARNING",
                   f"Impact event: peak {motion.get('peak_g',0):.1f}g, "
                   f"accel {motion.get('accel_g',0):.2f}g", uid)

    # Vitals
    if vitals.get("finger") and vitals.get("bpm", 80) > 140:
        _add_event("WARNING", f"Elevated heart rate: {vitals['bpm']} BPM", uid)
    elif vitals.get("finger") and vitals.get("bpm", 80) < 45:
        _add_event("CRITICAL", f"Abnormally low heart rate: {vitals['bpm']} BPM", uid)


# ══════════════════════════════════════════════════════════════════════════════
# CHANNEL MONITOR (IsolationForest)
# ══════════════════════════════════════════════════════════════════════════════
def _compute_window_features() -> list[float]:
    """Compute 4-feature vector from current monitor window."""
    times = list(_win_arrival_times)
    accepted = list(_win_accepted_times)
    attempts = max(_win_attempts, 1)

    # 1. Packet rate (packets/sec)
    packet_rate = len(times) / MONITOR_INTERVAL if times else 0.0

    # 2. Mean inter-arrival
    if len(times) >= 2:
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        mean_ia = float(np.mean(intervals))
    else:
        mean_ia = MONITOR_INTERVAL  # no data → assume full window gap

    # 3. Jitter (std dev of inter-arrival)
    if len(times) >= 3:
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        jitter = float(np.std(intervals))
    else:
        jitter = 0.0

    # 4. Rejection rate
    rejection_rate = _win_rejections / attempts

    return [packet_rate, mean_ia, jitter, rejection_rate]


def _reset_window():
    global _win_arrival_times, _win_accepted_times
    global _win_seq_gaps, _win_rejections, _win_attempts
    _win_arrival_times = []
    _win_accepted_times = []
    _win_seq_gaps = 0
    _win_rejections = 0
    _win_attempts = 0


def _channel_monitor_loop():
    """Background thread: every 5 s, score the window with IsolationForest."""
    global _channel_state, _attacked_since, _consecutive_clean
    global _active_channel, _iso_forest
    global _baseline_mean, _baseline_std
    global _cal_scores_mean, _cal_scores_std

    while True:
        time.sleep(MONITOR_INTERVAL)

        with _lock:
            features = _compute_window_features()
            _reset_window()
            accepted_so_far = _total_accepted

        # ── Calibrating ──────────────────────────────────────────────────
        if accepted_so_far < CALIBRATION_NEED:
            with _lock:
                _channel_state = "CALIBRATING"
            if any(f != 0 for f in features):
                _cal_features.append(features)
            continue

        # ── Fit model (once) ─────────────────────────────────────────────
        if _iso_forest is None and HAS_SKLEARN and len(_cal_features) >= 3:
            X = np.array(_cal_features)
            _baseline_mean = X.mean(axis=0)
            _baseline_std  = X.std(axis=0) + 1e-6

            _iso_forest = IsolationForest(
                contamination=0.05, random_state=42, n_estimators=100
            )
            _iso_forest.fit(X)

            cal_scores = _iso_forest.score_samples(X)
            _cal_scores_mean = float(cal_scores.mean())
            _cal_scores_std  = float(cal_scores.std()) + 1e-6

            with _lock:
                _channel_state = "SECURE"
                _add_event("INFO", "Channel monitor: baseline calibrated, "
                           f"model fitted on {len(_cal_features)} windows")
            continue

        if _iso_forest is None:
            # sklearn not available or not enough data
            with _lock:
                _channel_state = "SECURE"
            continue

        # ── Score new window ─────────────────────────────────────────────
        X_new = np.array([features])
        score = float(_iso_forest.score_samples(X_new)[0])
        z = (score - _cal_scores_mean) / _cal_scores_std

        if z < -3.0:
            new_state = "ATTACKED"
        elif z < -1.5:
            new_state = "SUSPICIOUS"
        else:
            new_state = "SECURE"

        # ── Hysteresis ───────────────────────────────────────────────────
        with _lock:
            old_state = _channel_state

            if old_state == "ATTACKED" and new_state == "SECURE":
                _consecutive_clean += 1
                if _consecutive_clean < 3:
                    new_state = "ATTACKED"  # stay ATTACKED until 3 clean
                else:
                    _consecutive_clean = 0
            elif new_state != "SECURE":
                _consecutive_clean = 0

            # ── State transition ─────────────────────────────────────────
            if new_state != old_state:
                # Build explanation from z-scores of features
                feat_z = (np.array(features) - _baseline_mean) / _baseline_std
                names = ["packet rate", "inter-arrival", "jitter", "rejection rate"]
                max_idx = int(np.argmax(np.abs(feat_z)))
                direction = "above" if feat_z[max_idx] > 0 else "below"
                explanation = (f"{names[max_idx]} {abs(feat_z[max_idx]):.1f}σ "
                               f"{direction} baseline")

                # Context
                if max_idx == 1 and feat_z[max_idx] > 0:
                    explanation += " — consistent with jamming, not signal fade"
                elif max_idx == 0 and feat_z[max_idx] > 1:
                    rej = features[3]
                    explanation += f", {rej:.0%} rejection rate — consistent with flood attack"
                elif max_idx == 3 and feat_z[max_idx] > 1:
                    explanation += " — consistent with replay or signature attacks"

                _add_event(
                    "CRITICAL" if new_state == "ATTACKED"
                    else "WARNING" if new_state == "SUSPICIOUS"
                    else "INFO",
                    f"Channel state: {old_state} → {new_state} — {explanation}",
                )
                _channel_state = new_state

            # ── ATTACKED timing for failover ─────────────────────────────
            if _channel_state == "ATTACKED":
                now = _mono()
                if _attacked_since is None:
                    _attacked_since = now
                elif (now - _attacked_since) >= FAILOVER_DELAY and _active_channel == "PRIMARY":
                    _active_channel = "LORA"
                    _add_event("CRITICAL",
                               "FAILOVER: channel ATTACKED for >"
                               f"{FAILOVER_DELAY}s — switching to LoRa BACKUP")
            else:
                _attacked_since = None

            # ── Revert to PRIMARY after clean windows ────────────────────
            if (_active_channel == "LORA"
                    and not _jamming_active
                    and _channel_state == "SECURE"):
                _consecutive_clean += 1
                if _consecutive_clean >= REVERT_CLEAN_WINS:
                    _active_channel = "PRIMARY"
                    _consecutive_clean = 0
                    _add_event("INFO",
                               "Channel recovered: reverting to PRIMARY — "
                               f"{REVERT_CLEAN_WINS * MONITOR_INTERVAL}s of clean windows")


# Start monitor thread
_monitor_thread = threading.Thread(target=_channel_monitor_loop, daemon=True)
_monitor_thread.start()


# ══════════════════════════════════════════════════════════════════════════════
# DEMO PACKET GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
def _demo_generator():
    global _demo_running

    lat, lon = 33.7548, 78.6834
    bpm_base = 78.0
    status = "ACTIVE"
    priority = "ROUTINE"

    while _demo_running:
        seq = _get_next_seq()
        now_iso = _now_utc()

        # Random walk (Ladakh Border Sector / LAC Forward Post)
        lat += random.gauss(0, 0.0003)
        lon += random.gauss(0, 0.0003)
        lat = max(33.70, min(33.82, lat))
        lon = max(78.60, min(78.75, lon))

        # Motion
        accel = round(abs(random.gauss(1.0, 0.15)), 2)
        peak = round(accel + random.uniform(0, 0.4), 2)
        motion_state = "STILL" if accel < 0.95 else "MOVING"

        # Occasional events (~8 %)
        roll = random.random()
        if roll < 0.03:
            status, priority = "INJURED_SUSPECTED", "CRITICAL"
            peak = round(random.uniform(2.8, 4.5), 2)
            accel = round(peak * 0.6, 2)
            motion_state = "IMPACT"
        elif roll < 0.08:
            status, priority = "DISTRESS", "HIGH"
        else:
            status, priority = "ACTIVE", "ROUTINE"

        # Vitals
        finger = random.random() > 0.08
        bpm_base += random.gauss(0, 2)
        bpm_base = max(55, min(150, bpm_base))
        if status == "INJURED_SUSPECTED":
            bpm_base = random.uniform(110, 155)
        elif status == "DISTRESS":
            bpm_base = random.uniform(95, 130)
        bpm = int(bpm_base) if finger else 0

        pkt = {
            "unit_id": "UNIT_01",
            "seq": seq,
            "ts": now_iso,
            "location": {
                "fix": True,
                "lat": round(lat, 6),
                "lon": round(lon, 6),
                "sats": random.randint(6, 14),
                "src": "SIM",
            },
            "motion": {
                "state": motion_state,
                "accel_g": accel,
                "peak_g": peak,
            },
            "vitals": {"finger": finger, "bpm": bpm},
            "status": status,
            "priority": priority,
            "security": {
                "mode": "HMAC-SHA256",
                "note": "PQC encryption pending integration",
            },
            "digest": "",
        }
        pkt["digest"] = _compute_digest(pkt)
        pkt["sig"] = _compute_sig(pkt)

        # Channel impairment applies to demo packets (they travel the channel)
        _ingest(pkt, apply_channel=True)

        time.sleep(2)


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK CONSOLE (server-side)
# ══════════════════════════════════════════════════════════════════════════════
def _attack_replay():
    """Resend the last accepted packet (same seq → REPLAY rejection)."""
    with _lock:
        if not _packets:
            return {"ok": False, "msg": "No packets to replay"}
        victim = dict(_packets[-1])  # shallow copy

    # Remove server-side fields, keep original sig and seq
    for k in ("server_rx", "verified", "anomaly_score"):
        victim.pop(k, None)

    result = _ingest(victim, apply_channel=False)
    return {"ok": True, "msg": f"Replay attack sent (seq #{victim.get('seq')})",
            "result": result.get("reason")}


def _attack_tamper():
    """Modify the last packet's data but keep old signature → INVALID_SIG."""
    with _lock:
        if not _packets:
            return {"ok": False, "msg": "No packets to tamper"}
        victim = dict(_packets[-1])

    for k in ("server_rx", "verified", "anomaly_score"):
        victim.pop(k, None)

    # Tamper: change status and bump seq so it's not also a replay
    victim["seq"] = _get_next_seq()
    victim["status"] = "INJURED_SUSPECTED"
    victim["priority"] = "CRITICAL"
    # Keep old sig → mismatch
    victim["digest"] = _compute_digest(victim)

    result = _ingest(victim, apply_channel=False)
    return {"ok": True, "msg": "Tamper attack sent (modified status, stale sig)",
            "result": result.get("reason")}


def _attack_flood():
    """Send 20 packets in rapid succession: mix of replays, tampered, valid."""
    results = {"sent": 0, "accepted": 0, "replay": 0, "invalid_sig": 0}

    with _lock:
        template = dict(_packets[-1]) if _packets else None

    if not template:
        return {"ok": False, "msg": "No packets to base flood on"}

    for k in ("server_rx", "verified", "anomaly_score"):
        template.pop(k, None)

    for i in range(20):
        pkt = dict(template)
        results["sent"] += 1

        if i < 8:
            # Replays: same seq
            pass  # keep original seq
        elif i < 14:
            # Tampered: new seq, old sig
            pkt["seq"] = _get_next_seq()
            pkt["status"] = "DISTRESS"
            pkt["digest"] = _compute_digest(pkt)
        else:
            # Valid: new seq, new sig
            pkt["seq"] = _get_next_seq()
            pkt["digest"] = _compute_digest(pkt)
            pkt["sig"] = _compute_sig(pkt)

        r = _ingest(pkt, apply_channel=False)
        if r.get("reason") == "accepted":
            results["accepted"] += 1
        elif r.get("reason") == "REPLAY":
            results["replay"] += 1
        elif r.get("reason") == "INVALID_SIGNATURE":
            results["invalid_sig"] += 1

        time.sleep(0.05)  # small gap so timestamps differ

    with _lock:
        _add_event("CRITICAL",
                   f"Flood attack completed: {results['sent']} packets, "
                   f"{results['accepted']} accepted, "
                   f"{results['replay']} replays, "
                   f"{results['invalid_sig']} invalid sigs")

    return {"ok": True, "msg": "Flood attack completed", "results": results}


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/packet")
def receive_packet():
    pkt = request.get_json(force=True)
    result = _ingest(pkt, apply_channel=True)
    code = result.get("code", 200)
    return jsonify(result), code


@app.get("/api/packets")
def get_packets():
    with _lock:
        return jsonify(list(_packets))


@app.get("/api/latest")
def get_latest():
    with _lock:
        if _packets:
            return jsonify(_packets[-1])
        return jsonify(None), 204


@app.get("/api/events")
def get_events():
    with _lock:
        return jsonify(list(_events))


@app.get("/api/security")
def get_security():
    with _lock:
        return jsonify({
            "stats": dict(_stats),
            "channel": _active_channel,
            "channel_state": _channel_state,
            "jamming": _jamming_active,
            "verified": _latest_verified,
            "calibration": {
                "current": min(_total_accepted, CALIBRATION_NEED),
                "target": CALIBRATION_NEED,
                "done": _total_accepted >= CALIBRATION_NEED,
            },
        })


# ── Demo ─────────────────────────────────────────────────────────────────────
@app.post("/api/demo/start")
def demo_start():
    global _demo_running, _demo_thread
    with _lock:
        if _demo_running:
            return jsonify({"ok": True, "msg": "already running"})
        _demo_running = True
        _demo_thread = threading.Thread(target=_demo_generator, daemon=True)
        _demo_thread.start()
    return jsonify({"ok": True, "msg": "demo started"})


@app.post("/api/demo/stop")
def demo_stop():
    global _demo_running
    _demo_running = False
    return jsonify({"ok": True, "msg": "demo stopped"})


@app.get("/api/demo/status")
def demo_status():
    return jsonify({"running": _demo_running})


# ── Jamming ──────────────────────────────────────────────────────────────────
@app.post("/api/jamming/start")
def jamming_start():
    global _jamming_active
    with _lock:
        if _jamming_active:
            return jsonify({"ok": True, "msg": "already active"})
        _jamming_active = True
        _add_event("WARNING",
                   "Simulated channel impairment ACTIVE: "
                   "50% packet drop, 0.5–2s delay on PRIMARY")
    return jsonify({"ok": True, "msg": "jamming simulation started"})


@app.post("/api/jamming/stop")
def jamming_stop():
    global _jamming_active
    with _lock:
        _jamming_active = False
        _add_event("INFO",
                   "Simulated channel impairment CLEARED — "
                   "monitoring for recovery")
    return jsonify({"ok": True, "msg": "jamming simulation stopped"})


# ── Attack console ───────────────────────────────────────────────────────────
@app.post("/api/attack/replay")
def attack_replay():
    result = _attack_replay()
    return jsonify(result)


@app.post("/api/attack/tamper")
def attack_tamper():
    result = _attack_tamper()
    return jsonify(result)


@app.post("/api/attack/flood")
def attack_flood():
    result = _attack_flood()
    return jsonify(result)


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
