#!/usr/bin/env python3
"""
Q-SHIELD dataset builder v2 — real HIFD data, 3-class labels (NORMAL / STRAIN / CRITICAL)

Label logic (data-driven, two-pass over the whole real dataset):
  1. accel_mag = sqrt(ax^2+ay^2+az^2)   (already gravity-removed per HIFD README)
  2. motion_intensity = rolling std of accel_mag over a 0.5s window
  3. Global P50 / P90 of motion_intensity computed across ALL files first
  4. Per sample:
       - inside a fall file, within +-window of the accel-magnitude peak -> CRITICAL
       - else if motion_intensity > P90                                  -> STRAIN
       - else if motion_intensity > P50                                  -> STRAIN
       - else                                                            -> NORMAL
  Heart (raw PPG counts, not calibrated BPM) is kept as a feature column
  but NOT used to set the label — the sensor's units in this dataset
  aren't reliable enough for that without proper HR extraction.

Temperature (DS18B20) is SYNTHETIC, thermal-lag (Ornstein-Uhlenbeck) model:
  target ~26C first ~2s (ambient/not-yet-worn), then drifts to
  28C (NORMAL), 29.5C (STRAIN), or gets a transient +1.5-2C bump
  capped at 31C during a CRITICAL window.

KNOWN LIMITATION: HIFD's "non-fall" folder mixes true ADLs and "near-fall"
recoveries with no separate label — a stumble that a subject recovered
from may get flagged STRAIN (high motion) but can't be told apart from a
generic vigorous ADL. Flag this if asked.
"""
import glob, os, re, sys
import numpy as np
import pandas as pd
from scipy.io import loadmat

FS_HZ = 50.0
ROOM_C, NORM_C, STRAIN_C, MAX_C = 26.0, 28.0, 29.5, 31.0
IMPACT_WINDOW_S = 2.0   # +- around the peak, inside a fall file

def load_one(path):
    m = loadmat(path)
    t = np.asarray(m["time"])                       # [yr,mon,day,hr,min,sec.ms]
    secs = t[:, 3] * 3600 + t[:, 4] * 60 + t[:, 5]
    secs = secs - secs[0]
    n = len(secs)
    df = pd.DataFrame({
        "time_s": secs,
        "ax": np.asarray(m["ax"]).squeeze(), "ay": np.asarray(m["ay"]).squeeze(), "az": np.asarray(m["az"]).squeeze(),
        "gyro_w": np.asarray(m["w"]).squeeze(), "gyro_x": np.asarray(m["x"]).squeeze(),
        "gyro_y": np.asarray(m["y"]).squeeze(), "gyro_z": np.asarray(m["z"]).squeeze(),
        "droll": np.asarray(m["droll"]).squeeze(), "dpitch": np.asarray(m["dpitch"]).squeeze(), "dyaw": np.asarray(m["dyaw"]).squeeze(),
        "heart_raw": np.asarray(m["heart"]).squeeze(),
    })
    return df

def ou(n, dt, target, x0, theta=0.15, sigma=0.03, rng=None):
    rng = rng or np.random.default_rng()
    x = np.empty(n); x[0] = x0
    for i in range(1, n):
        x[i] = x[i-1] + theta*(target - x[i-1])*dt + sigma*np.sqrt(dt)*rng.standard_normal()
    return x

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "../data/hifd"
    files = sorted(glob.glob(os.path.join(root, "subject_*", "*", "*.mat")))
    print(f"found {len(files)} files")

    raw = []
    for fp in files:
        parts = fp.split(os.sep)
        subject, fold, scenario = parts[-3], parts[-2], os.path.splitext(parts[-1])[0]
        df = load_one(fp)
        df["accel_mag"] = np.sqrt(df.ax**2 + df.ay**2 + df.az**2)
        w = max(3, int(0.5 * FS_HZ))
        df["motion_intensity"] = df["accel_mag"].rolling(w, center=True, min_periods=1).std().fillna(0)
        df["subject"], df["fold"], df["scenario"] = subject, fold, scenario
        raw.append(df)

    full = pd.concat(raw, ignore_index=True)
    p50, p90 = full["motion_intensity"].quantile([0.5, 0.9])
    print(f"global motion_intensity P50={p50:.4f}  P90={p90:.4f}")

    rng = np.random.default_rng(42)
    out = []
    for df in raw:
        df = df.copy()
        n = len(df)
        is_fall = (df["fold"].iloc[0] == "fall")
        label = np.where(df["motion_intensity"] > p90, "STRAIN",
                 np.where(df["motion_intensity"] > p50, "STRAIN", "NORMAL"))
        if is_fall:
            peak_idx = int(df["accel_mag"].idxmax())
            t_peak = df["time_s"].iloc[peak_idx]
            win = (df["time_s"] >= t_peak - IMPACT_WINDOW_S/4) & (df["time_s"] <= t_peak + IMPACT_WINDOW_S)
            label = np.where(win.to_numpy(), "CRITICAL", label)
        df["label"] = label

        dt = 1.0 / FS_HZ
        warm = min(n, max(1, int(2*FS_HZ)))
        temp = np.empty(n)
        temp[:warm] = ou(warm, dt, NORM_C, ROOM_C, theta=0.6, rng=rng)
        cur = temp[warm-1] if warm > 0 else ROOM_C
        for lbl_target, mask_start in [(None, warm)]:
            pass
        i = warm
        while i < n:
            seg_label = df["label"].iloc[i]
            target = STRAIN_C if seg_label == "STRAIN" else NORM_C
            j = i
            while j < n and df["label"].iloc[j] == seg_label:
                j += 1
            seg = ou(j - i, dt, target, cur, rng=rng)
            temp[i:j] = seg
            cur = seg[-1]
            i = j
        if is_fall:
            crit = (df["label"] == "CRITICAL").to_numpy()
            if crit.any():
                idxs = np.where(crit)[0]
                bump = 1.6 + 0.3*rng.random()
                center = idxs[np.argmax(df["accel_mag"].to_numpy()[idxs])]
                width = int(1.5*FS_HZ)
                for k in range(max(0, center-width//4), min(n, center+width)):
                    decay = np.exp(-(k-center)/(width/3)) if k >= center else (k-max(0,center-width//4))/max(1,width//4)
                    temp[k] += bump * max(0.0, decay)
        df["temp_c"] = np.clip(temp, ROOM_C - 0.5, MAX_C)
        out.append(df)

    final = pd.concat(out, ignore_index=True)
    cols = ["subject","fold","scenario","time_s","ax","ay","az","gyro_w","gyro_x","gyro_y","gyro_z",
            "droll","dpitch","dyaw","heart_raw","accel_mag","motion_intensity","temp_c","label"]
    final = final[cols]
    final.to_csv("../data/qshield_3class_dataset.csv", index=False)
    print(f"\nwrote {len(final)} rows")
    print(final["label"].value_counts())
    print(final.groupby("label")["temp_c"].agg(["min","max","mean"]))

if __name__ == "__main__":
    main()
