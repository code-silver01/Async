#!/usr/bin/env python3
"""
Turns a packet-level log (ts, seq, verdict, reason) into sliding-window
channel features + NORMAL/ATTACK label, for training the command-center
anomaly/classifier model.

Works on the synthetic log now; point LOG_CSV at your real channel_log.csv
once Flask is running - nothing else in this script changes.
"""
import numpy as np
import pandas as pd

LOG_CSV = "../data/channel_log_synthetic.csv"
OUT_CSV = "../data/channel_features_synthetic.csv"
WINDOW_S, STRIDE_S = 5, 1
SEG = 20 * 60
# segment boundaries from gen_synth.py: normal/replay/normal/tamper/normal/flood/normal/jammed/normal
ATTACK_WINDOWS = [(SEG, 2*SEG), (3*SEG, 4*SEG), (5*SEG, 6*SEG), (7*SEG, 8*SEG)]

def build_features(log_csv, attack_windows, window_s=WINDOW_S, stride_s=STRIDE_S):
    df = pd.read_csv(log_csv).sort_values("ts").reset_index(drop=True)
    t0, t1 = df.ts.min(), df.ts.max()
    rows, t = [], t0
    while t + window_s <= t1:
        w = df[(df.ts >= t) & (df.ts < t + window_s)]
        if len(w):
            inter = w.ts.diff().dropna()
            rows.append({
                "t": t,
                "n_packets": len(w),
                "mean_inter_arrival": inter.mean() if len(inter) else window_s,
                "jitter": inter.std() if len(inter) > 1 else 0.0,
                "max_gap": inter.max() if len(inter) else window_s,
                "rejection_rate": (w.verdict != "ACCEPTED").mean(),
                "replay_rate": (w.verdict == "REPLAY").mean(),
                "duplicate_rate": w.seq.duplicated().mean(),
                "seq_gaps": w.seq.diff().fillna(1).gt(1).sum(),
                "label": "ATTACK" if any(a <= t <= b for a, b in attack_windows) else "NORMAL",
            })
        t += stride_s
    return pd.DataFrame(rows)

feat = build_features(LOG_CSV, ATTACK_WINDOWS)
feat.to_csv(OUT_CSV, index=False)
print(f"{len(feat)} windows -> {OUT_CSV}")
print(feat.label.value_counts())
print(feat.groupby("label")[["n_packets","mean_inter_arrival","jitter","rejection_rate","replay_rate","duplicate_rate","seq_gaps"]].mean())
