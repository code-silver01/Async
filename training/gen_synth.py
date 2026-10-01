#!/usr/bin/env python3
"""
Q-SHIELD command-center channel dataset — SYNTHETIC (no Pi/Flask running yet)

Simulates a packet log (ts, seq, verdict, reason) across 5 back-to-back
20-minute segments:
  NORMAL   - steady ~1s inter-arrival, small jitter, all ACCEPTED
  REPLAY   - old packets resent: duplicate seq numbers appear, most traffic
             still looks normal otherwise
  TAMPER   - a chunk of packets fail signature/AEAD verification
  FLOOD    - burst of near-zero-interval junk packets, mostly rejected
  JAMMED   - packets arrive sparsely/late (simulated RF degradation): long
             gaps, high jitter, some packets just never arrive (dropped)

Replace this generator with real logged data once your Flask /api/packet
handler is running - same downstream feature/training code works unchanged.
"""
import csv
import numpy as np

rng = np.random.default_rng(7)
rows = []  # ts, seq, verdict, reason
t = 0.0
seq = 0

def normal_segment(t, seq, duration, rate=1.0, jitter=0.08):
    n = int(duration / rate)
    for _ in range(n):
        t += rng.normal(rate, jitter)
        seq += 1
        rows.append([t, seq, "ACCEPTED", ""])
    return t, seq

def replay_segment(t, seq, duration, rate=1.0, jitter=0.08, replay_prob=0.35):
    end = t + duration
    recent = []
    while t < end:
        t += max(0.05, rng.normal(rate, jitter))
        seq += 1
        rows.append([t, seq, "ACCEPTED", ""])
        recent.append(seq)
        if len(recent) > 8:
            recent.pop(0)
        if rng.random() < replay_prob and len(recent) > 2:
            old = rng.choice(recent[:-1])
            t += rng.uniform(0.05, 0.3)
            rows.append([t, old, "REPLAY", "duplicate sequence"])
    return t, seq

def tamper_segment(t, seq, duration, rate=1.0, jitter=0.08, tamper_prob=0.3):
    end = t + duration
    while t < end:
        t += max(0.05, rng.normal(rate, jitter))
        seq += 1
        if rng.random() < tamper_prob:
            rows.append([t, seq, "INVALID_SIG", "signature mismatch"])
        else:
            rows.append([t, seq, "ACCEPTED", ""])
    return t, seq

def flood_segment(t, seq, duration, rate=0.03, jitter=0.02, reject_prob=0.8):
    end = t + duration
    while t < end:
        t += max(0.005, rng.normal(rate, jitter))
        seq = rng.integers(1, 99999)   # junk/random seq, not sequential
        verdict = "INVALID_SIG" if rng.random() < reject_prob else "ACCEPTED"
        rows.append([t, seq, verdict, "flood" if verdict != "ACCEPTED" else ""])
    return t, seq

def jammed_segment(t, seq, duration, rate=1.0, jitter=0.08, drop_prob=0.55, late_mult=4.0):
    end = t + duration
    while t < end:
        gap = max(0.05, rng.normal(rate, jitter))
        if rng.random() < drop_prob:
            gap *= late_mult * rng.uniform(1.0, 2.0)   # packet delayed/lost, next one arrives late
        t += gap
        seq += 1
        rows.append([t, seq, "ACCEPTED", ""])
    return t, seq

SEG = 20 * 60  # 20 min each
t, seq = normal_segment(t, seq, SEG)
t, seq = replay_segment(t, seq, SEG)
t, seq = normal_segment(t, seq, SEG)
t, seq = tamper_segment(t, seq, SEG)
t, seq = normal_segment(t, seq, SEG)
t, seq = flood_segment(t, seq, SEG)
t, seq = normal_segment(t, seq, SEG)
t, seq = jammed_segment(t, seq, SEG)
t, seq = normal_segment(t, seq, SEG)

with open("../data/channel_log_synthetic.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ts", "seq", "verdict", "reason"])
    w.writerows(rows)

print(f"{len(rows)} packet rows, {t/60:.1f} min total, {seq} max seq")
