#!/usr/bin/env python3
"""
Trains both an Isolation Forest (unsupervised, matches your "no signature
needed" pitch) and a Random Forest (supervised, usually better numbers) on
the synthetic channel_features_synthetic.csv, and prints a comparison so
you can pick one honestly.

Swap FEAT_CSV to channel_features.csv (built from real Flask logs) later -
nothing else changes.
"""
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

FEAT_CSV = "../data/channel_features_synthetic.csv"
COLS = ["n_packets","mean_inter_arrival","jitter","max_gap","rejection_rate","replay_rate","duplicate_rate","seq_gaps"]

feat = pd.read_csv(FEAT_CSV)
X, y = feat[COLS], feat["label"]

print("=== Isolation Forest (trained on NORMAL only) ===")
normal_X = X[y == "NORMAL"]
iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42).fit(normal_X)
feat["iso_score"] = iso.decision_function(X)
print(feat.groupby("label")["iso_score"].describe()[["mean","min","max"]])
threshold = feat.groupby("label")["iso_score"].mean().mean()  # rough midpoint, tune on your own data
print(f"suggested threshold (score below this = ATTACKED): {threshold:.4f}")
joblib.dump(iso, "../models/channel_isolationforest.pkl")

print("\n=== Random Forest (supervised) ===")
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
rf = RandomForestClassifier(n_estimators=200, random_state=42).fit(X_tr, y_tr)
print(classification_report(y_te, rf.predict(X_te)))
print("feature importances:")
for c, imp in sorted(zip(COLS, rf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {c:20s} {imp:.3f}")
joblib.dump(rf, "../models/channel_randomforest.pkl")
