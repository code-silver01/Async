#!/usr/bin/env python3
"""
Trains the Pi-side edge classifier (NORMAL / STRAIN / CRITICAL) on
qshield_3class_dataset.csv. Splits by SUBJECT (not randomly) so the model
is validated on people it never trained on - random row splitting would
leak the same subject's data into both train and test and inflate accuracy.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

CSV = "../data/qshield_3class_dataset.csv"   # relative to training/, or pass an absolute path
FEATURES = ["ax","ay","az","gyro_w","gyro_x","gyro_y","gyro_z",
            "droll","dpitch","dyaw","heart_raw","accel_mag","motion_intensity","temp_c"]

df = pd.read_csv(CSV)
subjects = sorted(df.subject.unique())
test_subjects = subjects[::5]           # ~20% of subjects held out entirely
train_subjects = [s for s in subjects if s not in test_subjects]
print(f"train subjects: {len(train_subjects)}  test subjects: {len(test_subjects)} {test_subjects}")

train = df[df.subject.isin(train_subjects)]
test = df[df.subject.isin(test_subjects)]

X_train, y_train = train[FEATURES], train["label"]
X_test, y_test = test[FEATURES], test["label"]

clf = RandomForestClassifier(n_estimators=300, max_depth=14, class_weight="balanced",
                              random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

pred = clf.predict(X_test)
print("\n=== held-out-subject test report ===")
print(classification_report(y_test, pred))
print("confusion matrix (rows=true, cols=pred), labels:", sorted(y_test.unique()))
print(confusion_matrix(y_test, pred, labels=sorted(y_test.unique())))

print("\nfeature importances:")
for c, imp in sorted(zip(FEATURES, clf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {c:16s} {imp:.3f}")

joblib.dump(clf, "../models/qshield_status_classifier.pkl")
print("\nsaved -> ../models/qshield_status_classifier.pkl")
