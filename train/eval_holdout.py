#!/usr/bin/env python3
"""Evaluate models/model.joblib against a held-out REAL dataset."""
import glob, json, os, sys
import numpy as np, joblib

dataset = sys.argv[1] if len(sys.argv) > 1 else "../dataset_real"
model = joblib.load("../models/model.joblib")
keys = json.load(open("../models/feature_keys.json"))["feature_keys"]

snaps, skipped = [], 0
for p in sorted(glob.glob(os.path.join(dataset, "*.json"))):
    s = json.load(open(p))
    if s["meta"].get("label") not in ("clean", "vulnerable"): skipped += 1; continue
    snaps.append(s)
if not snaps: sys.exit("no labeled snapshots")

X = np.array([[0.0 if s["features_ml"].get(k) is None
               else float(s["features_ml"].get(k, 0.0)) for k in keys]
              for s in snaps])
y = np.array([1 if s["meta"]["label"] == "vulnerable" else 0 for s in snaps])

p = model.predict_proba(X)[:, 1]
pred = (p >= 0.5).astype(int)
tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
tn = int(((pred == 0) & (y == 0)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
print(f"samples={len(snaps)} (skipped {skipped})  clean={len(y)-y.sum()} vuln={y.sum()}")
print(f"TP={tp} FN={fn} TN={tn} FP={fp}")
print(f"accuracy={(pred==y).mean():.3f} precision={tp/max(tp+fp,1):.3f} "
      f"recall={tp/max(tp+fn,1):.3f}")
print("\nMissed (FN) tags:")
for s, pr, yy in zip(snaps, p, y):
    if yy == 1 and pr < 0.5: print(f"  {s['meta']['tag']:24s} p={pr:.3f}")
print("False alarms (FP) tags:")
for s, pr, yy in zip(snaps, p, y):
    if yy == 0 and pr >= 0.5: print(f"  {s['meta']['tag']:24s} p={pr:.3f}")
