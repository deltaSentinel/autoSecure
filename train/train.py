#!/usr/bin/env python3
"""AutoSecure — model training pipeline (reference implementation).

Trains the posture classifier on collector snapshots and exports:

    model.joblib        trained RandomForest pipeline (predict_proba capable)
    feature_keys.json   canonical sorted feature-key order  <-- MUST MATCH
                        agent/main.py's _vectorize() convention
    eval_report.md      metrics, confusion matrix, per-tag breakdown
    importances.csv     feature ranking (for slides / L2 evidence)

Compatibility contract with agent/main.py:
    - Features = snapshot["features_ml"], keys sorted alphabetically.
    - None values are masked to 0.0 (agent does the same at inference).
    - Model must expose predict_proba(); RandomForest does.

Three-model comparison included (RF / SVM / Logistic Regression) because the
theory narrative needs it — the report prints all three side by side, then
exports the RF (best default for small tabular data, native importances).

Small-dataset aware: if < 40 samples, swaps the held-out test split for
stratified k-fold cross-validation so every sample counts.

Usage:
    python3 train.py --dataset ../dataset --out .
    python3 train.py --dataset ../dataset --out . --model rf --folds 10
"""

import argparse
import glob
import json
import os
import sys
from collections import Counter

import numpy as np

try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (classification_report, confusion_matrix,
                                 f1_score, precision_score, recall_score,
                                 roc_auc_score)
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import SVC
except ImportError as e:
    sys.exit(f"[-] missing dependency: {e}\n"
             "    install with: pip install scikit-learn joblib numpy "
             "(or use your uv venv)")


# ===========================================================================
# DATA LOADING
# ===========================================================================

def load_dataset(dataset_dir, verbose=True):
    """Load collector snapshots -> (X, y, tags, hosts, feature_keys)."""
    paths = sorted(glob.glob(os.path.join(dataset_dir, "*.json")))
    if not paths:
        sys.exit(f"[-] no snapshots found in {dataset_dir}")

    samples, skipped = [], 0
    for p in paths:
        try:
            with open(p) as f:
                snap = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] unreadable snapshot {p}: {e}", file=sys.stderr)
            skipped += 1
            continue

        meta, feats = snap.get("meta", {}), snap.get("features_ml")
        label = meta.get("label")
        if feats is None or label not in ("clean", "vulnerable"):
            print(f"[!] skipping {os.path.basename(p)}: missing features "
                  f"or unlabeled (label={label!r})", file=sys.stderr)
            skipped += 1
            continue
        samples.append({
            "features": feats,
            "label": label,
            "tag": meta.get("tag", "?"),
            "host": meta.get("host_id", "?"),
            "inject": meta.get("injected_misconfigs", []),
        })

    if skipped and verbose:
        print(f"[!] {skipped} snapshot(s) skipped as unusable")

    # Canonical key order: sorted(features_ml) — agent uses the identical rule.
    feature_keys = sorted({k for s in samples for k in s["features"]})

    def vectorize(feats):
        return [0.0 if feats.get(k) is None else float(feats[k])
                for k in feature_keys]

    X = np.array([vectorize(s["features"]) for s in samples])
    y = np.array([1 if s["label"] == "vulnerable" else 0 for s in samples])
    tags = [s["tag"] for s in samples]
    hosts = [s["host"] for s in samples]

    if verbose:
        print(f"[+] loaded {len(samples)} labeled samples "
              f"({len(feature_keys)} features) from {dataset_dir}")
        dist = Counter(y)
        print(f"[+] class distribution: clean={dist.get(0, 0)} "
              f"vulnerable={dist.get(1, 0)}")
        hdist = Counter(hosts)
        print(f"[+] hosts: " + ", ".join(f"{h}({n})" for h, n in hdist.most_common()))
        if len(dist) < 2:
            sys.exit("[-] only one class present — need both clean and "
                     "vulnerable samples before training")
        if dist.get(1, 0) < 5 or dist.get(0, 0) < 5:
            print("[!] WARNING: <5 samples in a class — collect more data "
                  "before trusting these metrics", file=sys.stderr)
    return X, y, tags, hosts, feature_keys


# ===========================================================================
# MODELS
# ===========================================================================

def build_model(kind, seed):
    """All models wrapped in pipelines; class_weight='balanced' handles
    imbalance without SMOTE (fewer moving parts, easier to defend)."""
    if kind == "rf":
        return Pipeline([
            ("clf", RandomForestClassifier(
                n_estimators=200, max_depth=None, min_samples_leaf=2,
                class_weight="balanced", random_state=seed, n_jobs=-1))
        ])
    if kind == "svm":
        return Pipeline([
            ("scale", StandardScaler()),
            ("clf", SVC(kernel="rbf", C=1.0, gamma="scale",
                        class_weight="balanced", probability=True,
                        random_state=seed))
        ])
    if kind == "lr":
        return Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000,
                                        class_weight="balanced",
                                        random_state=seed))
        ])
    sys.exit(f"[-] unknown model kind '{kind}' (rf|svm|lr)")


# ===========================================================================
# EVALUATION
# ===========================================================================

def metrics_from_cv(X, y, folds, seed, verbose=True):
    """Stratified k-fold out-of-fold predictions -> honest per-sample metrics."""
    skf = StratifiedKFold(n_splits=min(folds, min(Counter(y).values())),
                          shuffle=True, random_state=seed)
    if verbose:
        print(f"[+] evaluating with {skf.n_splits}-fold stratified CV")
    y_prob = cross_val_predict(build_model("rf", seed), X, y,
                               cv=skf, method="predict_proba")[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    m = {
        "accuracy": float((y_pred == y).mean()),
        "precision": float(precision_score(y, y_pred, zero_division=0)),
        "recall": float(recall_score(y, y_pred, zero_division=0)),
        "f1": float(f1_score(y, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, y_prob)),
    }
    return m, y_pred, y_prob, skf


def compare_models(X, y, folds, seed):
    """Three-model comparison for the report — out-of-fold, same folds."""
    skf = StratifiedKFold(n_splits=min(folds, min(Counter(y).values())),
                          shuffle=True, random_state=seed)
    rows = []
    for kind in ("rf", "svm", "lr"):
        try:
            prob = cross_val_predict(build_model(kind, seed), X, y,
                                     cv=skf, method="predict_proba")[:, 1]
            pred = (prob >= 0.5).astype(int)
            rows.append({
                "model": kind,
                "accuracy": float((pred == y).mean()),
                "precision": float(precision_score(y, pred, zero_division=0)),
                "recall": float(recall_score(y, pred, zero_division=0)),
                "f1": float(f1_score(y, pred, zero_division=0)),
                "roc_auc": float(roc_auc_score(y, prob)),
            })
        except Exception as e:
            print(f"[!] {kind} comparison failed: {e}", file=sys.stderr)
    return rows


# ===========================================================================
# REPORT / EXPORT
# ===========================================================================

def per_tag_breakdown(tags, y, y_pred):
    """Which misconfig tags are detected vs missed — interpretable results."""
    out = {}
    for t in sorted(set(tags)):
        idx = [i for i, tg in enumerate(tags) if tg == t]
        tp = sum(1 for i in idx if y[i] == 1 and y_pred[i] == 1)
        fn = sum(1 for i in idx if y[i] == 1 and y_pred[i] == 0)
        tn = sum(1 for i in idx if y[i] == 0 and y_pred[i] == 0)
        fp = sum(1 for i in idx if y[i] == 0 and y_pred[i] == 1)
        out[t] = {"vulnerable_tp": tp, "missed_fn": fn,
                  "clean_tn": tn, "false_alarm_fp": fp}
    return out


def export_importances(model, feature_keys, path):
    """Feature ranking from the RF (falls back gracefully)."""
    clf = model.named_steps.get("clf")
    if not hasattr(clf, "feature_importances_"):
        print("[!] selected model has no feature_importances_ — skipping CSV",
              file=sys.stderr)
        return None
    pairs = sorted(zip(feature_keys, clf.feature_importances_),
                   key=lambda kv: -kv[1])
    with open(path, "w") as fh:
        fh.write("rank,feature,importance\n")
        for i, (k, v) in enumerate(pairs, 1):
            fh.write(f"{i},{k},{v:.5f}\n")
    print(f"[+] feature importances -> {path}")
    return pairs


def write_eval_report(path, n_samples, feature_keys, model_kind, m, cm,
                      cmp_rows, tags, y, y_pred, importances):
    lines = [
        "# AutoSecure Model Evaluation",
        "",
        f"- Samples: **{n_samples}** | Features: **{len(feature_keys)}** "
        f"| Model exported: **{model_kind}**",
        f"- Primary metrics (out-of-fold, stratified): "
        f"acc={m['accuracy']:.3f}, P={m['precision']:.3f}, "
        f"R={m['recall']:.3f}, F1={m['f1']:.3f}, ROC-AUC={m['roc_auc']:.3f}",
        "",
        "## Confusion matrix (rows=true, cols=pred; 1=vulnerable)",
        "",
        "```",
        f"          pred-clean  pred-vuln",
        f"true-clean    {cm[0][0]:>6}      {cm[0][1]:>6}",
        f"true-vuln     {cm[1][0]:>6}      {cm[1][1]:>6}",
        "```",
        "",
        "## Model comparison (same folds)",
        "",
        "| Model | Acc | Precision | Recall | F1 | ROC-AUC |",
        "|-------|-----|-----------|--------|----|---------|",
    ]
    for r in cmp_rows:
        lines.append(f"| {r['model']} | {r['accuracy']:.3f} | "
                     f"{r['precision']:.3f} | {r['recall']:.3f} | "
                     f"{r['f1']:.3f} | {r['roc_auc']:.3f} |")

    lines += ["", "## Per-tag detection breakdown", "",
              "| Tag | Vuln caught | Vuln missed | Clean OK | False alarm |",
              "|-----|-------------|-------------|----------|-------------|"]
    for t, d in per_tag_breakdown(tags, y, y_pred).items():
        lines.append(f"| {t} | {d['vulnerable_tp']} | {d['missed_fn']} | "
                     f"{d['clean_tn']} | {d['false_alarm_fp']} |")

    if importances:
        lines += ["", "## Top 10 features (importance)", ""]
        for k, v in importances[:10]:
            lines.append(f"- `{k}`: {v:.4f}")

    lines += ["",
              "> Metrics are out-of-fold: every sample is scored by a model "
              "that never saw it during training. The exported model is "
              "trained on all samples afterward.",
              ""]
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
    print(f"[+] evaluation report -> {path}")


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(description="AutoSecure trainer")
    ap.add_argument("--dataset", default="../dataset",
                    help="directory of collector snapshots")
    ap.add_argument("--out", default=".", help="output directory for artifacts")
    ap.add_argument("--model", default="rf", choices=["rf", "svm", "lr"],
                    help="model kind to train and export")
    ap.add_argument("--folds", type=int, default=5,
                    help="CV folds (clamped to minority class size)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # 1. Load
    X, y, tags, hosts, feature_keys = load_dataset(args.dataset)

    # 2. Honest metrics via out-of-fold CV (all samples counted, none leaked)
    m, y_pred, _, skf = metrics_from_cv(X, y, args.folds, args.seed)
    cm = confusion_matrix(y, y_pred)

    # 3. Three-model comparison on identical folds
    cmp_rows = compare_models(X, y, max(args.folds, skf.n_splits), args.seed)

    # 4. Train final model on ALL data — this is what gets deployed
    model = build_model(args.model, args.seed)
    model.fit(X, y)

    # 5. Export artifacts
    model_path = os.path.join(args.out, "model.joblib")
    joblib.dump(model, model_path)
    print(f"[+] model -> {model_path}")

    keys_path = os.path.join(args.out, "feature_keys.json")
    with open(keys_path, "w") as fh:
        json.dump({"feature_keys": feature_keys,
                   "none_mask_value": 0.0,
                   "note": "agent/main.py must vectorize with this exact "
                           "order (sorted keys); verify on first joint run"},
                  fh, indent=2)
    print(f"[+] canonical feature order -> {keys_path}")

    imp_path = os.path.join(args.out, "importances.csv")
    importances = export_importances(model, feature_keys, imp_path)

    # 6. Written evaluation report (slide-ready tables)
    write_eval_report(os.path.join(args.out, "eval_report.md"),
                      len(X), feature_keys, args.model, m, cm, cmp_rows,
                      tags, y, y_pred, importances)

    print("\n=== Summary (out-of-fold) ===")
    print(classification_report(y, y_pred, target_names=["clean",
                                                         "vulnerable"],
                                zero_division=0))
    print(f"ROC-AUC: {m['roc_auc']:.3f}")
    print("\n[.] next: drop model.joblib + feature_keys.json where "
          "agent/main.py looks for them, then rerun the agent on a known-"
          "vulnerable snapshot and confirm L1 lights up.")


if __name__ == "__main__":
    main()

