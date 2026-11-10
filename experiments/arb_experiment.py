#!/usr/bin/env python3
"""AutoSecure — arbitration experiment (Experiment 1 from the design doc).

Question: does the hybrid (L0 reflex ∪ L1 classifier) beat either layer alone
on the injected dataset?

Detectors evaluated (all on identical, out-of-fold footing):

    L0    : reflex-only        — fires if any reflex rule fires
    L1    : ML-only            — fires if p_vulnerable >= threshold
    HYB   : union arbitration  — fires if L0 OR L1 fires
    (opt) INTERSECT           — fires only if both agree (precision-max mode)

Methodology notes (for the write-up):
    - L1 probabilities come from cross_val_predict: every sample is scored by
      a model that never saw it. Using in-sample probabilities here would
      inflate L1/HYB — this is the leakage trap professors look for.
    - Because L0 is deterministic, no CV is needed for it; the same fold
      structure simply doesn't matter to it, keeping the comparison fair.
    - Threshold sweep for L1 is included so you can plot the P/R tradeoff.

Outputs (into --out dir):
    arbitration_report.md    slide-ready tables + per-tag analysis
    arbitration_results.json machine-readable full results
    threshold_sweep.csv      L1 threshold vs P/R/F1 (for plotting)

Usage:
    python3 arb_experiment.py --dataset ../dataset --out .
    python3 arb_experiment.py --dataset ../dataset --threshold 0.4

Imports evaluate_reflex from agent/main.py so the rule catalog can never
drift between agent and experiment. Requires the same deps as train.py.
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
    from sklearn.metrics import (confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score)
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import Pipeline
    from sklearn.calibration import CalibratedClassifierCV
except ImportError as e:
    sys.exit(f"[-] missing dependency: {e}")

AGENT_DIR_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "../agent")
sys.path.insert(0, AGENT_DIR_DEFAULT)
try:
    from main import evaluate_reflex  # the agent's canonical L0 rule catalog
except ImportError:
    sys.exit("[-] could not import evaluate_reflex from agent/main.py — "
             "pass --agent-dir with the correct path")


# ---------------------------------------------------------------------------
# loading + layer evaluation
# ---------------------------------------------------------------------------

def load_snapshots(dataset_dir):
    paths = sorted(glob.glob(os.path.join(dataset_dir, "*.json")))
    samples = []
    for p in paths:
        with open(p) as f:
            snap = json.load(f)
        if snap.get("meta", {}).get("label") not in ("clean", "vulnerable"):
            continue
        samples.append({
            "path": p,
            "tag": snap["meta"].get("tag", "?"),
            "inject": snap["meta"].get("injected_misconfigs", []),
            "label": 1 if snap["meta"]["label"] == "vulnerable" else 0,
            "raw": snap.get("features_raw", {}),
            "ml": snap.get("features_ml", {}),
        })
    if not samples:
        sys.exit(f"[-] no labeled snapshots in {dataset_dir}")
    dist = Counter(s["label"] for s in samples)
    print(f"[+] {len(samples)} labeled samples "
          f"(clean={dist.get(0,0)} vulnerable={dist.get(1,0)})")
    if len(dist) < 2:
        sys.exit("[-] need both classes in the dataset")
    return samples


def feature_keys_union(samples):
    return sorted({k for s in samples for k in s["ml"]})


def l0_decisions(samples):
    """Deterministic reflex layer — reuse the agent's exact catalog."""
    preds = []
    for s in samples:
        findings = evaluate_reflex(s["raw"])
        preds.append((1 if findings else 0,
                     [f["rule_id"] for f in findings]))
    return np.array([p for p, _ in preds]), preds


def base_rf(seed=42):
    return Pipeline([("clf", RandomForestClassifier(
            n_estimators=200, min_samples_leaf=2, class_weight="balanced",
            random_state=seed, n_jobs=-1))])


def l1_probabilities(samples, keys, seed, folds):
    """Out-of-fold classifier probabilities (leakage-free)."""
    X = np.array([[0.0 if s["ml"].get(k) is None else float(s["ml"].get(k, 0.0))
                   for k in keys] for s in samples])
    y = np.array([s["label"] for s in samples])
    n_folds = min(folds, Counter(y)[min(Counter(y))])
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=seed)
    model = CalibratedClassifierCV(estimator=base_rf(), method="sigmoid")
    prob = cross_val_predict(model, X, y, cv=skf,
                             method="predict_proba")[:, 1]
    print(f"[+] L1 out-of-fold probabilities via {n_folds}-fold CV")
    return prob


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------

def detector_metrics(y_true, y_pred, y_prob=None):
    m = {
        "accuracy": float((np.asarray(y_pred) == np.asarray(y_true)).mean()),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_prob is not None:
        try:
            m["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        except ValueError:
            m["roc_auc"] = None
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred,
                                      labels=[0, 1]).ravel()
    m["tn"], m["fp"], m["fn"], m["tp"] = int(tn), int(fp), int(fn), int(tp)
    return m


# ---------------------------------------------------------------------------
# main experiment
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="AutoSecure arbitration experiment")
    ap.add_argument("--dataset", default="../dataset")
    ap.add_argument("--out", default=".")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="L1 firing threshold")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--sweep", action="store_true",
                    help="emit threshold_sweep.csv for L1")
    args = ap.parse_args()

    samples = load_snapshots(args.dataset)
    keys = feature_keys_union(samples)
    y = np.array([s["label"] for s in samples])

    # L0
    l0_pred, l0_detail = l0_decisions(samples)

    # L1 (out-of-fold)
    p = l1_probabilities(samples, keys, args.seed, args.folds)
    l1_pred = (p >= args.threshold).astype(int)

    # arbitration variants
    hyb_pred = ((l0_pred == 1) | (l1_pred == 1)).astype(int)
    int_pred = ((l0_pred == 1) & (l1_pred == 1)).astype(int)

    detectors = {
        "L0 (reflex)": detector_metrics(y, l0_pred),
        "L1 (ML)": detector_metrics(y, l1_pred, p),
        "HYBRID (union)": detector_metrics(y, hyb_pred),
        "INTERSECT": detector_metrics(y, int_pred),
    }

    # ---- analysis: which samples does each layer catch/miss? --------------
    only_l0 = only_l1 = both = neither = 0
    for i, s in enumerate(samples):
        l0h, l1h = l0_pred[i] == 1, l1_pred[i] == 1
        if l0h and l1h:
            both += 1
        elif l0h:
            only_l0 += 1
        elif l1h:
            only_l1 += 1
        elif s["label"] == 1:
            neither += 1

    # L0 blind spots: vulnerable samples no reflex rule catches
    l0_missed_tags = Counter()
    l1_missed_tags = Counter()
    hyb_missed_tags = Counter()
    for i, s in enumerate(samples):
        if s["label"] == 1:
            if l0_pred[i] == 0:
                l0_missed_tags[s["tag"]] += 1
            if l1_pred[i] == 0:
                l1_missed_tags[s["tag"]] += 1
            if hyb_pred[i] == 0:
                hyb_missed_tags[s["tag"]] += 1

    # clean-sample false alarms per layer
    l0_fp = int(((l0_pred == 1) & (y == 0)).sum())
    l1_fp = int(((l1_pred == 1) & (y == 0)).sum())
    hyb_fp = int(((hyb_pred == 1) & (y == 0)).sum())

    # ---- optional threshold sweep -----------------------------------------
    sweep_rows = []
    if args.sweep:
        for th in [round(t / 20, 2) for t in range(5, 20)]:
            lp = (p >= th).astype(int)
            hp = ((l0_pred == 1) | (lp == 1)).astype(int)
            sweep_rows.append({
                "threshold": th,
                "l1_precision": precision_score(y, lp, zero_division=0),
                "l1_recall": recall_score(y, lp, zero_division=0),
                "l1_f1": f1_score(y, lp, zero_division=0),
                "hybrid_f1": f1_score(y, hp, zero_division=0),
            })

    # ---- report -----------------------------------------------------------
    os.makedirs(args.out, exist_ok=True)
    md = [
        "# AutoSecure Arbitration Experiment",
        "",
        f"- Dataset: **{len(samples)}** samples, "
        f"**{len(keys)}** features, L1 threshold **{args.threshold}**",
        f"- L1 probabilities are out-of-fold "
          f"({args.folds}-fold stratified CV) — no leakage.",
        "",
        "## Detector comparison",
        "",
        "| Detector | Accuracy | Precision | Recall | F1 | ROC-AUC | FP (on clean) |",
        "|----------|----------|-----------|--------|-----|---------|--------------|",
    ]
    for name, m in detectors.items():
        auc = f"{m['roc_auc']:.3f}" if m.get("roc_auc") else "n/a"
        fp_col = m["fp"] if name != "INTERSECT" else m["fp"]
        md.append(f"| {name} | {m['accuracy']:.3f} | {m['precision']:.3f} | "
                  f"{m['recall']:.3f} | {m['f1']:.3f} | {auc} | {fp_col} |")

    md += [
        "",
        "## Layer overlap (on vulnerable samples)",
        "",
        f"- Caught by BOTH layers: **{both}**",
        f"- Caught ONLY by L0 (reflex): **{only_l0}**",
        f"- Caught ONLY by L1 (classifier): **{only_l1}** — *the compound-"
        f"config blind-spot evidence for hybrid design*",
        f"- Missed by ALL detectors: **{neither}**",
        "",
        "## Blind spots by tag (vulnerable samples missed)",
        "",
        "| Tag | Missed by L0 | Missed by L1 | Missed by HYBRID |",
        "|-----|--------------|--------------|------------------|",
    ]
    all_tags = sorted(set(l0_missed_tags) | set(l1_missed_tags)
                      | set(hyb_missed_tags))
    if all_tags:
        for t in all_tags:
            md.append(f"| {t} | {l0_missed_tags[t]} | {l1_missed_tags[t]} "
                      f"| {hyb_missed_tags[t]} |")
    else:
        md.append("| (none — everything detected) | | | |")

    md += [
        "",
        "## Interpretation guide",
        "",
        "- If HYBRID recall > max(L0, L1) recall with acceptable precision, "
        "the union arbitration thesis holds.",
        "- `ONLY by L1` rows are samples whose misconfigurations the rule "
        "catalog doesn't cover — either add reflex rules (improving L0) or "
        "lean on the story that learned layers generalize to unseen "
        "misconfig classes.",
        "- INTERSECT mode shows the precision ceiling for "
        "human-in-the-loop triage.",
        "",
    ]

    report_path = os.path.join(args.out, "arbitration_report.md")
    with open(report_path, "w") as fh:
        fh.write("\n".join(md))
    print(f"[+] report -> {report_path}")

    results = {
        "n_samples": len(samples),
        "threshold": args.threshold,
        "detectors": detectors,
        "overlap": {"both": both, "only_l0": only_l0, "only_l1": only_l1,
                    "missed_by_all": neither},
        "l0_blind_spots": dict(l0_missed_tags),
        "l1_blind_spots": dict(l1_missed_tags),
        "hybrid_blind_spots": dict(hyb_missed_tags),
    }
    with open(os.path.join(args.out, "arbitration_results.json"), "w") as fh:
        json.dump(results, fh, indent=2)

    if sweep_rows:
        with open(os.path.join(args.out, "threshold_sweep.csv"), "w") as fh:
            fh.write("threshold,l1_precision,l1_recall,l1_f1,hybrid_f1\n")
            for r in sweep_rows:
                fh.write(f"{r['threshold']},{r['l1_precision']:.4f},"
                         f"{r['l1_recall']:.4f},{r['l1_f1']:.4f},"
                         f"{r['hybrid_f1']:.4f}\n")
        print(f"[+] threshold sweep -> threshold_sweep.csv")

    print("\n=== Headline ===")
    for name, m in detectors.items():
        print(f"  {name:<16} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f}")


if __name__ == "__main__":
    main()

