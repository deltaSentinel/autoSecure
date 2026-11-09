# AutoSecure Arbitration Experiment

- Dataset: **580** samples, **25** features, L1 threshold **0.5**
- L1 probabilities are out-of-fold (5-fold stratified CV) — no leakage.

## Detector comparison

| Detector | Accuracy | Precision | Recall | F1 | ROC-AUC | FP (on clean) |
|----------|----------|-----------|--------|-----|---------|--------------|
| L0 (reflex) | 0.955 | 1.000 | 0.940 | 0.969 | n/a | 0 |
| L1 (ML) | 0.972 | 0.993 | 0.970 | 0.981 | 0.990 | 3 |
| HYBRID (union) | 0.976 | 0.993 | 0.974 | 0.984 | n/a | 3 |
| INTERSECT | 0.952 | 1.000 | 0.935 | 0.966 | n/a | 0 |

## Layer overlap (on vulnerable samples)

- Caught by BOTH layers: **402**
- Caught ONLY by L0 (reflex): **2**
- Caught ONLY by L1 (classifier): **18** — *the compound-config blind-spot evidence for hybrid design*
- Missed by ALL detectors: **11**

## Blind spots by tag (vulnerable samples missed)

| Tag | Missed by L0 | Missed by L1 | Missed by HYBRID |
|-----|--------------|--------------|------------------|
| M01 | 0 | 1 | 0 |
| M02 | 12 | 11 | 11 |
| M05 | 0 | 1 | 0 |
| M11 | 12 | 0 | 0 |
| combo-M02-M11 | 2 | 0 | 0 |

## Interpretation guide

- If HYBRID recall > max(L0, L1) recall with acceptable precision, the union arbitration thesis holds.
- `ONLY by L1` rows are samples whose misconfigurations the rule catalog doesn't cover — either add reflex rules (improving L0) or lean on the story that learned layers generalize to unseen misconfig classes.
- INTERSECT mode shows the precision ceiling for human-in-the-loop triage.
