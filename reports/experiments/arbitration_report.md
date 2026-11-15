# AutoSecure Arbitration Experiment

- Dataset: **580** samples, **25** features, L1 threshold **0.5**
- L1 probabilities are out-of-fold (5-fold stratified CV) — no leakage.

## Detector comparison

| Detector | Accuracy | Precision | Recall | F1 | ROC-AUC | FP (on clean) |
|----------|----------|-----------|--------|-----|---------|--------------|
| L0 (reflex) | 0.902 | 0.899 | 0.977 | 0.936 | n/a | 47 |
| L1 (ML) | 0.955 | 0.990 | 0.949 | 0.969 | 0.972 | 4 |
| HYBRID (union) | 0.914 | 0.896 | 1.000 | 0.945 | n/a | 50 |
| INTERSECT | 0.943 | 0.997 | 0.926 | 0.960 | n/a | 1 |

## Layer overlap (on vulnerable samples)

- Caught by BOTH layers: **399**
- Caught ONLY by L0 (reflex): **68**
- Caught ONLY by L1 (classifier): **13** — *the compound-config blind-spot evidence for hybrid design*
- Missed by ALL detectors: **0**

## Blind spots by tag (vulnerable samples missed)

| Tag | Missed by L0 | Missed by L1 | Missed by HYBRID |
|-----|--------------|--------------|------------------|
| M01 | 0 | 10 | 0 |
| M02 | 0 | 11 | 0 |
| M11 | 10 | 0 | 0 |
| combo-M01-M02 | 0 | 1 | 0 |

## Interpretation guide

- If HYBRID recall > max(L0, L1) recall with acceptable precision, the union arbitration thesis holds.
- `ONLY by L1` rows are samples whose misconfigurations the rule catalog doesn't cover — either add reflex rules (improving L0) or lean on the story that learned layers generalize to unseen misconfig classes.
- INTERSECT mode shows the precision ceiling for human-in-the-loop triage.
