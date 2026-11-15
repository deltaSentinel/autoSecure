# AutoSecure Arbitration Experiment

- Dataset: **580** samples, **25** features, L1 threshold **0.5**
- L1 probabilities are out-of-fold (5-fold stratified CV) — no leakage.

## Detector comparison

| Detector | Accuracy | Precision | Recall | F1 | ROC-AUC | FP (on clean) |
|----------|----------|-----------|--------|-----|---------|--------------|
| L0 (reflex) | 0.959 | 1.000 | 0.944 | 0.971 | n/a | 0 |
| L1 (ML) | 0.955 | 0.990 | 0.949 | 0.969 | 0.972 | 4 |
| HYBRID (union) | 0.974 | 0.991 | 0.974 | 0.982 | n/a | 4 |
| INTERSECT | 0.940 | 1.000 | 0.919 | 0.958 | n/a | 0 |

## Layer overlap (on vulnerable samples)

- Caught by BOTH layers: **395**
- Caught ONLY by L0 (reflex): **11**
- Caught ONLY by L1 (classifier): **17** — *the compound-config blind-spot evidence for hybrid design*
- Missed by ALL detectors: **11**

## Blind spots by tag (vulnerable samples missed)

| Tag | Missed by L0 | Missed by L1 | Missed by HYBRID |
|-----|--------------|--------------|------------------|
| M01 | 0 | 10 | 0 |
| M02 | 12 | 11 | 11 |
| M11 | 12 | 0 | 0 |
| combo-M01-M02 | 0 | 1 | 0 |

## Interpretation guide

- If HYBRID recall > max(L0, L1) recall with acceptable precision, the union arbitration thesis holds.
- `ONLY by L1` rows are samples whose misconfigurations the rule catalog doesn't cover — either add reflex rules (improving L0) or lean on the story that learned layers generalize to unseen misconfig classes.
- INTERSECT mode shows the precision ceiling for human-in-the-loop triage.
