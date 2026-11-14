# AutoSecure Arbitration Experiment

- Dataset: **580** samples, **25** features, L1 threshold **0.5**
- L1 probabilities are out-of-fold (5-fold stratified CV) — no leakage.

## Detector comparison

| Detector | Accuracy | Precision | Recall | F1 | ROC-AUC | FP (on clean) |
|----------|----------|-----------|--------|-----|---------|--------------|
| L0 (reflex) | 0.876 | 1.000 | 0.833 | 0.909 | n/a | 0 |
| L1 (ML) | 0.972 | 0.993 | 0.970 | 0.981 | 0.990 | 3 |
| HYBRID (union) | 0.972 | 0.993 | 0.970 | 0.981 | n/a | 3 |
| INTERSECT | 0.876 | 1.000 | 0.833 | 0.909 | n/a | 0 |

## Layer overlap (on vulnerable samples)

- Caught by BOTH layers: **358**
- Caught ONLY by L0 (reflex): **0**
- Caught ONLY by L1 (classifier): **62** — *the compound-config blind-spot evidence for hybrid design*
- Missed by ALL detectors: **13**

## Blind spots by tag (vulnerable samples missed)

| Tag | Missed by L0 | Missed by L1 | Missed by HYBRID |
|-----|--------------|--------------|------------------|
| M01 | 12 | 1 | 1 |
| M02 | 12 | 11 | 11 |
| M05 | 12 | 1 | 1 |
| M11 | 12 | 0 | 0 |
| M12 | 12 | 0 | 0 |
| combo-M02-M05 | 1 | 0 | 0 |
| combo-M02-M11 | 2 | 0 | 0 |
| combo-M02-M12 | 1 | 0 | 0 |
| combo-M05-M02 | 2 | 0 | 0 |
| combo-M11-M12 | 1 | 0 | 0 |
| combo-M12-M01 | 1 | 0 | 0 |
| combo-M12-M01-M02 | 1 | 0 | 0 |
| combo-M12-M05 | 2 | 0 | 0 |
| combo-M12-M11 | 1 | 0 | 0 |

## Interpretation guide

- If HYBRID recall > max(L0, L1) recall with acceptable precision, the union arbitration thesis holds.
- `ONLY by L1` rows are samples whose misconfigurations the rule catalog doesn't cover — either add reflex rules (improving L0) or lean on the story that learned layers generalize to unseen misconfig classes.
- INTERSECT mode shows the precision ceiling for human-in-the-loop triage.
