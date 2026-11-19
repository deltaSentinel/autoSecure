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
| W_FUSED (agent verdict) | 0.959 | 0.990 | 0.953 | 0.972 | 0.993 | 4 |

## Fusion arbitration (verdict level)

- Fusion params this run: **K=0.5** threshold=0.5
- W_FUSED reproduces the deployed agent end to end: L0 catalog -> per-finding severity fusion -> composite risk -> verdict boundary at 0.5.
- Regression gate: HYB recall (1.000) must remain >= max(L0 0.977, L1 0.949) — fusion modulates ranking, never coverage.
- Clean false alarms at verdict level: 4 of 150
- Watch W_FUSED precision vs HYBRID: composite_risk max-fuses raw p, so hosts with p just over the threshold flip the verdict even with an empty findings list — this quantifies the open composite_risk gating question from the agent refactor.


## Layer overlap (on vulnerable samples)

- Caught by BOTH layers: **398**
- Caught ONLY by L0 (reflex): **22**
- Caught ONLY by L1 (classifier): **10** — *the compound-config blind-spot evidence for hybrid design*
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
- If the fusion grid shows verdict precision improving as K rises without recall loss, the modulation is earning its keep; if precision is flat in K, all the leverage is in the threshold, and K could be pinned to 0 for simplicity.