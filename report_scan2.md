# AutoSecure Assessment — Scan #2

- **Host**: `synth-desk`  **Tag**: `M11`  **Collected**: 2026-11-10T03:11:52.306281+00:00
- **Composite risk**: **0.900** (classifier p=0.9002889767522252)
- **L1 status**: OK
- **Drift**: 7 features changed since previous scan

## Findings

- **[L1/L1]** (sev 0.9) classifier flags vulnerable posture (p=0.90); no reflex rule fired — compound-config suspicion.
- **[R16/L2]** (sev 0.7) suid_binaries rose 210 -> 211 since previous scan

## Proposed remediation plan (utility-ranked)

| # | Rule | Utility | Disruption | Action |
|---|------|---------|------------|--------|
| 1 | L1 | 0.9 | None | `Classifier-only finding: investigate compound configuration manually` |
| 2 | R16 | 0.7 | None | `no remediation registered` |

> All actions are proposals. Execution requires `--act` plus interactive approval. Every executed action has a recorded rollback.
