# AutoSecure Assessment — Scan #1

- **Host**: `synth-desk`  **Tag**: `M13`  **Collected**: 2026-11-06T00:44:01.369077+00:00
- **Composite risk**: **0.839** (classifier p=0.8390222730171193)
- **L1 status**: OK
- **Drift**: first scan for this host — no delta baseline

## Findings

- **[R04/L0]** (sev 1.0) Non-root accounts with UID 0 (backdoor user) [classifier agrees: p=0.84]

## Proposed remediation plan (utility-ranked)

| # | Rule | Utility | Disruption | Action |
|---|------|---------|------------|--------|
| 1 | R04 | 0.65 | 0.7 | `userdel backdoor01` |

> All actions are proposals. Execution requires `--act` plus interactive approval. Every executed action has a recorded rollback.
