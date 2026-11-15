# AutoSecure Assessment — Scan #2

- **Host**: `synth-desk`  **Tag**: `M11`  **Collected**: 2026-11-10T03:11:52.306281+00:00
- **Composite risk**: **0.503** (classifier p=n/a)
- **L1 status**: model load/inference failed: X has 25 features, but RandomForestClassifier is expecting 26 features as input. (L1 disabled)
- **Drift**: 7 features changed since previous scan

## Findings

- **[R16/L2]** (sev 0.7) suid_binaries rose 210 -> 211 since previous scan

## Proposed remediation plan (utility-ranked)

| # | Rule | Utility | Disruption | Action |
|---|------|---------|------------|--------|
| 1 | R16 | 0.7 | None | `SUID drift: enumerate with `find /usr /bin /sbin /lib -xdev -perm -4000 -ls` (same scope as collector), diff against baseline, investigate added binaries manually; agent never auto-deletes (count-only evidence — fail-static)` |

> All actions are proposals. Execution requires `--act` plus interactive approval. Every executed action has a recorded rollback.
