# AutoSecure

[![CI](https://github.com/deltaSentinel/autoSecure/actions/workflows/ci.yml/badge.svg)](https://github.com/deltaSentinel/autoSecure/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12-blue)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-orange.svg)](./LICENSE)
[![Security](https://img.shields.io/badge/security-policy-blue)](./SECURITY.md)

AI-driven vulnerability and misconfiguration detection for personal computing environments — a four-layer hybrid agent combining hand-written reflex rules with a learned classifier. Developed as a semester project for AI-472.

**Team:** Raymond Balesky (EE/CPE) · Kayla Granger (Computer Science)

**Ethics note:** AutoSecure is intended for hosts you own or are explicitly authorized to test. Mutation mode (`--act`) requires root *and* an explicit human approval for every proposed fix. See [Responsible use](#responsible-use).

---

## What this is

AutoSecure scans a Linux host's configuration posture — SSH settings, file permissions, user accounts, firewall state, listening services — classifies the host as *clean* or *misconfigured* using a Random Forest over 25 normalized features, and proposes a utility-ranked, reversible remediation plan behind a human approval gate.

### Headline results

| Result (out-of-fold, 5-fold stratified CV, n=580) | Value |
|---|---|
| Precision / Recall / F1 / ROC-AUC | 0.993 / 0.970 / 0.981 / 0.990 |
| False positives / false negatives | 3 FP, 13 FN |
| Hybrid vs. classifier-only at strict threshold (t=0.95) | F1 **0.910 vs 0.646** |
| Post-calibration hybrid F1 | 0.981 (vs. 0.914 L1-only) |

The threshold-sweep result is the core architectural claim: the hand-written rule layer acts as **threshold-invariant recall insurance**, which is what justifies the hybrid design at strict operating points.

### Architecture

![AutoSecure four-layer architecture](Presentations/Images/Diagrams/architecture.png)

| Layer | Function | Type (Russell & Norvig) |
|-------|----------|-------------------------|
| L0 — Reflex | 12 deterministic condition→finding rules | Simple reflex |
| L1 — Classifier | Random Forest, 25-feature vector | Model-based |
| L2 — Diagnostician | Merges L0+L1 findings, drift attribution vs. prior scans | Internal state |
| L3 — Planner | Utility-ranked fixes: `severity − disruption − fp_penalty` | Utility-based |

**Safety invariants:** read-only unless `--act` is passed; `--act` requires root and hard-refuses otherwise (no silent degradation); every finding is evidence-chained; operator rejections persist and lower that rule's utility in future runs.

## Quick start

Python 3.12, managed with [`uv`](https://docs.astral.sh/uv/). Everything else is stdlib. Whole pipeline runs offline — no GPU, no special hardware.

```bash
git clone https://github.com/deltaSentinel/autoSecure.git
cd autoSecure
uv venv && uv pip install scikit-learn joblib numpy pytest

# Scan a snapshot (read-only by default)
uv run python3 agent/main.py --snapshot <path/to/snapshot.json> --db agent/mem.db
```

Mutation mode adds `--act` (requires root; refuses otherwise)

The full pipeline (dataset generation → training → experiments) is documented in [Canonical commands](#canonical-commands) below.

## Directory layout

Grouped by *where code executes* — everything under `collector/` runs on target hosts; everything else stays at the desk. Generated artifacts live under `reports/`, keyed by which stage produced them.

```
autoSecure/
├── agent/            # main.py (four-layer harness) + mem.db runtime state
├── collector/         # collect.py (+ PowerShell port), inject.sh, checks.py, backends.py
│                     #   CONTRACT.md, README-collector.md, README-windows.md
├── experiments/       # synth_dataset.py, gen_dataset.py, gen_real_data.sh,
│                     #   arb_experiment.py, planner_sweep.py
├── train/            # train.py, eval_holdout.py; agent model drop point
├── data/
│   ├── synth/         # 580 synthetic training snapshots (regenerable — seed 7;
│   │                  #   NOT version-controlled)
│   └── real/          # real LXC snapshots (break phase) — NEVER mixed with synth
├── models/            # model.joblib, feature_keys.json, importances.csv
├── reports/
│   ├── training/      # eval_report.md + history/ (pre-calibration baselines)
│   ├── experiments/   # arbitration_report.md, planner_report.md,
│   │                  #   threshold_sweep.csv, planner_sweep.csv + history/
│   └── scans/         # agent scan reports (Markdown)
├── Presentations/     # decks, demo material, Images/Diagrams, Images/Graphs
├── tests/             # pytest suite: rules catalog, R16 drift, artifact sync + fixtures
├── LICENSE            # MIT
├── SECURITY.md        # vulnerability reporting policy
└── README.md          # this file
```

The test suite includes per-rule known-positive/negative coverage and a `test_artifacts_synced.py` guard so committed reports can't silently drift from the code that generates them.

## Environment

Python 3.12, managed with `uv`. From the project root:

```bash
uv venv && uv pip install scikit-learn joblib numpy pytest
```

Everything else is stdlib. Whole pipeline runs offline. No GPU, no special hardware.

## Canonical commands

All commands run from the project root unless noted.

**Regenerate the synthetic training set** (seed 7 ⇒ bit-identical reproduction):

```bash
uv run python3 experiments/synth_dataset.py --out data/synth --clean 150 --singles 12 --combos 250 --seed 7
ls data/synth/*.json | wc -l   # MUST be 580 — verify after EVERY generation
```

The generator **appends**: never run it into a non-empty `data/synth/` unless you intend duplication (duplicated snapshots invalidate out-of-fold CV; see *Dataset provenance* below).

**Train:**

```bash
uv run python3 train/train.py --dataset data/synth --out models
```

Exports `model.joblib`, `feature_keys.json`, `importances.csv`, and writes evaluation artifacts under `reports/training/`. Metrics are out-of-fold (5-fold stratified CV).

**Arbitration experiment (L0 vs L1 vs hybrid, with threshold sweep):**

```bash
uv run python3 experiments/arb_experiment.py --dataset data/synth --out models --sweep
```

Imports `evaluate_reflex` directly from `agent/main.py` — the experiment and the deployed agent share one rule catalog by construction.

**Planner utility sweep** (`--alpha/--beta/--gamma`):

```bash
uv run python3 experiments/planner_sweep.py
```

**Real-data transfer test** (break phase — run from inside `train/`):

```bash
cd train && uv run python3 eval_holdout.py ../data/real && cd ..
```

Note: `eval_holdout.py` resolves `../models/` relative to its own location, so it must be launched from `train/`.

**On-target data collection** (inside a disposable LXC/VM, as root):

```bash
python3 /root/collect.py --host-id <id> --tag <tag> --label <clean|vulnerable> [--inject M01 ...] --out <dir>
```

## Dataset provenance

- **Synthetic set:** 580 snapshots = 150 clean + 180 singles (15 misconfig types × 12) + 250 random 2–4-misconfig combinations, across desktop/server/minimal host profiles. Generated with `--seed 7`; fully reproducible, therefore *not* version-controlled.
- **Label-collision fix (Nov 2026):** clean baselines originally carried strict-risk noise (firewall-down ~25%, weak password policy ~15%, etc.) identical to injected misconfig signatures, making five misconfig types unlearnable (recall 0.847). Strict-risk noise was removed from clean baselines; debatable soft risks (password auth ~30%, fail2ban absent ~80%) deliberately retained. Post-fix out-of-fold: precision 0.993, recall 0.970, ROC-AUC 0.990.
- **Real set (pending):** snapshots from disposable Proxmox LXC clones on HWHS-001; destroy-instead-of-revert guarantees zero residue. Train/test separation is mandatory and structural: synth trains, real tests.

## Model / agent contract

The vectorization contract is **law**, enforced by `models/feature_keys.json`:

1. Feature source: snapshot's `features_ml` dict
2. Key order: **alphabetically sorted**
3. Missing/`null` features: masked to **0.0**
4. Orientation: all `risk_*` features oriented so **1 = insecure**

## Limitations

Stating limits up front is deliberate: a security tool that can't articulate its blind spots is a liability.

- **M02 (SSH password auth) is intentionally blurred.** Clean baselines retain password-auth noise (~30%), so the model cannot fully separate M02 from clean hosts: 1 of 12 M02 hosts missed out-of-fold. Kept deliberately to mirror real-world ambiguity; see `reports/training/eval_report.md`.
- **Trained and evaluated on synthetic data.** Real-host performance is expected to differ — we have a registered prediction that default-threshold layer nesting breaks on real hosts (clean machines carry out-of-catalog misconfigurations). The break-phase transfer test will resolve this.
- **Uncalibrated by default:** L1-only F1 = 0.646 vs. hybrid 0.969; post-calibration L1-only rises to 0.914 (hybrid 0.981). Calibration and threshold choice materially change the operating point.
- **Configuration posture only.** Not a network vulnerability scanner, IDS, or antivirus.

## Known pitfalls (institutional memory)

<details>
<summary>Internal team notes — expand if you're contributing</summary>

1. **The generator appends.** Verify `ls data/synth/*.json | wc -l == 580` after every run. Duplicates silently inflate out-of-fold metrics (twin-in-fold leakage).
2. **Relative paths assume project root** (except `eval_holdout.py`, which assumes `train/`).
3. **Multiline pastes break `\` continuations**: treat every documented command as single-line.
4. **`arb_experiment.py`'s agent-dir default** is `../agent` relative to `experiments/`; if the script moves again, a sed or manual change must be made.

</details>

## Status & next steps

- [x] Collector + 15-misconfig injection catalog (reversible, manifest-tracked)
- [x] Synthetic dataset generator (seeded, three-tier, collision-safe)
- [x] Training pipeline + evaluation artifacts
- [x] Four-layer agent with memory, feedback loop, and approval gate
- [x] Arbitration + threshold-sweep experiments
- [x] Progress presentation
- [x] Probability calibration for L1 (Platt scaling, threshold sweep to set operating point)
- [ ] Break phase: real dataset via Proxmox LXC clone loop (`gen_dataset.py` / pct workflow)
- [ ] Transfer test (`eval_holdout.py`) + arbitration rerun on real data
- [x] Rule extension R13–R15 (blind-spot-driven: PermitRootLogin, world-writable dirs, world-writable /etc)
- [ ] Planner-utility experiment (`--alpha/--beta/--gamma` sweep)
- [ ] Final report + presentation

## Roadmap

**Tier 1**
- [ ] R13–R16 remediation paths: each needs a remediation entry. Decisions to make: idempotency (rerun fix after partial fix), verification (rescan to confirm cleared), and per-backend command indirection for system agnosticism.
- [x] Pytest regression suite: formalized echo test with `tests/` dir, a known positive and negative per rule ID.
- [ ] Utility coefficient tuning: currently hand-set. Collect labeled sets of tuples and fit coefficients against outcomes.

**Tier 2**
- [ ] Real-data retraining and hybrid datasets: after break-phase training, see if hybrid real/synth changes results. Also allows better setting of synth data generation.
- [ ] Smarter arbitration: union and intersect only go so far — a middle ground with weighted fusion (severity-modulated thresholds).
- [ ] Drift detection: "posture trend line" to show how posture improves/degrades.
- [ ] Multi-host: extend planner for multiple hosts.
- [ ] Second collector backend (dnf/rpm): set up agnosticism for data collection.
- [ ] Benchmark vs. scanner: verify results against Lynis or OpenSCAP to compare and prove validity.
- [ ] If more data becomes available, consider switching from Platt scaling to isotonic regression (currently it would overfit).

**Tier 3**
- [ ] Adversarial evasion analysis: study if feature perturbations can mask a signature.
- [ ] Active data collection: agent chooses what is scanned next — given current belief state, which probe or target maximizes expected information gain about the fleet.
- [ ] Learned rule generation: mine only-L1 samples' features for predicates and propose rules automatically.
- [ ] Counterfactual explanations: for each L1 fire, compute the minimal feature change to flip the verdict.
- [ ] Distribution-shift monitoring: measure synth → real drift and track it as more real data is collected.

## References

- Russell, S. & Norvig, P. — *Artificial Intelligence: A Modern Approach*, Ch. 2 (agent taxonomy)
- Project artifacts: `reports/training/eval_report.md`, `reports/experiments/arbitration_report.md`, `reports/experiments/planner_report.md`, `Presentations/`

## License

Released under the **BSD-3-Clause License** see [LICENSE](./LICENSE).

## Responsible use

**Run AutoSecure only against systems you own or are explicitly authorized to test**: your own lab, a class environment, or infrastructure with written permission. The collector's misconfiguration injection (`collector/inject.sh`) deliberately breaks configurations; never point it at a production or third-party host.

The agent is read-only by default. Even in `--act` mode, nothing executes without explicit human approval at the gate — but always review a proposed remediation plan before approving it.

Found a security issue in AutoSecure itself? Please report it privately — see [SECURITY.md](./SECURITY.md), not a public issue.

