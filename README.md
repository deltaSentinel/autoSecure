# AutoSecure

![CI](https://github.com/deltaSentinel/autoSecure/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.12-blue)

AI-driven vulnerability and misconfiguration detection for personal computing environments — a four-layer hybrid agent combining hand-written reflex rules with a learned classifier, developed as a semester project for AI-472.

**Team:** Raymond Balesky — EE/CPE — 800389453 · Kayla Granger — Computer Science — 800425201

---

## What this is

AutoSecure scans a Linux host's configuration posture (SSH settings, file permissions, user accounts, firewall state, listening services), classifies the host as *clean* or *misconfigured* using a Random Forest over 25 normalized features, and proposes a utility-ranked, reversible remediation plan behind a human approval gate.

**Architecture (four layers):**

| Layer | Function | Type (Russell & Norvig) |
|-------|----------|-------------------------|
| L0 — Reflex | 12 deterministic condition→finding rules | Simple reflex |
| L1 — Classifier | Random Forest, 25-feature vector | Model-based |
| L2 — Diagnostician | Merges L0+L1 findings, drift attribution vs. prior scans | Internal state |
| L3 — Planner | Utility-ranked fixes: `severity − disruption − fp_penalty` | Utility-based |

**Safety invariants:** read-only unless `--act` is passed; `--act` requires root and hard-refuses otherwise (no silent degradation); every finding is evidence-chained; operator rejections persist and lower that rule's utility in future runs.

## Directory layout

Grouped by *where code executes* — everything under `collector/` runs on target hosts; everything else stays at the desk.

```
aiProject/
├── agent/          # main.py (four-layer harness) + mem.db runtime state
├── collector/      # collect.py, inject.sh — pushed INTO target hosts/containers
├── experiments/    # synth_dataset.py, gen_dataset.py, arb_experiment.py
├── train/          # train.py, eval_holdout.py; agent model drop point
├── data/
│   ├── synth/      # synthetic training snapshots (regenerable — seed 7)
│   └── real/       # real LXC snapshots (break phase) — NEVER mixed with synth
├── models/         # model.joblib, feature_keys.json, importances.csv,
│                   # eval_report.md, arbitration_report.md, threshold_sweep.csv
├── reports/        # agent scan reports (Markdown)
├── presentations/  # decks and appendix documents
└── README.md       # this file
```

## Environment

Python 3.12, managed with `uv`. From the project root:

```bash
uv venv && uv pip install scikit-learn joblib numpy
```

Everything else is stdlib. Whole pipeline runs offline. No GPU, no special hardware.

## Canonical commands

All commands run from the project root unless noted.

**Regenerate the synthetic training set** (seed 7 ⇒ bit-identical reproduction):

```bash
uv run python3 experiments/synth_dataset.py --out data/synth --clean 150 --singles 12 --combos 250 --seed 7
ls data/synth/*.json | wc -l   # MUST be 580 — verify after EVERY generation
```

The generator **appends** — never run it into a non-empty `data/synth/` unless you intend duplication (duplicated snapshots invalidate out-of-fold CV; see *Dataset provenance* below).

**Train:**

```bash
uv run python3 train/train.py --dataset data/synth --out models
```

Exports `model.joblib`, `feature_keys.json`, `importances.csv`, `eval_report.md`. Metrics are out-of-fold (5-fold stratified CV).

**Arbitration experiment (L0 vs L1 vs hybrid, with threshold sweep):**

```bash
uv run python3 experiments/arb_experiment.py --dataset data/synth --out models --sweep
```

Imports `evaluate_reflex` directly from `agent/main.py` — the experiment and the deployed agent share one rule catalog by construction.

**Real-data transfer test** (break phase — run from inside `train/`):

```bash
cd train && uv run python3 eval_holdout.py ../data/real && cd ..
```

Note: `eval_holdout.py` resolves `../models/` relative to its own location, so it must be launched from `train/`.

**Agent run** (read-only by default):

```bash
uv run python3 agent/main.py --snapshot <path/to/snapshot.json> --db agent/mem.db
```

Mutation mode adds `--act` (requires root; refuses otherwise) and opens the interactive approval gate. The agent looks for `train/model.joblib` — copy the trained model there after retraining:

```bash
cp models/model.joblib train/model.joblib
```

**On-target data collection** (inside a disposable LXC/VM, as root):

```bash
python3 /root/collect.py --host-id <id> --tag <tag> --label <clean|vulnerable> [--inject M01 ...] --out <dir>
```

## Dataset provenance

- **Synthetic set:** 580 snapshots = 150 clean + 180 singles (15 misconfig types × 12) + 250 random 2–4-misconfig combinations, across desktop/server/minimal host profiles. Generated with `--seed 7`; fully reproducible, therefore *not* version-controlled.
- **Label-collision fix (Nov 2026):** clean baselines originally carried strict-risk noise (firewall-down ~25%, weak password policy ~15%, etc.) identical to injected misconfig signatures, making five misconfig types unlearnable (recall 0.847). Strict-risk noise was removed from clean baselines; debatable soft risks (password auth ~30%, fail2ban absent ~80%) deliberately retained. Post-fix out-of-fold: precision 0.993, recall 0.970, ROC-AUC 0.990. M02 (SSH password auth) remains intentionally blurred — see eval report.
- **Real set (pending):** snapshots from disposable Proxmox LXC clones on HWHS-001; destroy-instead-of-revert guarantees zero residue. Train/test separation is mandatory and structural: synth trains, real tests.

## Model / agent contract

The vectorization contract is **law**, enforced by `models/feature_keys.json`:

1. Feature source: snapshot's `features_ml` dict
2. Key order: **alphabetically sorted**
3. Missing/`null` features: masked to **0.0**
4. Orientation: all `risk_*` features oriented so **1 = insecure**

## Key results (as of progress presentation)

- Out-of-fold (RF, 580 synthetic): P 0.993 / R 0.970 / F1 0.981 / AUC 0.990; 3 FP, 13 FN
- Model comparison: RF 0.981 · SVM 0.982 · LR 0.977 (F1) — architecture, not model choice, is load-bearing
- Arbitration at threshold 0.5: layers nest (L0 ⊂ L1; 62 classifier-only detections, 0 reflex-only)
- Threshold sweep: at t=0.95 hybrid F1 0.910 vs classifier-only 0.646 — the rule layer is threshold-invariant recall insurance; justifies the hybrid at strict operating points
- Registered prediction for the real-data phase: the default-threshold nesting breaks on real hosts (clean machines carry out-of-catalog misconfigurations)

## Known pitfalls (institutional memory)

1. **The generator appends.** Verify `ls data/synth/*.json | wc -l == 580` after every run. Duplicates silently inflate out-of-fold metrics (twin-in-fold leakage).
2. **Relative paths assume project root** (except `eval_holdout.py`, which assumes `train/`).
3. **Multiline pastes break `\` continuations** — treat every documented command as single-line.
4. **`arb_experiment.py`'s agent-dir default** is `../agent` relative to `experiments/` — if the script moves again, that one sed must follow.

## Status & next steps

- [x] Collector + 15-misconfig injection catalog (reversible, manifest-tracked)
- [x] Synthetic dataset generator (seeded, three-tier, collision-safe)
- [x] Training pipeline + evaluation artifacts
- [x] Four-layer agent with memory, feedback loop, and approval gate
- [x] Arbitration + threshold-sweep experiments
- [x] Progress presentation
- [ ] Break phase: real dataset via Proxmox LXC clone loop (`gen_dataset.py` / pct workflow)
- [ ] Transfer test (`eval_holdout.py`) + arbitration rerun on real data
- [x] Rule extension R13–R15 (blind-spot-driven: PermitRootLogin, world-writable dirs, world-writable /etc)
- [ ] Planner-utility experiment (`--alpha/--beta/--gamma` sweep)
- [ ] Final report + presentation

## Roadmap

**Tier 1**
- [ ] R13-R16 remediation paths: Each needs a remediation entry. Decisions to make: idempotency (rerun fix after partial fix), verification (rescan to confirm cleared), and per-backend command indirection for system agnosticism.
- [ ] Pytest regression suite: Formalize echo test with tests/ dir with a known positive and negative per rule ID.
- [ ] Probability calibration for L1: Platt scaling or isotonic regression with threshold sweep to set operating point.- Utility coefficieant tuning: Currently coefficients are hand set. Collect labeled sets of tuples and fit coefficients against outcomes

**Tier 2**
- [ ] Real-data retraining and hybrid datasets: After break-phase training see if hybrid real/synth changes results. Also allows for better setting of synth data generation
- [ ] Smarter arbitration: Union and intersect only go so far. Try and set up a middle ground with a weighted fusion (severity-modulated thresholds).
- [ ] Drift detection: "Posture trend line" to show how posture improves/degrades
- [ ] Multi-host: Extend planner for multiple hosts
- [ ] Second collector backend (dnf/rpm): Set up agnosticism for data collect 
- [ ] Benchmark vs Scanner: Verify our results against Lynis or OpenSCAP to compare results and prove validity

**Tier 3**
- [ ] Adversarial Evasion Analysis: Study if peature perturbations can mask a signature
- [ ] Active data collection: Agent chooses what is scanned next, given current belief state, which probe or target maximizes expected information gain about the fleet
- [ ] Learned rule generation: Mine only-L1 samples features for predicates and propose rules automatically
- [ ] Counterfactual explanations: For each L1 fire, compute the minimal feature change to flip the verdict
- [ ] Distribution-shift monitoring: Measure synth -> real drift and track it as more real data is collected

## References

- Russell, S. & Norvig, P. — *Artificial Intelligence: A Modern Approach*, Ch. 2 (agent taxonomy)
- Project artifacts: `models/eval_report.md`, `models/arbitration_report.md`, `presentations/`
