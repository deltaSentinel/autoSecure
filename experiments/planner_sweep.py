#!/usr/bin/env python3
"""Planner coefficient sweep: how do alpha/beta/gamma shape remediation plans?

Imports plan() directly from agent/main.py (single source of truth: the
experiment measures the deployed planner, not a copy). Introspects the real
REFLEX_RULES and REMEDIATION_KB at runtime.

Findings:
  - plan() returns ALL steps (no zero-filter): regimes are utility SIGN
    crossings, not membership changes.
  - N/A-action steps are tier-quarantined below action-bearing steps
    regardless of utility (sort key (action is None, -utility)).

Modes:
  - synthetic (default): seeds in-memory feedback histories. Regression/CI
    mode. Never writes planner_coeffs.json, so it cannot clobber learned
    values from a real run.
  - real (--db PATH): loads the operator feedback table from a real mem.db
    (read-only), ranks grid cells by an objective, and persists the winning
    beta/gamma to models/planner_coeffs.json alongside model.joblib. Alpha
    stays fixed at 1.0 as the normalization anchor; only beta and gamma are
    learned.

Safety: in real mode the DB is opened read-only (the sweep only reads the
feedback table via fp_penalty()), and candidate cells that break the
N/A-quarantine invariant are excluded from selection. Below the
small-sample threshold the tool recommends nothing and leaves current
defaults (and any previously persisted coefficients) untouched.
"""
import argparse, csv, itertools, json, os, shutil, sqlite3, subprocess, sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, os.pardir, "agent"))
from main import plan, REFLEX_RULES, REMEDIATION_KB   # noqa: E402

from datetime import datetime
STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

ALPHA = 1.0
BETAS  = [0.0, 0.25, 0.5, 1.0, 2.0, 4.0]
GAMMAS = [0.0, 0.25, 0.5, 1.0, 2.0, 4.0]

DEFAULT_OUT    = os.path.join(BASE, os.pardir, "reports", "experiments")
DEFAULT_COEFFS = os.path.join(BASE, os.pardir, "models", "planner_coeffs.json")


def seed_con(history):
    """In-memory DB with just the feedback table fp_penalty() queries.

    History: list of (rule_id, decision, n) tuples. row_factory must be Row
    (fp_penalty accesses columns by name).
    """
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE feedback (id INTEGER PRIMARY KEY, "
                "finding_id INTEGER, decision TEXT, rule_id TEXT, "
                "reason TEXT, ts TEXT)")
    for rid, dec, n in history:
        con.executemany("INSERT INTO feedback(decision, rule_id, ts) "
                        "VALUES (?,?,datetime('now'))",
                        [(dec, rid)] * n)
    return con


def real_con(db_path):
    """Read-only connection to a real mem.db. Only the feedback table is
    touched (by fp_penalty()), so ro mode can never mutate operator data."""
    if not os.path.exists(db_path):
        sys.exit(f"[!] no such db: {db_path}")
    uri = "file:" + os.path.abspath(db_path).replace("\\", "/") + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    try:
        con.execute("SELECT 1 FROM feedback LIMIT 1")
    except sqlite3.DatabaseError:
        sys.exit(f"[!] {db_path} has no readable feedback table "
                 "(run agent/main.py first)")
    return con


def git_commit():
    """Best-effort commit hash for the report; 'unknown' outside a repo."""
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"],
                             cwd=BASE, capture_output=True, text=True,
                             check=True)
        return out.stdout.strip()
    except Exception:
        return "unknown"


def quarantine_held(steps):
    """Invariant: no N/A-action step precedes an action-bearing one."""
    action_idx = [i for i, s in enumerate(steps) if s["action"] is not None]
    na_idx = [i for i, s in enumerate(steps) if s["action"] is None]
    if not action_idx or not na_idx:
        return True
    return all(a < b for a in action_idx for b in na_idx)


def catalog_findings():
    """Findings for every catalog rule, at catalog severities."""
    return [{"rule_id": r[0], "layer": "L0", "severity": r[2],
             "evidence": f"sweep fixture for {r[0]}"} for r in REFLEX_RULES]


SCENARIOS = {
    "single_R06": lambda: [f for f in catalog_findings() if f["rule_id"] == "R06"],
    "high_trio":  lambda: [f for f in catalog_findings()
                           if f["rule_id"] in ("R04", "R13", "R15")],
    "all_catalog": catalog_findings,
    "L1_only":    lambda: [{"rule_id": "L1", "layer": "L1",
                            "severity": 0.9, "evidence": "classifier-only"}],
}

HISTORIES = {
    "no_feedback":    [],
    "R06_rej_2of3":   [("R06", "reject", 2), ("R06", "approve", 1)],
    "half_rejected":  [(r[0], "reject", 1) for r in REFLEX_RULES[::2]],
}


# --------------------------------------------------------------------------
# Synthetic mode (unchanged behavior; regression/CI)
# --------------------------------------------------------------------------

def run_synthetic(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    hist = os.path.join(out_dir, "history")
    os.makedirs(hist, exist_ok=True)
    csv_path = os.path.join(out_dir, "planner_sweep.csv")
    hist_csv = os.path.join(hist, f"planner_sweep_{STAMP}.csv")
    per_rule = {}          # (rule, history) -> {(beta,gamma): utility}
    rows_written = 0
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "history", "beta", "gamma",
                    "n_steps", "n_positive_utility", "n_negative_utility",
                    "head_rule", "r06_utility", "na_quarantine_held"])
        for sname, sfn in SCENARIOS.items():
            findings = sfn()
            for hname, hist_rows in HISTORIES.items():
                con = seed_con(hist_rows)
                for beta, gamma in itertools.product(BETAS, GAMMAS):
                    steps = plan(con, findings, alpha=ALPHA,
                                 beta=beta, gamma=gamma)
                    utils = {s["rule_id"]: s["utility"] for s in steps}
                    for rid, u in utils.items():
                        per_rule.setdefault((rid, hname), {})[(beta, gamma)] = u
                    w.writerow([sname, hname, beta, gamma, len(steps),
                                 sum(1 for u in utils.values() if u > 0),
                                 sum(1 for u in utils.values() if u < 0),
                                 steps[0]["rule_id"] if steps else "",
                                 utils.get("R06", ""),
                                 int(quarantine_held(steps))])
                    rows_written += 1
    print(f"[+] grid -> {csv_path} ({rows_written} cells)")

    # ---- boundary analysis: beta* where utility crosses 0, per rule/history ----
    rep_path = os.path.join(out_dir, "planner_report.md")
    with open(rep_path, "w") as fh:
        fh.write("# Planner Coefficient Sweep\n\n"
                 f"- alpha fixed at {ALPHA} (pure scale factor, not swept)\n"
                 f"- beta, gamma in {{0, 0.25, 0.5, 1, 2, 4}} ({len(BETAS)*len(GAMMAS)} cells)\n"
                 f"- scenarios: {', '.join(SCENARIOS)} | histories: {', '.join(HISTORIES)}\n\n"
                 "## Utility zero-crossings (beta* at gamma=0.5)\n\n"
                 "| Rule | history | beta* (measured) | beta* (analytic) |\n"
                 "|---|---|---|---|\n")
        for (rid, hname), grid in sorted(per_rule.items()):
            if rid not in REMEDIATION_KB or REMEDIATION_KB[rid][2] in (None, 0):
                continue    # unregistered / zero-cost rules never cross
            sev = next(r[2] for r in REFLEX_RULES if r[0] == rid)
            disrupt = REMEDIATION_KB[rid][2]
            con = seed_con(HISTORIES[hname])
            # penalty computed directly:
            row = con.execute("SELECT COUNT(*) total, "
                              "SUM(CASE WHEN decision='reject' THEN 1 ELSE 0 END) rej "
                              "FROM feedback WHERE rule_id=?", (rid,)).fetchone()
            penalty = row["rej"] / row["total"] if row["total"] else 0.0
            analytic = (ALPHA * sev - 0.5 * penalty) / disrupt
            # measured: first beta in BETAS where utility < 0 at gamma=0.5
            uvals = [(b, grid[(b, 0.5)]) for b in BETAS if (b, 0.5) in grid]
            neg = next((x for x in uvals if x[1] < 0), None)
            if neg:
                pos = max((x for x in uvals if x[1] >= 0),
                          key=lambda x: x[0], default=None)
                bracket = (f"({pos[0]}, {neg[0]}]" if pos else f"<= {neg[0]}")
                fh.write(f"| {rid} | {hname} | beta in {bracket} "
                         f"(U={neg[1]} at {neg[0]}) | {analytic:.2f} |\n")
        fh.write("\n## Notes\n\n"
                 "- plan() returns all steps; 'regimes' are utility sign "
                 "crossings, not membership changes.\n"
                 "- N/A-action steps are quarantined below action-bearing "
                 "steps by construction (verified per cell in CSV col "
                 "na_quarantine_held).\n")
        fh.write("- Measured column is a grid bracket: the true crossing is "
                 "within it; the analytic column (exact, U linear in beta) "
                 "is the precise value.\n")
    print(f"[+] report -> {rep_path}")
    shutil.copy2(csv_path, hist_csv)
    shutil.copy2(rep_path, os.path.join(hist, f"planner_report_{STAMP}.md"))
    print(f"[+] history -> {hist}/ (*_{STAMP})")
    print("[i] synthetic mode: planner_coeffs.json intentionally not "
          "written (regression/CI path)")


# --------------------------------------------------------------------------
# Real mode (--db): sweep against operator feedback, recommend, persist
# --------------------------------------------------------------------------

def rank_cells(per_cell, objective):
    """Total order over cells so repeated runs pick identical winners.

    approved_utility: maximize summed utility of operator-approved rules;
    min_negative: minimize approved steps landing below zero utility.
    Ties: prefer fewer approved negatives, then smaller beta, then smaller
    gamma (simpler cells win, output is fully deterministic).
    """
    def sort_key(item):
        (beta, gamma), st = item
        if objective == "approved_utility":
            return (-st["approved_utility"], st["approved_negatives"],
                    beta, gamma)
        return (st["approved_negatives"], -st["approved_utility"],
                beta, gamma)
    return sorted(per_cell.items(), key=sort_key)


def run_real(out_dir, db_path, objective, min_feedback, coeffs_path):
    os.makedirs(out_dir, exist_ok=True)
    hist = os.path.join(out_dir, "history")
    os.makedirs(hist, exist_ok=True)
    csv_path = os.path.join(out_dir, "planner_sweep.csv")
    rep_path = os.path.join(out_dir, "planner_report.md")

    con = real_con(db_path)
    total = con.execute("SELECT COUNT(*) AS n FROM feedback").fetchone()["n"]
    approved_rules = {r["rule_id"] for r in con.execute(
        "SELECT DISTINCT rule_id FROM feedback WHERE decision='approve'")}
    commit = git_commit()

    # aggregate per grid cell, summed across scenarios
    per_cell = {}
    rows_written = 0
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "history", "beta", "gamma",
                    "n_steps", "n_positive_utility", "n_negative_utility",
                    "head_rule", "r06_utility", "na_quarantine_held"])
        for sname, sfn in SCENARIOS.items():
            findings = sfn()
            for beta, gamma in itertools.product(BETAS, GAMMAS):
                steps = plan(con, findings, alpha=ALPHA,
                             beta=beta, gamma=gamma)
                utils = {s["rule_id"]: s["utility"] for s in steps}
                st = per_cell.setdefault(
                    (beta, gamma),
                    {"approved_utility": 0.0, "approved_negatives": 0,
                     "held": True})
                au = sum(u for rid, u in utils.items()
                         if rid in approved_rules)
                nneg = sum(1 for rid, u in utils.items()
                           if rid in approved_rules and u < 0)
                st["approved_utility"] += au
                st["approved_negatives"] += nneg
                held = quarantine_held(steps)
                st["held"] = st["held"] and held
                w.writerow([sname, "real_db", beta, gamma, len(steps),
                            sum(1 for u in utils.values() if u > 0),
                            sum(1 for u in utils.values() if u < 0),
                            steps[0]["rule_id"] if steps else "",
                            utils.get("R06", ""),
                            int(held)])
                rows_written += 1
    print(f"[+] grid -> {csv_path} ({rows_written} cells)")

    # invariant-safe candidates only
    candidates = {k: v for k, v in per_cell.items() if v["held"]}
    ranked = rank_cells(candidates, objective)

    guarded = total < min_feedback
    rec_lines = [
        "# Planner Coefficient Sweep (real feedback)\n",
        "## Inputs\n",
        f"- db: {os.path.abspath(db_path)} (opened read-only)",
        f"- feedback rows: {total}",
        f"- approved rules: {', '.join(sorted(approved_rules)) or 'none'}",
        f"- objective: {objective}",
        f"- grid: beta, gamma in {{0, 0.25, 0.5, 1, 2, 4}} "
        f"({len(BETAS)*len(GAMMAS)} cells, alpha fixed at {ALPHA})",
        f"- scenarios: {', '.join(SCENARIOS)}",
        f"- min_feedback guard: {min_feedback}",
        f"- commit: {commit}\n",
        "## Recommendation\n",
    ]
    if guarded:
        rec_lines.append(
            f"SKIPPED: feedback rows ({total}) below min_feedback "
            f"({min_feedback}). Current defaults kept; "
            f"{coeffs_path} was not written or overwritten. Collect more "
            "operator feedback tuples before recommending.\n")
        print(f"[!] small-sample guard tripped ({total} < {min_feedback}): "
              "no coefficients written")
    elif not ranked:
        rec_lines.append(
            "SKIPPED: no grid cell satisfied the N/A-quarantine invariant. "
            "Defaults kept; investigate before recommending anything.\n")
        print("[!] no invariant-safe cell: no coefficients written")
    else:
        (beta, gamma), st = ranked[0]
        rec_lines.extend([
            f"- recommended beta = {beta}, gamma = {gamma} "
            f"(alpha fixed at {ALPHA})",
            f"- scored: approved_utility = {st['approved_utility']}, "
            f"approved_negatives = {st['approved_negatives']}",
            "- N/A-quarantine invariant held in every scenario for this "
            "cell (na_quarantine_held = 1 throughout).",
            f"- persisted to: {coeffs_path}\n"])
        # reproducible: no timestamps inside the coefficients file, so
        # repeated runs on identical inputs produce an identical artifact
        payload = {
            "alpha": ALPHA,
            "beta": beta,
            "gamma": gamma,
            "objective": objective,
            "inputs": {
                "db": os.path.abspath(db_path),
                "feedback_rows": total,
                "approved_rules": sorted(approved_rules),
                "grid": {"alpha": ALPHA, "betas": BETAS, "gammas": GAMMAS},
                "scenarios": list(SCENARIOS),
                "min_feedback": min_feedback,
                "commit": commit,
            },
            "note": "Loaded by agent/main.py as planner defaults; explicit "
                    "CLI flags still override.",
        }
        os.makedirs(os.path.dirname(os.path.abspath(coeffs_path)),
                    exist_ok=True)
        with open(coeffs_path, "w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"[+] coefficients -> {coeffs_path} "
              f"(beta={beta}, gamma={gamma})")
    rec_lines.extend([
        "\n## Notes\n",
        "- Ranking is a total order over the finite grid (objective, then "
        "approved negatives, then smaller beta/gamma), so repeated runs on "
        "identical inputs yield identical coefficients.",
        "- Utility here cannot distinguish 'action was wrong' from 'finding "
        "was a false positive'; the feedback table records decisions only."])

    with open(rep_path, "w") as fh:
        fh.write("\n".join(rec_lines) + "\n")
    print(f"[+] report -> {rep_path}")
    shutil.copy2(csv_path, os.path.join(hist, f"planner_sweep_{STAMP}.csv"))
    shutil.copy2(rep_path, os.path.join(hist, f"planner_report_{STAMP}.md"))
    print(f"[+] history -> {hist}/ (*_{STAMP})")


def run(out_dir, db_path, objective, min_feedback, coeffs_path):
    if db_path:
        run_real(out_dir, db_path, objective, min_feedback, coeffs_path)
    else:
        run_synthetic(out_dir)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Sweep planner coefficients; recommend and persist "
                    "winners when --db is given.")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="output directory for CSV/report")
    ap.add_argument("--db", default=None,
                    help="real mem.db with an operator feedback table; "
                         "enables recommendation mode (read-only)")
    ap.add_argument("--objective", default="approved_utility",
                    choices=["approved_utility", "min_negative"],
                    help="approved_utility: maximize summed utility of "
                         "operator-approved rules; min_negative: minimize "
                         "approved steps with negative utility")
    ap.add_argument("--min-feedback", type=int, default=30,
                    help="small-sample guard: skip recommendation below "
                         "this many feedback rows (default 30)")
    ap.add_argument("--coeffs-out", default=DEFAULT_COEFFS,
                    help="where to persist winning coefficients in real mode")
    args = ap.parse_args()
    run(args.out, args.db, args.objective, args.min_feedback, args.coeffs_out)

