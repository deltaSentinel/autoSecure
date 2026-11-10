#!/usr/bin/env python3
"""Planner coefficient sweep: how do alpha/beta/gamma shape remediation plans?

Imports plan() directly from agent/main.py (single source of truth — the
experiment measures the deployed planner, not a copy). Introspects the real
REFLEX_RULES and REMEDIATION_KB at runtime.

Findings:
  - plan() returns ALL steps (no zero-filter): regimes are utility SIGN
    crossings, not membership changes.
  - N/A-action steps are tier-quarantined below action-bearing steps
    regardless of utility (sort key (action is None, -utility)).
"""
import argparse, csv, itertools, os, sqlite3, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "agent"))
from main import plan, REFLEX_RULES, REMEDIATION_KB   # noqa: E402

ALPHA = 1.0
BETAS  = [0.0, 0.25, 0.5, 1.0, 2.0, 4.0]
GAMMAS = [0.0, 0.25, 0.5, 1.0, 2.0, 4.0]


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


def run(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "planner_sweep.csv")
    per_rule = {}          # (rule, history) -> {(beta,gamma): utility}
    rows_written = 0
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "history", "beta", "gamma",
                    "n_steps", "n_positive_utility", "n_negative_utility",
                    "head_rule", "r06_utility", "na_quarantine_held"])
        for sname, sfn in SCENARIOS.items():
            findings = sfn()
            for hname, hist in HISTORIES.items():
                con = seed_con(hist)
                for beta, gamma in itertools.product(BETAS, GAMMAS):
                    steps = plan(con, findings, alpha=ALPHA,
                                 beta=beta, gamma=gamma)
                    utils = {s["rule_id"]: s["utility"] for s in steps}
                    for rid, u in utils.items():
                        per_rule.setdefault((rid, hname), {})[(beta, gamma)] = u
                    action_bearing = [s for s in steps if s["action"] is not None]
                    na = [s for s in steps if s["action"] is None]
                    # invariant: no N/A step precedes an action-bearing one
                    held = all(steps.index(a) < steps.index(b)
                               for a in action_bearing for b in na) \
                        if action_bearing and na else True
                    w.writerow([sname, hname, beta, gamma, len(steps),
                                 sum(1 for u in utils.values() if u > 0),
                                 sum(1 for u in utils.values() if u < 0),
                                 steps[0]["rule_id"] if steps else "",
                                 utils.get("R06", ""),
                                 int(held)])
                    rows_written += 1
    print(f"[+] grid -> {csv_path} ({rows_written} cells)")

    # ---- boundary analysis: beta* where utility crosses 0, per rule/history ----
    rep_path = os.path.join(out_dir, "planner_report.md")
    with open(rep_path, "w") as fh:
        fh.write("# Planner Coefficient Sweep\n\n"
                 f"- alpha fixed at {ALPHA} (pure scale factor — note, not swept)\n"
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
            cross = next(((b, grid[(b, 0.5)]) for b in BETAS
                          if (b, 0.5) in grid and grid[(b, 0.5)] < 0), None)
            if cross:
                fh.write(f"| {rid} | {hname} | beta>{cross[0]} (U={cross[1]}) "
                         f"| {analytic:.2f} |\n")
        fh.write("\n## Notes\n\n"
                 "- plan() returns all steps; 'regimes' are utility sign "
                 "crossings, not membership changes.\n"
                 "- N/A-action steps are quarantined below action-bearing "
                 "steps by construction (verified per cell in CSV col "
                 "na_quarantine_held).\n")
    print(f"[+] report -> {rep_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.pardir, "models"))
    run(ap.parse_args().out)
