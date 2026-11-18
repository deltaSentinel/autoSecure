"""Learned planner-coefficient tests for agent/main.py.

Issue #8 acceptance criteria, agent side:
  - a no-flag run uses the persisted planner_coeffs.json defaults;
  - explicit --beta/--gamma flags still win over learned values;
  - a missing/corrupt/malformed artifact degrades fail-static to the
    built-in 1.0/0.5/0.75 and never blocks a scan.

Two styles, matching the existing suite:
  - loader unit tests, direct-import style like test_gate_display.py
    (conftest puts agent/ on sys.path, so 'import main' works);
  - CLI subprocess drives like test_safety_gates.py, each pointed at
    tmp_path fixtures via --coeffs/--db/--report so no project artifact
    is read or written. The real models/planner_coeffs.json (if any) is
    never consulted, so tests are order-independent.

No --act anywhere: every run is READ-ONLY by invariant 1.
"""

import json
import os
import subprocess
import sys
import sqlite3

import pytest

import main

AGENT_DIR = os.path.dirname(os.path.abspath(main.__file__))
EXPERIMENTS_DIR = os.path.join(os.path.dirname(AGENT_DIR), "experiments")
SWEEP = os.path.join(EXPERIMENTS_DIR, "planner_sweep.py")

# beta/gamma chosen off-grid (neither built-in nor a grid value) so any
# leakage from defaults or the sweep grid would show up as a mismatch.
LEARNED_BETA = 1.75
LEARNED_GAMMA = 3.25


def write_coeffs(path, beta=LEARNED_BETA, gamma=LEARNED_GAMMA, **extra):
    """Persist coefficients exactly as planner_sweep.py --db would."""
    payload = {
        "alpha": 1.0,
        "beta": beta,
        "gamma": gamma,
        "objective": "approved_utility",
        "inputs": {
            "db": "/tmp/fake_mem.db",
            "feedback_rows": 42,
            "approved_rules": ["R01", "R06"],
            "grid": {"alpha": 1.0, "betas": [0, 0.25, 0.5], "gammas": [0, 0.25]},
            "scenarios": ["all_catalog"],
            "min_feedback": 30,
            "commit": "deadbeef",
        },
    }
    payload.update(extra)
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return str(path)


def write_snapshot(tmp_path):
    """Minimal valid snapshot firing R01 and R06 (both action-bearing)."""
    snap = {
        "meta": {"host_id": "test-host", "tag": "lab",
                 "collected_at": "2026-11-17T00:00:00Z", "check_errors": []},
        "features_raw": {
            "services": {"telnet_open": True},
            "accounts": {"sudo_nopasswd_entries": ["ALL=(ALL) NOPASSWD: ALL"]},
        },
        "features_ml": {},
    }
    p = tmp_path / "snap.json"
    p.write_text(json.dumps(snap))
    return str(p)


def run_agent(snapshot, extra_args, tmp_path, run_name):
    """Drive the CLI READ-ONLY. All outputs land in tmp_path."""
    report = str(tmp_path / f"report_{run_name}.md")
    cmd = [sys.executable, os.path.join(AGENT_DIR, "main.py"),
           "--snapshot", snapshot,
           "--db", str(tmp_path / f"mem_{run_name}.db"),
           "--report", report] + extra_args
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return proc, report


def coeffs_line(stdout):
    """The '[i] planner coeffs: ...' startup line, or fail the test."""
    for line in stdout.splitlines():
        if line.startswith("[i] planner coeffs:"):
            return line
    pytest.fail("planner coeffs startup line missing from output:\n" + stdout)


def parse_value(line, key):
    """Pull 'beta=1.75' style token out of the coeffs line."""
    for tok in line.split():
        if tok.startswith(key + "="):
            return float(tok[len(key) + 1:])
    pytest.fail(f"no {key}= token in coeffs line: {line}")


# ---------------------------------------------------------------------------
# Loader unit tests (direct import, like test_gate_display.py)
# ---------------------------------------------------------------------------

def test_missing_file_falls_back_to_builtin(tmp_path):
    vals, note = main.load_planner_coeffs(str(tmp_path / "absent.json"))
    assert vals == {}
    assert "built-in defaults" in note


def test_loads_learned_beta_gamma(tmp_path):
    p = write_coeffs(tmp_path / "planner_coeffs.json")
    vals, note = main.load_planner_coeffs(p)
    assert vals == {"beta": LEARNED_BETA, "gamma": LEARNED_GAMMA}
    assert "learned defaults loaded" in note


def test_roundtrips_sweep_payload(tmp_path):
    """Loader reads exactly the keys planner_sweep.py --db persists."""
    p = write_coeffs(tmp_path / "planner_coeffs.json")
    with open(p) as fh:
        written = json.load(fh)
    vals, _ = main.load_planner_coeffs(p)
    assert vals["beta"] == written["beta"]
    assert vals["gamma"] == written["gamma"]


def test_corrupt_json_degrades_fail_static(tmp_path):
    p = tmp_path / "planner_coeffs.json"
    p.write_text("{not json")
    vals, note = main.load_planner_coeffs(str(p))
    assert vals == {}
    assert "unreadable" in note and "fail-static" in note


def test_non_numeric_beta_degrades(tmp_path):
    p = write_coeffs(tmp_path / "planner_coeffs.json", beta="high")
    vals, note = main.load_planner_coeffs(p)
    assert vals == {}
    assert "unreadable" in note


def test_boolean_beta_rejected(tmp_path):
    """bool is an int subclass in Python; it must not pass as a number."""
    p = write_coeffs(tmp_path / "planner_coeffs.json", beta=True)
    vals, _ = main.load_planner_coeffs(p)
    assert vals == {}


def test_stored_alpha_ignored_but_noted(tmp_path):
    """Alpha stays the fixed 1.0 anchor even if the artifact says else."""
    p = write_coeffs(tmp_path / "planner_coeffs.json", alpha=2.0)
    vals, note = main.load_planner_coeffs(p)
    assert vals == {"beta": LEARNED_BETA, "gamma": LEARNED_GAMMA}
    assert "alpha=2.0 ignored" in note


def test_alpha_never_loaded_into_values(tmp_path):
    p = write_coeffs(tmp_path / "planner_coeffs.json")
    vals, _ = main.load_planner_coeffs(p)
    assert set(vals) == {"beta", "gamma"}


# ---------------------------------------------------------------------------
# CLI tests (subprocess, like test_safety_gates.py)
# ---------------------------------------------------------------------------

def test_no_flag_run_uses_learned_defaults(tmp_path):
    snap = write_snapshot(tmp_path)
    coeffs = write_coeffs(tmp_path / "planner_coeffs.json")
    proc, _ = run_agent(snap, ["--coeffs", coeffs], tmp_path, "learned")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    line = coeffs_line(proc.stdout)
    assert parse_value(line, "beta") == LEARNED_BETA
    assert parse_value(line, "gamma") == LEARNED_GAMMA
    assert parse_value(line, "alpha") == 1.0
    assert "learned defaults loaded" in line
    assert "explicit CLI flags override" not in line


def test_learned_defaults_match_explicit_flag_run(tmp_path):
    """Acceptance criterion: a no-flag run must plan identically to a
    manual run passing the persisted values as explicit flags."""
    snap = write_snapshot(tmp_path)
    coeffs = write_coeffs(tmp_path / "planner_coeffs.json")
    _, report_learned = run_agent(snap, ["--coeffs", coeffs], tmp_path, "a")
    # explicit flags win over an (irrelevant) missing artifact
    _, report_manual = run_agent(
        snap, ["--coeffs", str(tmp_path / "absent.json"),
               "--beta", str(LEARNED_BETA), "--gamma", str(LEARNED_GAMMA)],
        tmp_path, "b")
    learned = open(report_learned).read().splitlines()
    manual = open(report_manual).read().splitlines()
    # identical finding set, step order, and utilities; report bodies are
    # deterministic (no wall-clock content), so compare rule/utility rows
    def plan_rows(lines):
        return [ln for ln in lines
                if ln.startswith("| ") and "Rule" not in ln]
    assert plan_rows(learned) == plan_rows(manual)
    assert len(plan_rows(learned)) == 2          # R01 + R06, both actioned
    # and with learned beta=1.75 the utilities are not the built-in ones:
    # U(R01) = 1.0*1.0 - 1.75*0.6 = -0.05
    assert "| -0.05 |" in "".join(plan_rows(learned))


def test_explicit_flags_override_learned(tmp_path):
    snap = write_snapshot(tmp_path)
    coeffs = write_coeffs(tmp_path / "planner_coeffs.json")
    proc, _ = run_agent(snap, ["--coeffs", coeffs,
                               "--beta", "0.25", "--gamma", "0.25"],
                        tmp_path, "flags")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    line = coeffs_line(proc.stdout)
    assert parse_value(line, "beta") == 0.25
    assert parse_value(line, "gamma") == 0.25
    assert "explicit CLI flags override learned values" in line


def test_corrupt_coeffs_degrade_to_builtin_without_crashing(tmp_path):
    snap = write_snapshot(tmp_path)
    coeffs = tmp_path / "planner_coeffs.json"
    coeffs.write_text("{\"beta\": ")
    proc, _ = run_agent(snap, ["--coeffs", str(coeffs)], tmp_path, "corrupt")
    assert proc.returncode == 0, proc.stdout + proc.stderr   # invariant 3
    line = coeffs_line(proc.stdout)
    assert parse_value(line, "beta") == main.BETA_DEFAULT
    assert parse_value(line, "gamma") == main.GAMMA_DEFAULT
    assert "unreadable" in line


def test_na_quarantine_survives_learned_coeffs(tmp_path):
    """Safety criterion: a learned configuration keeps N/A steps below
    action-bearing steps. R16 is N/A (count-only evidence); include it by
    faking a drift is hard, so use L1-less quarantine via KB 'L1' entry:
    instead assert the sort invariant directly on plan() with learned
    values, matching planner_sweep's na_quarantine_held check."""
    snap = write_snapshot(tmp_path)
    con = main.open_memory(str(tmp_path / "mem_plan.db"))
    findings = [
        {"rule_id": "R01", "layer": "L0", "severity": 1.0, "evidence": "t"},
        {"rule_id": "L1", "layer": "L1", "severity": 0.9, "evidence": "t"},
    ]
    steps = main.plan(con, findings, alpha=1.0,
                      beta=LEARNED_BETA, gamma=LEARNED_GAMMA)
    action_idx = [i for i, s in enumerate(steps) if s["action"] is not None]
    na_idx = [i for i, s in enumerate(steps) if s["action"] is None]
    assert all(a < b for a in action_idx for b in na_idx)

def _mini_memdb(path, rows):
    """mem.db-shaped enough for real_con(): feedback table with approve
    tuples for two rules, below the guard threshold."""
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE feedback (id INTEGER PRIMARY KEY, "
                "finding_id INTEGER, decision TEXT, rule_id TEXT, "
                "reason TEXT, ts TEXT)")
    for rid, n in rows:
        con.executemany(
            "INSERT INTO feedback(decision, rule_id, ts) "
            "VALUES ('approve', ?, datetime('now'))", [(rid,)] * n)
    con.commit()
    con.close()


def test_min_feedback_guard_preserves_existing_coeffs(tmp_path):
    """Issue #8: below the small-sample threshold the sweep must not
    touch an already-persisted planner_coeffs.json, and the report must
    say why."""
    db = _mini_memdb(tmp_path / "mem.db",
                     [("R01", 3), ("R06", 2)])       # 5 rows < 30
    coeffs = tmp_path / "planner_coeffs.json"
    original = json.dumps({"alpha": 1.0, "beta": 0.75, "gamma": 1.25,
                           "objective": "manual"}, indent=2, sort_keys=True)
    coeffs.write_text(original)

    out = tmp_path / "reports"
    proc = subprocess.run(
        [sys.executable, SWEEP,
         "--db", str(tmp_path / "mem.db"),
         "--min-feedback", "30",
         "--coeffs-out", str(coeffs),
         "--out", str(out)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    # the acceptance criterion: byte-identical, not just present
    assert coeffs.read_text() == original
    # and the report says so instead of recommending noise
    report = (out / "planner_report.md").read_text()
    assert "SKIPPED" in report
    assert "below min_feedback" in report
    assert "no coefficients written" in proc.stdout
