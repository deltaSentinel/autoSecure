"""Gate-display honesty tests for agent/main.py execute_plan.

Invariant 2 (REVERSIBILITY) requires the approval gate to tell the truth
about rollback BEFORE the operator consents. Regression guard for the fix
of the '(file backup taken)' substitution, which previously displayed a
claimed backup for steps where _backup_paths() copies nothing (R03).

These are unit tests for the gate renderer, unlike test_safety_gates.py
(which drives the CLI as a subprocess to test exit paths) and test_r04_
dynamic.py (direct-import style, followed here). The interactive gate
cannot be reached non-interactively through the CLI: --act refuses when
non-root, so exercise execute_plan directly.
"""

import pytest
import main

def _step(rule, action, rollback=None, disrupt=0.5):
    return {"rule_id": rule, "severity": 1.0, "utility": 0.5,
            "action": action, "rollback": rollback,
            "disruptiveness": disrupt, "rationale": "t", "evidence": "t"}

@pytest.fixture
def con(tmp_path):
    return main.open_memory(str(tmp_path / "mem.db"))

def test_gate_admits_when_no_backup_exists(con, capsys, monkeypatch):
    """No rollback cmd + no bare-path tokens -> stark NONE message, and
    never the false '(file backup taken)'."""
    step = _step("R03", "passwd -l nobody")   # no /-prefixed tokens
    answers = iter(["n", "not today"])
    monkeypatch.setattr("builtins.input", lambda p="": next(answers))
    main.execute_plan(con, 1, {"R03": None}, [step])
    out = capsys.readouterr().out
    assert "no rollback command and no backup candidate" in out
    assert "(file backup taken" not in out

def test_gate_shows_real_backup_candidate(con, capsys, monkeypatch, tmp_path):
    """Rollback=None but action touches an existing file -> the gate shows
    the file as the backup candidate."""
    cfg = tmp_path / "shadow"; cfg.write_text("root:x:0:0")
    step = _step("R02", f"chmod 0640 {cfg}")
    answers = iter(["n", "stop"])
    monkeypatch.setattr("builtins.input", lambda p="": next(answers))
    main.execute_plan(con, 1, {"R02": None}, [step])
    out = capsys.readouterr().out
    assert "file backup taken at execution" in out and str(cfg) in out

def test_approved_state_precedes_execution(con, monkeypatch):
    """Invariant 4: consent is durably recorded before mutation."""
    step = _step("R01", "true")
    monkeypatch.setattr("builtins.input", lambda p="": "y")
    monkeypatch.setattr(main.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    main.execute_plan(con, 1, {"R01": None}, [step])
    row = con.execute("SELECT state FROM actions").fetchone()
    assert row["state"] == "failed"  # crashed AFTER consent...
    fb = con.execute("SELECT * FROM actions WHERE state='approved'").fetchone()
    assert fb is None  # ...transitioned through approved, not stuck at proposed

def test_in_gate_rollback_success(con, monkeypatch):
    step = _step("R08", "ufw enable", rollback="ufw disable")
    inputs = iter(["y", "y"])          # approve action, then approve rollback
    monkeypatch.setattr("builtins.input", lambda p="": next(inputs))
    monkeypatch.setattr(main, "AGENT_BACKUP_DIR",
                        str(main.os.path.join("/tmp", "as-backup-test")))
    class R: returncode = 0; stdout = ""; stderr = ""
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: R())
    main.execute_plan(con, 1, {"R08": None}, [step])
    assert con.execute(
        "SELECT state FROM actions").fetchone()["state"] == "rolled_back"


def test_in_gate_rollback_failure_keeps_executed(con, monkeypatch):
    step = _step("R08", "ufw enable", rollback="ufw disable")
    inputs = iter(["y", "y"])
    monkeypatch.setattr("builtins.input", lambda p="": next(inputs))
    class R: returncode = 0; stdout = ""; stderr = ""   # forward ok
    class RB: returncode = 1; stdout = ""; stderr = "boom"
    monkeypatch.setattr(main.subprocess, "run",
                        lambda cmd, **k: RB() if "disable" in cmd else R())
    monkeypatch.setattr(main, "AGENT_BACKUP_DIR",
                        str(main.os.path.join("/tmp", "as-backup-test")))
    main.execute_plan(con, 1, {"R08": None}, [step])
    row = con.execute("SELECT state, output FROM actions").fetchone()
    assert row["state"] == "executed" and "rollback FAILED" in row["output"]
