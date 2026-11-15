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
