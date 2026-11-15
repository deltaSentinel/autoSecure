"""R04 regression: remediation must be generated from the observed
UID-0 account list, not the fixture-era constant 'backdoor01'."""

import main

RAW_TOOR = {"accounts": {"users_uid0_extra": ["toor"]}}
RAW_MULTI = {"accounts": {"users_uid0_extra": ["hax", "svc0"]}}


def test_action_targets_observed_account():
    action, rollback = main.build_uid0_remediation(RAW_TOOR)
    assert "userdel" in action
    assert "toor" in action
    assert "backdoor01" not in action and "backdoor01" not in rollback


def test_multi_account_covers_all_offenders():
    action, _ = main.build_uid0_remediation(RAW_MULTI)
    snapshot = action.split("&&")[0]
    for name in ("hax", "svc0"):
        assert name in action
        assert name in snapshot   # every offender captured for rollback


def test_rollback_is_faithful_restore():
    _, rollback = main.build_uid0_remediation(RAW_TOOR)
    # parses the snapshot rather than hardcoding uid/gid
    assert "IFS=:" in rollback and "useradd" in rollback
    assert "useradd -o -u 0 -g 0" not in rollback
    assert main.UID0_PASSWD_BACKUP in rollback


def test_backup_precedes_deletion():
    action, _ = main.build_uid0_remediation(RAW_TOOR)
    snapshot, deletion = action.split("&&")
    assert snapshot.strip().startswith("getent passwd toor")
    assert main.UID0_PASSWD_BACKUP in snapshot
    assert "userdel" in deletion


def test_empty_observation_is_none():
    assert main.build_uid0_remediation({}) == (None, None)
    assert main.build_uid0_remediation(
        {"accounts": {"users_uid0_extra": []}}) == (None, None)


def test_plan_end_to_end_uses_observed_names(tmp_path):
    """Wiring check: _raw flows through plan(), KB constant bypassed."""
    con = main.open_memory(str(tmp_path / "mem.db"))
    finding = {"rule_id": "R04", "layer": "L0", "severity": 1.0,
               "evidence": "test", "_raw": RAW_TOOR}
    steps = main.plan(con, [finding])
    assert steps and steps[0]["action"] and "toor" in steps[0]["action"]
    assert "backdoor01" not in steps[0]["action"]

def test_kb_has_no_hardcoded_r04():
    assert "R04" not in main.REMEDIATION_KB
