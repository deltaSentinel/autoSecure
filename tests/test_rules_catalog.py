"""Catalog regression: every reflex rule fires on its positive and stays silent on clean.
Each positive fixture is derived from the rule's actual lambda condition (verified against
agent/main.py REFLEX_RULES) — not guessed from feature names."""
import pytest
import main  # agent/main.py, made importable by conftest.py

CATALOG = main.REFLEX_RULES

CLEAN = {
    "ssh": {"permit_root_login": "no", "password_authentication": "no",
            "permit_empty_passwords": "no"},
    "filesystem": {"shadow_permissions": "640", "world_writable_files_in_etc": 0,
                   "world_writable_dirs_no_sticky": 0, "suid_binaries": 210},
    "accounts": {"users_uid0_extra": [], "users_empty_password": [],
                 "sudo_nopasswd_entries": [], "accounts_with_login_shell": []},
    "login_defs": {"pass_min_len": 10, "pass_max_days": 90},
    "network_defense": {"firewall_active": True, "fail2ban_active": False},
    "updating": {"unattended_upgrades_enabled": True},
    "services": {"telnet_open": False, "ftp_open": False, "snmp_open": False,
                 "listening_ports": [22]},
}

def _merged(**overrides):
    raw = {k: dict(v) if isinstance(v, dict) else v for k, v in CLEAN.items()}
    for section, kv in overrides.items():
        raw[section] = {**raw.get(section, {}), **kv}
    return raw

POSITIVE_CASES = {
    "R01": _merged(services={"telnet_open": True}),                     # is True — literal required
    "R02": _merged(filesystem={"shadow_permissions": "646"}),            # 0o646 & 0o022 != 0
    "R03": _merged(accounts={"users_empty_password": ["svc_guest"]}),
    "R04": _merged(accounts={"users_uid0_extra": ["backdoor"]}),
    "R05": _merged(ssh={"permit_empty_passwords": "yes"}),
    "R06": _merged(accounts={"sudo_nopasswd_entries": ["user ALL=(ALL) NOPASSWD:ALL"]}),
    "R08": _merged(network_defense={"firewall_active": False}),         # is False — literal required
    "R09": _merged(login_defs={"pass_min_len": 5}),                     # < 8
    "R10": _merged(updating={"unattended_upgrades_enabled": False}),     # is False — literal required
    "R11": _merged(services={"ftp_open": True}),
    "R12": _merged(services={"snmp_open": True}),
    "R13": _merged(ssh={"permit_root_login": "yes"}),
    "R14": _merged(filesystem={"world_writable_dirs_no_sticky": 2}),
    "R15": _merged(filesystem={"world_writable_files_in_etc": 2}),
}

def _evaluate(raw):
    return [f["rule_id"] for f in main.evaluate_reflex(raw)]

def test_completeness_every_rule_has_a_positive():
    ids = {r[0] for r in CATALOG}
    missing = ids - set(POSITIVE_CASES)
    assert not missing, f"rules without firing tests (silent-death risk): {sorted(missing)}"

def test_clean_baseline_fires_nothing():
    fired = _evaluate(CLEAN)
    assert fired == [], f"FP REGRESSION on clean baseline: {fired}"

@pytest.mark.parametrize("rule_id", list(POSITIVE_CASES))
def test_rule_fires_on_positive(rule_id):
    assert rule_id in _evaluate(POSITIVE_CASES[rule_id]), f"DEAD RULE: {rule_id} did not fire"

@pytest.mark.parametrize("rule_id", list(POSITIVE_CASES))
def test_rule_is_sole_finding_on_positive(rule_id):
    fired = _evaluate(POSITIVE_CASES[rule_id])
    assert fired == [rule_id], f"cascade firing: expected [{rule_id}], got {fired}"
