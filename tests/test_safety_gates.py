"""Safety-gate regression tests for agent/main.py.

These enforce the invariants documented in the module docstring of
agent/main.py at CI time:

  1. READ-ONLY BY DEFAULT   -- no mutation without --act
  2. --act requires root    -- hard refusal otherwise (no silent degradation)
  3. FAIL-STATIC L1         -- missing model degrades gracefully, never crashes

They invoke the agent CLI as a subprocess so the real argument parsing and
exit paths are exercised, not reimplemented.

Fixture strategy:
  The gate tests need findings to EXIST, because the agent evaluates the
  --act branch (and prints the "PROPOSED only" notice) only when findings
  were produced. Rather than depending on committed fixtures whose findings
  depend on the trained classifier's probability (scan_m11.json is NOT
  reflex-visible: M11 raises risk_suid_binaries, and no L0 rule covers
  SUID — R16 is drift-based and needs a prior scan), these tests construct
  a snapshot with a guaranteed L0 firing (telnet open -> R01, sev 1.0).

Notes:
  * Runs must happen in a non-root environment for test_approval_gate_requires_root.
    CI runners satisfy this; locally under sudo the test skips itself.
  * --db and --report are redirected to tmp_path so tests never dirty the
    repository's agent/mem.db or reports/ tree.
"""

import json
import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).parents[1]
AGENT = ROOT / "agent" / "main.py"
FIXTURE_CLEAN = ROOT / "tests" / "fixtures" / "scan_clean.json"

SUBPROC_TIMEOUT = 120  # seconds; agent is lightweight, generous ceiling

# A guaranteed reflex-visible misconfiguration: R01 fires on
# features_raw.services.telnet_open == True, independent of the classifier.
TELENET_OPEN_SNAP = {
    "meta": {
        "host_id": "test-host",
        "tag": "gate-test",
        "collected_at": "2026-01-01T00:00:00Z",
        "check_errors": [],
        "synthetic": True,
    },
    "features_raw": {
        "ssh": {"permit_root_login": "no", "password_authentication": "no",
                "permit_empty_passwords": "no"},
        "filesystem": {"shadow_permissions": "640",
                       "world_writable_files_in_etc": 0,
                       "world_writable_dirs_no_sticky": 0,
                       "suid_binaries": 200},
        "accounts": {"users_uid0_extra": [], "users_empty_password": [],
                     "sudo_nopasswd_entries": []},
        "login_defs": {"pass_min_len": 12},
        "network_defense": {"firewall_active": True},
        "updating": {"unattended_upgrades_enabled": True},
        "services": {"telnet_open": True, "ftp_open": False, "snmp_open": False,
                     "listening_ports": [22, 23]},
    },
    "features_ml": {
        "risk_telnet_open": 1,
        "risk_ssh_permit_root_login": 0,
        "risk_ssh_empty_passwords": 0,
        "risk_shadow_group_writable": 0,
        "risk_users_empty_password": 0,
        "risk_sudo_nopasswd": 0,
        "risk_users_uid0_extra": 0,
        "risk_weak_password_policy": 0,
        "risk_firewall_disabled": 0,
        "risk_autoupdates_disabled": 0,
        "risk_world_writable_dirs_no_sticky": 0,
        "risk_world_writable_etc_files": 0,
        "num_listening_ports": 2,
        "num_running_services": 10,
        "num_accounts_with_shell": 2,
    },
}


def run_agent(*args, cwd=None):
    return subprocess.run(
        [sys.executable, str(AGENT), *args],
        cwd=cwd or str(ROOT),
        capture_output=True,
        text=True,
        timeout=SUBPROC_TIMEOUT,
    )


@pytest.fixture
def run_dir(tmp_path):
    """Scratch directory for per-test memory DBs and reports."""
    d = tmp_path / "run"
    d.mkdir()
    return d


@pytest.fixture
def finding_snapshot(run_dir):
    """Snapshot guaranteed to produce an L0 finding (R01: telnet open)."""
    p = run_dir / "snapshot_finding.json"
    p.write_text(json.dumps(TELENET_OPEN_SNAP))
    return str(p)


# ---------------------------------------------------------------------------
# Invariant: --yes-all without --act must refuse (silent-mutation guard)
# ---------------------------------------------------------------------------

def test_yes_all_requires_act(run_dir, finding_snapshot):
    r = run_agent(
        "--snapshot", finding_snapshot,
        "--db", str(run_dir / "mem.db"),
        "--report", str(run_dir / "report.md"),
        "--yes-all",
    )
    assert r.returncode != 0, (
        "--yes-all without --act must exit non-zero (refusing silent mutation)"
    )
    assert "yes-all" in r.stderr.lower(), (
        f"refusal message should mention --yes-all; stderr was: {r.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Invariant: --act requires root (hard refusal, no degradation)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="--act refusal only triggers when not root; cannot test as root",
)
def test_act_requires_root(run_dir, finding_snapshot):
    # The root check is evaluated only when findings exist, so the snapshot
    # must guarantee an L0 firing (R01 via telnet_open).
    r = run_agent(
        "--snapshot", finding_snapshot,
        "--db", str(run_dir / "mem.db"),
        "--report", str(run_dir / "report.md"),
        "--act",
    )
    assert r.returncode != 0, (
        f"--act without root must exit non-zero (hard refusal, no fallback). "
        f"stdout was: {r.stdout!r}"
    )
    assert "root" in r.stderr.lower(), (
        f"refusal message should mention root; stderr was: {r.stderr!r}"
    )
    # Hard refusal means zero side effects: no approvals, no executions.
    assert "approval gate closed" not in r.stdout


# ---------------------------------------------------------------------------
# Invariant: fail-static L1 — missing model degrades and reports, never crashes
# ---------------------------------------------------------------------------

def test_missing_model_is_fail_static(run_dir):
    r = run_agent(
        "--snapshot", str(FIXTURE_CLEAN),
        "--db", str(run_dir / "mem.db"),
        "--report", str(run_dir / "report.md"),
        "--model", str(run_dir / "does_not_exist.joblib"),
    )
    assert r.returncode == 0, (
        f"absent model must degrade, not crash. stderr: {r.stderr!r}"
    )

    # The agent emits its summary as a JSON block on stdout.
    try:
        result = json.loads(r.stdout[r.stdout.index("{"): r.stdout.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        pytest.fail(f"could not parse agent summary JSON from stdout: {r.stdout!r}")

    assert "fail-static" in result["l1_status"].lower() or \
           "model absent" in result["l1_status"].lower() or \
           "disabled" in result["l1_status"].lower(), (
        f"L1 should report disabled/absent, got: {result['l1_status']!r}"
    )
    assert result["classifier_p_vulnerable"] is None, (
        "degraded L1 must not fabricate a probability (fail-static, no guessing)"
    )

    # The assessment itself is unaffected: report was written, verdict exists.
    assert pathlib.Path(result["report"]).exists(), (
        "read-only assessment report must still be produced with L1 off"
    )


# ---------------------------------------------------------------------------
# Invariant: default run is read-only — no --act means no approval gate
# ---------------------------------------------------------------------------

def test_default_run_never_enters_approval_gate(run_dir, finding_snapshot):
    r = run_agent(
        "--snapshot", finding_snapshot,
        "--db", str(run_dir / "mem.db"),
        "--report", str(run_dir / "report.md"),
    )
    assert r.returncode == 0
    assert "PROPOSED only" in r.stdout, (
        "run without --act must leave the plan as proposals only; "
        f"stdout was: {r.stdout!r}"
    )
    assert "approval gate closed" not in r.stdout

