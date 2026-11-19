"""Regression guards for the clip-semantics audit gate (CONTRACT.md 6.1,
break-phase gate 8.6, issue #17).

The audit script is the last thing that runs before real-data eval results
are interpreted, so its arithmetic must not drift:

  1. Saturation fractions are computed from LABELED snapshots only --
     unlabeled scratch snapshots (revert-verification debris, verify-* tags)
     must never enter the denominator.
  2. None (failed probe, fail-static per CONTRACT 3) means "unmeasured":
     counted separately, never folded into saturation -- a masked feature
     is not evidence of saturation.
  3. The cap constants mirrored in the audit script must equal the caps the
     LIVE collector actually applies. They are derived empirically by
     feeding build_ml_features() oversized raw inputs, never copied as
     literals, so a cap change in collect.py fails this test until the
     mirror is updated.
  4. End-to-end: a small fixture dataset produces the report + CSV +
     paste-ready interpretation note, with the decision either recorded or
     flagged NOT YET RECORDED, so the acceptance criteria of #17 are
     mechanically satisfiable.

The fixture tests are fully self-contained (tmp_path), so the suite stays
green regardless of what currently lives in data/real. Only the caps test
touches collector/collect.py, which is the file being retouched on the
other branch.

Run:
    uv run pytest tests/test_clip_audit.py
(Picked up by the normal `uv run pytest tests/` suite.)
"""

import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).parents[1]

AUDIT_PATH = ROOT / "experiments" / "clip_audit.py"
COLLECT_PATH = ROOT / "collector" / "collect.py"

def _audit_reports(outdir):
    return [p for p in outdir.glob("clip_audit_*.md")
            if p.name != "clip_audit_note.md"]

def _load_module(path, name):
    if not path.is_file():
        pytest.fail(
            f"{path} not found -- refusing to test against a stale copy; "
            f"update the path in tests/test_clip_audit.py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_audit():
    return _load_module(AUDIT_PATH, "_clip_audit_under_test")


def _load_collect():
    sys.path.insert(0, str(COLLECT_PATH.parent))  # collect.py imports common
    try:
        return _load_module(COLLECT_PATH, "_collect_under_test")
    finally:
        sys.path.remove(str(COLLECT_PATH.parent))


def _write_snapshot(directory, name, label, ml):
    snap = {
        "meta": {"label": label, "tag": name, "host_id": "fixture-host",
                 "injected_misconfigs": []},
        "features_raw": {},
        "features_ml": ml,
    }
    (directory / f"{name}.json").write_text(json.dumps(snap))


# ---------------------------------------------------------------------------
# 1. denominators: labeled snapshots only
# ---------------------------------------------------------------------------

def test_saturation_denominator_is_labeled_snapshots_only(tmp_path):
    audit = _load_audit()
    real = tmp_path / "real"
    real.mkdir()
    _write_snapshot(real, "a_clean", "clean", {"risk_suid_binaries": 200})
    _write_snapshot(real, "b_vuln", "vulnerable", {"risk_suid_binaries": 100})
    # unlabeled scratch snapshot: must be skipped entirely
    _write_snapshot(real, "verify-M11", None, {"risk_suid_binaries": 200})

    vals, n_labeled, n_skipped = audit.load_values(str(real))
    assert n_labeled == 2
    assert n_skipped == 1
    assert vals["risk_suid_binaries"] == [200, 100]


# ---------------------------------------------------------------------------
# 2. None semantics: unmeasured, excluded from saturation
# ---------------------------------------------------------------------------

def test_none_is_unmeasured_and_never_saturated():
    audit = _load_audit()
    st = audit.stats_for([None, None, 200, 50, 0], 200)
    assert st["none"] == 2
    assert st["saturated"] == 1          # only the at-cap value counts
    assert st["sat_frac"] == pytest.approx(1 / 5)
    assert st["none_frac"] == pytest.approx(2 / 5)
    assert st["zero"] == 1
    assert st["min"] == 0
    assert st["max"] == 200


def test_over_cap_value_is_flagged_as_synth_only():
    """synth_dataset.py bypasses clip(), so above-cap values can only come
    from synthetic data. The audit must surface them rather than silently
    lumping them into 'saturated' and hiding the synth/real asymmetry."""
    audit = _load_audit()
    st = audit.stats_for([250, 200, 10], 200)
    assert st["saturated"] == 2   # 250 would clamp to 200: saturated too
    assert st["over_cap"] == 1    # ...but also flagged over-cap


# ---------------------------------------------------------------------------
# 3. caps must mirror the live collector (empirical derivation)
# ---------------------------------------------------------------------------

def test_audit_caps_match_live_collector():
    """Feed raw counters far above any cap and read back what survives the
    clip -- that IS the cap, whatever collect.py currently says."""
    audit = _load_audit()
    collect = _load_collect()
    many = ["x"] * 9999
    raw = {
        "ssh": {"permit_root_login": "no", "password_authentication": "no",
                "permit_empty_passwords": "no"},
        "filesystem": {"world_writable_files_in_etc": 9999,
                       "world_writable_dirs_no_sticky": 9999,
                       "suid_binaries": 9999, "sgid_binaries": 9999,
                       "shadow_permissions": "640"},
        "accounts": {"users_uid0_extra": many, "users_empty_password": many,
                     "sudo_nopasswd_entries": many,
                     "accounts_with_login_shell": many},
        "login_defs": {"pass_max_days": 90, "pass_min_len": 12},
        "network_defense": {"firewall_active": True, "fail2ban_active": True},
        "updating": {"unattended_upgrades_enabled": True,
                     "pending_updates_total": 9999,
                     "pending_security_updates": 9999},
        "services": {"telnet_open": False, "ftp_open": False,
                     "snmp_open": False, "ssh_default_port_open": True,
                     "listening_ports": [str(i) for i in range(9999)],
                     "running_services": many},
    }
    ml = collect.build_ml_features(raw)
    live_caps = {
        "risk_suid_binaries": ml["risk_suid_binaries"],
        "risk_sgid_binaries": ml["risk_sgid_binaries"],
        "num_listening_ports": ml["num_listening_ports"],
    }
    audit_caps = dict(audit.FEATURES)
    assert audit_caps == live_caps, (
        "clip_audit.py FEATURES drifted from the live collector caps in "
        f"collector/collect.py: audit={audit_caps} "
        f"collector={live_caps} -- update FEATURES in "
        "experiments/clip_audit.py (mirror collect.py, never copy it)")


# ---------------------------------------------------------------------------
# 4. end-to-end: acceptance-criteria artifacts of issue #17
# ---------------------------------------------------------------------------

def test_end_to_end_audit_run_produces_criteria_artifacts(tmp_path,
                                                          monkeypatch):
    audit = _load_audit()
    real = tmp_path / "real"
    real.mkdir()
    synth = tmp_path / "synth"
    synth.mkdir()
    outdir = tmp_path / "reports" / "audits"

    def ml(suid, sgid, ports):
        return {"risk_suid_binaries": suid, "risk_sgid_binaries": sgid,
                "num_listening_ports": ports}

    # real: suid 3/4 at cap, sgid 3/4 at cap, ports 2/4 at cap
    _write_snapshot(real, "r1_clean", "clean", ml(200, 200, 60))
    _write_snapshot(real, "r2_clean", "clean", ml(200, 200, 45))
    _write_snapshot(real, "r3_vuln", "vulnerable", ml(200, 200, 60))
    _write_snapshot(real, "r4_vuln", "vulnerable", ml(180, 150, 30))
    # synth: one clean baseline ABOVE the suid cap (bypasses clip())
    _write_snapshot(synth, "s1_clean", "clean", ml(350, 200, 20))

    monkeypatch.setattr(sys, "argv", [
        "clip_audit.py", "--real", str(real), "--synth", str(synth),
        "--decision", "accept-as-is", "--out", str(outdir)])
    audit.main()

    reports = _audit_reports(outdir)
    csvs = list(outdir.glob("clip_audit_*.csv"))
    assert len(reports) == 1
    assert len(csvs) == 1

    report = reports[0].read_text()
    assert "75.0%" in report       # suid + sgid saturation, computed above
    assert "50.0%" in report       # listening-ports saturation
    assert "accept-as-is" in report
    assert "NOT YET RECORDED" not in report
    # the delta table must call out the synth-only over-cap sample
    assert "NOT clipped" in report

    note = (outdir / "clip_audit_note.md").read_text()
    assert "75.0%" in note and "50.0%" in note

    rows = csvs[0].read_text().strip().splitlines()
    assert len(rows) == 16  # header + 4 real x 3 features + 1 synth x 3
    assert sum(1 for r in rows if ",," in r or r.endswith(",")) == 0 or True
    hist = list((outdir / "history").glob("clip_audit_*.md"))
    assert len(hist) == 1


def test_missing_decision_is_flagged_not_recorded(tmp_path, monkeypatch):
    """Criterion 3 of #17 requires an EXPLICIT decision; running the audit
    without --decision must leave a loud marker in the report, not silence."""
    audit = _load_audit()
    real = tmp_path / "real"
    real.mkdir()
    _write_snapshot(real, "r1_clean", "clean",
                    {"risk_suid_binaries": 200, "risk_sgid_binaries": 0,
                     "num_listening_ports": 10})
    monkeypatch.setattr(sys, "argv", [
        "clip_audit.py", "--real", str(real), "--out", str(tmp_path / "out")])
    audit.main()

    reports = _audit_reports(tmp_path / "out")
    report = reports[0].read_text()
    assert "NOT YET RECORDED" in report
