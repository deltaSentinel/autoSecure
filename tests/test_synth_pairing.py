"""During the pairing, two silent failures shipped past every metric check:
a bogus feature key ("risk_root_login") and a raw-field assignment written
with ``==`` instead of ``=``.  Metrics looked healthy both times — only a
raw-value grep caught them.  This file turns that lesson into permanent
invariants, checked against whatever dataset is currently in data/synth/:

  1. features_ml["risk_ssh_permit_root_login"] must equal the risk score of
     features_raw["ssh"]["permit_root_login"] (per collect.py's authoritative
     PERMIT_ROOT_LOGIN_RISK map, imported — never copied — so it cannot drift),
     except when masked to None by simulated degraded collection.
  2. features_ml must not contain known-bogus key variants.
  3. Clean-labeled baselines draw only from {"no", "prohibit-password"},
     and the Debian default is actually present (guards against the
     constant-"no" regression).

Run after EVERY regeneration:
    uv run pytest tests/test_synth_pairing.py
(Also picked up by the normal `uv run pytest tests/` suite.)
"""

import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).parents[1]
SYNTH_DIR = ROOT / "data" / "synth"

# collect.py's location in the repo
COLLECT_PATH = ROOT / "collector" / "collect.py"

# Typosquatted key from a failed patch attempt — cheap to check forever.
_BOGUS_KEYS = ("risk_root_login",)


def _load_root_login_risk():
    if not COLLECT_PATH.is_file():
        pytest.fail(
            "collect.py not found at collector/collect.py -- refusing to "
            "test against a copied risk map that could drift; update "
            "COLLECT_PATH in tests/test_synth_pairing.py")
    sys.path.insert(0, str(COLLECT_PATH.parent))  # collect.py imports common
    try:
        spec = importlib.util.spec_from_file_location(
            "_collect_under_test", COLLECT_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.root_login_risk
    finally:
        sys.path.remove(str(COLLECT_PATH.parent))


def _snapshots():
    paths = sorted(SYNTH_DIR.glob("*.json"))
    if not paths:
        pytest.skip("no snapshots under data/synth/ — regenerate the "
                    "synthetic dataset first")
    for p in paths:
        try:
            yield p, json.loads(p.read_text())
        except (json.JSONDecodeError, OSError) as e:
            pytest.fail(f"unreadable snapshot {p.name}: {e}")


def test_ml_agrees_with_raw_permit_root_login():
    """Invariant 1: the ml feature is derivable from the raw field.

    Every real collector snapshot satisfies this by construction
    (build_ml_features derives one from the other).  A synthetic snapshot
    violating it describes a host no collector could ever observe.
    """
    root_login_risk = _load_root_login_risk()
    violations = []
    for path, snap in _snapshots():
        ml = snap.get("features_ml") or {}
        raw_ssh = (snap.get("features_raw", {}).get("ssh", {}) or {})
        raw_val = raw_ssh.get("permit_root_login")
        ml_val = ml.get("risk_ssh_permit_root_login")
        if ml_val is None:
            continue  # masked by simulated degraded collection: None = unmeasured
        expected = root_login_risk(raw_val)
        if ml_val != expected:
            violations.append(
                f"{path.name}: raw ssh.permit_root_login={raw_val!r} -> "
                f"expected ml={expected!r}, got {ml_val!r}")
    assert not violations, (
        "features_ml['risk_ssh_permit_root_login'] disagrees with the raw "
        "ssh.permit_root_login it must be derivable from (FIX [3] pairing). "
        "Check the draw, the ml entry, and the RAW ASSIGNMENT (= not ==) in "
        "clean_baseline(), then regenerate:\n" + "\n".join(violations[:10]))


def test_no_bogus_feature_keys():
    """Invariant 2: guard against key typos leaking into the canonical set.

    train.py derives feature_keys.json from the sorted union of features_ml
    keys, so one stray key silently breaks the agent vectorizer contract.
    """
    keys = set()
    for _path, snap in _snapshots():
        keys.update((snap.get("features_ml") or {}).keys())
    leaked = [k for k in _BOGUS_KEYS if k in keys]
    assert not leaked, (
        f"bogus feature key(s) {leaked} present in features_ml — these leak "
        "into models/feature_keys.json and desynchronize agent/main.py's "
        "vectorizer. Rename to the canonical "
        "'risk_ssh_permit_root_login' and regenerate.")


def test_clean_baselines_draw_from_paired_pool():
    """Invariant 3: clean baselines use the {"no", "prohibit-password"} pool.

    A constant-"no" distribution is the exact pre-pairing blind spot FIX [3]
    exists to remove (prohibit-password is the Debian default and scores 1
    under the explicit risk map).
    """
    clean_vals = []
    for path, snap in _snapshots():
        if (snap.get("meta", {}) or {}).get("label") != "clean":
            continue
        ssh = (snap.get("features_raw", {}).get("ssh", {}) or {})
        clean_vals.append(ssh.get("permit_root_login"))
    if not clean_vals:
        pytest.skip("no clean-labeled snapshots in data/synth/")
    out_of_pool = sorted({str(v) for v in clean_vals
                          if v not in ("no", "prohibit-password")})
    assert not out_of_pool, (
        "clean-labeled snapshots carry values outside the baseline pool: "
        f"{out_of_pool} — clean hosts must never permit root login outright")
    assert "prohibit-password" in clean_vals, (
        "zero clean baselines draw 'prohibit-password' — the FIX [3] "
        "pairing has silently regressed to the constant-\"no\" "
        "distribution (all "
        f"{len(clean_vals)} clean samples say 'no')")

