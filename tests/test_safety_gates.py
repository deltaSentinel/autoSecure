"""Safety-gate regression tests for agent/main.py.

These enforce the invariants documented in the module docstring of
agent/main.py at CI time:

  1. READ-ONLY BY DEFAULT   -- no mutation without --act
  2. --act requires root    -- hard refusal otherwise (no silent degradation)
  3. FAIL-STATIC L1         -- missing model degrades gracefully, never crashes

They invoke the agent CLI as a subprocess so the real argument parsing and
exit paths are exercised, not reimplemented.

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
FIXTURE_M11 = ROOT / "tests" / "fixtures" / "scan_m11.json"
FIXTURE_CLEAN = ROOT / "tests" / "fixtures" / "scan_clean.json"

SUBPROC_TIMEOUT = 120  # seconds; agent is lightweight, generous ceiling


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


# ---------------------------------------------------------------------------
# Invariant: --yes-all without --act must refuse (silent-mutation guard)
# ---------------------------------------------------------------------------

def test_yes_all_requires_act(run_dir):
    r = run_agent(
        "--snapshot", str(FIXTURE_M11),
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
def test_act_requires_root(run_dir):
    # scan_m11 must produce findings so the --act branch is reached at all:
    # the root check sits *after* perception/planning and is only evaluated
    # when a remediation plan exists.
    r = run_agent(
        "--snapshot", str(FIXTURE_M11),
        "--db", str(run_dir / "mem.db"),
        "--report", str(run_dir / "report.md"),
        "--act",
    )
    assert r.returncode != 0, (
        "--act without root must exit non-zero (hard refusal, no fallback)"
    )
    assert "root" in r.stderr.lower(), (
        f"refusal message should mention root; stderr was: {r.stderr!r}"
    )
    # Hard refusal means zero side effects: no DB should have been left in a
    # half-executed state. We can't inspect the approval gate from here, but
    # the report may exist (assessment always runs) — that's fine. What must
    # NOT happen is a successful exit.
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

def test_default_run_never_enters_approval_gate(run_dir):
    r = run_agent(
        "--snapshot", str(FIXTURE_M11),
        "--db", str(run_dir / "mem.db"),
        "--report", str(run_dir / "report.md"),
    )
    assert r.returncode == 0
    assert "PROPOSED only" in r.stdout, (
        "run without --act must leave the plan as proposals only"
    )
    assert "approval gate closed" not in r.stdout

