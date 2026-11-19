"""Regression test for DnfBackend._count_packages() against real saved
dnf check-update output (issue #10, criterion 8).

The fixture must be captured on the real Fedora/EL host during the
verification session, BEFORE any fix to _count_packages is applied, so
the test locks in truth-first behavior:

    sudo dnf -q check-update > tests/fixtures/dnf_check_update_raw.txt
    sudo dnf -q --security check-update \\
        > tests/fixtures/dnf_security_check_update_raw.txt
    sudo dnf --version | head -n 2 > tests/fixtures/dnf_version.txt

(fedora default config prints the version banner to stderr; if your dnf
redirects it to stdout, `head` still keeps the fixture trimmed.)

Run on any machine: the fixture is a file, so this test passes or fails
offline with no dnf present, and fails LOUDLY (xskip, not silent pass)
until the fixture exists.

If the counts disagree with the hand cross-check from criterion 3, do
NOT tune this test to the parser: fix the parser, regenerate the manual
count, then assert on the corrected expectation. The fixture is the
ground truth; the parser is the thing under test.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))

from backends import DnfBackend  # noqa: E402

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
RAW_FIXTURE = os.path.join(FIXTURE_DIR, "dnf_check_update_raw.txt")
SEC_FIXTURE = os.path.join(FIXTURE_DIR, "dnf_security_check_update_raw.txt")
VERSION_FIXTURE = os.path.join(FIXTURE_DIR, "dnf_version.txt")


def _require_fixture(path):
    if not os.path.exists(path):
        pytest.xfail(
            f"fixture {os.path.basename(path)} not yet captured; "
            "capture it on the Fedora/EL host per the docstring in this "
            "file (issue #10 criterion 8)"
        )


def _load(path):
    with open(path) as fh:
        return fh.read()


def test_count_packages_on_real_dnf4_output():
    """Parser count on the saved full check-update output equals the
    hand-verified package count from criterion 3."""
    _require_fixture(RAW_FIXTURE)
    out = _load(RAW_FIXTURE)
    # REPLACE the sentinel with the hand-counted number from the host
    # session: count unique package names in the fixture manually (e.g.
    # awk '$0 !~ /^(Loaded|Last metadata|Existing lock|Updating|Uploading|Security)/
    #      && NF >= 2 { split($1, a, "."); g[a[1]] } END { print length(g) }')
    # and write it below. The sentinel asserts loudly instead of guessing.
    HAND_COUNTED_TOTAL = None  # fill from criterion 3 session notes
    assert HAND_COUNTED_TOTAL is not None, (
        "fill HAND_COUNTED_TOTAL with the hand count from the host run "
        "before relying on this test"
    )
    assert DnfBackend._count_packages(out) == HAND_COUNTED_TOTAL


def test_count_packages_on_real_security_subset():
    """Security-subset count equals the hand-verified count, proving dnf5
    (or the session's dnf) honored --security on check-update."""
    _require_fixture(SEC_FIXTURE)
    out = _load(SEC_FIXTURE)
    HAND_COUNTED_SECURITY = None  # fill from criterion 3 session notes
    assert HAND_COUNTED_SECURITY is not None, (
        "fill HAND_COUNTED_SECURITY with the hand count from the host run "
        "before relying on this test"
    )
    assert DnfBackend._count_packages(out) == HAND_COUNTED_SECURITY


def test_parser_skips_banner_and_dedups_repeated_rows():
    """Does not need the Fedora session; guards the two known parsing
    hazards (banner lines and pkgname.arch duplicates like multiple arch
    rows or kernel notices) with synthetic input shaped like real rows."""
    synthetic = (
        "Loaded plugins: builddep, changelog, config-manager\n"
        "Last metadata expiration check: 0:02:11 ago\n"
        "Security: kernel-6.11.0-1.fc40.x86_64\n"
        "kernel-core.x86_64                6.11.0-1.fc40  updates\n"
        "kernel-core.i686                  6.11.0-1.fc40  updates\n"
        "bash.x86_64                       5.2.26-4.fc40   updates\n"
        "openssl-libs.x86_64               1:3.2.1-1.fc40  updates\n"
        "\n"
        "Obsoleting Packages\n"
        "foo-bar.noarch                    2.0-1.fc40       updates\n"
    )
    # Expect: kernel-core counted once (dedup on name via rsplit(".",
    # 1)), bash once, openssl-libs once, foo-bar once => 4. Banner,
    # Security: prefix line, blank line, and obsoletes header excluded.
    assert DnfBackend._count_packages(synthetic) == 4


def test_parser_tolerates_empty_output():
    assert DnfBackend._count_packages("") == 0


def test_parser_tolerates_banner_only_output():
    assert DnfBackend._count_packages(
        "Loaded plugins: builddep\nLast metadata expiration check\n"
    ) == 0


def test_dnf_version_recorded_for_issue10_evidence():
    """Criterion 1 requires recording the dnf version used; this test
    merely asserts the evidence fixture was captured and is nonempty,
    keeping the chain (fixture -> issue evidence) checkable in CI."""
    _require_fixture(VERSION_FIXTURE)
    content = _load(VERSION_FIXTURE)
    assert content.strip(), "dnf_version.txt fixture is empty"

