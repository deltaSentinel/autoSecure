# =====================================================================
# File: backends.py
# Package-manager backends. This is the ONLY distro-coupled code in the
# package. Interface (mapped onto the "updating" section's original
# raw keys, so features_ml is unchanged):
#
#   .pending_updates()       -> (total, security) or (None, None)
#   .auto_updates_enabled()  -> True / False / None
#
# Unknown distros -> NullBackend -> features become None, which the
# agent/model/L0 already tolerate via the unresolved path.
#
# IMPORTANT — the AptBackend reproduces the ORIGINAL Debian logic
# byte-for-byte (regex, 50unattended-upgrades fallback, Inst-line
# counting, "SECURITY" matching) so existing snapshots stay comparable.
# =====================================================================

import re

from common import sh, sh_bool, sh_rc, read_file, which


class PkgBackend:
    name = "unknown"

    def pending_updates(self):
        return (None, None)

    def auto_updates_enabled(self):
        return None


class NullBackend(PkgBackend):
    """No supported package manager found. Update features -> None."""
    name = "none"


class AptBackend(PkgBackend):
    name = "apt"

    def pending_updates(self):
        # Simulated upgrade: count "Inst " lines; security pocket appears
        # in the repo component portion of the simulated line.
        out = sh(["apt-get", "-s", "upgrade"], timeout=90, ignore_rc=True)
        if out is None:
            return (None, None)
        inst = [l for l in out.splitlines() if l.startswith("Inst ")]
        total = len(inst)
        security = len([l for l in inst
                        if "security" in l or "SECURITY" in l])
        return (total, security)

    def auto_updates_enabled(self):
        # Original collect.py logic preserved exactly.
        content = read_file("/etc/apt/apt.conf.d/20auto-upgrades")
        if content is None:
            # Debian may keep settings elsewhere; fall back to
            # 50unattended-upgrades presence.
            return os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades")
        m = re.search(r'APT::Periodic::Unattended-Upgrade\s+"(\d+)"', content)
        if m:
            return int(m.group(1)) >= 1
        return None


import os  # noqa: E402  (kept next to its sole use in AptBackend)


class DnfBackend(PkgBackend):
    """dnf4 AND dnf5 targets, plus legacy yum (same query surface).
    CAUTION: exit-code contract verified against dnf4 docs. check-update
    should return 100 when updates exist, 0 when current, other = error.
    RE-VERIFY on a real Fedora/EL box before trusting DNF5 numbers."""
    name = "dnf"

    _SKIP_PREFIXES = ("Loaded", "Last metadata", "Existing lock",
                      "Updating", "Uploading", "Security")

    @classmethod
    def _count_packages(cls, out):
        """Count unique package names from check-update listing rows."""
        pkgs = set()
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith(cls._SKIP_PREFIXES):
                continue
            parts = line.split()
            # rows look like:  pkgname.arch  version  repo
            if len(parts) >= 2 and "." in parts[0]:
                pkgs.add(parts[0].rsplit(".", 1)[0])
        return len(pkgs)

    def pending_updates(self):
        rc = sh_rc(["dnf", "-q", "check-update"], timeout=120)
        if rc == 0:
            return (0, 0)
        if rc != 100:          # 100 == updates available; anything else = error
            return (None, None)
        out = sh(["dnf", "-q", "check-update"], timeout=120, ignore_rc=True)
        if out is None:
            return (None, None)
        total = self._count_packages(out)
        security = None
        sec_out = sh(["dnf", "-q", "--security", "check-update"],
                     timeout=120, ignore_rc=True)
        if sec_out is not None:
            security = self._count_packages(sec_out)
        return (total, security)

    def auto_updates_enabled(self):
        # Two enabling mechanisms on EL/Fedora:
        #  1. dnf-automatic-install.timer -> installs unconditionally
        #  2. dnf-automatic.timer + apply_updates=yes in dnf-automatic.conf
        if sh_bool(["systemctl", "is-enabled", "--quiet",
                    "dnf-automatic-install.timer"]):
            return True
        if not sh_bool(["systemctl", "is-enabled", "--quiet",
                        "dnf-automatic.timer"]):
            return False        # no timer -> not automatic
        conf = (read_file("/etc/dnf/dnf-automatic.conf")
                or read_file("/etc/dnf/automatic.conf"))
        if conf is None:
            return None
        m = re.search(r"^\s*apply_updates\s*=\s*(yes|true|1)",
                      conf, re.MULTILINE | re.IGNORECASE)
        return bool(m)


class PacmanBackend(PkgBackend):
    """Arch/BlackArch. checkupdates is from pacman-contrib."""
    name = "pacman"

    def pending_updates(self):
        if not which("checkupdates"):
            return (None, None)
        rc = sh_rc(["checkupdates"], timeout=120)
        if rc == 2:
            return (0, None)    # Arch has no security-update split
        if rc != 0:
            return (None, None)
        out = sh(["checkupdates"], timeout=120, ignore_rc=True)
        if out is None:
            return (None, None)
        total = len([l for l in out.splitlines() if l.strip()])
        return (total, None)

    def auto_updates_enabled(self):
        # No standard mechanism on Arch; None rather than a guess.
        return None


def detect_backend():
    """Probe BINARIES, not /etc/os-release — ID= can be wrong or absent
    in stripped LXCs and golden-copy Pi images."""
    if which("apt-get"):
        return AptBackend()
    if which("dnf"):
        return DnfBackend()
    if which("yum"):
        return DnfBackend()
    if which("pacman"):
        return PacmanBackend()
    return NullBackend()
