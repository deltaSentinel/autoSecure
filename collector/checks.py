# =====================================================================
# File: checks.py
# The seven features_raw sections, in original order, with original
# section names and raw key names. Bugfixes vs the original monolith:
#   [1] sshd candidate list deduplicated (was /usr/sbin/sshd twice)
#   [2] dead double-assignment of permit_empty_passwords removed
#   [3] PermitRootLogin scored via explicit risk map (see build_ml_features)
# Every check returns (raw_dict, errors_list) exactly like before.
# =====================================================================

import os
import pwd
import re

from common import sh, sh_bool, read_file, stat_octal
from backends import detect_backend


def ssh_setting(name, default):
    """Resolve an sshd setting via `sshd -T` (root), else parse sshd_config.
    FIX [1]: candidate list was ("/usr/sbin/sshd", "/usr/sbin/sshd", "sshd")."""
    for sshd_bin in ("/usr/sbin/sshd", "sshd"):
        out = sh([sshd_bin, "-T"], timeout=15, ignore_rc=True)
        if out:
            m = re.search(rf"^{name}\s+(\S+)", out, re.MULTILINE)
            if m:
                return m.group(1).lower()

    conf = read_file("/etc/ssh/sshd_config")
    if conf:
        # Global scope only: Match blocks must appear last in a
        # well-formed sshd_config, so everything after the first Match
        # line is conditional config and not scored.
        val = default
        in_match_block = False
        for line in conf.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("match "):
                in_match_block = True
                continue
            if in_match_block:
                continue
            m = re.match(rf"^\s*{name}\s+(\S+)", line, re.IGNORECASE)
            if m:
                val = m.group(1).lower()
        return val
    return None


def check_ssh():
    errs = []
    raw = {}
    raw["permit_root_login"] = ssh_setting("permitrootlogin", "prohibit-password")
    raw["password_authentication"] = ssh_setting("passwordauthentication", "yes")
    # FIX [2]: was assigned twice; the second assignment was a redundant
    # `or` fallback of the same call.
    raw["permit_empty_passwords"] = ssh_setting("permitemptypasswords", "no")
    for k, v in raw.items():
        if v is None:
            errs.append(f"ssh:{k}:unresolved")
    return raw, errs


def listening_sockets():
    """Return (set_of_ports, is_udp_set) from `ss -tuln`."""
    out = sh(["ss", "-tuln"], timeout=15, ignore_rc=True)
    ports = set()
    udp_ports = set()
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5 or not parts[0].lower() in ("tcp", "udp", "tcp6", "udp6"):
                continue
            local = parts[4] if len(parts) > 4 else ""
            m = re.search(r":(\d+)$", local)
            if m:
                p = int(m.group(1))
                ports.add(p)
                if "udp" in parts[0].lower():
                    udp_ports.add(p)
    return ports, udp_ports


def count_find(paths, perm_expr, extra=()):
    """Count files matching find expression across paths, with timeout."""
    total = set()
    for path in paths:
        cmd = ["find", path, "-xdev", "-type", "f"]
        cmd += [f"-perm", perm_expr]
        cmd += list(extra)
        out = sh(cmd, timeout=45, ignore_rc=True)
        if out:
            total.update(l for l in out.splitlines() if l.strip())
    return len(total)


def check_filesystem():
    errs = []
    raw = {}

    n = count_find(["/etc"], "-0002")
    raw["world_writable_files_in_etc"] = n

    # world-writable dirs WITHOUT the sticky bit in /tmp and /var/tmp
    out = sh(["find", "/tmp", "/var/tmp", "-xdev", "-type", "d",
              "-perm", "-0002", "!", "-perm", "-1000"],
             timeout=20, ignore_rc=True)
    raw["world_writable_dirs_no_sticky"] = (
        len([l for l in out.splitlines() if l.strip()]) if out else None
    )

    raw["suid_binaries"] = count_find(
        ["/usr", "/bin", "/sbin", "/lib"], "-4000")
    raw["sgid_binaries"] = count_find(
        ["/usr", "/bin", "/sbin", "/lib"], "-2000")

    raw["shadow_permissions"] = stat_octal("/etc/shadow")
    raw["passwd_permissions"] = stat_octal("/etc/passwd")

    if raw["shadow_permissions"] is None:
        errs.append("fs:shadow:stat_failed")
    return raw, errs


def check_accounts():
    errs = []
    raw = {}

    try:
        entries = pwd.getpwall()
        raw["users_uid0_extra"] = [
            e.pw_name for e in entries
            if e.pw_uid == 0 and e.pw_name != "root"
        ]
        nologin_shells = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                          "/usr/bin/false", "/bin/sync", "/sbin/halt",
                          "/sbin/shutdown")
        raw["accounts_with_login_shell"] = [
            e.pw_name for e in entries
            if e.pw_shell and e.pw_shell not in nologin_shells
        ]
    except Exception:
        errs.append("accounts:pwdb_failed")
        raw["users_uid0_extra"] = None
        raw["accounts_with_login_shell"] = None

    # empty password fields ("" in shadow field 2; locked "!" or "*" are normal)
    empty_pw = None
    shadow = read_file("/etc/shadow")
    if shadow is not None:
        empty = []
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) > 1 and parts[1] == "":
                empty.append(parts[0])
        empty_pw = empty
    else:
        errs.append("accounts:shadow_unreadable_needs_root")
    raw["users_empty_password"] = empty_pw

    # NOPASSWD sudo entries
    nopasswd = []
    sudoers_sources = ["/etc/sudoers"]
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        sudoers_sources += [
            os.path.join(sudoers_d, f)
            for f in sorted(os.listdir(sudoers_d))
        ]
    saw_sudoers = False
    for src in sudoers_sources:
        content = read_file(src)
        if content is None:
            continue
        saw_sudoers = True
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("#") or s.upper().startswith("DEFAULTS"):
                continue
            if "NOPASSWD" in s.upper():
                nopasswd.append(s)
    if not saw_sudoers:
        raw["sudo_nopasswd_entries"] = None
    else:
        raw["sudo_nopasswd_entries"] = nopasswd
    return raw, errs


def check_login_defs():
    errs = []
    raw = {}
    conf = read_file("/etc/login.defs")
    if conf is None:
        errs.append("login_defs:missing")
        return raw, errs
    for key in ("PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE"):
        m = re.search(rf"^\s*{key}\s+(\d+)", conf, re.MULTILINE)
        raw[key.lower()] = int(m.group(1)) if m else None
    return raw, errs


def check_network_defense():
    errs = []
    raw = {}
    fw_active = False
    fw_backend = None
    for svc in ("ufw", "nftables", "firewalld"):
        if sh_bool(["systemctl", "is-active", "--quiet", svc]):
            fw_active = True
            fw_backend = svc
            break
    # belt-and-braces: iptables rules present?
    if not fw_active:
        out = sh(["iptables", "-L", "-n"], timeout=15, ignore_rc=True)
        if out and len(out.splitlines()) > 3:
            fw_active = True
            fw_backend = "iptables"
    raw["firewall_active"] = fw_active
    raw["firewall_backend"] = fw_backend
    raw["fail2ban_active"] = sh_bool(
        ["systemctl", "is-active", "--quiet", "fail2ban"])
    return raw, errs


def check_updating():
    """Same output schema as the original apt-only version, but routed
    through the package-manager backend. Raw keys preserved:
      unattended_upgrades_enabled, pending_updates_total,
      pending_security_updates. Extra additive key: pkg_backend."""
    errs = []
    raw = {}

    backend = detect_backend()
    raw["pkg_backend"] = backend.name

    raw["unattended_upgrades_enabled"] = backend.auto_updates_enabled()
    if raw["unattended_upgrades_enabled"] is None:
        errs.append("updating:auto_upgrades_unresolved")

    total, security = backend.pending_updates()
    raw["pending_updates_total"] = total
    raw["pending_security_updates"] = security
    if total is None:
        errs.append(f"updating:simulation_failed_offline_{backend.name}")

    return raw, errs


def check_services():
    errs = []
    raw = {}
    out = sh(["systemctl", "list-units", "--type=service",
              "--state=running", "--no-legend", "--plain"],
             timeout=20, ignore_rc=True)
    running = [l.split()[0] for l in out.splitlines() if l.strip()] if out else None
    raw["running_services"] = running

    ports, udp_ports = listening_sockets()
    raw["listening_ports"] = sorted(ports)
    raw["telnet_open"] = 23 in ports
    raw["ftp_open"] = 21 in ports
    raw["snmp_open"] = (161 in ports) or (161 in udp_ports)
    raw["ssh_default_port_open"] = 22 in ports
    return raw, errs

