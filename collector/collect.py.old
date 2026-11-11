#!/usr/bin/env python3
"""AutoSecure — system posture collector.

Runs a battery of local configuration/security checks on a Linux host and
emits a JSON snapshot usable as an ML training sample.

Best run as root (sudo) so /etc/shadow and sshd -T are readable.
Runs in degraded mode without root — restricted checks are marked as
check_errors instead of crashing.

Usage:
    sudo python3 collect.py --host-id target-b --tag baseline \
         --out ../dataset [--label clean|vulnerable] [--inject M07 M09]

Output:
    <outdir>/<host_id>_<tag>_<epoch>.json
"""

import argparse
import json
import os
import pwd
import re
import subprocess
import time
from datetime import datetime, timezone

COLLECTOR_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def sh(cmd, timeout=30, ignore_rc=False):
    """Run a command (list form). Return stdout on success, else None."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 or ignore_rc:
            return r.stdout
    except Exception:
        pass
    return None


def sh_bool(cmd, timeout=30):
    """Return True if command exits 0."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def read_file(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def stat_octal(path):
    try:
        return oct(os.stat(path).st_mode & 0o7777)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# checks — each returns (raw_dict, errors_list)
# ---------------------------------------------------------------------------

def ssh_setting(name, default):
    """Resolve an sshd setting via `sshd -T` (root), else parse sshd_config."""
    for sshd_bin in ("/usr/sbin/sshd", "/usr/sbin/sshd", "sshd"):
        out = sh([sshd_bin, "-T"], timeout=15, ignore_rc=True)
        if out:
            m = re.search(rf"^{name}\s+(\S+)", out, re.MULTILINE)
            if m:
                return m.group(1).lower()

    conf = read_file("/etc/ssh/sshd_config")
    if conf:
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
    raw["permit_empty_passwords"] = ssh_setting("permitemptypasswords", "no")
    raw["permit_empty_passwords"] = ssh_setting(
        "permitemptypasswords", "no"
    ) or ssh_setting("permitemptypasswords", "no")
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
    errs = []
    raw = {}

    # unattended-upgrades enabled?
    enabled = None
    content = read_file("/etc/apt/apt.conf.d/20auto-upgrades")
    if content is None:
        # Debian may keep settings elsewhere; try 50unattended-upgrades presence
        enabled = os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades")
    else:
        m = re.search(r'APT::Periodic::Unattended-Upgrade\s+"(\d+)"', content)
        if m:
            enabled = int(m.group(1)) >= 1
    raw["unattended_upgrades_enabled"] = enabled
    if enabled is None:
        errs.append("updating:auto_upgrades_unresolved")

    # pending updates (requires `apt-get update` to have been run; air-gap tolerant)
    out = sh(["apt-get", "-s", "upgrade"], timeout=90, ignore_rc=True)
    if out is None:
        raw["pending_updates_total"] = None
        raw["pending_security_updates"] = None
        errs.append("updating:apt_simulation_failed_offline")
    else:
        inst = [l for l in out.splitlines() if l.startswith("Inst ")]
        raw["pending_updates_total"] = len(inst)
        raw["pending_security_updates"] = len(
            [l for l in inst if "security" in l or "SECURITY" in l])
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


# ---------------------------------------------------------------------------
# ML feature vector — every feature oriented so 1 / higher = MORE risk
# ---------------------------------------------------------------------------

def clip(v, cap):
    if v is None:
        return None
    return min(int(v), cap)


def truthy(v):
    if v is None:
        return None
    return 1 if str(v) in ("yes", "true", "on", "1") else 0


def build_ml_features(raw, errors):
    f = {}

    ssh = raw.get("ssh", {})
    f["risk_ssh_permit_root_login"] = truthy(ssh.get("permit_root_login"))
    f["risk_ssh_password_auth"] = truthy(ssh.get("password_authentication"))
    f["risk_ssh_empty_passwords"] = truthy(ssh.get("permit_empty_passwords"))

    fs = raw.get("filesystem", {})
    f["risk_world_writable_etc_files"] = clip(fs.get("world_writable_files_in_etc"), 10)
    f["risk_world_writable_dirs_no_sticky"] = clip(fs.get("world_writable_dirs_no_sticky"), 10)
    f["risk_suid_binaries"] = clip(fs.get("suid_binaries"), 200)
    f["risk_sgid_binaries"] = clip(fs.get("sgid_binaries"), 200)
    sp = fs.get("shadow_permissions")
    if sp is None:
        f["risk_shadow_world_readable"] = None
        f["risk_shadow_group_writable"] = None
    else:
        mode = int(sp, 8)
        f["risk_shadow_world_readable"] = 1 if mode & 0o004 else 0
        f["risk_shadow_group_writable"] = 1 if mode & 0o020 else 0

    acc = raw.get("accounts", {})
    uid0 = acc.get("users_uid0_extra")
    f["risk_users_uid0_extra"] = clip(len(uid0), 5) if uid0 is not None else None
    ep = acc.get("users_empty_password")
    f["risk_users_empty_password"] = clip(len(ep), 5) if ep is not None else None
    np_ = acc.get("sudo_nopasswd_entries")
    f["risk_sudo_nopasswd"] = clip(len(np_), 5) if np_ is not None else None
    shells = acc.get("accounts_with_login_shell")
    f["num_accounts_with_shell"] = clip(len(shells), 30) if shells is not None else None

    ld = raw.get("login_defs", {})
    pmax = ld.get("pass_max_days")
    plen = ld.get("pass_min_len")
    if pmax is None and plen is None:
        f["risk_weak_password_policy"] = None
    else:
        weak = (pmax is not None and pmax > 90) or (plen is not None and plen < 8)
        f["risk_weak_password_policy"] = 1 if weak else 0

    nd = raw.get("network_defense", {})
    if nd.get("firewall_active") is None:
        f["risk_firewall_disabled"] = None
    else:
        f["risk_firewall_disabled"] = 0 if nd.get("firewall_active") else 1
    if nd.get("fail2ban_active") is None:
        f["risk_fail2ban_absent"] = None
    else:
        f["risk_fail2ban_absent"] = 0 if nd.get("fail2ban_active") else 1

    up = raw.get("updating", {})
    if up.get("unattended_upgrades_enabled") is None:
        f["risk_autoupdates_disabled"] = None
    else:
        f["risk_autoupdates_disabled"] = 0 if up.get("unattended_upgrades_enabled") else 1
    f["risk_pending_updates"] = clip(up.get("pending_updates_total"), 100)
    f["risk_pending_security_updates"] = clip(up.get("pending_security_updates"), 100)

    svcs = raw.get("services", {})
    f["risk_telnet_open"] = 1 if svcs.get("telnet_open") else 0
    f["risk_ftp_open"] = 1 if svcs.get("ftp_open") else 0
    f["risk_snmp_open"] = 1 if svcs.get("snmp_open") else 0
    f["risk_ssh_default_port_open"] = 1 if svcs.get("ssh_default_port_open") else 0
    f["num_listening_ports"] = clip(
        len(svcs.get("listening_ports") or []), 60)
    rs = svcs.get("running_services")
    f["num_running_services"] = clip(len(rs), 80) if rs is not None else None

    return f


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="AutoSecure posture collector")
    ap.add_argument("--host-id", required=True,
                    help="identifier of scanned host, e.g. target-b")
    ap.add_argument("--tag", required=True,
                    help="free-form tag, e.g. baseline or M07-applied")
    ap.add_argument("--out", default=".", help="output directory")
    ap.add_argument("--label", choices=["clean", "vulnerable"], default=None,
                    help="ground-truth label for this snapshot")
    ap.add_argument("--inject", nargs="*", default=[],
                    help="misconfig IDs applied before collection (metadata)")
    args = ap.parse_args()

    all_errors = []

    sections = [
        ("ssh", check_ssh),
        ("filesystem", check_filesystem),
        ("accounts", check_accounts),
        ("login_defs", check_login_defs),
        ("network_defense", check_network_defense),
        ("updating", check_updating),
        ("services", check_services),
    ]
    raw = {}
    for name, fn in sections:
        data, errs = fn()
        raw[name] = data
        all_errors.extend(errs)

    ml = build_ml_features(raw, all_errors)

    snapshot = {
        "meta": {
            "collector_version": COLLECTOR_VERSION,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "host_id": args.host_id,
            "tag": args.tag,
            "label": args.label,
            "injected_misconfigs": args.inject,
            "ran_as_root": os.geteuid() == 0,
            "check_errors": all_errors,
        },
        "features_raw": raw,
        "features_ml": ml,
    }

    os.makedirs(args.out, exist_ok=True)
    stamp = int(time.time())
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", f"{args.host_id}_{args.tag}")
    fname = os.path.join(args.out, f"{safe}_{stamp}.json")
    with open(fname, "w") as fh:
        json.dump(snapshot, fh, indent=2)

    n_feats = len(ml)
    n_none = sum(1 for v in ml.values() if v is None)
    print(f"[+] wrote {fname}")
    print(f"[+] {n_feats} ML features ({n_none} unresolved, "
          f"{len(all_errors)} check errors)")
    print(f"[+] label={args.label} inject={args.inject or 'none'}")


if __name__ == "__main__":
    main()

