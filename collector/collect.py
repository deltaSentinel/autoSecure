# =====================================================================
# File: collect.py
# Orchestrator. SCHEMA-EXACT drop-in replacement for the original
# monolithic collect.py:
#   - identical CLI (--host-id --tag --out --label --inject)
#   - identical meta keys (plus additive os-release/pkg-backend info)
#   - identical features_raw sections and raw keys
#   - identical 26 features_ml keys, caps, and None-propagation
# Behavioral changes vs original: bugfixes [1][2][3] only (see checks.py).
#
# Usage (unchanged):
#   sudo python3 collect.py --host-id target-b --tag baseline \
#        --out ../dataset [--label clean|vulnerable] [--inject M07 M09]
#
# RETRAIN CHECKLIST (must be atomic, all-or-nothing):
#   1. apply the M01 clean_baseline patch to synth_dataset.py
#   2. regenerate the synthetic dataset
#   3. retrain train/model.joblib
#   4. re-run arb_experiment.py + threshold sweep
# =====================================================================

import argparse
import json
import os
import re
import time
from datetime import datetime, timezone

from common import parse_os_release
import checks

COLLECTOR_VERSION = "0.2.0"   # bumped: backend split + bugfixes [1][2][3]


# ---------------------------------------------------------------------------
# ML feature vector — every feature oriented so 1 / higher = MORE risk
# Key set, caps, and orientation are IDENTICAL to the original 26 features.
# ---------------------------------------------------------------------------

def clip(v, cap):
    if v is None:
        return None
    return min(int(v), cap)


def truthy(v):
    if v is None:
        return None
    return 1 if str(v) in ("yes", "true", "on", "1") else 0


# FIX [3]: PermitRootLogin previously went through truthy(), so
# "prohibit-password" (the Debian default!) scored 0 — a silent blind
# spot for the M01 attack surface. Explicit map instead.
# PAIRED ACTION REQUIRED: synth_dataset.py clean_baseline must draw
# permit_root_login from {"no", "prohibit-password"} and set the ml
# feature accordingly, then regenerate + retrain. Apply both or neither.
PERMIT_ROOT_LOGIN_RISK = {
    "yes": 1,
    "prohibit-password": 1,
    "without-password": 1,      # synonym for prohibit-password
    "forced-commands-only": 0,
    "no": 0,
}


def root_login_risk(v):
    if v is None:
        return None
    return PERMIT_ROOT_LOGIN_RISK.get(v, 0)


def build_ml_features(raw, errors=None):
    # `errors` kept as an optional param for backward compat with any
    # callers following the old two-arg signature; unused, as before.
    f = {}

    ssh = raw.get("ssh", {})
    f["risk_ssh_permit_root_login"] = root_login_risk(
        ssh.get("permit_root_login"))
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
        ("ssh", checks.check_ssh),
        ("filesystem", checks.check_filesystem),
        ("accounts", checks.check_accounts),
        ("login_defs", checks.check_login_defs),
        ("network_defense", checks.check_network_defense),
        ("updating", checks.check_updating),
        ("services", checks.check_services),
    ]
    raw = {}
    for name, fn in sections:
        data, errs = fn()
        raw[name] = data
        all_errors.extend(errs)

    ml = build_ml_features(raw, all_errors)

    osr = parse_os_release()
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
            # additive keys (agent ignores unknowns; used for dataset slicing)
            "os_release_id": osr.get("ID"),
            "os_release_like": osr.get("ID_LIKE"),
            "os_version_id": osr.get("VERSION_ID"),
            "pkg_backend": (raw.get("updating", {}) or {}).get("pkg_backend"),
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

