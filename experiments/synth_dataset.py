#!/usr/bin/env python3
"""AutoSecure — synthetic dataset generator.

Generates collector-compatible snapshots WITHOUT touching any real host,
by modeling clean-host baselines and misconfiguration effects over the
features_ml schema. Runs on your laptop, needs only Python stdlib.

Snapshot schema matches collect.py byte-for-byte, so train.py and
arb_experiment.py consume them unchanged. Synthetic origin is stamped in
meta (synthetic: true) and never silently mixed without your knowledge.

Modeling:
  1. Clean baseline drawn from a pool of plausible host "profiles"
     (minimal container, standard server, desktop) with per-feature noise.
  2. Each misconfig (M01-M15) applies a deterministic feature effect —
     identical to what inject.sh actually causes — plus small noise.
  3. Combos apply effects jointly (some interact, e.g. M06+M07 both stem
     from the victim01 account).
  4. Random degraded-check masking simulates non-root collectors.

USAGE:
  python3 synth_dataset.py --out ../dataset_synth --clean 150 --singles 10 --combos 200
  python3 synth_dataset.py --out ../dataset_synth --profile minimal --combos 50

Recommended workflow: TRAIN on synthetic, TEST on the small real set
collected from Proxmox LXC clones. Report both.
"""

import argparse
import json
import os
import random
import time
from datetime import datetime, timezone


VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# misconfig effects: what inject.sh actually changes in features_ml
# (mirrors collect.py's build_ml_features output orientation: 1/high = risky)
# ---------------------------------------------------------------------------

EFFECTS = {
    "M01": {"ml": {"risk_ssh_permit_root_login": 1},
            "raw": {"ssh": {"permit_root_login": "yes"}}},
    "M02": {"ml": {"risk_ssh_password_auth": 1},
            "raw": {}},
    "M03": {"ml": {"risk_ssh_empty_passwords": 1},
            "raw": {"ssh": {"permit_empty_passwords": "yes"}}},
    "M04": {"ml": {"risk_shadow_group_writable": 1,
                   "risk_shadow_world_readable": 1},
            "raw": {"filesystem": {"shadow_permissions": "666"}}},
    "M05": {"ml": {"risk_world_writable_dirs_no_sticky": 1},
            "raw": {}},
    "M06": {"ml": {"risk_users_empty_password": 1},
            "raw": {"accounts": {"users_empty_password": ["victim01"]}}},
    "M07": {"ml": {"risk_sudo_nopasswd": 1},
            "raw": {"accounts": {"sudo_nopasswd_entries":
                                 ["victim01 ALL=(ALL) NOPASSWD: ALL"]}}},
    "M08": {"ml": {"risk_weak_password_policy": 1},
            "raw": {"login_defs": {"pass_min_len": 0,
                                   "pass_max_days": 99999}}},
    "M09": {"ml": {"risk_firewall_disabled": 1},
            "raw": {"network_defense": {"firewall_active": False}}},
    "M10": {"ml": {"risk_telnet_open": 1,
                   "num_listening_ports": 1},
            "raw": {"services": {"telnet_open": True}}},
    "M11": {"ml": {"risk_suid_binaries": 1},
            "raw": {}},
    "M12": {"ml": {"risk_world_writable_etc_files": 1},
            "raw": {}},
    "M13": {"ml": {"risk_users_uid0_extra": 1},
            "raw": {"accounts": {"users_uid0_extra": ["backdoor01"]}}},
    "M14": {"ml": {"risk_autoupdates_disabled": 1},
            "raw": {"updating": {"unattended_upgrades_enabled": False}}},
    "M15": {"ml": {"risk_snmp_open": 1},
            "raw": {"services": {"snmp_open": True}}},
}

ALL_IDS = sorted(EFFECTS.keys())

# reflex-visible raw fields the clean baseline must contain for
# arb_experiment.py to run L0 over synthetic data without KeyError

CLEAN_RAW_TEMPLATE = {
    "ssh": {"permit_root_login": "no", "password_authentication": "no",
            "permit_empty_passwords": "no"},
    "filesystem": {"shadow_permissions": "640",
                   "world_writable_files_in_etc": 0,
                   "suid_binaries": 210},
    "accounts": {"users_uid0_extra": [], "users_empty_password": [],
                 "sudo_nopasswd_entries": [],
                 "accounts_with_login_shell": []},
    "login_defs": {"pass_min_len": 10, "pass_max_days": 90},
    "network_defense": {"firewall_active": True, "fail2ban_active": False},
    "updating": {"unattended_upgrades_enabled": True},
    "services": {"telnet_open": False, "ftp_open": False, "snmp_open": False,
                 "listening_ports": [22]},
}


def deep_copy(d):
    return json.loads(json.dumps(d))


# ---------------------------------------------------------------------------
# host profiles: plausible clean baselines with noise
# ---------------------------------------------------------------------------

PROFILES = {
    "minimal": {   # LXC-style minimal container
        "num_listening_ports": (1, 4), "num_running_services": (4, 12),
        "risk_suid_binaries": (150, 220), "risk_sgid_binaries": (30, 70),
        "num_accounts_with_shell": (1, 3),
        "risk_pending_updates": (0, 12), "risk_pending_security_updates": (0, 5),
    },
    "server": {    # standard Debian server with ssh
        "num_listening_ports": (5, 15), "num_running_services": (15, 35),
        "risk_suid_binaries": (180, 260), "risk_sgid_binaries": (40, 90),
        "num_accounts_with_shell": (2, 6),
        "risk_pending_updates": (0, 25), "risk_pending_security_updates": (0, 12),
    },
    "desktop": {   # fuller install (more surface, still "clean")
        "num_listening_ports": (10, 25), "num_running_services": (30, 60),
        "risk_suid_binaries": (250, 400), "risk_sgid_binaries": (60, 140),
        "num_accounts_with_shell": (2, 8),
        "risk_pending_updates": (5, 60), "risk_pending_security_updates": (2, 25),
    },
}


def clean_baseline(rng, profile):
    prof = PROFILES[profile]
    ml = {
        "risk_ssh_permit_root_login": 0,
        "risk_ssh_password_auth": int(rng.random() < 0.3),  # some allow it
        "risk_ssh_empty_passwords": 0,
        "risk_world_writable_etc_files": 0,
        "risk_world_writable_dirs_no_sticky": 0,
        "risk_suid_binaries": rng.randint(*prof["risk_suid_binaries"]),
        "risk_sgid_binaries": rng.randint(*prof["risk_sgid_binaries"]),
        "risk_shadow_world_readable": 0,
        "risk_shadow_group_writable": 0,
        "risk_users_uid0_extra": 0,
        "risk_users_empty_password": 0,
        "risk_sudo_nopasswd": 0,
        "num_accounts_with_shell": rng.randint(*prof["num_accounts_with_shell"]),
        "risk_weak_password_policy": 0,
        "risk_firewall_disabled": 0,
        "risk_fail2ban_absent": int(rng.random() < 0.8),  # commonly absent
        "risk_autoupdates_disabled": 0,
        "risk_pending_updates": rng.randint(*prof["risk_pending_updates"]),
        "risk_pending_security_updates":
            rng.randint(*prof["risk_pending_security_updates"]),
        "risk_telnet_open": 0,
        "risk_ftp_open": 0,
        "risk_snmp_open": 0,
        "risk_ssh_default_port_open": 1,
        "num_listening_ports": rng.randint(*prof["num_listening_ports"]),
        "num_running_services": rng.randint(*prof["num_running_services"]),
    }
    raw = deep_copy(CLEAN_RAW_TEMPLATE)
    if ml["risk_ssh_password_auth"]:
        raw["ssh"]["password_authentication"] = "yes"
    if ml["risk_sudo_nopasswd"]:
        raw["accounts"]["sudo_nopasswd_entries"] = ["lab ALL=NOPASSWD: ALL"]
    if ml["risk_weak_password_policy"]:
        raw["login_defs"]["pass_min_len"] = 5
    if ml["risk_firewall_disabled"]:
        raw["network_defense"]["firewall_active"] = False
    if ml["risk_autoupdates_disabled"]:
        raw["updating"]["unattended_upgrades_enabled"] = False  # deliberate typo?
    return ml, raw


def apply_effects(base_ml, base_raw, ids, rng):
    ml = dict(base_ml)
    raw = deep_copy(base_raw)
    for mid in ids:
        eff = EFFECTS[mid]
        for k, v in eff["ml"].items():
            if isinstance(v, int) and isinstance(ml.get(k), int) and v <= 1:
                ml[k] = ml.get(k, 0) + v if ml.get(k, 0) < 1 else 1
            elif isinstance(v, (int, float)) and isinstance(ml.get(k), (int, float)) and v > 1:
                ml[k] = ml.get(k, 0) + v
            else:
                ml[k] = v
        for section, fields in eff["raw"].items():
            if section not in raw:
                raw[section] = {}
            for k, v in fields.items():
                if isinstance(v, list) and isinstance(raw[section].get(k), list):
                    raw[section][k] = list(set(raw[section][k]) | set(v))
                elif isinstance(v, bool) or isinstance(v, (int, str)):
                    raw[section][k] = v
                else:
                    raw[section][k] = v
    # telnet also bumps port count realistically
    if "M10" in ids:
        ml["num_listening_ports"] += 1
    if "M11" in ids:
        ml["risk_suid_binaries"] += rng.randint(1, 3)
    return ml, raw


def degrade(rng, ml, rate=0.05):
    """Simulate degraded (non-root) collector runs by masking features."""
    masked = [k for k in ml if rng.random() < rate]
    for k in masked:
        ml[k] = None
    return ml, masked


# ---------------------------------------------------------------------------
# snapshot emission (schema-compatible with collect.py)
# ---------------------------------------------------------------------------

def emit(out, host_id, tag, label, inject_ids, ml, raw, rng):
    ml_degraded, masked = degrade(rng, deep_copy(ml)) if rng.random() < 0.15 \
        else (ml, [])
    snapshot = {
        "meta": {
            "collector_version": VERSION,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "host_id": host_id,
            "tag": tag,
            "label": label,
            "injected_misconfigs": inject_ids,
            "ran_as_root": not masked,
            "check_errors": [f"synthetic:mask:{k}" for k in masked],
            "synthetic": True,
            "generator": "synth_dataset.py",
        },
        "features_raw": raw,
        "features_ml": ml_degraded,
    }
    safe = f"{host_id}_{tag}".replace(" ", "_")
    fname = os.path.join(out, f"{safe}_{emit.seq:05d}_{int(time.time()*1000)}.json")
    emit.seq += 1
    with open(fname, "w") as fh:
        json.dump(snapshot, fh, indent=2)
    return fname
emit.seq = 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():

    ap = argparse.ArgumentParser(description="AutoSecure synthetic dataset generator")
    ap.add_argument("--out", default="../dataset_synth")
    ap.add_argument("--clean", type=int, default=150)
    ap.add_argument("--singles", type=int, default=10,
                    help="samples per misconfig ID")
    ap.add_argument("--combos", type=int, default=200)
    ap.add_argument("--combo-min", type=int, default=2)
    ap.add_argument("--combo-max", type=int, default=4)
    ap.add_argument("--misconfigs", nargs="*", default=ALL_IDS)
    ap.add_argument("--profiles", nargs="*", default=list(PROFILES.keys()))
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)

    # validate misconfig IDs
    bad = [m for m in args.misconfigs if m not in EFFECTS]
    if bad:
        ap.error(f"unknown misconfig IDs: {bad} (valid: {ALL_IDS})")

    n = 0
    print(f"[*] generating into {args.out}")

    # tier 1: clean
    for i in range(args.clean):
        prof = rng.choice(args.profiles)
        ml, raw = clean_baseline(rng, prof)
        emit(args.out, f"synth-{prof[:4]}", f"clean-{prof}", "clean", [], ml, raw, rng)
        n += 1
    print(f"[+] clean: {args.clean}")

    # tier 2: singles
    for mid in args.misconfigs:
        for r in range(args.singles):
            prof = rng.choice(args.profiles)
            base_ml, base_raw = clean_baseline(rng, prof)
            ml, raw = apply_effects(base_ml, base_raw, [mid], rng)
            emit(args.out, f"synth-{prof[:4]}", mid, "vulnerable", [mid],
                 ml, raw, rng)
            n += 1
    print(f"[+] singles: {args.singles} x {len(args.misconfigs)}")

    # tier 3: combos
    for i in range(args.combos):
        k = rng.randint(args.combo_min, args.combo_max)
        combo = rng.sample(args.misconfigs, min(k, len(args.misconfigs)))
        prof = rng.choice(args.profiles)
        base_ml, base_raw = clean_baseline(rng, prof)
        ml, raw = apply_effects(base_ml, base_raw, combo, rng)
        tag = "combo-" + "-".join(combo)
        emit(args.out, f"synth-{prof[:4]}", tag, "vulnerable", combo,
             ml, raw, rng)
        n += 1
    print(f"[+] combos: {args.combos}")

    print(f"[+] wrote {n} synthetic snapshots to {args.out}")
    print(f"[.] next: train on --dataset {args.out}, TEST on real snapshots")
    print("[.] from Proxmox LXC clones (train/test separation mandatory!)")


if __name__ == "__main__":
    main()

