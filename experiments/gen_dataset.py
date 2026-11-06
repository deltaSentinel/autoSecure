#!/usr/bin/env python3
"""AutoSecure — batch dataset generator.

Orchestrates inject.sh + collect.py to mass-produce labeled snapshots:

    tier 1: clean baselines (nothing injected)
    tier 2: single-misconfig samples (one ID from your chosen set)
    tier 3: random combinations (2-4 misconfigs stacked) — the compound-
            configuration samples that make the hybrid-arbitration
            experiment meaningful.

Each cycle: apply -> wait -> collect -> revert -> verify revert. If a revert
verification fails, the run ABORTS loudly rather than silently poisoning the
dataset with dirty hosts (a mislabeled 'clean' sample is worse than no sample).

Verification of revert: after reverting, collect an 'internal check' snapshot
and assert no reflex-detectable residue (checks the L0-visible subset, so it
catches everything your agent's reflex layer could see leaking across samples).

Usage (run as root on the LAB TARGET itself):
    sudo python3 gen_dataset.py --host-id target-b --out ../dataset \
         --clean 15 --singles 3 --combos 30

    # smaller shakeout run first:
    sudo python3 gen_dataset.py --host-id target-b --out ../dataset \
         --clean 3 --singles 1 --combos 0 --misconfigs M01 M04 M07

Requires: collect.py (imported from same dir), inject.sh (same dir),
sqlite3-free; everything else stdlib.
"""

import argparse
import itertools
import json
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECT = os.path.join(HERE, "collect.py")
INJECT = os.path.join(HERE, "inject.sh")

ALL_MISCONFIGS = [f"M{i:02d}" for i in range(1, 16)]


# ---------------------------------------------------------------------------
# shell helpers
# ---------------------------------------------------------------------------

def run(cmd, timeout=120, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(
            f"command failed ({r.returncode}): {' '.join(cmd)}\n"
            f"stderr: {r.stderr.strip()[:500]}")
    return r


def inject(action, mid):
    run(["bash", INJECT, action, mid], timeout=180)


def collect(host_id, tag, label, out, inject_ids=None):
    """Run the collector; returns path of the snapshot written."""
    cmd = ["python3", COLLECT, "--host-id", host_id, "--tag", tag,
           "--out", out]
    if label:
        cmd += ["--label", label]
    if inject_ids:
        cmd += ["--inject"] + list(inject_ids)
    before = set(snapshot_paths(out))
    run(cmd, timeout=600)
    after = set(snapshot_paths(out))
    new = sorted(after - before)
    if not new:
        raise RuntimeError("collector ran but wrote no snapshot — "
                           "check collect.py --out path")
    return new[-1]


def snapshot_paths(out):
    return [os.path.join(out, f) for f in os.listdir(out) if f.endswith(".json")]


# ---------------------------------------------------------------------------
# revert verification (dataset integrity guard)
# ---------------------------------------------------------------------------
# Reflex-visible residue checks — mirrors the agent's L0-relevant raw fields.
# Kept deliberately small and independent of agent/main.py so the generator
# stays a standalone tool.

def residue_findings(raw):
    bad = []
    svc = raw.get("services", {})
    if svc.get("telnet_open"):
        bad.append("telnet still open")
    acc = raw.get("accounts", {})
    if acc.get("users_uid0_extra"):
        bad.append("extra UID-0 users remain: " + ",".join(acc["users_uid0_extra"]))
    if acc.get("users_empty_password"):
        bad.append("empty-password users remain: " + ",".join(acc["users_empty_password"]))
    if acc.get("sudo_nopasswd_entries"):
        bad.append("sudoers NOPASSWD entries remain")
    ssh = raw.get("ssh", {})
    if ssh.get("permit_root_login") == "yes":
        bad.append("sshd still permits root login")
    if ssh.get("permit_empty_passwords") == "yes":
        bad.append("sshd still permits empty passwords")
    fs = raw.get("filesystem", {})
    sp = fs.get("shadow_permissions")
    if sp:
        try:
            mode = int(str(sp), 8)
            if mode & 0o022:
                bad.append(f"/etc/shadow mode still {sp}")
        except ValueError:
            pass
    nd = raw.get("network_defense", {})
    if nd.get("firewall_active") is False:
        bad.append("firewall still down")
    return bad


def verify_reverted(host_id, out, applied_ids, scratch):
    """Collect a scratch snapshot (unlabeled) and assert no L0 residue."""
    path = collect(host_id, f"verify-{'-'.join(applied_ids)}", None,
                   scratch, inject_ids=applied_ids)
    with open(path) as f:
        snap = json.load(f)
    residue = residue_findings(snap["features_raw"])
    # scratch snapshots are deleted; they exist only for verification
    os.remove(path)
    return residue


# ---------------------------------------------------------------------------
# generation passes
# ---------------------------------------------------------------------------

def gen_clean(host_id, out, n, scratch, jitter=2.0):
    print(f"\n=== tier 1: {n} clean baseline samples ===")
    for i in range(n):
        p = collect(host_id, "clean-baseline", "clean", out)
        print(f"  [clean {i+1}/{n}] {os.path.basename(p)}")
        time.sleep(random.uniform(0.2, jitter))


def gen_singles(host_id, out, ids, reps, scratch, settle=1.0):
    print(f"\n=== tier 2: {reps}x each of {len(ids)} single misconfigs ===")
    for mid in ids:
        for r in range(reps):
            inject("apply", mid)
            time.sleep(settle)          # let sshd reload / services settle
            p = collect(host_id, mid, "vulnerable", out, [mid])
            print(f"  [{mid} {r+1}/{reps}] {os.path.basename(p)}")
            inject("revert", mid)
            residue = verify_reverted(host_id, out, [mid], scratch)
            if residue:
                sys.exit(f"\n[ABORT] {mid} left residue after revert: "
                         f"{residue}\nFix the revert path in inject.sh before "
                         f"continuing — otherwise clean samples get poisoned.")


def gen_combos(host_id, out, ids, n, rng, scratch, min_k=2, max_k=4,
               settle=1.0):
    print(f"\n=== tier 3: {n} random combinations (k={min_k}-{max_k}) ===")
    for i in range(n):
        k = rng.randint(min_k, max_k)
        combo = rng.sample(ids, k)
        tag = "combo-" + "-".join(combo)
        try:
            for mid in combo:
                inject("apply", mid)
            time.sleep(settle)
            p = collect(host_id, tag, "vulnerable", out, combo)
            print(f"  [combo {i+1}/{n}] {tag} -> {os.path.basename(p)}")
        finally:
            # always attempt revert, even if collection failed
            for mid in reversed(combo):
                inject("revert", mid)
            residue = verify_reverted(host_id, out, combo, scratch)
        if residue:
            sys.exit(f"\n[ABORT] combo {combo} left residue: {residue}\n"
                     "Do not continue until every revert is clean.")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="AutoSecure dataset generator")
    ap.add_argument("--host-id", required=True, help="target identifier")
    ap.add_argument("--out", default="../dataset", help="snapshot output dir")
    ap.add_argument("--scratch", default="/tmp/autosecure-scratch",
                    help="dir for revert-verification snapshots (unlabeled)")
    ap.add_argument("--clean", type=int, default=10,
                    help="number of clean baseline samples")
    ap.add_argument("--singles", type=int, default=2,
                    help="repetitions per single misconfig")
    ap.add_argument("--combos", type=int, default=25,
                    help="number of random combination samples")
    ap.add_argument("--combo-min", type=int, default=2)
    ap.add_argument("--combo-max", type=int, default=4)
    ap.add_argument("--misconfigs", nargs="*", default=ALL_MISCONFIGS,
                    help=f"subset of misconfig IDs to use "
                         f"(default: all 15)")
    ap.add_argument("--skip-tier", nargs="*", default=[],
                    help="tiers to skip: clean singles combos")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[-] run as root: sudo python3 gen_dataset.py ... "
                 "(inject.sh requires root)")

    ids = args.misconfigs
    bad = [m for m in ids if m not in ALL_MISCONFIGS]
    if bad:
        sys.exit(f"[-] unknown misconfig IDs: {bad}")

    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.scratch, exist_ok=True)

    n_before = len(snapshot_paths(args.out))
    print(f"[*] AutoSecure dataset generator")
    print(f"    host={args.host_id} out={args.out}")
    print(f"    misconfigs={len(ids)}: {','.join(ids)}")
    print(f"    plan: clean={args.clean} singles={args.singles}/id "
          f"combos={args.combos}")
    print(f"    existing snapshots: {n_before}")
    sys.stdout.flush()

    # sanity check that the catalog works before doing anything
    inject("status", "")
    inject("applied_state_check", "") if False else None
    r = run(["bash", INJECT, "list"], check=False)
    if r.returncode != 0:
        sys.exit("[-] inject.sh list failed — check the script path")

    t0 = time.time()
    if "clean" not in args.skip_tier and args.clean > 0:
        gen_clean(args.host_id, args.out, args.clean, args.scratch)
    if "singles" not in args.skip_tier and args.singles > 0:
        gen_singles(args.host_id, args.out, ids, args.singles, args.scratch)
    if "combos" not in args.skip_tier and args.combos > 0:
        gen_combos(args.host_id, args.out, ids, args.combos, rng, args.scratch,
                   args.combo_min, args.combo_max)

    n_after = len(snapshot_paths(args.out))
    print(f"\n[+] done in {time.time()-t0:.0f}s: "
          f"{n_after - n_before} new snapshots "
          f"({n_after} total in {args.out})")

    # class balance summary
    labels = {"clean": 0, "vulnerable": 0, "unlabeled": 0}
    for p in snapshot_paths(args.out):
        with open(p) as f:
            lab = json.load(f)["meta"].get("label")
        labels[lab if lab in ("clean", "vulnerable") else "unlabeled"] += 1
    print(f"[+] dataset balance: {labels}")
    if labels["unlabeled"]:
        print("[!] unlabeled snapshots present — remove or relabel before "
              "training")


if __name__ == "__main__":
    main()

