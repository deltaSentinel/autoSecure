=====================================================================
 File: README-collector.md
 ---------------------------------------------------------------------
 collector/ package layout (place all files in the same directory):

   common.py     helpers (sh/read_file/which/os-release parsing)
   backends.py   apt | dnf | pacman | null  (updates + auto-updates)
   checks.py     the seven features_raw sections, backend-agnostic
   collect.py    orchestrator -> snapshot JSON (run this one)

 Drop-in status: schema-identical to the original monolithic collect.py.
 The ONLY behavioral differences are bugfixes [1][2][3] in checks.py /
 build_ml_features — and [3] (permit-root-login risk map) REQUIRES the
 paired synth_dataset.py clean_baseline patch + regenerate + retrain.

 Smoke test before trusting it:
   cd collector
   sudo python3 collect.py --host-id selftest --tag smoke --out /tmp/snaps
     then diff features_ml key sets against an old snapshot:
   python3 - << 'EOF'
   import json, glob, sys
   old = json.load(open(sorted(glob.glob("../dataset/OLD_FILE.json"))[0]))
   new = json.load(open(sorted(glob.glob("/tmp/snaps/selftest_smoke_*.json"))[0]))
   assert old["features_ml"].keys() == new["features_ml"].keys(), \
       set(old["features_ml"]) ^ set(new["features_ml"])
   print("[+] feature keys identical:", len(new["features_ml"]))
   EOF

 Cross-distro notes:
   - detect_backend() probes binaries, not /etc/os-release, so it works
     in stripped LXCs and golden-copy Pi images.
   - Unknown distro -> NullBackend -> update features are None, which
     the agent's unresolved path already handles.
   - DNF exit-code contract verified against dnf4 only; re-verify on a
     real Fedora/EL box before trusting DNF5 numbers.
   - Collect a clean Fedora/Rocky baseline BEFORE injecting misconfigs
     so the model sees cross-distro variation inside the SAFE class.
 =====================================================================

## Target prerequisites

Per-backend tooling the collector expects on the scanned host. The
collector probes binaries, not /etc/os-release, so what matters is what
is installed, not what the distro calls itself. Missing tooling does not
crash the run; affected features become None (unknown) and an error
entry is recorded in meta.check_errors.

### All targets

- python3 (3.8+), root recommended (some probes degrade without it)
- `ss` (iproute2) and `systemctl` used by the services check; absent or
  failing probes record errors and yield None features

### apt (Debian, Ubuntu)

- `apt-get` for the simulated upgrade
- `/etc/apt/apt.conf.d/20auto-upgrades` or
  `/etc/apt/apt.conf.d/50unattended-upgrades` presence fallback

### dnf (Fedora, RHEL/Rocky)

- `dnf` (dnf4 or dnf5). Exit-code contract verified against dnf4 only;
  re-verify on the target Fedora/EL box before trusting dnf5 numbers
- `systemctl` for the dnf-automatic timers. Timers absent = automatic
  updates treated as disabled, not unknown

### pacman (Arch, BlackArch)

- `pacman` for backend detection
- `checkupdates` from the `pacman-contrib` package for pending-update
  counting. Without it, pending updates are None (unknown), and you get
  the `updating:binary_missing_pacman` error entry rather than a count
- No Arch auto-update mechanism is assumed: auto-updates always read
  None and emit `updating:auto_upgrades_unresolved`. Expect that entry
  on every Arch snapshot; it is by design, not a fault

### null

- No recognized manager: all updating features None. Firewalls may
  still be probed via iptables if present
