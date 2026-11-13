# Collector Data Contract

Reference for the break phase: what `collector/` emits, the format
conventions, failure semantics, and the known synth/real divergences to
expect when the first LXC snapshots land in `data/real/`.

---

## 1. Snapshot structure

Each snapshot is a single JSON document produced by `collect.py`, containing:

- `meta` — host identity (`host_id`), timestamp, `pkg_backend`; synthetic
  snapshots carry `"synthetic": true` and are never silently mixed with real
  data.
- Seven `features_raw` sections, emitted by `checks.py` (see §2).
- `features_ml` — 25 derived features produced by `build_ml_features()`
  in `collect.py`, consumed by the L1 model via `models/feature_keys.json`
  (canonical order).
- `errors` — list of `<section>:<key>:<problem>` strings. Every check
  returns `(raw_dict, errors_list); **no error entry is ever swallowed**.

Agent pairing is by `meta.host_id` — there is no `--host-id` flag; host
identity comes from the snapshot itself.

## 2. Raw keys by section (authority: `checks.py`)

| Section | Keys |
|---|---|
| `ssh` | `permit_root_login`, `password_authentication`, `permit_empty_passwords` — lowercase strings ("yes"/"no"/…) resolved via `sshd -T` (root) with sshd_config global-scope fallback; **Match-block-scoped settings are not scored** |
| `filesystem` | `world_writable_files_in_etc`, `world_writable_dirs_no_sticky`, `suid_binaries`, `sgid_binaries` (ints), `shadow_permissions`, `passwd_permissions` (**bare octal strings**, e.g. "640") |
| `accounts` | `users_uid0_extra`, `accounts_with_login_shell`, `users_empty_password` (lists), `sudo_nopasswd_entries` (list of raw sudoers lines) |
| `login_defs` | `pass_max_days`, `pass_min_days`, `pass_min_len`, `pass_warn_age` (ints or null) |
| `network_defense` | `firewall_active` (bool), `firewall_backend` (string), `fail2ban_active` (bool) |
| `updating` | `unattended_upgrades_enabled`, `pending_updates_total`, `pending_security_updates`, plus additive `pkg_backend` |
| `services` | `running_services`, `listening_ports` (sorted list), `telnet_open`, `ftp_open`, `snmp_open`, `ssh_default_port_open` (bools) |

These exact key names are load-bearing: the L0 reflex rules (R01–R16),
R16's drift comparison, and the synthetic generator's `CLEAN_RAW_TEMPLATE`
and `EFFECTS` all reference them. Verified against the rule catalog during
the pre-break audit (Nov 2026).

## 3. ML derivation layer (`build_ml_features`, collect.py)

- Every `risk_*` feature passes through `clip(v, cap)`:
  `clip` returns **None when the raw value is None**, else `min(int(v), cap)`.
  Caps: world-writable files/dirs 10; suid/sgid 200; uid0-extra 5;
  empty-password 5; sudo-nopasswd 5; login-shell accounts 30; pending
  updates 100; security updates 100; running services 80;
  `num_listening_ports` clipped at its line-140 cap.
- **Fail-static:** a failed count surfaces as `None` in the ML feature —
  never a fabricated zero, never a crash. A `null` in a `risk_*` field
  means the underlying probe failed; treat it as "unmeasured," not "safe."

## 4. Failure semantics (fail-open postures — read before interpreting real data)

- `count_find` returns **0 on total find failure**. Consequence: if SUID
  counting fails in one scan, `suid_binaries` reads 0; R16 (fires on
  *increase only*) stays silent for that scan, but the *next* successful
  scan fires a phantom `0 → 211` increase. **A phantom R16 on real data
  means "suspect a failed count first, an intruder second."**
- `ssh_setting` fails to `None` when neither `sshd -T` nor the config
  resolve; R13 et al. treat None as not-firing.
- Shadow unreadable without root → error entry
  `accounts:shadow_unreadable_needs_root`; collection continues.

## 5. Format conventions (synth/real parity)

- **Permissions are bare octal strings** ("640", "666"), matching the
  synthetic generator and the pytest catalog fixtures. `stat_octal` was
  patched to `format(mode, "o")` for this reason (it previously emitted
  Python-style "0o640"; the agent's `_oct` parser tolerates both, but the
  canonical dialect is bare — kept one dialect to keep the raw-key diff
  gate clean).
- The R02 lambda's `_oct` is `int(str(p), 8)` — tolerant of the `0o`
  prefix, fail-static (None → rule does not fire).

## 6. Expected synth/real divergences (break-phase gate whitelist)

These differences are **anticipated** and must not be read as bugs:

1. **Clip saturation on count features.** Real Debian-ish hosts carry
   ~200+ SUID binaries and dozens of listening ports;
   `risk_suid_binaries`, `risk_sgid_binaries`, and `num_listening_ports`
   will saturate at their caps (200/200/…), while synthetic training data
   sits near 0. This is the registered clip-semantics audit item — check
   the distribution, don't retrain blindly.
2. **`pkg_backend`** is additive on real data (apt/dnf); synthetic
   snapshots carry the modeled equivalent. Allowed by the additive-keys
   rule of the raw-key diff gate.
3. **Absolute SUID counts** (raw `suid_binaries` ≈ 210 real vs 0–2 synth):
   handled temporally by R16 (fires on *increase*, not absolute level);
   no absolute-threshold rule exists by design.

## 7. Audit provenance

Raw keys, ML derivations, clip caps, and failure semantics were verified
line-by-line against the rule catalog and synthetic generator during the
pre-break contract review (commit `pre-real-data` era). Bug fixes from
that review: `world_writable_dirs_no_sticky` None-vs-0 (now always an
int), `stat_octal` bare-octal parity, sshd candidate dedup
(FIX [1]), dead double-assignment removal (FIX [2]), explicit
PermitRootLogin risk map (FIX [3]).

## 8. Break-phase verification gates (in run order)

1. **Shakeout cycle** (`gen_dataset.py --clean 3 --singles 1 --combos 0`)
   on one template CT — validates inject → collect → revert under the
   refactored collector before the 45-cycle batch.
2. **Effects-parity check:** diff the first real M0x snapshot against a
   synthetic M0x sample feature-by-feature. The transfer gap measures
   modeling fidelity as much as domain gap — verify the first one matches.
3. **Label counts:** `data/real` totals vs the campaign manifest; a
   failed revert aborts loudly in `gen_dataset.py` — never overrides it.
4. **feature_keys empty-diff:** `diff models/feature_keys.json` against
   the keys present in each real snapshot (25 keys, canonical order).
5. **Raw-key diff:** §2 table above is the whitelist; `pkg_backend` (§6.2)
   is the only sanctioned additive difference.
6. **Clip-semantics audit:** distribution of the three capped count
   features (§6.1) before `eval_holdout.py` results are interpreted.
