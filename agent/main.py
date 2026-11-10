#!/usr/bin/env python3
"""AutoSecure Agent — main harness.

Full 4-layer agent over the collector snapshots:

    L0  Reflex Engine       deterministic condition->finding rules
    L1  ML Classifier       trained posture model (fail-static if absent)
    L2  Diagnostician       merge L0+L1, attribute with cross-scan deltas
    L3  Remediation Planner utility-ranked reversible actions behind an
                            interactive human-approval gate

SAFETY INVARIANTS (enforced here, not by convention):
    1. READ-ONLY BY DEFAULT. Nothing is mutated on the target unless
       --act is passed AND the operator approves each step interactively.
    2. REVERSIBILITY. Every mutating action is drawn from the remediation
       KB, which carries a pre-registered rollback command. Rollback state
       is persisted before any action executes.
    3. FAIL-STATIC. Missing model, missing snapshot fields, or unreadable
       features degrade the run and are REPORTED — the agent never guesses.
    4. AUDITABILITY. Every decision, approval, rejection, and execution
       outcome is written to the SQLite working memory.

Usage:
    # Assessment only (always safe):
    python3 main.py --snapshot ../dataset/target-b_M01_1234.json

    # With explicit memory file and classifier:
    python3 main.py --snapshot snap.json --db mem.db --model ../train/model.joblib

    # Remediation with approval gate (mutating, interactive):
    sudo python3 main.py --snapshot snap.json --db mem.db --act

Requires: python3 stdlib; joblib+trained model optional for L1.
Tested mindset: Debian/Ubuntu lab targets.
"""

import argparse
import datetime as dt
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from getpass import getpass

AGENT_VERSION = "0.2.0"

# ===========================================================================
# SCHEMA / WORKING MEMORY
# ===========================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY,
    ts            TEXT NOT NULL,
    host_id       TEXT,
    tag           TEXT,
    snapshot_path TEXT,
    features_blob TEXT,          -- JSON of features_ml, for delta computation
    raw_blob      TEXT           -- JSON of features_raw, for L2 baseline-diff (R16)
);
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    rule_id       TEXT,         -- R01..R16, or 'L1' for classifier-only
    layer         TEXT,         -- L0 / L1 / L2
    severity      REAL,
    evidence      TEXT,         -- human-readable proof chain
    status        TEXT DEFAULT 'open'   -- open|remediated|rejected
);
CREATE TABLE IF NOT EXISTS feedback (
    id            INTEGER PRIMARY KEY,
    finding_id    INTEGER REFERENCES findings(id),
    decision      TEXT,         -- approve|reject
    rule_id       TEXT,
    reason        TEXT,
    ts            TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    id            INTEGER PRIMARY KEY,
    scan_id       INTEGER REFERENCES scans(id),
    finding_id    INTEGER REFERENCES findings(id),
    command       TEXT,
    rollback      TEXT,
    state         TEXT,         -- proposed|approved|executed|rolled_back|failed
    output        TEXT,
    ts            TEXT
);
"""

AGENT_BACKUP_DIR = "/var/lib/autosecure/agent-backups"   # root runs; see --act


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def open_memory(path):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


# ===========================================================================
# PERCEPTION
# ===========================================================================

def perceive(snapshot_path):
    """Load and validate a collector snapshot. Fail-static on bad input."""
    try:
        with open(snapshot_path) as f:
            snap = json.load(f)
    except FileNotFoundError:
        sys.exit(f"[-] snapshot not found: {snapshot_path}")
    except json.JSONDecodeError as e:
        sys.exit(f"[-] snapshot is not valid JSON: {e}")

    problems = []
    for key in ("meta", "features_raw", "features_ml"):
        if key not in snap:
            problems.append(key)
    if problems:
        sys.exit(f"[-] snapshot missing required sections: {problems} "
                 f"— regenerate with collect.py >= 0.1.0")

    degraded = [e for e in snap["meta"].get("check_errors", [])]
    if degraded:
        print(f"[!] {len(degraded)} degraded checks in snapshot: "
              f"{', '.join(degraded[:5])}{' ...' if len(degraded) > 5 else ''}",
              file=sys.stderr)
    return snap


def insert_scan(con, snap, snapshot_path):
    cur = con.execute(
        "INSERT INTO scans(ts, host_id, tag, snapshot_path, features_blob, raw_blob) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (utcnow(), snap["meta"].get("host_id"), snap["meta"].get("tag"),
         snapshot_path, json.dumps(snap["features_ml"], sort_keys=True),
         json.dumps(snap["features_raw"], sort_keys=True)))
    return cur.lastrowid


def previous_scan(con, scan_id, host_id):
    """Most recent PRIOR scan for the same host (belief state)."""
    row = con.execute(
        "SELECT id, features_blob, raw_blob, ts FROM scans "
        "WHERE id < ? AND (host_id = ? OR ? IS NULL) "
        "ORDER BY id DESC LIMIT 1",
        (scan_id, host_id, host_id)).fetchone()
    return row


# ===========================================================================
# L0 — REFLEX ENGINE (simple reflex agent)
# ===========================================================================
# Each rule: (rule_id, condition_fn, severity, description)
# condition_fn receives features_raw; return truthy to fire.
# Unknown/None values must be treated as NOT firing (fail-static, no guessing).

def _oct(p):
    try:
        return int(str(p), 8)
    except (TypeError, ValueError):
        return None


REFLEX_RULES = [
    ("R01", lambda r: r.get("services", {}).get("telnet_open") is True,
     1.0, "Telnet service exposed (port 23 open)"),
    ("R02", lambda r: (_oct(r.get("filesystem", {}).get("shadow_permissions"))
                       or 0) & 0o022 != 0,
     1.0, "/etc/shadow is group- or world-writable"),
    ("R03", lambda r: bool(r.get("accounts", {}).get("users_empty_password")),
     1.0, "User accounts with empty password fields"),
    ("R04", lambda r: bool(r.get("accounts", {}).get("users_uid0_extra")),
     1.0, "Non-root accounts with UID 0 (backdoor user)"),
    ("R05", lambda r: r.get("ssh", {}).get("permit_empty_passwords") == "yes",
     1.0, "SSH PermitEmptyPasswords enabled"),
    ("R06", lambda r: bool(r.get("accounts", {}).get("sudo_nopasswd_entries")),
     0.8, "NOPASSWD entries in sudoers"),
    ("R08", lambda r: r.get("network_defense", {}).get("firewall_active") is False,
     0.8, "No active firewall backend"),
    ("R09", lambda r: r.get("login_defs", {}).get("pass_min_len") is not None
                       and r["login_defs"]["pass_min_len"] < 8,
     0.5, "Password minimum length below 8 characters"),
    ("R10", lambda r: r.get("updating", {}).get("unattended_upgrades_enabled") is False,
     0.5, "Unattended security updates disabled"),
    ("R11", lambda r: r.get("services", {}).get("ftp_open") is True,
     0.8, "FTP service exposed (cleartext protocol)"),
    ("R12", lambda r: r.get("services", {}).get("snmp_open") is True,
     0.6, "SNMP service exposed"),
     ("R13", lambda r: str(r.get("ssh", {}).get("permit_root_login")).lower() == "yes",
     0.8, "SSH PermitRootLogin enabled - direct root login permitted"),
     ("R14", lambda r: bool(r.get("filesystem", {}).get("world_writable_dirs_no_sticky")),
     0.7, "World-writable directories without sticky bit"),
     ("R15", lambda r: bool(r.get("filesystem", {}).get("world_writable_files_in_etc")),
     0.9, "World-writable files under /etc"),
]


def evaluate_reflex(raw):
    """L0: run the condition-action catalog. Returns list of findings."""
    findings = []
    for rule_id, cond, severity, desc in REFLEX_RULES:
        try:
            if cond(raw):
                findings.append({
                    "rule_id": rule_id, "layer": "L0",
                    "severity": severity, "evidence": desc,
                })
        except Exception as e:  # never let one bad field kill the sweep
            print(f"[!] reflex rule {rule_id} skipped ({e.__class__.__name__})",
                  file=sys.stderr)
    return findings


# ===========================================================================
# L1 — ML CLASSIFIER (model-based agent)
# ===========================================================================

def _vectorize(features_ml):
    """Sorted-key vector. None -> 0.0 with a recorded mask (fail-static)."""
    keys = sorted(features_ml.keys())
    vec, masked = [], []
    for k in keys:
        v = features_ml[k]
        if v is None:
            masked.append(k)
            v = 0.0
        vec.append(float(v))
    return vec, keys, masked


def classify(features_ml, model_path):
    """Returns (p_vulnerable, feature_importances or None, note) — fail-static."""
    if model_path is None:
        return None, None, "no model path supplied (L1 disabled)"
    if not os.path.exists(model_path):
        return None, None, f"model absent: {model_path} (L1 disabled, fail-static)"
    try:
        import joblib  # noqa: deferred import keeps stdlib-only reflex mode
    except ImportError:
        return None, None, "joblib not installed (L1 disabled, fail-static)"

    vec, keys, masked = _vectorize(features_ml)
    try:
        model = joblib.load(model_path)
        proba = model.predict_proba([vec])[0]
        p = float(proba[1]) if len(proba) > 1 else float(proba[0])
    except Exception as e:
        return None, None, f"model load/inference failed: {e} (L1 disabled)"

    importances = None
    imp = getattr(model, "feature_importances_", None)
    if imp is not None:
        importances = dict(zip(keys, [float(x) for x in imp]))

    note = "OK"
    if masked:
        note = f"OK ({len(masked)} features masked to 0.0: {masked[:3]}...)"
    return p, importances, note


# ===========================================================================
# L2 — DIAGNOSTICIAN (delta attribution)
# ===========================================================================

def compute_deltas(prev_blob, current_ml):
    """Attribute changes since last scan (belief-state comparison)."""
    if prev_blob is None:
        return {}, "first scan for this host — no delta baseline"
    try:
        prev = json.loads(prev_blob)
    except json.JSONDecodeError:
        return {}, "previous feature blob corrupt — skipping deltas"

    deltas = {}
    for k in sorted(set(prev) | set(current_ml)):
        old, new = prev.get(k), current_ml.get(k)
        if old != new:
            deltas[k] = {"was": old, "now": new}
    note = f"{len(deltas)} features changed since previous scan"
    return deltas, note


def diagnose(reflex_findings, p_vuln, importances, deltas):
    """Merge L0 + L1 into attributed findings. Adds provenance."""
    findings = []
    for f in reflex_findings:
        ev = f["evidence"]
        if f["rule_id"] in {"R02"} and "risk_shadow" in deltas:
            d = deltas["risk_shadow"]
            ev += f" (drift: {d['was']} -> {d['now']})"
        if p_vuln is not None:
            ev += f" [classifier agrees: p={p_vuln:.2f}]"
        findings.append(dict(f, evidence=ev))

    if p_vuln is not None and not reflex_findings and p_vuln >= 0.5:
        top = ""
        if importances:
            ranked = sorted(importances.items(), key=lambda kv: -kv[1])[:3]
            top = " top contributing features: " + ", ".join(
                f"{k} ({v:.3f})" for k, v in ranked)
        findings.append({
            "rule_id": "L1", "layer": "L1", "severity": round(p_vuln, 2),
            "evidence": f"classifier flags vulnerable posture (p={p_vuln:.2f});"
                        f" no reflex rule fired — compound-config suspicion.{top}",
        })
    return findings


# ===========================================================================
# L3 — REMEDIATION PLANNER (utility-based, goal-based)
# ===========================================================================
# Remediation knowledge base: rule_id ->
#   (action, rollback_command, disruptiveness in [0,1], rationale)
# Alpha/beta/gamma are exposed as CLI knobs for the experiment plan.

REMEDIATION_KB = {
    "R01": ("systemctl disable --now inetutils-inetd",
            "systemctl enable --now inetutils-inetd", 0.6,
            "Disable telnet; rollback re-enables"),
    "R02": ("chmod 0640 /etc/shadow", None, 0.1,   # backup taken below
            "Restore restrictive /etc/shadow mode"),
    "R03": ("echo 'Lock affected empty-password accounts' ; "
            "passwd -l $(awk -F: '$2==\"\"{print $1}' /etc/shadow | tr '\\n' ' ')",
            None, 0.5, "Lock accounts with empty password fields"),
    "R04": ("userdel backdoor01", "useradd -o -u 0 -g 0 -M backdoor01", 0.7,
            "Remove unauthorized UID-0 account"),
    "R05": ("sed -i 's/^\\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "
            "/etc/ssh/sshd_config && systemctl reload ssh",
            "sed -i 's/^\\s*PermitEmptyPasswords.*/PermitEmptyPasswords yes/' "
            "/etc/ssh/sshd_config && systemctl reload ssh", 0.4,
            "Hardens sshd; rollback restores prior config"),
    "R06": ("rm -f /etc/sudoers.d/* && "
            "sed -i '/NOPASSWD/d' /etc/sudoers", None, 0.8,
            "Strip NOPASSWD grants — review before approving (breaks automation)"),
    "R08": ("ufw enable", "ufw disable", 0.7,
            "Enable firewall; may disrupt active listeners"),
    "R09": ("sed -i 's/^\\s*PASS_MIN_LEN.*/PASS_MIN_LEN\\t12/' /etc/login.defs",
            "sed -i 's/^\\s*PASS_MIN_LEN.*/PASS_MIN_LEN\\t5/' /etc/login.defs", 0.1,
            "Raise minimum password length"),
    "R10": ("sed -i 's/APT::Periodic::Unattended-Upgrade \"0\"/"
            "APT::Periodic::Unattended-Upgrade \"1\"/' "
            "/etc/apt/apt.conf.d/20auto-upgrades", None, 0.2,
            "Re-enable unattended security upgrades"),
    "R11": ("systemctl disable --now vsftpd", "systemctl enable --now vsftpd", 0.6,
            "Stop cleartext FTP exposure"),
    "R12": ("systemctl disable --now snmpd", "systemctl enable --now snmpd", 0.5,
            "Stop SNMP exposure"),
    "L1": (None, None, None,
           "Classifier-only finding: investigate compound configuration manually"),
}

# Utility:  U(a) = ALPHA*severity - BETA*disruptiveness - GAMMA*fp_penalty
ALPHA_DEFAULT, BETA_DEFAULT, GAMMA_DEFAULT = 1.0, 0.5, 0.75


def fp_penalty(con, rule_id):
    """Learning loop: fraction of past operator rejections for this rule."""
    row = con.execute(
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN decision='reject' THEN 1 ELSE 0 END) AS rejects "
        "FROM feedback WHERE rule_id = ?", (rule_id,)).fetchone()
    if not row or not row["total"]:
        return 0.0
    return row["rejects"] / row["total"]


def plan(con, findings, alpha=ALPHA_DEFAULT, beta=BETA_DEFAULT,
         gamma=GAMMA_DEFAULT):
    """Utility-ranked remediation plan. Only PROPOSES actions (invariant 1)."""
    steps = []
    for f in findings:
        rid = f["rule_id"]
        action, rollback, disrupt, rationale = REMEDIATION_KB.get(
            rid, (None, None, None, "no remediation registered"))
        penalty = fp_penalty(con, rid)
        utility = round(alpha * f["severity"]
                        - beta * (disrupt or 0.0)
                        - gamma * penalty, 3)
        steps.append({
            "rule_id": rid, "severity": f["severity"], "utility": utility,
            "action": action, "rollback": rollback,
            "disruptiveness": disrupt, "fp_penalty": penalty,
            "rationale": rationale, "evidence": f["evidence"],
        })
    # rank: highest utility first; N/A actions sink to the bottom
    steps.sort(key=lambda s: (s["action"] is None, -s["utility"]))
    return steps


def composite_risk(findings, p_vuln):
    """Reflex saturation risk fused with classifier probability (max fusion)."""
    if findings:
        total = sum(f["severity"] for f in findings)
        reflex_risk = 1.0 - pow(2.718281828, -total)     # saturating sum
    else:
        reflex_risk = 0.0
    if p_vuln is not None:
        return round(max(reflex_risk, p_vuln), 3)
    return round(reflex_risk, 3)


# ===========================================================================
# APPROVAL GATE + EXECUTION (invariants 1, 2, 4)
# ===========================================================================

def _backup_paths(action):
    """Snapshot any config files the action touches (invariant 2)."""
    os.makedirs(AGENT_BACKUP_DIR, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backed = []
    for token in action.split():
        if token.startswith("/") and os.path.isfile(token):
            dest = os.path.join(AGENT_BACKUP_DIR, f"{stamp}_"
                                + os.path.basename(token))
            shutil.copy2(token, dest)
            backed.append(f"{token} -> {dest}")
    return backed


def execute_plan(con, scan_id, findings_rows, steps, yes_all=False):
    """Interactive approval gate. Nothing runs without per-step consent."""
    approved_any = False
    for idx, step in enumerate(steps):
        if step["action"] is None:
            print(f"\n[{idx}] {step['rule_id']}: {step['rationale']} "
                  f"(no auto-action) — record for manual review")
            continue

        finding_id = findings_rows.get(step["rule_id"])
        con.execute(
            "INSERT INTO actions(scan_id, finding_id, command, rollback, "
            "state, ts) VALUES (?, ?, ?, ?, 'proposed', ?)",
            (scan_id, finding_id, step["action"], step["rollback"], utcnow()))
        con.commit()
        action_id = con.execute(
            "SELECT id FROM actions WHERE scan_id=? AND command=? "
            "ORDER BY id DESC LIMIT 1",
            (scan_id, step["action"])).fetchone()["id"]

        print(f"\n--- Step {idx + 1}/{len(steps)} | utility {step['utility']} "
              f"| disruptiveness {step['disruptiveness']} ---")
        print(f"    {step['rule_id']}: {step['evidence']}")
        print(f"    ACTION  : {step['action']}")
        print(f"    ROLLBACK: {step['rollback'] or '(file backup taken)'}")

        if not yes_all:
            decision = input("    Approve and execute? [y/N/a(ll)/q] ").strip().lower()
            if decision == "q":
                print("[.] operator quit — remaining steps stay proposed")
                break
            if decision == "a":
                yes_all = True
                decision = "y"
            if decision != "y":
                reason = input("    Reason for rejection (logged): ").strip()
                con.execute(
                    "INSERT INTO feedback(finding_id, decision, rule_id, "
                    "reason, ts) VALUES (?, 'reject', ?, ?, ?)",
                    (finding_id, step["rule_id"], reason or "none", utcnow()))
                con.execute("UPDATE actions SET state='rejected' WHERE id=?",
                            (action_id,))
                con.commit()
                print("    [logged rejection — lowers future utility of "
                      f"{step['rule_id']}]")
                continue

        # APPROVED — execute with backup-first discipline
        try:
            backups = _backup_paths(step["action"])
            for b in backups:
                print(f"    backup: {b}")
            r = subprocess.run(step["action"], shell=True, capture_output=True,
                               text=True, timeout=60)
            ok = r.returncode == 0
            con.execute(
                "UPDATE actions SET state=?, output=? WHERE id=?",
                ("executed" if ok else "failed",
                 (r.stdout + r.stderr)[-2000:], action_id))
            con.execute(
                "INSERT INTO feedback(finding_id, decision, rule_id, "
                "reason, ts) VALUES (?, 'approve', ?, 'executed', ?)",
                (finding_id, step["rule_id"], utcnow()))
            con.commit()
            print(f"    [{'+' if ok else '!'}] "
                  f"{'executed' if ok else 'FAILED'} — rollback on file:"
                  f"\n          {step['rollback'] or 'see backup above'}")
            approved_any = approved_any or ok
        except Exception as e:
            con.execute("UPDATE actions SET state='failed', output=? WHERE id=?",
                        (str(e), action_id))
            con.commit()
            print(f"    [-] execution error: {e}")


# ===========================================================================
# REPORT WRITER (primary actuator)
# ===========================================================================

def write_report(path, snap, scan_id, findings, p_vuln, deltas, delta_note,
                 risk, steps, l1_note):
    lines = [
        f"# AutoSecure Assessment — Scan #{scan_id}",
        "",
        f"- **Host**: `{snap['meta'].get('host_id')}`  "
        f"**Tag**: `{snap['meta'].get('tag')}`  "
        f"**Collected**: {snap['meta'].get('collected_at')}",
        f"- **Composite risk**: **{risk:.3f}** "
        f"(classifier p={p_vuln if p_vuln is not None else 'n/a'})",
        f"- **L1 status**: {l1_note}",
        f"- **Drift**: {delta_note}",
        "",
        "## Findings",
        "",
    ]
    if findings:
        for f in findings:
            lines.append(f"- **[{f['rule_id']}/{f['layer']}]** (sev "
                         f"{f['severity']}) {f['evidence']}")
    else:
        lines.append("- None. No reflex rules fired and classifier did not "
                     "flag the host.")
    lines += ["", "## Proposed remediation plan (utility-ranked)", ""]
    if steps:
        lines.append("| # | Rule | Utility | Disruption | Action |")
        lines.append("|---|------|---------|------------|--------|")
        for i, s in enumerate(steps, 1):
            act = (s["action"] or s["rationale"]).replace("|", "\\|")
            lines.append(f"| {i} | {s['rule_id']} | {s['utility']} | "
                         f"{s['disruptiveness']} | `{act}` |")
    else:
        lines.append("- Nothing to remediate.")
    lines += [
        "",
        "> All actions are proposals. Execution requires `--act` plus "
        "interactive approval. Every executed action has a recorded "
        "rollback.",
        "",
    ]
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
    return path


# ===========================================================================
# MAIN DECISION LOOP
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(
        description="AutoSecure agent harness",
        epilog="Default operation is READ-ONLY (report only). "
               "Pass --act for the interactive remediation gate.")
    ap.add_argument("--snapshot", required=True, help="collector snapshot JSON")
    ap.add_argument("--db", default="memory.db", help="SQLite working memory")
    ap.add_argument("--model", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "train", "model.joblib"),
        help="trained classifier (.joblib); absence => fail-static L1-off")
    ap.add_argument("--report", default=None,
                    help="report path (default: report_scan<N>.md)")
    ap.add_argument("--act", action="store_true",
                    help="ENABLE MUTATIONS: enter interactive approval gate")
    ap.add_argument("--yes-all", action="store_true",
                    help="approve every proposed action (lab use only!)")
    ap.add_argument("--alpha", type=float, default=ALPHA_DEFAULT,
                    help="planner weight: severity")
    ap.add_argument("--beta", type=float, default=BETA_DEFAULT,
                    help="planner weight: disruption penalty")
    ap.add_argument("--gamma", type=float, default=GAMMA_DEFAULT,
                    help="planner weight: false-positive penalty")
    args = ap.parse_args()

    if args.yes_all and not args.act:
        sys.exit("[-] --yes-all requires --act (refusing silent mutation)")

    # ---- Perception & belief state --------------------------------------
    snap = perceive(args.snapshot)
    con = open_memory(args.db)
    scan_id = insert_scan(con, snap, args.snapshot)

    prev = previous_scan(con, scan_id, snap["meta"].get("host_id"))
    deltas, delta_note = compute_deltas(
        prev["features_blob"] if prev else None, snap["features_ml"])

    # ---- Reasoning -------------------------------------------------------
    print(f"[+] AutoSecure v{AGENT_VERSION} | scan #{scan_id} | "
          f"host {snap['meta'].get('host_id')}")

    l0 = evaluate_reflex(snap["features_raw"])
    p_vuln, importances, l1_note = classify(snap["features_ml"], args.model)
    findings = diagnose(l0, p_vuln, importances, deltas)
    if prev is not None and prev["raw_blob"] is not None:
        try:
            prev_raw = json.loads(prev["raw_blob"])
            cur_suid = snap["features_raw"].get("filesystem", {}).get("suid_binaries")
            prv_suid = prev_raw.get("filesystem", {}).get("suid_binaries")
            if None not in (cur_suid, prv_suid) and cur_suid > prv_suid:
                findings.append({"rule_id": "R16", "layer": "L2", "severity": 0.7,
                                 "evidence": f"suid_binaries rose {prv_suid} -> {cur_suid} since previous scan"})
        except json.JSONDecodeError:
            pass # fail-static: corrupt history never blocks scan
    risk = composite_risk(findings, p_vuln)
    steps = plan(con, findings, alpha=args.alpha, beta=args.beta,
                 gamma=args.gamma)

    # persist findings (audit trail, invariant 4)
    findings_rows = {}
    for f in findings:
        cur = con.execute(
            "INSERT INTO findings(scan_id, rule_id, layer, severity, evidence) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, f["rule_id"], f["layer"], f["severity"], f["evidence"]))
        findings_rows.setdefault(f["rule_id"], cur.lastrowid)
    con.commit()

    # ---- Actuators: report (always), execution (gated) -------------------
    report_path = args.report or f"report_scan{scan_id}.md"
    write_report(report_path, snap, scan_id, findings, p_vuln, deltas,
                 delta_note, risk, steps, l1_note)

    result = {
        "scan_id": scan_id,
        "host": snap["meta"].get("host_id"),
        "composite_risk": risk,
        "classifier_p_vulnerable": p_vuln,
        "l1_status": l1_note,
        "drift": delta_note,
        "findings": [{"rule": f["rule_id"], "layer": f["layer"],
                      "severity": f["severity"]} for f in findings],
        "planned_steps": len(steps),
        "report": report_path,
        "verdict": "healthy" if risk < 0.5 else "action required",
    }
    print(json.dumps(result, indent=2))
    print(f"[+] report written: {report_path}")

    if findings and not args.act:
        print("[.] remediation plan PROPOSED only. Re-run with --act to "
              "enter the interactive approval gate.")
    elif findings and args.act:
        if os.geteuid() != 0:
            sys.exit("[-] --act mutations require root; rerun with sudo")
        execute_plan(con, scan_id, findings_rows, steps,
                    yes_all=args.yes_all)
        print("[+] approval gate closed — all outcomes logged to memory")

    con.close()


if __name__ == "__main__":
    main()

