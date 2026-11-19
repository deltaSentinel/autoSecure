#!/usr/bin/env python3
"""AutoSecure - clip-semantics audit gate (CONTRACT.md 6.1 / 8 gate 6).

Must run before real-data eval_holdout.py results are interpreted, so
saturation artifacts in risk_suid_binaries, risk_sgid_binaries, and
num_listening_ports are not misread as model failure.

Produces (under reports/audits/, plus a history copy):
    clip_audit_<STAMP>.md    distribution tables, saturation fractions,
                             synth-vs-real comparison, decision block
    clip_audit_<STAMP>.csv   raw per-snapshot values for the three features
    clip_audit_note.md       ready-to-paste interpretation note for the
                             real-data arbitration_report.md

Usage:
    python3 clip_audit.py --real ../data/real
    python3 clip_audit.py --real ../data/real --synth ../dataset_synth \
        --decision "accept-as-is"
"""
import argparse, csv, glob, json, os, shutil, statistics, sys
from datetime import datetime

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

# Caps mirror collect.py build_ml_features(); update both if caps change.
FEATURES = [
    ("risk_suid_binaries", 200),
    ("risk_sgid_binaries", 200),
    ("num_listening_ports", 60),
]


def load_values(dataset_dir):
    """Return {feature: [values]} over labeled snapshots, Nones preserved."""
    vals = {k: [] for k, _ in FEATURES}
    n_labeled = n_skipped = 0
    for p in sorted(glob.glob(os.path.join(dataset_dir, "*.json"))):
        with open(p) as f:
            s = json.load(f)
        if s.get("meta", {}).get("label") not in ("clean", "vulnerable"):
            n_skipped += 1
            continue
        n_labeled += 1
        ml = s.get("features_ml", {})
        for k, _cap in FEATURES:
            vals[k].append(ml.get(k))
    return vals, n_labeled, n_skipped


def stats_for(values, cap):
    present = [v for v in values if v is not None]
    none_ct = len(values) - len(present)
    sat_ct = sum(1 for v in present if v >= cap)
    over_ct = sum(1 for v in present if v > cap)  # only possible in synth
    zero_ct = sum(1 for v in present if v == 0)
    med = statistics.median(present) if present else None
    n = len(values) or 1
    return {
        "n": len(values), "none": none_ct, "none_frac": none_ct / n,
        "saturated": sat_ct, "sat_frac": sat_ct / n,
        "over_cap": over_ct, "zero": zero_ct,
        "min": min(present) if present else None,
        "max": max(present) if present else None,
        "median": med,
        "distinct": len(set(present)),
    }


def hist_lines(values, cap, bins=10):
    """Plain-text histogram, cap marked. Bin width adapts to data range."""
    present = [v for v in values if v is not None]
    if not present:
        return ["  (no measured values)"]
    lo, hi = 0, max(max(present), cap)
    # ceil((hi + 1) / bins): the range 0..hi inclusive must fit in `bins`
    # bins, so an at-cap value lands inside the last bin instead of one
    # past it (regression: values == cap fell outside the grid).
    width = max(1, -(-(hi + 1) // bins))
    counts = {b: 0 for b in range(bins)}   # pre-init every bin
    for v in present:
        counts[min((v - lo) // width, bins - 1)] += 1
    peak = max(counts.values())
    lines = []
    for b in range(bins):
        blo, bhi = lo + b * width, lo + (b + 1) * width - 1
        bar = "#" * round(40 * counts[b] / peak) if peak else ""
        mark = " <- cap" if blo <= cap <= bhi else ""
        lines.append(f"  {blo:>4}-{bhi:>4} | {bar} ({counts[b]}){mark}")
    none_ct = len(values) - len(present)
    if none_ct:
        lines.append(f"  None | {'#' * round(40 * none_ct / peak)}"
                     f" ({none_ct})  unmeasured")
    return lines


def report_block(title, vals, cap):
    st = stats_for(vals, cap)
    lines = [
        f"## {title}",
        "",
        f"- Cap: **{cap}** | n={st['n']} | "
        f"saturated (== cap): **{st['saturated']} "
        f"({st['sat_frac']*100:.1f}%)** | "
        f"None (unmeasured): {st['none']} ({st['none_frac']*100:.1f}%) | "
        f"zero: {st['zero']} | over-cap: {st['over_cap']} | "
        f"min={st['min']} median={st['median']} max={st['max']} | "
        f"distinct values: {st['distinct']}",
        "",
        "```",
    ]
    lines += hist_lines(vals, cap)
    lines += ["```", ""]
    return lines, st


def main():
    ap = argparse.ArgumentParser(description="clip-semantics audit gate")
    ap.add_argument("--real", required=True, help="real dataset dir")
    ap.add_argument("--synth", default=None, help="synthetic dataset dir")
    ap.add_argument("--decision", default=None,
                    choices=["accept-as-is", "re-train-hybrid",
                             "revisit-caps"],
                    help="record the audit decision (criteria 3)")
    ap.add_argument("--out", default=os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), os.pardir,
        "reports", "audits")))
    args = ap.parse_args()

    rv, rn, rs = load_values(args.real)
    if rn == 0:
        sys.exit(f"[-] no labeled snapshots in {args.real}")

    os.makedirs(args.out, exist_ok=True)
    md = [
        "# Clip-Semantics Audit (CONTRACT.md 6.1, gate 8.6)",
        "",
        f"- Run: {STAMP} | real: `{args.real}` ({rn} labeled, "
        f"{rs} skipped)",
        "- Question: are capped count features saturated on real data, "
        "and can that explain transfer degradation independently of "
        "model failure?",
        "",
    ]

    csv_rows = []
    real_stats = {}
    for k, cap in FEATURES:
        blk, st = report_block(f"Real data: `{k}`", rv[k], cap)
        md += blk
        real_stats[k] = st
        for i, v in enumerate(rv[k]):
            csv_rows.append({"dataset": "real", "feature": k,
                             "value": "" if v is None else v})

    if args.synth:
        sv, sn, _ = load_values(args.synth)
        md += [f"Synthetic reference: `{args.synth}` ({sn} labeled)", ""]
        for k, cap in FEATURES:
            blk, st = report_block(f"Synthetic data: `{k}`", sv[k], cap)
            md += blk
            for i, v in enumerate(sv[k]):
                csv_rows.append({"dataset": "synth", "feature": k,
                                 "value": "" if v is None else v})
        md += ["## Synth vs real delta", "",
               "| Feature | real sat% | synth sat% | synth over-cap% | Note |",
               "|---------|-----------|------------|-----------------|------|"]
        for k, cap in FEATURES:
            rst, sst = real_stats[k], stats_for(sv[k], cap)
            note = ""
            if sst["over_cap"]:
                note = ("synth is NOT clipped; values above cap possible "
                        "(synth_dataset.py bypasses clip())")
            md.append(f"| {k} | {rst['sat_frac']*100:.1f} | "
                      f"{sst['sat_frac']*100:.1f} | "
                      f"{sst['over_cap']/max(sst['n'],1)*100:.1f} | {note} |")
        md.append("")

    md += [
        "## Decision",
        "",
        (f"- Decision: **{args.decision}**" if args.decision
         else "- Decision: **NOT YET RECORDED** (pass --decision)"),
        "- Guidance: if real saturation is high but synth also carries "
        "at-cap or above-cap mass on the same features, accept as-is and "
        "annotate the eval report; if synth sits near 0 while real pins "
        "at cap, hybrid re-training is the registered remedy; revisit "
        "caps only if the saturated features also dominate "
        "importances.csv, otherwise the cap change perturbs well-behaved "
        "features for no gain.",
        "- Per CONTRACT 6.3: absolute SUID levels are deliberately "
        "rule-uncovered (R16 fires on increase only), so saturation here "
        "is not an L0 defect.",
        "",
    ]

    rep = os.path.join(args.out, f"clip_audit_{STAMP}.md")
    with open(rep, "w") as f:
        f.write("\n".join(md))
    csvp = os.path.join(args.out, f"clip_audit_{STAMP}.csv")
    with open(csvp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["dataset", "feature", "value"])
        w.writeheader()
        w.writerows(csv_rows)

    note = [
        "<!-- paste into the real-data arbitration_report.md header -->",
        "",
        "> Clip-semantics audit (gate 8.6): "
        + ", ".join(
            f"{k} saturated {real_stats[k]['sat_frac']*100:.1f}%"
            for k, _ in FEATURES)
        + f" on real data (reports/audits/clip_audit_{STAMP}.md). "
          "Absolute levels at the caps are expected per CONTRACT 6.1 and "
          "are not evidence of model failure; interpret transfer metrics "
          "accordingly.",
        "",
    ]
    notep = os.path.join(args.out, "clip_audit_note.md")
    with open(notep, "w") as f:
        f.write("\n".join(note))

    hist = os.path.join(args.out, "history")
    os.makedirs(hist, exist_ok=True)
    for p in (rep, csvp):
        shutil.copy2(p, os.path.join(
            hist, STAMP.join(os.path.splitext(os.path.basename(p)))))

    print(f"[+] audit -> {rep}")
    print(f"[+] values -> {csvp}")
    print(f"[+] interpretation note -> {notep}")
    for k, _cap in FEATURES:
        st = real_stats[k]
        print(f"    {k}: sat {st['sat_frac']*100:.1f}%  "
              f"none {st['none_frac']*100:.1f}%")
    if not args.decision:
        print("[!] decision not recorded - rerun with --decision")


if __name__ == "__main__":
    main()
