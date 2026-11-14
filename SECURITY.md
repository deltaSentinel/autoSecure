# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| main branch | ✅ |

AutoSecure is a university semester project (AI-472). Only the `main` branch receives fixes, and only while the course is active.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security-relevant findings.

Instead, use one of these channels:

1. **Preferred:** open a **private security advisory** on this repository (Security tab → "Report a vulnerability"), or
2. Email the maintainers: `rgb00009@mix.wvu.edu` with the subject line `[autoSecure] security report`.

Include if possible: the file/rule involved, how you reproduced it, and its impact. We aim to acknowledge reports within **7 days**, but this is a student project maintained in spare time — there is no formal SLA.

## Scope

In scope:
- Anything in this repository: the collector (`collector/`), the agent harness (`agent/`), the training/experiment scripts, and the shipped model artifacts.
- Logic bugs that could cause a **false clean** (a misconfigured host reported as clean) — these are the highest-severity class for a security scanner and we treat them accordingly.
- Bugs that could cause dangerous remediation commands to be proposed or executed even outside the approval gate.

Out of scope:
- Using `collector/inject.sh` or the injection catalog against hosts you do not own or are not authorized to test. This is misuse, not a vulnerability — see the README's Responsible use section.
- Findings about the *hosts you scanned* (that's what AutoSecure is for), or vulnerabilities in third-party dependencies that should be reported upstream.

## Design commitments worth knowing

These are documented so reviewers can hold us to them:

- The agent is **read-only by default**. Mutation requires `--act`, which requires root and hard-refuses otherwise — no silent degradation.
- Remediation plans execute only through the **human approval gate**; every finding is evidence-chained and logged.
- Operator rejections persist in `agent/mem.db` and lower that rule's utility in future runs.

## Expectations

This is a course project delivered by a two-person team. We welcome reports and will fix what we can, but we don't promise CVE-level rigor, embargo coordination, or long-term maintenance after the semester ends.

