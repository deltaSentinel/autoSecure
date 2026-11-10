---
name: Bug report
about: Something in AutoSecure behaves incorrectly
labels: bug
title: "[BUG] "
assignees: ''
---

**Environment**
- OS / machine:
- Python / uv versions (`uv --version`):
- AutoSecure version/commit (`git rev-parse --short HEAD`):

**What happened**
A clear description of the bug.

**How to reproduce**
1. Command(s) run (e.g., `uv run python3 agent/main.py --snapshot ... --db ... --act`)
2. What input/data was involved (synthetic world ID if applicable, e.g., M05)
3. What happened next

**Expected behavior**
What you expected instead.

**Evidence**
Logs, stderr, or the arbitration/threshold output that shows the problem.

**Suspected layer** (check one)
- [ ] L0 reflex detector (rule ID: R__)
- [ ] L1 ML classifier
- [ ] Arbitration logic
- [ ] Dataset/synthesis pipeline
- [ ] CLI / IO
