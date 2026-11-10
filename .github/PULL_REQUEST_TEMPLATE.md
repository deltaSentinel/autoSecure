## What does this change?

<!-- One or two sentences. Reference the issue if there is one: "Closes #12" -->

## Which layer does it touch? (check all)

- [ ] L0 reflex detector (rules / weights)
- [ ] L1 ML classifier (features / training)
- [ ] Arbitration logic
- [ ] Dataset / synthesis pipeline
- [ ] Experiments / evaluation
- [ ] CI / packaging / docs

## How did you test it?

<!-- Exact commands, e.g.:
     uv run python3 agent/main.py --snapshot data/synth/M05.json --db /tmp/check.db --act
     Paste key output if relevant. "Works on my machine" alone is not a test. -->

- [ ] Ran the agent locally against at least one snapshot
- [ ] CI is green (or this PR precedes CI)

## Checklist

- [ ] Commit messages say *why*, not just "update"
- [ ] No stray debug prints / commented-out code left behind
- [ ] No db files, demo recordings, or large artifacts included
