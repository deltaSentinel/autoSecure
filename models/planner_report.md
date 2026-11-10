# Planner Coefficient Sweep

- alpha fixed at 1.0 (pure scale factor — note, not swept)
- beta, gamma in {0, 0.25, 0.5, 1, 2, 4} (36 cells)
- scenarios: single_R06, high_trio, all_catalog, L1_only | histories: no_feedback, R06_rej_2of3, half_rejected

## Utility zero-crossings (beta* at gamma=0.5)

| Rule | history | beta* (measured) | beta* (analytic) |
|---|---|---|---|
| R01 | R06_rej_2of3 | beta>2.0 (U=-0.2) | 1.67 |
| R01 | half_rejected | beta>1.0 (U=-0.1) | 0.83 |
| R01 | no_feedback | beta>2.0 (U=-0.2) | 1.67 |
| R03 | R06_rej_2of3 | beta>4.0 (U=-1.0) | 2.00 |
| R03 | half_rejected | beta>2.0 (U=-0.5) | 1.00 |
| R03 | no_feedback | beta>4.0 (U=-1.0) | 2.00 |
| R04 | R06_rej_2of3 | beta>2.0 (U=-0.4) | 1.43 |
| R04 | half_rejected | beta>2.0 (U=-0.4) | 1.43 |
| R04 | no_feedback | beta>2.0 (U=-0.4) | 1.43 |
| R05 | R06_rej_2of3 | beta>4.0 (U=-0.6) | 2.50 |
| R05 | half_rejected | beta>2.0 (U=-0.3) | 1.25 |
| R05 | no_feedback | beta>4.0 (U=-0.6) | 2.50 |
| R06 | R06_rej_2of3 | beta>1.0 (U=-0.333) | 0.58 |
| R06 | half_rejected | beta>2.0 (U=-0.8) | 1.00 |
| R06 | no_feedback | beta>2.0 (U=-0.8) | 1.00 |
| R08 | R06_rej_2of3 | beta>2.0 (U=-0.6) | 1.14 |
| R08 | half_rejected | beta>0.5 (U=-0.05) | 0.43 |
| R08 | no_feedback | beta>2.0 (U=-0.6) | 1.14 |
| R10 | R06_rej_2of3 | beta>4.0 (U=-0.3) | 2.50 |
| R10 | half_rejected | beta>0.25 (U=-0.05) | 0.00 |
| R10 | no_feedback | beta>4.0 (U=-0.3) | 2.50 |
| R11 | R06_rej_2of3 | beta>2.0 (U=-0.4) | 1.33 |
| R11 | half_rejected | beta>2.0 (U=-0.4) | 1.33 |
| R11 | no_feedback | beta>2.0 (U=-0.4) | 1.33 |
| R12 | R06_rej_2of3 | beta>2.0 (U=-0.4) | 1.20 |
| R12 | half_rejected | beta>0.25 (U=-0.025) | 0.20 |
| R12 | no_feedback | beta>2.0 (U=-0.4) | 1.20 |

## Notes

- plan() returns all steps; 'regimes' are utility sign crossings, not membership changes.
- N/A-action steps are quarantined below action-bearing steps by construction (verified per cell in CSV col na_quarantine_held).
