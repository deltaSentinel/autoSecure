# AutoSecure Model Evaluation

- Samples: **580** | Features: **25** | Model exported: **rf**
- Primary metrics (out-of-fold, stratified): acc=0.955, P=0.990, R=0.949, F1=0.969, ROC-AUC=0.977

## Confusion matrix (rows=true, cols=pred; 1=vulnerable)

```
          pred-clean  pred-vuln
true-clean       146           4
true-vuln         22         408
```

## Model comparison (same folds)

| Model | Acc | Precision | Recall | F1 | ROC-AUC |
|-------|-----|-----------|--------|----|---------|
| rf | 0.955 | 0.990 | 0.949 | 0.969 | 0.977 |
| svm | 0.947 | 0.990 | 0.937 | 0.963 | 0.969 |
| lr | 0.948 | 0.995 | 0.935 | 0.964 | 0.976 |

## Per-tag detection breakdown

| Tag | Vuln caught | Vuln missed | Clean OK | False alarm |
|-----|-------------|-------------|----------|-------------|
| M01 | 2 | 10 | 0 | 0 |
| M02 | 1 | 11 | 0 | 0 |
| M03 | 12 | 0 | 0 | 0 |
| M04 | 12 | 0 | 0 | 0 |
| M05 | 12 | 0 | 0 | 0 |
| M06 | 12 | 0 | 0 | 0 |
| M07 | 12 | 0 | 0 | 0 |
| M08 | 12 | 0 | 0 | 0 |
| M09 | 12 | 0 | 0 | 0 |
| M10 | 12 | 0 | 0 | 0 |
| M11 | 12 | 0 | 0 | 0 |
| M12 | 12 | 0 | 0 | 0 |
| M13 | 12 | 0 | 0 | 0 |
| M14 | 12 | 0 | 0 | 0 |
| M15 | 12 | 0 | 0 | 0 |
| clean-desktop | 0 | 0 | 48 | 0 |
| clean-minimal | 0 | 0 | 56 | 4 |
| clean-server | 0 | 0 | 42 | 0 |
| combo-M01-M02 | 0 | 1 | 0 | 0 |
| combo-M01-M02-M04 | 1 | 0 | 0 | 0 |
| combo-M01-M03-M13-M08 | 1 | 0 | 0 | 0 |
| combo-M01-M04 | 1 | 0 | 0 | 0 |
| combo-M01-M04-M02 | 1 | 0 | 0 | 0 |
| combo-M01-M06 | 3 | 0 | 0 | 0 |
| combo-M01-M13-M04-M06 | 1 | 0 | 0 | 0 |
| combo-M01-M13-M15-M11 | 1 | 0 | 0 | 0 |
| combo-M01-M14-M02 | 1 | 0 | 0 | 0 |
| combo-M01-M15-M11-M05 | 1 | 0 | 0 | 0 |
| combo-M02-M03 | 1 | 0 | 0 | 0 |
| combo-M02-M04-M15 | 1 | 0 | 0 | 0 |
| combo-M02-M07 | 1 | 0 | 0 | 0 |
| combo-M02-M07-M11-M03 | 1 | 0 | 0 | 0 |
| combo-M02-M08-M12-M01 | 1 | 0 | 0 | 0 |
| combo-M02-M09 | 1 | 0 | 0 | 0 |
| combo-M02-M09-M11-M07 | 1 | 0 | 0 | 0 |
| combo-M02-M12-M05-M06 | 1 | 0 | 0 | 0 |
| combo-M02-M13-M07-M09 | 1 | 0 | 0 | 0 |
| combo-M02-M14-M15-M09 | 1 | 0 | 0 | 0 |
| combo-M03-M01-M09-M05 | 1 | 0 | 0 | 0 |
| combo-M03-M02 | 1 | 0 | 0 | 0 |
| combo-M03-M04-M09 | 1 | 0 | 0 | 0 |
| combo-M03-M05 | 1 | 0 | 0 | 0 |
| combo-M03-M08 | 2 | 0 | 0 | 0 |
| combo-M03-M08-M01-M11 | 1 | 0 | 0 | 0 |
| combo-M03-M12-M11 | 1 | 0 | 0 | 0 |
| combo-M03-M13-M06 | 1 | 0 | 0 | 0 |
| combo-M03-M14 | 1 | 0 | 0 | 0 |
| combo-M03-M15 | 2 | 0 | 0 | 0 |
| combo-M04-M02 | 1 | 0 | 0 | 0 |
| combo-M04-M02-M01 | 1 | 0 | 0 | 0 |
| combo-M04-M02-M07 | 1 | 0 | 0 | 0 |
| combo-M04-M02-M14-M06 | 1 | 0 | 0 | 0 |
| combo-M04-M03-M14-M05 | 1 | 0 | 0 | 0 |
| combo-M04-M05-M15 | 1 | 0 | 0 | 0 |
| combo-M04-M06-M09 | 1 | 0 | 0 | 0 |
| combo-M04-M07-M05-M11 | 1 | 0 | 0 | 0 |
| combo-M04-M07-M11 | 1 | 0 | 0 | 0 |
| combo-M04-M07-M11-M01 | 1 | 0 | 0 | 0 |
| combo-M04-M08 | 2 | 0 | 0 | 0 |
| combo-M04-M08-M12-M06 | 1 | 0 | 0 | 0 |
| combo-M04-M09 | 2 | 0 | 0 | 0 |
| combo-M04-M09-M11-M13 | 1 | 0 | 0 | 0 |
| combo-M04-M10-M13-M02 | 1 | 0 | 0 | 0 |
| combo-M04-M11-M03 | 1 | 0 | 0 | 0 |
| combo-M04-M11-M08-M09 | 1 | 0 | 0 | 0 |
| combo-M04-M12 | 2 | 0 | 0 | 0 |
| combo-M04-M12-M02-M07 | 1 | 0 | 0 | 0 |
| combo-M04-M13 | 1 | 0 | 0 | 0 |
| combo-M04-M13-M01 | 1 | 0 | 0 | 0 |
| combo-M04-M13-M02 | 1 | 0 | 0 | 0 |
| combo-M04-M15 | 1 | 0 | 0 | 0 |
| combo-M05-M01 | 1 | 0 | 0 | 0 |
| combo-M05-M02-M08 | 1 | 0 | 0 | 0 |
| combo-M05-M03-M02 | 1 | 0 | 0 | 0 |
| combo-M05-M04-M03 | 1 | 0 | 0 | 0 |
| combo-M05-M06-M01 | 1 | 0 | 0 | 0 |
| combo-M05-M07 | 1 | 0 | 0 | 0 |
| combo-M05-M07-M02 | 1 | 0 | 0 | 0 |
| combo-M05-M07-M03 | 1 | 0 | 0 | 0 |
| combo-M05-M07-M10-M02 | 1 | 0 | 0 | 0 |
| combo-M05-M07-M12 | 1 | 0 | 0 | 0 |
| combo-M05-M08 | 2 | 0 | 0 | 0 |
| combo-M05-M08-M13-M15 | 1 | 0 | 0 | 0 |
| combo-M05-M09-M13 | 1 | 0 | 0 | 0 |
| combo-M05-M13-M12-M10 | 1 | 0 | 0 | 0 |
| combo-M05-M14 | 1 | 0 | 0 | 0 |
| combo-M06-M02 | 1 | 0 | 0 | 0 |
| combo-M06-M02-M04-M12 | 1 | 0 | 0 | 0 |
| combo-M06-M03-M15-M02 | 1 | 0 | 0 | 0 |
| combo-M06-M04 | 1 | 0 | 0 | 0 |
| combo-M06-M04-M05 | 1 | 0 | 0 | 0 |
| combo-M06-M05 | 1 | 0 | 0 | 0 |
| combo-M06-M05-M14-M08 | 1 | 0 | 0 | 0 |
| combo-M06-M05-M14-M13 | 1 | 0 | 0 | 0 |
| combo-M06-M07-M04-M10 | 1 | 0 | 0 | 0 |
| combo-M06-M09-M03-M07 | 1 | 0 | 0 | 0 |
| combo-M06-M09-M03-M15 | 1 | 0 | 0 | 0 |
| combo-M06-M09-M13-M08 | 1 | 0 | 0 | 0 |
| combo-M06-M10 | 1 | 0 | 0 | 0 |
| combo-M06-M10-M01-M03 | 1 | 0 | 0 | 0 |
| combo-M06-M11 | 1 | 0 | 0 | 0 |
| combo-M06-M11-M12-M02 | 1 | 0 | 0 | 0 |
| combo-M06-M12 | 1 | 0 | 0 | 0 |
| combo-M06-M12-M02-M15 | 1 | 0 | 0 | 0 |
| combo-M06-M13-M03-M09 | 1 | 0 | 0 | 0 |
| combo-M06-M14-M05-M03 | 1 | 0 | 0 | 0 |
| combo-M07-M02-M14-M13 | 1 | 0 | 0 | 0 |
| combo-M07-M02-M15 | 1 | 0 | 0 | 0 |
| combo-M07-M02-M15-M04 | 1 | 0 | 0 | 0 |
| combo-M07-M03 | 2 | 0 | 0 | 0 |
| combo-M07-M03-M15 | 1 | 0 | 0 | 0 |
| combo-M07-M04-M06-M05 | 1 | 0 | 0 | 0 |
| combo-M07-M08 | 2 | 0 | 0 | 0 |
| combo-M07-M09 | 1 | 0 | 0 | 0 |
| combo-M07-M11-M03-M14 | 1 | 0 | 0 | 0 |
| combo-M07-M11-M12 | 1 | 0 | 0 | 0 |
| combo-M07-M11-M15 | 1 | 0 | 0 | 0 |
| combo-M07-M12 | 1 | 0 | 0 | 0 |
| combo-M07-M12-M04 | 1 | 0 | 0 | 0 |
| combo-M07-M12-M09 | 1 | 0 | 0 | 0 |
| combo-M07-M15 | 1 | 0 | 0 | 0 |
| combo-M08-M01 | 4 | 0 | 0 | 0 |
| combo-M08-M01-M02-M15 | 1 | 0 | 0 | 0 |
| combo-M08-M01-M05 | 1 | 0 | 0 | 0 |
| combo-M08-M01-M07-M02 | 1 | 0 | 0 | 0 |
| combo-M08-M02-M10-M06 | 1 | 0 | 0 | 0 |
| combo-M08-M04-M07 | 1 | 0 | 0 | 0 |
| combo-M08-M04-M10-M03 | 1 | 0 | 0 | 0 |
| combo-M08-M05-M02-M15 | 1 | 0 | 0 | 0 |
| combo-M08-M05-M04-M03 | 1 | 0 | 0 | 0 |
| combo-M08-M05-M12-M07 | 1 | 0 | 0 | 0 |
| combo-M08-M06-M14 | 1 | 0 | 0 | 0 |
| combo-M08-M06-M15-M13 | 1 | 0 | 0 | 0 |
| combo-M08-M07 | 1 | 0 | 0 | 0 |
| combo-M08-M09-M11 | 1 | 0 | 0 | 0 |
| combo-M08-M11 | 1 | 0 | 0 | 0 |
| combo-M08-M12-M11 | 1 | 0 | 0 | 0 |
| combo-M08-M13-M01-M04 | 1 | 0 | 0 | 0 |
| combo-M08-M15-M05 | 1 | 0 | 0 | 0 |
| combo-M08-M15-M05-M14 | 1 | 0 | 0 | 0 |
| combo-M09-M02-M03-M04 | 1 | 0 | 0 | 0 |
| combo-M09-M02-M03-M05 | 1 | 0 | 0 | 0 |
| combo-M09-M02-M10 | 1 | 0 | 0 | 0 |
| combo-M09-M03 | 1 | 0 | 0 | 0 |
| combo-M09-M04-M01 | 1 | 0 | 0 | 0 |
| combo-M09-M05 | 1 | 0 | 0 | 0 |
| combo-M09-M05-M06 | 1 | 0 | 0 | 0 |
| combo-M09-M06 | 1 | 0 | 0 | 0 |
| combo-M09-M07 | 1 | 0 | 0 | 0 |
| combo-M09-M08-M01 | 1 | 0 | 0 | 0 |
| combo-M09-M08-M07 | 1 | 0 | 0 | 0 |
| combo-M09-M12-M03 | 1 | 0 | 0 | 0 |
| combo-M09-M13-M05-M15 | 1 | 0 | 0 | 0 |
| combo-M09-M13-M11-M10 | 1 | 0 | 0 | 0 |
| combo-M09-M13-M12-M10 | 1 | 0 | 0 | 0 |
| combo-M09-M14-M02-M13 | 1 | 0 | 0 | 0 |
| combo-M09-M14-M15 | 1 | 0 | 0 | 0 |
| combo-M09-M15 | 1 | 0 | 0 | 0 |
| combo-M10-M02-M09-M08 | 1 | 0 | 0 | 0 |
| combo-M10-M03 | 2 | 0 | 0 | 0 |
| combo-M10-M03-M12 | 1 | 0 | 0 | 0 |
| combo-M10-M07 | 1 | 0 | 0 | 0 |
| combo-M10-M08-M04-M01 | 1 | 0 | 0 | 0 |
| combo-M10-M08-M11-M01 | 1 | 0 | 0 | 0 |
| combo-M10-M09-M02-M05 | 1 | 0 | 0 | 0 |
| combo-M10-M09-M14-M07 | 1 | 0 | 0 | 0 |
| combo-M10-M11 | 1 | 0 | 0 | 0 |
| combo-M10-M11-M07-M13 | 1 | 0 | 0 | 0 |
| combo-M10-M12 | 2 | 0 | 0 | 0 |
| combo-M10-M12-M15 | 1 | 0 | 0 | 0 |
| combo-M10-M13-M05-M01 | 1 | 0 | 0 | 0 |
| combo-M10-M15-M11 | 1 | 0 | 0 | 0 |
| combo-M11-M03 | 1 | 0 | 0 | 0 |
| combo-M11-M03-M13 | 1 | 0 | 0 | 0 |
| combo-M11-M06 | 2 | 0 | 0 | 0 |
| combo-M11-M06-M03-M14 | 1 | 0 | 0 | 0 |
| combo-M11-M09 | 1 | 0 | 0 | 0 |
| combo-M11-M13 | 1 | 0 | 0 | 0 |
| combo-M12-M02-M03-M13 | 1 | 0 | 0 | 0 |
| combo-M12-M02-M09 | 1 | 0 | 0 | 0 |
| combo-M12-M03 | 1 | 0 | 0 | 0 |
| combo-M12-M03-M06 | 1 | 0 | 0 | 0 |
| combo-M12-M05 | 1 | 0 | 0 | 0 |
| combo-M12-M07-M04-M02 | 1 | 0 | 0 | 0 |
| combo-M12-M08-M11-M07 | 1 | 0 | 0 | 0 |
| combo-M12-M09-M06-M03 | 1 | 0 | 0 | 0 |
| combo-M12-M11-M03-M13 | 1 | 0 | 0 | 0 |
| combo-M12-M11-M08-M06 | 1 | 0 | 0 | 0 |
| combo-M12-M13-M02-M01 | 1 | 0 | 0 | 0 |
| combo-M12-M13-M02-M09 | 1 | 0 | 0 | 0 |
| combo-M12-M13-M03-M11 | 1 | 0 | 0 | 0 |
| combo-M12-M13-M08-M03 | 1 | 0 | 0 | 0 |
| combo-M12-M14 | 1 | 0 | 0 | 0 |
| combo-M12-M14-M01-M07 | 1 | 0 | 0 | 0 |
| combo-M12-M15 | 1 | 0 | 0 | 0 |
| combo-M13-M02 | 1 | 0 | 0 | 0 |
| combo-M13-M02-M05-M15 | 1 | 0 | 0 | 0 |
| combo-M13-M04 | 1 | 0 | 0 | 0 |
| combo-M13-M04-M03-M09 | 1 | 0 | 0 | 0 |
| combo-M13-M05-M06 | 1 | 0 | 0 | 0 |
| combo-M13-M06 | 1 | 0 | 0 | 0 |
| combo-M13-M09-M02 | 1 | 0 | 0 | 0 |
| combo-M13-M09-M08 | 1 | 0 | 0 | 0 |
| combo-M13-M10-M11-M08 | 1 | 0 | 0 | 0 |
| combo-M13-M12-M03-M02 | 1 | 0 | 0 | 0 |
| combo-M13-M12-M05 | 1 | 0 | 0 | 0 |
| combo-M13-M14-M02 | 1 | 0 | 0 | 0 |
| combo-M13-M15-M12-M09 | 1 | 0 | 0 | 0 |
| combo-M14-M02 | 1 | 0 | 0 | 0 |
| combo-M14-M02-M03-M04 | 1 | 0 | 0 | 0 |
| combo-M14-M02-M04-M05 | 1 | 0 | 0 | 0 |
| combo-M14-M02-M05 | 1 | 0 | 0 | 0 |
| combo-M14-M03-M02 | 1 | 0 | 0 | 0 |
| combo-M14-M04 | 1 | 0 | 0 | 0 |
| combo-M14-M04-M10-M08 | 1 | 0 | 0 | 0 |
| combo-M14-M04-M15-M13 | 1 | 0 | 0 | 0 |
| combo-M14-M05 | 1 | 0 | 0 | 0 |
| combo-M14-M05-M12-M06 | 1 | 0 | 0 | 0 |
| combo-M14-M06 | 1 | 0 | 0 | 0 |
| combo-M14-M06-M10-M03 | 1 | 0 | 0 | 0 |
| combo-M14-M08-M06 | 1 | 0 | 0 | 0 |
| combo-M14-M08-M09-M07 | 1 | 0 | 0 | 0 |
| combo-M14-M11 | 1 | 0 | 0 | 0 |
| combo-M14-M12 | 1 | 0 | 0 | 0 |
| combo-M14-M13 | 1 | 0 | 0 | 0 |
| combo-M14-M13-M03 | 1 | 0 | 0 | 0 |
| combo-M14-M13-M04 | 1 | 0 | 0 | 0 |
| combo-M14-M13-M07-M10 | 1 | 0 | 0 | 0 |
| combo-M15-M01 | 1 | 0 | 0 | 0 |
| combo-M15-M01-M07 | 1 | 0 | 0 | 0 |
| combo-M15-M01-M12-M08 | 1 | 0 | 0 | 0 |
| combo-M15-M02-M03-M09 | 1 | 0 | 0 | 0 |
| combo-M15-M02-M04-M08 | 1 | 0 | 0 | 0 |
| combo-M15-M03-M05 | 1 | 0 | 0 | 0 |
| combo-M15-M03-M08 | 1 | 0 | 0 | 0 |
| combo-M15-M03-M11 | 1 | 0 | 0 | 0 |
| combo-M15-M04 | 1 | 0 | 0 | 0 |
| combo-M15-M04-M02-M10 | 1 | 0 | 0 | 0 |
| combo-M15-M04-M13 | 1 | 0 | 0 | 0 |
| combo-M15-M05-M04 | 1 | 0 | 0 | 0 |
| combo-M15-M06-M01 | 1 | 0 | 0 | 0 |
| combo-M15-M06-M02 | 1 | 0 | 0 | 0 |
| combo-M15-M08-M10-M05 | 1 | 0 | 0 | 0 |
| combo-M15-M09 | 1 | 0 | 0 | 0 |
| combo-M15-M10 | 1 | 0 | 0 | 0 |
| combo-M15-M10-M08 | 1 | 0 | 0 | 0 |
| combo-M15-M10-M11-M13 | 1 | 0 | 0 | 0 |
| combo-M15-M11-M05-M04 | 1 | 0 | 0 | 0 |
| combo-M15-M12-M03-M04 | 1 | 0 | 0 | 0 |
| combo-M15-M13 | 1 | 0 | 0 | 0 |
| combo-M15-M13-M01 | 1 | 0 | 0 | 0 |
| combo-M15-M14-M13 | 1 | 0 | 0 | 0 |

## Top 10 features (importance)

- `risk_ssh_empty_passwords`: 0.0781
- `risk_weak_password_policy`: 0.0764
- `risk_suid_binaries`: 0.0675
- `risk_snmp_open`: 0.0675
- `risk_users_uid0_extra`: 0.0673
- `risk_users_empty_password`: 0.0644
- `risk_world_writable_etc_files`: 0.0637
- `risk_world_writable_dirs_no_sticky`: 0.0635
- `risk_firewall_disabled`: 0.0612
- `risk_sudo_nopasswd`: 0.0606

> Metrics are out-of-fold: every sample is scored by a model that never saw it during training. The exported model is trained on all samples afterward.

## Probability calibration (Platt sigmoid, nested CV)

| Scores | Brier (lower = better) |
|---|---|
| Uncalibrated RF votes | 0.0506 |
| Calibrated (exported model) | 0.0416 |

Reliability bins, calibrated (predicted vs observed):

| bin center | observed vuln rate | n |
|---|---|---|
| 0.05 | 0.000 | 5 |
| 0.15 | 0.143 | 105 |
| 0.25 | 0.106 | 47 |
| 0.35 | 0.100 | 10 |
| 0.45 | 1.000 | 1 |
| 0.65 | 0.667 | 3 |
| 0.75 | 0.750 | 4 |
| 0.85 | 0.923 | 26 |
| 0.95 | 1.000 | 379 |
