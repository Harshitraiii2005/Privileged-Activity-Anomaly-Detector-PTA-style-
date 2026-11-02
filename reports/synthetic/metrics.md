# Evaluation: synthetic

Train (clean baseline): 6,276 events before 2026-01-19 00:00:00. Test: 6,774 events (178 attack events, 17 incidents) over 14 days.
Thresholds are label-free: Isolation Forest and autoencoder alert above the 99% quantile of their own baseline scores; rules alert at combined weight >= 0.4; the hybrid (served model) alerts at risk >= 40 (medium).

| Detector | Precision | Recall | F1 | PR-AUC | FPR | Incident recall | Benign alerts/day |
|---|---|---|---|---|---|---|---|
| Rules | 0.821 | 0.646 | 0.723 | 0.631 | 0.38% | 0.76 (13/17) | 1.8 |
| IsolationForest | 0.512 | 0.618 | 0.560 | 0.646 | 1.59% | 0.35 (6/17) | 7.5 |
| Autoencoder | 0.529 | 0.725 | 0.611 | 0.736 | 1.74% | 0.59 (10/17) | 8.2 |
| Hybrid | 0.522 | 0.792 | 0.629 | 0.748 | 1.96% | 0.76 (13/17) | 9.2 |

Recall by attack type: event recall (incidents detected / incidents).

| Attack type | Rules | IsolationForest | Autoencoder | Hybrid |
|---|---|---|---|---|
| `checkout_burst` | 0.76 (3/3) | 0.80 (3/3) | 0.96 (3/3) | 0.86 (3/3) |
| `lateral_movement` | 0.65 (3/3) | 0.92 (3/3) | 1.00 (3/3) | 0.92 (3/3) |
| `new_source_host` | 0.00 (0/4) | 0.00 (0/4) | 0.42 (4/4) | 0.00 (0/4) |
| `off_hours_admin` | 1.00 (3/3) | 0.00 (0/3) | 0.00 (0/3) | 1.00 (3/3) |
| `privilege_escalation` | 0.52 (4/4) | 0.00 (0/4) | 0.00 (0/4) | 0.52 (4/4) |
