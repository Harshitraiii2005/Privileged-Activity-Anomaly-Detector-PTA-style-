import json
from dataclasses import replace

import numpy as np
import pandas as pd
import pytest

from privguard.config import load_config
from privguard.evaluate import DETECTORS, detector_metrics, evaluate, load_split, main
from privguard.synthetic import ATTACK_TYPES, generate


@pytest.fixture
def cfg(tmp_path):
    base = load_config()
    syn = replace(base.synthetic, days=8, n_humans=10, n_admins=3, n_servers=10, attack_start_day=4,
                  attacks=dict.fromkeys(ATTACK_TYPES, 1))
    model = replace(base.model, reports_dir=tmp_path / "reports", iforest={"n_estimators": 50},
                    autoencoder={"hidden": 4, "epochs": 2})
    return replace(base, synthetic=syn, model=model, processed_dir=tmp_path / "processed")


def test_evaluate_writes_reports(cfg):
    cfg.processed_dir.mkdir()
    generate(cfg.synthetic).to_parquet(cfg.processed_dir / "synthetic_events.parquet")

    report = evaluate("synthetic", cfg)

    out = cfg.model.reports_dir / "synthetic"
    for name in ("metrics.json", "metrics.md", "pr_curves.png", "recall_by_attack.png", "score_distributions.png",
                 "shap_summary.png"):
        assert (out / name).stat().st_size > 0, name
    assert json.loads((out / "metrics.json").read_text()) == json.loads(json.dumps(report))
    assert list(report["detectors"]) == list(DETECTORS)
    assert set(report["recall_by_attack"]) == set(ATTACK_TYPES)
    for m in report["detectors"].values():
        assert all(0 <= m[k] <= 1 for k in ("precision", "recall", "f1", "pr_auc", "fpr", "incident_recall"))
    # the hybrid alerts exactly when the rules or the Isolation Forest alert
    det = report["detectors"]
    assert det["Hybrid"]["true_positives"] >= max(det["Rules"]["true_positives"],
                                                  det["IsolationForest"]["true_positives"])
    md = (out / "metrics.md").read_text()
    assert "| Hybrid |" in md and "`privilege_escalation`" in md


def test_detector_metrics_by_hand():
    test = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-01-01 10:00", "2026-01-01 11:00", "2026-01-02 10:00",
                                     "2026-01-02 11:00", "2026-01-02 12:00"]),
        "user": ["a", "a", "b", "c", "c"],
        "attack_type": ["lateral_movement", "lateral_movement", "checkout_burst", "", ""],
        "is_attack": [1, 1, 1, 0, 0],
    })
    alert = np.array([True, False, False, True, False])
    m = detector_metrics(test, np.array([0.9, 0.2, 0.1, 0.8, 0.0]), alert)
    assert (m["precision"], m["recall"]) == (0.5, pytest.approx(1 / 3))
    assert (m["incidents_detected"], m["incidents"]) == (1, 2)  # a's lateral movement caught, b's burst missed
    assert m["fpr"] == 0.5 and m["benign_alerts_per_day"] == 0.5


def test_lanl_split_boundary_is_first_red_team_event(cfg):
    cfg.processed_dir.mkdir()
    events = generate(replace(cfg.synthetic, attacks={"lateral_movement": 1}))
    events.to_parquet(cfg.processed_dir / "lanl_events.parquet")
    train, test = load_split("lanl", cfg)
    first = events.timestamp[events.is_attack == 1].min()
    assert train.timestamp.max() < first == test.timestamp.min()
    assert train.is_attack.sum() == 0 and len(train) + len(test) == len(events)


def test_lanl_missing_raises_clear_error(cfg):
    with pytest.raises(FileNotFoundError, match="make lanl"):
        evaluate("lanl", cfg)


def test_cli_rejects_unknown_dataset():
    with pytest.raises(SystemExit):
        main(["--dataset", "nope"])
