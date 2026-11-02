from dataclasses import replace

import numpy as np
import pandas as pd
import pytest

from privguard.config import load_config
from privguard.features import FEATURES
from privguard.schema import COLUMNS
from privguard.scorer import Scorer, baseline_end, calibrate, main
from privguard.synthetic import ATTACK_TYPES, generate

OUTPUTS = ["risk_score", "severity", "is_alert", "rules_triggered", "reasons", "explanation", "top_features"]


@pytest.fixture(scope="module")
def cfg():
    base = load_config()
    syn = replace(base.synthetic, days=10, n_humans=10, n_admins=3, n_servers=10, attack_start_day=5,
                  attacks=dict.fromkeys(ATTACK_TYPES, 1))
    return replace(base, synthetic=syn, model=replace(base.model, iforest={"n_estimators": 50}))


@pytest.fixture(scope="module")
def split(cfg):
    events = generate(cfg.synthetic)
    end = baseline_end(cfg)
    return events[events.timestamp < end], events[events.timestamp >= end]


@pytest.fixture(scope="module")
def scorer(cfg, split):
    return Scorer.fit(split[0], cfg)


def test_contract_columns_order_and_bands(scorer, split):
    train, test = split
    events = test.sample(frac=1, random_state=0).drop(columns=["is_attack", "attack_type"])  # unlabeled, shuffled
    out = scorer.score(events, history=train)

    assert list(out.columns) == COLUMNS + FEATURES + OUTPUTS
    assert out.user.tolist() == events.user.tolist() and out.timestamp.tolist() == events.timestamp.tolist()
    assert (out.is_attack == 0).all() and (out.attack_type == "").all()
    assert out.risk_score.between(0, 100).all()
    bands = pd.cut(out.risk_score, [-np.inf, 40, 70, 90, np.inf], right=False,
                   labels=["low", "medium", "high", "critical"]).astype(str)
    assert (out.severity == bands).all()
    assert (out.is_alert == (out.severity != "low")).all()
    assert out.is_alert.any() and (~out.is_alert).any()

    alerts = out[out.is_alert]
    assert alerts.reasons.map(len).gt(0).all() and alerts.explanation.str.len().gt(0).all()
    assert alerts.top_features.map(len).between(1, 5).all()
    assert set(alerts.top_features.iloc[0][0]) == {"feature", "value", "contribution"}
    assert out.rules_triggered.map(lambda r: all(isinstance(x, str) for x in r)).all()


def test_calibration_anchors_and_monotonic():
    t, medium = 0.63, 40
    assert calibrate(np.array([0.0, t, 1.0]), t, medium).tolist() == [0.0, 40.0, 100.0]
    s = np.sort(np.random.default_rng(0).uniform(0, 1, 1000))
    assert (np.diff(calibrate(s, t, medium)) >= 0).all()


def test_iforest_score_at_threshold_is_medium_boundary(scorer):
    medium = scorer.severity["medium"]
    assert calibrate(np.array([scorer.iforest.threshold_]), scorer.iforest.threshold_, medium)[0] == medium


def test_priv_cmd_is_critical(scorer, cfg):
    event = {"timestamp": baseline_end(cfg) + pd.Timedelta(days=1, hours=10), "user": "adm01",
             "account_type": "admin", "src_host": "WS-0011", "dst_host": "SRV-DC01", "event_type": "command",
             "success": True, "command": 'net group "Domain Admins" sysadm /add /domain'}
    out = scorer.score(pd.DataFrame([event])).iloc[0]
    assert out.severity == "critical" and out.rules_triggered[0] == "PRIV_CMD"
    assert out.reasons[0].startswith("Privilege-escalation command")


def test_save_load_roundtrip(scorer, split, tmp_path):
    train, test = split
    path = tmp_path / "bundle.joblib"
    scorer.save(path)
    pd.testing.assert_frame_equal(Scorer.load(path).score(test, history=train), scorer.score(test, history=train))


def test_cli_trains_and_learns_false_positives(cfg, split, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    config = root / "config.toml"
    config.write_text(load_config().root.joinpath("config.toml").read_text())
    data, feedback = tmp_path / "events.parquet", tmp_path / "feedback.parquet"
    split[0].to_parquet(data)  # synthetic baseline_end of the repo config is after all of it
    fp = split[1].iloc[[0, 1]].assign(src_host=["WS-FP", "WS-TP"], label=["false_positive", "true_positive"])
    fp.to_parquet(feedback)

    main(["--config", str(config), "--data", str(data), "--feedback", str(feedback)])

    profile = Scorer.load(root / "artifacts" / "scorer.joblib").profile
    assert (fp.user.iloc[0], "WS-FP") in profile.known_src
    assert (fp.user.iloc[1], "WS-TP") not in profile.known_src
