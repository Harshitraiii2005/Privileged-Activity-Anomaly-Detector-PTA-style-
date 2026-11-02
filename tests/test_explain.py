from dataclasses import replace

import numpy as np
import pandas as pd
import pytest

from privguard.config import load_config
from privguard.explain import TEMPLATES, anomaly_contributions, shap_reasons, summary_plot, top_features
from privguard.features import FEATURES
from privguard.scorer import Scorer, baseline_end, baseline_features
from privguard.synthetic import generate


@pytest.fixture(scope="module")
def cfg():
    base = load_config()
    syn = replace(base.synthetic, days=7, n_humans=10, n_admins=3, n_servers=10, attack_start_day=6, attacks={})
    return replace(base, synthetic=syn, model=replace(base.model, iforest={"n_estimators": 50}))


@pytest.fixture(scope="module")
def train(cfg):
    events = generate(cfg.synthetic)
    return events[events.timestamp < baseline_end(cfg)]


@pytest.fixture(scope="module")
def scorer(cfg, train):
    return Scorer.fit(train, cfg)


def test_shap_sign_convention(scorer, train):
    """Positive contributions = toward anomaly: the IF score is strictly increasing in their sum."""
    X = baseline_features(train)
    total = anomaly_contributions(scorer.explainer, X).sum(axis=1)
    order = np.argsort(scorer.iforest.score(X), kind="stable")
    assert (np.diff(total[order]) >= -1e-9).all()


def test_every_feature_has_a_template():
    assert set(TEMPLATES) == set(FEATURES)


def test_night_admin_logon_explanation_mentions_time(scorer, cfg):
    day = baseline_end(cfg) + pd.Timedelta(days=1, hours=3)  # 03:00 the day after the baseline
    event = {"timestamp": day, "user": "adm00", "account_type": "admin", "src_host": "WS-9999",
             "dst_host": "SRV-DC01", "event_type": "logon", "success": True, "command": ""}
    out = scorer.score(pd.DataFrame([event])).iloc[0]
    assert out.is_alert
    assert "OFF_HOURS_PRIV" in out.rules_triggered
    assert "03:00" in out.explanation
    assert "WS-9999" in " ".join(out.reasons)  # new source host is reported too (rule or SHAP)


def test_shap_reasons_skip_covered_and_absent_features():
    row = {**dict.fromkeys(FEATURES, 0.0), "new_src_host": 1.0, "events_1h": 7.0, "acct_admin": 1.0,
           "timestamp": pd.Timestamp("2026-01-20 03:12"), "user": "adm01", "account_type": "admin",
           "event_type": "logon", "success": True, "src_host": "WS-0042", "dst_host": "SRV-DC01", "command": ""}
    contrib = np.zeros(len(FEATURES))
    contrib[FEATURES.index("off_hours")] = 3.0  # value 0: an absence, not described
    contrib[FEATURES.index("new_src_host")] = 2.0
    contrib[FEATURES.index("events_1h")] = 1.0  # covered by a fired rule
    contrib[FEATURES.index("failed")] = -1.0  # pushes toward normal
    assert shap_reasons(row, contrib, covered={"events_1h"}) == [
        "Admin login at 03:12 from a host never seen before for adm01 (WS-0042)"
    ]
    top = top_features(row, contrib)
    assert [t["feature"] for t in top] == ["off_hours", "new_src_host", "events_1h"]
    assert top[1] == {"feature": "new_src_host", "value": 1.0, "contribution": 2.0}


def test_summary_plot_writes_png(scorer, train, tmp_path):
    path = tmp_path / "shap_summary.png"
    summary_plot(scorer.explainer, baseline_features(train), path, max_rows=200)
    assert path.stat().st_size > 0
