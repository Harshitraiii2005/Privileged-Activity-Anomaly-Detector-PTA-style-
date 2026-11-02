import subprocess
import sys
from dataclasses import replace

import numpy as np
import pandas as pd
import pytest

from privguard.config import load_config
from privguard.detectors import PRIV_CMD, AutoencoderDetector, IsolationForestDetector, RulesEngine
from privguard.features import FEATURES
from privguard.scorer import baseline_features
from privguard.synthetic import BENIGN_COMMANDS, ESCALATION_COMMANDS, generate


@pytest.fixture(scope="module")
def X():
    syn = replace(load_config().synthetic, days=6, n_humans=10, n_admins=3, n_servers=10, attack_start_day=5,
                  attacks={})
    return baseline_features(generate(syn))


def row(**over):
    """A featurized admin logon with every feature at 0, plus overrides."""
    base = {"timestamp": pd.Timestamp("2026-01-06 10:00"), "user": "adm01", "account_type": "admin",
            "src_host": "WS-1", "dst_host": "SRV-1", "event_type": "logon", "success": True, "command": "",
            "is_attack": 0, "attack_type": ""}
    return {**base, **dict.fromkeys(FEATURES, 0.0), "acct_admin": 1.0, "is_logon": 1.0, **over}


@pytest.mark.parametrize(
    "cmd", [c.format(u="bob") for cmds in ESCALATION_COMMANDS.values() for c in cmds] + ["sudo -i", "visudo"]
)
def test_priv_cmd_matches_escalation(cmd):
    assert PRIV_CMD.search(cmd)


@pytest.mark.parametrize("cmd", [c for cmds in BENIGN_COMMANDS.values() for c in cmds])
def test_priv_cmd_ignores_benign_lookalikes(cmd):
    assert not PRIV_CMD.search(cmd)


def test_rules_fire_combine_and_explain():
    X = pd.DataFrame([
        row(),
        row(is_command=1, is_logon=0, event_type="command", command="net localgroup administrators bob /add"),
        row(distinct_dst_1h=12),
        row(checkouts_1h=6),
        row(off_hours=1, hour_rarity=1.0, timestamp=pd.Timestamp("2026-01-06 03:07")),
        row(off_hours=1, hour_rarity=1.0, acct_admin=0, acct_service=1, account_type="service"),  # services run 24/7
        row(failed_1h=6, fail_ratio_1h=0.6),
        row(no_checkout=1, new_src_host=1),
        row(new_src_host=1, acct_admin=0, acct_service=1, account_type="service"),  # fixed-host jobs exempt
        row(failed_1h=1, fail_ratio_1h=0.5, events_1h=5),  # one mistyped password, then commands
    ])
    rules = RulesEngine().fit(X)
    fired = rules.triggered(X)
    assert [list(fired.columns[m]) for m in fired.to_numpy()] == [
        [], ["PRIV_CMD"], ["LATERAL"], ["VAULT_BURST"], ["OFF_HOURS_PRIV"], [], ["FAILED_BURST"],
        ["UNMANAGED_ACCESS", "NEW_SOURCE"], [], [],
    ]
    score = rules.score(X)
    assert score[0] == 0 and score[1] == pytest.approx(0.9)
    assert score[7] == pytest.approx(1 - 0.7 * 0.7)  # 1 - prod(1 - w)
    # a weak rule alone is context, two weak rules together alert
    assert RulesEngine.BY_ID["NEW_SOURCE"].weight < rules.threshold_ <= score[7]
    reasons = rules.reasons(X, fired)
    assert reasons[0] == []
    assert "bob /add" in reasons[1][0] and "12 distinct hosts" in reasons[2][0] and "03:07" in reasons[4][0]
    assert len(reasons[7]) == 2


def test_iforest_threshold_is_baseline_quantile(X):
    det = IsolationForestDetector(quantile=0.95, seed=0, n_estimators=50).fit(X)
    s = det.score(X)
    assert det.threshold_ == pytest.approx(np.quantile(s, 0.95))
    assert 0 < det.threshold_ < 1 and (s > det.threshold_).mean() <= 0.05  # ties at the quantile are allowed
    assert np.array_equal(s, IsolationForestDetector(quantile=0.95, seed=0, n_estimators=50).fit(X).score(X))


def test_autoencoder_runs_deterministically(X):
    det = AutoencoderDetector(quantile=0.99, seed=0, hidden=4, epochs=2).fit(X)
    s = det.score(X)
    assert s.shape == (len(X),) and (s >= 0).all()
    assert det.threshold_ == pytest.approx(np.quantile(s, 0.99))
    assert np.allclose(s, AutoencoderDetector(quantile=0.99, seed=0, hidden=4, epochs=2).fit(X).score(X))


def test_serving_path_never_imports_torch():
    code = "import sys, privguard.detectors, privguard.scorer; assert 'torch' not in sys.modules"
    subprocess.run([sys.executable, "-c", code], check=True)
