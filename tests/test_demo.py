import io
import json

import httpx
import pandas as pd
import pytest

from privguard.config import load_config
from privguard.demo import KILL_CHAIN, build_scenario, replay
from privguard.schema import COLUMNS


@pytest.fixture(scope="module")
def scenario():
    return build_scenario(load_config())


def test_scenario_deterministic(scenario):
    again = build_scenario(load_config())
    for a, b in zip(scenario, again):
        pd.testing.assert_frame_equal(a, b)


def test_scenario_shape(scenario):
    warmup, events = scenario
    for df in (warmup, events):
        assert list(df.columns) == COLUMNS
        assert df.timestamp.is_monotonic_increasing
    assert (warmup.is_attack == 0).all()
    assert warmup.timestamp.max() < events.timestamp.min()
    assert events.timestamp.min() - warmup.timestamp.min() <= pd.Timedelta(hours=1)
    attack = events[events.is_attack == 1]
    assert (events.is_attack == 0).sum() > 50  # benign traffic around the attack
    assert attack.user.nunique() == 1 and (attack.account_type == "admin").all()
    # Steps happen in kill-chain order.
    assert list(dict.fromkeys(attack.attack_type)) == list(KILL_CHAIN)
    assert attack.command.str.contains("Domain Admins").any()


def mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://api")


def test_replay_against_mock_api(scenario):
    warmup, events = scenario
    attacker = events.user[events.is_attack == 1].iloc[0]
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok", "model_loaded": True})
        batch = json.loads(request.content)["events"]
        sent.extend(batch)
        # Fake model: alert on vault checkouts and account-creation commands only.
        results = [
            {"risk_score": 95.0 if hot else 5.0, "severity": "critical" if hot else "low",
             "explanation": "test", "alert_id": 1 if hot else None}
            for e in batch
            for hot in [e["event_type"] == "checkout" and e["user"] == attacker or "/add" in e["command"]]
        ]
        return httpx.Response(200, json={"results": results})

    out = io.StringIO()
    summary = replay(mock_client(handler), warmup, events, speed=0, out=out)

    assert len(sent) == len(warmup) + len(events)
    assert all("is_attack" not in e and "attack_type" not in e for e in sent)  # labels never leave the demo
    assert summary["steps_detected"] == {
        "new_source_host": False, "checkout_burst": True, "lateral_movement": False, "privilege_escalation": True,
    }
    assert summary["attack_events"] == (events.is_attack == 1).sum()
    assert summary["attack_alerted"] == 12 + 3
    assert summary["benign_events"] == (events.is_attack == 0).sum()
    own_checkouts = (events.is_attack == 0) & (events.user == attacker) & (events.event_type == "checkout")
    assert summary["benign_alerted"] == own_checkouts.sum()
    assert summary["false_alerts_other_accounts"] == 0
    text = out.getvalue()
    assert "CRITICAL" in text and "DETECTED" in text and "MISSED" in text
    assert "\033[" not in text  # no ANSI codes when not a TTY


def refuse(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


@pytest.mark.parametrize(
    "handler, message",
    [
        (lambda r: httpx.Response(200, json={"status": "ok", "model_loaded": False}), "make train"),
        (lambda r: httpx.Response(200, json={"status": "ok", "model_loaded": True}) if r.url.path == "/health"
         else httpx.Response(503, json={"detail": "model not trained"}), "make train"),
        (refuse, "not reachable"),
    ],
)
def test_replay_api_errors(scenario, handler, message):
    with pytest.raises(SystemExit, match=message):
        replay(mock_client(handler), *scenario, speed=0, out=io.StringIO())
