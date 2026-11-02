import sys
import types
from typing import get_args

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from privguard.api import EventIn, app
from privguard.schema import ACCOUNT_TYPES, EVENT_TYPES
from privguard.store import Store

SEVERITY = {"crit": ("critical", 95.0), "high": ("high", 75.0), "med": ("medium", 50.0)}


class FakeScorer:
    """Implements the Scorer contract; severity is driven by a keyword in the command."""

    def __init__(self):
        self.history = None

    @classmethod
    def load(cls, path=None):
        return cls()

    def score(self, events, history=None):
        self.history = history
        out = events.copy()
        sev = [SEVERITY.get(c.split(":")[0], ("low", 5.0)) for c in out.command]
        out["severity"] = [s for s, _ in sev]
        out["risk_score"] = [r for _, r in sev]
        out["is_alert"] = out.severity != "low"
        out["rules_triggered"] = [["PRIV_CMD"] if c else [] for c in out.command]
        out["reasons"] = [[f"{s} reason"] for s in out.severity]
        out["explanation"] = "because"
        out["top_features"] = [[{"feature": "off_hours", "value": 1.0, "contribution": 0.3}]] * len(out)
        return out


def ev(ts, user="adm01", command="", **kw):
    return {"timestamp": ts, "user": user, "account_type": "admin", "src_host": "WS-1", "dst_host": "SRV-1",
            "event_type": "command" if command else "logon", "command": command, **kw}


@pytest.fixture
def client(tmp_path):
    app.state.store = Store(tmp_path / "t.db")
    app.state.scorer = FakeScorer()
    return TestClient(app)  # no `with`: skip the lifespan so the real model is never loaded


def post(client, *events):
    r = client.post("/score", json={"events": list(events)})
    assert r.status_code == 200, r.text
    return r.json()["results"]


def test_enums_match_schema():
    assert get_args(EventIn.model_fields["account_type"].annotation) == ACCOUNT_TYPES
    assert get_args(EventIn.model_fields["event_type"].annotation) == EVENT_TYPES


def test_health_and_503_without_model(client):
    assert client.get("/health").json() == {"status": "ok", "model_loaded": True}
    app.state.scorer = None
    assert client.get("/health").json()["model_loaded"] is False
    r = client.post("/score", json={"events": [ev("2026-01-19T10:00:00")]})
    assert r.status_code == 503 and "make train" in r.json()["detail"]


def test_score_order_alerts_and_utc(client):
    res = post(client, ev("2026-01-19T10:00:00"), ev("2026-01-19T04:01:00+01:00", command="crit: sudo su -"),
               ev("2026-01-19T10:02:00", user="bob", command="high: x"))
    assert [r["user"] for r in res] == ["adm01", "adm01", "bob"]
    assert [r["severity"] for r in res] == ["low", "critical", "high"]
    assert res[0]["alert_id"] is None and res[1]["alert_id"] and res[2]["alert_id"]
    assert res[1]["timestamp"] == "2026-01-19T03:01:00"  # tz-aware input stored as naive UTC
    assert res[1]["top_features"][0] == {"feature": "off_hours", "value": 1.0, "contribution": 0.3}
    alerts = client.get("/alerts").json()
    assert [a["id"] for a in alerts] == [res[2]["alert_id"], res[1]["alert_id"]]
    assert alerts[1]["command"] == "crit: sudo su -" and alerts[1]["event_id"] == res[1]["event_id"]


def test_history_from_store_feeds_windowed_features(client):
    post(client, ev("2026-01-19T08:00:00"), ev("2026-01-19T09:40:00"), ev("2026-01-19T09:50:00", user="bob"))
    post(client, ev("2026-01-19T10:30:00"))
    hist = app.state.scorer.history
    assert hist.user.tolist() == ["adm01"]  # other users excluded
    assert hist.timestamp.tolist() == [pd.Timestamp("2026-01-19 09:40")]  # only the last hour


@pytest.mark.parametrize("bad", [
    [],
    [ev("2026-01-19T10:00:00", account_type="root")],
    [ev("2026-01-19T10:00:00", event_type="sudo")],
    [ev("2026-01-19T10:00:00", user="  ")],
    [ev("2026-01-19T10:00:00", src_host="")],
    [ev("not a time")],
    [ev("2026-01-19T10:00:00")] * 10_001,
])
def test_validation_422(client, bad):
    assert client.post("/score", json={"events": bad}).status_code == 422


def test_alert_filters_feedback_and_404(client):
    res = post(client, ev("2026-01-19T10:00:00", command="med: a"), ev("2026-01-19T10:01:00", command="crit: b"),
               ev("2026-01-19T10:02:00", user="bob", command="high: c"))
    med, crit, high = (r["alert_id"] for r in res)
    assert [a["id"] for a in client.get("/alerts", params={"severity": "critical"}).json()] == [crit]
    assert [a["id"] for a in client.get("/alerts", params={"user": "bob"}).json()] == [high]
    assert len(client.get("/alerts", params={"limit": 1}).json()) == 1
    assert client.get("/alerts", params={"status": "pending"}).status_code == 422

    r = client.post(f"/alerts/{crit}/feedback", json={"label": "true_positive", "analyst": "ana", "note": "confirmed"})
    assert r.status_code == 200 and r.json()["status"] == "closed" and r.json()["feedback_label"] == "true_positive"
    assert client.get(f"/alerts/{crit}").json()["status"] == "closed"
    assert [a["id"] for a in client.get("/alerts", params={"status": "open"}).json()] == [high, med]
    assert client.post(f"/alerts/{med}/feedback", json={"label": "meh", "analyst": "ana"}).status_code == 422
    assert client.post(f"/alerts/{med}/feedback", json={"label": "false_positive", "analyst": ""}).status_code == 422
    assert client.get("/alerts/999").status_code == 404
    assert client.post("/alerts/999/feedback", json={"label": "true_positive", "analyst": "a"}).status_code == 404

    client.post(f"/alerts/{med}/feedback", json={"label": "false_positive", "analyst": "ana"})
    fb = app.state.store.export_feedback()
    assert fb.label.tolist() == ["false_positive", "true_positive"] and fb.command.tolist() == ["med: a", "crit: b"]


def test_events_top_users_summary(client):
    post(client, ev("2026-01-19T10:00:00"), ev("2026-01-19T11:00:00", command="crit: x"),
         ev("2026-01-19T10:30:00", user="bob"))
    events = client.get("/events", params={"user": "adm01"}).json()
    assert [e["severity"] for e in events] == ["low", "critical"]  # oldest first
    assert len(client.get("/events", params={"since": "2026-01-19T10:15:00"}).json()) == 2
    top = client.get("/stats/top-users", params={"limit": 1}).json()
    assert top == [{"user": "adm01", "account_type": "admin", "alerts": 1, "max_risk": 95.0, "mean_risk": 50.0}]
    assert client.get("/stats/summary").json() == {"events_scored": 3, "alerts": 1, "open_alerts": 1,
                                                   "open_by_severity": {"critical": 1}}


@pytest.mark.parametrize("scorer_module", [None, types.SimpleNamespace(Scorer=FakeScorer)])
def test_lifespan_loads_model_or_degrades(tmp_path, monkeypatch, scorer_module):
    monkeypatch.setenv("PRIVGUARD_DB_PATH", str(tmp_path / "life" / "t.db"))
    monkeypatch.setitem(sys.modules, "privguard.scorer", scorer_module)  # None -> ImportError
    with TestClient(app) as c:
        assert c.get("/health").json()["model_loaded"] is (scorer_module is not None)
        assert c.get("/alerts").json() == []
    assert (tmp_path / "life" / "t.db").exists()
