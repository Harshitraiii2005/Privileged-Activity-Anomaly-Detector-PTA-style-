from pathlib import Path

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from privguard import dashboard

APP = str(Path(dashboard.__file__))
ALERT = {
    "id": 2, "event_id": 7, "created_at": "2026-01-19T03:13:00", "timestamp": "2026-01-19T03:12:00", "user": "adm01",
    "account_type": "admin", "src_host": "WS-0042", "dst_host": "DC-01", "event_type": "command",
    "command": "net user evil /add", "risk_score": 96.5, "severity": "critical", "explanation": "Admin at 03:12",
    "reasons": ["off hours", "new host"], "rules_triggered": ["PRIV_CMD"], "status": "open", "feedback_label": None,
    "top_features": [{"feature": "off_hours", "value": 1.0, "contribution": 0.4},
                     {"feature": "events_1h", "value": 2.0, "contribution": -0.1}],
}
ROUTES = {
    "/health": {"status": "ok", "model_loaded": True},
    "/stats/summary": {"events_scored": 40, "alerts": 2, "open_alerts": 2, "open_by_severity": {"critical": 1}},
    "/alerts": [ALERT, {**ALERT, "id": 1, "event_id": 3, "severity": "medium", "risk_score": 45.0, "user": "bob"}],
    "/stats/top-users": [{"user": "adm01", "account_type": "admin", "alerts": 1, "max_risk": 96.5, "mean_risk": 30.0}],
    "/events": [{k: ALERT[k] for k in ("timestamp", "user", "account_type", "src_host", "dst_host", "event_type",
                                       "command", "risk_score", "severity")} | {"id": 7}],
}


@pytest.fixture
def api(monkeypatch):
    posts = []

    def get(url, params=None, timeout=None):
        return httpx.Response(200, json=ROUTES[url.split("8000", 1)[1]], request=httpx.Request("GET", url))

    def post(url, json=None, timeout=None):
        posts.append((url, json))
        return httpx.Response(200, json={**ALERT, "status": "closed"}, request=httpx.Request("POST", url))

    monkeypatch.setenv("PRIVGUARD_API_URL", "http://api:8000")
    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setattr(httpx, "post", post)
    return posts


def test_renders_and_submits_feedback(api):
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert [m.value for m in at.metric] == ["2", "1", "0", "40"]
    assert any("Admin at 03:12" in m.value for m in at.markdown)  # most urgent alert's explanation

    next(b for b in at.button if b.label == "True positive").click().run()
    assert at.warning and not api  # analyst name required
    at.text_input[0].input("ana")
    next(b for b in at.button if b.label == "True positive").click().run()
    assert api == [("http://api:8000/alerts/2/feedback", {"label": "true_positive", "analyst": "ana", "note": ""})]
    assert "closed as true positive" in at.success[0].value


def test_api_unreachable(monkeypatch):
    def down(url, **kw):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setenv("PRIVGUARD_API_URL", "http://api:8000")
    monkeypatch.setattr(httpx, "get", down)
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception and "unreachable" in at.error[0].value
