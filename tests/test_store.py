import sqlite3

import pandas as pd
import pytest

from privguard import store as store_mod
from privguard.schema import COLUMNS
from privguard.store import Store

RISK = {"low": 5.0, "medium": 50.0, "high": 75.0, "critical": 95.0}


def scored(ts, user="adm01", severity="low", account_type="admin", command=""):
    return {
        "timestamp": pd.Timestamp(ts), "user": user, "account_type": account_type, "src_host": "WS-1",
        "dst_host": "SRV-1", "event_type": "command" if command else "logon", "success": True, "command": command,
        "is_attack": 0, "attack_type": "", "risk_score": RISK[severity], "severity": severity,
        "explanation": f"{severity} thing", "reasons": [f"reason {severity}"],
        "rules_triggered": ["PRIV_CMD"] if command else [],
        "top_features": [{"feature": "off_hours", "value": 1.0, "contribution": 0.4}],
    }


@pytest.fixture
def db(tmp_path):
    return Store(tmp_path / "sub" / "t.db")


def test_schema_wal_and_ids(db):
    with sqlite3.connect(db.path) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    ids = db.insert_scored(pd.DataFrame([scored("2026-01-19 10:00"), scored("2026-01-19 10:05", severity="high")]))
    assert ids[0][1] is None and isinstance(ids[1][1], int) and ids[1][0] > ids[0][0]
    alert = db.get_alert(ids[1][1])
    assert alert["event_id"] == ids[1][0] and alert["status"] == "open" and alert["feedback_label"] is None
    assert alert["top_features"][0]["feature"] == "off_hours" and alert["reasons"] == ["reason high"]
    assert db.get_alert(999) is None


def test_history_filters_users_and_window(db):
    db.insert_scored(pd.DataFrame([
        scored("2026-01-19 08:00"),                       # before window
        scored("2026-01-19 09:30:00.5"),                  # sub-second precision, in window
        scored("2026-01-19 09:45", user="bob", account_type="human"),
        scored("2026-01-19 09:50", user="eve", account_type="human"),  # not requested
        scored("2026-01-19 11:00"),                       # after window
    ]))
    hist = db.history(["adm01", "bob"], pd.Timestamp("2026-01-19 09:00"), pd.Timestamp("2026-01-19 10:00"))
    assert list(hist.columns) == COLUMNS
    assert hist.user.tolist() == ["adm01", "bob"]
    assert hist.timestamp.iloc[0] == pd.Timestamp("2026-01-19 09:30:00.5")
    assert hist.success.dtype == bool and (hist.is_attack == 0).all()
    assert db.history(["nobody"], "2026-01-01", "2027-01-01").empty


def test_alert_filters_and_feedback(db):
    ids = db.insert_scored(pd.DataFrame([
        scored("2026-01-19 10:00", severity="medium"),
        scored("2026-01-19 10:01", severity="critical", command="sudo su -"),
        scored("2026-01-19 10:02", user="bob", account_type="human", severity="high"),
    ]))
    alert_ids = [a for _, a in ids]
    assert [a["id"] for a in db.list_alerts()] == alert_ids[::-1]  # newest first
    assert [a["id"] for a in db.list_alerts(severity="critical")] == [alert_ids[1]]
    assert [a["id"] for a in db.list_alerts(user="bob")] == [alert_ids[2]]
    assert len(db.list_alerts(limit=1)) == 1

    assert db.add_feedback(alert_ids[1], "false_positive", "ana")
    assert db.add_feedback(alert_ids[1], "true_positive", "ana", "on second look")  # latest label wins
    assert not db.add_feedback(999, "true_positive", "ana")
    with pytest.raises(sqlite3.IntegrityError):
        db.add_feedback(alert_ids[0], "maybe", "ana")
    assert db.get_alert(alert_ids[0])["status"] == "open"  # failed insert rolled back the close
    closed = db.list_alerts(status="closed")
    assert [(a["id"], a["feedback_label"]) for a in closed] == [(alert_ids[1], "true_positive")]
    assert len(db.list_alerts(status="open")) == 2


def test_events_top_users_summary(db):
    db.insert_scored(pd.DataFrame([scored(f"2026-01-19 1{i}:00", severity=s) for i, s in
                                   enumerate(["low", "high", "low", "critical"])]
                                  + [scored("2026-01-19 10:30", user="bob", account_type="human")]))
    events = db.list_events(user="adm01", limit=2)
    assert [e["timestamp"] for e in events] == ["2026-01-19T12:00:00", "2026-01-19T13:00:00"]  # latest 2, oldest first
    assert len(db.list_events(since="2026-01-19 10:30")) == 4
    top = db.top_users()
    assert [t["user"] for t in top] == ["adm01", "bob"]
    assert top[0] == {"user": "adm01", "account_type": "admin", "alerts": 2, "max_risk": 95.0, "mean_risk": 45.0}
    assert db.summary() == {"events_scored": 5, "alerts": 2, "open_alerts": 2,
                            "open_by_severity": {"high": 1, "critical": 1}}


def test_export_feedback_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVGUARD_DB_PATH", str(tmp_path / "t.db"))
    db = Store(tmp_path / "t.db")
    ids = db.insert_scored(pd.DataFrame([scored("2026-01-19 10:00", severity="high"),
                                         scored("2026-01-19 10:01", severity="critical", command="sudo su -"),
                                         scored("2026-01-19 10:02", severity="medium")]))
    db.add_feedback(ids[0][1], "false_positive", "ana")
    db.add_feedback(ids[1][1], "true_positive", "ana")
    out = tmp_path / "fb.parquet"
    store_mod.main(["export-feedback", "--out", str(out)])
    df = pd.read_parquet(out)
    assert list(df.columns) == [*COLUMNS, "label"]
    assert df.label.tolist() == ["false_positive", "true_positive"]  # unlabeled alert excluded
    assert (df.is_attack == 0).all() and df.command.tolist() == ["", "sudo su -"]
