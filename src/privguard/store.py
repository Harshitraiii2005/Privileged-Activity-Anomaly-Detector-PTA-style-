"""SQLite store for scored events, alerts and analyst feedback.

The API persists every scored event here, raises an alert for each event above
"low" severity, and records analyst verdicts on those alerts. The verdicts are
exported as labeled data so the model can be retrained on them
(``python -m privguard.scorer --feedback PATH``).

Plain ``sqlite3`` in WAL mode: a single file, no server, readers never block
the writer. Every call opens its own short-lived connection, so one
:class:`Store` is safe to share across FastAPI's worker threads.

Usage:
    python -m privguard.store export-feedback [--config PATH] [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from privguard.config import load_config
from privguard.schema import validate

log = logging.getLogger(__name__)

FEEDBACK_NAME = "feedback.parquet"
JSON_FIELDS = ("reasons", "rules_triggered", "top_features")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY,
    timestamp       TEXT    NOT NULL,          -- ISO 8601, naive UTC (sorts lexicographically)
    user            TEXT    NOT NULL,
    account_type    TEXT    NOT NULL,
    src_host        TEXT    NOT NULL,
    dst_host        TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    success         INTEGER NOT NULL,
    command         TEXT    NOT NULL DEFAULT '',
    risk_score      REAL    NOT NULL,
    severity        TEXT    NOT NULL,
    explanation     TEXT    NOT NULL DEFAULT '',
    reasons         TEXT    NOT NULL DEFAULT '[]',  -- JSON list[str]
    rules_triggered TEXT    NOT NULL DEFAULT '[]',  -- JSON list[str]
    top_features    TEXT    NOT NULL DEFAULT '[]',  -- JSON list[{feature, value, contribution}]
    scored_at       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events (user, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY,
    event_id   INTEGER NOT NULL UNIQUE REFERENCES events (id),
    created_at TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

CREATE TABLE IF NOT EXISTS feedback (
    id         INTEGER PRIMARY KEY,
    alert_id   INTEGER NOT NULL REFERENCES alerts (id),
    label      TEXT    NOT NULL CHECK (label IN ('true_positive', 'false_positive')),
    analyst    TEXT    NOT NULL,
    note       TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_alert ON feedback (alert_id);
"""

EVENT_COLUMNS = (
    "e.timestamp, e.user, e.account_type, e.src_host, e.dst_host, e.event_type, e.command, e.risk_score, e.severity"
)
ALERT_SQL = f"""
SELECT a.id, a.event_id, a.created_at, a.status, {EVENT_COLUMNS},
       e.explanation, e.reasons, e.rules_triggered, e.top_features,
       (SELECT f.label FROM feedback f WHERE f.alert_id = a.id ORDER BY f.id DESC LIMIT 1) AS feedback_label
FROM alerts a JOIN events e ON e.id = a.event_id
"""


def _ts(value: Any) -> str:
    """ISO 8601 text for a timestamp, so string order equals time order in SQL."""
    return pd.Timestamp(value).isoformat()


def _now() -> str:
    """Current naive-UTC time as ISO 8601 text."""
    return datetime.now(UTC).replace(tzinfo=None).isoformat(timespec="seconds")


def _where(*conds: tuple[str, Any]) -> tuple[str, list[Any]]:
    """``WHERE`` clause and params from ``(sql, value)`` pairs, skipping ``None`` values."""
    used = [(sql, value) for sql, value in conds if value is not None]
    return (" WHERE " + " AND ".join(sql for sql, _ in used) if used else ""), [value for _, value in used]


def _canonical(df: pd.DataFrame) -> pd.DataFrame:
    """Rows read from ``events`` -> canonical schema (stored events carry no ground-truth label)."""
    return validate(df.assign(timestamp=pd.to_datetime(df.timestamp, format="ISO8601"), is_attack=0, attack_type=""))


class Store:
    """Scored events, alerts and feedback in one SQLite file."""

    def __init__(self, path: str | Path) -> None:
        """Open (creating if needed) the database at ``path`` and ensure the schema exists."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")  # persistent per file; readers don't block the writer
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One transaction on a fresh connection: commit on success, roll back on error, always close."""
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        """Run a SELECT and return rows as dicts with JSON columns decoded."""
        with self._connect() as conn:
            rows = [dict(row) for row in conn.execute(sql, tuple(params))]
        for row in rows:
            for field in JSON_FIELDS:
                if field in row:
                    row[field] = json.loads(row[field])
        return rows

    def insert_scored(self, scored: pd.DataFrame) -> list[tuple[int, int | None]]:
        """Persist scored events (the :class:`~privguard.scorer.Scorer` output) in one transaction.

        An open alert is created for every event whose severity is not ``"low"``.

        Returns:
            ``(event_id, alert_id or None)`` per input row, in input order.
        """
        now, ids = _now(), []
        with self._connect() as conn:
            for row in scored.to_dict("records"):
                event_id = conn.execute(
                    "INSERT INTO events (timestamp, user, account_type, src_host, dst_host, event_type, success,"
                    " command, risk_score, severity, explanation, reasons, rules_triggered, top_features, scored_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        _ts(row["timestamp"]), row["user"], row["account_type"], row["src_host"], row["dst_host"],
                        row["event_type"], bool(row["success"]), row["command"] or "", float(row["risk_score"]),
                        row["severity"], row["explanation"],
                        *(json.dumps(list(row[field]), default=float) for field in JSON_FIELDS),
                        now,
                    ),
                ).lastrowid
                alert_id = None
                if row["severity"] != "low":
                    alert_id = conn.execute(
                        "INSERT INTO alerts (event_id, created_at) VALUES (?, ?)", (event_id, now)
                    ).lastrowid
                ids.append((event_id, alert_id))
        return ids

    def history(self, users: Iterable[str], start: Any, end: Any) -> pd.DataFrame:
        """Canonical events already stored for ``users`` with ``start <= timestamp <= end``.

        This is the context the scorer needs for trailing-window features, so a
        single event posted on its own is scored with its account's last hour.
        """
        with self._connect() as conn:
            df = pd.read_sql_query(
                "SELECT timestamp, user, account_type, src_host, dst_host, event_type, success, command FROM events"
                " WHERE user IN (SELECT value FROM json_each(?)) AND timestamp BETWEEN ? AND ?"
                " ORDER BY timestamp, id",
                conn,
                params=(json.dumps([str(u) for u in users]), _ts(start), _ts(end)),
            )
        return _canonical(df)

    def list_alerts(
        self, status: str | None = None, severity: str | None = None, user: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Alerts joined with their event and latest feedback label, newest first."""
        where, params = _where(("a.status = ?", status), ("e.severity = ?", severity), ("e.user = ?", user))
        return self._query(f"{ALERT_SQL}{where} ORDER BY a.id DESC LIMIT ?", [*params, limit])

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        """One alert (same shape as :meth:`list_alerts` rows), or ``None`` if it doesn't exist."""
        rows = self._query(f"{ALERT_SQL} WHERE a.id = ?", [alert_id])
        return rows[0] if rows else None

    def add_feedback(self, alert_id: int, label: str, analyst: str, note: str = "") -> bool:
        """Record an analyst verdict and close the alert.

        Returns:
            ``False`` if the alert doesn't exist.

        Raises:
            sqlite3.IntegrityError: if ``label`` is not ``true_positive``/``false_positive``.
        """
        with self._connect() as conn:
            if not conn.execute("UPDATE alerts SET status = 'closed' WHERE id = ?", (alert_id,)).rowcount:
                return False
            conn.execute(
                "INSERT INTO feedback (alert_id, label, analyst, note, created_at) VALUES (?, ?, ?, ?, ?)",
                (alert_id, label, analyst, note, _now()),
            )
        return True

    def list_events(self, user: str | None = None, since: Any = None, limit: int = 1000) -> list[dict[str, Any]]:
        """The most recent ``limit`` scored events matching the filters, returned oldest first."""
        where, params = _where(("e.user = ?", user), ("e.timestamp >= ?", None if since is None else _ts(since)))
        return self._query(
            f"SELECT * FROM (SELECT e.id, {EVENT_COLUMNS} FROM events e{where}"
            " ORDER BY e.timestamp DESC, e.id DESC LIMIT ?) ORDER BY timestamp, id",
            [*params, limit],
        )

    def top_users(self, limit: int = 10) -> list[dict[str, Any]]:
        """Accounts ranked by their highest risk score, then by number of alerts."""
        # Full scan + GROUP BY per call: fine for a demo-sized DB; keep a per-user rollup table past ~1M events.
        return self._query(
            "SELECT e.user, MAX(e.account_type) AS account_type, COUNT(a.id) AS alerts,"
            " MAX(e.risk_score) AS max_risk, AVG(e.risk_score) AS mean_risk"
            " FROM events e LEFT JOIN alerts a ON a.event_id = e.id"
            " GROUP BY e.user ORDER BY max_risk DESC, alerts DESC, e.user LIMIT ?",
            [limit],
        )

    def summary(self) -> dict[str, Any]:
        """Headline counts for the SOC dashboard."""
        with self._connect() as conn:
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            rows = conn.execute(
                "SELECT a.status, e.severity, COUNT(*) FROM alerts a JOIN events e ON e.id = a.event_id GROUP BY 1, 2"
            ).fetchall()
        return {
            "events_scored": events,
            "alerts": sum(n for _, _, n in rows),
            "open_alerts": sum(n for status, _, n in rows if status == "open"),
            "open_by_severity": {sev: n for status, sev, n in rows if status == "open"},
        }

    def export_feedback(self) -> pd.DataFrame:
        """Alerted events that have analyst feedback: canonical columns + ``label`` (the latest verdict)."""
        with self._connect() as conn:
            df = pd.read_sql_query(
                "SELECT e.timestamp, e.user, e.account_type, e.src_host, e.dst_host, e.event_type, e.success,"
                " e.command, f.label FROM feedback f JOIN alerts a ON a.id = f.alert_id JOIN events e ON e.id = a.event_id"
                " WHERE f.id IN (SELECT MAX(id) FROM feedback GROUP BY alert_id) ORDER BY e.timestamp, e.id",
                conn,
            )
        return _canonical(df).assign(label=df["label"])


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: export analyst feedback as a labeled parquet file for retraining."""
    parser = argparse.ArgumentParser(description="PrivGuard alert store utilities.")
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export-feedback", help="write alerted events with analyst labels to parquet")
    export.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    export.add_argument("--out", type=Path, help=f"output parquet (default: <processed_dir>/{FEEDBACK_NAME})")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    out = args.out or cfg.processed_dir / FEEDBACK_NAME
    df = Store(cfg.serving.db_path).export_feedback()
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    log.info(
        "Wrote %d labeled events (%d true positive, %d false positive) from %s to %s",
        len(df), (df.label == "true_positive").sum(), (df.label == "false_positive").sum(), cfg.serving.db_path, out,
    )


if __name__ == "__main__":
    main()
