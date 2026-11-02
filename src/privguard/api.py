"""FastAPI scoring service: score privileged events, persist them, and serve the alert queue.

``POST /score`` enriches each event with its account's recent history from the
store (so trailing 1-hour features are correct even when events arrive one at a
time), scores it with the trained :class:`~privguard.scorer.Scorer`, stores the
result and opens an alert for anything above "low". The remaining endpoints
are the read/triage side used by the SOC dashboard.

The model is optional at startup: without a trained artifact the API still
serves alerts and feedback, and ``/score`` answers 503.

Usage:
    uvicorn privguard.api:app --port 8000
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import pandas as pd
from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import AfterValidator, BaseModel, Field, StringConstraints

from privguard import __version__
from privguard.config import load_config
from privguard.features import WINDOW
from privguard.store import Store

log = logging.getLogger(__name__)


def _naive_utc(ts: datetime) -> datetime:
    """Canonical timestamps are naive UTC; convert timezone-aware input."""
    return ts.astimezone(UTC).replace(tzinfo=None) if ts.tzinfo else ts


Timestamp = Annotated[datetime, AfterValidator(_naive_utc)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Severity = Literal["low", "medium", "high", "critical"]
Label = Literal["true_positive", "false_positive"]


class EventIn(BaseModel):
    """One raw privileged-activity event (canonical schema without ground-truth labels)."""

    timestamp: Timestamp
    user: Name
    account_type: Literal["human", "admin", "service"]
    src_host: Name
    dst_host: Name
    event_type: Literal["logon", "command", "checkout"]
    success: bool = True
    command: Annotated[str, StringConstraints(max_length=4096)] = ""


class ScoreRequest(BaseModel):
    """A batch of events to score."""

    events: list[EventIn] = Field(min_length=1, max_length=10_000)


class TopFeature(BaseModel):
    """One SHAP attribution: how much a feature pushed the anomaly score up (+) or down (-)."""

    feature: str
    value: float
    contribution: float


class ScoreOut(BaseModel):
    """Scoring result for one event, in request order."""

    event_id: int
    timestamp: datetime
    user: str
    risk_score: float
    severity: Severity
    rules_triggered: list[str]
    reasons: list[str]
    explanation: str
    top_features: list[TopFeature]
    alert_id: int | None


class ScoreResponse(BaseModel):
    """Results for a :class:`ScoreRequest`."""

    results: list[ScoreOut]


class EventOut(BaseModel):
    """A stored, scored event."""

    id: int
    timestamp: datetime
    user: str
    account_type: str
    src_host: str
    dst_host: str
    event_type: str
    command: str
    risk_score: float
    severity: Severity


class AlertOut(EventOut):
    """An alert joined with its event; ``id`` is the alert id."""

    event_id: int
    created_at: datetime
    explanation: str
    reasons: list[str]
    rules_triggered: list[str]
    top_features: list[TopFeature]
    status: Literal["open", "closed"]
    feedback_label: Label | None


class FeedbackIn(BaseModel):
    """An analyst's verdict on an alert."""

    label: Label
    analyst: Name
    note: Annotated[str, StringConstraints(max_length=2000)] = ""


class TopUser(BaseModel):
    """Per-account risk rollup."""

    user: str
    account_type: str
    alerts: int
    max_risk: float
    mean_risk: float


class Summary(BaseModel):
    """Headline counts for the dashboard KPI row."""

    events_scored: int
    alerts: int
    open_alerts: int
    open_by_severity: dict[str, int]


class Health(BaseModel):
    """Liveness and whether ``/score`` is available."""

    status: str
    model_loaded: bool


def load_scorer() -> Any | None:
    """Load the trained scorer, or ``None`` if it isn't trained or its dependencies are missing."""
    try:
        from privguard.scorer import Scorer  # lazy: the triage endpoints work without the ML stack

        return Scorer.load()
    except (ImportError, FileNotFoundError) as exc:
        log.warning("Model not loaded (%s); /score returns 503 until you run `make train`", exc)
        return None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open the store and load the model once per process."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    app.state.store = Store(cfg.serving.db_path)
    app.state.scorer = load_scorer()
    log.info("PrivGuard API ready: db=%s model_loaded=%s", cfg.serving.db_path, app.state.scorer is not None)
    yield


# Tests replace app.state.store / app.state.scorer with a temp DB and a fake scorer.
app = FastAPI(title="PrivGuard", version=__version__, lifespan=lifespan,
              description="Privileged-activity anomaly scoring and alert triage (PTA-style).")


@app.get("/health", response_model=Health)
def health(request: Request) -> dict[str, Any]:
    """Liveness probe; ``model_loaded`` says whether ``/score`` will work."""
    return {"status": "ok", "model_loaded": request.app.state.scorer is not None}


@app.post("/score", response_model=ScoreResponse)
def score(body: ScoreRequest, request: Request) -> dict[str, Any]:
    """Score events, persist them and open an alert for every event above "low" severity."""
    scorer, store = request.app.state.scorer, request.app.state.store
    if scorer is None:
        raise HTTPException(503, "model not trained: run `make train`")
    events = pd.DataFrame([e.model_dump() for e in body.events]).assign(is_attack=0, attack_type="")
    # Trailing-window features need each account's previous hour, which earlier requests already stored.
    history = store.history(events.user.unique(), events.timestamp.min() - WINDOW, events.timestamp.max())
    scored = scorer.score(events, history)
    ids = store.insert_scored(scored)
    n_alerts = sum(alert_id is not None for _, alert_id in ids)
    log.info("Scored %d events (%d history rows): %d alerts", len(events), len(history), n_alerts)
    rows = scored.to_dict("records")
    return {"results": [{**row, "event_id": e, "alert_id": a} for row, (e, a) in zip(rows, ids, strict=True)]}


@app.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    request: Request,
    status: Literal["open", "closed"] | None = None,
    severity: Severity | None = None,
    user: str | None = None,
    limit: Annotated[int, Query(ge=1, le=10_000)] = 100,
) -> list[dict[str, Any]]:
    """Alerts, newest first, optionally filtered."""
    return request.app.state.store.list_alerts(status=status, severity=severity, user=user, limit=limit)


@app.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, request: Request) -> dict[str, Any]:
    """One alert with its explanation and feedback status."""
    alert = request.app.state.store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, f"alert {alert_id} not found")
    return alert


@app.post("/alerts/{alert_id}/feedback", response_model=AlertOut)
def add_feedback(alert_id: int, body: FeedbackIn, request: Request) -> dict[str, Any]:
    """Record an analyst verdict (closes the alert); returns the updated alert."""
    store = request.app.state.store
    if not store.add_feedback(alert_id, body.label, body.analyst, body.note):
        raise HTTPException(404, f"alert {alert_id} not found")
    log.info("Alert %d marked %s by %s", alert_id, body.label, body.analyst)
    return store.get_alert(alert_id)


@app.get("/events", response_model=list[EventOut])
def list_events(
    request: Request,
    user: str | None = None,
    since: Timestamp | None = None,
    limit: Annotated[int, Query(ge=1, le=10_000)] = 1000,
) -> list[dict[str, Any]]:
    """The most recent scored events (oldest first), e.g. for a per-user risk timeline."""
    return request.app.state.store.list_events(user=user, since=since, limit=limit)


@app.get("/stats/top-users", response_model=list[TopUser])
def top_users(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 10) -> list[dict[str, Any]]:
    """Riskiest accounts by peak risk score, then alert count."""
    return request.app.state.store.top_users(limit)


@app.get("/stats/summary", response_model=Summary)
def summary(request: Request) -> dict[str, Any]:
    """Event and alert counts for the dashboard KPI row."""
    return request.app.state.store.summary()
