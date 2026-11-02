"""Streamlit SOC dashboard: alert queue, alert triage with explanations, risk timelines.

The dashboard is just another API client: it talks to the PrivGuard API over
HTTP (``serving.api_url`` / ``$PRIVGUARD_API_URL``) and never opens the SQLite
file, so it runs in its own container and sees exactly what the API exposes.

Usage:
    streamlit run src/privguard/dashboard.py [--server.port 8501]
"""

from __future__ import annotations

from typing import Any

import altair as alt
import httpx
import pandas as pd
import streamlit as st

from privguard.config import load_config

TIMEOUT = 10.0
SEVERITIES = ["low", "medium", "high", "critical"]
# Severity is a state, so it uses status colours (always shown next to its text label, never colour alone).
SEVERITY_COLORS = {"low": "#8a8a85", "medium": "#fab219", "high": "#ec835a", "critical": "#d03b3b"}
SEVERITY_BADGE = {"low": "gray", "medium": "yellow", "high": "orange", "critical": "red"}
SEVERITY_SCALE = alt.Scale(domain=SEVERITIES, range=[SEVERITY_COLORS[s] for s in SEVERITIES])
QUEUE_COLUMNS = ["id", "severity", "risk_score", "status", "user", "account_type", "event_type",
                 "src_host", "dst_host", "command", "timestamp", "feedback_label"]


# --- HTTP client (small, pure functions so they can be tested without Streamlit) ---

def api_get(base_url: str, path: str, **params: Any) -> Any:
    """GET ``base_url + path`` and return the JSON body; ``None`` params are dropped.

    Raises:
        httpx.HTTPError: on connection errors and non-2xx responses.
    """
    params = {k: v for k, v in params.items() if v is not None}
    return httpx.get(f"{base_url}{path}", params=params, timeout=TIMEOUT).raise_for_status().json()


def post_feedback(base_url: str, alert_id: int, label: str, analyst: str, note: str = "") -> dict[str, Any]:
    """Submit an analyst verdict for an alert; returns the updated (closed) alert."""
    body = {"label": label, "analyst": analyst, "note": note}
    return httpx.post(f"{base_url}/alerts/{alert_id}/feedback", json=body, timeout=TIMEOUT).raise_for_status().json()


# --- UI sections ---

def _severity_style(severity: str) -> str:
    text = "#0b0b0b" if severity in ("medium", "high") else "#ffffff"
    return f"background-color: {SEVERITY_COLORS.get(severity, '')}; color: {text}"


def live_overview(base_url: str) -> None:
    """KPI row, alert queue and top accounts; re-run on a timer when auto-refresh is on."""
    try:
        summary = api_get(base_url, "/stats/summary")
        alerts = api_get(base_url, "/alerts", limit=1000)
        top = api_get(base_url, "/stats/top-users", limit=10)
    except httpx.HTTPError as exc:
        st.error(f"API request failed: {exc}")
        return

    open_sev = summary["open_by_severity"]
    cols = st.columns(4)
    cols[0].metric("Open alerts", summary["open_alerts"])
    cols[1].metric("Critical (open)", open_sev.get("critical", 0))
    cols[2].metric("High (open)", open_sev.get("high", 0))
    cols[3].metric("Events scored", summary["events_scored"])

    st.subheader("Alert queue")
    if not alerts:
        st.info("No alerts yet. Score some events (e.g. `make demo`) and they will appear here.")
    else:
        df = pd.DataFrame(alerts)
        f1, f2, f3 = st.columns([2, 1, 1])
        sev = f1.multiselect("Severity", SEVERITIES[1:], default=SEVERITIES[1:])
        status = f2.selectbox("Status", ["open", "closed", "all"])
        user = f3.selectbox("User", ["all", *sorted(df.user.unique())])
        df = df[df.severity.isin(sev)]
        if status != "all":
            df = df[df.status == status]
        if user != "all":
            df = df[df.user == user]
        df = df.sort_values(["risk_score", "id"], ascending=False)[QUEUE_COLUMNS]
        st.dataframe(
            df.style.map(_severity_style, subset=["severity"]),
            hide_index=True,
            column_config={"id": "Alert", "risk_score": st.column_config.NumberColumn("Risk", format="%.1f")},
        )

    st.subheader("Top risky accounts")
    if top:
        st.dataframe(
            pd.DataFrame(top),
            hide_index=True,
            column_config={
                "max_risk": st.column_config.ProgressColumn("Max risk", min_value=0, max_value=100, format="%.0f"),
                "mean_risk": st.column_config.ProgressColumn("Mean risk", min_value=0, max_value=100, format="%.1f"),
            },
        )


def shap_chart(top_features: list[dict[str, Any]]) -> alt.Chart:
    """Horizontal bars of SHAP contributions: red pushes the anomaly score up, blue pulls it down."""
    df = pd.DataFrame(top_features)
    df["effect"] = df.contribution.map(lambda c: "raises risk" if c >= 0 else "lowers risk")
    return alt.Chart(df).mark_bar(cornerRadiusEnd=4, height=14).encode(
        x=alt.X("contribution:Q", title="SHAP contribution to anomaly score"),
        y=alt.Y("feature:N", sort="-x", title=None),
        color=alt.Color("effect:N", title=None, legend=alt.Legend(orient="bottom"),
                        scale=alt.Scale(domain=["raises risk", "lowers risk"], range=["#e34948", "#2a78d6"])),
        tooltip=["feature", alt.Tooltip("value:Q", format=".2f"), alt.Tooltip("contribution:Q", format=".3f")],
    )


def alert_detail(base_url: str) -> None:
    """Pick an alert, read why it fired, and record a verdict."""
    st.subheader("Alert detail")
    alerts = api_get(base_url, "/alerts", limit=1000)
    if not alerts:
        st.caption("No alerts to triage.")
        return
    # Most urgent first: open before closed, then highest risk, then newest.
    alerts.sort(key=lambda a: (a["status"] == "closed", -a["risk_score"], -a["id"]))
    by_id = {a["id"]: a for a in alerts}
    alert_id = st.selectbox(
        "Alert", list(by_id),
        format_func=lambda i: f"#{i}  {by_id[i]['severity'].upper()}  risk {by_id[i]['risk_score']:.0f}  "
                              f"{by_id[i]['user']}  ({by_id[i]['status']})",
    )
    a = by_id[alert_id]

    left, right = st.columns([3, 2])
    with left:
        st.badge(f"{a['severity'].upper()} - risk {a['risk_score']:.1f}", color=SEVERITY_BADGE[a["severity"]])
        st.markdown(f"**{a['explanation']}**")
        if a["reasons"]:
            st.markdown("\n".join(f"- {r}" for r in a["reasons"]))
        st.markdown("Rules fired: " + (", ".join(f"`{r}`" for r in a["rules_triggered"]) or "none"))
        st.table(pd.Series({
            "Time (UTC)": a["timestamp"].replace("T", " "),
            "User": a["user"],
            "Account type": a["account_type"],
            "Event": a["event_type"],
            "Source -> target": f"{a['src_host']} -> {a['dst_host']}",
            "Command": a["command"] or "-",
            "Status": a["status"] + (f" ({a['feedback_label']})" if a["feedback_label"] else ""),
        }), hide_header=True)
    with right:
        if a["top_features"]:
            st.altair_chart(shap_chart(a["top_features"]), width="stretch")

    with st.form(f"feedback-{alert_id}"):
        analyst = st.text_input("Analyst", value=st.session_state.get("analyst", ""))
        note = st.text_area("Note", placeholder="What did you check?")
        b1, b2 = st.columns(2)
        true_pos = b1.form_submit_button("True positive", type="primary", width="stretch")
        false_pos = b2.form_submit_button("False positive", width="stretch")
    if true_pos or false_pos:
        if not analyst.strip():
            st.warning("Enter your name as analyst before submitting a verdict.")
            return
        label = "true_positive" if true_pos else "false_positive"
        post_feedback(base_url, alert_id, label, analyst.strip(), note)
        st.session_state.analyst = analyst.strip()
        st.session_state.flash = f"Alert #{alert_id} closed as {label.replace('_', ' ')}."
        st.rerun()


def risk_timeline(base_url: str, bands: dict[str, int]) -> None:
    """Risk score over time for one account, with the severity thresholds drawn as rules."""
    st.subheader("Risk timeline")
    users = [u["user"] for u in api_get(base_url, "/stats/top-users", limit=1000)]
    if not users:
        st.caption("No scored events yet.")
        return
    user = st.selectbox("Account (riskiest first)", users)
    events = pd.DataFrame(api_get(base_url, "/events", user=user, limit=5000))
    events["timestamp"] = pd.to_datetime(events.timestamp)
    x, y = alt.X("timestamp:T", title=None), alt.Y("risk_score:Q", title="Risk score", scale=alt.Scale(domain=[0, 100]))
    line = alt.Chart(events).mark_line(strokeWidth=1, color="#c3c2b7").encode(x=x, y=y)
    points = alt.Chart(events).mark_circle(size=70, opacity=1).encode(
        x=x, y=y, color=alt.Color("severity:N", scale=SEVERITY_SCALE, legend=alt.Legend(orient="bottom")),
        tooltip=[alt.Tooltip("timestamp:T", format="%Y-%m-%d %H:%M:%S"), "event_type", "src_host", "dst_host",
                 "command", alt.Tooltip("risk_score:Q", format=".1f"), "severity"],
    )
    thresholds = pd.DataFrame({"severity": list(bands), "risk_score": list(bands.values())})
    rules = alt.Chart(thresholds).mark_rule(strokeDash=[4, 4]).encode(
        y="risk_score:Q", color=alt.Color("severity:N", scale=SEVERITY_SCALE, legend=None),
        tooltip=["severity", "risk_score"],
    )
    st.altair_chart(line + rules + points, width="stretch")


def main() -> None:
    """Render the dashboard."""
    st.set_page_config(page_title="PrivGuard SOC", layout="wide")
    cfg = load_config()
    base_url = cfg.serving.api_url.rstrip("/")

    st.sidebar.title("PrivGuard SOC")
    st.sidebar.caption(f"API: `{base_url}`")
    auto = st.sidebar.toggle("Auto-refresh", value=True)
    every = st.sidebar.slider("Refresh every (s)", 2, 60, 5, disabled=not auto)

    st.title("Privileged activity alerts")
    try:
        health = api_get(base_url, "/health")
    except httpx.HTTPError as exc:
        st.error(f"PrivGuard API unreachable at {base_url} ({exc}). Start it with "
                 "`uvicorn privguard.api:app --port 8000` or set PRIVGUARD_API_URL.")
        st.stop()
    st.sidebar.caption(f"Model loaded: {'yes' if health['model_loaded'] else 'no (run `make train`)'}")
    if msg := st.session_state.pop("flash", None):
        st.success(msg)

    st.fragment(live_overview, run_every=every if auto else None)(base_url)
    st.divider()
    try:
        alert_detail(base_url)
        st.divider()
        risk_timeline(base_url, cfg.serving.severity)
    except httpx.HTTPError as exc:
        st.error(f"API request failed: {exc}")


if __name__ == "__main__":
    main()
