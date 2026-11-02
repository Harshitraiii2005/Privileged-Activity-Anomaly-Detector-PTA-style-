"""Plain-English alert explanations from SHAP values of the Isolation Forest.

SHAP sign convention (verified empirically, asserted in tests/test_explain.py):
``shap.TreeExplainer`` on an sklearn ``IsolationForest`` explains the expected
isolation path length E[h(x)], i.e. ``expected_value + sum(shap) == E[h(x)]``,
and the anomaly score is ``2 ** (-E[h(x)] / c(n))``. A longer path means the
event is harder to isolate, i.e. more normal, so NEGATIVE SHAP values push
toward anomaly. :func:`anomaly_contributions` negates them once; everywhere
downstream a positive contribution means "pushes toward anomaly" (units:
expected path length).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import IsolationForest

from privguard.features import FEATURES

log = logging.getLogger(__name__)

MAX_SHAP_REASONS = 3
MAX_TOP_FEATURES = 5
WHO = {"human": "User", "admin": "Admin", "service": "Service account"}
WHAT = {"logon": "login", "command": "command", "checkout": "vault checkout"}


def explainer(model: IsolationForest) -> shap.TreeExplainer:
    """Exact TreeSHAP explainer for a fitted IsolationForest (cheap to rebuild, so never pickled)."""
    return shap.TreeExplainer(model)


def anomaly_contributions(tree_explainer: shap.TreeExplainer, X: pd.DataFrame) -> np.ndarray:
    """Per-feature contributions toward anomaly, shape (len(X), len(FEATURES)); positive = more anomalous."""
    return -np.asarray(tree_explainer.shap_values(X[FEATURES]))


def _subject(r: dict) -> str:
    """'Admin login at 03:12'."""
    what = WHAT[r["event_type"]] if r["success"] else "failed login"
    return f"{WHO[r['account_type']]} {what} at {r['timestamp']:%H:%M}"


def _off_hours(r: dict) -> str:
    day = f" on a {r['timestamp']:%A}" if r["timestamp"].day_of_week >= 5 else ""
    return f"{_subject(r)}{day}, outside business hours"


def _hour_rarity(r: dict) -> str:
    how = "never" if r["hour_rarity"] >= 0.99 else "rarely" if r["hour_rarity"] >= 0.75 else "not usually"
    return f"{_subject(r)}, an hour when {r['user']} is {how} active"


def _account(r: dict) -> str:
    return f"Unusual behaviour for a{'n' if r['account_type'] == 'admin' else ''} {r['account_type']} account"


def _event(r: dict) -> str:
    return f"Unusual {WHAT[r['event_type']]} activity for {r['user']}"


# One template per feature, describing the feature's value in the event's own context.
TEMPLATES: dict[str, Callable[[dict], str]] = {
    "off_hours": _off_hours,
    "hour_rarity": _hour_rarity,
    "new_src_host": lambda r: f"{_subject(r)} from a host never seen before for {r['user']} ({r['src_host']})",
    "new_dst_host": lambda r: f"First access by {r['user']} to {r['dst_host']}",
    "distinct_dst_1h": lambda r: f"{r['distinct_dst_1h']:.0f} distinct hosts accessed by {r['user']} in the last hour",
    "events_1h": lambda r: f"{r['events_1h']:.0f} events by {r['user']} in the last hour",
    "fail_ratio_1h": lambda r: f"{r['fail_ratio_1h']:.0%} of {r['user']}'s logins failed in the last hour",
    "failed_1h": lambda r: f"{r['failed_1h']:.0f} failed logins by {r['user']} in the last hour",
    "checkouts_1h": lambda r: f"{r['checkouts_1h']:.0f} vault password checkouts by {r['user']} in the last hour",
    "cmd_rarity": lambda r: f"Command on {r['dst_host']} with tokens never seen in the baseline: `{r['command']}`",
    "no_checkout": lambda r: f"No vault checkout before this admin login to {r['dst_host']}",
    "failed": lambda r: f"Failed login to {r['dst_host']} from {r['src_host']}",
    "acct_human": _account,
    "acct_admin": _account,
    "acct_service": _account,
    "is_logon": _event,
    "is_command": _event,
    "is_checkout": _event,
}


def shap_reasons(row: dict, contrib: np.ndarray, covered: set[str]) -> list[str]:
    """Up to :data:`MAX_SHAP_REASONS` reasons for features pushing toward anomaly.

    Skips features a fired rule already explains (``covered``) and features at
    0, whose anomaly contribution describes an absence that has no useful
    plain-English reading.
    """
    out: list[str] = []
    for j in np.argsort(-contrib):
        feature = FEATURES[j]
        if contrib[j] <= 0 or len(out) == MAX_SHAP_REASONS:
            break
        if feature in covered or not row[feature]:
            continue
        text = TEMPLATES[feature](row)
        if text not in out:
            out.append(text)
    return out


def top_features(row: dict, contrib: np.ndarray) -> list[dict]:
    """Top features by contribution toward anomaly (positive only), most anomalous first."""
    order = [j for j in np.argsort(-contrib)[:MAX_TOP_FEATURES] if contrib[j] > 0]
    return [
        {"feature": FEATURES[j], "value": float(row[FEATURES[j]]), "contribution": round(float(contrib[j]), 4)}
        for j in order
    ]


def summary_plot(tree_explainer: shap.TreeExplainer, X: pd.DataFrame, path: Path, max_rows: int = 2000) -> None:
    """Global beeswarm of anomaly contributions over (a sample of) ``X``, saved as a PNG."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sample = X[FEATURES].sample(min(len(X), max_rows), random_state=0)
    shap.summary_plot(anomaly_contributions(tree_explainer, sample), sample, show=False, max_display=len(FEATURES))
    plt.xlabel("Contribution toward anomaly (negated SHAP, isolation path-length units)")
    plt.title("Isolation Forest: what drives anomaly scores")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close("all")
    log.info("Wrote %s", path)
