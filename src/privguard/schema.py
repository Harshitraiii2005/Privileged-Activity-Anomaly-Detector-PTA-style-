"""Canonical event schema shared by every data source.

Both the synthetic generator and the LANL loader emit exactly these columns,
so feature engineering, models and the API never care where data came from.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

ACCOUNT_TYPES = ("human", "admin", "service")
EVENT_TYPES = ("logon", "command", "checkout")

COLUMNS = [
    "timestamp",     # event time (naive UTC)
    "user",          # account performing the action
    "account_type",  # one of ACCOUNT_TYPES
    "src_host",      # where the action originates
    "dst_host",      # target host (for checkout: host whose credential was retrieved)
    "event_type",    # one of EVENT_TYPES
    "success",       # authentication outcome; always True for command/checkout
    "command",       # command line for event_type == "command", else ""
    "is_attack",     # ground-truth label (0/1)
    "attack_type",   # attack scenario name, "" for benign
]


def validate(df: pd.DataFrame) -> pd.DataFrame:
    """Return ``df`` restricted to the canonical columns with canonical dtypes.

    Raises:
        ValueError: if a column is missing or a categorical field has an
            unknown value.
    """
    missing = set(COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"missing columns: {sorted(missing)}")
    out = df[COLUMNS].copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"])
    out["success"] = out["success"].astype(bool)
    out["is_attack"] = out["is_attack"].astype("int8")
    out["command"] = out["command"].fillna("").astype(str)
    out["attack_type"] = out["attack_type"].fillna("").astype(str)
    for col, allowed in (("account_type", ACCOUNT_TYPES), ("event_type", EVENT_TYPES)):
        bad = set(out[col].unique()) - set(allowed)
        if bad:
            raise ValueError(f"unknown {col} values: {sorted(bad)}")
    return out


def load_events(path: str | Path) -> pd.DataFrame:
    """Read a canonical events parquet file and validate it."""
    return validate(pd.read_parquet(path))
