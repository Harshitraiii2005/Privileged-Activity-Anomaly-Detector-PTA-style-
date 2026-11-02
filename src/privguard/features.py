"""Per-event behavioural features against a learned per-account baseline.

Each event gets a feature vector built from two sources of context:

* a :class:`Profile` fitted on clean baseline history (which hosts each
  account normally uses, when it is normally active, which command tokens
  admins normally type), and
* trailing 1-hour windows over the same account's recent events.

The same :func:`build_features` call is used for offline training/evaluation
and for online scoring in the API, so there is no train/serve skew.

Usage:
    python -m privguard.features [--config PATH]   # feature summary for the synthetic dataset
"""

from __future__ import annotations

import argparse
import logging
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from privguard.config import load_config
from privguard.schema import load_events, validate

log = logging.getLogger(__name__)

WINDOW = pd.Timedelta(hours=1)
CHECKOUT_LOOKBACK = pd.Timedelta(minutes=15)
BUSINESS_HOURS = (7, 20)  # [07:00, 20:00) on weekdays

# Model inputs, in a fixed order. Documented with security rationale in README "Features".
FEATURES = [
    "off_hours",
    "hour_rarity",
    "new_src_host",
    "new_dst_host",
    "distinct_dst_1h",
    "events_1h",
    "fail_ratio_1h",
    "failed_1h",
    "checkouts_1h",
    "cmd_rarity",
    "no_checkout",
    "failed",
    "acct_human",
    "acct_admin",
    "acct_service",
    "is_logon",
    "is_command",
    "is_checkout",
]


def tokenize(command: str) -> list[str]:
    """Lower-cased whitespace/quote-separated tokens of a command line."""
    return re.findall(r"[^\s\"']+", command.lower())


@dataclass
class Profile:
    """What "normal" looks like, learned from baseline events."""

    known_src: set[tuple[str, str]]  # (user, src_host) pairs seen in baseline
    known_dst: set[tuple[str, str]]  # (user, dst_host) pairs seen in baseline
    hour_rarity: dict[str, np.ndarray]  # user -> 24 values in [0, 1]; 1 = never active then
    cmd_vocab: set[str]  # command tokens seen in baseline

    @classmethod
    def fit(cls, events: pd.DataFrame) -> Profile:
        """Learn the baseline from (assumed benign) canonical events."""
        hour_rarity = {}
        for user, hours in events.timestamp.dt.hour.groupby(events.user):
            counts = np.bincount(hours, minlength=24).astype(float)
            # Smooth over +-1 hour so 08:59 vs 09:01 doesn't matter, wrapping at midnight.
            near = counts + np.roll(counts, 1) + np.roll(counts, -1)
            hour_rarity[user] = 1.0 - near / near.max()
        cmds = events.loc[events.event_type == "command", "command"]
        return cls(
            known_src=set(zip(events.user, events.src_host)),
            known_dst=set(zip(events.user, events.dst_host)),
            hour_rarity=hour_rarity,
            cmd_vocab={tok for cmd in cmds for tok in tokenize(cmd)},
        )


def _window_stats(df: pd.DataFrame) -> np.ndarray:
    """Trailing-1h per-user stats for a timestamp-sorted frame.

    Returns an (n, 5) array: distinct_dst_1h, events_1h, fail_ratio_1h, failed_1h, checkouts_1h.
    The window is (t - 1h, t] and only includes earlier/same-time events (causal).
    """
    # Python two-pointer loop, O(n): fine to a few million rows; vectorise if the LANL sample grows past that.
    ts = df.timestamp.to_numpy("datetime64[ns]").astype("int64")
    dst = df.dst_host.to_numpy()
    logon = (df.event_type == "logon").to_numpy()
    fail = (logon & ~df.success.to_numpy(bool))
    chk = (df.event_type == "checkout").to_numpy()
    win = WINDOW.value
    out = np.zeros((len(df), 5))
    for idx in df.groupby("user", sort=False).indices.values():
        hosts: Counter[str] = Counter()
        lo = n_logon = n_fail = n_chk = 0
        for k, i in enumerate(idx):
            hosts[dst[i]] += 1
            n_logon += logon[i]
            n_fail += fail[i]
            n_chk += chk[i]
            while ts[idx[lo]] <= ts[i] - win:
                j = idx[lo]
                hosts[dst[j]] -= 1
                if not hosts[dst[j]]:
                    del hosts[dst[j]]
                n_logon -= logon[j]
                n_fail -= fail[j]
                n_chk -= chk[j]
                lo += 1
            out[i] = (len(hosts), k - lo + 1, n_fail / n_logon if n_logon else 0.0, n_fail, n_chk)
    return out


def _no_checkout(df: pd.DataFrame) -> np.ndarray:
    """1 for admin remote logons with no vault checkout of that host in the prior 15 minutes."""
    out = np.zeros(len(df))
    logons = df[(df.event_type == "logon") & (df.account_type == "admin") & (df.src_host != df.dst_host)]
    if logons.empty:
        return out
    checkouts = df.loc[df.event_type == "checkout", ["timestamp", "user", "dst_host"]]
    matched = pd.merge_asof(
        logons[["timestamp", "user", "dst_host"]].reset_index(),
        checkouts.assign(checkout_time=checkouts.timestamp),
        on="timestamp",
        by=["user", "dst_host"],
        tolerance=CHECKOUT_LOOKBACK,
        direction="backward",
    )
    out[matched.loc[matched.checkout_time.isna(), "index"].to_numpy()] = 1.0
    return out


def build_features(
    events: pd.DataFrame, profile: Profile, history: pd.DataFrame | None = None
) -> pd.DataFrame:
    """Compute :data:`FEATURES` for ``events``.

    Args:
        events: Canonical events to featurize.
        profile: Baseline learned with :meth:`Profile.fit`.
        history: Earlier canonical events used only as context for the
            trailing windows and checkout lookback (e.g. the previous hour).
            They are not returned.

    Returns:
        ``events`` in their input order (index reset) with the canonical
        columns plus one column per name in :data:`FEATURES`.
    """
    events = validate(events).assign(_order=np.arange(len(events)))
    frame = events
    if history is not None and len(history):
        frame = pd.concat([validate(history).assign(_order=-1), events], ignore_index=True)
    df = frame.sort_values("timestamp", kind="stable").reset_index(drop=True)

    hour = df.timestamp.dt.hour.to_numpy()
    weekend = df.timestamp.dt.day_of_week.to_numpy() >= 5
    users = df.user.to_numpy()
    rarity = pd.DataFrame.from_dict(profile.hour_rarity, orient="index", columns=range(24))
    rows = rarity.index.get_indexer(users)
    known_rarity = rarity.to_numpy()[rows.clip(0), hour] if len(rarity) else np.ones(len(df))

    df["off_hours"] = ((hour < BUSINESS_HOURS[0]) | (hour >= BUSINESS_HOURS[1]) | weekend).astype(float)
    df["hour_rarity"] = np.where(rows >= 0, known_rarity, 1.0)  # unseen account: everything is rare
    df["new_src_host"] = [float((u, h) not in profile.known_src) for u, h in zip(users, df.src_host)]
    df["new_dst_host"] = [float((u, h) not in profile.known_dst) for u, h in zip(users, df.dst_host)]
    df[["distinct_dst_1h", "events_1h", "fail_ratio_1h", "failed_1h", "checkouts_1h"]] = _window_stats(df)
    df["cmd_rarity"] = [
        float(np.mean([t not in profile.cmd_vocab for t in toks])) if (toks := tokenize(c)) else 0.0
        for c in df.command
    ]
    df["no_checkout"] = _no_checkout(df)
    df["failed"] = (~df.success).astype(float)
    for kind in ("human", "admin", "service"):
        df[f"acct_{kind}"] = (df.account_type == kind).astype(float)
    for kind in ("logon", "command", "checkout"):
        df[f"is_{kind}"] = (df.event_type == kind).astype(float)

    out = df[df._order >= 0].sort_values("_order").drop(columns="_order")
    return out.reset_index(drop=True)


def main(argv: list[str] | None = None) -> None:
    """Fit a profile on the synthetic baseline and print mean features per attack type."""
    parser = argparse.ArgumentParser(description="Summarise features on the synthetic dataset.")
    parser.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    events = load_events(cfg.processed_dir / "synthetic_events.parquet")
    split = pd.Timestamp(cfg.synthetic.start_date) + pd.Timedelta(days=cfg.synthetic.attack_start_day)
    train, test = events[events.timestamp < split], events[events.timestamp >= split]
    feats = build_features(test, Profile.fit(train), history=train)
    behavioural = [f for f in FEATURES if not f.startswith(("acct_", "is_"))]
    summary = feats.assign(group=feats.attack_type.replace("", "benign")).groupby("group")[behavioural].mean()
    log.info("Mean feature value by group (test period):\n%s", summary.round(2).T.to_string())


if __name__ == "__main__":
    main()
