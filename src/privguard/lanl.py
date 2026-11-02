"""Stream a manageable, labeled sample out of the LANL auth dataset.

``auth.txt.gz`` is ~7.2 GB compressed, so it is read in chunks and filtered on
the fly by (1) a time window and (2) a deterministic user sample. Every
red-team user is always kept so the sample still contains the attacks.
Red-team rows are joined back onto auth events to produce ``is_attack``.

Usage:
    python -m privguard.lanl [--config PATH] [--out PATH]
"""

from __future__ import annotations

import argparse
import logging
import zlib
from pathlib import Path

import numpy as np
import pandas as pd

from privguard.config import LanlConfig, load_config
from privguard.schema import validate

log = logging.getLogger(__name__)

OUTPUT_NAME = "lanl_events.parquet"
AUTH_COLUMNS = [
    "time", "src_user", "dst_user", "src_host", "dst_host",
    "auth_type", "logon_type", "orientation", "outcome",
]
REDTEAM_COLUMNS = ["time", "src_user", "src_host", "dst_host"]
JOIN_KEYS = REDTEAM_COLUMNS
# LANL has no role data: U<digits>@ accounts are people, everything else
# (C123$ machine accounts, SYSTEM, ANONYMOUS LOGON, ...) is treated as service.
HUMAN_PATTERN = r"^U\d+@"


def load_redteam(path: Path) -> pd.DataFrame:
    """Read ``redteam.txt[.gz]`` (time,user@domain,source computer,destination computer)."""
    return pd.read_csv(path, header=None, names=REDTEAM_COLUMNS, dtype={"time": "int64"})


def _user_mask(users: pd.Series, rate: float, always: set[str]) -> pd.Series:
    """Deterministic per-user sample: keep a user iff crc32(user) falls under ``rate``.

    Hash-based so it is stable across runs and chunks without a pre-pass over
    the whole file to enumerate users.
    """
    keep = {
        u for u in users.unique()
        if u in always or zlib.crc32(u.encode()) % 10_000 < rate * 10_000
    }
    return users.isin(keep)


def sample_auth(cfg: LanlConfig, redteam: pd.DataFrame) -> pd.DataFrame:
    """Stream ``auth`` rows in the time window for sampled users, dropping LogOff rows."""
    always = set(redteam.src_user)
    reader = pd.read_csv(
        cfg.auth_file, header=None, names=AUTH_COLUMNS, dtype={"time": "int64"}, chunksize=cfg.chunksize
    )
    parts, scanned, kept = [], 0, 0
    for chunk in reader:
        if chunk.time.iat[0] > cfg.end_time:  # file is time-ordered
            break
        scanned += len(chunk)
        chunk = chunk[chunk.time.between(cfg.start_time, cfg.end_time) & (chunk.orientation != "LogOff")]
        parts.append(chunk[_user_mask(chunk.src_user, cfg.user_sample_rate, always)])
        kept += len(parts[-1])
        log.info("scanned %d rows, kept %d", scanned, kept)
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=AUTH_COLUMNS)


def to_events(auth: pd.DataFrame, redteam: pd.DataFrame) -> pd.DataFrame:
    """Label auth rows against red-team ground truth and map to the canonical schema."""
    labels = redteam.drop_duplicates().assign(is_attack=1)
    df = auth.merge(labels, on=JOIN_KEYS, how="left")
    is_attack = df.is_attack.fillna(0).astype("int8")
    return validate(pd.DataFrame({
        # LANL time is seconds since an undisclosed start; hour-of-day is relative to it.
        "timestamp": pd.to_datetime(df.time, unit="s"),
        "user": df.src_user,
        "account_type": np.where(df.src_user.str.match(HUMAN_PATTERN), "human", "service"),
        "src_host": df.src_host,
        "dst_host": df.dst_host,
        "event_type": "logon",
        "success": df.outcome.eq("Success"),
        "command": "",
        "is_attack": is_attack,
        "attack_type": np.where(is_attack == 1, "redteam", ""),
    }))


def build_sample(cfg: LanlConfig) -> pd.DataFrame:
    """Load red-team labels, stream the auth sample, and return canonical labeled events."""
    for f in (cfg.auth_file, cfg.redteam_file):
        if not f.exists():
            raise FileNotFoundError(f"{f} not found - see README 'Data > LANL' for download steps")
    redteam = load_redteam(cfg.redteam_file)
    events = to_events(sample_auth(cfg, redteam), redteam)
    in_window = redteam[redteam.time.between(cfg.start_time, cfg.end_time)]
    matched = events[events.is_attack == 1]
    log.info(
        "Red-team records in window: %d; auth events labeled attack: %d (%d distinct users)",
        len(in_window), len(matched), matched.user.nunique(),
    )
    return events


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: build the LANL sample and write it to parquet."""
    parser = argparse.ArgumentParser(description="Build a labeled LANL auth sample.")
    parser.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    parser.add_argument("--out", type=Path, help=f"output parquet (default: <processed_dir>/{OUTPUT_NAME})")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    out = args.out or cfg.processed_dir / OUTPUT_NAME
    df = build_sample(cfg.lanl)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    log.info("Wrote %d events (%d attack) for %d users to %s", len(df), df.is_attack.sum(), df.user.nunique(), out)


if __name__ == "__main__":
    main()
