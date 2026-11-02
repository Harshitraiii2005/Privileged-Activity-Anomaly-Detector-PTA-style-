"""Typed project configuration loaded from ``config.toml``.

The TOML file is the single source of truth for every tunable value; the
dataclasses below only give it types. Set ``PRIVGUARD_CONFIG`` to use a
different file (e.g. inside Docker).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config.toml"


@dataclass(frozen=True)
class SyntheticConfig:
    """Parameters for the simulated company and injected attacks."""

    seed: int
    start_date: str
    days: int
    n_humans: int
    n_admins: int
    n_service: int
    n_servers: int
    attack_start_day: int
    attacks: dict[str, int]


@dataclass(frozen=True)
class LanlConfig:
    """Parameters for sampling the LANL auth/redteam files."""

    auth_file: Path
    redteam_file: Path
    start_time: int
    end_time: int
    user_sample_rate: float
    chunksize: int


@dataclass(frozen=True)
class ModelConfig:
    """Training, evaluation and artifact settings."""

    artifact_path: Path
    reports_dir: Path
    threshold_quantile: float
    seed: int
    iforest: dict
    autoencoder: dict


@dataclass(frozen=True)
class ServingConfig:
    """API / dashboard settings."""

    db_path: Path
    api_url: str
    severity: dict[str, int]


@dataclass(frozen=True)
class Config:
    """Top-level configuration."""

    root: Path
    processed_dir: Path
    synthetic: SyntheticConfig
    lanl: LanlConfig
    model: ModelConfig
    serving: ServingConfig


def load_config(path: str | Path | None = None) -> Config:
    """Load and type the configuration file.

    Args:
        path: Explicit config path. Falls back to ``$PRIVGUARD_CONFIG``, then
            the repository's ``config.toml``.

    Returns:
        The parsed configuration with all paths made absolute.
    """
    path = Path(path or os.environ.get("PRIVGUARD_CONFIG", DEFAULT_CONFIG)).resolve()
    raw = tomllib.loads(path.read_text())
    root = path.parent
    lanl, model, serving = raw["lanl"], raw["model"], raw["serving"]
    return Config(
        root=root,
        processed_dir=root / raw["paths"]["processed_dir"],
        synthetic=SyntheticConfig(**raw["synthetic"]),
        lanl=LanlConfig(
            **{**lanl, "auth_file": root / lanl["auth_file"], "redteam_file": root / lanl["redteam_file"]}
        ),
        model=ModelConfig(
            **{**model, "artifact_path": root / model["artifact_path"], "reports_dir": root / model["reports_dir"]}
        ),
        serving=ServingConfig(
            db_path=root / os.environ.get("PRIVGUARD_DB_PATH", serving["db_path"]),
            api_url=os.environ.get("PRIVGUARD_API_URL", serving["api_url"]),
            severity=serving["severity"],
        ),
    )
