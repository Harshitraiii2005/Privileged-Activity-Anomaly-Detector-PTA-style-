"""Serving scorer: rules + Isolation Forest hybrid with a calibrated 0-100 risk and explanations.

Risk calibration. Each detector's raw score ``s`` (both live in [0, 1]: rules
``1 - prod(1 - w)``, Isolation Forest ``2 ** (-E[h(x)] / c(n))``) is mapped
piecewise-linearly through (0, 0), (threshold, M), (1, 100), where ``M`` is the
``medium`` severity bound, and ``risk = max`` over the two detectors. Hence:

* risk is monotonic in each detector's score;
* an Isolation Forest score exactly at its baseline threshold maps to exactly
  ``M``, so "alert" (severity >= medium) means the same thing for the served
  model, the evaluation and each detector: the hybrid alerts iff the rules or
  the Isolation Forest alert on their own;
* with ``M = 40`` the rules map is the identity, so a rule's weight is its
  risk when it fires alone (PRIV_CMD 0.9 -> 90, critical; LATERAL 0.8 -> high).

The served bundle never imports torch: the autoencoder is evaluation-only.

Usage:
    python -m privguard.scorer [--config PATH] [--data PATH] [--feedback PATH]
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from privguard.config import Config, load_config
from privguard.detectors import IsolationForestDetector, RulesEngine
from privguard.explain import anomaly_contributions, explainer, shap_reasons, top_features
from privguard.features import Profile, build_features
from privguard.schema import load_events, validate
from privguard.synthetic import OUTPUT_NAME

log = logging.getLogger(__name__)

PROFILE_FRACTION = 0.5  # share of the baseline used to fit the profile that featurizes detector training rows
MAX_EXPLANATION_REASONS = 3  # the one-line explanation; `reasons` keeps the full list


def baseline_end(cfg: Config) -> pd.Timestamp:
    """First timestamp after the clean synthetic baseline (start_date + attack_start_day)."""
    return pd.Timestamp(cfg.synthetic.start_date) + pd.Timedelta(days=cfg.synthetic.attack_start_day)


def baseline_features(events: pd.DataFrame) -> pd.DataFrame:
    """Detector training rows: the later part of the baseline, featurized against a profile of the earlier part.

    Featurizing the baseline against a profile fitted on itself makes every host
    "known" and every command "in vocabulary", so new_src_host / new_dst_host /
    cmd_rarity would be constant 0 and an Isolation Forest could never split on
    them. Profiling strictly earlier events mirrors serving, where each event is
    scored against a profile of the past, so detectors learn how much novelty is
    normal (hot-desking, first visit to a server).
    """
    events = validate(events).sort_values("timestamp", kind="stable")
    cut = int(len(events) * PROFILE_FRACTION)
    early, late = events.iloc[:cut], events.iloc[cut:]
    return build_features(late, Profile.fit(early), history=early)


def calibrate(score: np.ndarray, threshold: float, medium: float) -> np.ndarray:
    """Map a [0, 1] detector score to 0-100 risk with ``threshold -> medium`` (see module docstring)."""
    return np.interp(score, [0.0, threshold, 1.0], [0.0, medium, 100.0])


def _labeled(events: pd.DataFrame) -> pd.DataFrame:
    """Fill the optional ground-truth columns so unlabeled (API) events pass schema validation."""
    return events.assign(**{c: v for c, v in (("is_attack", 0), ("attack_type", "")) if c not in events})


class Scorer:
    """Fitted serving bundle: baseline profile, rules, Isolation Forest and severity bands."""

    def __init__(
        self, profile: Profile, rules: RulesEngine, iforest: IsolationForestDetector, severity: dict[str, float]
    ) -> None:
        self.profile, self.rules, self.iforest, self.severity = profile, rules, iforest, severity
        self.explainer = explainer(iforest.model)

    @classmethod
    def fit(cls, train: pd.DataFrame, cfg: Config) -> Scorer:
        """Fit on clean baseline events (no labels used)."""
        train = validate(train)
        iforest = IsolationForestDetector(cfg.model.threshold_quantile, cfg.model.seed, **cfg.model.iforest)
        iforest.fit(baseline_features(train))
        return cls(Profile.fit(train), RulesEngine(), iforest, dict(cfg.serving.severity))

    @classmethod
    def load(cls, path: Path | None = None) -> Scorer:
        """Load a bundle written by :meth:`save` (default ``cfg.model.artifact_path``)."""
        return cls(**joblib.load(path or load_config().model.artifact_path))

    def save(self, path: Path | None = None) -> None:
        """Write the bundle; the SHAP explainer is rebuilt on load rather than pickled."""
        path = Path(path or load_config().model.artifact_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"profile": self.profile, "rules": self.rules, "iforest": self.iforest, "severity": self.severity}, path
        )
        log.info("Saved scorer to %s", path)

    def score(self, events: pd.DataFrame, history: pd.DataFrame | None = None) -> pd.DataFrame:
        """Score canonical events (``is_attack``/``attack_type`` optional).

        Args:
            events: Events to score.
            history: Earlier events used only as context for 1h windows / checkout lookback.

        Returns:
            One row per input event in input order: canonical columns, FEATURES,
            risk_score, severity, is_alert, rules_triggered, reasons, explanation,
            top_features. SHAP (reasons beyond rules, top_features) is computed
            for alerts only, which keeps large batches fast.
        """
        X = build_features(_labeled(events), self.profile, None if history is None else _labeled(history))
        fired = self.rules.triggered(X)
        medium = self.severity["medium"]
        risk = np.maximum(
            calibrate(self.rules.score(X), self.rules.threshold_, medium),
            calibrate(self.iforest.score(X), self.iforest.threshold_, medium),
        )
        bands = sorted(self.severity.items(), key=lambda kv: -kv[1])
        severity = np.select([risk >= bound for _, bound in bands], [name for name, _ in bands], default="low")
        alert = severity != "low"

        rule_ids = [list(fired.columns[m]) for m in fired.to_numpy()]
        reasons = self.rules.reasons(X, fired)
        top: list[list[dict]] = [[] for _ in range(len(X))]
        idx = np.flatnonzero(alert)
        if len(idx):
            for i, contrib in zip(idx, anomaly_contributions(self.explainer, X.iloc[idx])):
                row = X.iloc[i].to_dict()
                covered = {f for rid in rule_ids[i] for f in RulesEngine.BY_ID[rid].covers}
                reasons[i] = reasons[i] + shap_reasons(row, contrib, covered) or [
                    f"Unusual combination of activity for {row['user']} compared with the baseline"
                ]
                top[i] = top_features(row, contrib)
        return X.assign(
            risk_score=risk,
            severity=severity,
            is_alert=alert,
            rules_triggered=rule_ids,
            reasons=reasons,
            explanation=["; ".join(r[:MAX_EXPLANATION_REASONS]) or "No anomaly detected" for r in reasons],
            top_features=top,
        )


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: train the serving bundle on the baseline (+ analyst feedback) and save it."""
    parser = argparse.ArgumentParser(description="Train and save the PrivGuard serving scorer.")
    parser.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    parser.add_argument("--data", type=Path, help=f"events parquet (default: <processed_dir>/{OUTPUT_NAME})")
    parser.add_argument(
        "--feedback", type=Path, help="feedback parquet from `python -m privguard.store export-feedback`"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    data = args.data or cfg.processed_dir / OUTPUT_NAME
    if not data.exists():
        raise FileNotFoundError(f"{data} not found: run `make data` first")
    events = load_events(data)
    train = events[events.timestamp < baseline_end(cfg)]
    if args.feedback:
        feedback = pd.read_parquet(args.feedback)
        confirmed_normal = feedback[feedback.label == "false_positive"].assign(is_attack=0, attack_type="")
        train = pd.concat([train, validate(confirmed_normal)], ignore_index=True)
        log.info("Added %d analyst-confirmed false positives to the baseline", len(confirmed_normal))
    log.info("Training on %d baseline events before %s", len(train), baseline_end(cfg))
    scorer = Scorer.fit(train, cfg)
    scorer.save(cfg.model.artifact_path)


if __name__ == "__main__":
    main()
