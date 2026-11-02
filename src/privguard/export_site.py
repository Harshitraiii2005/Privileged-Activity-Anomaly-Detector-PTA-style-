"""Export the demo replay and evaluation metrics as JSON for the static showcase site.

Scores the same scenario ``make demo`` replays with the trained scorer, offline.
Features are causal and the profile is frozen, so this is exactly what the API
returns for those events; the site only ever shows real model output.

Usage:
    python -m privguard.export_site [--config PATH] [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from privguard.config import Config, load_config
from privguard.demo import KILL_CHAIN, build_scenario
from privguard.scorer import Scorer

log = logging.getLogger(__name__)

OUTPUT = Path("site/data/demo.json")


def export(cfg: Config) -> dict:
    """Score the demo scenario and bundle it with ``reports/synthetic/metrics.json``."""
    warmup, scenario = build_scenario(cfg)
    scored = Scorer.load(cfg.model.artifact_path).score(
        scenario.drop(columns=["is_attack", "attack_type"]), history=warmup
    )
    events = [
        {
            "t": ts.isoformat(),
            "user": r.user,
            "account_type": r.account_type,
            "src": r.src_host,
            "dst": r.dst_host,
            "type": r.event_type,
            "success": bool(r.success),
            "command": r.command,
            "risk": round(float(r.risk_score), 1),
            "severity": r.severity,
            "rules": list(r.rules_triggered),
            "reasons": list(r.reasons),
            "explanation": r.explanation,
            "top_features": [
                {"feature": f["feature"], "value": round(f["value"], 3), "contribution": round(f["contribution"], 3)}
                for f in r.top_features
            ],
            "step": label,  # ground truth, shown on the site only; never used to score
        }
        for ts, r, label in zip(scored.timestamp, scored.itertuples(), scenario.attack_type)
    ]
    metrics = json.loads((cfg.model.reports_dir / "synthetic" / "metrics.json").read_text())
    return {"kill_chain": KILL_CHAIN, "events": events, "metrics": metrics}


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: write the site's data file."""
    parser = argparse.ArgumentParser(description="Export demo + metrics JSON for the showcase site.")
    parser.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    parser.add_argument("--out", type=Path, help=f"output JSON (default: <repo>/{OUTPUT})")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    out = args.out or cfg.root / OUTPUT
    data = export(cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, separators=(",", ":")))
    attack = [e for e in data["events"] if e["step"]]
    log.info(
        "Wrote %d events (%d attack, %d attack alerts, %d benign alerts) to %s",
        len(data["events"]), len(attack), sum(e["severity"] != "low" for e in attack),
        sum(e["severity"] != "low" and not e["step"] for e in data["events"]), out,
    )


if __name__ == "__main__":
    main()
