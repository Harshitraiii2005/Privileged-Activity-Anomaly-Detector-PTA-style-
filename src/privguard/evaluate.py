"""Offline evaluation of every detector on a held-out attack period.

Split (labels never enter features or training):

* synthetic: train = events before ``start_date + attack_start_day`` (the clean
  baseline), test = the rest.
* LANL: train = events before the first labeled red-team event, test = the
  rest. The labels only place the boundary, so the baseline is attack-free by
  construction; they are not used to fit anything.

All detectors are fitted on train only; thresholds are label-free. Metrics on
test: event-level precision / recall / F1, PR-AUC (average precision over raw
scores), false-positive rate at the threshold, incident recall (an incident is
one (user, attack_type) group; detected if any of its events alerts) and benign
alerts per day (analyst workload).

Usage:
    python -m privguard.evaluate [--dataset synthetic|lanl] [--config PATH]
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve

from privguard.config import Config, load_config
from privguard.detectors import AutoencoderDetector
from privguard.explain import summary_plot
from privguard.lanl import OUTPUT_NAME as LANL_FILE
from privguard.schema import load_events
from privguard.scorer import Scorer, baseline_end, baseline_features
from privguard.synthetic import OUTPUT_NAME as SYNTHETIC_FILE

log = logging.getLogger(__name__)

DETECTORS = ("Rules", "IsolationForest", "Autoencoder", "Hybrid")
COLORS = dict(zip(DETECTORS, ("#2a78d6", "#eb6834", "#1baf7a", "#eda100")))  # categorical slots 1-4, fixed order
BENIGN, ATTACK = "#2a78d6", "#eb6834"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e5e4e0"


def load_split(dataset: str, cfg: Config) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load a processed dataset and split it into (baseline train, test)."""
    path = cfg.processed_dir / (SYNTHETIC_FILE if dataset == "synthetic" else LANL_FILE)
    if not path.exists():
        hint = "make data" if dataset == "synthetic" else "make lanl (see README, Data > LANL)"
        raise FileNotFoundError(f"{path} not found: run `{hint}` first")
    events = load_events(path)
    if dataset == "synthetic":
        boundary = baseline_end(cfg)
    else:
        attacks = events.timestamp[events.is_attack == 1]
        if attacks.empty:
            raise ValueError(f"no red-team events in {path}; widen [lanl] start_time/end_time")
        boundary = attacks.min()
    return events[events.timestamp < boundary], events[events.timestamp >= boundary]


def detector_metrics(test: pd.DataFrame, score: np.ndarray, alert: np.ndarray) -> dict:
    """Event-, incident- and workload-level metrics for one detector."""
    y = test.is_attack.to_numpy() == 1
    tp, fp = int((alert & y).sum()), int((alert & ~y).sum())
    fn, tn = int((~alert & y).sum()), int((~alert & ~y).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    incidents = pd.Series(alert[y]).groupby([test.user[y].to_numpy(), test.attack_type[y].to_numpy()]).any()
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "pr_auc": float(average_precision_score(y, score)),
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "incident_recall": float(incidents.mean()),
        "incidents_detected": int(incidents.sum()),
        "incidents": len(incidents),
        "benign_alerts_per_day": fp / test.timestamp.dt.normalize().nunique(),
        "alerts": tp + fp,
        "true_positives": tp,
        "false_positives": fp,
    }


def recall_by_attack(test: pd.DataFrame, alerts: dict[str, np.ndarray]) -> dict[str, dict[str, dict]]:
    """{attack_type: {detector: {event_recall, incidents_detected, incidents}}}."""
    out: dict[str, dict[str, dict]] = {}
    for attack, group in test[test.is_attack == 1].groupby("attack_type"):
        out[attack] = {}
        for name, alert in alerts.items():
            hit = pd.Series(alert[group.index.to_numpy()], index=group.index)
            per_incident = hit.groupby(group.user).any()
            out[attack][name] = {
                "event_recall": float(hit.mean()),
                "incidents_detected": int(per_incident.sum()),
                "incidents": len(per_incident),
            }
    return out


def to_markdown(report: dict) -> str:
    """Markdown tables ready to paste into the README."""
    s = report["split"]
    lines = [
        f"# Evaluation: {report['dataset']}",
        "",
        (f"Train (clean baseline): {s['train_events']:,} events before {s['boundary']}. "
        f"Test: {s['test_events']:,} events ({s['test_attack_events']} attack events, "
        f"{s['test_incidents']} incidents) over {s['test_days']} days."),
        ("Thresholds are label-free: Isolation Forest and autoencoder alert above the "
        f"{report['threshold_quantile']:.0%} quantile of their own baseline scores; rules alert at combined "
        f"weight >= {report['thresholds']['Rules']}; the hybrid (served model) alerts at risk >= "
        f"{report['thresholds']['Hybrid']:.0f} (medium)."),
        "",
        "| Detector | Precision | Recall | F1 | PR-AUC | FPR | Incident recall | Benign alerts/day |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for name, m in report["detectors"].items():
        lines.append(
            f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['pr_auc']:.3f} | "
            f"{m['fpr']:.2%} | {m['incident_recall']:.2f} ({m['incidents_detected']}/{m['incidents']}) | "
            f"{m['benign_alerts_per_day']:.1f} |"
        )
    lines += [
        "",
        "Recall by attack type: event recall (incidents detected / incidents).",
        "",
        "| Attack type | " + " | ".join(DETECTORS) + " |",
        "|---|" + "---|" * len(DETECTORS),
    ]
    for attack, per in report["recall_by_attack"].items():
        cells = [f"{v['event_recall']:.2f} ({v['incidents_detected']}/{v['incidents']})" for v in per.values()]
        lines.append(f"| `{attack}` | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def _style(ax) -> None:
    """Recessive axes: no top/right spines, light grid behind the data."""
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def write_plots(out_dir: Path, test: pd.DataFrame, scores: dict, thresholds: dict, report: dict) -> None:
    """pr_curves.png, recall_by_attack.png and score_distributions.png."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    y = test.is_attack.to_numpy() == 1

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    for name, score in scores.items():
        p, r, _ = precision_recall_curve(y, score)
        ax.plot(r, p, color=COLORS[name], linewidth=2, label=f"{name} (AP {report['detectors'][name]['pr_auc']:.2f})")
    ax.axhline(y.mean(), color=MUTED, linewidth=1, linestyle="--", label=f"Chance ({y.mean():.3f})")
    ax.set(xlabel="Recall", ylabel="Precision", xlim=(0, 1), ylim=(0, 1.02))
    ax.set_title(f"Precision-recall on the test period ({report['dataset']})", color=INK, fontsize=11)
    ax.legend(frameon=False, fontsize=9)
    _style(ax)
    fig.tight_layout()
    fig.savefig(out_dir / "pr_curves.png", dpi=120)

    attacks = list(report["recall_by_attack"])
    fig, ax = plt.subplots(figsize=(8, 4.5))
    width = 0.8 / len(DETECTORS)
    for k, name in enumerate(DETECTORS):
        vals = [report["recall_by_attack"][a][name]["event_recall"] for a in attacks]
        x = np.arange(len(attacks)) + (k - 1.5) * width
        ax.bar(x, vals, width, color=COLORS[name], label=name, edgecolor="white", linewidth=2)
        for xi, v in zip(x, vals):
            if v == 0:  # an empty slot would read as missing data
                ax.text(xi, 0.01, "0", ha="center", va="bottom", color=MUTED, fontsize=8)
    ax.set_xticks(np.arange(len(attacks)), [a.replace("_", " ") for a in attacks])
    ax.set(ylabel="Event recall", ylim=(0, 1.05))
    ax.set_title("Recall by attack type", color=INK, fontsize=11)
    ax.legend(frameon=False, fontsize=9, ncols=len(DETECTORS), loc="upper center", bbox_to_anchor=(0.5, -0.1))
    _style(ax)
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(out_dir / "recall_by_attack.png", dpi=120)

    fig, axes = plt.subplots(2, 2, figsize=(9, 6))
    for ax, (name, score) in zip(axes.flat, scores.items()):
        bins = np.linspace(np.min(score), np.max(score), 40)
        ax.hist(score[~y], bins=bins, density=True, histtype="step", linewidth=2, color=BENIGN, label="Benign")
        ax.hist(score[y], bins=bins, density=True, histtype="step", linewidth=2, color=ATTACK, label="Attack")
        ax.axvline(thresholds[name], color=INK, linewidth=1, linestyle="--", label="Alert threshold")
        ax.set_yscale("log")
        ax.set_title(name, color=INK, fontsize=10)
        _style(ax)
    fig.legend(*axes.flat[0].get_legend_handles_labels(), frameon=False, fontsize=9, ncols=3, loc="upper center")
    fig.supxlabel("Detector score (Hybrid: risk 0-100)", color=MUTED, fontsize=9)
    fig.supylabel("Density (log)", color=MUTED, fontsize=9)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(out_dir / "score_distributions.png", dpi=120)
    plt.close("all")


def evaluate(dataset: str, cfg: Config) -> dict:
    """Fit on the baseline, score the test period, write reports/<dataset>/ and return the report dict."""
    train, test = load_split(dataset, cfg)
    test = test.reset_index(drop=True)
    log.info("Train %d events, test %d events (%d attack)", len(train), len(test), test.is_attack.sum())

    scorer = Scorer.fit(train, cfg)
    ae = AutoencoderDetector(cfg.model.threshold_quantile, cfg.model.seed, **cfg.model.autoencoder)
    ae.fit(baseline_features(train))
    scored = scorer.score(test, history=train)

    scores = {
        "Rules": scorer.rules.score(scored),
        "IsolationForest": scorer.iforest.score(scored),
        "Autoencoder": ae.score(scored),
        "Hybrid": scored.risk_score.to_numpy(),
    }
    thresholds = {
        "Rules": scorer.rules.threshold_,
        "IsolationForest": scorer.iforest.threshold_,
        "Autoencoder": ae.threshold_,
        "Hybrid": float(scorer.severity["medium"]),
    }
    alerts = {name: scores[name] >= thresholds[name] for name in DETECTORS}
    report = {
        "dataset": dataset,
        "split": {
            "boundary": str(test.timestamp.min() if dataset == "lanl" else baseline_end(cfg)),
            "train_events": len(train),
            "test_events": len(test),
            "test_attack_events": int(test.is_attack.sum()),
            "test_incidents": int(test[test.is_attack == 1].groupby(["user", "attack_type"]).ngroups),
            "test_days": int(test.timestamp.dt.normalize().nunique()),
        },
        "threshold_quantile": cfg.model.threshold_quantile,
        "thresholds": thresholds,
        "detectors": {name: detector_metrics(test, scores[name], alerts[name]) for name in DETECTORS},
        "recall_by_attack": recall_by_attack(test, alerts),
    }

    out_dir = cfg.model.reports_dir / dataset
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(json.dumps(report, indent=2))
    (out_dir / "metrics.md").write_text(to_markdown(report))
    write_plots(out_dir, test, scores, thresholds, report)
    summary_plot(scorer.explainer, scored, out_dir / "shap_summary.png")
    log.info("Wrote metrics and plots to %s\n%s", out_dir, to_markdown(report))
    return report


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Evaluate PrivGuard detectors on a held-out attack period.")
    parser.add_argument("--dataset", choices=("synthetic", "lanl"), default="synthetic")
    parser.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    evaluate(args.dataset, load_config(args.config))


if __name__ == "__main__":
    main()
