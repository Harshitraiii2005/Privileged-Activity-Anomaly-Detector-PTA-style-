"""Live attack-replay demo against the running scoring API.

Builds a deterministic scenario from the synthetic company: ordinary benign
traffic from one test-period morning, plus a four-step kill chain by a single
compromised admin account (unfamiliar workstation -> vault checkout burst ->
lateral movement -> privilege escalation). The API is warmed up with the
preceding hour so its 1h windows have context, then the scenario is replayed
in accelerated time through ``POST /score`` while alerts stream to the
terminal. Ground-truth labels never leave this process: the API only sees raw
events.

Usage:
    python -m privguard.demo [--api URL] [--speed N] [--config PATH]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from typing import TextIO

import httpx
import numpy as np
import pandas as pd

from privguard.config import Config, load_config
from privguard.features import WINDOW
from privguard.schema import COLUMNS, validate
from privguard.synthetic import BACKDOOR_NAMES, ESCALATION_COMMANDS, Simulator

log = logging.getLogger(__name__)

SCENARIO_START = pd.Timedelta(hours=9, minutes=30)  # replay window on the demo day
SCENARIO_LENGTH = pd.Timedelta(minutes=90)
ATTACK_START = pd.Timedelta(hours=10)
NO_MODEL = "PrivGuard API has no trained model (503). Run `make train`, then restart the API."
PAYLOAD_COLUMNS = ["timestamp", "user", "account_type", "src_host", "dst_host", "event_type", "success", "command"]

# Kill-chain steps, in order, keyed by the synthetic ATTACK_TYPES label they carry.
KILL_CHAIN = {
    "new_source_host": "Initial access: admin credentials used from an unfamiliar workstation",
    "checkout_burst": "Credential harvesting: burst of vault password checkouts",
    "lateral_movement": "Lateral movement: fan-out logons across many hosts",
    "privilege_escalation": "Privilege escalation: backdoor account added to Domain Admins",
}

COLOURS = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[1;93m"}
DIM, BOLD, CYAN, GREEN, RED, RESET = "\033[2m", "\033[1m", "\033[96m", "\033[92m", "\033[91m", "\033[0m"


def build_scenario(cfg: Config) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Build the demo's warm-up and replay events from the synthetic company.

    The demo day is the first weekday of the test period, so none of it was
    seen in training. Benign events come from the same seeded simulation as
    the training data (the dataset's own injected attacks are dropped); the
    kill chain is added on top.

    Returns:
        ``(warmup, scenario)``: canonical, timestamp-sorted frames. ``warmup``
        is the benign hour before the replay window; ``scenario`` is the
        replay window with the labeled kill chain mixed in.
    """
    syn = cfg.synthetic
    sim = Simulator(syn)
    benign = sim.run().query("is_attack == 0")
    split = pd.Timestamp(syn.start_date) + pd.Timedelta(days=syn.attack_start_day)
    day = pd.Timestamp(np.busday_offset(split.date(), 0, roll="forward"))
    start = day + SCENARIO_START

    rng = np.random.default_rng(syn.seed)
    admin = sim.admins[-1]
    ws = sim.humans[0].home  # a phished employee's workstation, never used by this admin
    rows: list[tuple] = []
    t = day + ATTACK_START

    def emit(step: str, dst: str, event_type: str, success: bool = True, command: str = "") -> None:
        rows.append((t, admin.name, admin.kind, ws, dst, event_type, success, command, 1, step))

    for dst in admin.targets[:2]:
        emit("new_source_host", dst, "logon")
        t += pd.Timedelta(seconds=rng.uniform(120, 300))
    for dst in rng.choice(sim.servers, size=12, replace=False):
        emit("checkout_burst", dst, "checkout")
        t += pd.Timedelta(seconds=rng.uniform(10, 40))
    t += pd.Timedelta(minutes=3)
    for dst in rng.choice([h for h in sim.servers + sim.workstations if h not in (ws, admin.home)], 16, replace=False):
        emit("lateral_movement", dst, "logon", success=rng.random() > 0.3)
        t += pd.Timedelta(seconds=rng.uniform(15, 90))
    dc = next(s for s in sim.servers if "-DC" in s)
    emit("privilege_escalation", dc, "logon")
    backdoor = str(rng.choice(BACKDOOR_NAMES))
    for cmd in ESCALATION_COMMANDS[sim.os[dc]]:
        t += pd.Timedelta(seconds=rng.uniform(20, 90))
        emit("privilege_escalation", dc, "command", command=cmd.format(u=backdoor))

    attack = pd.DataFrame(rows, columns=COLUMNS).assign(timestamp=lambda d: d.timestamp.dt.floor("s"))
    window = benign[(benign.timestamp >= start) & (benign.timestamp < start + SCENARIO_LENGTH)]
    warmup = benign[(benign.timestamp >= start - WINDOW) & (benign.timestamp < start)]
    scenario = pd.concat([window, attack]).sort_values("timestamp", kind="stable")
    return validate(warmup.reset_index(drop=True)), validate(scenario.reset_index(drop=True))


def _payload(events: pd.DataFrame) -> list[dict]:
    """Events as POST /score JSON items; ground-truth columns are never sent."""
    out = events[PAYLOAD_COLUMNS].assign(timestamp=events.timestamp.dt.strftime("%Y-%m-%dT%H:%M:%S"))
    return out.to_dict("records")


def _unreachable(client: httpx.Client, exc: Exception) -> SystemExit:
    return SystemExit(f"PrivGuard API not reachable at {client.base_url} ({exc}). Start it with `make api`.")


def check_api(client: httpx.Client) -> None:
    """Fail fast with a readable message if the API is down or has no model."""
    try:
        health = client.get("/health").raise_for_status().json()
    except httpx.HTTPError as exc:
        raise _unreachable(client, exc) from exc
    if not health.get("model_loaded"):
        raise SystemExit(NO_MODEL)


def score(client: httpx.Client, events: pd.DataFrame) -> list[dict]:
    """POST one batch to /score and return its results (same order)."""
    try:
        resp = client.post("/score", json={"events": _payload(events)})
    except httpx.TransportError as exc:
        raise _unreachable(client, exc) from exc
    if resp.status_code == 503:
        raise SystemExit(NO_MODEL)
    if resp.is_error:
        raise SystemExit(f"POST /score failed ({resp.status_code}): {resp.text[:500]}")
    return resp.json()["results"]


class Feed:
    """Terminal output: colour and an in-place status line only on a TTY."""

    def __init__(self, out: TextIO) -> None:
        self.out = out
        self.tty = out.isatty() and "NO_COLOR" not in os.environ

    def c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.tty else text

    def line(self, text: str = "") -> None:
        self.out.write(("\r\033[K" if self.tty else "") + text + "\n")
        self.out.flush()

    def status(self, text: str) -> None:
        if self.tty:
            self.out.write(f"\r\033[K{self.c(DIM, text)}")
            self.out.flush()


def _alert_line(feed: Feed, ev: pd.Series, res: dict, compromised: set[str]) -> None:
    sev = res["severity"]
    if ev.is_attack:
        label = feed.c(RED, f"[attack: {ev.attack_type}]")
    else:
        label = feed.c(DIM, "[benign, on the compromised account]" if ev.user in compromised else "[false alert]")
    route = f"{ev.src_host} -> {ev.dst_host}"
    what = f"{ev.event_type} {ev.command}".strip()
    feed.line(
        f"{ev.timestamp:%H:%M:%S}  {feed.c(COLOURS[sev], f' {sev.upper():8} ')}  risk {res['risk_score']:5.1f}  "
        f"{feed.c(BOLD, ev.user)}  {route}  {what}  {label}"
    )
    feed.line(f"          {res['explanation']}")


def replay(
    client: httpx.Client, warmup: pd.DataFrame, scenario: pd.DataFrame, speed: float, out: TextIO = sys.stdout
) -> dict:
    """Warm up the API, replay ``scenario`` minute by minute and print a live feed.

    Args:
        client: HTTP client with ``base_url`` set to the API.
        warmup: Events sent first, silently, to give the windowed features context.
        scenario: Labeled events to replay (labels stay local).
        speed: Simulated seconds per wall-clock second; 0 replays without pausing.
        out: Stream for the feed.

    Returns:
        Summary counts (also printed).
    """
    feed = Feed(out)
    check_api(client)
    warm = score(client, warmup) if len(warmup) else []
    feed.line(feed.c(DIM, f"warm-up: {len(warmup)} events from the previous hour sent as context "
                          f"({sum(r['severity'] != 'low' for r in warm)} alerted)"))
    feed.line(feed.c(BOLD, f"replaying {scenario.timestamp.min():%Y-%m-%d %H:%M} - {scenario.timestamp.max():%H:%M} "
                           f"at {speed:g}x ({len(scenario)} events)\n"))

    t0, wall0 = scenario.timestamp.min(), time.monotonic()
    compromised = set(scenario.user[scenario.is_attack == 1])
    done = 0
    seen_steps: set[str] = set()
    alerted = np.zeros(len(scenario), dtype=bool)
    risk = np.zeros(len(scenario))
    for minute, batch in scenario.groupby(scenario.timestamp.dt.floor("min"), sort=True):
        if speed:
            time.sleep(max(0.0, wall0 + (minute - t0).total_seconds() / speed - time.monotonic()))
        for step in batch.attack_type[batch.is_attack == 1].unique():
            if step not in seen_steps:
                seen_steps.add(step)
                feed.line(feed.c(CYAN, f">> attacker step {len(seen_steps)}: {KILL_CHAIN.get(step, step)}"))
        for (pos, ev), res in zip(batch.iterrows(), score(client, batch), strict=True):
            alerted[pos], risk[pos] = res["severity"] != "low", res["risk_score"]
            if alerted[pos]:
                _alert_line(feed, ev, res, compromised)
        done += len(batch)
        feed.status(f"{minute:%H:%M}  {done}/{len(scenario)} events scored, {alerted.sum()} alerts")
    return _summary(feed, scenario, alerted, risk, compromised)


def _summary(feed: Feed, scenario: pd.DataFrame, alerted: np.ndarray, risk: np.ndarray, compromised: set[str]) -> dict:
    attack = (scenario.is_attack == 1).to_numpy()
    steps = {}
    feed.line()
    feed.line(feed.c(BOLD, "== Summary =="))
    feed.line(f"attack events: {attack.sum()} sent, {alerted[attack].sum()} alerted")
    for step, title in KILL_CHAIN.items():
        mask = (scenario.attack_type == step).to_numpy()
        if not mask.any():
            continue
        steps[step] = bool(alerted[mask].any())
        mark = feed.c(GREEN, "DETECTED") if steps[step] else feed.c(RED, "MISSED  ")
        feed.line(f"  {mark}  {title}: {alerted[mask].sum()}/{mask.sum()} events alerted, "
                  f"max risk {risk[mask].max():.1f}")
    hits = scenario.timestamp[attack & alerted]
    if len(hits):
        delay = hits.min() - scenario.timestamp[attack].min()
        feed.line(f"first alert {int(delay.total_seconds())} s (simulated) after the first attacker action")
    benign = ~attack
    # The compromised account's own routine work shares its 1h windows with the attacker, so it lights up too.
    own = benign & scenario.user.isin(compromised).to_numpy()
    other = benign & ~own
    feed.line(f"benign events: {benign.sum()} scored, {alerted[benign].sum()} alerted "
              f"({alerted[own].sum()} on the compromised account, "
              f"{alerted[other].sum()} false alerts on {other.sum()} events of other accounts)")
    return {
        "attack_events": int(attack.sum()),
        "attack_alerted": int(alerted[attack].sum()),
        "steps_detected": steps,
        "benign_events": int(benign.sum()),
        "benign_alerted": int(alerted[benign].sum()),
        "false_alerts_other_accounts": int(alerted[other].sum()),
    }


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: build the scenario and replay it against the API."""
    parser = argparse.ArgumentParser(description="Replay a simulated privileged-account attack through the API.")
    parser.add_argument("--api", help="API base URL (default: config serving.api_url / $PRIVGUARD_API_URL)")
    parser.add_argument("--speed", type=float, default=120, help="simulated seconds per real second; 0 = no pauses")
    parser.add_argument("--dashboard", default="http://localhost:8501", help="dashboard URL printed at the end")
    parser.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    args = parser.parse_args(argv)
    # WARNING, not INFO: httpx logs every request at INFO and would drown the feed.
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    warmup, scenario = build_scenario(cfg)
    log.debug("scenario: %d warm-up, %d replay events", len(warmup), len(scenario))
    with httpx.Client(base_url=args.api or cfg.serving.api_url, timeout=60) as client:
        replay(client, warmup, scenario, args.speed)
    print(f"\nInvestigate the alerts in the dashboard: {args.dashboard}")


if __name__ == "__main__":
    main()
