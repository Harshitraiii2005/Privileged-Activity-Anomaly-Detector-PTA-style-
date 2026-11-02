"""Synthetic privileged-activity log generator.

Simulates a small company (employees, IT admins, service accounts,
workstations and servers) with realistic daily rhythms, then injects labeled
attacks after a clean baseline period.

Usage:
    python -m privguard.synthetic [--config PATH] [--out PATH]
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import numpy as np
import pandas as pd

from privguard.config import SyntheticConfig, load_config
from privguard.schema import COLUMNS, validate

log = logging.getLogger(__name__)
T = TypeVar("T")

HOUR = 3_600
DAY = 24 * HOUR
OUTPUT_NAME = "synthetic_events.parquet"

ATTACK_TYPES = (
    "off_hours_admin",
    "new_source_host",
    "lateral_movement",
    "checkout_burst",
    "privilege_escalation",
)
SERVER_ROLES = [("DC", "windows"), ("FS", "windows"), ("SQL", "windows"), ("APP", "linux"), ("WEB", "linux")]
SERVICE_NAMES = ["svc_backup", "svc_monitor", "svc_sql", "svc_deploy", "svc_av", "svc_patch"]

# Benign admin commands. Some deliberately share tokens with attack commands
# ("net user", "net localgroup", "sudo") so keyword matching alone can't win.
BENIGN_COMMANDS = {
    "windows": [
        "ipconfig /all",
        "Get-Service",
        "Get-EventLog -LogName System -Newest 50",
        "Restart-Service spooler",
        "dir C:\\Logs",
        "gpupdate /force",
        "tasklist",
        "netstat -ano",
        "net user jdoe /domain",
        "net localgroup administrators",
    ],
    "linux": [
        "df -h",
        "systemctl status nginx",
        "tail -n 100 /var/log/syslog",
        "ps aux",
        "free -m",
        "journalctl -u sshd --since today",
        "uptime",
        "sudo systemctl restart nginx",
        "sudo tail /var/log/auth.log",
    ],
}
ESCALATION_COMMANDS = {
    "windows": [
        "net user {u} P@ssw0rd123! /add",
        "net localgroup administrators {u} /add",
        'net group "Domain Admins" {u} /add /domain',
    ],
    "linux": [
        "sudo su -",
        "useradd -m {u}",
        "usermod -aG sudo {u}",
        "echo '{u} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
    ],
}
BACKDOOR_NAMES = ["svc_update", "helpdesk2", "sysadm"]


@dataclass
class Account:
    """A simulated identity and its normal footprint."""

    name: str
    kind: str  # human | admin | service
    home: str  # own workstation, or source server for service accounts
    targets: list[str]  # servers this account normally touches
    period_h: int = 0  # job interval, service accounts only


class Simulator:
    """Generates benign activity, then injects attacks, into one event list."""

    def __init__(self, cfg: SyntheticConfig) -> None:
        self.cfg = cfg
        self.rng = np.random.default_rng(cfg.seed)
        self.rows: list[tuple] = []

        self.os: dict[str, str] = {}
        for i in range(cfg.n_servers):
            role, os_name = SERVER_ROLES[i % len(SERVER_ROLES)]
            prefix = "SRV" if os_name == "windows" else "LNX"
            self.os[f"{prefix}-{role}{i // len(SERVER_ROLES) + 1:02d}"] = os_name
        self.servers = list(self.os)
        self.workstations = [f"WS-{i:04d}" for i in range(cfg.n_humans + cfg.n_admins)]

        ws = iter(self.workstations)
        self.humans = [
            Account(f"u{i:04d}", "human", next(ws), self._sample(self.servers, 2, 4))
            for i in range(cfg.n_humans)
        ]
        self.admins = [
            Account(f"adm{i:02d}", "admin", next(ws), self._sample(self.servers, 4, 8))
            for i in range(cfg.n_admins)
        ]
        self.services = [
            Account(
                SERVICE_NAMES[i] if i < len(SERVICE_NAMES) else f"svc_{i:02d}",
                "service",
                self._pick(self.servers),
                self._sample(self.servers, 1, 4),
                period_h=int(self._pick([1, 4, 24])),
            )
            for i in range(cfg.n_service)
        ]

    # -- helpers -------------------------------------------------------------

    def _pick(self, seq: Sequence[T]) -> T:
        return seq[self.rng.integers(len(seq))]

    def _sample(self, seq: Sequence[str], lo: int, hi: int) -> list[str]:
        k = min(int(self.rng.integers(lo, hi + 1)), len(seq))
        return [seq[i] for i in self.rng.choice(len(seq), size=k, replace=False)]

    def _emit(
        self,
        t: float,
        acct: Account,
        src: str,
        dst: str,
        event_type: str,
        success: bool = True,
        command: str = "",
        attack: str = "",
    ) -> None:
        self.rows.append(
            (t, acct.name, acct.kind, src, dst, event_type, success, command, int(bool(attack)), attack)
        )

    def _logon(
        self, acct: Account, t: float, src: str, dst: str, attack: str = "", p_fail: float = 0.03
    ) -> float:
        """Emit a logon, sometimes preceded by a mistyped-password failure. Returns end time."""
        if self.rng.random() < p_fail:
            self._emit(t, acct, src, dst, "logon", success=False, attack=attack)
            t += self.rng.uniform(5, 30)
        self._emit(t, acct, src, dst, "logon", attack=attack)
        return t

    def _session(
        self,
        acct: Account,
        t: float,
        dst: str,
        checkout: bool = True,
        commands: list[str] | None = None,
        attack: str = "",
    ) -> float:
        """Privileged session: optional vault checkout, logon, then commands (PSM-style)."""
        if checkout:
            self._emit(t, acct, acct.home, dst, "checkout", attack=attack)
            t += self.rng.uniform(10, 120)
        t = self._logon(acct, t, acct.home, dst, attack=attack)
        if commands is None:
            pool = BENIGN_COMMANDS[self.os[dst]]
            commands = [self._pick(pool) for _ in range(1 + self.rng.poisson(3))]
        for cmd in commands:
            t += self.rng.uniform(5, 300)
            self._emit(t, acct, acct.home, dst, "command", command=cmd, attack=attack)
        return t

    # -- benign behaviour ----------------------------------------------------

    def _human_day(self, acct: Account, day0: float) -> None:
        # ~2% of days the user hot-desks at another workstation: benign "new host" noise.
        src = acct.home if self.rng.random() > 0.02 else self._pick(self.workstations)
        start = day0 + self.rng.normal(8.5, 0.75) * HOUR
        end = start + self.rng.normal(9, 1) * HOUR
        self._logon(acct, start, src, src)
        for t in np.sort(self.rng.uniform(start, end, self.rng.poisson(4))):
            self._logon(acct, t, src, self._pick(acct.targets))

    def _admin_day(self, acct: Account, day0: float, weekend: bool) -> None:
        start = day0 + self.rng.normal(10 if weekend else 8, 1) * HOUR
        hours = max(self.rng.normal(3, 1) if weekend else self.rng.normal(9.5, 1), 0.5)
        self._logon(acct, start, acct.home, acct.home)
        n_sessions = 1 + self.rng.poisson(1 if weekend else 3)
        for t in np.sort(self.rng.uniform(start, start + hours * HOUR, n_sessions)):
            self._session(acct, t, self._pick(acct.targets), checkout=self.rng.random() < 0.9)
        # Legitimate on-call work between 19:00 and 05:00: benign off-hours noise.
        if self.rng.random() < 0.04:
            t = day0 + (self.rng.uniform(19, 29) % 24) * HOUR
            self._session(acct, t, self._pick(acct.targets))

    def _service_jobs(self, acct: Account) -> None:
        # Scheduled jobs run 24/7 from a fixed host, so night activity is normal for services.
        period = acct.period_h * HOUR
        for t in np.arange(self.rng.uniform(0, period), self.cfg.days * DAY, period):
            for dst in acct.targets:
                self._logon(acct, t + self.rng.uniform(0, 120), acct.home, dst, p_fail=0.002)

    def _benign(self) -> None:
        start = pd.Timestamp(self.cfg.start_date)
        for d in range(self.cfg.days):
            weekend = (start + pd.Timedelta(days=d)).weekday() >= 5
            for acct in self.humans:
                if self.rng.random() < (0.05 if weekend else 0.92):
                    self._human_day(acct, d * DAY)
            for acct in self.admins:
                if self.rng.random() < (0.15 if weekend else 0.95):
                    self._admin_day(acct, d * DAY, weekend)
        for acct in self.services:
            self._service_jobs(acct)

    # -- attacks (each isolates one primary signal) -------------------------

    def _attack_time(self, lo_h: float, hi_h: float) -> float:
        day = self.rng.integers(self.cfg.attack_start_day, self.cfg.days)
        return day * DAY + self.rng.uniform(lo_h, hi_h) * HOUR

    def off_hours_admin(self) -> None:
        """Admin credentials used at 01:00-04:30, without a vault checkout."""
        a = self._pick(self.admins)
        self._session(a, self._attack_time(1, 4.5), self._pick(a.targets), checkout=False, attack="off_hours_admin")

    def new_source_host(self) -> None:
        """Valid credentials used from a workstation the account has never used."""
        a = self._pick(self.humans + self.admins)
        src = self._pick([w for w in self.workstations if w != a.home])
        t = self._attack_time(9, 17)
        for _ in range(self.rng.integers(2, 5)):
            t = self._logon(a, t, src, self._pick(a.targets), attack="new_source_host")
            t += self.rng.uniform(60, 1800)

    def lateral_movement(self) -> None:
        """One compromised account fans out to 15-40 hosts within roughly an hour."""
        a = self._pick(self.humans)
        hosts = [h for h in self.servers + self.workstations if h != a.home]
        t = self._attack_time(0, 24)
        for dst in self._sample(hosts, 15, 40):
            t += self.rng.uniform(10, 120)
            self._emit(t, a, a.home, dst, "logon", success=self.rng.random() > 0.3, attack="lateral_movement")

    def checkout_burst(self) -> None:
        """Admin retrieves many privileged passwords from the vault within minutes."""
        a = self._pick(self.admins)
        t = self._attack_time(8, 20)
        for dst in self._sample(self.servers, 10, 25):
            t += self.rng.uniform(5, 40)
            self._emit(t, a, a.home, dst, "checkout", attack="checkout_burst")

    def privilege_escalation(self) -> None:
        """Insider admin, normal hours and host, creates a backdoor account / goes root."""
        a = self._pick(self.admins)
        dst = self._pick(a.targets)
        os_name = self.os[dst]
        backdoor = self._pick(BACKDOOR_NAMES)
        cmds = [self._pick(BENIGN_COMMANDS[os_name])]
        cmds += [c.format(u=backdoor) for c in ESCALATION_COMMANDS[os_name]]
        self._session(a, self._attack_time(9, 17), dst, commands=cmds, attack="privilege_escalation")

    # -- driver --------------------------------------------------------------

    def run(self) -> pd.DataFrame:
        """Generate benign traffic plus configured attacks as a canonical DataFrame."""
        unknown = set(self.cfg.attacks) - set(ATTACK_TYPES)
        if unknown:
            raise ValueError(f"unknown attack types {sorted(unknown)}; choose from {ATTACK_TYPES}")
        if not 0 <= self.cfg.attack_start_day < self.cfg.days:
            raise ValueError("attack_start_day must be within [0, days)")

        self._benign()
        for name, count in self.cfg.attacks.items():
            for _ in range(count):
                getattr(self, name)()

        df = pd.DataFrame(self.rows, columns=COLUMNS)
        df["timestamp"] = (
            pd.Timestamp(self.cfg.start_date) + pd.to_timedelta(df["timestamp"], unit="s")
        ).dt.floor("s")
        return validate(df.sort_values("timestamp", kind="stable").reset_index(drop=True))


def generate(cfg: SyntheticConfig) -> pd.DataFrame:
    """Generate a labeled synthetic event log from ``cfg`` (deterministic per seed)."""
    return Simulator(cfg).run()


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: generate the dataset and write it to parquet."""
    parser = argparse.ArgumentParser(description="Generate the synthetic PrivGuard dataset.")
    parser.add_argument("--config", type=Path, help="config.toml path (default: repo config)")
    parser.add_argument("--out", type=Path, help=f"output parquet (default: <processed_dir>/{OUTPUT_NAME})")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    out = args.out or cfg.processed_dir / OUTPUT_NAME
    df = generate(cfg.synthetic)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    attacks = df[df.is_attack == 1]
    log.info("Wrote %d events (%d attack, %.2f%%) to %s", len(df), len(attacks), 100 * len(attacks) / len(df), out)
    log.info("Events by account type:\n%s", df.account_type.value_counts().to_string())
    log.info("Attack events by type:\n%s", attacks.attack_type.value_counts().to_string())


if __name__ == "__main__":
    main()
