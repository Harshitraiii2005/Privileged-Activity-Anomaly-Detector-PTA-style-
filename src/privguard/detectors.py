"""Anomaly detectors over :data:`privguard.features.FEATURES`.

Three detectors share one duck-typed interface (no base class):

* ``fit(X) -> self`` on baseline feature rows,
* ``score(X) -> np.ndarray``, higher = more anomalous,
* ``threshold_``: an event alerts when ``score >= threshold_``.

:class:`RulesEngine` is the PTA-style deterministic layer; the two ML detectors
learn "normal" from the baseline only and set their threshold label-free, as a
quantile of their own baseline scores (0.99 -> ~1% baseline false-positive rate).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import ClassVar

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from privguard.features import FEATURES

log = logging.getLogger(__name__)

# Commands that create accounts, grant admin/root, or open a root shell. Anchored on the
# privilege-changing verb (/add, useradd, sudoers ...) so read-only look-alikes such as
# "net user jdoe /domain", "net localgroup administrators" and "sudo systemctl ..." don't match.
PRIV_CMD = re.compile(
    r"""\bnet\s+(?:user|localgroup|group)\b.*\s/add\b      # create user / add to a group
      | \b(?:add-localgroupmember|add-adgroupmember|new-localuser|new-aduser)\b
      | \bsudo\s+(?:su|-i|-s)\b                          # interactive root shell
      | \b(?:useradd|adduser|visudo)\b
      | \busermod\b.*\b(?:sudo|wheel|root)\b              # add to sudo/wheel group
      | /etc/sudoers""",
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class Rule:
    """One deterministic detection."""

    id: str
    weight: float  # confidence in (0, 1]; also the rule's risk when it fires alone
    covers: tuple[str, ...]  # features this rule already explains (SHAP reasons for them are skipped)
    reason: str  # str.format template over a featurized event row


class RulesEngine:
    """PTA-style rules written the way a PAM admin would, not fitted to labels.

    Score = 1 - prod(1 - weight) over the rules that fire, i.e. independent
    pieces of evidence combine like probabilities. One rule with weight >= 0.4,
    or two weak ones together, reaches the alert threshold; weak rules on their
    own are context for the analyst, not alerts.
    """

    LATERAL_HOSTS = 10  # distinct destinations in 1h: more than any admin touches by hand
    VAULT_BURST = 5  # password checkouts in 1h
    RARE_HOUR = 0.9  # hour_rarity: the account (almost) never works at this hour
    FAILED_LOGONS = 5  # failed logons in 1h: well past a mistyped password
    threshold_ = 0.4

    RULES: ClassVar[tuple[Rule, ...]] = (
        Rule("PRIV_CMD", 0.9, ("cmd_rarity", "is_command"),
             "Privilege-escalation command on {dst_host}: `{command}`"),
        Rule("LATERAL", 0.8, ("distinct_dst_1h", "events_1h"),
             "{user} targeted {distinct_dst_1h:.0f} distinct hosts within an hour (possible lateral movement)"),
        Rule("VAULT_BURST", 0.7, ("checkouts_1h", "events_1h", "is_checkout"),
             "{user} checked out {checkouts_1h:.0f} privileged passwords from the vault within an hour"),
        Rule("OFF_HOURS_PRIV", 0.5, ("off_hours", "hour_rarity", "acct_admin"),
             "Admin activity at {timestamp:%H:%M}, outside business hours and at an hour {user} is rarely active"),
        Rule("FAILED_BURST", 0.5, ("failed_1h", "fail_ratio_1h", "failed"),
             "{failed_1h:.0f} failed logins by {user} within the last hour ({fail_ratio_1h:.0%} of attempts)"),
        Rule("UNMANAGED_ACCESS", 0.3, ("no_checkout",),
             "Admin login to {dst_host} without a vault password checkout (unmanaged privileged access)"),
        Rule("NEW_SOURCE", 0.3, ("new_src_host",),
             "Activity from a host never seen before for {user} ({src_host})"),
    )  # ordered by weight: reasons are listed most important first
    BY_ID: ClassVar[dict[str, Rule]] = {r.id: r for r in RULES}

    def fit(self, X: pd.DataFrame) -> RulesEngine:
        """No-op: rules are fixed policy, nothing is learned."""
        return self

    def triggered(self, X: pd.DataFrame) -> pd.DataFrame:
        """Boolean frame (events x rule ids) of which rules fire for each event."""
        admin = X.acct_admin == 1
        fired = {
            "PRIV_CMD": (X.is_command == 1) & X.command.str.contains(PRIV_CMD),
            "LATERAL": X.distinct_dst_1h >= self.LATERAL_HOSTS,
            "VAULT_BURST": X.checkouts_1h >= self.VAULT_BURST,
            "OFF_HOURS_PRIV": admin & (X.off_hours == 1) & (X.hour_rarity >= self.RARE_HOUR),
            "FAILED_BURST": X.failed_1h >= self.FAILED_LOGONS,
            "UNMANAGED_ACCESS": X.no_checkout == 1,
            "NEW_SOURCE": (X.new_src_host == 1) & (X.acct_service == 0),
        }
        return pd.DataFrame(fired, index=X.index)[[r.id for r in self.RULES]]

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """1 - prod(1 - w) over fired rules; 0 when nothing fires."""
        weights = np.array([r.weight for r in self.RULES])
        return 1.0 - np.prod(np.where(self.triggered(X).to_numpy(), 1.0 - weights, 1.0), axis=1)

    def reasons(self, X: pd.DataFrame, fired: pd.DataFrame) -> list[list[str]]:
        """Plain-English reason for every fired rule, per event, highest weight first."""
        out: list[list[str]] = [[] for _ in range(len(X))]
        for i in np.flatnonzero(fired.to_numpy().any(axis=1)):
            row = X.iloc[i].to_dict()
            out[i] = [self.BY_ID[rid].reason.format(**row) for rid in fired.columns[fired.iloc[i].to_numpy()]]
        return out


class IsolationForestDetector:
    """sklearn IsolationForest; score = -score_samples in (0, 1], ~0.5 is ordinary, 1 is isolated at once."""

    def __init__(self, quantile: float = 0.99, seed: int = 0, **params) -> None:
        self.quantile, self.seed, self.params = quantile, seed, params

    def fit(self, X: pd.DataFrame) -> IsolationForestDetector:
        """Fit on baseline rows; threshold = ``quantile`` of the baseline's own scores."""
        self.model = IsolationForest(random_state=self.seed, **self.params).fit(X[FEATURES])
        self.threshold_ = float(np.quantile(self.score(X), self.quantile))
        log.info("IsolationForest fitted on %d rows, threshold %.4f", len(X), self.threshold_)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Anomaly score, higher = more anomalous."""
        return -self.model.score_samples(X[FEATURES])


class AutoencoderDetector:
    """PyTorch MLP autoencoder on standardized features; score = per-event reconstruction MSE.

    torch is imported inside the methods so importing this module (e.g. in the
    torch-free serving image) never pulls it in.
    """

    def __init__(
        self,
        quantile: float = 0.99,
        seed: int = 0,
        hidden: int = 8,
        epochs: int = 40,
        lr: float = 1e-3,
        batch_size: int = 256,
    ) -> None:
        self.quantile, self.seed = quantile, seed
        self.hidden, self.epochs, self.lr, self.batch_size = hidden, epochs, lr, batch_size

    def _tensor(self, X: pd.DataFrame):
        import torch

        return torch.tensor(self.scaler_.transform(X[FEATURES].to_numpy()), dtype=torch.float32)

    def fit(self, X: pd.DataFrame) -> AutoencoderDetector:
        """Train d -> 2h -> h -> 2h -> d with Adam on MSE; deterministic for a given seed."""
        import torch
        from torch import nn

        torch.manual_seed(self.seed)
        self.scaler_ = StandardScaler().fit(X[FEATURES].to_numpy())
        x = self._tensor(X)
        d, h = x.shape[1], self.hidden
        self.net_ = nn.Sequential(
            nn.Linear(d, 2 * h), nn.ReLU(), nn.Linear(2 * h, h), nn.ReLU(),
            nn.Linear(h, 2 * h), nn.ReLU(), nn.Linear(2 * h, d),
        )
        opt = torch.optim.Adam(self.net_.parameters(), lr=self.lr)
        gen = torch.Generator().manual_seed(self.seed)
        for _ in range(self.epochs):
            for idx in torch.randperm(len(x), generator=gen).split(self.batch_size):
                opt.zero_grad()
                loss = ((self.net_(x[idx]) - x[idx]) ** 2).mean()
                loss.backward()
                opt.step()
        self.net_.eval()
        self.threshold_ = float(np.quantile(self.score(X), self.quantile))
        log.info("Autoencoder fitted on %d rows (final batch loss %.4f), threshold %.4f",
                 len(X), loss.item(), self.threshold_)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Mean squared reconstruction error per event."""
        import torch

        x = self._tensor(X)
        with torch.no_grad():
            return ((self.net_(x) - x) ** 2).mean(dim=1).numpy()
