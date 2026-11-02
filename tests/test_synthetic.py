from dataclasses import replace

import pandas as pd
import pytest

from privguard.config import load_config
from privguard.schema import COLUMNS
from privguard.synthetic import ATTACK_TYPES, generate


@pytest.fixture(scope="module")
def cfg():
    base = load_config().synthetic
    return replace(base, days=10, n_humans=10, n_admins=3, n_servers=10, attack_start_day=5,
                   attacks=dict.fromkeys(ATTACK_TYPES, 2))


@pytest.fixture(scope="module")
def events(cfg):
    return generate(cfg)


def test_schema_and_order(events):
    assert list(events.columns) == COLUMNS
    assert events.timestamp.is_monotonic_increasing


def test_deterministic_per_seed(cfg, events):
    pd.testing.assert_frame_equal(events, generate(cfg))
    assert not generate(replace(cfg, seed=cfg.seed + 1)).equals(events)


def test_every_attack_labeled_and_after_baseline(cfg, events):
    attacks = events[events.is_attack == 1]
    assert set(attacks.attack_type) == set(ATTACK_TYPES)
    assert (events.loc[events.is_attack == 0, "attack_type"] == "").all()
    baseline_end = pd.Timestamp(cfg.start_date) + pd.Timedelta(days=cfg.attack_start_day)
    assert (attacks.timestamp >= baseline_end).all()


def test_attack_signatures(events):
    a = events[events.is_attack == 1]
    lm = a[a.attack_type == "lateral_movement"]
    assert lm.groupby("user").dst_host.nunique().min() >= 10
    burst = a[a.attack_type == "checkout_burst"]
    assert (burst.event_type == "checkout").all()
    esc = a[(a.attack_type == "privilege_escalation") & (a.event_type == "command")]
    assert esc.command.str.contains(r"/add|sudo su|usermod|sudoers").any()
    assert a[a.attack_type == "off_hours_admin"].timestamp.dt.hour.between(1, 5).all()


def test_rejects_unknown_attack(cfg):
    with pytest.raises(ValueError, match="unknown attack"):
        generate(replace(cfg, attacks={"ransomware": 1}))
