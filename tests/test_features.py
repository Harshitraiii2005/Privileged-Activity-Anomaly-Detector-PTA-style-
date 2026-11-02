import pandas as pd
import pytest

from privguard.features import FEATURES, Profile, build_features, tokenize


def ev(ts, user="adm01", src="WS-1", dst="SRV-1", event_type="logon", success=True, command="",
       account_type="admin"):
    return {"timestamp": pd.Timestamp(ts), "user": user, "account_type": account_type, "src_host": src,
            "dst_host": dst, "event_type": event_type, "success": success, "command": command,
            "is_attack": 0, "attack_type": ""}


@pytest.fixture
def profile():
    base = [ev(f"2026-01-05 {h:02d}:00") for h in range(9, 18)]  # Monday, office hours
    base.append(ev("2026-01-05 10:00", event_type="command", command="Get-Service"))
    return Profile.fit(pd.DataFrame(base))


def test_profile_hour_rarity(profile):
    r = profile.hour_rarity["adm01"]
    assert r[10] == 0.0 and r[12] < 0.5 and r[3] == 1.0  # peak at 10:00 (two events), never at 03:00


def test_known_vs_new_hosts_and_time(profile):
    f = build_features(pd.DataFrame([
        ev("2026-01-06 10:00"),                              # normal
        ev("2026-01-06 03:00", src="WS-9", dst="SRV-7"),      # night, new hosts
    ]), profile)
    assert f.loc[0, ["off_hours", "hour_rarity", "new_src_host", "new_dst_host"]].tolist() == [0, 0, 0, 0]
    assert f.loc[1, ["off_hours", "hour_rarity", "new_src_host", "new_dst_host"]].tolist() == [1, 1, 1, 1]
    assert list(f.columns[-len(FEATURES):]) == FEATURES


def test_unknown_user_is_fully_novel(profile):
    f = build_features(pd.DataFrame([ev("2026-01-06 10:00", user="ghost")]), profile)
    assert f.loc[0, ["hour_rarity", "new_src_host", "new_dst_host"]].tolist() == [1, 1, 1]


def test_window_stats_are_trailing_and_per_user(profile):
    rows = [ev(f"2026-01-06 10:{m:02d}", dst=f"H{m}", success=m % 2 == 0) for m in range(10)]
    rows.append(ev("2026-01-06 10:05", user="adm02"))
    rows.append(ev("2026-01-06 11:30", dst="H0"))  # >1h after all but nothing
    f = build_features(pd.DataFrame(rows), profile)
    assert f.loc[9, "distinct_dst_1h"] == 10
    assert f.loc[9, "fail_ratio_1h"] == 0.5
    assert f.loc[9, "failed_1h"] == 5
    assert f.loc[10, "events_1h"] == 1          # other user not counted
    assert f.loc[11, "events_1h"] == 1          # earlier events fell out of the window


def test_history_used_as_context_only(profile):
    hist = pd.DataFrame([ev("2026-01-06 09:50", event_type="checkout")])
    f = build_features(pd.DataFrame([ev("2026-01-06 10:00")]), profile, history=hist)
    assert len(f) == 1
    assert f.loc[0, "checkouts_1h"] == 1 and f.loc[0, "no_checkout"] == 0


def test_no_checkout_only_for_admin_remote_logons(profile):
    f = build_features(pd.DataFrame([
        ev("2026-01-06 10:00"),                                         # admin, no checkout
        ev("2026-01-06 10:00", user="u1", account_type="human"),         # humans don't use the vault
        ev("2026-01-06 10:00", src="WS-1", dst="WS-1"),                  # console logon
    ]), profile)
    assert f.no_checkout.tolist() == [1, 0, 0]


def test_cmd_rarity(profile):
    f = build_features(pd.DataFrame([
        ev("2026-01-06 10:00", event_type="command", command="Get-Service"),
        ev("2026-01-06 10:01", event_type="command", command='net group "Domain Admins" x /add'),
    ]), profile)
    assert f.cmd_rarity.tolist() == [0.0, 1.0]
    assert tokenize('net group "Domain Admins" x') == ["net", "group", "domain", "admins", "x"]


def test_preserves_input_order(profile):
    f = build_features(pd.DataFrame([ev("2026-01-06 12:00", user="b"), ev("2026-01-06 08:00", user="a")]), profile)
    assert f.user.tolist() == ["b", "a"]
