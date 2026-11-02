from privguard.config import LanlConfig
from privguard.lanl import build_sample

AUTH = """\
1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success
5,U10@DOM1,U10@DOM1,C1,C2,Kerberos,Network,LogOn,Success
5,U10@DOM1,U10@DOM1,C1,C2,?,?,LogOff,Success
7,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success
8,U748@DOM1,U748@DOM1,C17693,C999,NTLM,Network,LogOn,Fail
50,U10@DOM1,U10@DOM1,C1,C3,Kerberos,Network,LogOn,Success
"""
REDTEAM = "7,U748@DOM1,C17693,C728\n"


def test_build_sample(tmp_path):
    (tmp_path / "auth.txt").write_text(AUTH)
    (tmp_path / "redteam.txt").write_text(REDTEAM)
    cfg = LanlConfig(tmp_path / "auth.txt", tmp_path / "redteam.txt",
                     start_time=1, end_time=10, user_sample_rate=1.0, chunksize=2)

    ev = build_sample(cfg)

    assert len(ev) == 4  # LogOff row and t=50 (outside window) dropped
    assert ev.is_attack.tolist() == [0, 0, 1, 0]
    assert ev.loc[ev.is_attack == 1, "attack_type"].item() == "redteam"
    assert ev.account_type.tolist() == ["service", "human", "human", "human"]
    assert ev.success.tolist() == [True, True, True, False]


def test_user_sampling_keeps_redteam_users(tmp_path):
    (tmp_path / "auth.txt").write_text(AUTH)
    (tmp_path / "redteam.txt").write_text(REDTEAM)
    cfg = LanlConfig(tmp_path / "auth.txt", tmp_path / "redteam.txt",
                     start_time=1, end_time=10, user_sample_rate=0.0, chunksize=100)

    assert set(build_sample(cfg).user) == {"U748@DOM1"}
