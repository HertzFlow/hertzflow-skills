"""test_quiet_excludes_decoys.py — v1.2.8 (product spec 2026-06-29): a genuine quiet/潜伏
insider must actually HOLD. dumped_pct==0 alone also matches 0-value address-
poisoning decoys (received 0, hold 0) which inflated n_quiet (VELVET 13 vs real 2).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
import section_alloc  # noqa: E402


def _run(receivers):
    return section_alloc.run(rule11={"deployer": "0xdead", "pre_launch_receivers": receivers},
                             total_supply=1_000_000_000, circulating_supply=1_000_000_000)


def test_zero_balance_decoys_excluded_from_quiet():
    receivers = [
        {"addr": "0x" + "a" * 40, "dumped_pct": 0, "current_balance": 10_000_000, "received_from_deployer": 10_000_000},
        {"addr": "0x" + "b" * 40, "dumped_pct": 0, "current_balance": 5_333_333, "received_from_deployer": 5_333_333},
        # 11 decoys: dumped_pct==0 but 0 received / 0 held
        *[{"addr": "0x" + f"{i:040x}", "dumped_pct": 0, "current_balance": 0, "received_from_deployer": 0}
          for i in range(11)],
    ]
    out = _run(receivers)
    assert out["n_quiet"] == 2, out["n_quiet"]   # only the 2 real holders


def test_dust_balance_not_quiet():
    receivers = [{"addr": "0x" + "c" * 40, "dumped_pct": 0, "current_balance": 1.16e-10, "received_from_deployer": 0}]
    assert _run(receivers)["n_quiet"] == 0
