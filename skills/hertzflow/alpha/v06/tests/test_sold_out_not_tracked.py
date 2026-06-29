"""test_sold_out_not_tracked.py — regression for the v1.2.7 fix (product spec 2026-06-29).

A sold-out (已分完, dumped ~100%) insider wallet, AND a dummy-decoy "潜伏 持 0
tokens" address (0-value address-poisoning), were ranked 🔥 HIGH and leaked into the
import paste — pointless to track a wallet that holds nothing. They must be
NOT_TRACKED; genuine latent holders (balance ≥ 1) must stay HIGH.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
from monitoring_ranker import _is_sold_out, annotate_monitoring_wallets  # noqa: E402


def test_sold_out_detected():
    assert _is_sold_out({"role": "已分完钱包 (已分 100%)", "balance_tokens": 1.16e-10})
    assert _is_sold_out({"role": "已派完内幕钱包", "balance_tokens": 0.0})
    # sold out even with a small real sliver (option B: drop regardless)
    assert _is_sold_out({"role": "已分完钱包 (已分 100%)", "balance_tokens": 15400})


def test_empty_quiet_decoy_detected():
    # a "潜伏" wallet holding ~0 is a dummy decoy, not a real latent holder
    assert _is_sold_out({"role": "潜伏钱包 (持 0 tokens, 未分发)", "balance_tokens": 0.0})
    assert _is_sold_out({"role": "潜伏钱包 (持 0 tokens, 未分发)", "balance_tokens": 1e-10})


def test_real_latent_holder_kept():
    # a 潜伏 wallet that genuinely holds is NOT sold-out → stays trackable
    assert not _is_sold_out({"role": "潜伏钱包 (持 10,000,000 tokens)", "balance_tokens": 10_000_000})


def test_deployer_and_others_not_flagged():
    assert not _is_sold_out({"role": "项目方部署钱包", "balance_tokens": 0.0})
    assert not _is_sold_out({"role": "近 72h 异常大单参与方", "balance_tokens": 0.0})
    assert not _is_sold_out({"role": "mint authority", "balance_tokens": 0.0})


def test_annotate_forces_not_tracked_for_sold_out():
    skel = {"monitoring_wallets": [
        {"addr_full": "0x" + "a" * 40, "role": "已分完钱包 (已分 100%)",
         "balance_tokens": 1.16e-10, "status_emoji": "🟢"},
        {"addr_full": "0x" + "b" * 40, "role": "潜伏钱包 (持 0 tokens, 未分发)",
         "balance_tokens": 0.0, "status_emoji": "🔴"},
        {"addr_full": "0x" + "c" * 40, "role": "潜伏钱包 (持 10,000,000 tokens)",
         "balance_tokens": 10_000_000, "status_emoji": "🔴"},
    ], "meta": {"total_supply": 1_000_000_000}}
    annotate_monitoring_wallets(skel)
    by_addr = {w["addr_full"]: w["monitor_level"] for w in skel["monitoring_wallets"]}
    assert by_addr["0x" + "a" * 40] == "NOT_TRACKED"   # sold out
    assert by_addr["0x" + "b" * 40] == "NOT_TRACKED"   # decoy 持 0
    assert by_addr["0x" + "c" * 40] != "NOT_TRACKED"   # real latent → kept


def test_sold_out_excluded_from_paste_but_deployer_kept():
    """End-to-end paste path (adversarial review LOW): sold-out + decoy drop from the paste;
    the 0-balance deployer (HIGH, can re-fund) STAYS (adversarial review HIGH)."""
    from monitoring_export import build_canonical, to_paste_json
    import json as _json
    skel = {"monitoring_wallets": [
        {"addr_full": "0x" + "a" * 40, "addr_short": "0xaaaa", "role": "已分完钱包 (已分 100%)",
         "balance_tokens": 1.16e-10, "status_emoji": "🟢"},
        {"addr_full": "0x" + "b" * 40, "addr_short": "0xbbbb", "role": "潜伏钱包 (持 0 tokens, 未分发)",
         "balance_tokens": 0.0, "status_emoji": "🔴"},
        {"addr_full": "0x" + "c" * 40, "addr_short": "0xcccc", "role": "潜伏钱包 (持 10,000,000 tokens)",
         "balance_tokens": 10_000_000, "status_emoji": "🔴"},
        {"addr_full": "0x" + "d" * 40, "addr_short": "0xdddd", "role": "项目方部署钱包",
         "balance_tokens": 0.0, "status_emoji": "🟡"},
    ], "meta": {"total_supply": 1_000_000_000}}
    annotate_monitoring_wallets(skel)
    canonical = build_canonical(symbol="T", chain="bsc",
                                contract_address="0x" + "e" * 40,
                                monitoring_wallets=skel["monitoring_wallets"])
    addrs = {p["address"] for p in _json.loads(to_paste_json(canonical))}
    assert ("0x" + "a" * 40) not in addrs   # sold out → out
    assert ("0x" + "b" * 40) not in addrs   # decoy 持 0 → out
    assert ("0x" + "c" * 40) in addrs        # real latent → in
    assert ("0x" + "d" * 40) in addrs        # deployer (0 bal, HIGH) → STAYS


def test_unknown_balance_latent_not_dropped():
    """adversarial review MED: a 潜伏 wallet with UNKNOWN (None) balance must NOT be assumed
    empty / sold-out."""
    assert not _is_sold_out({"role": "潜伏钱包 (未分发)", "balance_tokens": None})
