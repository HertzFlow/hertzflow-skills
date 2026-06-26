"""test_dexscreener_lp.py — v0.9.8 DexScreener LP cross-check regression.

Root cause (BR / Bedrock 2026-06-17): the surf-token-holders + Arkham-label
LP path gave BR a $34.95 LP for a token with a real $1M PancakeSwap V3
pool. Two compounding bugs: (1) Arkham labels are async so the real V3 pool
was missed, (2) the V4 PoolManager singleton (0x000...4444, holding a
meaningless shared-vault balance) got picked as the "main pool".

v0.9.8 makes DexScreener (reads on-chain reserves directly) the
authoritative LP source. These tests mock the DexScreener HTTP response so
CI never hits the network, and assert:
  - the max-LP pool on the active chain is picked
  - V4 singleton / dust pools are NOT picked when a real pool exists
  - cross-chain pools are filtered to the active chain
  - discover_main_pool prefers DexScreener over the surf path
  - graceful fallback to surf when DexScreener has no data
"""
import sys
from pathlib import Path

_HELPERS = Path(__file__).resolve().parent.parent / "helpers"
sys.path.insert(0, str(_HELPERS))

import pytest  # noqa: E402
import section_liq  # noqa: E402
from chain_router import set_active_chain  # noqa: E402

_CA = "0xff7d6a96ae471bbcd7713af9cb1feeb16cf56b41"
_MAIN_POOL = "0xe2461367e562df374acf8d8a012729721ad5b486"   # real $1M V3
_DUST_POOL = "0x000000000004444c5dc75cb358380d2e3de08a90"   # V4 singleton


@pytest.fixture(autouse=True)
def _bsc():
    set_active_chain("bsc")
    yield
    set_active_chain("bsc")


def _ds_doc(pairs):
    return {"pairs": pairs}


def _pair(chain, addr, lp, price="0.18", dex="pancakeswap"):
    return {
        "chainId": chain,
        "dexId": dex,
        "pairAddress": addr,
        "priceUsd": price,
        "liquidity": {"usd": lp},
        "volume": {"h24": 49000},
        "fdv": 1860000,
        "marketCap": 4670000,
        "baseToken": {"address": _CA},
        "quoteToken": {"address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"},
    }


def test_picks_max_lp_pool(monkeypatch):
    # Real $1M pool + a $35 dust pool — must pick the $1M one.
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([
        _pair("bsc", _DUST_POOL, 34.95),
        _pair("bsc", _MAIN_POOL, 994718.76),
    ]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out is not None
    assert out["pool_addr"] == _MAIN_POOL
    assert out["liquidity_usd"] == 994718.76


def test_v4_singleton_not_picked_over_real_pool(monkeypatch):
    # The exact BR failure: dust singleton must lose to the real pool.
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([
        _pair("bsc", _MAIN_POOL, 994718.76),
        _pair("bsc", _DUST_POOL, 34.95),
    ]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out["pool_addr"] == _MAIN_POOL
    assert out["liquidity_usd"] > 100000


def test_coingecko_platform_name_resolves_same_as_prefix(monkeypatch):
    """v1.0.3 (O 2026-06-20): the pipeline calls fetch_dexscreener_main_pool
    with meta.primary_chain — a CoinGecko platform NAME (binance-smart-chain),
    not a chain_router prefix (bsc). Since v0.9.8 the chain lookup silently
    returned None for bsc/arbitrum/polygon/optimism (CG name != prefix), so the
    real pool was dropped → LP shown as 数据缺失. Both formats must resolve."""
    pairs = [_pair("bsc", _MAIN_POOL, 994718.76)]
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc(pairs))
    out_prefix = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    out_cgname = section_liq.fetch_dexscreener_main_pool(_CA, "binance-smart-chain")
    assert out_prefix is not None and out_cgname is not None
    assert out_cgname["pool_addr"] == out_prefix["pool_addr"] == _MAIN_POOL
    assert out_cgname["liquidity_usd"] == 994718.76


def test_all_coingecko_names_map_to_dexscreener(monkeypatch):
    """Every primary_chain a token can carry must resolve in the DexScreener
    map. Guards against a future chain whose CoinGecko name != prefix being
    added to derive_primary_chain but not to _DEXSCREENER_CHAIN_MAP."""
    for cg_name, ds in [
        ("binance-smart-chain", "bsc"), ("arbitrum-one", "arbitrum"),
        ("polygon-pos", "polygon"), ("optimistic-ethereum", "optimism"),
        ("ethereum", "ethereum"), ("base", "base"),
    ]:
        assert section_liq._DEXSCREENER_CHAIN_MAP.get(cg_name) == ds, cg_name


def test_filters_to_active_chain(monkeypatch):
    # A bigger pool on a DIFFERENT chain must NOT be picked for bsc.
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([
        _pair("ethereum", "0xaaa", 5_000_000),   # bigger but wrong chain
        _pair("bsc", _MAIN_POOL, 994718.76),
    ]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out["pool_addr"] == _MAIN_POOL


def test_returns_none_when_no_pairs(monkeypatch):
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([]))
    assert section_liq.fetch_dexscreener_main_pool(_CA, "bsc") is None


def test_quote_token_pair_excluded(monkeypatch):
    # adversarial review Finding 2: a pair where the token is QUOTE (e.g. Vyx/BR) has
    # priceUsd = the OTHER token's price. Even if its LP is bigger, it
    # must NOT be picked — only baseToken==ca pairs are considered.
    quote_pair = {
        "chainId": "bsc", "dexId": "pancakeswap",
        "pairAddress": "0xVYXquotePOOL",
        "priceUsd": "0.0198",   # this is Vyx's price, NOT BR's
        "liquidity": {"usd": 5_000_000},   # bigger than the real BR pool
        "volume": {"h24": 1},
        "baseToken": {"address": "0xvyxtokenaddr00000000000000000000000000"},
        "quoteToken": {"address": _CA},   # BR is QUOTE here
    }
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([
        quote_pair,
        _pair("bsc", _MAIN_POOL, 994718.76, price="0.1858"),
    ]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    # Must pick the real BR base-pair, NOT the bigger quote-pair.
    assert out["pool_addr"] == _MAIN_POOL
    assert out["price_usd"] == 0.1858


def test_corrupted_price_pool_rejected(monkeypatch):
    """v1.0.0 (O / o1.exchange): a $900M 'pool' with corrupted priceUsd
    (4.5e26) and $62 vol must be rejected in favour of the real $2.7M pool
    with consensus price. The v0.9.8 activity guard (vol24>0) missed it
    because $62 > 0. Max-vol-anchored price filter catches it."""
    garbage = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": "0xGARBAGE",
        "priceUsd": "450203585649632976722584554.13",   # corrupted
        "liquidity": {"usd": 900_407_172},               # fake $900M
        "volume": {"h24": 62},                            # $62 — can't fake real vol
        "txns": {"h24": {"buys": 1, "sells": 1}},
        "baseToken": {"address": _CA},
        "quoteToken": {"address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"},
    }
    real = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": _MAIN_POOL,
        "priceUsd": "0.6531", "liquidity": {"usd": 2_735_082},
        "volume": {"h24": 45_987_904},                    # real $46M market
        "txns": {"h24": {"buys": 5000, "sells": 4000}},
        "baseToken": {"address": _CA},
        "quoteToken": {"address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"},
    }
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([garbage, real]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out["pool_addr"] == _MAIN_POOL          # real wins, garbage rejected
    assert out["liquidity_usd"] == 2_735_082       # NOT the fake $900M
    assert abs(out["price_usd"] - 0.6531) < 1e-6


def test_high_lp_near_zero_turnover_demoted(monkeypatch):
    """v1.0.0: a >$50K pool with near-zero vol/LP turnover is demoted below
    a real pool even when its price is sane (belt-and-suspenders for fakes
    that happen to carry a plausible price)."""
    sleepy_big = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": "0xSLEEPY",
        "priceUsd": "0.65", "liquidity": {"usd": 5_000_000},   # big
        "volume": {"h24": 50},                                  # turnover 1e-5
        "txns": {"h24": {"buys": 1, "sells": 1}},
        "baseToken": {"address": _CA},
        "quoteToken": {"address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"},
    }
    real = _pair("bsc", _MAIN_POOL, 994718.76, price="0.65")
    real["volume"] = {"h24": 1_000_000}
    real["txns"] = {"h24": {"buys": 500, "sells": 400}}
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([sleepy_big, real]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out["pool_addr"] == _MAIN_POOL   # real (active) wins over sleepy big


def test_external_anchor_beats_self_poisoned_max_vol(monkeypatch):
    """adversarial review v1.0.0 R1 Finding 1 (HIGH): a fake pool that out-VOLUMES the
    real one ($50M wash) would self-anchor the price filter and reject the
    real pool. The surf RTI external anchor closes this — pass the real
    price and the fake (corrupted price) is rejected regardless of its vol."""
    fakevol = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": "0xFAKEVOL",
        "priceUsd": "450203585649632976722584554.13",
        "liquidity": {"usd": 900_000_000},
        "volume": {"h24": 50_000_000},   # OUT-VOLUMES the real pool
        "txns": {"h24": {"buys": 9, "sells": 9}},
        "baseToken": {"address": _CA}, "quoteToken": {"address": "0xbb"},
    }
    real = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": _MAIN_POOL,
        "priceUsd": "0.65", "liquidity": {"usd": 2_700_000},
        "volume": {"h24": 46_000_000},
        "txns": {"h24": {"buys": 5000, "sells": 4000}},
        "baseToken": {"address": _CA}, "quoteToken": {"address": "0xbb"},
    }
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([fakevol, real]))
    # Without external anchor, the fake (higher vol) self-anchors → fake wins.
    out_no = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out_no["pool_addr"] == "0xfakevol"   # documents the weakness
    # With surf RTI external anchor (real price), the fake is rejected.
    out_anchor = section_liq.fetch_dexscreener_main_pool(_CA, "bsc", anchor_price=0.65)
    assert out_anchor["pool_addr"] == _MAIN_POOL
    assert out_anchor["liquidity_usd"] == 2_700_000


def test_no_price_large_pool_demoted(monkeypatch):
    """adversarial review v1.0.0 R1 Finding 2 (HIGH): a >$50K pool with NO priceUsd
    bypassed the corrupted-price filter and could win on fake LP. Must be
    demoted below a real priced pool."""
    noprice = {
        "chainId": "bsc", "dexId": "x", "pairAddress": "0xNOPRICE",
        "priceUsd": None, "liquidity": {"usd": 900_000_000},
        "volume": {"h24": 200_000}, "txns": {"h24": {"buys": 50, "sells": 50}},
        "baseToken": {"address": _CA}, "quoteToken": {"address": "0xbb"},
    }
    real = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": _MAIN_POOL,
        "priceUsd": "0.65", "liquidity": {"usd": 2_700_000},
        "volume": {"h24": 46_000_000},
        "txns": {"h24": {"buys": 5000, "sells": 4000}},
        "baseToken": {"address": _CA}, "quoteToken": {"address": "0xbb"},
    }
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([noprice, real]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc", anchor_price=0.65)
    assert out["pool_addr"] == _MAIN_POOL
    assert out["liquidity_usd"] == 2_700_000


def test_unknown_chain_returns_none(monkeypatch):
    # adversarial review Finding 4: unmapped chain must NOT guess across chains.
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([
        _pair("bsc", _MAIN_POOL, 994718.76),
    ]))
    assert section_liq.fetch_dexscreener_main_pool(_CA, "fakechain") is None


def test_fake_high_lp_pool_loses_to_real_pool(monkeypatch):
    # adversarial review Finding 1: a fabricated pool with huge fake LP but ZERO 24h
    # trades must lose to a real pool with activity.
    fake = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": "0xFAKE",
        "priceUsd": "9.99", "liquidity": {"usd": 10_000_000},
        "volume": {"h24": 0}, "txns": {"h24": {"buys": 0, "sells": 0}},
        "baseToken": {"address": _CA},
        "quoteToken": {"address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"},
    }
    real = {
        "chainId": "bsc", "dexId": "pancakeswap", "pairAddress": _MAIN_POOL,
        "priceUsd": "0.1858", "liquidity": {"usd": 994718.76},
        "volume": {"h24": 49000}, "txns": {"h24": {"buys": 500, "sells": 400}},
        "baseToken": {"address": _CA},
        "quoteToken": {"address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"},
    }
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([fake, real]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out["pool_addr"] == _MAIN_POOL   # real pool wins despite lower LP
    assert out["_lp_low_confidence"] is False


def test_all_zero_activity_falls_to_max_lp_low_confidence(monkeypatch):
    # When NO pool has activity (brand-new listing), pick max LP but flag
    # it low-confidence so downstream knows it's unverified.
    p1 = _pair("bsc", "0xpoolA", 5000)
    p2 = _pair("bsc", "0xpoolB", 8000)
    for p in (p1, p2):
        p["volume"] = {"h24": 0}
        p["txns"] = {"h24": {"buys": 0, "sells": 0}}
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([p1, p2]))
    out = section_liq.fetch_dexscreener_main_pool(_CA, "bsc")
    assert out["pool_addr"] == "0xpoolb"   # max LP
    assert out["_lp_low_confidence"] is True


def test_solana_case_preserved(monkeypatch):
    # adversarial review Finding 9: Solana base58 mints are case-sensitive — must NOT
    # be lowercased. Verify the address comparison preserves case.
    sol_mint = "So11111111111111111111111111111111111111112"
    captured = {}

    def _spy(url, timeout=8):
        captured["url"] = url
        return _ds_doc([{
            "chainId": "solana", "dexId": "raydium", "pairAddress": "PoolAddr123",
            "priceUsd": "1.5", "liquidity": {"usd": 500000},
            "volume": {"h24": 10000}, "txns": {"h24": {"buys": 50, "sells": 40}},
            "baseToken": {"address": sol_mint},   # exact case
            "quoteToken": {"address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
        }])

    monkeypatch.setattr(section_liq, "_curl_json", _spy)
    set_active_chain("solana")
    try:
        out = section_liq.fetch_dexscreener_main_pool(sol_mint, "solana")
        # URL must contain the EXACT-case mint, not lowercased.
        assert sol_mint in captured["url"]
        assert sol_mint.lower() not in captured["url"] or sol_mint == sol_mint.lower()
        # Base-token match must succeed (case preserved) → pool found.
        assert out is not None
        assert out["liquidity_usd"] == 500000
    finally:
        set_active_chain("bsc")


def test_returns_none_on_http_failure(monkeypatch):
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: None)
    assert section_liq.fetch_dexscreener_main_pool(_CA, "bsc") is None


def test_discover_main_pool_prefers_dexscreener(monkeypatch):
    # Surf path would return the $35 dust pool; DexScreener must override.
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: _ds_doc([
        _pair("bsc", _MAIN_POOL, 994718.76),
    ]))
    surf_chain_lp = {
        "bsc": {"top_pool_addr": _DUST_POOL, "lp_usd": 34.95},
    }
    pool = section_liq.discover_main_pool(
        _CA, scope_chain_lp=surf_chain_lp,
        scope_realtime_token_info={}, primary_chain="bsc",
    )
    assert pool["pool_addr"] == _MAIN_POOL
    assert pool["liquidity_usd"] == 994718.76
    assert pool["_source"] == "dexscreener"


def test_discover_main_pool_falls_back_to_surf(monkeypatch):
    # DexScreener down → must fall back to the surf top_pool_addr path.
    monkeypatch.setattr(section_liq, "_curl_json", lambda url, timeout=8: None)
    surf_chain_lp = {
        "bsc": {"top_pool_addr": _MAIN_POOL, "lp_usd": 500000.0},
    }
    pool = section_liq.discover_main_pool(
        _CA, scope_chain_lp=surf_chain_lp,
        scope_realtime_token_info={"price_usd": 0.18},
        primary_chain="bsc",
    )
    assert pool["pool_addr"] == _MAIN_POOL
    assert pool["liquidity_usd"] == 500000.0
    # surf-path result has no _source=dexscreener marker
    assert pool.get("_source") != "dexscreener"
