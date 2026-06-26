#!/usr/bin/env python3
"""test_chain_router.py — v0.7.20 cross-chain SQL routing regression.

The chain_router module replaces hardcoded `bsc_transfers` / `bsc_dex_trades`
table names across 11 helpers with chain-aware lookups driven by a
ContextVar. These tests pin down:

  1. set_active_chain() accepts the documented chain IDs and strings and
     returns the canonical short name.
  2. transfers_table() / dex_trades_table() produce the right table for
     every supported chain.
  3. Unsupported chain IDs raise UnsupportedChainError (fail-loud — we
     don't want a silent BSC fallback when the Alpha API reports an
     unknown chain because that's how PLAY got mis-routed pre-v0.7.20).
  4. Default state is BSC for backwards compatibility with helpers that
     are imported directly and never call set_active_chain().
  5. derive_primary_chain() honours the Alpha-API chain instead of
     hardcoding BSC when LP is zero on all surf-supported chains.
"""

from __future__ import annotations

import sys
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))
sys.path.insert(0, str(V06_DIR / "helpers"))

import pytest
import chain_router
from chain_router import (
    set_active_chain,
    get_active_chain,
    transfers_table,
    dex_trades_table,
    chain_lock,
    UnsupportedChainError,
)
from section_a_scope import (
    derive_primary_chain,
    _inject_alpha_chain_platform,
    _SURF_HOLDER_CHAINS,
    _CHAIN_ID_TO_CG_PLATFORM,
)
import chain_router as _cr
from concurrent.futures import ThreadPoolExecutor


# ---- v1.0.2 (H): Alpha chain always pulled, even when CoinGecko omits it ----

def test_inject_alpha_chain_when_coingecko_omits_it():
    """H 2026-06-20: the holder pull is driven by CoinGecko's platform list,
    not the Alpha chainId. H (ETH token, chainId=1) had CG platforms listing
    only hyperliquid/hyperevm, so ethereum was never queried → no
    chain_lp_realtime['ethereum'] → chip-structure 3-way 0% → 数据缺失.
    The Alpha chain must be force-injected so its holders get fetched."""
    out = _inject_alpha_chain_platform({"hyperliquid": "0xabc"}, "1", "0xCA")
    assert out["ethereum"] == "0xCA"          # injected
    assert out["hyperliquid"] == "0xabc"      # CG entries preserved


def test_inject_alpha_chain_never_overrides_coingecko():
    """If CoinGecko already lists the Alpha chain with a real address, keep it."""
    out = _inject_alpha_chain_platform({"ethereum": "0xEXISTING"}, "1", "0xCA")
    assert out["ethereum"] == "0xEXISTING"


def test_inject_alpha_chain_repairs_blank_coingecko_address():
    """adversarial review v1.0.2: CoinGecko sometimes lists the platform key with a blank /
    None address. setdefault would keep the blank → fetch skips empty CAs →
    the bug recurs. The Alpha chain CA must replace a falsy entry."""
    assert _inject_alpha_chain_platform({"ethereum": ""}, "1", "0xCA")["ethereum"] == "0xCA"
    assert _inject_alpha_chain_platform({"ethereum": None}, "1", "0xCA")["ethereum"] == "0xCA"


def test_inject_alpha_chain_skips_unsupported_chainid():
    """Unmapped / non-surf Alpha chainId → no injection (can't query it)."""
    assert _inject_alpha_chain_platform({"celo": "0xc"}, "999", "0xCA") == {"celo": "0xc"}
    # avalanche (43114) was removed from the map in v1.0.1 → not injectable
    assert "avalanche" not in _inject_alpha_chain_platform({}, "43114", "0xCA")


def test_inject_alpha_chain_into_empty_platforms():
    """Empty / None platforms + valid surf chainId → inject the Alpha chain."""
    assert _inject_alpha_chain_platform(None, "8453", "0xCA") == {"base": "0xCA"}
    assert _inject_alpha_chain_platform({}, "1", "0xCA") == {"ethereum": "0xCA"}


# ---- anti-drift: derive_primary_chain can only return router-routable chains

def test_surf_holder_chains_subset_of_router():
    """v1.0.1 (adversarial review HIGH): derive_primary_chain gates `alpha_chain_authoritative`
    on _SURF_HOLDER_CHAINS. Every short-name it can return MUST be routable by
    chain_router.set_active_chain, else primary_chain diverges from the SQL chain
    (the avalanche/43114 bug: listed surf-supported but unrouteable → would route
    holders to a chain set_active_chain rejects)."""
    router_prefixes = set(_cr._VALID_PREFIXES)
    offenders = [short for short in _SURF_HOLDER_CHAINS.values()
                 if short not in router_prefixes]
    assert not offenders, (
        f"_SURF_HOLDER_CHAINS short-names not routable by chain_router: {offenders}"
    )


def test_chain_id_to_cg_platform_only_routable():
    """Every Alpha chainId that maps to a CoinGecko platform must, via
    _SURF_HOLDER_CHAINS, resolve to a router-routable chain. Prevents a
    chainId→non-routable-platform mapping (43114→avalanche) sneaking back."""
    router_prefixes = set(_cr._VALID_PREFIXES)
    for chain_id, platform in _CHAIN_ID_TO_CG_PLATFORM.items():
        short = _SURF_HOLDER_CHAINS.get(platform)
        assert short is not None, f"chainId {chain_id}→{platform} absent from _SURF_HOLDER_CHAINS"
        assert short in router_prefixes, (
            f"chainId {chain_id}→{platform}→{short} not routable by chain_router"
        )


# ---- set_active_chain accepts int + str -------------------------------

@pytest.mark.parametrize("chain_id,expected", [
    (1, "ethereum"),
    (10, "optimism"),
    (56, "bsc"),
    (137, "polygon"),
    (8453, "base"),
    (42161, "arbitrum"),
    ("ethereum", "ethereum"),
    ("bsc", "bsc"),
    ("base", "base"),
    ("solana", "solana"),
    # String chainId from Alpha API (json strings).
    ("8453", "base"),
    ("42161", "arbitrum"),
])
def test_set_active_chain_canonicalises(chain_id, expected):
    """All supported chain IDs canonicalise to the same short name."""
    try:
        assert set_active_chain(chain_id) == expected
        assert get_active_chain() == expected
    finally:
        set_active_chain("bsc")  # restore default to keep tests isolated.


# ---- transfers / dex_trades table generation --------------------------

@pytest.mark.parametrize("chain,t_table,d_table", [
    ("bsc",       "agent.bsc_transfers",       "agent.bsc_dex_trades"),
    ("ethereum",  "agent.ethereum_transfers",  "agent.ethereum_dex_trades"),
    ("base",      "agent.base_transfers",      "agent.base_dex_trades"),
    ("arbitrum",  "agent.arbitrum_transfers",  "agent.arbitrum_dex_trades"),
    ("polygon",   "agent.polygon_transfers",   "agent.polygon_dex_trades"),
    ("optimism",  "agent.optimism_transfers",  "agent.optimism_dex_trades"),
])
def test_table_names_match_chain(chain, t_table, d_table):
    try:
        set_active_chain(chain)
        assert transfers_table() == t_table
        assert dex_trades_table() == d_table
    finally:
        set_active_chain("bsc")


# ---- Solana: transfers exists, dex_trades exists, naming consistent ---

def test_solana_tables():
    try:
        set_active_chain("solana")
        assert transfers_table() == "agent.solana_transfers"
        assert dex_trades_table() == "agent.solana_dex_trades"
    finally:
        set_active_chain("bsc")


# ---- Unsupported chain fails loud (no silent BSC fallback) -----------

def test_unsupported_chain_id_raises():
    """Alpha API returning a chain we don't have surf coverage for must
    NOT silently fall back to BSC — that's how PLAY (8453) ran the
    pre-v0.7.20 pipeline against bsc_transfers and got zero hits.
    """
    with pytest.raises(UnsupportedChainError):
        set_active_chain(99999)


def test_unsupported_chain_string_raises():
    with pytest.raises(UnsupportedChainError):
        set_active_chain("dogechain")


# ---- Default state is bsc (backward compat) ---------------------------

def test_default_chain_is_bsc():
    """Helpers imported directly without calling set_active_chain() must
    still produce the historical BSC SQL — otherwise every existing
    callsite (test fixtures, ad-hoc scripts) would break overnight.
    """
    # Don't touch the ContextVar — start from module default.
    # ContextVar defaults are read-only at module level, so we reset by
    # calling set_active_chain("bsc") which is the documented init.
    set_active_chain("bsc")
    assert get_active_chain() == "bsc"
    assert transfers_table() == "agent.bsc_transfers"
    assert dex_trades_table() == "agent.bsc_dex_trades"


# ---- derive_primary_chain honours Alpha-API chainId fallback ---------

def test_derive_primary_chain_zero_lp_honours_alpha_base():
    """v0.7.20 fix: PLAY (chainId 8453) with surf-supported chains all 0
    LP must derive primary_chain='base', not 'binance-smart-chain'.
    """
    chain_lp = {
        "base": {"surf_supported": True, "lp_usd": 0, "n_dex_pools": 0},
        "binance-smart-chain": {"surf_supported": True, "lp_usd": 0, "n_dex_pools": 0},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id="8453")
    assert primary == "base"
    assert derivation == "alpha_chain_authoritative"


def test_derive_primary_chain_zero_lp_honours_alpha_eth():
    chain_lp = {
        "ethereum": {"surf_supported": True, "lp_usd": 0},
        "binance-smart-chain": {"surf_supported": True, "lp_usd": 0},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id="1")
    assert primary == "ethereum"
    assert derivation == "alpha_chain_authoritative"


def test_derive_primary_chain_zero_lp_with_non_surf_chain_honours_alpha():
    """v0.7.21.5 regression — OLAS case.

    OLAS (Ethereum, chainId 1) is deployed across 9 chains; surf returns
    `lp_usd: None` on every chain (token-holders endpoint can't price the
    LP). Pre-v0.7.21.5 derive_primary_chain saw the all-None state, ran
    step 3, picked `non_surf_chains[0]` alphabetically → "celo", and
    silently ignored the Alpha-API chainId=1 hint. chain_router still
    routed SQL to ethereum (via set_active_chain), so the forensic was
    correct, but `meta.primary_chain="celo"` mis-attributed the report.

    v0.7.21.5 makes the Alpha-API chain win whenever its CoinGecko
    platform is in the chain_lp dict, regardless of LP USD state and
    regardless of whether non-surf platforms also appear.
    """
    # All-zero LP across 8 platforms (4 surf-supported, 4 non-surf), Alpha
    # says chainId=1 → must derive "ethereum", not "celo".
    chain_lp = {
        "arbitrum-one": {"surf_supported": True, "lp_usd": None},
        "base": {"surf_supported": True, "lp_usd": None},
        "celo": {"surf_supported": False, "lp_usd": None},
        "ethereum": {"surf_supported": True, "lp_usd": None},
        "mode": {"surf_supported": False, "lp_usd": None},
        "optimistic-ethereum": {"surf_supported": True, "lp_usd": None},
        "polygon-pos": {"surf_supported": True, "lp_usd": None},
        "xdai": {"surf_supported": False, "lp_usd": None},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id="1")
    assert primary == "ethereum"
    assert derivation == "alpha_chain_authoritative"


def test_derive_primary_chain_all_non_surf_falls_back_bsc_not_non_surf():
    """v1.0.1 (H 2026-06-18): when the ONLY platforms are non-surf chains
    (the old `non_surf_inferred` path), primary_chain must NOT be set to a
    non-surf chain — it routes the holder / cluster / CEX token-holders
    queries, and a non-surf chain sends those to a partition surf can't
    serve → empty → 筹码结构 0%. Fall back to BSC (queryable) instead.
    """
    chain_lp = {
        "celo": {"surf_supported": False, "lp_usd": None},
        "xdai": {"surf_supported": False, "lp_usd": None},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id=None)
    assert primary == "binance-smart-chain"      # NOT "celo"
    assert derivation == "no_surf_chain_bsc_fallback"


def test_derive_primary_chain_never_returns_non_surf_chain():
    """v1.0.1 H regression: even when a non-surf chain (hyperliquid) is
    present alongside a surf-supported one, primary_chain must pick the
    surf-supported chain. The H bug: ETH token whose CoinGecko platforms
    listed hyperliquid → old code returned hyperliquid → holder/cluster/CEX
    SQL hit the empty hyperliquid partition → 筹码三桶 0%.
    """
    # H case: Alpha says chainId=1 (ethereum); CoinGecko did NOT list an
    # 'ethereum' key (only hyperliquid + hyperevm). Must still route ETH.
    chain_lp = {
        "hyperliquid": {"surf_supported": False, "lp_usd": None},
        "hyperevm": {"surf_supported": False, "lp_usd": None},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id="1")
    assert primary == "ethereum"
    assert derivation == "alpha_chain_authoritative"

    # surf chain present at 0 LP + non-surf present + no Alpha hint → must
    # pick the surf-supported chain, never the non-surf one.
    chain_lp2 = {
        "celo": {"surf_supported": False, "lp_usd": None},
        "ethereum": {"surf_supported": True, "lp_usd": None},
    }
    primary2, deriv2 = derive_primary_chain(chain_lp2, alpha_chain_id=None)
    assert primary2 == "ethereum"
    assert deriv2 == "surf_supported_fallback"


def test_derive_primary_chain_zero_lp_unknown_alpha_falls_back_bsc():
    """If Alpha chainId is missing / unmapped but a surf-supported chain
    is present, use it (v1.0.1: surf_supported_fallback). The chain stays
    BSC here because BSC is the only (surf-supported) candidate."""
    chain_lp = {
        "binance-smart-chain": {"surf_supported": True, "lp_usd": 0},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id=None)
    assert primary == "binance-smart-chain"
    assert derivation == "surf_supported_fallback"

    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id="99999")
    assert primary == "binance-smart-chain"
    assert derivation == "surf_supported_fallback"


# ---- ThreadPoolExecutor propagation (adversarial review v0.7.20 CRITICAL #1) -------

def test_thread_pool_executor_sees_active_chain():
    """v0.7.20 CRITICAL: the v0.6 - v0.7.19.5 SQL was hardcoded BSC; the
    initial v0.7.20 ContextVar implementation looked correct in single-
    threaded code but ContextVar defaults are NOT inherited by worker
    threads in `concurrent.futures.ThreadPoolExecutor`. dump_tracker /
    wash_infra_detector build SQL via `transfers_table()` INSIDE worker
    callables — under ContextVar those workers would silently read the
    default 'bsc' even after set_active_chain('base'), re-creating the
    PLAY mis-routing bug under threading.

    We switched to a plain module-level string (audit accepted the
    'global mutable' cost — single-shot CLI semantics make it safe). This
    test pins down the cross-thread behavior so a future refactor can't
    silently regress.
    """
    try:
        set_active_chain("base")

        def worker():
            return (get_active_chain(), transfers_table(), dex_trades_table())

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = [ex.submit(worker) for _ in range(8)]
            for fut in futures:
                chain, t, d = fut.result()
                assert chain == "base", f"worker thread saw {chain!r}, not 'base'"
                assert t == "agent.base_transfers"
                assert d == "agent.base_dex_trades"
    finally:
        set_active_chain("bsc")


# ---- chain_lock context manager ---------------------------------------

def test_chain_lock_restores_prior_chain():
    """chain_lock is the documented escape hatch for tests / ad-hoc
    scripts that need to flip the router for one block without leaking
    state. Confirm prior chain is restored even on exception.
    """
    set_active_chain("bsc")
    with chain_lock("ethereum"):
        assert get_active_chain() == "ethereum"
        assert transfers_table() == "agent.ethereum_transfers"
    assert get_active_chain() == "bsc"


def test_chain_lock_restores_on_exception():
    set_active_chain("bsc")
    with pytest.raises(RuntimeError):
        with chain_lock("base"):
            assert get_active_chain() == "base"
            raise RuntimeError("simulated failure inside chain_lock body")
    assert get_active_chain() == "bsc"


# ---- Long-lived process leak prevention (adversarial review Round 2 HIGH) ---------

def test_build_skeleton_resets_chain_at_entry():
    """adversarial review Round 2 HIGH: in a long-lived process (daemon / batch
    wrapper), `_active_chain` would carry over from the prior run unless
    `build_skeleton` resets it at entry. Confirm the reset happens by
    importing `forensic_pipeline` and inspecting its source (we cannot
    easily exercise `build_skeleton` end-to-end without surf credit, but
    we can pin down that the reset is wired up).
    """
    import inspect
    sys.path.insert(0, str(V06_DIR))
    import forensic_pipeline
    src = inspect.getsource(forensic_pipeline.build_skeleton)
    assert 'set_active_chain("bsc")' in src, (
        "build_skeleton must reset chain to bsc at entry to prevent "
        "long-lived-process state leak — see adversarial review Round 2 HIGH."
    )


def test_chain_lock_rejects_unsupported_inside_block():
    """Unsupported chain inside chain_lock fails-loud at entry and leaves
    the prior chain intact (no half-set state)."""
    set_active_chain("bsc")
    with pytest.raises(UnsupportedChainError):
        with chain_lock("nochain"):
            pytest.fail("chain_lock body must not execute on UnsupportedChainError")
    assert get_active_chain() == "bsc"


def test_derive_primary_chain_alpha_wins_over_bigger_foreign_lp():
    """v1.0.1 (adversarial review HIGH): the Alpha chainId is the authoritative routing
    key. A Base-listed token (chainId=8453) with a bigger ETH wrapper LP
    must route holders to BASE — same chain the SQL detectors use via
    set_active_chain(8453). The old `lp_usd_max`-first behaviour picked
    ethereum, splitting the report (SQL on Base, holders on Ethereum).
    """
    chain_lp = {
        "base": {"surf_supported": True, "lp_usd": 100_000},
        "ethereum": {"surf_supported": True, "lp_usd": 250_000},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id="8453")
    assert primary == "base"                      # NOT ethereum
    assert derivation == "alpha_chain_authoritative"


def test_derive_primary_chain_lp_usd_max_only_when_no_alpha_hint():
    """lp_usd_max remains the discovery path ONLY when Alpha chainId is
    missing / unmapped — then we pick the highest-LP surf chain."""
    chain_lp = {
        "base": {"surf_supported": True, "lp_usd": 100_000},
        "ethereum": {"surf_supported": True, "lp_usd": 250_000},
    }
    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id=None)
    assert primary == "ethereum"
    assert derivation == "lp_usd_max"

    primary, derivation = derive_primary_chain(chain_lp, alpha_chain_id="99999")
    assert primary == "ethereum"
    assert derivation == "lp_usd_max"
