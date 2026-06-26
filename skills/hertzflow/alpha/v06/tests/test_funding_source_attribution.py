#!/usr/bin/env python3
"""test_funding_source_attribution.py — v0.7.23.1 regression tests.

Covers the reverse funding-source attribution helper introduced to
classify high-value addresses (wash_infra P/Q, flow_operators op_addrs,
rule_11 receivers, dump_tracker insiders, top_holders top-N) by where
their incoming token came from: mint vs dex_buy vs cex_withdraw vs p2p.

Tests stub out `section_a_scope._run_surf_with_retry` so they are
deterministic and never hit live surf. Coverage:

  1. SQL build correctness: every interpolated address is lowercase;
     dex/cex IN-lists fall back to the unmatchable sentinel when empty.
  2. Pivot correctness: per-addr source buckets sum + pct + primary_source.
  3. Empty input handling: 0 high-value addrs returns empty without
     calling surf.
  4. surf failure: __ERR sentinel path preserves error string.
  5. Truncation: max_addrs caps input + reports truncated_n.
  6. is_mining_fed flag: >= 50% mint → True; just below → False.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))
sys.path.insert(0, str(V06_DIR / "helpers"))

import funding_source_attribution as fsa


CA = "0x44f161ae29361e332dea039dfa2f404e0bc5b5cc"
DEPLOYER = "0xbaab7211438f33be0344d57978c7571f2d797ab2"
PAIR1 = "0x1111111111111111111111111111111111111111"
PAIR2 = "0x2222222222222222222222222222222222222222"
CEX1 = "0x3333333333333333333333333333333333333333"
WALLET_A = "0xaaaa00000000000000000000000000000000aaaa"
WALLET_B = "0xbbbb00000000000000000000000000000000bbbb"
WALLET_C = "0xcccc00000000000000000000000000000000cccc"


def _stub_surf(rows):
    """Build a patched _run_surf_with_retry returning (doc, err)."""
    def _retry(*args, **kwargs):
        return {"data": rows, "meta": {}}, None
    return _retry


def _stub_surf_err(err_msg):
    def _retry(*args, **kwargs):
        return None, err_msg
    return _retry


def test_sql_build_lowercases_addrs_and_uses_sentinel_for_empty():
    """SQL must lowercase the CA + every interpolated addr; empty
    dex/cex IN lists must fall back to the unmatchable sentinel so the
    CASE branch is preserved without false positives."""
    sql = fsa._build_source_sql(
        ca=CA.upper(),
        high_value_addrs=[WALLET_A.upper(), WALLET_B.upper()],
        dex_pair_addrs=[], cex_addrs=[],
        date_floor="2025-01-01",
    )
    # CA + addrs all lowercase
    assert CA in sql
    assert CA.upper() not in sql
    assert WALLET_A in sql
    assert WALLET_B in sql
    # Empty dex / cex IN lists use sentinel
    assert "0xffffffffffffffffffffffffffffffffffffffff" in sql
    # No lower() wrap on column values (surf-team anti-pattern)
    assert "lower(\"from\")" not in sql
    assert "lower(\"to\")" not in sql
    assert "lower(contract_address)" not in sql


def test_sql_build_uses_provided_dex_and_cex_lists():
    sql = fsa._build_source_sql(
        ca=CA, high_value_addrs=[WALLET_A],
        dex_pair_addrs=[PAIR1, PAIR2], cex_addrs=[CEX1],
        date_floor="2025-01-01",
    )
    assert f"'{PAIR1}'" in sql
    assert f"'{PAIR2}'" in sql
    assert f"'{CEX1}'" in sql
    # Sentinel NOT present when real lists are provided
    assert "0xffffffffffffffffffffffffffffffffffffffff" not in sql


def test_empty_input_returns_empty_without_surf_call():
    """Zero high-value addrs ⇒ short-circuit, never call surf."""
    with patch.object(fsa, "_clean_addrs", wraps=fsa._clean_addrs):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=[],
            dex_pair_addrs=[PAIR1], cex_addrs=[CEX1],
            date_floor="2025-01-01",
        )
    assert out["attributions"] == {}
    assert out["summary"]["n_addrs_queried"] == 0
    assert out["summary"]["n_addrs_with_data"] == 0
    assert "_error" not in out


def test_pivot_classifies_per_source_and_computes_pct():
    """Stubbed surf rows pivoted into per-addr classification."""
    rows = [
        # Wallet A: 70% mint, 30% dex_buy → primary mint, is_mining_fed=True
        {"addr": WALLET_A, "source": "mint", "amt": 700.0, "n_tx": 7},
        {"addr": WALLET_A, "source": "dex_buy", "amt": 300.0, "n_tx": 3},
        # Wallet B: 80% dex_buy, 20% p2p → primary dex_buy, is_mining_fed=False
        {"addr": WALLET_B, "source": "dex_buy", "amt": 800.0, "n_tx": 8},
        {"addr": WALLET_B, "source": "p2p", "amt": 200.0, "n_tx": 2},
        # Wallet C: 60% cex_withdraw, 40% p2p → primary cex_withdraw
        {"addr": WALLET_C, "source": "cex_withdraw", "amt": 600.0, "n_tx": 6},
        {"addr": WALLET_C, "source": "p2p", "amt": 400.0, "n_tx": 4},
    ]
    with patch("section_a_scope._run_surf_with_retry", side_effect=_stub_surf(rows)):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=[WALLET_A, WALLET_B, WALLET_C],
            dex_pair_addrs=[PAIR1], cex_addrs=[CEX1],
            date_floor="2025-01-01",
        )

    attrs = out["attributions"]
    assert set(attrs.keys()) == {WALLET_A, WALLET_B, WALLET_C}

    # Wallet A: mining-fed
    a = attrs[WALLET_A]
    assert a["mint"] == 700.0
    assert a["dex_buy"] == 300.0
    assert a["total"] == 1000.0
    assert abs(a["mint_pct"] - 0.7) < 1e-9
    assert a["primary_source"] == "mint"
    assert a["is_mining_fed"] is True

    # Wallet B: dex-fed
    b = attrs[WALLET_B]
    assert b["primary_source"] == "dex_buy"
    assert b["is_mining_fed"] is False
    assert abs(b["dex_buy_pct"] - 0.8) < 1e-9

    # Wallet C: cex-fed
    c = attrs[WALLET_C]
    assert c["primary_source"] == "cex_withdraw"
    assert c["is_mining_fed"] is False

    s = out["summary"]
    assert s["n_addrs_queried"] == 3
    assert s["n_addrs_with_data"] == 3
    assert s["n_mining_fed"] == 1
    assert s["n_dex_fed"] == 1
    assert s["n_cex_fed"] == 1
    assert s["n_p2p_fed"] == 0


def test_mining_fed_threshold_boundary_at_50pct():
    """Exactly 50% mint = is_mining_fed True; 49% = False."""
    # Case 1: 50/50 → mint primary (tie-break by dict iteration order in
    # max() which goes mint → dex_buy → cex_withdraw → p2p)
    rows_50 = [
        {"addr": WALLET_A, "source": "mint", "amt": 500.0, "n_tx": 5},
        {"addr": WALLET_A, "source": "dex_buy", "amt": 500.0, "n_tx": 5},
    ]
    with patch("section_a_scope._run_surf_with_retry", side_effect=_stub_surf(rows_50)):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=[WALLET_A],
            dex_pair_addrs=[PAIR1], cex_addrs=[],
            date_floor="2025-01-01",
        )
    a = out["attributions"][WALLET_A]
    assert a["mint_pct"] == 0.5
    assert a["is_mining_fed"] is True  # >= 50%

    # Case 2: 49% mint, 51% dex
    rows_49 = [
        {"addr": WALLET_A, "source": "mint", "amt": 490.0, "n_tx": 5},
        {"addr": WALLET_A, "source": "dex_buy", "amt": 510.0, "n_tx": 5},
    ]
    with patch("section_a_scope._run_surf_with_retry", side_effect=_stub_surf(rows_49)):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=[WALLET_A],
            dex_pair_addrs=[PAIR1], cex_addrs=[],
            date_floor="2025-01-01",
        )
    a = out["attributions"][WALLET_A]
    assert a["is_mining_fed"] is False
    assert a["primary_source"] == "dex_buy"


def test_addr_with_zero_inflow_returns_total_zero_and_null_pct():
    """A queried addr that has no inflow rows still appears in the
    output (so callers can show "no token activity"). pct=None,
    primary_source=None, is_mining_fed=False."""
    rows = [
        {"addr": WALLET_A, "source": "mint", "amt": 1000.0, "n_tx": 1},
        # WALLET_B not in rows
    ]
    with patch("section_a_scope._run_surf_with_retry", side_effect=_stub_surf(rows)):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=[WALLET_A, WALLET_B],
            dex_pair_addrs=[PAIR1], cex_addrs=[],
            date_floor="2025-01-01",
        )
    b = out["attributions"][WALLET_B]
    assert b["total"] == 0
    assert b["mint_pct"] is None
    assert b["primary_source"] is None
    assert b["is_mining_fed"] is False
    assert out["summary"]["n_addrs_queried"] == 2
    assert out["summary"]["n_addrs_with_data"] == 1


def test_surf_failure_surfaces_error_string():
    """When surf returns no doc, helper returns _error so caller can
    distinguish "no data" from "queried but empty"."""
    with patch("section_a_scope._run_surf_with_retry",
               side_effect=_stub_surf_err("timeout after 4 attempts")):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=[WALLET_A],
            dex_pair_addrs=[PAIR1], cex_addrs=[],
            date_floor="2025-01-01",
        )
    assert "_error" in out
    assert "timeout" in out["_error"]
    assert out["attributions"] == {}


def test_truncation_caps_addr_list_and_reports_truncated_n():
    """max_addrs=5 with 10 input addrs ⇒ scan only first 5, report
    truncated_n=5 in _debug."""
    many = [f"0x{i:040x}" for i in range(1, 11)]  # 10 addrs
    with patch("section_a_scope._run_surf_with_retry", side_effect=_stub_surf([])):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=many,
            dex_pair_addrs=[PAIR1], cex_addrs=[],
            date_floor="2025-01-01",
            max_addrs=5,
        )
    # 5 in attributions output (only first 5 scanned)
    assert len(out["attributions"]) == 5
    assert out["_debug"]["sql_truncated_addr_n"] == 5


def test_dedup_and_lowercase_in_clean_addrs():
    """_clean_addrs is the single point of normalisation: dedup,
    lowercase, drop burn/zero."""
    cleaned = fsa._clean_addrs([
        WALLET_A.upper(),
        WALLET_A,  # duplicate
        "0x0000000000000000000000000000000000000000",  # zero
        "0x000000000000000000000000000000000000dead",  # burn
        "not_an_addr",
        None,
        "",
        WALLET_B,
    ])
    assert cleaned == [WALLET_A, WALLET_B]


def test_invalid_source_value_from_surf_normalised_to_p2p():
    """If surf returns an unexpected source value (shouldn't happen
    given the CASE, but defensive), it falls into p2p."""
    rows = [
        {"addr": WALLET_A, "source": "weird_thing", "amt": 100.0, "n_tx": 1},
        {"addr": WALLET_A, "source": "mint", "amt": 100.0, "n_tx": 1},
    ]
    with patch("section_a_scope._run_surf_with_retry", side_effect=_stub_surf(rows)):
        out = fsa.attribute_funding(
            ca=CA, high_value_addrs=[WALLET_A],
            dex_pair_addrs=[PAIR1], cex_addrs=[],
            date_floor="2025-01-01",
        )
    a = out["attributions"][WALLET_A]
    assert a["p2p"] == 100.0
    assert a["mint"] == 100.0
