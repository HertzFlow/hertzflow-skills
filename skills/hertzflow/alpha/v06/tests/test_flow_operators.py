#!/usr/bin/env python3
"""test_flow_operators.py — v0.7.21 flow_operator_detector regression.

Pins down the documented thresholds in `v0721_DESIGN.md` and guards the
SQL hygiene (validated addr / date format → no injection via IN-list).
"""
from __future__ import annotations

import sys
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))
sys.path.insert(0, str(V06_DIR / "helpers"))

import pytest
import flow_operator_detector as fod


# ---- Threshold constants are pre-committed -----------------------------

def test_thresholds_match_design_doc():
    """Thresholds in flow_operator_detector must match v0721_DESIGN.md.
    Per project methodology M35 we pre-register; this test refuses silent tuning.
    """
    assert fod.MIN_TX_THIS_TOKEN == 200
    assert fod.MAX_TX_FROM_DIVERSITY == 0.05
    assert fod.MIN_TOP2_RATIO == 0.80
    assert fod.MIN_CROSS_ALPHA_TOKENS == 5
    assert fod.MAX_NET_BALANCE_PCT == 0.5


# ---- Input validation guards (SQL injection prevention) ----------------

def test_validate_inputs_rejects_bad_ca():
    with pytest.raises(fod.FlowOperatorError):
        fod._validate_inputs(
            "not-an-address", ["0x" + "a" * 40], "2025-07-30"
        )


def test_validate_inputs_rejects_bad_date():
    with pytest.raises(fod.FlowOperatorError):
        fod._validate_inputs(
            "0x" + "a" * 40, ["0x" + "b" * 40], "invalid-date"
        )


def test_validate_inputs_rejects_sql_injection_in_date():
    """A trailing newline + injected SQL must not pass the regex gate."""
    with pytest.raises(fod.FlowOperatorError):
        fod._validate_inputs(
            "0x" + "a" * 40, ["0x" + "b" * 40], "2025-07-30\n' OR 1=1 --"
        )


def test_validate_inputs_drops_bad_candidate_addrs():
    """Bad candidate addresses are silently dropped (no exception);
    the survivors are deduped lower-case 0x40-hex.
    """
    clean = fod._validate_inputs(
        "0x" + "a" * 40,
        [
            "0x" + "b" * 40,          # valid
            "0x" + "B" * 40,          # same as previous (case)
            "not-an-address",         # bad
            "0x" + "c" * 39,          # too short
            None,                     # None
            "",                       # empty
            "0x" + "c" * 40,          # valid 2nd
        ],
        "2025-07-30",
    )
    assert clean == ["0x" + "b" * 40, "0x" + "c" * 40]


# ---- Arkham classification ---------------------------------------------

@pytest.mark.parametrize("label,entity,etype,expected", [
    ("DexRouter", None, None, "router"),
    ("OKX Universal Router", "OKX", "dex", "router"),
    ("Uniswap V3 Router", None, "dex", "router"),
    ("Aggregator", None, None, "router"),
    ("Binance Deposit", "Binance", "cex", "cex"),
    ("KuCoin Hot Wallet", "KuCoin", "cex", "cex"),
    ("XT.com Deposit", None, None, "cex"),
    ("Vesting (Proxy)", None, None, "other"),
    ("Random NFT Contract", None, None, "other"),
    (None, None, None, "eoa"),
    ("", "", "", "eoa"),
])
def test_arkham_classify(label, entity, etype, expected):
    assert fod._arkham_classify(label, etype, entity) == expected


# ---- Detect path (with mocked SQL + Arkham) ----------------------------

def test_detect_empty_candidates_returns_empty():
    """No candidates → empty operators + 0 credits, never raise."""
    ops, credits = fod.detect(
        ca="0x" + "a" * 40,
        candidate_addrs=[],
        listing_date="2025-07-30",
        total_supply=5_000_000_000,
    )
    assert ops == []
    assert credits == 0


def test_detect_play_known_positive(monkeypatch):
    """v0.7.21 driver case: PLAY 0x865166 must be detected as
    DEX_ARB_BOT + CROSS_ALPHA_OPERATOR with the documented thresholds.

    Uses synthetic SQL responses that mirror the live values we measured
    (tx_from_diversity ≈ 0.001, 2022 tx, top-2 counterparties both
    routers, 31 Alpha-token cross hits).
    """
    PLAY_CA = "0x853a7c99227499dba9db8c3a02aa691afdebf841"
    X = "0x865166dca4519a0aee3fe30db27dd5de799d7c5c"
    P = "0xc8f6b8ba0dc0f175b568b99440b0867f69a29265"   # DexRouter (router)
    Q = "0x411d2c093e4c2e69bf0d8e94be1bf13dadd879c6"   # OKX router (router)

    # Mock _run_sql to return canned responses keyed by SQL fingerprint.
    def fake_run_sql(sql, max_rows=500):
        if "unique_origins" in sql and "n_tx" in sql:
            # subject-token stats
            return [{
                "addr": X,
                "unique_origins": 2,
                "n_tx": 2022,
                "tok_in": 2920342.0,
                "tok_out": 2694500.0,
            }], 5
        if "counterparty" in sql and "GROUP BY addr, counterparty" in sql:
            # top counterparties on this token
            return [
                {"addr": X, "counterparty": P, "n": 1078},
                {"addr": X, "counterparty": Q, "n": 821},
                {"addr": X, "counterparty": "0x42781ec558f9fb95f5e080572bcd0a37523b55e2", "n": 74},
            ], 5
        if "GROUP BY addr, ca" in sql:
            # v0.7.21.2: per-Alpha-token breakdown SQL — need ≥5 tokens
            # for CROSS_ALPHA_OPERATOR sub-class (MIN_CROSS_ALPHA_TOKENS).
            return [
                {"addr": X, "ca": "0x" + "1" * 40, "n_tx": 3056},
                {"addr": X, "ca": "0x" + "2" * 40, "n_tx": 3052},
                {"addr": X, "ca": "0x" + "3" * 40, "n_tx": 3033},
                {"addr": X, "ca": "0x" + "4" * 40, "n_tx": 2922},
                {"addr": X, "ca": "0x" + "5" * 40, "n_tx": 1852},
                {"addr": X, "ca": "0x" + "6" * 40, "n_tx": 100},
            ], 5
        if "n_alpha_tokens" in sql:
            # Legacy v0.7.21 path (kept for callers that haven't migrated).
            return [{"addr": X, "n_alpha_tokens": 31}], 5
        if "n_tokens" in sql:
            # all-token cross-token count
            return [{"addr": X, "n_tokens": 91, "n_tx": 56918}], 5
        return [], 0

    def fake_labels(addrs):
        return {
            P.lower(): {"label_text": "DexRouter", "entity_name": None,
                        "entity_type": None},
            Q.lower(): {"label_text": "OKX Universal Router",
                        "entity_name": "OKX",
                        "entity_type": "dex"},
        }

    monkeypatch.setattr(fod, "_run_sql", fake_run_sql)
    monkeypatch.setattr(fod, "_fetch_arkham_labels", fake_labels)

    # v0.7.21.2: pass sym map so cross_alpha_tokens carries readable names.
    sym_map = {
        "0x" + "1" * 40: "NEX",
        "0x" + "2" * 40: "ESPORTS",
        "0x" + "3" * 40: "SKYAI",
        "0x" + "4" * 40: "TOKEN",
        "0x" + "5" * 40: "PEAQ",
        "0x" + "6" * 40: "GUA",
    }
    ops, credits = fod.detect(
        ca=PLAY_CA,
        candidate_addrs=[X],
        listing_date="2025-07-30",
        total_supply=5_000_000_000,
        alpha_token_cas_base=set(sym_map.keys()),
        alpha_ca_to_sym_base=sym_map,
    )
    assert len(ops) == 1
    op = ops[0]
    assert op["addr"] == X
    assert op["sub_class"] in ("DEX_ARB_BOT", "CROSS_ALPHA_OPERATOR")
    assert "DEX_ARB_BOT" in op["sub_classes_all"]
    assert "CROSS_ALPHA_OPERATOR" in op["sub_classes_all"]
    assert op["n_tx_this_token"] == 2022
    assert op["tx_from_diversity"] < 0.05
    assert op["counterparty_top2_ratio"] >= 0.80
    assert op["cross_alpha_token_count"] == 6
    assert credits > 0
    # v0.7.21.1: narrative placeholders.
    assert op["identity_narrative"] == "<LLM_NARRATIVE_PLACEHOLDER>"
    assert op["risk_assessment_narrative"] == "<LLM_NARRATIVE_PLACEHOLDER>"
    # v0.7.21.2: per-Alpha-token breakdown with sym + chain + n_tx, sorted DESC.
    tokens = op["cross_alpha_tokens"]
    assert len(tokens) == 6
    assert [t["sym"] for t in tokens] == ["NEX", "ESPORTS", "SKYAI", "TOKEN", "PEAQ", "GUA"]
    # Sorted DESC by n_tx
    for i in range(len(tokens) - 1):
        assert tokens[i]["n_tx"] >= tokens[i + 1]["n_tx"]
    assert all("chain" in t for t in tokens)


def test_detect_rejects_high_diversity(monkeypatch):
    """A wallet with tx_from_diversity 0.07 (above threshold) must NOT
    be detected even if every other signal triggers.
    """
    X = "0x" + "1" * 40

    def fake_run_sql(sql, max_rows=500):
        if "unique_origins" in sql:
            return [{
                "addr": X,
                "unique_origins": 140,   # 140 / 2000 = 0.07 > 0.05
                "n_tx": 2000,
                "tok_in": 100.0,
                "tok_out": 100.0,
            }], 5
        return [], 0

    monkeypatch.setattr(fod, "_run_sql", fake_run_sql)
    monkeypatch.setattr(fod, "_fetch_arkham_labels", lambda addrs: {})

    ops, _ = fod.detect(
        ca="0x" + "a" * 40,
        candidate_addrs=[X],
        listing_date="2025-07-30",
        total_supply=5_000_000_000,
    )
    assert ops == []


def test_detect_rejects_high_balance(monkeypatch):
    """A wallet that passes diversity + tx count but holds > 0.5% of
    supply is a genuine holder, not a bot — must be excluded.
    """
    X = "0x" + "1" * 40
    total_supply = 1_000_000

    def fake_run_sql(sql, max_rows=500):
        if "unique_origins" in sql:
            return [{
                "addr": X,
                "unique_origins": 1,
                "n_tx": 500,
                "tok_in": 10_000.0,    # 1% of supply
                "tok_out": 0.0,         # net = 1%
            }], 5
        return [], 0

    monkeypatch.setattr(fod, "_run_sql", fake_run_sql)
    monkeypatch.setattr(fod, "_fetch_arkham_labels", lambda addrs: {})

    ops, _ = fod.detect(
        ca="0x" + "a" * 40,
        candidate_addrs=[X],
        listing_date="2025-07-30",
        total_supply=total_supply,
    )
    assert ops == []
