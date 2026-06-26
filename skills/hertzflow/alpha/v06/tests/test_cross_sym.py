#!/usr/bin/env python3
"""test_cross_sym.py — v0.7 cross-sym helpers + validators.

Covers:
  - cross_sym_detector.detect — find candidates from registry + holders
  - pre_launch_insider_index.append_from_report / lookup — idempotent
  - identity_classifier.classify — 5 enum decision tree boundaries
  - V_CROSS_SYM_WHALES_INVARIANCE
  - V_CROSS_SYM_CLASSIFICATION_LOCKED
  - V_CROSS_SYM_NARRATIVE_MUST_CITE_EVIDENCE
  - V_CROSS_SYM_NARRATIVE_NO_FREELANCE_IDENTITY
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))
sys.path.insert(0, str(V06_DIR / "helpers"))

import cross_sym_detector
import pre_launch_insider_index as insider_idx
import identity_classifier
from validate_report_data import Validator


# ============================================================
# Detector tests
# ============================================================

def test_detector_finds_cross_sym_whale():
    registry = {
        "reverse_index": {
            "0xb589": [
                {"sym": "OPEN", "ca": "0xopen", "pct": 35.83, "rank": 1},
                {"sym": "TAC", "ca": "0xtac", "pct": 5.92, "rank": 4},
                {"sym": "MERL", "ca": "0xmerl", "pct": 5.41, "rank": 5},
            ],
        }
    }
    top_holders = [
        {"address": "0xb589", "percentage": 2.71, "balance": "135M"},
    ]
    cands = cross_sym_detector.detect("0xagt", top_holders, set(), registry)
    assert len(cands) == 1
    assert cands[0]["cross_sym_count"] == 3


def test_detector_filters_excluded():
    registry = {
        "reverse_index": {
            "0xb589": [
                {"sym": "OPEN", "ca": "0xopen", "pct": 35.83, "rank": 1},
                {"sym": "TAC", "ca": "0xtac", "pct": 5.92, "rank": 4},
                {"sym": "MERL", "ca": "0xmerl", "pct": 5.41, "rank": 5},
            ],
        }
    }
    top_holders = [{"address": "0xb589", "percentage": 2.71}]
    cands = cross_sym_detector.detect("0xagt", top_holders, {"0xb589"}, registry)
    assert cands == []


def test_detector_filters_labeled_entity():
    registry = {
        "reverse_index": {
            "0xb589": [
                {"sym": "OPEN", "ca": "0xopen", "pct": 35.83, "rank": 1},
                {"sym": "TAC", "ca": "0xtac", "pct": 5.92, "rank": 4},
                {"sym": "MERL", "ca": "0xmerl", "pct": 5.41, "rank": 5},
            ],
        }
    }
    top_holders = [{"address": "0xb589", "percentage": 2.71, "entity_name": "MEXC"}]
    cands = cross_sym_detector.detect("0xagt", top_holders, set(), registry)
    assert cands == []


def test_detector_dedupes_top_holders():
    registry = {"reverse_index": {
        "0xb589": [
            {"sym": "X", "ca": "0xx", "pct": 1, "rank": 1},
            {"sym": "Y", "ca": "0xy", "pct": 1, "rank": 1},
            {"sym": "Z", "ca": "0xz", "pct": 1, "rank": 1},
        ]}}
    # Same addr listed twice + once with case variation
    top_holders = [
        {"address": "0xb589", "percentage": 1},
        {"address": "0xB589", "percentage": 2.71},   # higher pct dup
        {"address": "0xb589", "percentage": 0.5},
    ]
    cands = cross_sym_detector.detect("0xagt", top_holders, set(), registry)
    assert len(cands) == 1
    assert cands[0]["this_token_pct"] == 2.71   # kept highest


def test_detector_handles_malformed_pct():
    """Defensive: non-numeric percentage doesn't crash."""
    registry = {"reverse_index": {}}
    top_holders = [
        {"address": "0xa", "percentage": "not a number"},
        {"address": "0xb", "percentage": None},
    ]
    cands = cross_sym_detector.detect("0xagt", top_holders, set(), registry)
    assert cands == []


def test_detector_max_candidates_cap():
    registry = {"reverse_index": {
        f"0x{i:040x}": [
            {"sym": "X", "ca": "0xx", "pct": 1, "rank": 1},
            {"sym": "Y", "ca": "0xy", "pct": 1, "rank": 1},
            {"sym": "Z", "ca": "0xz", "pct": 1, "rank": 1},
        ] for i in range(20)
    }}
    top_holders = [{"address": f"0x{i:040x}", "percentage": 1.0} for i in range(20)]
    cands = cross_sym_detector.detect("0xagt", top_holders, set(), registry, max_candidates=5)
    assert len(cands) == 5


# ============================================================
# Pre-launch insider index tests
# ============================================================

def test_insider_idx_append_and_lookup():
    with tempfile.TemporaryDirectory() as td:
        idx = Path(td) / "idx.json"
        lck = Path(td) / "idx.lock"
        insider_idx.append_from_report(
            "0x" + "a" * 40, "AAA",
            [
                {"addr": "0x" + "1" * 40, "dumped_pct": 0, "received_from_deployer": 1000, "current_balance": 1000},
                {"addr": "0x" + "2" * 40, "dumped_pct": 50, "received_from_deployer": 5000, "current_balance": 2500},
            ],
            index_path=idx, lock_path=lck,
        )
        hits = insider_idx.lookup("0x" + "1" * 40, index_path=idx)
        assert len(hits) == 1
        assert hits[0]["sym"] == "AAA"


def test_insider_idx_cross_token_lookup():
    with tempfile.TemporaryDirectory() as td:
        idx = Path(td) / "idx.json"
        lck = Path(td) / "idx.lock"
        insider_idx.append_from_report(
            "0x" + "a" * 40, "AAA",
            [{"addr": "0x" + "1" * 40, "dumped_pct": 0, "received_from_deployer": 1000, "current_balance": 1000}],
            index_path=idx, lock_path=lck,
        )
        insider_idx.append_from_report(
            "0x" + "b" * 40, "BBB",
            [{"addr": "0x" + "1" * 40, "dumped_pct": 50, "received_from_deployer": 5000, "current_balance": 2500}],
            index_path=idx, lock_path=lck,
        )
        hits = insider_idx.lookup("0x" + "1" * 40, index_path=idx)
        assert len(hits) == 2  # both AAA + BBB
        syms = {h["sym"] for h in hits}
        assert syms == {"AAA", "BBB"}


def test_insider_idx_idempotent_overwrite():
    with tempfile.TemporaryDirectory() as td:
        idx = Path(td) / "idx.json"
        lck = Path(td) / "idx.lock"
        insider_idx.append_from_report(
            "0x" + "a" * 40, "AAA",
            [
                {"addr": "0x" + "1" * 40, "dumped_pct": 0, "received_from_deployer": 1000, "current_balance": 1000},
                {"addr": "0x" + "2" * 40, "dumped_pct": 0, "received_from_deployer": 1000, "current_balance": 1000},
            ],
            index_path=idx, lock_path=lck,
        )
        # Re-append with only 1 addr (remove 0x2 from this token)
        insider_idx.append_from_report(
            "0x" + "a" * 40, "AAA",
            [{"addr": "0x" + "1" * 40, "dumped_pct": 80, "received_from_deployer": 1000, "current_balance": 200}],
            index_path=idx, lock_path=lck,
        )
        # 0x2 should be gone (idempotent token-level overwrite)
        assert insider_idx.lookup("0x" + "2" * 40, index_path=idx) == []
        # 0x1 should have updated dumped_pct
        hits = insider_idx.lookup("0x" + "1" * 40, index_path=idx)
        assert hits[0]["dumped_pct"] == 80


# ============================================================
# Identity classifier tests (decision tree)
# ============================================================

def test_classify_kol_manager_priority():
    """KOL_MANAGER triggers even if MM conditions also met."""
    sig = identity_classifier._empty_signature("0xa", 90)
    sig["bidirectional_lp_flow_ratio"] = 0.5
    sig["tx_count_90d"] = 80
    res = identity_classifier.classify(sig, cross_sym_count=5, pre_launch_insider_count=3)
    assert res["identity_enum"] == "KOL_MANAGER"
    assert res["confidence"] == 0.90


def test_classify_active_mm():
    sig = identity_classifier._empty_signature("0xa", 90)
    sig["bidirectional_lp_flow_ratio"] = 0.45
    sig["tx_count_90d"] = 65
    res = identity_classifier.classify(sig, cross_sym_count=2, pre_launch_insider_count=0)
    assert res["identity_enum"] == "ACTIVE_MM"


def test_classify_arb_desk():
    sig = identity_classifier._empty_signature("0xa", 90)
    sig["inflow_from_cex_pct"] = 0.5
    sig["outflow_to_cex_pct"] = 0.4
    sig["avg_hold_days"] = 3
    res = identity_classifier.classify(sig, cross_sym_count=1, pre_launch_insider_count=0)
    assert res["identity_enum"] == "ARB_DESK"


def test_classify_otc_desk():
    sig = identity_classifier._empty_signature("0xa", 90)
    sig["single_largest_inflow_pct"] = 0.8
    sig["tx_count_90d"] = 5
    res = identity_classifier.classify(sig, cross_sym_count=2, pre_launch_insider_count=0)
    assert res["identity_enum"] == "OTC_DESK"


def test_classify_unknown_high_cross_sym():
    sig = identity_classifier._empty_signature("0xa", 90)
    res = identity_classifier.classify(sig, cross_sym_count=8, pre_launch_insider_count=0)
    assert res["identity_enum"] == "UNKNOWN_WHALE_HIGH_CROSS_SYM"


def test_classify_insufficient_signal():
    sig = identity_classifier._empty_signature("0xa", 90)
    res = identity_classifier.classify(sig, cross_sym_count=2, pre_launch_insider_count=0)
    assert res["identity_enum"] == "INSUFFICIENT_SIGNAL"


def test_classify_threshold_boundary_inclusive():
    """v0.6.4 P2b fix: thresholds use >= /<= so boundary value triggers."""
    sig = identity_classifier._empty_signature("0xa", 90)
    sig["bidirectional_lp_flow_ratio"] = 0.40   # exactly threshold
    sig["tx_count_90d"] = 60                    # exactly threshold
    res = identity_classifier.classify(sig, cross_sym_count=1, pre_launch_insider_count=0)
    assert res["identity_enum"] == "ACTIVE_MM"


# ============================================================
# Validator tests (4 new V_CROSS_SYM_*)
# ============================================================

def _build_filled_with_whale(skel_enum="KOL_MANAGER", fill_enum=None,
                              fill_narrative="cross_sym_count=9, pre_launch_insider_count=3, KOL detected",
                              skel_addrs=None, fill_addrs=None):
    """Build a minimal skeleton + filled with cross_sym section."""
    base_addrs = skel_addrs or ["0xa" * 8 + "0" * 32]
    fill_a = fill_addrs or base_addrs
    skeleton = {
        "_schema_version": "0.7.0",
        "_field_authority": {"locked": [], "writable": []},
        "cross_sym": {
            "whales": [
                {
                    "address": a,
                    "this_token_pct": 2.71,
                    "this_token_balance": "100M",
                    "cross_sym_count": 9,
                    "cross_sym_tokens": [
                        {"sym": "OPEN", "ca": "0x1", "pct": 35.83, "rank": 1},
                    ],
                    "top_cross_sym_token": {"sym": "OPEN", "pct": 35.83},
                    "arkham_label": None,
                    "pre_launch_insider_count": 3,
                    "pre_launch_insider_tokens": [],
                    "behavior_signature": {"tx_count_90d": 50},
                    "identity_classification_enum": skel_enum,
                    "confidence_score": 0.90,
                    "evidence_required_fields": ["cross_sym_count", "pre_launch_insider_count", "pre_launch_insider_tokens"],
                }
                for a in base_addrs
            ],
        },
    }
    filled = {
        "_schema_version": "0.7.0",
        "cross_sym": {
            "whales": [
                {
                    "address": a,
                    "this_token_pct": 2.71,
                    "this_token_balance": "100M",
                    "cross_sym_count": 9,
                    "cross_sym_tokens": [
                        {"sym": "OPEN", "ca": "0x1", "pct": 35.83, "rank": 1},
                    ],
                    "top_cross_sym_token": {"sym": "OPEN", "pct": 35.83},
                    "arkham_label": None,
                    "pre_launch_insider_count": 3,
                    "pre_launch_insider_tokens": [],
                    "behavior_signature": {"tx_count_90d": 50},
                    "identity_classification_enum": fill_enum or skel_enum,
                    "confidence_score": 0.90,
                    "evidence_required_fields": ["cross_sym_count", "pre_launch_insider_count", "pre_launch_insider_tokens"],
                    "identity_narrative": fill_narrative,
                    "risk_assessment_narrative": "Risk narrative content here longer than 30 chars.",
                }
                for a in fill_a
            ],
        },
    }
    return skeleton, filled


def _has_error(errs, code):
    return any(code in e for e in errs)


def _run_cross_sym_validator_only(skeleton, filled):
    v = Validator()
    v.errors = []
    v._check_cross_sym_whales(skeleton, filled)
    return list(v.errors)


def test_v_invariance_addresses_match():
    skeleton, filled = _build_filled_with_whale()
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert not _has_error(errs, "V_CROSS_SYM_WHALES_INVARIANCE"), f"clean filled should pass: {errs}"


def test_v_invariance_addresses_mismatch_fires():
    skeleton, filled = _build_filled_with_whale(
        skel_addrs=["0xa" * 8 + "0" * 32],
        fill_addrs=["0xb" * 8 + "0" * 32],  # diff address
    )
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert _has_error(errs, "V_CROSS_SYM_WHALES_INVARIANCE")


def test_v_classification_locked_fires():
    skeleton, filled = _build_filled_with_whale(
        skel_enum="ARB_DESK",
        fill_enum="KOL_MANAGER",   # LLM tried to change identity!
    )
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert _has_error(errs, "V_CROSS_SYM_CLASSIFICATION_LOCKED")


def test_v_narrative_must_cite_evidence_fires_when_no_cites():
    skeleton, filled = _build_filled_with_whale(
        fill_narrative="This wallet looks suspicious in general but no specifics given.",
    )
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert _has_error(errs, "V_CROSS_SYM_NARRATIVE_MUST_CITE_EVIDENCE")


def test_v_narrative_must_cite_evidence_passes_with_field_names():
    skeleton, filled = _build_filled_with_whale(
        fill_narrative="This wallet has cross_sym_count of 9 and pre_launch_insider_count of 3 across multiple Alpha projects, matching KOL manager pattern.",
    )
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert not _has_error(errs, "V_CROSS_SYM_NARRATIVE_MUST_CITE_EVIDENCE"), errs


def test_v_narrative_must_cite_evidence_passes_with_numeric_values():
    """Citing the locked numeric value (e.g. '9 个其他 Alpha 币') counts as evidence."""
    skeleton, filled = _build_filled_with_whale(
        fill_narrative="该地址跨 9 个 Alpha 币持有, 上线前在 3 个项目拿到 deployer 筹码, 典型 KOL 操盘代理 pattern.",
    )
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert not _has_error(errs, "V_CROSS_SYM_NARRATIVE_MUST_CITE_EVIDENCE"), errs


def test_v_no_freelance_identity_fires_when_llm_says_arb_but_locked_kol():
    skeleton, filled = _build_filled_with_whale(
        fill_narrative="该地址跨 9 币 + 3 个项目预挖矿, 但行为看起来像跨所套利桌, 短期持仓多.",
    )
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert _has_error(errs, "V_CROSS_SYM_NARRATIVE_NO_FREELANCE_IDENTITY")


def test_v_no_freelance_identity_passes_when_narrative_consistent():
    skeleton, filled = _build_filled_with_whale(
        fill_narrative="该地址跨 9 个 Alpha 币 + 上线前在 3 个项目拿到 deployer 筹码, 是典型的 KOL 操盘代理.",
    )
    errs = _run_cross_sym_validator_only(skeleton, filled)
    assert not _has_error(errs, "V_CROSS_SYM_NARRATIVE_NO_FREELANCE_IDENTITY"), errs


# ============================================================
# main runner
# ============================================================

if __name__ == "__main__":
    tests = [
        ("detector finds cross-sym whale", test_detector_finds_cross_sym_whale),
        ("detector filters excluded", test_detector_filters_excluded),
        ("detector filters labeled entity", test_detector_filters_labeled_entity),
        ("detector dedupes top holders", test_detector_dedupes_top_holders),
        ("detector handles malformed pct", test_detector_handles_malformed_pct),
        ("detector max_candidates cap", test_detector_max_candidates_cap),
        ("insider idx append + lookup", test_insider_idx_append_and_lookup),
        ("insider idx cross-token lookup", test_insider_idx_cross_token_lookup),
        ("insider idx idempotent overwrite", test_insider_idx_idempotent_overwrite),
        ("classify KOL > MM priority", test_classify_kol_manager_priority),
        ("classify ACTIVE_MM", test_classify_active_mm),
        ("classify ARB_DESK", test_classify_arb_desk),
        ("classify OTC_DESK", test_classify_otc_desk),
        ("classify UNKNOWN", test_classify_unknown_high_cross_sym),
        ("classify INSUFFICIENT_SIGNAL", test_classify_insufficient_signal),
        ("classify threshold boundary inclusive (v0.6.4 P2b)", test_classify_threshold_boundary_inclusive),
        ("V invariance pass", test_v_invariance_addresses_match),
        ("V invariance mismatch fires", test_v_invariance_addresses_mismatch_fires),
        ("V classification_locked fires", test_v_classification_locked_fires),
        ("V narrative cite fires when missing", test_v_narrative_must_cite_evidence_fires_when_no_cites),
        ("V narrative cite passes with field names", test_v_narrative_must_cite_evidence_passes_with_field_names),
        ("V narrative cite passes with numeric values", test_v_narrative_must_cite_evidence_passes_with_numeric_values),
        ("V no_freelance fires when ARB vs KOL", test_v_no_freelance_identity_fires_when_llm_says_arb_but_locked_kol),
        ("V no_freelance passes when consistent", test_v_no_freelance_identity_passes_when_narrative_consistent),
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
            failed += 1
    if failed:
        print(f"\n{failed}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"\n{len(tests)}/{len(tests)} passed")
