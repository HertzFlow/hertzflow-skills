#!/usr/bin/env python3
"""test_narrative_vs_locked.py — v0.6.4 V_NARRATIVE_VS_LOCKED_SEMANTIC.

Triggered by cross-LLM regression test on STAR 2026-05-25: two
independent LLMs (an LLM + adversarial review) both filled cex_trace.interpretation
with "perp 未确认" while locked tier == "S2" + Binance perp listing
row was present. Validator V_NARRATIVE_VS_LOCKED_SEMANTIC catches
this contradiction class.

Coverage:
  - 4 locked-condition rules (cex_trace.tier S2/S3, m6 empty,
    deployer.balance 0, cex_trace.tier S1)
  - Forbidden phrases: hits (must fire) + clean narratives (must pass)
  - P0-B negation lookback: refuted phrases (must skip)
"""

from __future__ import annotations

import sys
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))

from validate_report_data import Validator


def _build_filled_with(overrides: dict) -> dict:
    """Minimal filled dict for isolated semantic-check tests."""
    base = {
        "_schema_version": "0.6.4",
        "meta": {"symbol": "TEST", "name": "Test Token"},
        "cex_trace": {"tier": "S1", "rows": [], "interpretation": "placeholder narrative content."},
        "lineage": {"m6": {"rows": []}, "m4_notes": ["placeholder note about the supply chain."]},
        "holdings_distribution": {
            "role_rows": [
                {"role": "DEPLOYER", "total_balance": 0, "n_wallets": 0},
            ],
            "key_takeaways": ["distribution detail placeholder."],
        },
        "verdict": {"one_liner": "default placeholder verdict narrative content."},
        "anomaly": {"verdict_impact": "default impact narrative content goes here."},
        "alloc": {"interpretation": "default alloc interpretation content."},
    }
    # apply nested overrides via dotted path
    for path, value in overrides.items():
        cur = base
        parts = path.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value
    return base


def _has_error(errs, code):
    return any(code in e for e in errs)


def _run(filled):
    v = Validator()
    v.errors = []
    v._check_narrative_vs_locked_semantic(filled)
    return list(v.errors)


# -------------------- Rule 1: S2/S3 must not deny CEX catalyst --------------------

def test_s2_perp_未确认_fires():
    filled = _build_filled_with({
        "cex_trace.tier": "S2",
        "cex_trace.interpretation": "目前没有明确的 perp 等覆盖未在 snapshot 中确认, CEX 催化不突出.",
    })
    errs = _run(filled)
    assert _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"S2 + perp denial must trigger, got: {errs}"


def test_s3_no_perp_catalyst_fires():
    filled = _build_filled_with({
        "cex_trace.tier": "S3",
        "verdict.one_liner": "Token shows clean fundamentals but no perp catalyst expected near term.",
    })
    errs = _run(filled)
    assert _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"S3 + 'no perp catalyst' denial must trigger, got: {errs}"


def test_s2_with_catalyst_acknowledged_passes():
    filled = _build_filled_with({
        "cex_trace.tier": "S2",
        "cex_trace.interpretation": "Binance 永续 10 天前刚上线, 完成 S1→S2 升级, 属近期 CEX 催化已兑现.",
    })
    errs = _run(filled)
    assert not _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"S2 + catalyst-acknowledged narrative should pass, got: {errs}"


# -------------------- Rule 2: m6 empty must not claim active distribution --------------------

def test_m6_empty_claim_active_distribution_fires():
    filled = _build_filled_with({
        "lineage.m6.rows": [],
        "verdict.one_liner": "Rule 11 trace shows 内幕已确认派发, 多个地址在主动出货 of supply.",
    })
    errs = _run(filled)
    assert _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"m6 empty + claim active distribution must trigger, got: {errs}"


def test_m6_nonempty_claim_active_distribution_passes():
    filled = _build_filled_with({
        "lineage.m6.rows": [{"addr": "0xaaa"}, {"addr": "0xbbb"}],
        "verdict.one_liner": "Rule 11 trace 内幕已确认派发, 多个地址在主动出货, deserves caution.",
    })
    errs = _run(filled)
    assert not _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"m6 NON-empty + same narrative should pass, got: {errs}"


# -------------------- Rule 3: deployer balance 0 must not claim still-holding --------------------

def test_deployer_zero_claim_still_holding_fires():
    filled = _build_filled_with({
        "holdings_distribution.role_rows": [
            {"role": "DEPLOYER", "total_balance": 0, "n_wallets": 0},
        ],
        "alloc.interpretation": "项目方仍持有大量筹码 in the deployer wallet, indicating retained control.",
    })
    errs = _run(filled)
    assert _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"deployer=0 + claim still-holding must trigger, got: {errs}"


# -------------------- Rule 4: tier S1 must not claim perp listed --------------------

def test_s1_claim_perp_listed_fires():
    filled = _build_filled_with({
        "cex_trace.tier": "S1",
        "cex_trace.interpretation": "Token currently has 已上 Binance 永续 status, providing CEX catalyst.",
    })
    errs = _run(filled)
    assert _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"S1 + claim perp listed must trigger, got: {errs}"


# -------------------- P0-B negation lookback (FP guard) --------------------

def test_negation_并非_skips_match():
    filled = _build_filled_with({
        "cex_trace.tier": "S2",
        "cex_trace.interpretation": "本币 S2 完成, 并非无 cex 催化, 实际上 Binance 永续 10 天前已上.",
    })
    errs = _run(filled)
    assert not _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"refuted phrase via '并非' should not trigger, got: {errs}"


def test_negation_并不像_skips_match():
    filled = _build_filled_with({
        "cex_trace.tier": "S2",
        "verdict.one_liner": "Token healthy: 并不像 perp 未确认 那种状态, 已经在 5/14 上 Binance perp.",
    })
    errs = _run(filled)
    assert not _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"refuted phrase via '并不像' should not trigger, got: {errs}"


def test_negation_没有_skips_match():
    filled = _build_filled_with({
        "cex_trace.tier": "S2",
        "cex_trace.interpretation": "实际状态: 没有 perp 未确认 的情况, perp 已经上线 well before this snapshot.",
    })
    errs = _run(filled)
    assert not _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"refuted phrase via '没有' should not trigger, got: {errs}"


def test_real_violation_after_quoted_refutation_still_fires():
    """If text has BOTH a refuted occurrence AND an asserted one, we fire."""
    filled = _build_filled_with({
        "cex_trace.tier": "S2",
        "cex_trace.interpretation": (
            "有人之前说 '并非无 cex 催化', 但本次报告判断: 目前没有明确的近期 cex 催化, "
            "等待更进一步信号."
        ),
    })
    errs = _run(filled)
    # The second occurrence ("目前没有明确的近期 cex 催化") is asserted, not refuted
    assert _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"asserted phrase + earlier refuted phrase must still trigger, got: {errs}"


# -------------------- Locked predicate boundaries --------------------

def test_no_locked_condition_no_constraint():
    filled = _build_filled_with({
        "cex_trace.tier": None,  # tier not set
        "cex_trace.interpretation": "perp 未确认, no perp catalyst observed.",
    })
    errs = _run(filled)
    # tier=None doesn't match S1 or S2/S3, so no rule fires
    assert not _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"no locked condition triggered → no constraint, got: {errs}"


def test_short_narrative_skipped():
    filled = _build_filled_with({
        "cex_trace.tier": "S2",
        "cex_trace.interpretation": "perp 未上",  # < 30 chars
    })
    errs = _run(filled)
    # short narrative (< 30 chars) is skipped to avoid trivial-string FP
    assert not _has_error(errs, "V_NARRATIVE_VS_LOCKED_SEMANTIC"), \
        f"narrative < 30 chars should be skipped, got: {errs}"


# -------------------- main --------------------

if __name__ == "__main__":
    tests = [
        ("S2 + perp denial fires", test_s2_perp_未确认_fires),
        ("S3 + 'no perp catalyst' fires", test_s3_no_perp_catalyst_fires),
        ("S2 + catalyst acknowledged passes", test_s2_with_catalyst_acknowledged_passes),
        ("m6 empty + claim active distribution fires", test_m6_empty_claim_active_distribution_fires),
        ("m6 non-empty + same narrative passes", test_m6_nonempty_claim_active_distribution_passes),
        ("deployer=0 + claim still-holding fires", test_deployer_zero_claim_still_holding_fires),
        ("S1 + claim perp listed fires", test_s1_claim_perp_listed_fires),
        ("negation 并非 skips match", test_negation_并非_skips_match),
        ("negation 并不像 skips match", test_negation_并不像_skips_match),
        ("negation 没有 skips match", test_negation_没有_skips_match),
        ("real violation after quoted refutation still fires", test_real_violation_after_quoted_refutation_still_fires),
        ("no locked condition no constraint", test_no_locked_condition_no_constraint),
        ("short narrative skipped", test_short_narrative_skipped),
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
