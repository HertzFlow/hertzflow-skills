#!/usr/bin/env python3
"""test_anti_duplication.py — v0.6.1 anti-narrative-duplication validators.

Triggered by cross-LLM regression test: an LLM lazily filled 12 m6
rows with identical "项目方派发的内幕派发方" string, 5 section interpretations
all identical, 3 key_takeaways all the same. v0.6.1 adds 4 validators:

  V_NARRATIVE_DUPLICATION (m6.rows[].identity/status_narrative, >70%)
  V_INTERPRETATION_DUPLICATION (5 section interpretations, >60%)
  V_KEY_TAKEAWAYS_DUPLICATION (3 takeaways all identical)
  V_DETECTOR_DUPLICATION (4 detector_summary[].detail, >70%)
"""

from __future__ import annotations

import sys
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))

from validate_report_data import Validator


def _build_filled_with(overrides: dict) -> dict:
    """Build a minimal filled dict that passes all OTHER validators, so we
    can isolate anti-dup behavior. Other validators (locked invariance,
    META, etc) operate on different fields — they need the surrounding
    structure to be valid."""
    base = {
        "_schema_version": "0.6.0",
        "_field_authority": {"locked": [], "writable": []},
        "meta": {"symbol": "TEST"},
        "evidence_graph": {},
        "lineage": {"m6": {"rows": []}, "m4_notes": []},
        "anomaly": {"waves": [], "detector_summary": [], "rhythm": {}, "verdict_impact": "x" * 30},
        "monitoring_wallets": [],
        "verdict": {"enum": "ENTER", "one_liner": "x" * 30},
        "decision_action_block": {
            "immediate_action": {"action_enum": "buy", "narrative": "x" * 30},
            "stop_loss": {"trigger_price_usd": 1, "rationale": "x" * 30},
            "re_entry_conditions": [],
        },
        "holdings_distribution": {"role_rows": [], "key_takeaways": []},
        "monitoring_footer": "x" * 30,
        "multi_chain": {"interpretation": "x" * 30},
        "tge": {"interpretation": "x" * 30},
        "alloc": {"interpretation": "x" * 30},
        "cex_trace": {"interpretation": "x" * 30},
        "liq": {"interpretation": "x" * 30},
    }
    # Apply overrides deep-merged
    for k, v in overrides.items():
        if "." in k:
            parts = k.split(".")
            d = base
            for p in parts[:-1]:
                d = d.setdefault(p, {})
            d[parts[-1]] = v
        else:
            base[k] = v
    return base


def _has_error(errors: list[str], code: str) -> bool:
    return any(code in e for e in errors)


def test_m6_narrative_duplication_caught():
    """If 12 m6 rows all share identical identity_narrative, fail."""
    filled = _build_filled_with({})
    filled["lineage"]["m6"]["rows"] = [
        {
            "identity_narrative": "项目方派发的内幕受益方",
            "status_narrative": f"row {i} distinct status narrative content here.",
        }
        for i in range(12)
    ]
    v = Validator()
    errs = v.validate(filled, filled)
    assert _has_error(errs, "V_NARRATIVE_DUPLICATION"), (
        f"expected V_NARRATIVE_DUPLICATION, got: {errs}"
    )


def test_m6_narrative_variation_passes():
    """12 m6 rows with genuinely varied narratives must pass.

    v0.6.4: each row's narrative must differ in MORE than just an index
    or count — the v2 normalized-string anti-dup check fires on
    "上线前发现 N 个" boilerplate-with-fact-substitution evasion.
    """
    filled = _build_filled_with({})
    distinct_identities = [
        "deployer wallet itself, currently empty after distribution.",
        "DEX main pool address, holding LP-side reserves.",
        "early insider with mid-size allocation, dormant since launch.",
        "fully-exited dumper, moved all tokens to CEX hot wallet.",
        "operator relay hub, received from multiple Rule 11 receivers.",
        "vesting contract proxy holding locked supply.",
        "treasury multisig Safe for project funding.",
        "market maker desk, two-way quote provider.",
        "OTC counterparty receiving large block at TGE.",
        "airdrop distributor handling claim contract outflow.",
        "team allocation wallet with cliff schedule.",
        "advisor allocation wallet, dormant for half a year.",
    ]
    distinct_statuses = [
        "drained to zero balance within hours of mint.",
        "current reserves fluctuate with DEX trading volume.",
        "no outbound transfers observed in eight months window.",
        "last activity was bulk send to MEXC hot wallet.",
        "periodic small outflows to retail wallets observed.",
        "supply still time-locked until next year.",
        "treasury reserve operating under multi-signature governance.",
        "daily-volume-proportional swap activity throughout.",
        "single bulk transfer happened in TGE window only.",
        "drip distributions ongoing to airdrop claimants.",
        "cliff release scheduled for later this year.",
        "quiet since allocation, no signature activity at all.",
    ]
    filled["lineage"]["m6"]["rows"] = [
        {
            "identity_narrative": distinct_identities[i],
            "status_narrative": distinct_statuses[i],
        }
        for i in range(12)
    ]
    v = Validator()
    errs = v.validate(filled, filled)
    assert not _has_error(errs, "V_NARRATIVE_DUPLICATION"), (
        f"varied narratives should not trigger anti-dup, got: {errs}"
    )


def test_section_interpretations_duplication_caught():
    """5 section interpretations all the same → fail."""
    filled = _build_filled_with({})
    same = "本节数据已落地, 关键读数与结论推理一致. 详见证据图."
    filled["multi_chain"]["interpretation"] = same
    filled["tge"]["interpretation"] = same
    filled["alloc"]["interpretation"] = same
    filled["cex_trace"]["interpretation"] = same
    filled["liq"]["interpretation"] = same
    v = Validator()
    errs = v.validate(filled, filled)
    assert _has_error(errs, "V_INTERPRETATION_DUPLICATION"), (
        f"expected V_INTERPRETATION_DUPLICATION, got: {errs}"
    )


def test_section_interpretations_variation_passes():
    """5 distinct section interpretations must pass."""
    filled = _build_filled_with({})
    filled["multi_chain"]["interpretation"] = "multi_chain unique interpretation here for v0.6.1 test."
    filled["tge"]["interpretation"] = "tge unique interpretation about price anchoring data."
    filled["alloc"]["interpretation"] = "alloc unique interpretation about quiet wallets exposure."
    filled["cex_trace"]["interpretation"] = "cex_trace unique interpretation about Binance listing."
    filled["liq"]["interpretation"] = "liq unique interpretation about LP depth and slip cap."
    v = Validator()
    errs = v.validate(filled, filled)
    assert not _has_error(errs, "V_INTERPRETATION_DUPLICATION"), (
        f"varied interpretations should pass, got: {errs}"
    )


def test_key_takeaways_all_identical_caught():
    """3 holdings_distribution.key_takeaways all identical → fail."""
    filled = _build_filled_with({})
    same = "潜伏钱包 持仓占总供应 0.5%, 是未来抛压主要来源."
    filled["holdings_distribution"]["key_takeaways"] = [same, same, same]
    v = Validator()
    errs = v.validate(filled, filled)
    assert _has_error(errs, "V_KEY_TAKEAWAYS_DUPLICATION"), (
        f"expected V_KEY_TAKEAWAYS_DUPLICATION, got: {errs}"
    )


def test_key_takeaways_variation_passes():
    """3 distinct key_takeaways must pass."""
    filled = _build_filled_with({})
    filled["holdings_distribution"]["key_takeaways"] = [
        "takeaway 1: 庄家持 89% 供应是核心控盘度.",
        "takeaway 2: DEX 主池仅 $111K 流动性极薄.",
        "takeaway 3: 项目方 0 余额, 抛压来自庄家.",
    ]
    v = Validator()
    errs = v.validate(filled, filled)
    assert not _has_error(errs, "V_KEY_TAKEAWAYS_DUPLICATION"), (
        f"varied takeaways should pass, got: {errs}"
    )


def test_detector_summary_duplication_caught():
    """4 detector_summary[].detail all identical → fail."""
    filled = _build_filled_with({})
    same = "本类检测器命中, 已累计计数, 详见上方 anomaly.waves 列表."
    filled["anomaly"]["detector_summary"] = [
        {"detail": same} for _ in range(4)
    ]
    v = Validator()
    errs = v.validate(filled, filled)
    assert _has_error(errs, "V_DETECTOR_DUPLICATION"), (
        f"expected V_DETECTOR_DUPLICATION, got: {errs}"
    )


def test_too_few_items_no_check():
    """If lists are < min size, don't trigger anti-dup (insufficient data)."""
    filled = _build_filled_with({})
    # Only 2 m6 rows — too few to judge
    filled["lineage"]["m6"]["rows"] = [
        {"identity_narrative": "same", "status_narrative": "same"},
        {"identity_narrative": "same", "status_narrative": "same"},
    ]
    v = Validator()
    errs = v.validate(filled, filled)
    assert not _has_error(errs, "V_NARRATIVE_DUPLICATION"), (
        f"< 5 rows should skip anti-dup, got: {errs}"
    )


if __name__ == "__main__":
    tests = [
        ("m6 narrative duplication caught", test_m6_narrative_duplication_caught),
        ("m6 narrative variation passes", test_m6_narrative_variation_passes),
        ("section interpretations duplication caught", test_section_interpretations_duplication_caught),
        ("section interpretations variation passes", test_section_interpretations_variation_passes),
        ("key_takeaways all identical caught", test_key_takeaways_all_identical_caught),
        ("key_takeaways variation passes", test_key_takeaways_variation_passes),
        ("detector_summary duplication caught", test_detector_summary_duplication_caught),
        ("too few items no check", test_too_few_items_no_check),
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
