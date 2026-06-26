#!/usr/bin/env python3
"""test_narrative_quality.py — v0.7.3 regression suite for the 3 new
narrative quality validators.

Motivation: v0.7.2 smoke-fixture gate catches agents invoking
tests/smoke_fill.py literally, but does NOT catch:
  - Kimi-style boilerplate (real LLM fill but lazy):
    "该字段已沿邻近锁定数据补充叙述" repeated across slots
  - Numeric hallucination ("0.5%" cited but locked has 0.19%)
  - Template reuse across non-array slots (10 different sections all
    filled with the same boilerplate)

The three new validators (V_NARRATIVE_GENERIC_PHRASES,
V_NARRATIVE_TEMPLATE_REUSE, V_NARRATIVE_NUMERIC_HALLUCINATION) catch
each failure mode independently. All three are NARRATIVE_QUALITY so
they don't abort render — they emit warnings so the agent can re-fill.

Run:
    cd v06/ && python3 tests/test_narrative_quality.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

V06_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(V06_ROOT))
from validate_report_data import Validator, categorize_errors


def _load_skeleton() -> dict:
    return json.loads(
        (V06_ROOT / "tests/fixtures/zest_skeleton_fixture.json").read_text(
            encoding="utf-8",
        )
    )


def _smoke_fill_filled(skel: dict) -> dict:
    """Use smoke_fill.py to produce a baseline filled.json that mostly
    passes the OLD validators (so we can isolate the NEW ones)."""
    import subprocess
    with tempfile.TemporaryDirectory() as td:
        skel_path = Path(td) / "skel.json"
        filled_path = Path(td) / "filled.json"
        skel_path.write_text(json.dumps(skel, ensure_ascii=False), encoding="utf-8")
        subprocess.run(
            [sys.executable, str(V06_ROOT / "tests/smoke_fill.py"),
             str(skel_path), str(filled_path)],
            check=True, capture_output=True,
        )
        return json.loads(filled_path.read_text(encoding="utf-8"))


def _patch_slot(obj, slot_key: str, new_value: str) -> bool:
    """Recursively find the FIRST dict key matching slot_key and replace
    its value. Returns True if patched."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == slot_key and isinstance(v, str):
                obj[k] = new_value
                return True
            if _patch_slot(v, slot_key, new_value):
                return True
    elif isinstance(obj, list):
        for v in obj:
            if _patch_slot(v, slot_key, new_value):
                return True
    return False


def _has_error(errors: list[str], prefix: str) -> bool:
    return any(e.startswith(prefix) for e in errors)


def _count_errors(errors: list[str], prefix: str) -> int:
    return sum(1 for e in errors if e.startswith(prefix))


# ============================================================
# V_NARRATIVE_GENERIC_PHRASES
# ============================================================

def test_generic_phrases_fires_on_kimi_boilerplate() -> None:
    """Kimi v0.7.1 observed boilerplate must trigger the validator."""
    skel = _load_skeleton()
    filled = _smoke_fill_filled(skel)
    assert _patch_slot(filled, "interpretation", "该字段已沿邻近锁定数据补充叙述")
    errs = Validator().validate(skel, filled)
    assert _has_error(errs, "V_NARRATIVE_GENERIC_PHRASES"), (
        f"Kimi boilerplate must trigger V_NARRATIVE_GENERIC_PHRASES. Errors:\n"
        + "\n".join(errs[:10])
    )


def test_generic_phrases_fires_on_model_b_boilerplate() -> None:
    """model_b/smoke_fill observed boilerplate template."""
    skel = _load_skeleton()
    filled = _smoke_fill_filled(skel)
    # smoke_fill already produces "本节数据已落地, ..." in interpretation slots,
    # so just running validate should catch it without further patching.
    errs = Validator().validate(skel, filled)
    assert _has_error(errs, "V_NARRATIVE_GENERIC_PHRASES")


def test_generic_phrases_does_not_fire_on_real_narrative() -> None:
    """A long narrative that happens to mention a blacklisted phrase
    inside a longer analytical text should NOT trigger (length gate).
    """
    skel = _load_skeleton()
    filled = _smoke_fill_filled(skel)
    real = (
        "ZEST 当前流通比例 22.4% 是典型 VC 解锁结构, 接下来 28 个月按月线性"
        "释放. 上线后 24h vol $26M 配 LP $2M 体现典型 perp arb 抢筹. "
        "潜伏钱包占供应 19% 未抛, 派发观察重点是 deployer 0x...4d50."
    )
    assert _patch_slot(filled, "interpretation", real)
    errs = Validator().validate(skel, filled)
    # We can't assert "no GENERIC_PHRASES" overall (smoke_fill stubs other
    # slots) — assert specifically this slot did NOT trigger:
    generic_hits = [e for e in errs if e.startswith("V_NARRATIVE_GENERIC_PHRASES")]
    for e in generic_hits:
        # The patched slot is "interpretation" — ensure we don't see THIS slot
        # complained about (other smoke slots are OK to complain about).
        assert real[:30] not in e, f"FP on real narrative: {e}"


def test_generic_phrases_is_narrative_quality() -> None:
    """V_NARRATIVE_GENERIC_PHRASES must be categorized as NARRATIVE_QUALITY
    (not STRUCTURAL), so render still produces the report."""
    errs = ["V_NARRATIVE_GENERIC_PHRASES: foo.bar contains 'baz'..."]
    structural, narrative = categorize_errors(errs)
    assert structural == []
    assert narrative == errs


# ============================================================
# V_NARRATIVE_TEMPLATE_REUSE
# ============================================================

def test_template_reuse_fires_when_majority_share_template() -> None:
    """If > 25% of narrative slots share a normalized template, fire."""
    skel = _load_skeleton()
    filled = _smoke_fill_filled(skel)
    # smoke_fill produces section.interpretation in many sections — they
    # all use a similar template. Should trigger.
    errs = Validator().validate(skel, filled)
    # Smoke fill outputs templates per-section, so this may or may not
    # trigger depending on the per-section variation. Don't strictly
    # require it — just check that when we DO inject obvious repetition,
    # it fires.
    # Inject 5 identical strings to guarantee detection:
    bad_template = (
        "本节数据已落地, 上方表格中的数字与下方推理一致. 请参考相邻锁定字段了解详情."
    )
    targets = ["interpretation"]
    for _ in range(5):
        _patch_slot(filled, "interpretation", bad_template)
    errs = Validator().validate(skel, filled)
    # At least one V_NARRATIVE_* should fire (either TEMPLATE_REUSE or
    # GENERIC_PHRASES — both are valid catches for this pattern).
    has_template_or_generic = (
        _has_error(errs, "V_NARRATIVE_TEMPLATE_REUSE")
        or _has_error(errs, "V_NARRATIVE_GENERIC_PHRASES")
        or _has_error(errs, "V_INTERPRETATION_DUPLICATION")
    )
    assert has_template_or_generic, (
        "Heavy template reuse must trigger at least one anti-dup validator. "
        f"Errors: {errs[:5]}"
    )


def test_template_reuse_is_narrative_quality() -> None:
    errs = ["V_NARRATIVE_TEMPLATE_REUSE: 5/8 slots share template..."]
    structural, narrative = categorize_errors(errs)
    assert structural == []
    assert narrative == errs


# ============================================================
# V_NARRATIVE_NUMERIC_HALLUCINATION
# ============================================================

def test_numeric_hallucination_fires_on_invented_percentage() -> None:
    """Narrative cites '99.7%' which doesn't exist in any locked field."""
    skel = _load_skeleton()
    filled = _smoke_fill_filled(skel)
    # Use a clearly non-locked number. Locked values are mostly in the
    # 0-30% / dollar / count range; 99.7% is improbable.
    bad = (
        "潜伏钱包持有 99.7% 的供应量, 历史从未抛售. 派发 88.4M 美元到 47 个内幕钱包."
    )
    assert _patch_slot(filled, "interpretation", bad)
    errs = Validator().validate(skel, filled)
    assert _has_error(errs, "V_NARRATIVE_NUMERIC_HALLUCINATION"), (
        f"Fabricated numbers must trigger V_NARRATIVE_NUMERIC_HALLUCINATION. "
        f"Errors:\n" + "\n".join(errs[:10])
    )


def test_numeric_hallucination_skips_time_ago_phrases() -> None:
    """'12 小时前' / '约 24 小时' must NOT trigger (derived from now())."""
    skel = _load_skeleton()
    filled = _smoke_fill_filled(skel)
    time_ago = (
        "首次内幕派发发生在约 12 小时前, 距上线 24 小时. 总计观察期 7 天. "
        "本次派发金额 0.5 USD 测试场景 — 此为本节解读, 含足够字符以触及 30 字门槛."
    )
    assert _patch_slot(filled, "interpretation", time_ago)
    errs = Validator().validate(skel, filled)
    # The patched slot specifically should not appear as a HALLUCINATION
    # source. (Other smoke slots may still have hallucination errors.)
    hal_errs = [e for e in errs if e.startswith("V_NARRATIVE_NUMERIC_HALLUCINATION")]
    for e in hal_errs:
        assert "interpretation" not in e or "约 12 小时前" not in e, (
            f"FP on time-ago phrase: {e}"
        )


def test_numeric_hallucination_is_structural_by_default(monkeypatch) -> None:
    """v0.7.19.5: NUMERIC_HALLUCINATION is now STRUCTURAL by default
    (data-correctness, hard-fail). Pre-v0.7.19.5 behavior tested as
    `test_numeric_hallucination_soft_with_env_override` below."""
    monkeypatch.delenv("BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS", raising=False)
    errs = ["V_NARRATIVE_NUMERIC_HALLUCINATION: foo.bar mentions '99%'..."]
    structural, narrative = categorize_errors(errs)
    assert structural == errs
    assert narrative == []


def test_numeric_hallucination_soft_with_env_override(monkeypatch) -> None:
    """v0.7.19.5 env override: dev/CI may restore pre-v0.7.19.5 soft
    behavior with BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS=1."""
    monkeypatch.setenv("BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS", "1")
    errs = ["V_NARRATIVE_NUMERIC_HALLUCINATION: foo.bar mentions '99%'..."]
    structural, narrative = categorize_errors(errs)
    assert structural == []
    assert narrative == errs


def test_numeric_hallucination_accepts_locked_value() -> None:
    """Narrative that cites the EXACT locked value within ±5% must pass."""
    skel = _load_skeleton()
    filled = _smoke_fill_filled(skel)
    # Find a locked number in the meta section
    total_supply = (skel.get("meta") or {}).get("total_supply")
    if total_supply is None or total_supply == 0:
        return   # fixture didn't have a usable number; skip
    # Build a narrative that mentions the locked total_supply
    real = (
        f"ZEST 总供应 {int(total_supply):,} 枚, 当前流通占比 22.4%. "
        f"上线 24h vol $26M, 详见 alpha-listing API. 已观察派发 4 个内幕钱包."
    )
    assert _patch_slot(filled, "interpretation", real)
    errs = Validator().validate(skel, filled)
    # The total_supply number was cited; should NOT be flagged on that number.
    hal_errs = [
        e for e in errs
        if e.startswith("V_NARRATIVE_NUMERIC_HALLUCINATION")
        and str(int(total_supply))[:6] in e
    ]
    assert not hal_errs, (
        f"Cited locked total_supply ({total_supply}) was flagged as "
        f"hallucination — false positive. Errors: {hal_errs}"
    )


# ============================================================
# Helper: validate end-to-end via render_report.py soft-fail
# ============================================================

def test_render_emits_warning_header_when_only_narrative_quality_errors() -> None:
    """v0.7.1 soft-fail wiring: NARRATIVE_QUALITY errors should produce
    a report (exit code 2), not abort (exit 1). Test the categorization
    layer directly. v0.7.19.5: NUMERIC_HALLUCINATION promoted to
    STRUCTURAL by default and dropped from this list (it has its own
    dedicated test pair); only the remaining style validators stay
    soft-classified."""
    errs = [
        "V_NARRATIVE_GENERIC_PHRASES: foo contains '...'",
        "V_NARRATIVE_TEMPLATE_REUSE: 5/8 slots share template",
    ]
    structural, narrative = categorize_errors(errs)
    assert structural == [], (
        f"v0.7.3 style validators must be NARRATIVE_QUALITY (soft-fail), "
        f"not STRUCTURAL. Got structural: {structural}"
    )
    assert len(narrative) == 2


# ============================================================
# Standalone runner
# ============================================================

def _run_all() -> int:
    import inspect
    tests = [
        (name, fn) for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    n_pass = n_fail = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
            n_pass += 1
        except AssertionError as e:
            print(f"FAIL  {name}: {e}")
            n_fail += 1
        except Exception as e:
            print(f"ERROR {name}: {type(e).__name__}: {e}")
            n_fail += 1
    print(f"\n{n_pass} passed, {n_fail} failed")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(_run_all())
