#!/usr/bin/env python3
"""test_smoke_fill_gate.py — regression test for v0.7.2 smoke-fixture gate.

Cross-LLM acceptance testing of v0.7.1 found that agents (both adversarial review and
Claude) defaulted to invoking `tests/smoke_fill.py` as their LLM fill
step in production runs, producing reports full of NATO-suffix placeholder
stubs. v0.7.2 closes this at the renderer level by:

  1. Tagging smoke_fill output with `_smoke_test_fixture: true`.
  2. Render refuses (exit 3) on detection.
  3. Even if the flag is stripped, fingerprint detection on NATO-suffix
     stubs (≥3 distinct words) trips the same exit 3.
  4. Override is `BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1` (CI/E2E only).

These tests pin all four behaviors so a future refactor cannot silently
regress.

Run:
    cd v06/ && python3 -m pytest tests/test_smoke_fill_gate.py -v
    # or standalone:
    cd v06/ && python3 tests/test_smoke_fill_gate.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

V06_ROOT = Path(__file__).parent.parent
FIXTURE = V06_ROOT / "tests" / "fixtures" / "zest_skeleton_fixture.json"


def _run_smoke_fill(out_path: Path) -> int:
    """Invoke smoke_fill.py to produce a tagged filled.json."""
    cmd = [
        sys.executable,
        str(V06_ROOT / "tests" / "smoke_fill.py"),
        str(FIXTURE),
        str(out_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode


def _run_render(skeleton: Path, filled: Path, out: Path, env_extra: dict | None = None) -> tuple[int, str]:
    """Invoke render_report.py and return (exit_code, stderr_combined)."""
    cmd = [
        sys.executable,
        str(V06_ROOT / "render_report.py"),
        "--skeleton", str(skeleton),
        "--filled", str(filled),
        "--out", str(out),
    ]
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    # Disable update_check noise.
    env["BINANCE_ALPHA_NO_UPDATE_CHECK"] = "1"
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return proc.returncode, (proc.stderr or "") + (proc.stdout or "")


# ============================================================
# 1. smoke_fill output carries the gate flag
# ============================================================

def test_smoke_fill_injects_flag(tmp_path: Path) -> None:
    out = tmp_path / "filled.json"
    rc = _run_smoke_fill(out)
    assert rc == 0, "smoke_fill.py should exit 0"
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data.get("_smoke_test_fixture") is True, (
        "smoke_fill.py must inject _smoke_test_fixture: true at top level"
    )
    assert data.get("_smoke_generator") == "tests/smoke_fill.py", (
        "smoke_fill.py must inject _smoke_generator attribution"
    )


# ============================================================
# 2. Render refuses tagged fixture (exit 3)
# ============================================================

def test_render_refuses_flagged_smoke_fixture(tmp_path: Path) -> None:
    filled = tmp_path / "filled.json"
    assert _run_smoke_fill(filled) == 0
    out = tmp_path / "report.md"
    rc, log = _run_render(FIXTURE, filled, out)
    assert rc == 3, f"Render must exit 3 on flagged smoke fixture, got {rc}\n{log}"
    assert "REFUSED" in log
    assert "_smoke_test_fixture" in log
    assert not out.exists(), "Render must not write report.md when REFUSED"


# ============================================================
# 3. Fingerprint catches stripped flag (still exit 3)
# ============================================================

def test_render_fingerprint_catches_stripped_flag(tmp_path: Path) -> None:
    filled = tmp_path / "filled.json"
    assert _run_smoke_fill(filled) == 0
    # Adversary strips the gate flag, hoping render proceeds.
    data = json.loads(filled.read_text(encoding="utf-8"))
    data.pop("_smoke_test_fixture", None)
    data.pop("_smoke_generator", None)
    filled.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    out = tmp_path / "report.md"
    rc, log = _run_render(FIXTURE, filled, out)
    assert rc == 3, (
        f"Render must exit 3 on fingerprint match even when flag is "
        f"stripped, got {rc}\n{log}"
    )
    assert "NATO suffix fingerprint" in log
    assert not out.exists()


# ============================================================
# 4. Override env var lets CI proceed
# ============================================================

def test_render_override_requires_both_env_vars(tmp_path: Path) -> None:
    """v0.7.2 adversarial-review fix #3: single-flag override is rejected;
    BINANCE_ALPHA_SMOKE_OVERRIDE_REASON is required for audit trail.
    """
    filled = tmp_path / "filled.json"
    assert _run_smoke_fill(filled) == 0
    out = tmp_path / "report.md"
    # Flag without reason → REFUSED (must NOT silently allow).
    rc, log = _run_render(
        FIXTURE, filled, out,
        env_extra={"BINANCE_ALPHA_ALLOW_SMOKE_RENDER": "1"},
    )
    assert rc == 3, (
        f"Override flag without reason must REFUSE (audit-trail "
        f"requirement), got {rc}\n{log}"
    )
    assert "REASON" in log.upper() or "reason" in log
    assert not out.exists()


def test_render_override_with_reason_allows_smoke_fixture(tmp_path: Path) -> None:
    """Override with BOTH env vars set proceeds; reason text appears in
    the WARNING line for audit trail."""
    filled = tmp_path / "filled.json"
    assert _run_smoke_fill(filled) == 0
    out = tmp_path / "report.md"
    rc, log = _run_render(
        FIXTURE, filled, out,
        env_extra={
            "BINANCE_ALPHA_ALLOW_SMOKE_RENDER": "1",
            "BINANCE_ALPHA_SMOKE_OVERRIDE_REASON": "regression test fixture render",
            # v0.7.19.5: smoke fixture has stale numbers; NUMERIC_HALLUCINATION
            # is now structural-by-default. CI smoke flow opts in to soft.
            "BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS": "1",
        },
    )
    assert rc in (0, 2), (
        f"With both override vars set, render should produce report "
        f"(rc 0 or 2 for narrative warnings), got {rc}\n{log}"
    )
    assert "WARNING: rendering smoke test fixture" in log
    assert "regression test fixture render" in log, (
        "Audit trail: reason text must appear in WARNING line"
    )
    assert out.exists()


# ============================================================
# 5. Fingerprint helper: word-level de-dup (1 repeated word ≠ trip)
# ============================================================

def test_fingerprint_dedups_repeated_word() -> None:
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _count_nato_smoke_fingerprints
    # Same NATO word repeated 10 times = 1 distinct fingerprint (well below
    # the threshold of 3). Real narrative could mention "(alpha variant)"
    # once or twice in a discussion of testnet variants; that's fine.
    obj = {"narrative": "First (alpha variant). Then (alpha variant)."}
    assert _count_nato_smoke_fingerprints(obj) == 1


def test_fingerprint_counts_distinct_nato_words() -> None:
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _count_nato_smoke_fingerprints
    obj = {
        "a": "stub (alpha variant)",
        "b": ["another (bravo variant)", "third (charlie variant)"],
        "c": "fourth (delta variant)",
    }
    assert _count_nato_smoke_fingerprints(obj) == 4


def test_fingerprint_ignores_non_nato_words() -> None:
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _count_nato_smoke_fingerprints
    # "(testnet variant)" / "(staging variant)" are NOT NATO words → 0.
    obj = {
        "a": "deploy to (testnet variant) and (staging variant)",
        "b": "compare with (mainnet variant)",
    }
    assert _count_nato_smoke_fingerprints(obj) == 0


# ============================================================
# 6. v0.7.2 adversarial-review fix #1: bypass-evasion coverage
# ============================================================

def test_fingerprint_catches_uppercase_bypass() -> None:
    """Adversary tries '(Alpha variant)' / '(ALPHA VARIANT)' to evade
    lowercase-only regex. Casefold normalization must catch."""
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _count_nato_smoke_fingerprints
    obj = {
        "a": "stub (Alpha variant)",
        "b": "another (BRAVO VARIANT)",
        "c": "third (CharLie Variant)",
    }
    assert _count_nato_smoke_fingerprints(obj) == 3


def test_fingerprint_catches_whitespace_bypass() -> None:
    """Adversary tries '( alpha  variant )' / '(\\talpha\\tvariant\\t)' to
    evade single-space regex. \\s+ + IGNORECASE must catch."""
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _count_nato_smoke_fingerprints
    obj = {
        "a": "stub ( alpha  variant )",
        "b": "another (\tbravo\tvariant\t)",
        "c": "third (charlie    variant)",
    }
    assert _count_nato_smoke_fingerprints(obj) == 3


def test_fingerprint_catches_unicode_confusable_bypass() -> None:
    """Adversary tries Greek α / Cyrillic а / Cyrillic е homoglyphs to
    evade ASCII-only regex. Confusable substitution must catch."""
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _count_nato_smoke_fingerprints
    # "αlpha" = Greek α + ASCII "lpha" → normalizes to "alpha"
    # "brаvo" = ASCII "br" + Cyrillic а + ASCII "vo" → normalizes to "bravo"
    # "еcho"  = Cyrillic е + ASCII "cho" → normalizes to "echo"
    obj = {
        "a": "stub (αlpha variant)",   # Greek alpha
        "b": "another (brаvo variant)",  # Cyrillic a
        "c": "third (еcho variant)",   # Cyrillic e
    }
    assert _count_nato_smoke_fingerprints(obj) == 3


def test_fingerprint_catches_nbsp_bypass() -> None:
    """Adversary tries NBSP (U+00A0) inside the parens to evade \\s+."""
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _count_nato_smoke_fingerprints
    # NFKC normalizes NBSP → regular space, then \s+ catches it.
    obj = {
        "a": "stub (alpha variant)",   # NBSP between word and "variant"
        "b": "another (bravo variant)",
        "c": "third (charlie variant)",
    }
    assert _count_nato_smoke_fingerprints(obj) == 3


def test_fingerprint_normalization_is_idempotent() -> None:
    """Sanity: running normalize twice yields the same string."""
    sys.path.insert(0, str(V06_ROOT))
    from render_report import _normalize_for_fingerprint
    s = "(αLPHA Variant)"
    a = _normalize_for_fingerprint(s)
    b = _normalize_for_fingerprint(a)
    assert a == b, f"normalize not idempotent: {a!r} != {b!r}"


def _run_all() -> int:
    """Allow standalone invocation for environments without pytest."""
    import inspect
    tests = [
        (name, fn) for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    n_pass = n_fail = 0
    for name, fn in tests:
        sig = inspect.signature(fn)
        with tempfile.TemporaryDirectory() as td:
            try:
                if "tmp_path" in sig.parameters:
                    fn(Path(td))
                else:
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
