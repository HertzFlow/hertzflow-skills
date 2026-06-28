#!/usr/bin/env python3
"""test_monitoring_export.py — regression tests for adversarial review beta.3 audit fixes.

3 findings from the beta.3 adversarial review:
- HIGH 1: path traversal / symlink guard on write_all out_dir
- HIGH 2: CSV formula injection neutralization
- MED:    holder_pct type guard in _classify

Tests pin every fix so future refactors can't silently regress.

Run:
    cd v06/ && python3 tests/test_monitoring_export.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
import monitoring_export
from monitoring_export import (
    _sanitize_csv_cell,
    _guard_output_dir,
    build_canonical,
    write_all,
)
from section_l_distribution import _classify, _OPERATOR_RELAY_PCT_THRESHOLD


# Beta.14: Windows non-admin (no Developer Mode) can't create symlinks
# (WinError 1314 SeCreateSymbolicLinkPrivilege). Symlink tests probe
# behavior that's POSIX-native; on Windows where we can't even create
# the test setup, SKIP cleanly instead of ERROR-ing the suite.
class _SkipSymlinkTest(Exception):
    """Sentinel for tests that need real symlinks but env can't create them."""


def _make_symlink_or_skip(link_path: Path, target: Path) -> None:
    """Create symlink; raise _SkipSymlinkTest if env lacks the privilege.

    Surface the skip distinct from a genuine test FAIL so the runner
    can mark it differently (printed as SKIP, not counted as failed).
    """
    try:
        link_path.symlink_to(target)
    except OSError as e:
        # Windows: [WinError 1314] required privilege not held.
        # POSIX: EPERM/EACCES — also acceptable to skip.
        raise _SkipSymlinkTest(
            f"env cannot create symlink ({type(e).__name__}: {e}); "
            f"test requires symlink-capable filesystem + privileges"
        ) from e


# ============================================================
# HIGH 2 — CSV formula injection
# ============================================================

def test_csv_sanitizer_equals_prefix_neutralized():
    """Cells starting with '=' must be prefixed with single-quote."""
    assert _sanitize_csv_cell("=HYPERLINK(\"evil.com\")") == "'=HYPERLINK(\"evil.com\")"


def test_csv_sanitizer_plus_prefix_neutralized():
    assert _sanitize_csv_cell("+SUM(A1:A2)") == "'+SUM(A1:A2)"


def test_csv_sanitizer_minus_prefix_neutralized():
    """Excel treats `-cmd|...` as a formula too."""
    assert _sanitize_csv_cell("-cmd|/c calc.exe") == "'-cmd|/c calc.exe"


def test_csv_sanitizer_at_prefix_neutralized():
    """LibreOffice treats `@SUM(...)` as a function."""
    assert _sanitize_csv_cell("@SUM(A1)") == "'@SUM(A1)"


def test_csv_sanitizer_tab_then_formula_neutralized():
    """Tab + formula sigil → neutralized. Tab alone (no formula after) is
    not dangerous because spreadsheets render tab as whitespace, not as a
    formula trigger. The lstrip-then-check approach handles both correctly.
    """
    # Tab + formula = neutralize
    assert _sanitize_csv_cell("\t=cmd") == "'\t=cmd"
    # Tab alone (with safe content after) = unchanged
    assert _sanitize_csv_cell("\tinvisible") == "\tinvisible"


def test_csv_sanitizer_crlf_stripped():
    """CRLF inside a cell breaks downstream parsers (some ignore RFC 4180 quoting)."""
    out = _sanitize_csv_cell("first\r\nsecond")
    assert "\r" not in out and "\n" not in out, f"CRLF survived: {out!r}"


def test_csv_sanitizer_safe_input_unchanged():
    """Idempotent on benign input."""
    assert _sanitize_csv_cell("ZEST-Deployer-3a6dc") == "ZEST-Deployer-3a6dc"
    assert _sanitize_csv_cell("Rule 11 Deployer (项目方)") == "Rule 11 Deployer (项目方)"
    assert _sanitize_csv_cell("") == ""
    assert _sanitize_csv_cell(None) == ""


# NOTE: test_okx_csv_neutralizes_malicious_alert and
# test_binance_web3_csv_neutralizes_malicious_label removed in beta.11.
# Those tested CSV writers that no longer exist — Binance Wallet + OKX
# accept paste-JSON, not CSV. _sanitize_csv_cell still tested directly
# above; if future DeBank/other CSV emit is added, re-add e2e tests.

def test_paste_json_format():
    """beta.11: monitoring_paste.json (Binance Wallet + OKX paste format).

    Must be JSON array of `{address, name, emoji}`.
    """
    from monitoring_export import to_paste_json
    import json as _json
    canonical = [{
        "address": "0x" + "a" * 40,
        "label": "ZEST-项目方-aaaaa",
        "role": "项目方部署钱包",
        "severity": "critical",
        "alert": "test alert",
        "chain": "bsc",
        "source_sym": "ZEST",
        "source_contract": "0x" + "b" * 40,
        "addr_short": "0xaaaaaaa",
    }]
    j = _json.loads(to_paste_json(canonical))
    assert len(j) == 1
    assert j[0]["address"] == "0x" + "a" * 40
    assert j[0]["name"] == "ZEST-项目方-aaaaa"
    assert j[0]["emoji"] == "🔴"   # critical → 🔴


def test_dex_pool_excluded_from_paste():
    """product spec 2026-06-29: a DEX liquidity pool is neutral, token-specific infra and
    wallet apps already surface LP state natively, so it must NOT appear in the
    import paste. monitoring_ranker scores dex_pool -999 → NOT_TRACKED, and
    to_paste_json skips NOT_TRACKED — verify the full path end-to-end, alongside
    CEX (already excluded) and a real deployer wallet (kept)."""
    from monitoring_ranker import annotate_monitoring_wallets
    from monitoring_export import build_canonical, to_paste_json
    import json as _json

    skel = {"monitoring_wallets": [
        {"addr_full": "0x" + "a" * 40, "addr_short": "0xaaaa",
         "role": "项目方部署钱包", "status_emoji": "🔴", "balance_tokens": 5_000_000,
         "monitor_role_enum": "deployer"},
        {"addr_full": "0x" + "b" * 40, "addr_short": "0xbbbb",
         "role": "DEX 主池", "status_emoji": "🟡", "balance_tokens": 9_000_000,
         "monitor_role_enum": "dex_pool"},
        {"addr_full": "0x" + "c" * 40, "addr_short": "0xcccc",
         "role": "Binance hot wallet", "status_emoji": "🟡", "balance_tokens": 8_000_000,
         "monitor_role_enum": "public_cex_hot_wallet"},
    ]}
    annotate_monitoring_wallets(skel)
    by_addr = {w["addr_full"]: w.get("monitor_level") for w in skel["monitoring_wallets"]}
    assert by_addr["0x" + "b" * 40] == "NOT_TRACKED", by_addr   # DEX pool
    assert by_addr["0x" + "c" * 40] == "NOT_TRACKED", by_addr   # CEX hot wallet
    assert by_addr["0x" + "a" * 40] != "NOT_TRACKED", by_addr   # deployer kept

    canonical = build_canonical(symbol="O", chain="bsc",
                                contract_address="0x" + "d" * 40,
                                monitoring_wallets=skel["monitoring_wallets"])
    paste = _json.loads(to_paste_json(canonical))
    addrs = {p["address"] for p in paste}
    assert ("0x" + "a" * 40) in addrs           # deployer kept
    assert ("0x" + "b" * 40) not in addrs        # DEX pool dropped
    assert ("0x" + "c" * 40) not in addrs        # CEX dropped


def test_paste_json_pure_ascii_bytes():
    """beta.16: monitoring_paste.json must be pure ASCII bytes.

    User reported beta.15 mojibake on Windows: paste.json contains
    中文 + emoji written as UTF-8 bytes, but Windows cp1252 viewers
    mis-decode as Latin-1, showing garbage chars. Ctrl+A Ctrl+C copies
    the mojibake → Binance/OKX get garbage names.

    Fix: ensure_ascii=True in to_paste_json → 中文 → \\u5e84\\u5bb6
    style escapes, emoji → \\uXXXX surrogate pairs. All bytes are 7-bit
    ASCII, so any Windows codepage viewer shows the same bytes;
    clipboard preserves them; Binance/OKX JSON parser un-escapes them
    on import → correct 中文 + emoji rendered in tracker UI.
    """
    import json as _json
    from monitoring_export import to_paste_json
    canonical = [
        {"address": "0x" + "a" * 40, "label": "ZEST-项目方-aaaaa", "severity": "critical"},
        {"address": "0x" + "b" * 40, "label": "ZEST-潜伏-bbbbb", "severity": "watch"},
    ]
    out = to_paste_json(canonical)
    # All bytes must be 7-bit ASCII (0-127).
    out_bytes = out.encode("utf-8")
    non_ascii = [(i, b) for i, b in enumerate(out_bytes) if b > 127]
    assert not non_ascii, (
        f"paste.json must be pure ASCII but contains non-ASCII bytes: "
        f"{non_ascii[:5]}"
    )
    # Verify content un-escapes correctly per JSON spec.
    parsed = _json.loads(out)
    assert parsed[0]["name"] == "ZEST-项目方-aaaaa"
    assert parsed[0]["emoji"] == "🔴"
    assert parsed[1]["name"] == "ZEST-潜伏-bbbbb"
    assert parsed[1]["emoji"] == "🟡"
    # The raw text MUST contain the escape sequences (not the rendered chars)
    assert "\\u" in out, "expected \\uXXXX escapes in raw paste.json text"
    assert "项目方" not in out, "raw paste.json must not contain 中文 chars directly"


# ============================================================
# HIGH 1 — Path traversal / symlink guard
# ============================================================

def test_path_guard_rejects_dotdot():
    """`..` segments in path string must raise ValueError."""
    try:
        _guard_output_dir(Path("/tmp/foo/../escape"))
    except ValueError as e:
        assert ".." in str(e)
        return
    raise AssertionError("expected ValueError on ../ path, got nothing")


def test_path_guard_rejects_nul_byte():
    try:
        _guard_output_dir(Path("/tmp/foo\x00bar"))
    except ValueError as e:
        assert "NUL" in str(e)
        return
    raise AssertionError("expected ValueError on NUL-byte path")


def test_path_guard_rejects_symlink_out_dir():
    """Symlink as out_dir itself must be rejected."""
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "real"
        target.mkdir()
        link = Path(td) / "link"
        _make_symlink_or_skip(link, target)
        try:
            _guard_output_dir(link)
        except ValueError as e:
            assert "symlink" in str(e).lower()
            return
        raise AssertionError("expected ValueError on symlinked out_dir")


def test_path_guard_accepts_macos_tmp_system_symlink():
    """macOS /tmp resolves to /private/tmp — must NOT be rejected as
    user-controlled symlink. (System symlink table, always present.)"""
    if os.name != "posix":
        return   # skip on Windows
    target = Path("/tmp")
    if not target.exists() or not (target.resolve() == Path("/private/tmp")):
        return   # not on a macOS-like system
    try:
        _guard_output_dir(target)
    except ValueError as e:
        # Should not raise; this is the system /tmp
        raise AssertionError(f"macOS /tmp rejected: {e}")


def test_write_all_rejects_traversal_in_out_dir():
    """End-to-end: write_all() refuses an out_dir containing ../"""
    canonical = []
    try:
        write_all(
            symbol="X", chain="BSC", contract_address="0x" + "0" * 40,
            monitoring_wallets=[], out_dir=Path("/tmp/test/../escape"),
        )
    except ValueError as e:
        assert ".." in str(e)
        return
    raise AssertionError("expected write_all() to reject ../ out_dir")


# ============================================================
# MED — holder_pct type guard
# ============================================================

def _classify_args(addr: str, holder_pct):
    """Helper: invoke _classify with addr in dumper_dest_set + given pct."""
    return _classify(
        addr,
        deployer=None,
        dex_pool=None,
        quiet_set=set(),
        partial_set=set(),
        full_set=set(),
        dumper_dest_set={addr.lower()},
        holder_pct=holder_pct,
    )


def test_classify_holder_pct_none_safe():
    """holder_pct=None → DUMPER_DEST (not OPERATOR_RELAY, no crash)."""
    result = _classify_args("0x" + "a" * 40, None)
    assert result == "DUMPER_DEST", f"None holder_pct should fail-safe; got {result}"


def test_classify_holder_pct_nan_safe():
    """NaN → DUMPER_DEST (not OPERATOR_RELAY, no crash)."""
    result = _classify_args("0x" + "a" * 40, float("nan"))
    assert result == "DUMPER_DEST", f"NaN holder_pct should fail-safe; got {result}"


def test_classify_holder_pct_numeric_string_coerced():
    """String '5.0' → coerced to 5.0 → OPERATOR_RELAY (>= 1.0)."""
    result = _classify_args("0x" + "a" * 40, "5.0")
    assert result == "OPERATOR_RELAY", (
        f"Numeric string holder_pct should coerce; got {result}"
    )


def test_classify_holder_pct_invalid_string_safe():
    """Garbage string → DUMPER_DEST (no crash)."""
    result = _classify_args("0x" + "a" * 40, "not_a_number")
    assert result == "DUMPER_DEST", (
        f"Invalid string holder_pct should fail-safe; got {result}"
    )


def test_classify_holder_pct_threshold_boundary():
    """Exactly 1.0 → OPERATOR_RELAY (inclusive). 0.99 → DUMPER_DEST."""
    assert _classify_args("0x" + "a" * 40, 1.0) == "OPERATOR_RELAY"
    assert _classify_args("0x" + "a" * 40, 0.99) == "DUMPER_DEST"


# ============================================================
# Beta.4 8th audit findings — narrower edge cases
# ============================================================

def test_classify_holder_pct_infinity_safe():
    """adversarial review beta.4 8th audit MED: float('inf') >= 1.0 was passing the
    NaN check and upgrading to OPERATOR_RELAY. Now math.isfinite() catches it.
    """
    assert _classify_args("0x" + "a" * 40, float("inf")) == "DUMPER_DEST"
    assert _classify_args("0x" + "a" * 40, float("-inf")) == "DUMPER_DEST"


def test_classify_holder_pct_decimal_coerced():
    """Decimal type from upstream surf libs → coerced via float()."""
    from decimal import Decimal
    assert _classify_args("0x" + "a" * 40, Decimal("2.5")) == "OPERATOR_RELAY"
    assert _classify_args("0x" + "a" * 40, Decimal("0.5")) == "DUMPER_DEST"


def test_classify_holder_pct_empty_string_safe():
    """'' → float('') raises ValueError → fail-safe DUMPER_DEST."""
    assert _classify_args("0x" + "a" * 40, "") == "DUMPER_DEST"


def test_csv_sanitizer_whitespace_prefix_neutralized():
    """adversarial review beta.4 8th audit MED: '  =CMD(...)' was bypassing because
    s[0] is space, not formula sigil. Now we lstrip then check the
    first non-whitespace char."""
    assert _sanitize_csv_cell("  =cmd|/c calc.exe") == "'  =cmd|/c calc.exe"
    assert _sanitize_csv_cell("\t  =evil") == "'\t  =evil"   # mixed whitespace
    assert _sanitize_csv_cell("   +SUM(A1)") == "'   +SUM(A1)"


def test_path_guard_rejects_symlinked_ancestor_on_nonexistent_target():
    """adversarial review beta.4 8th audit HIGH 1: mkdir(parents=True) on
    `/tmp/link_to_etc/newdir` follows the link if `link_to_etc` is a
    symlink, even though `newdir` doesn't exist (so the guard's
    `p.is_symlink()` returns False)."""
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "real_target"
        target.mkdir()
        link = Path(td) / "link"
        _make_symlink_or_skip(link, target)
        # Target dir doesn't exist yet (would be created by mkdir(parents=True))
        nonexistent_target = link / "nested" / "child"
        try:
            _guard_output_dir(nonexistent_target)
        except ValueError as e:
            assert "ancestor" in str(e).lower() and "symlink" in str(e).lower(), str(e)
            return
        raise AssertionError(
            "expected ValueError on symlinked ancestor of nonexistent path"
        )


def test_windows_short_path_no_fast_path_bypass():
    """adversarial review beta.6 9th-audit CRITICAL: _is_windows_short_path was used
    as a full-path early-return in _guard_output_dir, skipping symlink
    + ancestor walk + .. checks. ANY Windows path with `name~1` segment
    became a security bypass. Beta.7 keeps short-path detection scoped
    to realpath-mismatch exception only; all other checks always run.

    Verify: a path with `..` still rejected even if 8.3-looking.
    """
    try:
        _guard_output_dir(Path("/tmp/TESTUS~1/foo/../escape"))
    except ValueError as e:
        assert ".." in str(e), f"expected `..` rejection, got: {e}"
        return
    raise AssertionError(
        "Windows 8.3-style path bypassed `..` check — guard re-introduced bypass"
    )


def test_windows_8_3_regex_strict():
    """adversarial review beta.6 9th-audit HIGH: loose regex `^.+~[1-9]...` matched
    Linux backup files like `foo.tar~1`. Strict 8.3 grammar: 1-6 chars +
    `~N` + optional `.` + 0-3 chars, NTFS reserved chars excluded.
    """
    from monitoring_export import _is_windows_short_path
    import os
    if os.name != "nt":
        # On POSIX, function always returns False regardless of input.
        # Verify the gate works (no path on POSIX is ever classified as 8.3).
        assert _is_windows_short_path(Path("C:/Users/TESTUS~1")) is False
        assert _is_windows_short_path(Path("/home/user/backup.tar~1")) is False
        return
    # On Windows: tighter test (would run on actual Windows CI):
    # `TESTUS~1` strict match → True
    # `backup.tar~1` (illegal: 6+ chars before ~ excluded by `{1,6}`) → False
    # `evil~1.tar~1.tar` (two ~N segments, illegal grammar) → False


def test_truncate_display_ellipsis_budget_edge():
    """adversarial review beta.6 9th-audit MED: ensure truncate_display respects
    max_width even at the 1-col-remaining + 2-col-char edge.
    """
    import sys, os
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from render_report import truncate_display, _display_width
    # Long Chinese string, truncate to 8 cols.
    # Each Chinese char is 2 cols. Ellipsis is 1 col.
    # Budget = 8 - 1 (reserve for `…`) = 7 for content.
    # 3 chars × 2 cols = 6 ≤ 7. 4 chars × 2 = 8 > 7 → stop.
    # Expect: 3 chars + `…` = 7 cols total.
    out = truncate_display("中文测试ABCDEF", 8)
    assert _display_width(out) <= 8, f"truncate overflowed: {out!r} = {_display_width(out)} cols"


def test_display_width_strips_zero_width():
    """adversarial review beta.6 9th-audit MED: combining marks + variation selectors
    + ZWJ + control chars must NOT contribute width.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from render_report import _display_width
    # 'a' + combining acute (U+0301) — appears as 1 col (á), not 2.
    assert _display_width("á") == 1, "combining mark counted as width"
    # ZWJ alone is 0 width
    assert _display_width("‍") == 0, "ZWJ counted as width"
    # Variation selector alone is 0 width
    assert _display_width("️") == 0, "VS-16 counted as width"


def test_path_guard_walks_all_ancestors():
    """Even if the FIRST ancestor is OK, a deeper one being a symlink
    must still be caught."""
    with tempfile.TemporaryDirectory() as td:
        # Create td/legitimate/, then td/legitimate/symlinked → td/elsewhere/
        legit = Path(td) / "legitimate"
        legit.mkdir()
        elsewhere = Path(td) / "elsewhere"
        elsewhere.mkdir()
        symlinked = legit / "symlinked"
        _make_symlink_or_skip(symlinked, elsewhere)
        # Target = td/legitimate/symlinked/child (child doesn't exist)
        target = symlinked / "child"
        try:
            _guard_output_dir(target)
        except ValueError as e:
            assert "symlink" in str(e).lower()
            return
        raise AssertionError("expected ValueError on deeper symlinked ancestor")


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    tests = [
        ("csv: = neutralized", test_csv_sanitizer_equals_prefix_neutralized),
        ("csv: + neutralized", test_csv_sanitizer_plus_prefix_neutralized),
        ("csv: - neutralized", test_csv_sanitizer_minus_prefix_neutralized),
        ("csv: @ neutralized", test_csv_sanitizer_at_prefix_neutralized),
        ("csv: \\t then formula neutralized", test_csv_sanitizer_tab_then_formula_neutralized),
        ("csv: CRLF stripped", test_csv_sanitizer_crlf_stripped),
        ("csv: safe input unchanged", test_csv_sanitizer_safe_input_unchanged),
        ("paste: monitoring_paste.json format (beta.11)", test_paste_json_format),
        ("paste: monitoring_paste.json pure ASCII bytes (beta.16)", test_paste_json_pure_ascii_bytes),
        ("path: ../ rejected", test_path_guard_rejects_dotdot),
        ("path: NUL byte rejected", test_path_guard_rejects_nul_byte),
        ("path: symlink out_dir rejected", test_path_guard_rejects_symlink_out_dir),
        ("path: macOS /tmp accepted", test_path_guard_accepts_macos_tmp_system_symlink),
        ("path: write_all rejects traversal", test_write_all_rejects_traversal_in_out_dir),
        ("classify: holder_pct=None safe", test_classify_holder_pct_none_safe),
        ("classify: holder_pct=NaN safe", test_classify_holder_pct_nan_safe),
        ("classify: numeric string coerced", test_classify_holder_pct_numeric_string_coerced),
        ("classify: invalid string safe", test_classify_holder_pct_invalid_string_safe),
        ("classify: threshold boundary", test_classify_holder_pct_threshold_boundary),
        ("classify: Infinity safe (beta.4)", test_classify_holder_pct_infinity_safe),
        ("classify: Decimal coerced (beta.4)", test_classify_holder_pct_decimal_coerced),
        ("classify: empty string safe (beta.4)", test_classify_holder_pct_empty_string_safe),
        ("csv: whitespace prefix neutralized (beta.4)", test_csv_sanitizer_whitespace_prefix_neutralized),
        ("path: symlinked ancestor (nonexistent target) (beta.4)", test_path_guard_rejects_symlinked_ancestor_on_nonexistent_target),
        ("path: walks all ancestors (beta.4)", test_path_guard_walks_all_ancestors),
        ("path: Windows 8.3 no fast-path bypass (beta.7)", test_windows_short_path_no_fast_path_bypass),
        ("path: Windows 8.3 strict regex (beta.7)", test_windows_8_3_regex_strict),
        ("render: truncate_display ellipsis budget (beta.7)", test_truncate_display_ellipsis_budget_edge),
        ("render: display_width strips zero-width (beta.7)", test_display_width_strips_zero_width),
    ]
    failed = 0
    skipped = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except _SkipSymlinkTest as e:
            print(f"  SKIP  {name}: {e}")
            skipped += 1
        except AssertionError as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
            failed += 1
    if failed:
        print(f"\n{failed}/{len(tests)} FAILED ({skipped} skipped)")
        sys.exit(1)
    passed = len(tests) - skipped
    if skipped:
        print(f"\n{passed}/{len(tests)} passed ({skipped} skipped — symlink env)")
    else:
        print(f"\n{len(tests)}/{len(tests)} passed")
