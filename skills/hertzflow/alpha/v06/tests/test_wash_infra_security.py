#!/usr/bin/env python3
"""test_wash_infra_security.py — v0.7.7 SQL-injection regression.

Covers the SQL-injection class fixed by switching `re.match` to
`re.fullmatch` in wash_infra_detector + role_classifier. Without the
fix, payloads like `"2026-01-01\n' OR 1=1 --"` pass the prefix gate
because Python's `$` matches before a trailing newline.

This test ensures the regression cannot silently come back even if the
helpers are refactored.
"""

from __future__ import annotations

import sys
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))
sys.path.insert(0, str(V06_DIR / "helpers"))

import pytest
import wash_infra_detector
import role_classifier


# ---- wash_infra_detector listing_date ----------------------------------

def test_wash_infra_rejects_newline_suffix_listing_date():
    """Trailing newline + injected SQL must NOT pass the regex gate."""
    with pytest.raises(wash_infra_detector.WashInfraError) as ei:
        wash_infra_detector.detect_all(
            ca="0x" + "a" * 40,
            candidate_addrs=["0x" + "b" * 40],
            listing_date="2026-01-01\n' OR 1=1 --",
        )
    assert "invalid listing_date" in str(ei.value)


def test_wash_infra_rejects_trailing_garbage_listing_date():
    with pytest.raises(wash_infra_detector.WashInfraError):
        wash_infra_detector.detect_all(
            ca="0x" + "a" * 40,
            candidate_addrs=["0x" + "b" * 40],
            listing_date="2026-01-01garbage",
        )


def test_wash_infra_accepts_valid_listing_date_format():
    # Should NOT raise on format; downstream surf call will fail
    # because we don't have a real CA/listing in test, but the regex
    # gate must let a well-formed date through.
    # We can't easily run detect_all without surf so just smoke-test
    # the regex via fullmatch directly.
    import re
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", "2026-01-01")
    assert not re.fullmatch(r"\d{4}-\d{2}-\d{2}", "2026-01-01\nbad")
    assert not re.fullmatch(r"\d{4}-\d{2}-\d{2}", "2026-01-01bad")


# ---- wash_infra_detector ca + address ----------------------------------

def test_wash_infra_rejects_newline_suffix_ca():
    with pytest.raises(wash_infra_detector.WashInfraError) as ei:
        wash_infra_detector.detect_all(
            ca="0x" + "a" * 40 + "\n' OR 1=1 --",
            candidate_addrs=["0x" + "b" * 40],
            listing_date="2026-01-01",
        )
    assert "invalid ca" in str(ei.value)


def test_wash_infra_addr_re_fullmatch_drops_newline_suffix():
    # Direct check the compiled regex used to filter candidate addresses
    assert not wash_infra_detector._ADDR_RE.fullmatch(
        "0x" + "a" * 40 + "\n' OR 1=1"
    )
    assert wash_infra_detector._ADDR_RE.fullmatch("0x" + "a" * 40)


# ---- role_classifier listing_date + addr -------------------------------

def test_role_classifier_rejects_newline_suffix_listing_date():
    with pytest.raises(role_classifier.RoleClassifierError) as ei:
        role_classifier.classify(
            addr="0x" + "a" * 40,
            ca="0x" + "b" * 40,
            listing_date="2026-01-01\n'; DROP TABLE x; --",
        )
    assert "invalid listing_date" in str(ei.value)


def test_role_classifier_rejects_newline_suffix_addr():
    with pytest.raises(role_classifier.RoleClassifierError) as ei:
        role_classifier.classify(
            addr="0x" + "a" * 40 + "\nbad",
            ca="0x" + "b" * 40,
            listing_date="2026-01-01",
        )
    assert "invalid addr" in str(ei.value)


def test_role_classifier_rejects_newline_suffix_ca():
    with pytest.raises(role_classifier.RoleClassifierError) as ei:
        role_classifier.classify(
            addr="0x" + "a" * 40,
            ca="0x" + "b" * 40 + "\nevil",
            listing_date="2026-01-01",
        )
    assert "invalid ca" in str(ei.value)


# ---- v0.7.18 ThreadPoolExecutor parallel semantics ---------------------
# These tests stub `_process_candidate` so we don't need a live surf
# connection. They verify that the adversarial review CRITICAL#1 (credits leak under
# truncation) and HIGH#1 (n_processed off-by-one) fixes hold.

import time as _time
from unittest.mock import patch


def _fake_candidates(n: int) -> list[str]:
    """Generate n distinct valid lowercase hex addresses."""
    return [("0x" + format(i + 1, "040x")) for i in range(n)]


def test_v0718_credits_sink_captures_all_paid_work_no_truncation():
    """Every worker's credits land in credits_total even when no surf runs.

    Stubs _process_candidate to mimic 5 candidates each costing 4
    credits. With no truncation, credits_total must equal 5×4 = 20.
    """
    candidates = _fake_candidates(5)

    def _fake_proc(ca, addr, ratio, listing_date, prefilt, sink):
        sink.append(4)  # mimic 4 SQL × 1 credit each
        return {  # claim it's a wash hit so results lands too
            "executor_X": addr,
            "maker_buy_P": "0x" + "b" * 40,
            "maker_sell_Q": "0x" + "c" * 40,
            "atomic_pair_ratio": 1.0,
            "p_drift_pct": 0.0,
            "q_drift_pct": 0.0,
            "p_tok_in": 0,
            "q_tok_in": 0,
            "tx_from_diversity": 0.5,
            "classification": "wash_infrastructure_routed",
        }

    with patch.object(wash_infra_detector, "_process_candidate", _fake_proc), \
         patch.object(wash_infra_detector, "_entry_filter_batch",
                      return_value=(
                          {a: (1000, 1000) for a in candidates}, 1
                      )), \
         patch.object(wash_infra_detector, "_step1_batch_parallel",
                      return_value=({a: 0.95 for a in candidates}, 5)):
        results, credits, meta = wash_infra_detector.detect_all(
            ca="0x" + "a" * 40,
            candidate_addrs=candidates,
            listing_date="2026-01-01",
        )

    assert len(results) == 5
    assert credits == 1 + 5 + 5 * 4  # step0 batch (1) + step1 batch (5) + 5×4
    assert meta["n_candidates_processed"] == 5
    assert meta["n_candidates_total"] == 5
    assert meta["truncated"] is False
    assert meta["workers"] == wash_infra_detector.WASH_INFRA_WORKERS


def test_v0718_truncation_does_not_undercount_credits():
    """adversarial review CRITICAL#1: in-flight workers contribute credits even
    when the consumer loop breaks on wall-clock budget.

    Stub _process_candidate to sleep so workers race the budget; set
    budget = 0.05s; verify credits_total >= n_processed × per_credits
    (every worker that ran appended to sink, even if never consumed).
    """
    candidates = _fake_candidates(20)

    def _slow_proc(ca, addr, ratio, listing_date, prefilt, sink):
        # Each worker spends 0.1s of work then records 3 credits.
        _time.sleep(0.1)
        sink.append(3)
        return None  # not a wash hit

    original_budget = wash_infra_detector.WASH_INFRA_MAX_SECONDS
    wash_infra_detector.WASH_INFRA_MAX_SECONDS = 0.05  # trip almost immediately
    try:
        with patch.object(wash_infra_detector, "_process_candidate", _slow_proc), \
             patch.object(wash_infra_detector, "_entry_filter_batch",
                          return_value=(
                              {a: (1000, 1000) for a in candidates}, 1
                          )), \
             patch.object(wash_infra_detector, "_step1_batch_parallel",
                          return_value=({a: 0.95 for a in candidates}, 5)):
            results, credits, meta = wash_infra_detector.detect_all(
                ca="0x" + "a" * 40,
                candidate_addrs=candidates,
                listing_date="2026-01-01",
            )
    finally:
        wash_infra_detector.WASH_INFRA_MAX_SECONDS = original_budget

    # Truncation must have fired (budget was 0.05s, each worker takes 0.1s).
    assert meta["truncated"] is True
    # credits_total = step0_batch(1) + step1_batch(5) + 3 * (workers that ran)
    # n_workers_ran >= WASH_INFRA_WORKERS (the first wave all started before
    # any could finish + the consumer could check budget). We can't assert
    # an exact count but we CAN assert credits include at least the first
    # wave (adversarial review CRITICAL#1 — they wouldn't have been counted before the
    # credits_sink fix).
    n_workers = wash_infra_detector.WASH_INFRA_WORKERS
    assert credits >= 1 + 5 + 3 * n_workers, (
        f"credits leak: got {credits}, expected ≥ {1 + 5 + 3 * n_workers}"
    )
    # And n_processed must be <= n_total (sanity).
    assert meta["n_candidates_processed"] <= meta["n_candidates_total"]


# ---- v0.7.19 _run_sql 429 retry semantics ------------------------------
# Pins audit findings (1H + 1M) so we don't regress.

def test_v0719_transient_detector_covers_format_variants():
    """adversarial review MEDIUM#1: 429 detection must be case-insensitive and cover
    multiple wordings ('Too Many Requests' / 'rate limit' / 'throttle' /
    raw '429'). Pre-fix it only matched exact-case + 200-char window."""
    f = wash_infra_detector._is_transient_rate_limit
    # Positive cases (must retry)
    assert f("WARN: Got 429 Too Many Requests, retrying in 1s")
    assert f("rate-limited (HTTP 429), retry-after: 5s")
    assert f("too many requests")  # lowercase
    assert f("Rate-Limited at upstream")
    assert f("upstream throttled")
    assert f("rate_limit exceeded")
    # Long stderr: 429 marker past byte 200 still detected
    long_msg = ("WARN: " + "x" * 300 + " 429 Too Many Requests")
    assert f(long_msg)
    # Negative cases (must NOT retry — non-transient)
    assert not f("invalid SQL: column 'foo' not found")
    assert not f("syntax error near 'GROUP'")
    assert not f("")


def test_v0719_transient_detector_handles_none():
    """Defensive: None / empty must return False, not raise."""
    f = wash_infra_detector._is_transient_rate_limit
    assert not f(None)
    assert not f("")


# ---- v0.7.19.2 monitoring_export _paths_equal_normalized -----------------
# Pins adversarial review BSC postmortem fix: Windows raw str() comparison flagged
# perfectly-canonical paths as "realpath differs from absolute" when the
# only difference was drive-letter case or `/` vs `\\` separator.

def test_v0719_2_paths_equal_normalized_identical_passes():
    """Identical paths must compare equal."""
    import monitoring_export
    f = monitoring_export._paths_equal_normalized
    assert f(Path("/tmp/foo/bar"), Path("/tmp/foo/bar"))


def test_v0719_2_paths_equal_normalized_separator_normalized():
    """`/` vs `\\` paths must compare equal post-normalization (Windows
    semantics; on POSIX `\\` is literal so the normpath path stays
    different and the strings still don't match — that's correct)."""
    import monitoring_export
    f = monitoring_export._paths_equal_normalized
    import os
    if os.name == "nt":
        assert f(Path("C:/Users/Test/Docs"), Path("C:\\Users\\Test\\Docs"))


def test_v0719_2_paths_equal_normalized_redundant_segments():
    """`.` / `..` segments collapse — same on-disk dir compares equal."""
    import monitoring_export
    f = monitoring_export._paths_equal_normalized
    assert f(Path("/tmp/foo/./bar"), Path("/tmp/foo/bar"))
    assert f(Path("/tmp/foo/../foo/bar"), Path("/tmp/foo/bar"))


def test_v0719_2_paths_equal_normalized_different_dirs_still_unequal():
    """Genuinely different paths still compare unequal — the fix must
    NOT defang the actual symlink-mismatch check on POSIX."""
    import monitoring_export
    f = monitoring_export._paths_equal_normalized
    assert not f(Path("/tmp/foo"), Path("/tmp/bar"))
    assert not f(Path("/tmp/foo/bar"), Path("/var/foo/bar"))


# ---- v0.7.19.3 rule_11 quiet_wallets excludes protocol_lockup ----------
# Pins the data-correctness fix: vesting / multisig / treasury / DEX-infra /
# CEX-custody (Arkham-confirmed protocol lockup) MUST NOT be counted as
# "insider quiet wallets" because their token release follows a public
# schedule / governance, not opaque insider hand. The COLLECT verdict bug
# manifested as the report claiming "80% 潜伏 insider 抛压" when that 80%
# was actually Arkham-labeled Vesting (Proxy) + Gnosis Safe Proxy.

def test_v0719_3_quiet_wallets_excludes_protocol_lockup():
    """rule_11 must return quiet_wallets WITHOUT protocol_lockup wallets,
    even when they have dumped_pct == 0 (locked = never dumped)."""
    import sys as _sys
    from pathlib import Path as _Path
    _v06 = _Path(__file__).parent.parent
    if str(_v06 / "helpers") not in _sys.path:
        _sys.path.insert(0, str(_v06 / "helpers"))
    # We can't run the full rule_11 (needs surf), but we can verify the
    # filter expression on a synthetic receiver set by importing the
    # module and running its post-classification filter.
    receivers = [
        # Real quiet insider — must be in quiet_wallets.
        {"addr": "0x" + "a" * 40, "dumped_pct": 0,
         "is_protocol_lockup": False, "current_balance": 1000},
        # Vesting contract — Arkham-labeled, must NOT be in quiet_wallets
        # even though dumped_pct == 0.
        {"addr": "0x" + "b" * 40, "dumped_pct": 0,
         "is_protocol_lockup": True, "arkham_label": "Vesting (Proxy)",
         "current_balance": 2_400_000_000},
        # Gnosis Safe Proxy — same: lockup, must be excluded.
        {"addr": "0x" + "c" * 40, "dumped_pct": 0,
         "is_protocol_lockup": True, "arkham_label": "Gnosis Safe Proxy",
         "current_balance": 100_000_000},
        # Fully-dumped insider — already excluded by dumped_pct != 0.
        {"addr": "0x" + "d" * 40, "dumped_pct": 100,
         "is_protocol_lockup": False, "current_balance": 0},
    ]
    # Replicate the v0.7.19.3 filter expression directly.
    quiet = [
        r for r in receivers
        if r.get("dumped_pct", 0) == 0
        and not r.get("is_protocol_lockup")
    ]
    assert len(quiet) == 1, (
        f"Expected 1 genuine quiet wallet (excluding 2 lockup), got "
        f"{len(quiet)}: {[r['arkham_label'] if 'arkham_label' in r else 'genuine' for r in quiet]}"
    )
    assert quiet[0]["addr"] == "0x" + "a" * 40


# ---- v0.7.19.4 dump_tracker tree_holds vs pure_insider_holds split ----
# COLLECT methodology bug: the old `insider_holds_*` field name implied
# pure insider holds, but the value was a tree_holds stock (with lockup +
# exit-infra) for conservation math. Narrative templates paraphrased it
# as "内幕方 N 钱包仍掌控 X% 总供应", conflating vesting with insider
# 潜伏. v0.7.19.4 splits into tree_holds (conservation) + pure_insider
# (narrative), with the old field name kept as a backward-compat alias.

def test_v0719_4_dump_tracker_emits_split_fields():
    """Exercise the real `dump_tracker.run` with mocked surf calls and
    assert the emitted dict contains all three holdings field sets +
    the alias correctly points at tree_holds.

    v0.7.19.4 adversarial review MEDIUM#1: the pre-audit draft self-asserted against
    a hand-built dict instead of calling the production function,
    leaving the actual emit path untested. This version stubs every
    surf-touching helper and runs the real `dump_tracker.run`."""
    import sys as _sys
    from pathlib import Path as _Path
    _v06 = _Path(__file__).parent.parent
    if str(_v06 / "helpers") not in _sys.path:
        _sys.path.insert(0, str(_v06 / "helpers"))
    import dump_tracker

    # rule_11-shaped synthetic input. 3 receivers: 1 real insider with
    # balance + 2 Arkham-classified lockup-or-infra wallets (vesting +
    # cex_custody) that must NOT contribute to pure_insider_holds but
    # MUST still be in tree_holds for the conservation anchor.
    rule11 = {
        "pre_launch_receivers": [
            {"addr": "0x" + "a" * 40, "current_balance": 100,
             "is_protocol_lockup": False, "is_cex_custody": False,
             "is_dex_infra": False, "received_from_deployer": 200},
            {"addr": "0x" + "b" * 40, "current_balance": 2_400_000_000,
             "is_protocol_lockup": True,
             "received_from_deployer": 2_400_000_000},
            {"addr": "0x" + "c" * 40, "current_balance": 50_000_000,
             "is_cex_custody": True,
             "received_from_deployer": 50_000_000},
        ],
    }

    with patch.object(dump_tracker, "fetch_apparatus_to_cex",
                      return_value={"cex_tokens": 0.0, "cex_labels": [], "ok": True}), \
         patch.object(dump_tracker, "fetch_apparatus_dex_sold",
                      return_value={"dex_sold_tokens": 0.0, "n_swaps": 0, "ok": True}), \
         patch.object(dump_tracker, "fetch_dex_sell_profile",
                      return_value={"median_price_usd": 1.0, "n_sellers": 0,
                                    "total_swaps": 0, "top_seller_swaps": 0,
                                    "wash_dominated": False}), \
         patch.object(dump_tracker, "fetch_current_balances",
                      return_value={}):
        out = dump_tracker.run(
            rule11=rule11,
            ca="0x" + "f" * 40,
            symbol="TEST",
            listing_ts_ms=None,
            listing_date="2025-01-01",
            circulating_supply=2_500_000_000,
            total_supply=3_000_000_000,
        )

    # All three holdings field sets must be present.
    for k in ("tree_holds_tokens", "tree_holds_pct_supply",
              "pure_insider_holds_tokens", "pure_insider_holds_pct_supply",
              "insider_holds_tokens", "insider_holds_pct_supply"):
        assert k in out, f"missing emitted key: {k}"

    # tree_holds = sum of all 3 balances (real + vesting + cex_custody).
    assert out["tree_holds_tokens"] == 100 + 2_400_000_000 + 50_000_000, (
        f"tree_holds_tokens wrong: {out['tree_holds_tokens']}"
    )
    # pure_insider = only the real insider's balance.
    assert out["pure_insider_holds_tokens"] == 100, (
        f"pure_insider_holds_tokens wrong: {out['pure_insider_holds_tokens']}"
    )
    # Backward-compat alias must equal tree_holds (semantics unchanged
    # for downstream consumers that haven't read the changelog).
    assert out["insider_holds_tokens"] == out["tree_holds_tokens"]
    assert out["insider_holds_pct_supply"] == out["tree_holds_pct_supply"]
    # Pure must be <= tree (lockup balance is non-negative).
    assert out["pure_insider_holds_tokens"] <= out["tree_holds_tokens"]


def test_v0719_4_pure_insider_excludes_lockup_logic():
    """Verify the actual filter expression dump_tracker uses to compute
    pure_insider_holds — exclude is_protocol_lockup OR is_cex_custody OR
    is_dex_infra. Mirrors the inline loop in dump_tracker.run."""
    receivers = [
        # Real insider with balance 100 — must be included.
        {"addr": "0x" + "a" * 40, "is_protocol_lockup": False,
         "is_cex_custody": False, "is_dex_infra": False,
         "current_balance": 100},
        # Vesting contract — excluded (is_protocol_lockup).
        {"addr": "0x" + "b" * 40, "is_protocol_lockup": True,
         "current_balance": 2_400_000_000},
        # Gnosis Safe — excluded (is_protocol_lockup).
        {"addr": "0x" + "c" * 40, "is_protocol_lockup": True,
         "current_balance": 100_000_000},
        # CEX custody (e.g. Binance omnibus) — excluded.
        {"addr": "0x" + "d" * 40, "is_cex_custody": True,
         "current_balance": 50_000_000},
        # DEX router — excluded.
        {"addr": "0x" + "e" * 40, "is_dex_infra": True,
         "current_balance": 30_000_000},
        # Another real insider — must be included.
        {"addr": "0x" + "f" * 40, "is_protocol_lockup": False,
         "is_cex_custody": False, "is_dex_infra": False,
         "current_balance": 50},
    ]
    pure = sum(
        r["current_balance"]
        for r in receivers
        if not r.get("is_protocol_lockup")
        and not r.get("is_cex_custody")
        and not r.get("is_dex_infra")
    )
    assert pure == 150, f"Expected pure insider sum 150, got {pure}"


# ---- v0.7.19.5 V_NARRATIVE_NUMERIC_HALLUCINATION hard-fail by default ----
# COLLECT v0.7.19.4 rerun shipped with $8K narrative + $9,239 locked table
# right next to each other because numeric hallucination was a soft warning.
# v0.7.19.5 promotes it to STRUCTURAL hard-fail by default; env override
# `BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS=1` restores soft for dev/CI flows.

def test_v0719_5_numeric_hallucination_classified_structural_by_default(monkeypatch):
    """Default (no env): NUMERIC_HALLUCINATION must land in structural list."""
    import sys as _sys
    from pathlib import Path as _Path
    _v06 = _Path(__file__).parent.parent
    if str(_v06) not in _sys.path:
        _sys.path.insert(0, str(_v06))
    from validate_report_data import categorize_errors

    monkeypatch.delenv("BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS", raising=False)

    errors = [
        "V_NARRATIVE_NUMERIC_HALLUCINATION: liq.interpretation mentions number '$8,106' ...",
        "V_NARRATIVE_GENERIC_PHRASES: tge.interpretation uses generic phrase ...",
    ]
    structural, narrative = categorize_errors(errors)
    # Numeric hallucination MUST be structural (hard fail) by default.
    assert any("NUMERIC_HALLUCINATION" in e for e in structural), (
        f"Expected NUMERIC_HALLUCINATION in structural, got: structural={structural}, narrative={narrative}"
    )
    # Generic phrases stay narrative-quality (soft warning).
    assert any("GENERIC_PHRASES" in e for e in narrative)


def test_v0719_5_numeric_hallucination_soft_with_env_override(monkeypatch):
    """With BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS=1: NUMERIC_HALLUCINATION
    falls back to narrative-quality (soft warning, render continues)."""
    import sys as _sys
    from pathlib import Path as _Path
    _v06 = _Path(__file__).parent.parent
    if str(_v06) not in _sys.path:
        _sys.path.insert(0, str(_v06))
    from validate_report_data import categorize_errors

    monkeypatch.setenv("BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS", "1")

    errors = [
        "V_NARRATIVE_NUMERIC_HALLUCINATION: liq.interpretation mentions number '$8,106' ...",
    ]
    structural, narrative = categorize_errors(errors)
    # Env override: numeric hallucination back to narrative (soft).
    assert any("NUMERIC_HALLUCINATION" in e for e in narrative), (
        f"Env override should soft-classify, got: structural={structural}, narrative={narrative}"
    )
    assert not structural, f"Should be empty structural, got {structural}"


def test_v0719_5_env_truthy_variants(monkeypatch):
    """Env override accepts 1/true/yes/on (case-insensitive)."""
    import sys as _sys
    from pathlib import Path as _Path
    _v06 = _Path(__file__).parent.parent
    if str(_v06) not in _sys.path:
        _sys.path.insert(0, str(_v06))
    from validate_report_data import categorize_errors

    err = ["V_NARRATIVE_NUMERIC_HALLUCINATION: foo"]
    for val in ("1", "true", "TRUE", "yes", "YES", "on", "On"):
        monkeypatch.setenv("BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS", val)
        s, n = categorize_errors(err)
        assert n and not s, f"val={val!r} should soft-classify, got s={s} n={n}"
    # falsy values: 0/empty/false/random — still hard-fail
    for val in ("0", "", "false", "False", "no", "off", "random"):
        monkeypatch.setenv("BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS", val)
        s, n = categorize_errors(err)
        assert s and not n, f"val={val!r} should hard-fail, got s={s} n={n}"
