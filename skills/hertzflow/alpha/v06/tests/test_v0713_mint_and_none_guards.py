#!/usr/bin/env python3
"""test_v0713_mint_and_none_guards.py — v0.7.13 regression tests.

Covers two independent v0.7.13 changes:

1. rule_11 mint detection upgrade (Phase 3): wide-floor aggregate over 0x0
   mints so a deploy→listing gap > 180d (XPIN: ~186d) no longer loses the
   whole trace; multi-recipient emission picks the largest cumulative 0x0
   recipient; no 0x0 mint at all degrades to a `no_deployer_anchor` partial
   instead of a hard error.

2. issue #1 robustness:
   - Bug 1: a sub-dumper with `dumped_pct=None` (balance backfill failed, e.g.
     surf 429 exhausted retries) must not crash the consumers that compare it
     (`0 < None < 95`). Guards added in section_alloc / section_l_distribution
     / forensic_pipeline.
   - Bug 2: i18n.t() must not crash when a numeric template placeholder gets a
     None kwarg (`"${x:.6f}".format(x=None)` → TypeError); it degrades to a
     dash.

Mint tests monkeypatch `run_parallel` so they are deterministic and never hit
live surf (and deliberately keep receiver amounts small so the Step-4 recursion
does not fire).
"""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(V06_DIR))
sys.path.insert(0, str(V06_DIR / "helpers"))

import rule_11_backward_trace as r11
import section_alloc
import section_l_distribution
import i18n
from forensic_pipeline import _derive_verdict_enum


# ---------------------------------------------------------------------------
# Mint detection (monkeypatched run_parallel)
# ---------------------------------------------------------------------------

def _fake_run_parallel(routes):
    """Return a run_parallel stand-in that routes by query-file name substring.

    routes: {filename_substring: value}. value is either a list of rows
    (→ {"data": rows}) or a dict carrying "error" (→ returned verbatim, to
    simulate a surf failure). Unmatched queries return empty data.

    v0.7.23 chunker-aware: when the route key matches a chunked query
    (filename has a YYYY-MM-DD chunk suffix like `step1_mint_2024-01-28`),
    the mock data is served ONCE across all chunks (on the first matching
    file by lexicographic order), and subsequent chunks for the same key
    return empty. This mirrors real surf behavior where the data only
    exists in one chunk bucket; without this, merge_chunked_rows would
    inflate totals by N chunks.
    """
    import re as _re
    _chunk_suffix_re = _re.compile(r"_\d{4}-\d{2}-\d{2}(_\d+)?(?:\.json)?$")
    # Persist across `fake()` calls — `_run_one_chunk` invokes
    # `run_parallel` once per chunk, so a call-local set resets on every
    # chunk and re-serves the data N times.
    served: set[str] = set()

    def fake(paths, max_workers=8):
        results = {}
        # Sort paths so the "first chunk" served is deterministic.
        sorted_paths = sorted(paths)
        for p in sorted_paths:
            name = Path(p).name
            resp = {"data": []}
            for key, val in routes.items():
                if key in name:
                    is_chunked = bool(_chunk_suffix_re.search(name))
                    is_error_route = (
                        isinstance(val, dict) and "error" in val
                    )
                    if is_chunked:
                        if is_error_route:
                            # Error routes simulate a sustained surf
                            # transport failure (e.g. 429 across all
                            # retries). Real surf would fail every
                            # chunk independently, not "once". So serve
                            # the error on EVERY chunked filename match.
                            resp = val
                        elif key in served:
                            # Chunked query for the same logical key —
                            # already served data once; subsequent
                            # chunks empty.
                            resp = {"data": []}
                        else:
                            served.add(key)
                            resp = {"data": val}
                    else:
                        resp = (
                            val if is_error_route else {"data": val}
                        )
                    break
            results[p] = resp
        return results, {p: 0.0 for p in paths}
    return fake


def test_mint_outside_180d_window_is_found(monkeypatch, tmp_path):
    """XPIN-style: a single 0x0 genesis mint ~186d before listing must still
    anchor the deployer (old 180d window dropped it → whole trace lost)."""
    listing = "2026-01-27"
    mint_day = date.fromisoformat(listing) - timedelta(days=186)
    # surf returns unix seconds; pick noon of the mint day.
    import calendar
    mint_ts = calendar.timegm(mint_day.timetuple()) + 43200

    routes = {
        "step1_mint": [{
            "deployer": "0x008a28809ddf6cf12edef360f9ab20f58c3c5ff7",
            "amt": 100_000_000_000.0,
            "first_mint_ts": mint_ts,
            "n_mints": 1,
        }],
        # No deployer outflows → empty-outflow branch returns mint disclosure.
        "step2_deployer_outflows": [],
    }
    monkeypatch.setattr(r11, "run_parallel", _fake_run_parallel(routes))

    out = r11.run_backward_trace(
        ca="0xd955c9ba56fb1ab30e34766e252a97ccce3d31a6",
        alpha_listing_date=listing,
        workdir=tmp_path,
    )
    assert "error" not in out
    assert out["deployer"] == "0x008a28809ddf6cf12edef360f9ab20f58c3c5ff7"
    assert out["mint_basis"] == "genesis_0x0"
    assert out["mint_found_outside_180d"] is True
    assert abs(out["total_minted"] - 100_000_000_000.0) < 1.0


def test_mint_multi_recipient_emission(monkeypatch, tmp_path):
    """Multiple 0x0 recipients → largest cumulative is the de-facto deployer,
    total_minted sums all, basis flags emission."""
    a, b, c = "0x" + "aa" * 20, "0x" + "bb" * 20, "0x" + "cc" * 20
    routes = {
        "step1_mint": [
            {"deployer": a, "amt": 5e8, "first_mint_ts": 1_700_000_000, "n_mints": 3},
            {"deployer": b, "amt": 3e8, "first_mint_ts": 1_700_000_500, "n_mints": 2},
            {"deployer": c, "amt": 2e8, "first_mint_ts": 1_700_001_000, "n_mints": 1},
        ],
        "step2_deployer_outflows": [],
    }
    monkeypatch.setattr(r11, "run_parallel", _fake_run_parallel(routes))

    out = r11.run_backward_trace(
        ca="0x" + "de" * 20, alpha_listing_date="2024-01-01", workdir=tmp_path,
    )
    assert out["deployer"] == a                   # largest cumulative
    assert out["mint_basis"] == "emission_0x0_multi"
    assert abs(out["total_minted"] - 1e9) < 1.0   # 5+3+2 hundred-million
    assert out["n_mint_recipients"] == 3


def test_no_0x0_mint_degrades_to_partial(monkeypatch, tmp_path):
    """No 0x0 mint anywhere → graceful no_deployer_anchor partial, NOT a hard
    error, and a deployer-independent top_holders snapshot is returned."""
    routes = {
        "step1_mint": [],   # nothing minted via 0x0 in the lookback window
        "step1b_top_holders": [
            {"addr": "0x1111", "total_in": 100.0, "total_out": 0.0, "balance": 100.0},
            {"addr": "0x2222", "total_in": 50.0, "total_out": 10.0, "balance": 40.0},
        ],
    }
    monkeypatch.setattr(r11, "run_parallel", _fake_run_parallel(routes))

    out = r11.run_backward_trace(
        ca="0x" + "ab" * 20, alpha_listing_date="2026-01-27", workdir=tmp_path,
    )
    assert "error" not in out
    assert out["_status"] == "no_deployer_anchor"
    assert out["deployer"] is None
    assert out["pre_launch_receivers"] == []      # downstream-safe empty
    assert len(out["top_holders"]) == 2


_CA40 = "0x" + "ab" * 20          # valid 0x40-hex CA for SQL-validation guard
_DEP40 = "0x" + "11" * 20
_DUMPER40 = "0x" + "22" * 20
_SUB40 = "0x" + "33" * 20


def test_subdumper_backfill_error_marks_unverified_not_fully_dumped(monkeypatch, tmp_path):
    """adversarial review HIGH #1: when the sub-dumper balance backfill query ERRORS (429
    exhausting retries), the sub-dumper's balance is UNKNOWN — it must be left
    dumped_pct=None + `_balance_unverified` (NOT a fabricated 100% that would
    inflate the full-dumper count / flip the verdict). The downstream
    `is not None` guards then exclude it from verdict + dumper counts."""
    routes = {
        "step1_mint": [{"deployer": _DEP40, "amt": 1e9,
                        "first_mint_ts": 1_700_000_000, "n_mints": 1}],
        "step2_deployer_outflows": [
            {"block_time": 1_700_000_100, "receiver": _DUMPER40, "amt": 1e7},
        ],
        "step3_balances": [
            {"addr": _DUMPER40, "total_in": 1e7, "total_out": 1e7, "balance": 0.0},
        ],
        "step4_dest": [
            {"receiver": _SUB40, "total_amt": 1e7, "num_tx": 2,
             "first_tx": 1_700_000_200, "last_tx": 1_700_000_300},
        ],
        "step4b_sub_balances": {"error": {"code": "SURF_EXIT", "message": "429 Too Many Requests"}},
    }
    monkeypatch.setattr(r11, "run_parallel", _fake_run_parallel(routes))

    out = r11.run_backward_trace(ca=_CA40, alpha_listing_date="2024-01-01", workdir=tmp_path)
    assert "error" not in out
    subs = [r for r in out["pre_launch_receivers"] if r.get("_depth", 1) > 1]
    assert subs, "expected a recursive sub-dumper"
    # Honest unknown, NOT a fabricated 100%.
    assert all(r.get("_balance_unverified") for r in subs)
    assert all(r.get("dumped_pct") is None for r in subs)
    assert all(r.get("current_balance") is None for r in subs)

    # Over-flagging guard: the unverified sub-dumper must NOT count as a full
    # dumper in the verdict (would otherwise flip to EXIT_IF_HOLDING on a
    # sustained outage). The first-level dumper here received only 1e7 (< 5M
    # threshold? no, 1e7 > 5M) — so to isolate the unverified row, assert it is
    # excluded from the full-dumper count.
    from forensic_pipeline import _derive_verdict_enum
    # Build a rule11 where ONLY the unverified sub-dumper would be a "dumper".
    rule11 = {
        "pre_launch_receivers": [
            {"addr": _SUB40, "dumped_pct": None, "current_balance": None,
             "received_from_deployer": 9_000_000, "_balance_unverified": True,
             "is_protocol_lockup": False},
        ],
        "quiet_wallets": [], "dumper_destinations": {},
    }
    enum, _cn, _base = _derive_verdict_enum(rule11, {"n_recent_events": 0})
    assert enum != "EXIT_IF_HOLDING", "unverified row must not drive EXIT verdict"


def test_step4_recursion_budget_bounds_fanout(monkeypatch, tmp_path):
    """v0.7.14 (XPIN fix): a wide dispersal tree must NOT fan out unbounded.
    With 45 promotable sub-receivers in one batch, the recursion promotes at
    most MAX_PROMOTED_SUBDUMPERS (40), largest-first, and flags truncation —
    instead of exploding into hundreds of queries / a killed run."""
    many = ["0x%040x" % i for i in range(1, 46)]   # 45 distinct valid addrs
    routes = {
        "step1_mint": [{"deployer": _DEP40, "amt": 1e9,
                        "first_mint_ts": 1_700_000_000, "n_mints": 1}],
        "step2_deployer_outflows": [
            {"block_time": 1_700_000_100, "receiver": _DUMPER40, "amt": 1e8},
        ],
        "step3_balances": [
            {"addr": _DUMPER40, "total_in": 1e8, "total_out": 1e8, "balance": 0.0},
        ],
        # 45 sub-receivers each 1e7 (> 0.5% of 1e9 = 5e6) → all promotable.
        "step4_dest": [
            {"receiver": a, "total_amt": 1e7, "num_tx": 1,
             "first_tx": 1_700_000_200, "last_tx": 1_700_000_300} for a in many
        ],
        "step4b_sub_balances": [],   # query OK, no rows → verified fully-dumped
    }
    monkeypatch.setattr(r11, "run_parallel", _fake_run_parallel(routes))

    out = r11.run_backward_trace(ca=_CA40, alpha_listing_date="2024-01-01", workdir=tmp_path)
    assert "error" not in out
    # v0.7.13 era: 40-cap behaviour; mock fed 45 rows.
    # v0.7.23 (chunker): single-dumper case emits 30 sub-dumpers (SQL LIMIT
    #   30 / dumper) and never reaches MAX_PROMOTED ceiling.
    # v0.9.7 (post-decimals threshold rescale, FOLKS-class fix): default
    #   MAX_PROMOTED_SUBDUMPERS = 12 (env override `BINANCE_ALPHA_STEP4_MAX_DUMPERS`).
    #   Now the cap fires on 30 mock candidates → 12 promoted + 18 truncated.
    #   Regression test that recursion_truncated flag fires correctly under
    #   the new tighter default.
    assert out["n_sub_dumpers_promoted"] == 12       # v0.9.7 new default cap
    assert out["recursion_truncated"] is True        # 30 > 12, MAX_PROMOTED hit
    assert out["n_sub_dumpers_skipped"] == 18        # 30 candidates - 12 promoted
    subs = [r for r in out["pre_launch_receivers"] if r.get("_depth", 1) > 1]
    assert len(subs) == 12


# ---------------------------------------------------------------------------
# issue #1 Bug 1 — None dumped_pct must not crash consumers (defense in depth)
# ---------------------------------------------------------------------------

def _rule11_with_none_subdumper():
    return {
        "deployer": "0xdeployer",
        "pre_launch_receivers": [
            {"addr": "0xfull", "dumped_pct": 97.0, "current_balance": 10.0,
             "received_from_deployer": 9_000_000, "is_protocol_lockup": False},
            {"addr": "0xquiet", "dumped_pct": 0.0, "current_balance": 8_000_000,
             "received_from_deployer": 8_000_000, "is_protocol_lockup": False},
            # The dangerous one: backfill failed → unknown.
            {"addr": "0xsub", "dumped_pct": None, "current_balance": None,
             "received_from_deployer": 6_000_000, "is_protocol_lockup": False},
        ],
        "quiet_wallets": [],
        "dumper_destinations": {},
    }


def test_section_alloc_none_dumped_pct_no_crash():
    out = section_alloc.run(
        total_supply=1_000_000_000, circulating_supply=500_000_000,
        rule11=_rule11_with_none_subdumper(), current_price_usd=0.01,
    )
    # The None sub-dumper is excluded from both partial and full (unknown),
    # but the full dumper and quiet receiver are still counted.
    assert out["n_full"] == 1
    assert out["n_partial"] == 0
    assert out["n_quiet"] == 1


def test_section_l_distribution_none_dumped_pct_no_crash():
    from evidence_graph import EvidenceGraph
    rule11 = _rule11_with_none_subdumper()
    # The None sub-dumper must not crash the quiet/partial/full set-building.
    out = section_l_distribution.run(
        top_holders=[],
        rule11=rule11,
        dex_pool_addr=None,
        total_supply=1_000_000_000,
        current_price_usd=0.01,
        eg=EvidenceGraph(),
    )
    assert isinstance(out, dict)


def test_pipeline_verdict_none_dumped_pct_no_crash():
    enum, cn, baseline = _derive_verdict_enum(
        _rule11_with_none_subdumper(), {"n_recent_events": 0}
    )
    # 0xfull is a real full dumper with size → EXIT_IF_HOLDING, and crucially
    # the None sub-dumper did not raise.
    assert enum == "EXIT_IF_HOLDING"


# ---------------------------------------------------------------------------
# issue #1 Bug 2 — i18n.t must not crash on a None numeric kwarg
# ---------------------------------------------------------------------------

def test_i18n_none_numeric_kwarg_degrades_to_dash():
    # stop_loss_summary template applies :.6f to trigger/current.
    out = i18n.t(
        "section.decision.stop_loss_summary",
        trigger=None, current=None, delta_pct=12,
    )
    assert "None" not in out            # must not leak a literal None
    assert "{trigger" not in out        # placeholder must be resolved
    assert "12" in out                  # surviving kwarg still interpolates


def _walk_strings_with_派(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings_with_派(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings_with_派(v, f"{path}[{i}]")
    elif isinstance(obj, str) and "派" in obj:
        yield path, obj


# v0.7.15: 派发 = sell-out / dump (链下卖出, dump_tracker confirmed-sold only);
# 分发 = on-chain transfer (rule_11 / lineage / m6 / holdings / anomaly waves).
# These three paths in zh.json carry "派" legitimately, all in sell-out / 砸盘-risk
# semantics — any other leaf string carrying "派" is a regression.
_ZH_ALLOWED_派_PATHS = {
    "smoke_stub.rationale",         # "触发价对应潜伏钱包开始派发的早期临界点, 防止连锁砸盘"
    "smoke_stub.re_entry",          # "表明派发风险已解除"
    "smoke_stub.verdict_one_liner", # contains "已进入分批派发 (开始卖出) 阶段"
}

# adversarial review MEDIUM #1: path-level whitelist alone lets a future edit add MORE wrong
# "派" usages into the verdict_one_liner string and still pass. For that key
# specifically, pin the exact ONE allowed occurrence ("分批派发 (开始卖出)") and
# fail if "派" appears anywhere else inside that string.
_VERDICT_ONE_LINER_KEY = "smoke_stub.verdict_one_liner"
_VERDICT_ONE_LINER_ALLOWED_派_SUBSTR = "分批派发 (开始卖出)"


def test_zh_json_term_discipline_派发_vs_分发():
    """v0.7.15 — zh.json: "派" only in sell-out paths; verdict_one_liner uses
    "派" exactly inside the "分批派发 (开始卖出)" parenthetical disclaimer."""
    import json
    zh = json.load(open(V06_DIR / "lang" / "zh.json", encoding="utf-8"))

    leaks = [(p, v) for p, v in _walk_strings_with_派(zh) if p not in _ZH_ALLOWED_派_PATHS]
    assert not leaks, (
        "派发 (sell-out) term leaked to a 分发 (on-chain transfer) path. "
        "rule_11 / lineage / m6 / holdings / anomaly waves must use '分发'.\n"
        + "\n".join(f"  {p} = {v!r}" for p, v in leaks)
    )

    # Content-level pin on verdict_one_liner: 派 count == count inside the
    # allowed substring → no extra unauthorized 派 elsewhere in that string.
    vol = zh["smoke_stub"]["verdict_one_liner"]
    total_派 = vol.count("派")
    allowed_派 = _VERDICT_ONE_LINER_ALLOWED_派_SUBSTR.count("派")
    occur = vol.count(_VERDICT_ONE_LINER_ALLOWED_派_SUBSTR)
    assert occur >= 1, (
        f"verdict_one_liner lost its '{_VERDICT_ONE_LINER_ALLOWED_派_SUBSTR}' "
        f"sell-out disclaimer; got: {vol!r}"
    )
    assert total_派 == allowed_派 * occur, (
        f"verdict_one_liner has stray 派 outside the allowed "
        f"'{_VERDICT_ONE_LINER_ALLOWED_派_SUBSTR}' substring: {vol!r}"
    )


def test_v0716_token_info_renders_when_only_alpha_has_price(tmp_path):
    """v0.7.16 — GUA-style scenario: surf project-detail returns NOT_FOUND but
    the Binance Alpha API has price/vol/marketCap. Token-info header table
    must render anyway (no "—" everywhere), pulling from meta.alpha_*."""
    import json
    import os
    import subprocess

    fixture = V06_DIR / "tests" / "fixtures" / "zest_skeleton_fixture.json"
    skel = json.loads(fixture.read_text())
    # Knock out surf project-detail (simulate NOT_FOUND), then inject Alpha API
    # price/vol/marketCap/24h-change/holders into meta.
    skel["meta"]["realtime_token_info"] = {"fetch_ok": False, "_status": "NOT_FOUND"}
    skel["meta"]["alpha_price_usd"] = 0.6886
    skel["meta"]["alpha_percent_change_24h"] = -33.54
    skel["meta"]["alpha_vol_24h_usd"] = 58_503_903.0
    skel["meta"]["alpha_market_cap_usd"] = 189_209_543.0
    skel["meta"]["alpha_fdv_usd"] = 688_674_092.0
    skel["meta"]["alpha_liquidity_usd"] = 2_747_037.0
    skel["meta"]["alpha_holders"] = 15638
    skel["meta"]["alpha_count_24h"] = 200027

    skel_path = tmp_path / "skeleton.json"
    filled_path = tmp_path / "filled.json"
    report_path = tmp_path / "report.md"
    skel_path.write_text(json.dumps(skel))

    env = os.environ.copy()
    env["BINANCE_ALPHA_ALLOW_SMOKE_RENDER"] = "1"
    env["BINANCE_ALPHA_SMOKE_OVERRIDE_REASON"] = "v0.7.16 token-info header regression"
    env["BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS"] = "1"  # v0.7.19.5: stale fixture
    env["BINANCE_ALPHA_NO_UPDATE_CHECK"] = "1"

    r1 = subprocess.run(
        [sys.executable, str(V06_DIR / "tests" / "smoke_fill.py"),
         str(skel_path), str(filled_path)],
        capture_output=True, text=True,
    )
    assert r1.returncode == 0, f"smoke_fill failed: {r1.stderr}"
    r2 = subprocess.run(
        [sys.executable, str(V06_DIR / "render_report.py"),
         "--skeleton", str(skel_path), "--filled", str(filled_path),
         "--out", str(report_path)],
        capture_output=True, text=True, env=env,
    )
    assert "Traceback" not in r2.stderr, f"render crashed: {r2.stderr[-600:]}"
    assert r2.returncode in (0, 2), f"render exit {r2.returncode}: {r2.stderr[-400:]}"
    report = report_path.read_text()

    # The token-info header must render with the Alpha-API price/vol, not skip.
    assert "💹 代币行情" in report, "token-info header section is missing"
    assert "$0.6886" in report, "Alpha API current price not surfaced"
    assert "$58,503,903" in report, "Alpha API 24h volume not surfaced"
    assert "-33.54%" in report, "Alpha API 24h change not surfaced"
    assert "Alpha API" in report, "data-source label should say 'Alpha API'"
    # The "实时行情未就绪" banner must NOT fire when Alpha has the price.
    assert "实时行情未就绪" not in report, (
        "banner wrongly fired even though Alpha API has the price"
    )


def test_v0716_zero_volume_preserved_not_overridden_by_alpha(tmp_path):
    """adversarial review LOW#1: a legit `0` from surf (e.g. illiquid token with no swaps
    today) must NOT be silently replaced by an Alpha-API non-zero value. The
    truthiness-vs-None bug class would have hidden a real "vol = 0" signal
    behind the fallback value."""
    import json
    import os
    import subprocess

    fixture = V06_DIR / "tests" / "fixtures" / "zest_skeleton_fixture.json"
    skel = json.loads(fixture.read_text())
    # surf returns 0 volume + 0 LP (legit on illiquid token); alpha has nonzero.
    skel["meta"]["realtime_token_info"] = {
        "fetch_ok": True,
        "price_usd": 0.12,
        "volume_24h_usd": 0,
        "liquidity_usd": 0,
        "market_cap_usd": 0,
        "fdv_usd": 0,
    }
    skel["meta"]["alpha_price_usd"] = 99.99
    skel["meta"]["alpha_vol_24h_usd"] = 1_000_000
    skel["meta"]["alpha_liquidity_usd"] = 500_000

    skel_path = tmp_path / "skeleton.json"
    filled_path = tmp_path / "filled.json"
    report_path = tmp_path / "report.md"
    skel_path.write_text(json.dumps(skel))

    env = os.environ.copy()
    env["BINANCE_ALPHA_ALLOW_SMOKE_RENDER"] = "1"
    env["BINANCE_ALPHA_SMOKE_OVERRIDE_REASON"] = "v0.7.16 zero-edge regression"
    env["BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS"] = "1"  # v0.7.19.5: stale fixture
    env["BINANCE_ALPHA_NO_UPDATE_CHECK"] = "1"

    r1 = subprocess.run([sys.executable, str(V06_DIR / "tests" / "smoke_fill.py"),
                         str(skel_path), str(filled_path)], capture_output=True, text=True)
    assert r1.returncode == 0
    r2 = subprocess.run([sys.executable, str(V06_DIR / "render_report.py"),
                         "--skeleton", str(skel_path), "--filled", str(filled_path),
                         "--out", str(report_path)],
                        capture_output=True, text=True, env=env)
    assert "Traceback" not in r2.stderr
    report = report_path.read_text()
    # surf's 0.12 wins (price), and surf's 0 vol/LP MUST surface as "$0", not as
    # alpha's $1M/$500K. Otherwise the trader sees fabricated activity.
    assert "$0.12" in report, "surf price (0.12) was not used"
    # 提取 token-info table 看 surf 0 没被 Alpha 值覆盖 (token-info 限定查找,
    # 避开 totalSupply / 24h 成交额等天然出现的大数字).
    info_start = report.index("## 💹 代币行情")
    info_end = report.index("##", info_start + 1)
    info_block = report[info_start:info_end]
    assert "**$0**" in info_block, f"surf 0 vol not preserved in token-info table:\n{info_block}"
    assert "$1,000,000" not in info_block, "Alpha 1M vol wrongly replaced surf 0"
    assert "$500,000" not in info_block, "Alpha 500K LP wrongly replaced surf 0"


def test_zest_fixture_term_discipline_派发_vs_分发():
    """adversarial review MEDIUM #2: the fixture rendered by pre-v0.7.15 pipeline carries
    the old "派发" lexicon. Tests using it would pass while silently asserting
    against stale terminology. Refresh it + lock the same contract here."""
    import json
    fixture = V06_DIR / "tests" / "fixtures" / "zest_skeleton_fixture.json"
    data = json.load(open(fixture, encoding="utf-8"))
    leaks = list(_walk_strings_with_派(data))
    assert not leaks, (
        "zest_skeleton_fixture.json contains 派发 — fixture must use v0.7.15 "
        "term discipline (run the v0.7.15 refresh script).\n"
        + "\n".join(f"  {p} = {v!r}" for p, v in leaks)
    )


def test_retry_classifies_permanent_vs_transient():
    """adversarial review MEDIUM #2: permanent request/schema errors must fail fast (not
    retry 4×); 429 / 5xx / timeout / truncated-JSON are transient (retry)."""
    import parallel_surf as ps
    transient = [
        {"error": {"code": "SURF_EXIT", "message": "429 Too Many Requests"}},
        {"error": {"code": "SURF_EXIT", "message": "503 Service Unavailable"}},
        {"error": {"code": "PARSE_ERROR", "message": "Expecting value"}},
        {"error": {"code": "SURF_EXIT", "message": "connection reset"}},
    ]
    permanent = [
        {"error": {"code": "INVALID_REQUEST", "message": "bad body"}},
        {"error": {"code": "SURF_EXIT", "message": "SQL syntax error near GROUP"}},
        {"error": {"code": "SURF_EXIT", "message": "Unknown identifier foo"}},
        {"error": {"code": "SURF_EXIT", "message": "Unknown table agent.xyz"}},
    ]
    assert all(ps._is_transient_error(r) for r in transient)
    assert all(not ps._is_transient_error(r) for r in permanent)


def test_multi_chain_mirror_aligns_with_primary_chain():
    """v0.7.20.1: a cross-chain mirror (primary_chain != BSC) is now
    **single_chain forensic on the primary chain** — the v0.7.20 SQL
    router fetches m6 / transfers / wash / holdings from the primary
    chain's partition, so coverage is no longer 'partial / BSC mirror
    only' as it was through v0.7.14 - v0.7.20. `single_chain` stays True
    in both cases (it now means 'pipeline ran single-chain forensic
    coverage' regardless of which chain that was); `is_bsc_primary`
    remains the BSC-vs-primary discriminator the caller needs."""
    from section_multi_chain import run as mc_run
    bsc = mc_run(chain_label="BSC", total_supply=10**9, primary_chain="binance-smart-chain")
    assert bsc["single_chain"] is True and bsc["is_bsc_primary"] is True
    mirror = mc_run(chain_label="BSC", total_supply=10**9, primary_chain="stacks")
    # v0.7.20.1 contract: single_chain True even for mirror — pipeline
    # forensic is on the primary chain, not split across two chains.
    assert mirror["single_chain"] is True and mirror["is_bsc_primary"] is False
    blob = mirror["rows"][0]["value"] + mirror["rows"][3]["value"] + mirror["rows"][4]["value"]
    assert "[MISSING:" not in blob          # i18n keys exist in zh
    assert "stacks" in blob                 # real main chain surfaced
    # The coverage row must NOT carry the old "partial coverage" /
    # "verdict downgrade" verbiage — pipeline routes SQL to the primary
    # chain in v0.7.20+, so coverage is full.
    coverage_row = mirror["rows"][4]["value"]
    assert "完整覆盖" in coverage_row or "Full coverage" in coverage_row
    # No primary_chain signal → fall back to venue chain (old behaviour).
    fallback = mc_run(chain_label="BSC", total_supply=10**9, primary_chain=None)
    assert fallback["single_chain"] is True


def test_numeric_hallucination_pipeline_number_via_pool_not_exemption():
    """adversarial review HIGH #1: the m4_notes[0] PATH exemption opened a numeric-bypass
    on the writable m4_notes[] array. The proper fix: expose pipeline-summary
    numbers as `lineage.summary_locked_numbers` so the pool naturally includes
    them, and check ALL indices (no exemption). Pipeline numbers pass cleanly;
    LLM-invented numbers — at ANY index incl. 0 — are flagged."""
    from validate_report_data import Validator
    filled = {
        "lineage": {
            # Locked numeric field — every number cited in m4_notes[0] is here:
            "summary_locked_numbers": {"mint_amount": 2_130_011_366, "n_quiet": 7},
            "m4_notes": [
                # Pipeline summary citing the locked number (must NOT be flagged).
                "Deployer 0x008a28... minted 2,130,011,366 tokens at genesis 创世铸造事件",
                # LLM slot with a hallucinated number (MUST be flagged).
                "LLM 说项目方一共派发了约 9,876,543,210 个代币给内幕地址用于砸盘出货操作",
            ],
        },
    }
    v = Validator()
    v.errors = []
    v._check_narrative_numeric_hallucination(filled)
    joined = " ".join(v.errors)
    assert "2,130,011,366" not in joined     # matched against locked pool
    assert "9,876,543,210" in joined         # LLM hallucination still caught

    # Attack-surface regression: an LLM smuggling a fabricated number into
    # m4_notes[0] (the path the old exemption blanket-skipped) must STILL be
    # flagged — no path-based bypass.
    filled_attack = {
        "lineage": {
            "summary_locked_numbers": {"mint_amount": 2_130_011_366},
            "m4_notes": [
                "LLM 偷偷在 [0] 塞了个伪造数字 1,234,567,890 试图逃过检查 (would be a bypass)",
                "<placeholder>", "<placeholder>",
            ],
        },
    }
    v2 = Validator()
    v2.errors = []
    v2._check_narrative_numeric_hallucination(filled_attack)
    assert "1,234,567,890" in " ".join(v2.errors)   # bypass closed


def test_render_no_bsc_price_stop_loss_no_crash(tmp_path):
    """issue #1 Bug 2: a cross-chain mirror token with no BSC main-pool price
    has stop_loss.{trigger,current,delta} = None. render_report must not crash
    formatting None with :.6f.

    v0.7.25: advice block (decision_action_block: immediate_action / stop_loss
    / re_entry_conditions) was deleted from render template (violates core
    "no buy/sell advice" constraint). stop_loss fallback branch ('价格数据未就绪')
    no longer exists. The None-crash risk this test was guarding against is
    now structurally impossible (no template code touches stop_loss fields).
    Test still useful as regression: verifies setting None on the surviving
    `liq.current_price_usd` field doesn't break the rest of the render."""
    import json
    import os
    import subprocess

    fixture = V06_DIR / "tests" / "fixtures" / "zest_skeleton_fixture.json"
    if not fixture.exists():
        import pytest
        pytest.skip("zest skeleton fixture missing")
    skel = json.loads(fixture.read_text())
    sl = skel["decision_action_block"]["stop_loss"]
    sl["trigger_price_usd"] = None
    sl["current_price_usd"] = None
    sl["delta_pct"] = None
    skel["liq"]["current_price_usd"] = None

    skel_path = tmp_path / "skeleton.json"
    filled_path = tmp_path / "filled.json"
    report_path = tmp_path / "report.md"
    skel_path.write_text(json.dumps(skel))

    env = os.environ.copy()
    env["BINANCE_ALPHA_ALLOW_SMOKE_RENDER"] = "1"
    env["BINANCE_ALPHA_SMOKE_OVERRIDE_REASON"] = "test_v0713 Bug2 render"
    env["BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS"] = "1"  # v0.7.19.5: stale fixture
    env["BINANCE_ALPHA_NO_UPDATE_CHECK"] = "1"

    r1 = subprocess.run(
        [sys.executable, str(V06_DIR / "tests" / "smoke_fill.py"),
         str(skel_path), str(filled_path)],
        capture_output=True, text=True,
    )
    assert r1.returncode == 0, f"smoke_fill failed: {r1.stderr}"
    r2 = subprocess.run(
        [sys.executable, str(V06_DIR / "render_report.py"),
         "--skeleton", str(skel_path), "--filled", str(filled_path),
         "--out", str(report_path)],
        capture_output=True, text=True, env=env,
    )
    # Exit 0 or 2 (narrative warnings) OK; a TypeError traceback is the crash.
    assert "Traceback" not in r2.stderr, f"render crashed: {r2.stderr[-800:]}"
    assert r2.returncode in (0, 2), f"render exit {r2.returncode}: {r2.stderr[-400:]}"
    report = report_path.read_text()
    # v0.7.25: stop_loss "价格数据未就绪" fallback branch removed with advice block.
    # No-crash assertions above (Traceback + returncode) cover regression goal.
    # Sanity-check that the rendered report has the H1 + footer (= rendered, not aborted).
    assert "# " in report   # has at least one H1 title
    assert "evidence_graph" in report   # rendered through to footer (not mid-template fail)


# ---------------------------------------------------------------------------
# v0.7.23 — fetch_mint_event_with_fast_path correctness (audit M4 fix)
# ---------------------------------------------------------------------------

class TestMintFastPath:
    """Lock the fast-path semantics so a surf failure can never be silently
    misclassified as "no mint exists". Three outcomes the fast-path must
    distinguish:

      1. fast-hit       — fast slice returned rows → return (rows, "hit", True)
      2. fast-miss      — fast clean miss + fallback hit → return (rows, "fallback hit", True)
      3. fast-miss-miss — fast clean miss + fallback clean miss → ([], ..., True)
      4. fast-all-error — every fast chunk errored → ([], ..., False) [SKIP fallback]
      5. fallback-all-error — fast clean miss + fallback all errored → ([], ..., False)
    """

    def test_fast_path_hit_returns_rows_and_ok(self, monkeypatch, tmp_path):
        """Fast slice returns rows → no fallback call, ok=True."""
        calls = []

        def fake_chunked(ca, floor, workdir, chunk_days=90, limit=20, ceiling=None):
            calls.append((floor, ceiling))
            # Fast slice: hit with a mint row.
            return [{"deployer": "0xabc", "amt": 100.0, "first_mint_ts": 1, "n_mints": 1}], "fast diag", 0, 2

        monkeypatch.setattr(r11, "fetch_mint_event_chunked", fake_chunked)
        rows, diag, ok = r11.fetch_mint_event_with_fast_path(
            ca="0x" + "a" * 40, listing_date="2026-01-27",
            mint_floor="2024-01-27", workdir=tmp_path,
        )
        assert ok is True
        assert len(rows) == 1
        assert "fast-path hit" in diag
        assert len(calls) == 1, "fallback must not run when fast hits"

    def test_fast_miss_fallback_hit(self, monkeypatch, tmp_path):
        """Fast clean miss → fallback fires → fallback returns rows. ok=True."""
        calls = []

        def fake_chunked(ca, floor, workdir, chunk_days=90, limit=20, ceiling=None):
            calls.append((floor, ceiling))
            if ceiling is not None:
                return [], "fast clean miss", 0, 2   # fast slice, no rows, no errors
            return [{"deployer": "0xabc", "amt": 100.0, "first_mint_ts": 1, "n_mints": 1}], "fallback hit", 0, 10

        monkeypatch.setattr(r11, "fetch_mint_event_chunked", fake_chunked)
        rows, diag, ok = r11.fetch_mint_event_with_fast_path(
            ca="0x" + "a" * 40, listing_date="2026-01-27",
            mint_floor="2024-01-27", workdir=tmp_path,
        )
        assert ok is True
        assert len(rows) == 1
        assert "fast-path miss → fallback hit" in diag
        assert len(calls) == 2

    def test_fast_miss_fallback_miss_both_clean(self, monkeypatch, tmp_path):
        """Both clean misses → ok=True (genuine no-anchor case)."""
        def fake_chunked(ca, floor, workdir, chunk_days=90, limit=20, ceiling=None):
            return [], ("fast miss" if ceiling else "fallback miss"), 0, 10

        monkeypatch.setattr(r11, "fetch_mint_event_chunked", fake_chunked)
        rows, diag, ok = r11.fetch_mint_event_with_fast_path(
            ca="0x" + "a" * 40, listing_date="2026-01-27",
            mint_floor="2024-01-27", workdir=tmp_path,
        )
        assert ok is True
        assert rows == []
        assert "fallback clean miss" in diag

    def test_fast_all_error_skips_fallback(self, monkeypatch, tmp_path):
        """Every fast chunk errored → return ok=False, do NOT pay for
        fallback (surf is clearly broken end-to-end)."""
        calls = []

        def fake_chunked(ca, floor, workdir, chunk_days=90, limit=20, ceiling=None):
            calls.append((floor, ceiling))
            # n_errs == n_chunks → all errored.
            return [], "fast all errored", 2, 2

        monkeypatch.setattr(r11, "fetch_mint_event_chunked", fake_chunked)
        rows, diag, ok = r11.fetch_mint_event_with_fast_path(
            ca="0x" + "a" * 40, listing_date="2026-01-27",
            mint_floor="2024-01-27", workdir=tmp_path,
        )
        assert ok is False
        assert rows == []
        assert "all chunks errored" in diag and "skip fallback" in diag
        assert len(calls) == 1, "fallback must be skipped when fast all errors"

    def test_fallback_all_error_returns_not_ok(self, monkeypatch, tmp_path):
        """Fast clean miss but fallback fully errors → ok=False (do NOT
        misclassify as no-anchor)."""
        def fake_chunked(ca, floor, workdir, chunk_days=90, limit=20, ceiling=None):
            if ceiling is not None:
                return [], "fast clean miss", 0, 2
            return [], "fallback all errored", 10, 10

        monkeypatch.setattr(r11, "fetch_mint_event_chunked", fake_chunked)
        rows, diag, ok = r11.fetch_mint_event_with_fast_path(
            ca="0x" + "a" * 40, listing_date="2026-01-27",
            mint_floor="2024-01-27", workdir=tmp_path,
        )
        assert ok is False
        assert rows == []
        assert "fallback all errored" in diag
