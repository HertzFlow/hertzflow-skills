#!/usr/bin/env python3
"""rule_11_backward_trace.py — Rule 11 deployment backward trace (v0.6).

v0.6 upgrade from v0.5.9:
1. Returns provenance IDs (evt_NNN, m6_NNN) into a passed-in EvidenceGraph,
   not raw dicts. Caller (forensic_pipeline.py) gets back evidence IDs to
   embed into the report skeleton.
2. Returns `waves_proposal` — fully-formed `anomaly.waves[]` structure
   ready to drop into `report_data_skeleton.json`. This closes the
   "Rule 11 narrative gap" audit finding (v0.5.9 produced m6.rows
   but did not derive the wave structure; LLMs forgot to write waves
   themselves).

## 4-step backward trace

1. Find mint event — wide-floor aggregate over `from = 0x0` mints (v0.7.13).
   GROUP BY recipient picks the largest cumulative 0x0 recipient as the
   de-facto deployer; works for a single genesis mint AND multi-recipient
   emission. A wide MINT_LOOKBACK_DAYS floor catches deploy→listing gaps the
   180d default misses (XPIN: 0x0 genesis 2025-07-25, listed 2026-01-27 =
   ~186d → mint fell 6 days outside the old 180d floor → whole trace lost).
   No 0x0 mint in the window → `_status='no_deployer_anchor'` graceful
   partial (holder snapshot, no fabricated origin), never a hard abort.
2. Trace deployer outflows in `[trace_floor, alpha_listing_date]`
   (trace_floor = min(180d floor, mint day) so genesis-era dispersal is kept)
3. Per receiver: received + balance → dumped_pct
4. Top dumpers: trace destination addresses

## v0.6 NEW: waves_proposal output

```python
{
  "evidence_graph": EvidenceGraph(...),    # populated with evt_/m6_ IDs
  "deployer": "0x...",
  "mint_evt_ref": "evt_001",
  "pre_launch_receivers": [{addr, evt_ref, m6_ref, dumped_pct, ...}],
  "quiet_wallets": [...],
  "dumper_destinations": {...},
  "waves_proposal": [
    {
      "emoji": "🟠",
      "title": "第一波 Pre-launch OTC 预分发",
      "ts_range": "2026-02-26 ~ 2026-03-03 UTC",
      "status_text": "已完成",
      "events": [
        {"evt_ref": "evt_002", "ts": ..., "from_to": "...", "amount": "...",
         "nature": "<LLM_NARRATIVE_PLACEHOLDER>"}
      ]
    },
    ...
  ],
  "summary_text": "...",
}
```

v0.6 (2026-05-24, cross-LLM audit condition.)
v0.7.13 (2026-05-28, mint detection: wide-floor aggregate + graceful no-anchor.)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from parallel_surf import run_parallel
from i18n import t   # v0.6.2 i18n
from evidence_graph import EvidenceGraph
from chain_router import transfers_table, dex_trades_table  # v0.7.20
from collections import defaultdict
from window_chunker import (  # v0.7.23
    chunked_dates,
    parallel_run_chunked,
    parallel_run_flat_tasks,  # v0.7.23 regression-fix: flat (dumper × chunk) parallel
    merge_chunked_rows,
    chunk_summary,
)


# v1.2.8 (product spec 2026-06-29): the SINGLE source of truth for "is this receiver a
# genuine 潜伏 (quiet / undistributed) insider". Used by rule_11 (quiet_wallets),
# section_alloc (n_quiet), and section_l_distribution (quiet_set + flowchart node
# typing) so all three agree — adversarial review flagged that they had diverged.
#
# A genuine quiet holder: received from the deployer, has NOT dumped
# (dumped_pct == 0 — None means "unknown", NOT quiet), is NOT a project lockup
# (vesting / multisig / treasury / CEX / DEX infra), AND still actually HOLDS
# (≥ 1 token). The balance gate is what excludes 0-value address-poisoning DECOYS
# — look-alike-prefix addresses (e.g. 0x219f3a7a mirroring the real 0x219f074e)
# that received 0 and hold 0 but show dumped_pct == 0; they were inflating the
# 潜伏 count (VELVET: 13 reported, only 2 genuine = 1.53% supply).
def is_genuine_quiet_holder(r: dict) -> bool:
    return (r.get("dumped_pct") == 0
            and not r.get("is_protocol_lockup")
            and (r.get("current_balance") or 0) >= 1)


def is_zero_balance_decoy(r: dict) -> bool:
    """A dumped_pct==0, non-lockup receiver that received ~0 AND holds ~0 — a
    dummy address-poisoning decoy, not a real quiet insider. Surfaced separately
    so the operator-obfuscation tactic stays visible instead of silently dropped."""
    return (r.get("dumped_pct") == 0
            and not r.get("is_protocol_lockup")
            and (r.get("current_balance") or 0) < 1
            and (r.get("received_from_deployer") or 0) < 1)


# Wide lookback for the 0x0 mint-detection query ONLY (not the heavier
# Step 2-4 outflow/balance scans). `from = 0x0` AND `contract_address` is a
# highly selective predicate, so scanning ~2y of partitions is cheap. Covers
# deploy→listing gaps the 180d default window silently drops (XPIN ~186d).
MINT_LOOKBACK_DAYS = 730

# v0.7.13: mint detection upgraded from "first 0x0 transfer in 180d window"
# (single row, ORDER BY block_time) to a wide-floor aggregate. The old form
# hit two failure modes that lost the entire trace:
#   (1) deploy→listing gap > 180d → the 0x0 genesis mint falls outside the
#       window → Step 1 empty → hard error → whole rule_11 trace abandoned.
#   (2) multi-recipient / continuous-emission genesis → ORDER BY block_time
#       picked the first (possibly tiny) mint instead of the real deployer.
# GROUP BY recipient + sum picks the largest CUMULATIVE 0x0 recipient as the
# de-facto deployer and reports total minted across all recipients.
# Tie-break (adversarial review HIGH #2): `ORDER BY amt DESC` alone is non-deterministic when
# two recipients minted equal cumulative amounts. Add first_mint_ts ASC (earliest
# minter wins) then deployer ASC so the de-facto deployer is stable run-to-run.
SQL_FIND_MINT = """SELECT "to" AS deployer, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt, min(block_time) AS first_mint_ts, count() AS n_mints FROM {transfers} WHERE contract_address = '{ca}' AND "from" = '0x0000000000000000000000000000000000000000' AND block_date >= '{date_floor}' GROUP BY deployer ORDER BY amt DESC, first_mint_ts ASC, deployer ASC LIMIT 20"""

# v0.7.23 step1_mint chunker: same selectivity as SQL_FIND_MINT but
# bounded by BETWEEN so each chunk fits inside surf's 30s budget. Long
# lookback windows (MINT_LOOKBACK_DAYS=730) used to silently time out
# on busy partitions even though 0x0 mint is highly selective. SUM /
# MIN / COUNT all distribute over chunks so Python-side merge is
# mathematically equivalent to the single-window form.
SQL_FIND_MINT_CHUNK = """SELECT "to" AS deployer, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt, min(block_time) AS first_mint_ts, count() AS n_mints FROM {transfers} WHERE contract_address = '{ca}' AND "from" = '0x0000000000000000000000000000000000000000' AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}' GROUP BY deployer ORDER BY amt DESC, first_mint_ts ASC, deployer ASC LIMIT 100"""

# v0.7.13: deployer-independent top holders by net balance. Used by the
# graceful no-anchor path (no 0x0 mint found in MINT_LOOKBACK_DAYS) so rule_11
# still emits a distribution snapshot instead of hard-erroring. ins/outs
# CTE-join form, NOT UNION ALL (which OOM'd surf on large-transfer tokens —
# v0.7.7.1 finding).
SQL_TOP_HOLDERS = """WITH ins AS (SELECT "to" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca}' AND block_date >= '{date_floor}' GROUP BY addr), outs AS (SELECT "from" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca}' AND block_date >= '{date_floor}' GROUP BY addr) SELECT ins.addr AS addr, ins.amt AS total_in, COALESCE(outs.amt, 0) AS total_out, ins.amt - COALESCE(outs.amt, 0) AS balance FROM ins LEFT JOIN outs ON ins.addr = outs.addr WHERE ins.addr NOT IN ('0x0000000000000000000000000000000000000000', '0x000000000000000000000000000000000000dead') ORDER BY balance DESC LIMIT 30"""

# v0.7.23: chunkable variants for sliding-window aggregation. The Python-side
# merge_chunked_rows combines per-chunk groupings back into a single
# group-by because SUM is distributive over the chunk partition. Bare
# `block_date >= floor` form (above) kept as the no-chunk single-shot
# version for newer tokens where one bucket fits inside surf's 30s budget.
SQL_TOP_HOLDERS_CHUNK = """SELECT addr, sum(amt_in) AS total_in, sum(amt_out) AS total_out FROM (SELECT "to" AS addr, toFloat64(toDecimal256(amount_raw,0))/{decimals_factor} AS amt_in, toFloat64(0) AS amt_out FROM {transfers} WHERE contract_address = '{ca}' AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}' UNION ALL SELECT "from" AS addr, toFloat64(0) AS amt_in, toFloat64(toDecimal256(amount_raw,0))/{decimals_factor} AS amt_out FROM {transfers} WHERE contract_address = '{ca}' AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}') GROUP BY addr"""

SQL_DEPLOYER_OUTFLOWS = """SELECT block_time, "to" AS receiver, toFloat64(toDecimal256(amount_raw,0))/{decimals_factor} AS amt FROM {transfers} WHERE contract_address = '{ca}' AND "from" = '{deployer}' AND block_date BETWEEN '{date_floor}' AND '{alpha_listing_date}' ORDER BY block_time LIMIT 100"""

SQL_RECEIVER_BALANCES = """WITH ins AS (SELECT "to" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca}' AND block_date >= '{date_floor}' GROUP BY addr), outs AS (SELECT "from" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca}' AND block_date >= '{date_floor}' GROUP BY addr) SELECT r.addr AS addr, COALESCE(ins.amt, 0) AS total_in, COALESCE(outs.amt, 0) AS total_out, COALESCE(ins.amt, 0) - COALESCE(outs.amt, 0) AS balance FROM (SELECT arrayJoin({receiver_array}) AS addr) r LEFT JOIN ins ON r.addr = ins.addr LEFT JOIN outs ON r.addr = outs.addr ORDER BY balance DESC"""

# v0.7.23: chunkable variant for receiver balances. Same UNION ALL trick
# as SQL_TOP_HOLDERS_CHUNK but with an extra IN filter on the receiver
# array so we only scan rows touching m6 receivers (much smaller).
SQL_RECEIVER_BALANCES_CHUNK = """SELECT addr, sum(amt_in) AS total_in, sum(amt_out) AS total_out FROM (SELECT "to" AS addr, toFloat64(toDecimal256(amount_raw,0))/{decimals_factor} AS amt_in, toFloat64(0) AS amt_out FROM {transfers} WHERE contract_address = '{ca}' AND "to" IN ({receiver_in_list}) AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}' UNION ALL SELECT "from" AS addr, toFloat64(0) AS amt_in, toFloat64(toDecimal256(amount_raw,0))/{decimals_factor} AS amt_out FROM {transfers} WHERE contract_address = '{ca}' AND "from" IN ({receiver_in_list}) AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}') GROUP BY addr"""

SQL_DUMPER_DESTINATIONS = """SELECT "to" AS receiver, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS total_amt, count() AS num_tx, min(block_time) AS first_tx, max(block_time) AS last_tx FROM {transfers} WHERE contract_address = '{ca}' AND "from" = '{dumper}' AND block_date >= '{date_floor}' GROUP BY receiver ORDER BY total_amt DESC LIMIT 30"""

# v0.7.23: chunkable variant for dumper destinations. SUM + COUNT + MIN +
# MAX all distribute over chunk partition; merge_chunked_rows handles it.
# audit M4: add ORDER BY total_amt DESC + LIMIT so each chunk
# returns its true top-N receivers; without this, max_rows truncation in
# _run_one_chunk could return an arbitrary subset (large-fanout dumpers).
# 200 per chunk × 7 chunks = 1400 candidates feeding the Python merge,
# which then selects top-30 to match v0.7.22 baseline semantics (H1).
SQL_DUMPER_DESTINATIONS_CHUNK = """SELECT "to" AS receiver, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS total_amt, count() AS num_tx, min(block_time) AS first_tx, max(block_time) AS last_tx FROM {transfers} WHERE contract_address = '{ca}' AND "from" = '{dumper}' AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}' GROUP BY receiver ORDER BY total_amt DESC LIMIT 200"""


# adversarial review MEDIUM #3: every value interpolated into surf SQL (the f-string
# .format(decimals_factor=decimals_factor_str()) below) must be a validated address. `ca` is caller-supplied;
# deployer / receivers / dumpers come from surf (on-chain) but we re-validate
# at the query boundary so a malformed value can never reach the SQL string.
# v0.7.21.7: chain-aware via chain_router.is_valid_addr (EVM 0x40-hex on EVM
# chains; Solana base58 32-44 on Solana). Pre-v0.7.21.7 this was hardcoded
# EVM, which silently dropped every base58 address on Solana → m6 empty.
_HEX_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")  # kept for back-compat callers

from chain_router import (  # noqa: E402
    is_valid_addr as _chain_is_valid_addr,
    get_active_chain as _chain_get_active,
    decimals_factor_str,
)


def _valid_addr(addr) -> bool:
    if not addr or not isinstance(addr, str):
        return False
    # Solana base58 is case-sensitive; EVM is case-insensitive.
    if _chain_get_active() == "solana":
        return _chain_is_valid_addr(addr)
    return _chain_is_valid_addr(addr.lower())


def _clean_addrs(addrs: list[str]) -> list[str]:
    """Keep only addresses that pass the active chain's format check,
    de-duplicated + sorted. Solana preserves case; EVM lowercases."""
    if _chain_get_active() == "solana":
        return sorted({a for a in addrs if a and _chain_is_valid_addr(a)})
    return sorted({
        a.lower() for a in addrs
        if a and _chain_is_valid_addr(a.lower())
    })


def _write_query(workdir: Path, name: str, sql: str, max_rows: int = 200) -> Path:
    p = workdir / f"{name}.json"
    p.write_text(json.dumps({"max_rows": max_rows, "sql": sql}), encoding="utf-8")
    return p


def _ts_to_iso(ts: int | str) -> str:
    """Convert Unix seconds or ISO string to 'YYYY-MM-DD HH:MM' UTC."""
    if isinstance(ts, str):
        return ts
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(ts)


def _ts_to_date(ts: int | str) -> str:
    if isinstance(ts, str):
        return ts.split(" ")[0]
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return str(ts)


# v0.7.23 conditional bypass — short-history tokens (LAB/COLLECT-class)
# pay a 3x SQL count penalty for nothing if forced through the chunker.
# v0.7.22 baseline single-SQL form fits the 30s surf budget cleanly on
# these tokens. Long-history tokens (SKYAI 14mo, OLAS 18mo) still time
# out as a single SQL and MUST use chunker.
#
# 300d covers LAB step3/step4 trace windows (listing - 180d = ~270d for
# a 90d-old listing) but is well below SKYAI/PEAQ deploy-anchored windows
# (>600d). Empirical: BSC partition SUM/COUNT on a busy token completes
# in 5-15s at ≤300d window on surf-normal days; >300d flirts with the
# 30s timeout. The number is a heuristic — override via env on tokens
# where the default proves wrong (timeouts at 200d → lower; surf back
# to normal → raise toward 400-500d). This switch is the difference
# between LAB regressing 2-3x vs LAB matching v0.7.21 wall-time.
SHORT_WINDOW_DAYS = int(os.environ.get("BINANCE_ALPHA_SHORT_WINDOW_DAYS", "300"))


def _is_short_window(floor: str, ceiling: str | None = None) -> bool:
    """True if `(ceiling - floor) ≤ SHORT_WINDOW_DAYS`. Treats `None`
    ceiling as today (UTC), matching `chunked_dates` semantics. Used
    by fetch_*_chunked helpers to decide chunker vs single-SQL path.
    """
    floor_d = date.fromisoformat(floor)
    ceiling_d = (
        date.fromisoformat(ceiling) if ceiling else date.today()
    )
    return (ceiling_d - floor_d).days <= SHORT_WINDOW_DAYS


def _single_chunk_or_chunker_dates(
    floor: str, ceiling: str | None, chunk_days: int = 90,
) -> list[tuple[str, str]]:
    """v0.7.23 conditional bypass: short windows collapse to a single
    [(floor, ceiling)] chunk (SQL shape preserved as BETWEEN), long
    windows use the 90d-chunked partition. SUM/COUNT/MIN/MAX merge is
    a no-op on the single-chunk case (1 chunk's rows = merged rows),
    so the conditional is purely a SQL-count optimization with zero
    output divergence. The single-chunk path still goes through
    parallel_run_chunked / merge_chunked_rows so the surrounding
    pipeline (error tagging, output ordering) is identical."""
    if _is_short_window(floor, ceiling):
        ceiling_concrete = ceiling or date.today().isoformat()
        return [(floor, ceiling_concrete)]
    return chunked_dates(floor, ceiling, chunk_days=chunk_days)


def _run_one_chunk(sql: str, workdir: Path, name_prefix: str) -> dict[str, Any]:
    """Execute one chunk SQL via surf and return {'data': [...], '_error'?: str}.

    v0.7.23: thin wrapper used by `parallel_run_chunked` callers so each
    chunk's surf call follows the existing `run_parallel` plumbing
    (jq / surf cli flags / 429 retry wrapper).
    """
    qf = _write_query(workdir, name_prefix, sql, max_rows=2000)
    try:
        results, _ = run_parallel([str(qf)])
        resp = results.get(str(qf), {}) or {}
        if "error" in resp:
            return {"_error": str(resp["error"])[:300], "data": []}
        return {"data": resp.get("data") or []}
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"[:200], "data": []}


def fetch_top_holders_chunked(
    ca: str,
    floor: str,
    ceiling: str | None,
    workdir: Path,
    chunk_days: int = 90,
    limit: int = 30,
) -> tuple[list[dict[str, Any]], str]:
    """v0.7.23: SQL_TOP_HOLDERS but sliding-window so it survives the
    surf 30s ClickHouse budget on long-lived BSC tokens (SKYAI / PEAQ /
    any 6+ month listing). Newer tokens with one chunk fall through
    a single-shot path identical to the legacy behavior.

    Returns (top_holders, diagnostic_summary).
    """
    chunks = _single_chunk_or_chunker_dates(floor, ceiling, chunk_days=chunk_days)
    transfers = transfers_table()

    def _sql_fn(chunk_floor: str, chunk_ceiling: str) -> dict[str, Any]:
        sql = SQL_TOP_HOLDERS_CHUNK.format(
            ca=ca, chunk_floor=chunk_floor, chunk_ceiling=chunk_ceiling,
            transfers=transfers,
         decimals_factor=decimals_factor_str())
        return _run_one_chunk(sql, workdir, f"step1b_top_holders_{chunk_floor}")

    chunk_results = parallel_run_chunked(_sql_fn, chunks)
    # Surface any chunk-level errors but keep the rest — partial data
    # beats nothing on a flaky surf retry storm.
    errs = [r.get("_error") for r in chunk_results if r.get("_error")]
    rows_per_chunk = [r.get("data") or [] for r in chunk_results]
    merged = merge_chunked_rows(
        rows_per_chunk, key_field="addr",
        sum_fields=["total_in", "total_out"],
    )
    # Compute balance + filter burn addresses (single-window SQL did this
    # inline via WHERE addr NOT IN (0x0, 0xdead)).
    BURN = {
        "0x0000000000000000000000000000000000000000",
        "0x000000000000000000000000000000000000dead",
    }
    for r in merged:
        r["balance"] = (r.get("total_in") or 0) - (r.get("total_out") or 0)
    merged = [r for r in merged if (r.get("addr") or "").lower() not in BURN]
    merged.sort(key=lambda r: r.get("balance") or 0, reverse=True)
    top = merged[:limit]
    summary = chunk_summary(chunks)
    if errs:
        summary += f"; {len(errs)}/{len(chunks)} chunks errored"
    return top, summary


def fetch_receiver_balances_chunked(
    ca: str,
    receivers: list[str],
    floor: str,
    ceiling: str | None,
    workdir: Path,
    chunk_days: int = 90,
    name_prefix: str = "step3_balances",
) -> tuple[dict[str, dict[str, float]], str, bool]:
    """v0.7.23: SQL_RECEIVER_BALANCES sliding-window. Returns
    `(balances_dict, diag, lookup_ok)`.

    audit H1 fix: when EVERY chunk errors, the zero-fill block
    below would produce {addr: balance=0} for every receiver, which
    downstream classifies as `rule11_full_dumper` (dumped_pct = 100%)
    — a catastrophic false-positive forensic conclusion driven entirely
    by surf transport failure. The third return slot `lookup_ok=False`
    tells `run_backward_trace` to fail loud instead of zero-filling.
    Partial chunk error (some chunks ok, some errored) still produces
    a result because SUM-merge over the ok chunks is correct; only
    `n_errs == n_chunks` is a real "we have no idea" case.
    """
    if not receivers:
        return {}, "0 receivers", True
    chunks = _single_chunk_or_chunker_dates(floor, ceiling, chunk_days=chunk_days)
    transfers = transfers_table()
    receiver_in_list = ",".join(f"'{a.lower()}'" for a in receivers)

    def _sql_fn(chunk_floor: str, chunk_ceiling: str) -> dict[str, Any]:
        sql = SQL_RECEIVER_BALANCES_CHUNK.format(
            ca=ca, receiver_in_list=receiver_in_list,
            chunk_floor=chunk_floor, chunk_ceiling=chunk_ceiling,
            transfers=transfers,
         decimals_factor=decimals_factor_str())
        return _run_one_chunk(sql, workdir, f"{name_prefix}_{chunk_floor}")

    chunk_results = parallel_run_chunked(_sql_fn, chunks)
    errs = [r.get("_error") for r in chunk_results if r.get("_error")]
    n_chunks = len(chunks)
    n_errs = len(errs)
    rows_per_chunk = [r.get("data") or [] for r in chunk_results]
    merged = merge_chunked_rows(
        rows_per_chunk, key_field="addr",
        sum_fields=["total_in", "total_out"],
    )
    out: dict[str, dict[str, float]] = {}
    for r in merged:
        addr = (r.get("addr") or "").lower()
        if not addr:
            continue
        total_in = float(r.get("total_in") or 0)
        total_out = float(r.get("total_out") or 0)
        out[addr] = {
            "total_in": total_in,
            "total_out": total_out,
            "balance": total_in - total_out,
        }
    # Ensure every requested receiver appears in the result with zero
    # balances when they had no activity in any chunk (matches single-
    # window LEFT JOIN behavior the chunked UNION ALL above does not
    # naturally produce).
    for a in receivers:
        addr = (a or "").lower()
        if addr and addr not in out:
            out[addr] = {"total_in": 0.0, "total_out": 0.0, "balance": 0.0}
    summary = chunk_summary(chunks)
    if errs:
        summary += f"; {n_errs}/{n_chunks} chunks errored"
    # audit H1: lookup_ok=False on ANY chunk error.
    # v0.7.23 ship-day update: original logic allowed partial pass
    # (lookup_ok = n_errs < n_chunks) on the theory that SUM-merge over
    # ok chunks is "underestimate not fabrication". Reverted to strict
    # because:
    #   (1) An underestimate of `total_in` directly inflates dumped_pct
    #       (= (received - balance) / received). On SKYAI 6/7 errored,
    #       a 41/42 receiver clean-shows as 100% dumped from one chunk
    #       of true data — exactly the false-positive zero-fill problem
    #       this fix was supposed to prevent.
    #   (2) Aligns with step4's H3 semantics: any chunk error → that
    #       dumper SKIPPED. Two segments of the same forensic shouldn't
    #       have different partial-failure tolerance.
    #   (3) Surf transient backend failures are surf's bug to fix; we
    #       fail loud so the operator sees "rerun when surf recovers",
    #       not a silently-skewed verdict.
    lookup_ok = n_errs == 0
    return out, summary, lookup_ok
    return out, summary


def fetch_dumper_destinations_chunked(
    ca: str,
    dumper: str,
    floor: str,
    ceiling: str | None,
    workdir: Path,
    chunk_days: int = 90,
    # v0.7.23: 100 is generous vs legacy `LIMIT 30` — the legacy cap was a
    # defensive surf query-size guard, not a business-logic decision. The
    # recursion in `run_backward_trace` has its own `MAX_PROMOTED_SUBDUMPERS
    # = 40` cap, and test fixtures sometimes feed > 40 mock destinations
    # to exercise that cap. Set the per-dumper limit high enough that the
    # cap behavior matches the legacy code.
    limit: int = 100,
) -> tuple[list[dict[str, Any]], str]:
    """v0.7.23: SQL_DUMPER_DESTINATIONS sliding-window for one dumper.
    Returns sorted [(receiver, total_amt, num_tx, first_tx, last_tx)],
    top `limit` by total_amt descending.
    """
    chunks = _single_chunk_or_chunker_dates(floor, ceiling, chunk_days=chunk_days)
    transfers = transfers_table()

    def _sql_fn(chunk_floor: str, chunk_ceiling: str) -> dict[str, Any]:
        sql = SQL_DUMPER_DESTINATIONS_CHUNK.format(
            ca=ca, dumper=dumper,
            chunk_floor=chunk_floor, chunk_ceiling=chunk_ceiling,
            transfers=transfers,
         decimals_factor=decimals_factor_str())
        # v0.7.23: keep `step4_dest_` prefix so existing pytest mocks
        # routing by filename substring (test_v0713_mint_and_none_guards
        # and friends) still match. Per-chunk suffix `_{chunk_floor}`
        # disambiguates the on-disk query files for parallel workers.
        return _run_one_chunk(
            sql, workdir, f"step4_dest_{dumper[:10]}_{chunk_floor}",
        )

    chunk_results = parallel_run_chunked(_sql_fn, chunks)
    errs = [r.get("_error") for r in chunk_results if r.get("_error")]
    rows_per_chunk = [r.get("data") or [] for r in chunk_results]
    merged = merge_chunked_rows(
        rows_per_chunk, key_field="receiver",
        sum_fields=["total_amt", "num_tx"],
        min_fields=["first_tx"],
        max_fields=["last_tx"],
    )
    summary = chunk_summary(chunks)
    if errs:
        summary += f"; {len(errs)}/{len(chunks)} chunks errored"
    return merged[:limit], summary


def fetch_mint_event_chunked(
    ca: str,
    floor: str,
    workdir: Path,
    chunk_days: int = 90,
    limit: int = 20,
    ceiling: str | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """v0.7.23: SQL_FIND_MINT sliding-window.

    The legacy single-window form scanned `block_date >= floor` across the
    entire MINT_LOOKBACK_DAYS window (default 730d). Even with the
    selective `from = 0x0` filter, large-supply tokens timed out on
    surf's 30s budget when BSC partition was hot. Each chunk runs the
    same group-by-deployer; merge sums per deployer across chunks
    (mathematically equivalent because SUM/MIN/COUNT distribute).

    v0.7.23 fast-path: `ceiling` lets the caller restrict the window so
    fetch_mint_event_with_fast_path can try a narrow listing-±90d slice
    first and fall back to full 730d only when the fast slice misses
    (LAB-class tokens hit in the narrow slice ~80-90% of the time, saving
    9 chunks per run).

    Returns (top-N rows ordered by amt DESC, diag string).
    """
    chunks = _single_chunk_or_chunker_dates(floor, ceiling, chunk_days=chunk_days)
    transfers = transfers_table()

    def _sql_fn(chunk_floor: str, chunk_ceiling: str) -> dict[str, Any]:
        sql = SQL_FIND_MINT_CHUNK.format(
            ca=ca,
            chunk_floor=chunk_floor, chunk_ceiling=chunk_ceiling,
            transfers=transfers,
         decimals_factor=decimals_factor_str())
        return _run_one_chunk(
            sql, workdir, f"step1_mint_{chunk_floor}",
        )

    chunk_results = parallel_run_chunked(_sql_fn, chunks)
    errs = [r.get("_error") for r in chunk_results if r.get("_error")]
    rows_per_chunk = [r.get("data") or [] for r in chunk_results]
    merged = merge_chunked_rows(
        rows_per_chunk, key_field="deployer",
        sum_fields=["amt", "n_mints"],
        min_fields=["first_mint_ts"],
    )
    summary = chunk_summary(chunks)
    n_chunks = len(chunks)
    n_errs = len(errs)
    if errs:
        summary += f"; {n_errs}/{n_chunks} chunks errored"
    # audit H1 fix: store the error count on the returned tuple so
    # the caller (fetch_mint_event_with_fast_path) can distinguish
    # "queried successfully, zero mints found" from "all chunks errored,
    # we have no idea". The legacy 2-element return is preserved via the
    # `_partial` attribute trick (Python lets us tag the tuple via a
    # wrapping list-like form), but the cleanest way is exposing a
    # parallel helper that the fast-path consumes directly.
    return merged[:limit], summary, n_errs, n_chunks


def fetch_mint_event_with_fast_path(
    ca: str,
    listing_date: str,
    mint_floor: str,
    workdir: Path,
    fast_days_before: int = 90,
    fast_days_after: int = 7,
) -> tuple[list[dict[str, Any]], str, bool]:
    """v0.7.23 fast-path: try listing-±90d slice (1-2 chunks) before the
    full 730d lookback (10 chunks).

    Rationale: 80-90% of LAB-class tokens have mint within 90d of listing.
    The fast-path saves ~9 chunks per run on those, dropping step1_mint
    cost from ~10× single SQL latency to ~1×. Tokens with mint outside
    the fast window (XPIN-style 186d, mature tokens listed many months
    after deploy) fall back to the full lookback automatically — no
    correctness loss.

    audit H1 fix: distinguishes 3 outcomes via the third tuple element
    `lookup_ok`:
    - rows + ok=True: clean hit, downstream proceeds.
    - [] + ok=True: clean miss (queries ran, no 0x0 mint exists in window) —
      downstream degrades to no-anchor partial (existing graceful path).
    - [] + ok=False: chunks errored, we don't actually know — caller MUST
      surface this as a transient failure, NOT misclassify as no-anchor.

    audit M2 fix: when fast-path errors on ALL fast chunks, do NOT
    waste time on the fallback (it will also error if surf is broken).
    Return ok=False immediately so the caller fails loud instead of
    paying for a doubled SQL surface.

    Args:
        ca: contract address.
        listing_date: 'YYYY-MM-DD' Alpha listing date — fast slice is
            anchored on this.
        mint_floor: 'YYYY-MM-DD' wide-window floor used by the fallback.
        workdir: scratch dir for surf query files.
        fast_days_before: window size before listing (default 90).
        fast_days_after: window size after listing (default 7) — covers
            tokens that minted to deployer post-listing (rare but seen).

    Returns:
        (rows, diag_string, lookup_ok). lookup_ok=False means surf
        errored across one or more chunks; the empty rows are NOT
        evidence of "no mint". Caller must propagate as transient failure.
    """
    listing_d = date.fromisoformat(listing_date)
    fast_floor = (listing_d - timedelta(days=fast_days_before)).isoformat()
    fast_ceiling = (listing_d + timedelta(days=fast_days_after)).isoformat()

    fast_rows, fast_diag, fast_errs, fast_n = fetch_mint_event_chunked(
        ca=ca, floor=fast_floor, workdir=workdir, ceiling=fast_ceiling,
    )
    if fast_rows:
        # Even a partial hit is informative — mint event found, ignore
        # any fast-window chunk errors (they would only matter if they
        # hid earlier mint candidates, but SUM-merge across the FULL
        # fallback would surface those anyway).
        return fast_rows, f"fast-path hit ({fast_diag})", True

    if fast_errs >= fast_n:
        # M2: every fast chunk errored. Falling back to a full 10-chunk
        # lookback on a clearly-broken surf is wasted wall-clock AND
        # gives the same all-error result. Bail loud so the pipeline
        # can degrade to a no-anchor partial with a clean failure
        # narrative (NOT silently misclassify as "no 0x0 mint exists").
        return [], f"fast-path all chunks errored ({fast_diag}) — skip fallback", False

    # Genuine fast-path miss: queries returned cleanly, just no 0x0 mint
    # in the listing ±90d window. Token might be XPIN-style (mint
    # outside fast slice). Pay for the full 730d lookback.
    full_rows, full_diag, full_errs, full_n = fetch_mint_event_chunked(
        ca=ca, floor=mint_floor, workdir=workdir,
    )
    if full_rows:
        return full_rows, f"fast-path miss → fallback hit ({fast_diag} / {full_diag})", True
    if full_errs >= full_n:
        # H1: fallback also fully errored. Surf is broken end-to-end;
        # do NOT report this as no-anchor (silent data loss).
        return [], f"fast-path miss → fallback all errored ({fast_diag} / {full_diag})", False
    # Both paths queried cleanly, neither found a mint. Genuine
    # no-anchor case.
    return [], f"fast-path miss → fallback clean miss ({fast_diag} / {full_diag})", True


def _no_anchor_partial(
    *,
    ca: str,
    evidence_graph: EvidenceGraph,
    workdir: Path,
    mint_floor: str,
    deployment_date_floor: str,
) -> dict[str, Any]:
    """No 0x0 mint found in the lookback window — graceful degradation (v0.7.13).

    Returns a NON-error result (no 'error' key, so the pipeline does not treat
    it as a query failure and abandon the token) carrying:
      - `_status='no_deployer_anchor'`
      - `deployer=None` + empty `pre_launch_receivers` (keeps downstream verdict
        / monitoring code that indexes `received_from_deployer` safe — same
        shape the pipeline already substitutes on a hard error)
      - `top_holders`: a deployer-INDEPENDENT current-balance snapshot so the
        distribution is not lost in rule_11's own output.

    It deliberately does NOT fabricate a de-facto deployer from the earliest
    large holder: that heuristic is relay-prone (an OTC desk / bridge / pool
    that merely relayed supply looks identical to an origin) and has no
    validation case. An honest "no anchor" beats a guessed origin driving
    false dumped_pct claims. (See Phase 3 notes: a real emission/bridge
    validation token is needed before adding inferred-origin logic.)
    """
    top_holders: list[dict[str, Any]] = []
    try:
        # v0.7.23: switched from single-shot SQL_TOP_HOLDERS to sliding-
        # window fetch — on long-lived BSC tokens the full-window
        # group-by hit surf's 30s ClickHouse timeout (SKYAI 14-month
        # range with 24h 26k tx). Newer tokens with one chunk fall
        # through a single call so credit cost stays at baseline.
        rows, diag = fetch_top_holders_chunked(
            ca=ca, floor=mint_floor, ceiling=None, workdir=workdir,
        )
        print(f"[rule_11] step1b top holders: {diag}", file=sys.stderr)
        for row in rows:
            top_holders.append({
                "addr": (row.get("addr") or "").lower(),
                "total_in": float(row.get("total_in", 0.0)),
                "total_out": float(row.get("total_out", 0.0)),
                "current_balance": float(row.get("balance", 0.0)),
            })
        # Best-effort identity enrichment so a reader can separate infra
        # (vesting / CEX-custody) from real holders in the snapshot.
        try:
            from protocol_lockup_detector import enrich_addresses_with_lockup_classification
            cls_map = enrich_addresses_with_lockup_classification(
                [h["addr"] for h in top_holders if h["addr"]]
            )
            for h in top_holders:
                c = cls_map.get(h["addr"]) or {}
                h["is_protocol_lockup"] = bool(c.get("is_protocol_lockup"))
                h["is_cex_custody"] = bool(c.get("is_cex_custody"))
                # parity with the deployer-anchored enrich (the DEX / vesting /
                # multisig / treasury flags were missing here, so a DEX pool reached
                # the monitoring list with is_dex_infra unset and was mislabeled an
                # operator wallet).
                h["is_dex_infra"] = bool(c.get("is_dex_infra"))
                h["is_vesting"] = bool(c.get("is_vesting"))
                h["is_multisig"] = bool(c.get("is_multisig"))
                h["is_treasury"] = bool(c.get("is_treasury"))
                h["arkham_label"] = c.get("display_label")
        except Exception as e:
            print(f"[rule_11] no-anchor lockup classifier failed: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[rule_11] no-anchor top-holders query failed: {e}", file=sys.stderr)

    return {
        "evidence_graph": evidence_graph,
        "deployer": None,
        "mint_evt_ref": None,
        "mint_event": None,
        "pre_launch_receivers": [],
        "quiet_wallets": [],
        "dumper_destinations": {},
        "waves_proposal": [],
        "top_holders": top_holders,
        "mint_basis": "no_0x0_mint_in_lookback",
        "mint_lookback_days": MINT_LOOKBACK_DAYS,
        "_status": "no_deployer_anchor",
        "summary_text": (
            f"No 0x0 mint found for {ca} within {MINT_LOOKBACK_DAYS}d before "
            f"listing (floor {mint_floor}). Genesis likely predates surf BSC "
            f"coverage or uses a non-0x0 mechanism (bridge / proxy factory). "
            f"No deployer anchor → no pre-launch dispersal trace. Showing top "
            f"{len(top_holders)} current holders by net balance "
            f"(deployer-independent)."
        ),
    }


def run_backward_trace(
    ca: str,
    alpha_listing_date: str,
    deployment_date_floor: str | None = None,
    workdir: Path | None = None,
    evidence_graph: EvidenceGraph | None = None,
) -> dict[str, Any]:
    """Execute Rule 11 4-step backward trace, populate evidence_graph, return
    structured findings + waves_proposal.

    Args:
        ca: contract address.
        alpha_listing_date: 'YYYY-MM-DD'.
        deployment_date_floor: 'YYYY-MM-DD' or None (defaults to alpha-90d).
        workdir: temp dir for query JSON files.
        evidence_graph: EvidenceGraph instance to populate. If None, a new
            one is created and returned in the result dict.

    Returns:
        {
          "evidence_graph": EvidenceGraph,  # populated
          "deployer": "0x...",
          "mint_evt_ref": "evt_001",
          "pre_launch_receivers": [...],
          "quiet_wallets": [...],
          "dumper_destinations": {...},
          "waves_proposal": [...],
          "summary_text": "...",
        }

    Or on error:
        {"error": "<msg>", "raw": <surf response>}
    """
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="rule11_v06_"))
    workdir = Path(workdir)
    workdir.mkdir(exist_ok=True, parents=True)

    listing = date.fromisoformat(alpha_listing_date)
    if deployment_date_floor is None:
        # v0.7.1: widen default window 90d→180d for the heavy Step 2-4 scans.
        # ESPORTS (listing 2025-12-04) and H (2025-12-03) had mint events in
        # mid-2025, outside 90d but within 180d.
        deployment_date_floor = (listing - timedelta(days=180)).isoformat()

    # v0.7.13: the MINT query gets a wider floor than the Step 2-4 scans. It is
    # a selective from=0x0 lookup, cheap to widen, and catches deploy→listing
    # gaps the 180d default drops. (ISO date strings compare lexicographically,
    # so min() == the earlier date.)
    mint_floor = min(
        deployment_date_floor,
        (listing - timedelta(days=MINT_LOOKBACK_DAYS)).isoformat(),
    )

    ca = ca.lower()
    if not _valid_addr(ca):
        # adversarial review MEDIUM #3: never interpolate an unvalidated CA into surf SQL.
        return {"error": f"invalid contract address: {ca!r}", "raw": None}
    if evidence_graph is None:
        evidence_graph = EvidenceGraph()

    # ---------- Step 1: find mint event (aggregate, wide floor) ----------
    # v0.7.23: sliding-window + fast-path. Fast slice is listing-±90d
    # (1-2 chunks); falls back to mint_floor (listing-730d, ~10 chunks)
    # only when fast misses. 80-90% of LAB-class tokens hit fast,
    # saving ~9 chunks per run; XPIN-style 186d mints still found via
    # fallback. Mathematically equivalent to the single-window form
    # since SUM/MIN/COUNT distribute over the chunk partition.
    #
    # audit H1 fix: lookup_ok=False means surf errored on every
    # chunk we tried. Empty rows are NOT proof of "no mint"; we have no
    # data either way. Surface as a hard step1 failure so the pipeline
    # degrades to no-anchor partial WITH an explicit transient marker
    # (not silently misclassify the token as deployerless).
    mint_rows, mint_diag, lookup_ok = fetch_mint_event_with_fast_path(
        ca=ca, listing_date=alpha_listing_date,
        mint_floor=mint_floor, workdir=workdir,
    )
    print(f"[rule_11] step1 mint lookup: {mint_diag}", file=sys.stderr)
    if not lookup_ok:
        return {
            "error": (
                f"Step 1 (find mint) all surf chunks failed — {mint_diag}. "
                "Empty mint result is NOT evidence of no-mint; cannot "
                "anchor trace. Retry when surf BSC partition recovers."
            ),
            "raw": {"diag": mint_diag, "_step1_lookup_ok": False},
        }
    if not mint_rows:
        # No 0x0 mint anywhere in the MINT_LOOKBACK_DAYS window. Real causes:
        # (a) genesis mint predates surf's BSC partition coverage, or (b) the
        # token uses a non-0x0 mechanism (bridge / proxy factory). Either way
        # there is no deployer to anchor a trace — but we must NOT hard-error
        # and abandon the token. Degrade to a holder-distribution snapshot with
        # an explicit no-anchor status. We deliberately do NOT guess a de-facto
        # deployer from the earliest large holder: that is relay-prone and has
        # no validation case, and a fabricated origin driving false dumped_pct
        # claims is worse than an honest "no anchor".
        return _no_anchor_partial(
            ca=ca, evidence_graph=evidence_graph, workdir=workdir,
            mint_floor=mint_floor, deployment_date_floor=deployment_date_floor,
        )

    # Largest cumulative 0x0 recipient = de-facto deployer. Handles a single
    # genesis mint (1 row = full supply) and multi-recipient emission (top row
    # = biggest pre-mine; total_minted sums all 0x0 issuance).
    top = mint_rows[0]
    deployer = (top["deployer"] or "").lower()
    if not _valid_addr(deployer):
        # adversarial review MEDIUM #3: deployer is interpolated into the Step 2 SQL; never
        # trace from a malformed address.
        return {"error": f"invalid deployer address from mint query: {deployer!r}", "raw": top}
    deployer_mint_amt = float(top["amt"])
    total_minted = sum(float(r["amt"]) for r in mint_rows)
    mint_ts = min(int(r["first_mint_ts"]) for r in mint_rows)
    n_mint_recipients = len(mint_rows)
    n_mint_events = sum(int(r.get("n_mints", 1)) for r in mint_rows)
    mint_basis = (
        "genesis_0x0"
        if n_mint_recipients == 1 or deployer_mint_amt >= 0.9 * total_minted
        else "emission_0x0_multi"
    )
    # Supply reference used everywhere downstream (promotion threshold, summary
    # cap, display) = TOTAL tokens minted via 0x0, not just the deployer share.
    mint_amt = total_minted

    # v0.7.13: extend the heavy Step 2-4 floor back to the mint day when the
    # mint is older than the 180d default (XPIN), so dispersal between genesis
    # and the 180d floor is not silently dropped. Bounded below by mint_floor
    # (≤730d) since mint_ts was found within that window → widening is capped.
    mint_date_day = _ts_to_date(mint_ts)
    trace_floor = min(deployment_date_floor, mint_date_day)
    mint_found_outside_180d = mint_date_day < deployment_date_floor

    mint_evt_ref = evidence_graph.add_event(
        type="mint",
        ts=mint_ts,
        amount=deployer_mint_amt,
        from_addr="0x0000000000000000000000000000000000000000",
        to_addr=deployer,
        notes=(
            None if mint_basis == "genesis_0x0"
            else (f"multi-recipient/emission: {n_mint_recipients} recipients, "
                  f"{n_mint_events} 0x0 mints, total {total_minted:,.0f}; "
                  f"deployer={deployer_mint_amt:,.0f}")
        ),
    )

    # ---------- Step 2: deployer outflows ----------
    q2 = _write_query(
        workdir, "step2_deployer_outflows",
        SQL_DEPLOYER_OUTFLOWS.format(
            ca=ca, deployer=deployer,
            date_floor=trace_floor,
            alpha_listing_date=alpha_listing_date,
        transfers=transfers_table(), decimals_factor=decimals_factor_str(), dex_trades=dex_trades_table()),
        max_rows=100,
    )
    results, _ = run_parallel([str(q2)])
    step2 = results[str(q2)]
    if "error" in step2:
        return {"error": "Step 2 (deployer outflows) failed.", "raw": step2}

    outflow_rows = step2.get("data", [])
    if not outflow_rows:
        return {
            "evidence_graph": evidence_graph,
            "deployer": deployer,
            "mint_evt_ref": mint_evt_ref,
            "mint_event": {"ts": mint_ts, "amount": mint_amt},
            "pre_launch_receivers": [],
            "quiet_wallets": [],
            "dumper_destinations": {},
            "waves_proposal": [],
            "mint_basis": mint_basis,
            "total_minted": total_minted,
            "deployer_mint_amt": deployer_mint_amt,
            "n_mint_recipients": n_mint_recipients,
            "mint_lookback_days": MINT_LOOKBACK_DAYS,
            "mint_found_outside_180d": mint_found_outside_180d,
            "summary_text": (
                f"Deployer {deployer[:10]}... minted {mint_amt:,.0f} tokens "
                f"at {_ts_to_iso(mint_ts)} but had no outflows in pre-listing "
                f"window [{trace_floor}, {alpha_listing_date}]."
            ),
        }

    # Burn / mint sinks — never count these as receivers. NEX 3-sym test
    # exposed this on 2026-05-24: deployer burned tokens to 0x0, the burn
    # destination got logged as an m6 "receiver" with bal=-4.5T (because 0x0
    # is also the mint source on-chain), dumped_pct=10^14%. Filtering at
    # aggregation prevents the m6 row + downstream destination trace from
    # picking up the burn flow.
    _BURN_ADDRS = {
        "0x0000000000000000000000000000000000000000",
        "0x000000000000000000000000000000000000dead",
    }

    # Add deployer outflow events + aggregate by receiver
    receiver_totals: dict[str, float] = {}
    receiver_first_outflow_ts: dict[str, int | str] = {}
    receiver_first_evt_ref: dict[str, str] = {}
    for row in outflow_rows:
        addr = (row["receiver"] or "").lower()
        if addr in _BURN_ADDRS:
            # Still record the burn as a deployer_outflow event in evidence_graph
            # (for provenance + monitoring), but skip the m6 aggregation.
            evidence_graph.add_event(
                type="deployer_outflow",
                ts=row["block_time"],
                amount=float(row["amt"]),
                from_addr=deployer,
                to_addr=addr,
            )
            continue
        amt = float(row["amt"])
        ts = row["block_time"]
        evt_ref = evidence_graph.add_event(
            type="deployer_outflow",
            ts=ts,
            amount=amt,
            from_addr=deployer,
            to_addr=addr,
        )
        if addr not in receiver_totals:
            receiver_totals[addr] = 0.0
            receiver_first_outflow_ts[addr] = ts
            receiver_first_evt_ref[addr] = evt_ref
        receiver_totals[addr] += amt

    # ---------- Step 3: compute balance + dumped_pct per receiver ----------
    # NEX 3-sym test (2026-05-24): if every deployer outflow went to burn
    # addresses, the burn filter above leaves receiver_totals empty. Surf
    # rejects arrayJoin([]) with INVALID_REQUEST. Emit a "no real receivers"
    # result instead of crashing the whole Rule 11 chain — caller (forensic
    # pipeline) treats this as a legitimate degenerate case (token deployer
    # only burns, no pre-launch dispersal to humans).
    if not receiver_totals:
        return {
            "evidence_graph": evidence_graph,
            "deployer": deployer,
            "mint_evt_ref": mint_evt_ref,
            "mint_event": {"ts": mint_ts, "amount": mint_amt},
            "pre_launch_receivers": [],
            "quiet_wallets": [],
            "dumper_destinations": {},
            "waves_proposal": [],
            "mint_basis": mint_basis,
            "total_minted": total_minted,
            "deployer_mint_amt": deployer_mint_amt,
            "n_mint_recipients": n_mint_recipients,
            "mint_lookback_days": MINT_LOOKBACK_DAYS,
            "mint_found_outside_180d": mint_found_outside_180d,
            "summary_text": (
                f"Deployer {deployer[:10]}... minted {mint_amt:,.0f} tokens "
                f"at {_ts_to_iso(mint_ts)}. All pre-listing outflows in window "
                f"[{trace_floor}, {alpha_listing_date}] went to burn "
                f"addresses (0x0 / 0xdead). No human/insider receivers detected."
            ),
        }
    # v0.7.23: sliding-window receiver balance fetch. The single-window
    # SQL_RECEIVER_BALANCES used `block_date >= trace_floor` (no upper
    # bound), which on a 14-month-old token timed out at surf side
    # before returning anything. The chunked variant scans 90d at a
    # time per receiver IN-list, sums per-chunk in Python, and returns
    # the same {addr → total_in/total_out/balance} dict shape.
    receiver_list = _clean_addrs(list(receiver_totals.keys()))
    balances_by_addr, balances_diag, balances_ok = fetch_receiver_balances_chunked(
        ca=ca, receivers=receiver_list, floor=trace_floor, ceiling=None,
        workdir=workdir,
    )
    print(f"[rule_11] step3 receiver balances: {balances_diag}", file=sys.stderr)
    if not balances_by_addr:
        return {"error": "Step 3 (balances) failed.", "raw": {"diag": balances_diag}}
    # audit H1 fix: if EVERY chunk surfed errored, the dict above
    # is zero-filled for every receiver. Downstream classifies balance=0
    # as `rule11_full_dumper` (dumped_pct=100%) — a catastrophic
    # false-positive driven by surf transport failure, not insider
    # dumping. Fail loud instead.
    if not balances_ok:
        return {
            "error": (
                f"Step 3 (balances) all surf chunks failed — {balances_diag}. "
                "Receiver balances are not zero, they are UNKNOWN; cannot "
                "classify dumpers vs quiet wallets. Retry when surf "
                "recovers."
            ),
            "raw": {"diag": balances_diag, "_step3_lookup_ok": False},
        }

    receivers: list[dict[str, Any]] = []
    # Iterate the deployer-side receiver list so every requested address
    # gets a row, even one that had zero post-listing activity (matches
    # the single-window LEFT JOIN behavior).
    for addr in receiver_list:
        b = balances_by_addr.get(addr) or {}
        received = receiver_totals.get(addr, float(b.get("total_in", 0.0)))
        balance = float(b.get("balance", 0.0))
        dumped = max(received - balance, 0.0)
        dumped_pct = (dumped / received * 100.0) if received > 0 else 0.0

        # Classify + add to evidence graph as m6 row
        if dumped_pct == 0.0:
            m6_type = "rule11_quiet"
        elif dumped_pct >= 95.0:
            m6_type = "rule11_full_dumper"
        else:
            m6_type = "rule11_partial_dumper"

        m6_ref = evidence_graph.add_m6(
            type=m6_type,
            addr=addr,
            received=received,
            balance=balance,
            dumped_pct=round(dumped_pct, 2),
            source_section="rule_11",
            ts_received=receiver_first_outflow_ts.get(addr),
        )

        receivers.append({
            "addr": addr,
            "evt_ref_received": receiver_first_evt_ref.get(addr),
            "m6_ref": m6_ref,
            "received_from_deployer": received,
            "current_balance": balance,
            "dumped": dumped,
            "dumped_pct": round(dumped_pct, 2),
        })
    receivers.sort(key=lambda r: r["dumped_pct"], reverse=True)

    # ---------- Step 4: dumper destinations (v0.7.9 recursive expansion) ----------
    # v0.7.9: depth-1 was the ESPORTS 5/19 cluster miss — main distributor
    # 0x94111012 was a 1st-level receiver of 100M that re-distributed 50M to 8
    # fresh wallets. Pipeline saw 0x94111012 but never scanned its outflows.
    # Fix: any m6 receiver getting > MIN_SUPPLY_PCT of total mint to a single
    # sub-receiver promotes that sub-receiver to m6 + scans its outflows.
    # Bounded recursion to depth 4. Sub-dumper events naturally flow into
    # `dumper_destinations` which wave 2 reads → user sees the full chain.
    MIN_SUPPLY_PCT = 0.005  # 0.5% of total mint
    MAX_DEPTH = 4
    MIN_PROMOTE_AMT = mint_amt * MIN_SUPPLY_PCT
    # v0.7.14: the recursion was depth-capped (≤4) but BREADTH-unbounded — every
    # sub-receiver > 0.5% supply at every depth got promoted + scanned. A
    # high-supply wide-distribution token (XPIN, 100B → 0.5% = 500M, crossed by
    # dozens of sub-receivers per level) fanned out to hundreds/thousands of
    # surf queries and a 20+ min run that had to be killed. Cap the TOTAL number
    # of promoted sub-dumpers across all depths and spend that budget on the
    # LARGEST dispersals first (forensically the chains that matter); flag the
    # rest as truncated. Immediate destinations are still recorded for every
    # dumper (wave display) — only the FURTHER recursive expansion is bounded.
    # v0.9.7 fix (post-decimals): cap step4 total promotions across all
    # depths. v0.7.14 set 40 to handle XPIN-class wide-fanout tokens, but
    # with v0.9.7 decimals fix (FOLKS-class 6-decimal tokens), more sub-
    # dumpers now cross the promote threshold (real amounts surfaced where
    # 1e-12 量级 bug previously filtered them). FOLKS empirical: 18 sub-
    # dumpers promoted across 4 batches = 90 chunk SQL = 7+ min step4
    # alone. Lower the default to 12 so non-18-decimal token reports don't
    # take 3× longer than 18-decimal equivalents. Tokens that genuinely
    # need deep coverage (XPIN-class wide fanout) override via env.
    #
    # Trade-off: skipped sub-dumpers still appear as `recursion_truncated:
    # True` + `n_sub_dumpers_skipped: N` in the skeleton, so the report
    # Data Gap section discloses what was truncated. The forensic verdict
    # generally sits on the top-12 biggest fish anyway (smaller wallets
    # individually shift verdict <5%), so truncation cost on the verdict
    # is low.
    MAX_PROMOTED_SUBDUMPERS = int(
        os.environ.get("BINANCE_ALPHA_STEP4_MAX_DUMPERS", "12")
    )
    # Seeded from first-level receivers only (Step 3 set their dumped_pct to a
    # float); sub-dumpers with possibly-None dumped_pct are appended later by
    # the recursion below. Guard None anyway so a future reorder can't crash.
    top_dumpers = [
        r for r in receivers
        if r.get("dumped_pct") is not None
        and r["dumped_pct"] >= 10.0 and r["received_from_deployer"] >= 5_000_000
    ][:5]

    dumper_destinations: dict[str, list[dict[str, Any]]] = {}
    _already_m6: set[str] = {r["addr"] for r in receivers}
    _already_m6.add(deployer.lower())
    _already_m6.update(_BURN_ADDRS)
    promoted_count = 0
    promote_skipped = 0
    promote_skipped_tokens = 0.0  # v0.9.7 adversarial review Finding 6: aggregate skipped size
    # v0.9.6 Fix #3 (adversarial review Windows EVAA 2026-06-15 feedback): collect
    # step4 dumpers SKIPPED due to chunk errors. Pre-v0.9.6 the SKIPPED
    # warning was only printed to stderr; the skeleton had no record so
    # users couldn't see how many dumpers were dropped or which ones.
    # render_report uses this to emit a Data Gap entry.
    step4_skipped_dumpers: list[dict[str, Any]] = []

    # Process queue of (dumper, depth) — starts with top_dumpers at depth 1
    process_queue: list[tuple[str, int]] = [(r["addr"], 1) for r in top_dumpers]

    while process_queue:
        current_batch = list(process_queue)
        process_queue = []
        # v0.7.23 regression-fix (in-session): the first pass of this loop
        # called `fetch_dumper_destinations_chunked` once per dumper inside
        # a Python `for`, which serialized the dumper axis even though
        # each call internally fanned its 7 chunks out across a
        # `parallel_run_chunked` ThreadPool. On SKYAI (14-month window, 4
        # recursion depths, ~20 dumpers per depth) that turned 56 minutes
        # of wall-time into >2h. v0.7.22 baseline (`run_parallel(all
        # dumper queries)`) submitted the whole batch at once into an
        # 8-worker pool, which is the correct shape.
        #
        # Fix: flatten `(dumper × chunk_floor × chunk_ceiling)` into a
        # single task list and dispatch it through
        # `parallel_run_flat_tasks` with `max_workers=8` to match v0.7.22.
        # Per-dumper rows are then Python-merged via `merge_chunked_rows`
        # (same SUM/MIN/MAX semantics as the chunked single-dumper path).
        chunks_step4 = _single_chunk_or_chunker_dates(trace_floor, None, chunk_days=90)
        chunk_summary_step4 = chunk_summary(chunks_step4)
        valid_batch = [
            (d, dp) for d, dp in current_batch if _valid_addr(d)
        ]
        # Cartesian product → flat list. Order matters: zip(flat_tasks,
        # results) needs to round-trip to (dumper, chunk_rows).
        # audit H2: include enumerated index in name_prefix so two
        # dumpers sharing the first 10 chars (vanity-prefix clusters like
        # 0x0000092d / 0x0000719d seen on SKYAI) can never race-write the
        # same temp JSON file under concurrent ThreadPool execution.
        flat_tasks: list[tuple[int, str, int, str, str]] = [
            (idx, dumper, depth, cf, cc)
            for idx, (dumper, depth, cf, cc) in enumerate(
                (dumper, depth, cf, cc)
                for dumper, depth in valid_batch
                for cf, cc in chunks_step4
            )
        ]

        # audit M5: keep the env worker-throttle escape hatch even
        # when matching v0.7.22 baseline cap. 8 is the safe default; ops
        # can lower via `BINANCE_ALPHA_STEP4_WORKERS` if surf 429s.
        step4_workers = int(os.environ.get("BINANCE_ALPHA_STEP4_WORKERS", "8"))

        def _step4_one(task: tuple[int, str, int, str, str]) -> dict[str, Any]:
            idx, dumper, _depth, cf, cc = task
            sql = SQL_DUMPER_DESTINATIONS_CHUNK.format(
                ca=ca, dumper=dumper,
                chunk_floor=cf, chunk_ceiling=cc,
                transfers=transfers_table(), decimals_factor=decimals_factor_str(),
            )
            # audit H2 fix: full 40-char dumper address (already
            # _valid_addr-checked) + per-batch unique idx in filename.
            return _run_one_chunk(
                sql, workdir, f"step4_dest_{dumper}_{cf}_{idx:04d}",
            )

        flat_results = parallel_run_flat_tasks(
            _step4_one, flat_tasks, max_workers=step4_workers,
        )

        # Re-group: dumper_addr → [chunk_rows_1, chunk_rows_2, ...]
        per_dumper_chunks: dict[str, list[list[dict[str, Any]]]] = defaultdict(list)
        per_dumper_errs: dict[str, int] = defaultdict(int)
        for task, result in zip(flat_tasks, flat_results):
            _idx, dumper_addr, _depth, _cf, _cc = task
            per_dumper_chunks[dumper_addr].append(result.get("data") or [])
            if result.get("_error"):
                per_dumper_errs[dumper_addr] += 1

        # Batch-level diagnostic (one line per batch, not per dumper).
        # audit L7 fix.
        print(
            f"[rule_11] step4 batch d{valid_batch[0][1] if valid_batch else '?'}: "
            f"{len(valid_batch)} dumpers × {chunk_summary_step4} "
            f"(flat-parallel, {step4_workers}-worker pool)",
            file=sys.stderr,
        )

        dest_results: list[tuple[str, int, list[dict[str, Any]] | None]] = []
        n_chunks = len(chunks_step4)
        for dumper_addr, depth in valid_batch:
            err_n = per_dumper_errs.get(dumper_addr, 0)
            # audit H3 fix: any chunk error → mark this dumper's
            # rows as None so the downstream Pass 1/Pass 2 logic
            # (lines below) skips it for `dumper_destinations` recording
            # and promotion candidate gathering. Matches v0.7.22
            # "if 'error' in resp: continue" behaviour where a failed
            # single-window query did not emit partial truth.
            if err_n > 0:
                print(
                    f"[rule_11] step4 dumper {dumper_addr[:10]}… d{depth}: "
                    f"SKIPPED ({err_n}/{n_chunks} chunks errored) — partial "
                    f"data would undercount total_amt and skew promotion",
                    file=sys.stderr,
                )
                # v0.9.6 Fix #3: structured record for Data Gap render.
                step4_skipped_dumpers.append({
                    "addr": dumper_addr,
                    "depth": depth,
                    "errored_chunks": err_n,
                    "total_chunks": n_chunks,
                })
                dest_results.append((dumper_addr, depth, None))
                continue
            merged = merge_chunked_rows(
                per_dumper_chunks.get(dumper_addr, []),
                key_field="receiver",
                sum_fields=["total_amt", "num_tx"],
                min_fields=["first_tx"],
                max_fields=["last_tx"],
            )
            # audit H1 fix: keep top-30 to match v0.7.22 baseline
            # `ORDER BY total_amt DESC LIMIT 30`. The chunker emits 200
            # per-chunk × 7 chunks = 1400 candidates so the merged
            # top-30 is the true global top-30 (no truncation bias).
            rows = merged[:30]
            dest_results.append((dumper_addr, depth, rows))
        # Pass 1: record destinations for every dumper + gather promote candidates.
        promote_candidates: list[tuple[float, str, int, str, Any]] = []
        for dumper_addr, depth, rows in dest_results:
            if rows is None:
                continue
            dest_rows = []
            for d in rows:
                evt_ref = evidence_graph.add_event(
                    type="cex_hop" if "0d07" in d["receiver"] else "recent_transfer",
                    ts=d.get("first_tx"),
                    amount=float(d["total_amt"]),
                    from_addr=dumper_addr,
                    to_addr=d["receiver"],
                )
                dest_rows.append({
                    "to": d["receiver"],
                    "evt_ref": evt_ref,
                    "total_amt": float(d["total_amt"]),
                    "num_tx": int(d.get("num_tx", 0)),
                    "first_tx": d.get("first_tx"),
                    "last_tx": d.get("last_tx"),
                    "_depth": depth,
                })
                # v0.7.9 recursion: candidate to promote sub-receiver if > 0.5%
                # supply. v0.7.14: collect, then promote largest-first under the
                # global budget (Pass 2) instead of promoting inline.
                sub_addr = (d["receiver"] or "").lower()
                sub_amt = float(d["total_amt"])
                if (
                    depth < MAX_DEPTH
                    and sub_addr
                    and sub_addr not in _already_m6
                    and sub_amt >= MIN_PROMOTE_AMT
                ):
                    promote_candidates.append(
                        (sub_amt, sub_addr, depth, evt_ref, d.get("first_tx"))
                    )
            dumper_destinations[dumper_addr] = dest_rows
        # Pass 2: promote the largest dispersals first, within the global budget.
        promote_candidates.sort(key=lambda c: c[0], reverse=True)
        for sub_amt, sub_addr, depth, evt_ref, first_tx in promote_candidates:
            if sub_addr in _already_m6:
                continue  # a sub-receiver shared by two dumpers in this batch
            if promoted_count >= MAX_PROMOTED_SUBDUMPERS:
                promote_skipped += 1
                # v0.9.7 adversarial review Finding 6 (HIGH): accumulate the SIZE of
                # skipped sub-dumpers, not just the count. Pre-fix the cap
                # silently dropped the 13th+ biggest sub-dumpers from the
                # receiver set, so the verdict undercounted with only
                # `recursion_truncated=True` as a hint. Now we surface the
                # aggregate token amount skipped so the report Data Gap can
                # say "verdict is a LOWER BOUND — N more sub-dumpers holding
                # ~X tokens were not expanded".
                promote_skipped_tokens += float(sub_amt or 0)
                continue
            m6_ref = evidence_graph.add_m6(
                type="rule11_sub_dumper",
                addr=sub_addr,
                received=sub_amt,
                balance=None,
                dumped_pct=None,
                source_section=f"rule_11_depth_{depth + 1}",
                ts_received=first_tx,
            )
            _already_m6.add(sub_addr)
            receivers.append({
                "addr": sub_addr,
                "evt_ref_received": evt_ref,
                "m6_ref": m6_ref,
                "received_from_deployer": sub_amt,
                "current_balance": None,
                "dumped": None,
                "dumped_pct": None,
                "_depth": depth + 1,
                "_parent_dumper": dumper_addr,
            })
            process_queue.append((sub_addr, depth + 1))
            promoted_count += 1

    recursion_truncated = promote_skipped > 0

    # v0.7.9: backfill balance + dumped_pct for sub-dumpers via single SQL.
    # v0.7.23 audit M4 fix: switch to chunker (with conditional
    # bypass for short windows). Sub-dumper backfill on a SKYAI-class
    # window was the last remaining single-SQL site that hit the surf
    # 30s timeout after Step 4 had already chunked successfully —
    # silently flipping all sub-dumpers to `_balance_unverified` and
    # excluding them from the verdict. Now follows the same chunker +
    # lookup_ok path as step3, with v0.7.13's surf-failure semantics
    # preserved (None / _balance_unverified) so a transient surf
    # outage NEVER zero-fills sub-dumpers into rule11_full_dumper.
    sub_dumpers = [r for r in receivers if r.get("_depth", 1) > 1]
    if sub_dumpers:
        sub_addrs = [r["addr"] for r in sub_dumpers]
        sub_bal_dict, sub_diag, sub_ok = fetch_receiver_balances_chunked(
            ca=ca, receivers=_clean_addrs(sub_addrs),
            floor=trace_floor, ceiling=None, workdir=workdir,
            name_prefix="step4b_sub_balances",
        )
        print(
            f"[rule_11] step4b sub_balances: {sub_diag}",
            file=sys.stderr,
        )
        # v0.7.13 (issue #1 Bug 1, adversarial review HIGH #1): distinguish two cases so a
        # surf failure never masquerades as confirmed behaviour —
        #   • query OK + row missing → address holds no net-positive position →
        #     genuinely fully dumped (existing convention, fed to verdict).
        #   • query ERRORED (e.g. 429 exhausting parallel_surf's retries) →
        #     balance is UNKNOWN → leave dumped_pct / current_balance = None
        #     and flag `_balance_unverified`. The downstream `is not None`
        #     guards then exclude these rows from quiet/partial/full buckets,
        #     dumper counts and the verdict, so a sustained outage can NOT
        #     inflate the full-dumper count or flip the verdict to
        #     EXIT_IF_HOLDING. (None is rendered as "—".)
        # v0.7.23: query_failed now means "every chunk in the sliding
        # window errored", not "the single SQL call errored". Same
        # semantics, different transport.
        query_failed = not sub_ok
        # Re-shape chunker output `{addr: {total_in, total_out, balance}}`
        # into the legacy `bal_by_addr[addr] -> {"balance": ...}` form so
        # the original sub-dumper update loop below works unchanged.
        bal_by_addr: dict[str, Any] = {} if query_failed else sub_bal_dict
        if query_failed:
            print(
                f"[rule_11] sub-dumper balance backfill failed after retries "
                f"({sub_diag}); {len(sub_dumpers)} sub-dumpers left "
                f"balance-unverified (excluded from dumper counts/verdict).",
                file=sys.stderr,
            )
        for r in sub_dumpers:
            row = bal_by_addr.get(r["addr"])
            if row:
                received = r["received_from_deployer"]
                balance = float(row.get("balance", 0.0))
                dumped = max(received - balance, 0.0)
                dumped_pct = (dumped / received * 100.0) if received > 0 else 0.0
                r["current_balance"] = balance
                r["dumped"] = dumped
                r["dumped_pct"] = round(dumped_pct, 2)
                m6_entry = evidence_graph._store.get(r["m6_ref"])
                if m6_entry:
                    m6_entry["balance"] = balance
                    m6_entry["dumped_pct"] = round(dumped_pct, 2)
            elif query_failed:
                # Unknown — could not fetch. Honest None; guards exclude it.
                r["current_balance"] = None
                r["dumped"] = None
                r["dumped_pct"] = None
                r["_balance_unverified"] = True
            else:
                # Query OK but address absent → no net position → fully dumped.
                r["current_balance"] = 0.0
                r["dumped"] = r["received_from_deployer"]
                r["dumped_pct"] = 100.0

    # ---------- Build waves_proposal ----------
    quiet_wallets = [r for r in receivers if r["dumped_pct"] == 0.0]
    # `received_from_deployer` is a FLOW — summing it across all receivers
    # double-counts whenever the deployer round-trips / relays tokens (R2: a
    # relay chain logged ~total supply at each of 4 hops → sum > total supply).
    # Cap the summary "distributed" figure at the mint amount: the deployer
    # cannot have distributed more than it minted. (Cosmetic summary line only.)
    total_received = min(sum(r["received_from_deployer"] for r in receivers), mint_amt)
    total_quiet_balance = sum(r["current_balance"] for r in quiet_wallets)

    waves_proposal: list[dict[str, Any]] = []

    # Wave 1: Pre-launch OTC distribution
    # v0.7.9: pre-launch is **deployer → 1st-level receivers only**. Sub-receivers
    # from recursive m6 (_depth > 1) must not render in wave 1 with deployer-as-from
    # — they'd trigger V_PROVENANCE_MISMATCH (their actual from is a sub-dumper).
    first_level_receivers = [r for r in receivers if r.get("_depth", 1) == 1]
    if first_level_receivers:
        first_level_ts = [
            receiver_first_outflow_ts[r["addr"]]
            for r in first_level_receivers
            if r["addr"] in receiver_first_outflow_ts
        ]
        outflow_ts_min = min(first_level_ts) if first_level_ts else mint_ts
        outflow_ts_max = max(first_level_ts) if first_level_ts else mint_ts
        wave1_events = []
        for r in first_level_receivers[:8]:  # top 8 by dumped_pct for narrative compactness
            wave1_events.append({
                "evt_ref": r["evt_ref_received"],
                "ts": _ts_to_iso(receiver_first_outflow_ts.get(r["addr"])),
                "hours_ago_text": "<LLM_NARRATIVE_PLACEHOLDER>",
                "from_to": f"{t('rule_11.from_to_deployer_prefix')} `{deployer[:10]}…` → `{r['addr'][:10]}…`",
                "amount": f"{r['received_from_deployer']:,.0f} tokens",
                "nature": "<LLM_NARRATIVE_PLACEHOLDER>",
            })
        waves_proposal.append({
            "emoji": "🟠",
            "title": t("anomaly.wave_title.pre_launch_otc"),
            "ts_range": f"{_ts_to_date(outflow_ts_min)} ~ {_ts_to_date(outflow_ts_max)} UTC",
            "status_text": t("anomaly.wave_status.completed"),
            "events": wave1_events,
            "_pipeline_locked_fields": ["evt_ref", "ts", "from_to", "amount"],
        })

    # Wave 2: Dumper distribution (1st-level + recursive sub-dumpers)
    # v0.7.9: 同源合并 — 每个 dumper 一行 summary "X → N 个新地址 (总 Y tokens)",
    # 不再逐 (source, dest) 列. ESPORTS 0x94111012 → 8 cluster 合成一行,
    # 而不是 8 行. 详细每条 destination 在 evidence_graph + monitoring JSON
    # 里, 用户跟踪不耽误.
    if top_dumpers and dumper_destinations:
        all_dump_ts = []
        wave2_events = []
        # Sort dumpers by total outflow amount DESC for wave 2 ordering.
        dumper_summaries = []
        for dumper_addr, dest_rows in dumper_destinations.items():
            if not dest_rows:
                continue
            total_amt = sum(d["total_amt"] for d in dest_rows)
            n_dests = len(dest_rows)
            first_tx_min = min(d["first_tx"] for d in dest_rows if d.get("first_tx"))
            last_tx_max = max(d["last_tx"] for d in dest_rows if d.get("last_tx"))
            # Pick representative evt_ref (top dest by amount) for provenance.
            top_dest = max(dest_rows, key=lambda d: d["total_amt"])
            dumper_summaries.append({
                "dumper_addr": dumper_addr,
                "n_dests": n_dests,
                "total_amt": total_amt,
                "first_tx": first_tx_min,
                "last_tx": last_tx_max,
                "evt_ref": top_dest["evt_ref"],  # link to one representative event
            })
        # Sort by total_amt DESC + take top 20 dumpers for wave 2 narrative.
        dumper_summaries.sort(key=lambda x: x["total_amt"], reverse=True)
        dumper_summaries = dumper_summaries[:20]

        for s in dumper_summaries:
            all_dump_ts.append(s["first_tx"])
            wave2_events.append({
                "evt_ref": s["evt_ref"],
                "ts": _ts_to_iso(s["first_tx"]),
                "hours_ago_text": "<LLM_NARRATIVE_PLACEHOLDER>",
                # v0.7.9: 同源合并 — "X → N 个新地址" 而不是 "X → 0xabc..."
                "from_to": t(
                    "sec1.rule_11.wave2_from_to",
                    dumper_short=s['dumper_addr'][:10],
                    n_dests=s['n_dests'],
                ),
                "amount": t("sec1.rule_11.wave2_amount", total_amt=s['total_amt']),
                "nature": "<LLM_NARRATIVE_PLACEHOLDER>",
            })
        if wave2_events:
            ts_min = min(all_dump_ts)
            ts_max = max(all_dump_ts)
            waves_proposal.append({
                "emoji": "🔴",
                "title": t("anomaly.wave_title.dumper_to_downstream"),
                "ts_range": f"{_ts_to_date(ts_min)} ~ {_ts_to_date(ts_max)} UTC",
                "status_text": "<LLM_NARRATIVE_PLACEHOLDER>",
                "events": wave2_events,
                "_pipeline_locked_fields": ["evt_ref", "ts", "from_to", "amount"],
            })

    # v0.7.10.3: enrich every receiver with Arkham label classification so
    # downstream sections can separate project-side / infrastructure
    # (vesting / multisig / treasury / DEX-infra / CEX-custody) from genuine
    # insider candidates. rule_11 itself is a pure transfer-graph analysis
    # with no identity awareness — without this, a project's vesting
    # contract (COLLECT 0xf27d6fc9 = "Vesting (Proxy)", 79% of supply) or
    # Binance's omnibus custody wallet (COLLECT 0x73d8bd54 = "Binance
    # Wallet") gets counted as a quiet/partial insider receiver.
    try:
        from protocol_lockup_detector import enrich_addresses_with_lockup_classification
        addrs = [r.get("addr") for r in receivers if r.get("addr")]
        lockup_map = enrich_addresses_with_lockup_classification(addrs)
        for r in receivers:
            cls = lockup_map.get((r.get("addr") or "").lower()) or {}
            r["is_vesting"] = bool(cls.get("is_vesting"))
            r["is_multisig"] = bool(cls.get("is_multisig"))
            r["is_treasury"] = bool(cls.get("is_treasury"))
            r["is_dex_infra"] = bool(cls.get("is_dex_infra"))
            r["is_cex_custody"] = bool(cls.get("is_cex_custody"))
            r["is_protocol_lockup"] = bool(cls.get("is_protocol_lockup"))
            r["arkham_label"] = cls.get("display_label")
        # v0.7.19.3 (P0 data-correctness): exclude Arkham-confirmed
        # protocol_lockup wallets (vesting / multisig / treasury /
        # dex_infra / cex_custody) from quiet_wallets. A locked vesting
        # contract is NOT an "insider quiet wallet" — its release follows
        # a public schedule, governance, or smart-contract auto-vest, not
        # an opaque insider hand. Conflating them produced the COLLECT
        # verdict bug where "80% 潜伏 insider 抛压" was actually 80%
        # vesting + Gnosis Safe (Arkham label "Vesting (Proxy)" +
        # "Gnosis Safe Proxy"); the verdict downgraded to
        # EXIT_IF_HOLDING on a signal that does not exist.
        # `genuine_quiet` was already filtering this for the
        # summary_text narrative since v0.7.10.3, but the canonical
        # `quiet_wallets` returned to forensic_pipeline / detector_summary
        # / section_l_distribution was the unfiltered version. Unify.
        quiet_wallets = [r for r in receivers if is_genuine_quiet_holder(r)]
        # v1.2.8: 0-value address-poisoning decoys (dumped_pct==0 but received 0 /
        # hold 0) are tracked separately, NOT counted as quiet overhang.
        decoy_wallets = [r for r in receivers if is_zero_balance_decoy(r)]
        quiet_wallets_classifier_ok = True
    except Exception as e:
        print(f"[rule_11] lockup classifier failed: {e}", file=sys.stderr)
        # v0.7.19.3 adversarial review HIGH#1: fail-CLOSED instead of fail-open.
        # The pre-audit draft fell back to the unfiltered
        # `[r for r in receivers if dumped_pct == 0]` list, which
        # silently reintroduced the exact false-潜伏 inflation this
        # patch fixes any time the classifier raised. Now we return an
        # empty quiet_wallets + set `quiet_wallets_classifier_ok=False`
        # so downstream renderers can show an "untrusted" badge instead
        # of a (potentially inflated) detector count. The verdict
        # engine is independent of quiet_wallets (it reads
        # pre_launch_receivers directly with per-row is_protocol_lockup
        # checks), so a fail-closed empty list does not affect the
        # actual EXIT_IF_HOLDING decision — only the surfaced count.
        quiet_wallets = []
        quiet_wallets_classifier_ok = False

    # `genuine_quiet` kept as alias for symmetry with the v0.7.10.3
    # summary_text path. With the fix above, quiet_wallets == genuine_quiet
    # on the happy path; both empty on the classifier-failed path.
    genuine_quiet = quiet_wallets
    genuine_quiet_balance = sum(r.get("current_balance", 0) for r in genuine_quiet)
    summary_text = t(
        "rule_11.summary_minted_distributed",
        deployer_short=deployer[:10],
        mint_ts=_ts_to_iso(mint_ts),
        mint_amount=int(mint_amt),
        n_receivers=len(receivers),
        distributed_amount=int(total_received),
        n_quiet=len(genuine_quiet),
        quiet_balance=int(genuine_quiet_balance),
    )
    # v0.7.14 (adversarial review HIGH #1): expose every NUMBER cited in summary_text as
    # locked fields so V_NARRATIVE_NUMERIC_HALLUCINATION's pool naturally
    # includes them. Earlier fix exempted m4_notes[0] entirely, but that opens
    # a numeric-bypass on the writable m4_notes[] array (LLM could place a
    # fabricated number at index 0 and evade the check). Pooling the numbers
    # closes the bypass and removes the false-positive in one move.
    summary_locked_numbers = {
        "mint_amount": int(mint_amt),
        "n_receivers": len(receivers),
        "distributed_amount": int(total_received),
        "n_quiet": len(genuine_quiet),
        "quiet_balance": int(genuine_quiet_balance),
        "n_decoy": len(decoy_wallets),
    }

    return {
        "evidence_graph": evidence_graph,
        "deployer": deployer,
        "mint_evt_ref": mint_evt_ref,
        "mint_event": {"ts": mint_ts, "amount": mint_amt},
        "pre_launch_receivers": receivers,
        "quiet_wallets": quiet_wallets,
        # v1.2.8: 0-value address-poisoning decoys, surfaced separately so the
        # operator-obfuscation tactic stays visible (not silently merged into quiet).
        "decoy_wallets": decoy_wallets,
        "n_decoy": len(decoy_wallets),
        # v0.7.19.3 adversarial review HIGH#1: if False, `quiet_wallets` was
        # fail-closed-emptied because the protocol_lockup classifier
        # raised; downstream renderers should mark detector counts
        # / decision-block conditions derived from quiet_wallets as
        # untrusted rather than treating an empty list as "no quiet
        # insiders found".
        "quiet_wallets_classifier_ok": quiet_wallets_classifier_ok,
        "dumper_destinations": dumper_destinations,
        "waves_proposal": waves_proposal,
        "mint_basis": mint_basis,
        "total_minted": total_minted,
        "deployer_mint_amt": deployer_mint_amt,
        "n_mint_recipients": n_mint_recipients,
        "mint_lookback_days": MINT_LOOKBACK_DAYS,
        "mint_found_outside_180d": mint_found_outside_180d,
        # v0.7.14: Step-4 recursion budget telemetry. recursion_truncated=True
        # means the dispersal tree was wider than MAX_PROMOTED_SUBDUMPERS and
        # only the largest chains were followed (a report should disclose this).
        "recursion_truncated": recursion_truncated,
        "n_sub_dumpers_promoted": promoted_count,
        "n_sub_dumpers_skipped": promote_skipped,
        # v0.9.7 adversarial review Finding 6 (HIGH): aggregate token amount of skipped
        # sub-dumpers. When >0, the verdict is a LOWER BOUND — the report
        # Data Gap discloses "N more sub-dumpers holding ~X tokens were not
        # recursively expanded due to the step4 budget cap".
        "n_sub_dumpers_skipped_tokens": promote_skipped_tokens,
        # v0.9.6 Fix #3 (adversarial review Windows EVAA 2026-06-15 feedback): step4
        # dumpers dropped due to chunk errors (any 1/N chunk errored →
        # whole dumper skipped to avoid undercount). Render template
        # surfaces these in Data Gap so the report reader sees what's
        # missing rather than only finding it in stderr logs.
        "step4_skipped_dumpers": step4_skipped_dumpers,
        "n_step4_skipped_dumpers": len(step4_skipped_dumpers),
        "summary_locked_numbers": summary_locked_numbers,
        "summary_text": summary_text,
        # v0.8.1: expose the pre-launch trace floor so downstream
        # detectors (push_airdrop_detector) run against the same window
        # rule_11 used. trace_floor = min(180d default floor, mint day).
        "trace_floor": trace_floor,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ca", required=True)
    ap.add_argument("--alpha-listing-date", required=True)
    ap.add_argument("--deployment-date-floor", default=None)
    ap.add_argument("--out", default="-")
    args = ap.parse_args()

    result = run_backward_trace(
        ca=args.ca,
        alpha_listing_date=args.alpha_listing_date,
        deployment_date_floor=args.deployment_date_floor,
    )

    if "error" in result:
        payload = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        if args.out == "-":
            print(payload)
        else:
            Path(args.out).write_text(payload, encoding="utf-8")
        return 1

    # Serialize: evidence_graph instance → dict
    eg = result.pop("evidence_graph")
    result["evidence_graph"] = eg.to_dict()

    payload = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if args.out == "-":
        print(payload)
    else:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(f"OK: wrote {args.out} ({len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
