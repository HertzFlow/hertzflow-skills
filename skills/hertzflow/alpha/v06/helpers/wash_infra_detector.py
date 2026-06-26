#!/usr/bin/env python3
"""wash_infra_detector.py — v0.7.7 wash infrastructure detection.

Pure on-chain signature (no Arkham label dependency). Identifies the
three-address pattern of a wash-trading infrastructure setup:

  X (Taker / executor)
    │
    ├─ atomic-pair tx: each tx contains BOTH X→user AND user→X
    │
    ├─ P (Maker buy-side): X consistently receives `from` P > 80% of inflows
    └─ Q (Maker sell-side): X consistently sends `to` Q > 80% of outflows

  P + Q each individually have `tok_in == tok_out` (drift < 0.1%) — they
  recycle tokens through X. The wash entity is the controller of P + Q
  (and possibly X if not labeled as something else).

Method B (5-step) from reference_whale_role_and_wash_methodology.md:

  Step 0 (entry): high-frequency + balanced bidirectional + tx > 500
  Step 1: atomic-pair tx ratio > 0.9
  Step 2: find single dominant counterparty on each side (>80% concentration)
  Step 3: P and Q each have drift < 0.1%
  Step 4: tx_from diversity — routed wash vs operator-controlled
  Step 5: classify

Cost: 1 batch SQL covers all entry candidates; 4 SQL per real candidate
that passes Step 0. Most CAs have 0-2 real candidates.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import random
import re
import subprocess
import sys
import time
from chain_router import transfers_table, dex_trades_table  # v0.7.20

SURF_TIMEOUT_SECS = 60
# v0.7.19: surf 429 transient retry. Default 3 attempts at 1s × 2^(n-1)
# jittered base = ~1s, ~2s, ~4s between retries. Tuned to give surf's
# server-side rate-limiter a chance to drain without compounding our
# 8-way ThreadPoolExecutor's pressure.
WASH_INFRA_RETRY_ATTEMPTS = max(1, int(
    os.environ.get("BINANCE_ALPHA_WASH_INFRA_RETRY_ATTEMPTS", "3")
))
WASH_INFRA_RETRY_BASE_SECS = float(
    os.environ.get("BINANCE_ALPHA_WASH_INFRA_RETRY_BASE_SECS", "1.0")
)
# v0.7.17: wall-clock budget for the per-candidate loop (Steps 2-5).
# Step 0 (batch entry filter) + Step 1 (parallel atomic-pair) run before this
# budget starts. v0.7.18 parallelized Steps 2-5 so 70-candidate BEAT (which
# v0.7.17 truncated at 51/70 in 300s) drops to ~50s; budget kept at 300s as
# safety net against pathological surf slowdowns / rate-limit retries.
WASH_INFRA_MAX_SECONDS = float(
    os.environ.get("BINANCE_ALPHA_WASH_INFRA_MAX_SECONDS", "300")
)
# v0.7.18: worker count for the Steps 2-5 ThreadPoolExecutor. 8 was the
# original after GUA / BEAT testing. v0.7.23 dropped default 8 → 4 per
# surf-team guidance (2026-06-09 reply): "every CA firing 10-20 group-by
# at once will saturate a single ClickHouse node — serialize or limit".
# 4 workers is the client-side cooperation pattern that surf's backend
# is built for, NOT a vendor-outage fallback. Override via env for hot
# tokens if surf telemetry confirms headroom.
WASH_INFRA_WORKERS = max(1, int(os.environ.get("BINANCE_ALPHA_WASH_INFRA_WORKERS", "4")))

# v0.7.21.7: chain-aware address check. The constant `_ADDR_RE` is kept
# (back-compat with any out-of-pipeline test that imports it directly) but
# every call site now goes through `_addr_ok` so Solana base58 addresses
# survive the SQL-injection guard the same way EVM addresses do.
_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")

from chain_router import (  # noqa: E402
    is_valid_addr as _chain_is_valid_addr,
    get_active_chain as _chain_get_active,
)


def _addr_ok(addr) -> bool:
    """Chain-aware replacement for `_ADDR_RE.fullmatch`. Lowercases on
    EVM; preserves case on Solana (base58 is case-sensitive)."""
    if not isinstance(addr, str) or not addr:
        return False
    if _chain_get_active() == "solana":
        return _chain_is_valid_addr(addr)
    return _chain_is_valid_addr(addr.lower())


class WashInfraError(Exception):
    pass


def _is_transient_rate_limit(msg: str) -> bool:
    """Match the various ways surf / the upstream API can surface a
    transient rate-limit. v0.7.19 adversarial review MEDIUM#1 widened detection: the
    original substring check was case-sensitive and capped at 200 chars,
    so any of `too many requests` (lowercase) / `Rate-Limited` /
    `throttled` / message past byte 200 would silently bypass retry.

    Empirical surf signatures seen in the wild:
      `surf exit 4: WARN: Got 429 Too Many Requests, retrying in 1s`
      `surf exit 4: rate-limited (HTTP 429), retry-after: 5s`
      JSON body `{"error": "rate-limit exceeded"}` (surf returns exit 0
        but the body carries the upstream error — see HIGH#1 below).
    """
    if not msg:
        return False
    s = msg.lower()
    return ("429" in s
            or "too many requests" in s
            or "rate limit" in s
            or "rate-limit" in s
            or "rate_limit" in s
            or "throttle" in s)


def _run_sql(sql: str, max_rows: int = 50) -> tuple[list[dict], int]:
    """Run one surf SQL with transient-error retry.

    v0.7.19: 8-way ThreadPoolExecutor on Steps 2-5 (v0.7.18) was empirically
    capable of saturating surf's per-account rate limit (COLLECT 238
    candidates × 4 SQL ≈ ~950 SQL in 222s = ~4.3 SQL/s; surf returned
    `surf exit 4: 429 Too Many Requests` for several candidates which
    were then mis-classified as "candidate failed" by the per-candidate
    `except WashInfraError` and silently dropped — masking real wash
    setups.

    Two retry surfaces (adversarial review HIGH#1 fix):
      1. Non-zero exit + stderr contains a transient signature → retry.
      2. Exit 0 + JSON body `{"error": "...429..."}` → retry.

    Both go through `_is_transient_rate_limit` for the substring match.
    Non-transient errors (non-429 4xx / JSON-decode / non-rate-limit
    API error in body) fail-fast as before.
    """
    body = json.dumps({"sql": sql, "max_rows": max_rows})
    attempt = 0
    while True:
        attempt += 1
        try:
            proc = subprocess.run(
                ["surf", "onchain-sql"],
                input=body, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=SURF_TIMEOUT_SECS, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            # v0.7.23 fix: subprocess timeout is transient. Previously this
            # raised on the first timeout, which sent the wash_infra Step
            # 0 batch query down the serial-fallback path on a single 60s
            # blip. Now we treat it like 429 — backoff + retry up to
            # WASH_INFRA_RETRY_ATTEMPTS. After all retries exhausted, raise
            # so the section reports the failure to the data-quality banner
            # instead of silently degrading to a slower-and-also-failing
            # serial path.
            if attempt < WASH_INFRA_RETRY_ATTEMPTS:
                sleep_s = (WASH_INFRA_RETRY_BASE_SECS *
                           (2 ** (attempt - 1)) *
                           (0.5 + random.random()))
                time.sleep(sleep_s)
                continue
            raise WashInfraError(
                f"surf timeout after {WASH_INFRA_RETRY_ATTEMPTS} attempts: {e}"
            ) from e

        def _maybe_retry(reason: str) -> bool:
            """Sleep + return True if we still have attempts; else False
            so caller raises. Per-thread random jitter prevents 8
            workers from sync-retrying into the same wave."""
            if attempt >= WASH_INFRA_RETRY_ATTEMPTS:
                return False
            sleep_s = (WASH_INFRA_RETRY_BASE_SECS *
                       (2 ** (attempt - 1)) *
                       (0.5 + random.random()))
            time.sleep(sleep_s)
            return True

        # Path 1: non-zero exit + stderr carries the rate-limit signature
        if proc.returncode != 0:
            # adversarial review MEDIUM#1: don't cap stderr to 200 chars when checking
            # for retry — let _is_transient_rate_limit see the full
            # message (some surf builds put the 429 marker past byte 200).
            if (_is_transient_rate_limit(proc.stderr)
                    and _maybe_retry("non-zero exit 429")):
                continue
            # Surface only the first 200 chars in the exception message
            # for log hygiene (full stderr already inspected above).
            raise WashInfraError(f"surf exit {proc.returncode}: {proc.stderr[:200]}")

        # Path 2: exit 0 + JSON body
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise WashInfraError(f"surf non-JSON: {e}") from e
        # adversarial review HIGH#1 fix: surf can return exit 0 with a JSON error body
        # carrying the upstream rate-limit. Retry the same way we retry
        # the non-zero-exit case.
        err = doc.get("error")
        if err:
            err_str = str(err)
            if (_is_transient_rate_limit(err_str)
                    and _maybe_retry("exit-0 body 429")):
                continue
            raise WashInfraError(f"surf API error: {err}")
        credits = int((doc.get("meta") or {}).get("credits_used") or 1)
        return doc.get("data") or [], credits


def _entry_filter_per_addr(ca: str, addr: str, listing_date: str,
                           min_tx: int = 500,
                           max_drift_pct: float = 0.05) -> tuple[bool, int]:
    """Single-address entry filter (legacy serial path, kept for tests).

    v0.7.9: production now uses `_entry_filter_batch` which collapses N
    addresses into 1 SQL. Keep this helper for unit tests + fallback if
    batch SQL fails on a degenerate input.
    """
    sql = (
        f"SELECT "
        f"  countIf(`from` = '{addr}') AS sends, "
        f"  countIf(`to` = '{addr}') AS recvs "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' "
        f"AND block_date >= '{listing_date}' "
        f"AND (`from` = '{addr}' OR `to` = '{addr}')"
    )
    rows, credits = _run_sql(sql, max_rows=5)
    if not rows:
        return False, credits
    row = rows[0]
    sends = int(row.get("sends") or 0)
    recvs = int(row.get("recvs") or 0)
    if sends + recvs < min_tx:
        return False, credits
    if abs(sends - recvs) > (sends + recvs) * max_drift_pct:
        return False, credits
    return True, credits


def _entry_filter_batch(ca: str, candidates: list[str], listing_date: str,
                        min_tx: int = 500,
                        max_drift_pct: float = 0.05) -> tuple[dict[str, tuple[int, int]], int]:
    """v0.7.9 batch path: ONE SQL filters all candidates at once.

    Instead of N SQLs of `countIf(from=addr) + countIf(to=addr) GROUP BY 1`
    (one per addr), build a single SQL using `addr IN ('a1', 'a2', ..., 'aN')`
    + GROUP BY addr aggregated. 244 candidates collapse from 244 × 3s
    serial → 1 × ~5s = ~150x speedup on Step 0 cost.

    v0.7.23 (adversarial review M6 fix): returns the per-addr (sends, recvs) metrics so
    the caller can rank survivors by a composite score
    (tx_count × atomic_pair_ratio × balance_symmetry) instead of relying
    on Step 1's pre-filter alone. Previously a 0.99-ratio low-volume
    setup ranked the same as a 0.86-ratio high-volume one; under the
    300s budget cap that meant high-value setups could be cancelled
    while low-value ones got the worker slots. The composite score
    keeps real-money wash setups at the front of the queue.

    Returns: (dict mapping passing addr → (sends, recvs), credits_used).
    """
    if not candidates:
        return {}, 0
    # Sanitize candidate addresses (defense-in-depth, even though caller
    # already filters via _ADDR_RE.fullmatch)
    safe = [a for a in candidates if _addr_ok(a)]
    if not safe:
        return {}, 0
    addr_list = ",".join(f"'{a}'" for a in safe)
    # Aggregate sends + recvs per addr in 1 query
    sql = (
        "SELECT addr, sum(sends) AS sends, sum(recvs) AS recvs FROM ("
        f"  SELECT `from` AS addr, count(*) AS sends, 0 AS recvs "
        f"  FROM {transfers_table()} "
        f"  WHERE contract_address = '{ca}' "
        f"  AND block_date >= '{listing_date}' "
        f"  AND `from` IN ({addr_list}) "
        f"  GROUP BY `from`"
        "  UNION ALL "
        f"  SELECT `to` AS addr, 0 AS sends, count(*) AS recvs "
        f"  FROM {transfers_table()} "
        f"  WHERE contract_address = '{ca}' "
        f"  AND block_date >= '{listing_date}' "
        f"  AND `to` IN ({addr_list}) "
        f"  GROUP BY `to`"
        ") GROUP BY addr"
    )
    try:
        rows, credits = _run_sql(sql, max_rows=max(500, len(safe) * 2))
    except WashInfraError as e:
        # v0.7.23 fix: NO serial fallback. The old per-addr serial path
        # (244 candidates × 1 SQL each) compounded the very surf-side
        # contention that caused the batch SQL to fail in the first place
        # — and on a partial-surf-outage day it silently produced
        # "2 / 49 passed" results that looked like real forensic data but
        # were just N-of-244 surf successes. Propagate as empty so the
        # render layer fires the "wash candidate scan failed" data-
        # quality banner instead of misleading the reader.
        print(
            f"[wash_infra_detector] Step 0 batch entry filter failed after "
            f"all retries ({e}); 0 candidates passed (no serial fallback). "
            f"Render will show data-quality warning.",
            file=sys.stderr,
        )
        return {}, 0

    passes: dict[str, tuple[int, int]] = {}
    for row in rows:
        addr = (row.get("addr") or "").lower()
        sends = int(row.get("sends") or 0)
        recvs = int(row.get("recvs") or 0)
        if sends + recvs < min_tx:
            continue
        if abs(sends - recvs) > (sends + recvs) * max_drift_pct:
            continue
        passes[addr] = (sends, recvs)
    return passes, credits


def _step1_sql(ca: str, addr: str, listing_date: str) -> str:
    """SQL for the atomic-pair-ratio of one candidate (shared by the serial
    and the parallel-batch paths)."""
    return (
        f"SELECT countIf(sends_in_tx > 0 AND recvs_in_tx > 0) AS paired, "
        f"  count(*) AS total_tx "
        f"FROM ("
        f"  SELECT tx_hash, "
        f"    countIf(`from` = '{addr}') AS sends_in_tx, "
        f"    countIf(`to` = '{addr}') AS recvs_in_tx "
        f"  FROM {transfers_table()} "
        f"  WHERE contract_address = '{ca}' "
        f"  AND block_date >= '{listing_date}' "
        f"  AND (`from` = '{addr}' OR `to` = '{addr}') "
        f"  GROUP BY tx_hash"
        f")"
    )


def _step1_batch_parallel(ca: str, candidates: list[str], listing_date: str,
                          min_ratio: float = 0.85
                          ) -> tuple[dict[str, float] | None, int]:
    """v0.7.11.2: run Step-1 atomic-pair-ratio for ALL candidates in
    parallel (≤8 surf workers), return survivors (ratio ≥ min_ratio).

    Returns:
        ({addr: exact_atomic_pair_ratio, ...}, credits_used) on success,
        or (None, 0) if the `parallel_surf` helper is unavailable so the
        caller can fall back to the serial per-candidate path.

    v0.7.18 doc fix: return type was annotated as `list[str]` but the
    implementation has always returned a dict mapping address → exact
    ratio (so Step 1 needn't be recomputed inside `_process_candidate`).
    v0.7.18 also wraps the temp dir in a try/finally so it gets removed
    even on a surf failure (was leaking under `/tmp/washstep1_*`).
    """
    import shutil
    import tempfile
    from pathlib import Path as _Path
    try:
        from parallel_surf import run_parallel
    except ImportError:
        return None, 0  # caller falls back to serial
    if not candidates:
        return {}, 0
    wd = _Path(tempfile.mkdtemp(prefix="washstep1_"))
    try:
        paths = []
        addr_by_path = {}
        for i, a in enumerate(candidates):
            p = str(wd / f"s1_{i}.json")
            _Path(p).write_text(
                json.dumps({"sql": _step1_sql(ca, a, listing_date), "max_rows": 5}),
                encoding="utf-8",
            )
            paths.append(p)
            addr_by_path[p] = a
        # audit M9 fix: Step 1 was 8 workers while Steps 2-5 are 4
        # (post-v0.7.23). The 8-worker Step 1 starts the 429 storm BEFORE
        # Steps 2-5 ever run, defeating the worker throttle. Use the same
        # WASH_INFRA_WORKERS cap as Steps 2-5 so the surf load profile
        # stays consistent across the section.
        results, _timings = run_parallel(paths, max_workers=WASH_INFRA_WORKERS)
        survivors: dict[str, float] = {}   # addr → exact atomic-pair ratio
        for p, a in addr_by_path.items():
            resp = results.get(p) or {}
            if resp.get("error"):
                continue
            rows = resp.get("data") or []
            if not rows:
                continue
            paired = float(rows[0].get("paired") or 0)
            total = float(rows[0].get("total_tx") or 0)
            ratio = (paired / total) if total > 0 else 0.0
            if ratio >= min_ratio:
                survivors[a] = ratio
        return survivors, len(paths)  # credits ≈ 1/query
    finally:
        # v0.7.18 adversarial review LOW#2 fix: was leaking `/tmp/washstep1_*` dirs.
        try:
            shutil.rmtree(wd, ignore_errors=True)
        except Exception:
            pass


def _step1_atomic_pair_ratio(ca: str, addr: str, listing_date: str) -> tuple[float, int]:
    """% of tx where same tx_hash has both X→Y and Y→X transfers."""
    sql = (
        f"SELECT countIf(sends_in_tx > 0 AND recvs_in_tx > 0) AS paired, "
        f"  count(*) AS total_tx "
        f"FROM ("
        f"  SELECT tx_hash, "
        f"    countIf(`from` = '{addr}') AS sends_in_tx, "
        f"    countIf(`to` = '{addr}') AS recvs_in_tx "
        f"  FROM {transfers_table()} "
        f"  WHERE contract_address = '{ca}' "
        f"  AND block_date >= '{listing_date}' "
        f"  AND (`from` = '{addr}' OR `to` = '{addr}') "
        f"  GROUP BY tx_hash"
        f")"
    )
    rows, credits = _run_sql(sql, max_rows=5)
    if not rows:
        return 0.0, credits
    row = rows[0]
    total = int(row.get("total_tx") or 0)
    paired = int(row.get("paired") or 0)
    return (paired / total if total else 0.0), credits


def _step2_counterparties(ca: str, addr: str, listing_date: str
                          ) -> tuple[dict | None, dict | None, int]:
    """Find dominant buy-side counterparty (P) and sell-side counterparty (Q)."""
    # P = top `from` when addr is `to` (buy-side maker = sender of token to X)
    sql_p = (
        f"SELECT `from` AS p, count(*) AS n "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' "
        f"AND block_date >= '{listing_date}' "
        f"AND `to` = '{addr}' "
        f"GROUP BY p ORDER BY n DESC LIMIT 3"
    )
    p_rows, c1 = _run_sql(sql_p, max_rows=3)
    # Q = top `to` when addr is `from` (sell-side maker = receiver of token from X)
    sql_q = (
        f"SELECT `to` AS q, count(*) AS n "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' "
        f"AND block_date >= '{listing_date}' "
        f"AND `from` = '{addr}' "
        f"GROUP BY q ORDER BY n DESC LIMIT 3"
    )
    q_rows, c2 = _run_sql(sql_q, max_rows=3)
    credits = c1 + c2

    def _pick(rows: list[dict]) -> dict | None:
        if not rows:
            return None
        top = rows[0]
        total = sum(int(r.get("n") or 0) for r in rows)
        top_n = int(top.get("n") or 0)
        share = top_n / total if total else 0
        if share < 0.80:
            return None  # not dominant enough
        return {
            "addr": (top.get("p") or top.get("q") or "").lower(),
            "share": share,
            "n": top_n,
        }
    return _pick(p_rows), _pick(q_rows), credits


def _step3_pq_drift(ca: str, candidates: list[str], listing_date: str
                    ) -> tuple[dict, int]:
    """For each P/Q candidate, compute net token drift over the period.
    Returns {addr: drift_pct} where drift_pct = |out - in| / max(out, in).
    drift < 0.001 = perfect round-trip = wash member.

    1 SQL per candidate (typically 2 total). UNION-based batch query
    triggered surf timeouts so we run per-address."""
    out = {}
    credits_total = 0
    for a in candidates:
        if not a or not _addr_ok(a):
            continue
        sql = (
            f"SELECT "
            f"  sumIf(amount, `from` = '{a}') AS tok_out, "
            f"  sumIf(amount, `to` = '{a}') AS tok_in "
            f"FROM {transfers_table()} "
            f"WHERE contract_address = '{ca}' "
            f"AND block_date >= '{listing_date}' "
            f"AND (`from` = '{a}' OR `to` = '{a}')"
        )
        rows, credits = _run_sql(sql, max_rows=5)
        credits_total += credits
        if not rows:
            continue
        row = rows[0]
        to_ = float(row.get("tok_out") or 0)
        ti = float(row.get("tok_in") or 0)
        denom = max(to_, ti, 1.0)
        drift = abs(to_ - ti) / denom
        out[a.lower()] = {
            "drift_pct": drift,
            "tok_in": ti,
            "tok_out": to_,
        }
    return out, credits_total


def _step4_diversity(ca: str, addr: str, listing_date: str) -> tuple[float, int]:
    """Fraction of unique tx_from across all txs involving addr.
    high diversity = routed wash (serves many users), low = operator-controlled."""
    sql = (
        f"SELECT count(DISTINCT tx_from) AS unique_origins, "
        f"  count(*) AS total_tx "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' "
        f"AND block_date >= '{listing_date}' "
        f"AND (`from` = '{addr}' OR `to` = '{addr}')"
    )
    rows, credits = _run_sql(sql, max_rows=5)
    if not rows:
        return 0.0, credits
    row = rows[0]
    unique = int(row.get("unique_origins") or 0)
    total = int(row.get("total_tx") or 0)
    return (unique / total if total else 0.0), credits


def _process_candidate(ca: str, x_addr: str, prefilt_ratio: float | None,
                       listing_date: str, step1_prefiltered: bool,
                       credits_sink: list[int]) -> dict | None:
    """Run Steps 2-5 on one candidate (Step 1 reuse if pre-filtered).

    v0.7.18: extracted from the inline detect_all loop so the per-candidate
    flow can run inside a ThreadPoolExecutor worker. Each call is fully
    independent — no shared mutable state besides `credits_sink`.

    `credits_sink` is a thread-safe credits accumulator (CPython
    `list.append` is atomic under the GIL). The worker appends its surf
    credit total in a `finally` clause so credits are captured even if
    the caller never consumes `fut.result()` (e.g. after wall-clock
    truncation breaks the consumer loop). This closes the credits-leak
    hole that adversarial review flagged as CRITICAL during v0.7.18 review: an
    in-flight worker that finishes during executor `shutdown(wait=True)`
    still gets its paid surf calls counted.

    Returns:
        setup_dict on a wash hit, None on any gate failure.

    Each call catches its own `WashInfraError` so one bad surf reply
    cannot poison sibling workers in the executor.
    """
    credits = 0
    try:
        # Step 1 — atomic-pair ratio (reuse parallel-computed exact ratio
        # when the pre-filter ran, else compute now and gate at ≥0.85).
        if step1_prefiltered:
            pair_ratio = prefilt_ratio
        else:
            pair_ratio, c1 = _step1_atomic_pair_ratio(ca, x_addr, listing_date)
            credits += c1
            if pair_ratio < 0.85:
                return None

        # Step 2 — dominant P (buy-side) and Q (sell-side) counterparties
        p_info, q_info, c2 = _step2_counterparties(ca, x_addr, listing_date)
        credits += c2
        if not p_info or not q_info:
            return None

        # Step 3 — drift on P + Q (net flow must round-trip to ~0)
        pq_drifts, c3 = _step3_pq_drift(
            ca, [p_info["addr"], q_info["addr"]], listing_date,
        )
        credits += c3
        p_drift = pq_drifts.get(p_info["addr"], {}).get("drift_pct", 1.0)
        q_drift = pq_drifts.get(q_info["addr"], {}).get("drift_pct", 1.0)
        if max(p_drift, q_drift) > 0.001:
            # Either P or Q has real net flow — not a pure wash member
            return None

        # Step 4 — tx_from diversity
        diversity, c4 = _step4_diversity(ca, x_addr, listing_date)
        credits += c4

        # Step 5 — classify
        wash_type = ("routed" if diversity > 0.3
                     else "operator_controlled" if diversity < 0.05
                     else "ambiguous")
        return {
            "executor_X": x_addr,
            "maker_buy_P": p_info["addr"],
            "maker_sell_Q": q_info["addr"],
            "atomic_pair_ratio": pair_ratio,
            "p_drift_pct": p_drift,
            "q_drift_pct": q_drift,
            "p_tok_in": pq_drifts.get(p_info["addr"], {}).get("tok_in", 0),
            "q_tok_in": pq_drifts.get(q_info["addr"], {}).get("tok_in", 0),
            "tx_from_diversity": diversity,
            "classification": f"wash_infrastructure_{wash_type}",
        }
    except WashInfraError as e:
        print(
            f"[wash_infra_detector] candidate {x_addr[:14]} failed: {e}",
            file=sys.stderr,
        )
        return None
    finally:
        # Always record paid surf cost, even on gate-fail / exception /
        # caller-never-consumes. This is the adversarial review CRITICAL#1 fix.
        credits_sink.append(credits)


def detect_all(ca: str, candidate_addrs: list[str],
               listing_date: str | None = None) -> tuple[list[dict], int, dict]:
    """Run the 5-step pipeline on this CA against a pre-narrowed candidate
    address list (e.g. top-100 holders + any extra suspect addresses).

    Returns:
        (results, credits_used, meta) where meta has:
          - n_candidates_total: candidates after Step 0 batch entry filter
          - n_candidates_processed: how many reached Steps 2-5 before
            truncation (== n_candidates_total when complete)
          - truncated: True iff wall-clock budget hit
          - wall_clock_seconds_used: actual loop seconds
          - wall_clock_budget_seconds: configured budget

    v0.7.17: 3-tuple return (was 2-tuple). Truncation is **partial**, not
    a failure — callers should still treat `results` as valid findings.

    Caller must narrow the candidate set first — running this over the
    entire chain would be prohibitive. Typical input: top-100 holders
    (already pulled by section_f_holders), filtered to addresses that
    are CONTRACT (since the executor in a wash setup is always a
    contract). Total cost: ~1-5 SQL per candidate that passes Step 0,
    less than 100 SQL per CA in worst case.
    """
    c = (ca or "").lower()
    if not _addr_ok(c):
        raise WashInfraError(f"invalid ca: {ca!r}")
    listing_date = listing_date or "2025-01-01"
    # Cross-LLM security audit fix: use fullmatch — `re.match` lets `$`
    # match before a trailing `\n`, so `"2026-01-01\n' OR 1=1 --"` passes
    # the prefix gate and reaches f-string SQL interpolation below.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", listing_date):
        raise WashInfraError(f"invalid listing_date: {listing_date!r}")

    credits_total = 0
    candidates = [a.lower() for a in candidate_addrs
                  if a and _addr_ok(a)]
    if not candidates:
        return [], credits_total, {
            "n_candidates_total": 0,
            "n_candidates_processed": 0,
            "truncated": False,
            "wall_clock_seconds_used": 0.0,
            "wall_clock_budget_seconds": WASH_INFRA_MAX_SECONDS,
            "workers": WASH_INFRA_WORKERS,
        }

    # v0.7.9: batch Step 0 entry filter — 1 SQL covers all N candidates
    # (was N × 1 SQL serial). ESPORTS 244 candidates: 800s → ~10s.
    # v0.7.23 (adversarial review M6 fix): returns dict[addr → (sends, recvs)] so we
    # can rank survivors by composite score below.
    # v0.7.23 follow-up (no-serial-fallback): when the batch SQL fails
    # after all retries, the helper now returns ({}, 0) instead of
    # silently degrading to a serial path that compounds the very surf
    # contention causing the failure. Detect that case here so the
    # render layer fires a "wash candidate scan failed" data-quality
    # banner — distinct from a real 0-hit scan.
    step0_metrics, batch_credits = _entry_filter_batch(c, candidates, listing_date)
    credits_total += batch_credits
    step0_surf_failed = (batch_credits == 0 and len(candidates) > 0
                        and not step0_metrics)
    # Preserve original candidate order (top-100 holders先, then top-200 balanced)
    filtered_candidates = [a for a in candidates if a in step0_metrics]
    print(
        f"[wash_infra_detector] Step 0 batch: {len(filtered_candidates)} / "
        f"{len(candidates)} passed entry filter (credits {batch_credits})"
        + ("  ⚠️ step0 SQL surf-failed across retries — no fallback"
           if step0_surf_failed else ""),
        file=sys.stderr,
    )
    if step0_surf_failed:
        # Short-circuit: no point trying Steps 1-5 with zero candidates.
        # Propagate via truncation_meta so render can pick up the marker.
        return [], credits_total, {
            "n_candidates_total": len(candidates),
            "n_candidates_processed": 0,
            "truncated": True,   # render hooks the truncation banner
            "wall_clock_seconds_used": 0.0,
            "wall_clock_budget_seconds": WASH_INFRA_MAX_SECONDS,
            "workers": WASH_INFRA_WORKERS,
            "step0_surf_failed": True,
        }

    # v0.7.11.2: Step 1 (atomic-pair ratio) is run as the parallel pre-filter
    # — only candidates with ratio ≥ 0.85 reach Steps 2-5.
    step1_ratios, c_s1 = _step1_batch_parallel(c, filtered_candidates, listing_date)
    if step1_ratios is None:
        # parallel helper unavailable → fall back to per-candidate Step 1
        step1_iter = [(a, None) for a in filtered_candidates]
        _step1_prefiltered = False
    else:
        credits_total += c_s1
        _step1_prefiltered = True
        # v0.7.23 adversarial review M6 fix: rank survivors by composite score
        # `tx_count × atomic_pair_ratio × balance_symmetry` so high-value
        # setups (e.g. 0.86 ratio + 50k tx + perfectly balanced) outrank
        # low-value ones (e.g. 0.99 ratio + 600 tx + asymmetric) before
        # the 300s budget cap kicks in. Under the prior FIFO-by-Step-0
        # order, budget-cancelled candidates were effectively random,
        # which could drop real-money wash setups while keeping noise.
        # Top-N defaults to 30 (env-overridable); the remainder are
        # disclosed as "deferred (low composite score)" so the report
        # is honest about what was checked vs skipped.
        # v0.8.4.9: default top-N 30 → 20. 用户 review: 顶部 wash share %
        # 数字 (B1 12.7% 类) 是 user 关心的唯一 metric, setup 详细表已删.
        # adversarial review M41 audit: 15 太激进 (wash 量 long-tail 分布, top-15 可能
        # 漏覆盖). 20 = 节省 ~100 credits/run + 保留 80%+ 覆盖率. env override OK.
        wash_top_n = int(os.environ.get("BINANCE_ALPHA_WASH_INFRA_TOP_N", "20"))
        scored: list[tuple[float, str, float]] = []
        for addr, ratio in step1_ratios.items():
            sends, recvs = step0_metrics.get(addr, (0, 0))
            tx_count = sends + recvs
            total = float(tx_count) if tx_count else 1.0
            symmetry = 1.0 - abs(sends - recvs) / total
            score = float(tx_count) * float(ratio) * symmetry
            scored.append((score, addr, float(ratio)))
        scored.sort(reverse=True)   # highest score first
        step1_iter = [(addr, ratio) for _, addr, ratio in scored[:wash_top_n]]
        n_deferred = max(0, len(scored) - wash_top_n)
        print(f"[wash_infra_detector] Step 1 parallel: {len(scored)} / "
              f"{len(filtered_candidates)} passed atomic-pair ≥0.85", file=sys.stderr)
        if n_deferred:
            print(
                f"[wash_infra_detector] composite-rank top-{wash_top_n} "
                f"selected; {n_deferred} candidates deferred (low score: "
                f"tx_count × ratio × symmetry). Override via "
                f"BINANCE_ALPHA_WASH_INFRA_TOP_N.",
                file=sys.stderr,
            )

    results = []
    # v0.7.17 adversarial review MEDIUM#2: monotonic clock — NTP step / DST jump safe.
    _loop_start = time.monotonic()
    _truncated_at = None
    # v0.7.18: Steps 2-5 run in parallel via ThreadPoolExecutor.
    # Each candidate's flow (Steps 2 → 3 → 4 → 5) is independent; the
    # serial dependency is only WITHIN one candidate. BEAT 70 candidates
    # at ~6s/candidate serial = 420s (v0.7.17 truncated at 51/70 in 300s);
    # 8-way parallel collapses that to ~50-60s.
    #
    # Truncation semantics (adversarial review CRITICAL#1 + HIGH#1 corrected):
    #   - Budget is checked AFTER consuming each completed future, so the
    #     just-finished candidate IS counted in n_processed (no off-by-one).
    #   - On trip we cancel pending (queued-but-not-started) futures via
    #     per-future .cancel(); Python cannot kill a running worker thread,
    #     so in-flight workers (≤ WASH_INFRA_WORKERS) run to completion
    #     during the executor's `with` shutdown(wait=True).
    #   - credits_sink is a thread-safe accumulator: every worker (consumed,
    #     in-flight, or never-consumed) appends its paid surf credits in a
    #     finally clause. We sum the sink AFTER the with block exits, so
    #     the credits_total never under-reports paid work.
    #   - After the with block exits, any future that finished in-flight
    #     but was never consumed by the as_completed iterator is drained
    #     so its setup (a real wash finding) is not silently discarded.
    n_processed = 0
    credits_sink: list[int] = []
    futures_to_addr: dict[concurrent.futures.Future, str] = {}
    consumed: set[concurrent.futures.Future] = set()
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=WASH_INFRA_WORKERS,
        thread_name_prefix="wash_infra",
    ) as executor:
        for x_addr, prefilt_ratio in step1_iter:
            fut = executor.submit(
                _process_candidate, c, x_addr, prefilt_ratio,
                listing_date, _step1_prefiltered, credits_sink,
            )
            futures_to_addr[fut] = x_addr
        for fut in concurrent.futures.as_completed(futures_to_addr):
            consumed.add(fut)
            try:
                setup = fut.result()
                n_processed += 1
                if setup is not None:
                    results.append(setup)
            except concurrent.futures.CancelledError:
                # Pending future cancelled before the worker pool picked
                # it up. Do not count it as processed.
                continue
            except Exception as e:  # pragma: no cover — defensive
                addr = futures_to_addr.get(fut, "?")[:14]
                print(
                    f"[wash_infra_detector] worker exception on "
                    f"{addr}: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                n_processed += 1
            # Budget check AFTER consumption so the current candidate IS
            # counted (adversarial review HIGH#1 fix).
            if time.monotonic() - _loop_start > WASH_INFRA_MAX_SECONDS:
                _truncated_at = n_processed
                in_flight = sum(
                    1 for f in futures_to_addr
                    if not f.done() and not f.cancelled()
                )
                print(
                    f"[wash_infra_detector] wall-clock budget "
                    f"{WASH_INFRA_MAX_SECONDS:.0f}s exceeded after "
                    f"{n_processed}/{len(futures_to_addr)} candidates; "
                    f"cancelling pending and letting {in_flight} in-flight "
                    f"workers finish (cannot kill threads in Python). "
                    f"Override via BINANCE_ALPHA_WASH_INFRA_MAX_SECONDS / "
                    f"BINANCE_ALPHA_WASH_INFRA_WORKERS env.",
                    file=sys.stderr,
                )
                # Cancel anything still queued (worker pool hasn't started
                # it yet); in-flight workers complete naturally during
                # shutdown(wait=True) on with-exit.
                for f in futures_to_addr:
                    if not f.done():
                        f.cancel()
                break

    # `with` exited → executor.shutdown(wait=True) has joined every worker.
    # Drain any future that finished AFTER the budget break and was never
    # consumed by the as_completed iterator. Credits for these are already
    # in credits_sink (atomic finally append in the worker); we only need
    # to harvest valid `setup` dicts so a real wash finding is not lost.
    for fut in futures_to_addr:
        if fut in consumed or fut.cancelled():
            continue
        if not fut.done():
            # Defensive — shouldn't happen after wait=True, but if a
            # future is somehow still running (e.g. exception in the
            # executor itself) we skip it rather than block.
            continue
        try:
            setup = fut.result(timeout=0)
            n_processed += 1
            if setup is not None:
                results.append(setup)
        except (concurrent.futures.CancelledError,
                concurrent.futures.TimeoutError):
            continue
        except Exception:
            n_processed += 1

    # Sum credits AFTER the executor has fully shut down + drain pass.
    # credits_sink now contains one int per worker that ran at all,
    # including in-flight ones that we never consumed (adversarial review CRITICAL#1).
    credits_total += sum(credits_sink)

    _wall_clock_used = time.monotonic() - _loop_start
    # n_processed is maintained inside the executor loop above; when no
    # truncation occurred and the executor `with` exited cleanly, it
    # equals len(step1_iter). The truncated branch breaks before consuming
    # remaining completed/in-flight futures, so n_processed snapshots the
    # exact count of consumed results at the moment the budget tripped.
    meta = {
        "n_candidates_total": len(step1_iter),
        "n_candidates_processed": n_processed,
        "truncated": _truncated_at is not None,
        "wall_clock_seconds_used": round(_wall_clock_used, 1),
        "wall_clock_budget_seconds": WASH_INFRA_MAX_SECONDS,
        "workers": WASH_INFRA_WORKERS,
    }
    return results, credits_total, meta


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--ca", required=True)
    ap.add_argument("--listing-date", default=None)
    ap.add_argument("--candidates", nargs="+", required=True,
                    help="Candidate addresses to check (typically top-100 holders).")
    args = ap.parse_args()
    try:
        results, credits, meta = detect_all(
            args.ca, args.candidates, listing_date=args.listing_date,
        )
    except WashInfraError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    trunc = " [TRUNCATED]" if meta.get("truncated") else ""
    print(
        f"[surf credits: {credits}, {len(results)} wash setups found, "
        f"{meta.get('n_candidates_processed')}/{meta.get('n_candidates_total')} "
        f"candidates processed in {meta.get('wall_clock_seconds_used')}s{trunc}]",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
