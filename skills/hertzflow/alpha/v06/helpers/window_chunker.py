"""window_chunker.py — v0.7.23 sliding-window SQL aggregation.

Surf's ClickHouse layer hard-caps each `surf onchain-sql` call at 30s. For
EVM tokens older than ~5 months a single full-window aggregation on
`agent.bsc_transfers` blows past that limit (SKYAI listing 2025-04-22 →
13-month window → ~10M+ rows on a busy token → QUERY_TIMEOUT).

This module chunks long date ranges into per-bucket sub-queries that each
fit inside the 30s budget. Helpers compose:

  1. `chunked_dates(floor, ceiling, chunk_days=90)` — generate inclusive
     [(YYYY-MM-DD, YYYY-MM-DD)] tuples covering [floor, ceiling].
  2. `merge_chunked_rows(rows_per_chunk, key_field, sum_fields)` — sum
     per-chunk aggregations back into a single per-key result (so a
     wallet's `total_in` across 7 chunks lands as one row).
  3. `parallel_run_chunked(sql_fn, chunks, max_workers=7)` — ThreadPool
     fan-out across chunks; respects surf's 429 throttle by capping
     workers.

The Python-side merge is mathematically equivalent to a single full-window
group-by because all aggregation functions we use (SUM, COUNT, MIN, MAX)
distribute over the bucket partition. MEDIAN and DISTINCT do not — those
remain single-shot queries with a hard-coded narrow window inside the
helper that needs them (see `dump_tracker.fetch_dex_sell_profile`).

v0.7.23 (2026-06-07) — solves SKYAI / PEAQ / any 6+ month old BSC token
that previously hung in surf retry loops.
"""

from __future__ import annotations

import concurrent.futures
import os
from datetime import date, timedelta
from typing import Any, Callable, Iterable


# --------------------------- date chunking ---------------------------

def chunked_dates(
    floor: str,
    ceiling: str,
    chunk_days: int = 90,
) -> list[tuple[str, str]]:
    """Split `[floor, ceiling]` inclusive into per-chunk date pairs.

    Args:
        floor: YYYY-MM-DD lower bound (inclusive).
        ceiling: YYYY-MM-DD upper bound (inclusive). When None, defaults
            to today (UTC).
        chunk_days: target chunk width. Defaults to 90 — empirically
            the largest BSC partition we can group-by on a busy token
            inside surf's 30s budget. Reduce to 30 if a single-chunk
            query still times out (degrades to fast-mode behavior, see
            `sql_retry.run_with_window_fallback`).

    Returns:
        Inclusive [(chunk_floor, chunk_ceiling)] pairs whose union is
        [floor, ceiling]. The last chunk may be shorter than chunk_days
        when the range does not divide evenly.

    Raises:
        ValueError: floor > ceiling, malformed date string, or
            chunk_days < 1.
    """
    if chunk_days < 1:
        raise ValueError(f"chunk_days must be ≥ 1, got {chunk_days!r}")
    floor_d = date.fromisoformat(floor)
    if ceiling is None:
        ceiling_d = date.today()
    else:
        ceiling_d = date.fromisoformat(ceiling)
    if floor_d > ceiling_d:
        raise ValueError(
            f"floor {floor!r} is after ceiling {ceiling!r}; chunker would "
            "emit an empty list and helpers would treat that as 'no data', "
            "masking the upstream date error. Fail loud instead."
        )

    chunks: list[tuple[str, str]] = []
    cur = floor_d
    while cur <= ceiling_d:
        end = min(cur + timedelta(days=chunk_days - 1), ceiling_d)
        chunks.append((cur.isoformat(), end.isoformat()))
        cur = end + timedelta(days=1)
    return chunks


# --------------------------- parallel runner ---------------------------

# v0.7.23: surf 429 throttle empirically tolerates ~6-8 concurrent
# onchain-sql calls before retry storms; 7 matches one bucket per worker
# for the most common SKYAI-class range (13 months ÷ 90d ≈ 7 chunks).
# Override via env for ARM Python / slow link debugging.
_DEFAULT_WORKERS = int(os.environ.get("BINANCE_ALPHA_CHUNK_WORKERS", "7"))


def parallel_run_chunked(
    sql_fn: Callable[[str, str], dict[str, Any]],
    chunks: list[tuple[str, str]],
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """Run `sql_fn(chunk_floor, chunk_ceiling)` for every chunk in
    parallel; return ordered list of per-chunk results.

    `sql_fn` should return a dict shaped like the underlying surf call —
    typically `{"data": [...], "meta": {...}, "_error": ...}`. Errors
    surface in the returned list (not raised) so the caller can decide
    whether a partial result is usable; this matches the existing
    `_run_surf_with_retry` contract.

    Args:
        sql_fn: per-chunk callable taking (chunk_floor, chunk_ceiling).
        chunks: output of `chunked_dates`.
        max_workers: ThreadPool size. Defaults to env
            `BINANCE_ALPHA_CHUNK_WORKERS` (or 7).

    Returns:
        list of per-chunk dicts in input order.
    """
    if not chunks:
        return []
    workers = max_workers if max_workers is not None else _DEFAULT_WORKERS
    workers = max(1, min(workers, len(chunks)))
    results: list[dict[str, Any] | None] = [None] * len(chunks)
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="window_chunk",
    ) as ex:
        fut_to_idx = {
            ex.submit(sql_fn, floor, ceiling): i
            for i, (floor, ceiling) in enumerate(chunks)
        }
        for fut in concurrent.futures.as_completed(fut_to_idx):
            i = fut_to_idx[fut]
            try:
                results[i] = fut.result()
            except Exception as e:
                results[i] = {
                    "_error": f"{type(e).__name__}: {e}"[:200],
                    "data": [],
                }
    return [r if r is not None else {"_error": "no result", "data": []} for r in results]


def parallel_run_flat_tasks(
    task_fn: Callable[[Any], dict[str, Any]],
    tasks: list[Any],
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """Flat ThreadPool fan-out across an arbitrary task list.

    v0.7.23 (post-regression-fix): `parallel_run_chunked` only parallelizes
    over chunk boundaries for a single SQL. When the caller has a 2-D
    task surface (e.g. step 4 of rule_11 has `(dumper, chunk)` for N
    dumpers × M chunks), nesting two layers serializes the outer loop
    and squanders the worker budget. This helper takes the full task
    cross-product as a flat list and dispatches all of them in one pool,
    matching v0.7.22 `run_parallel`'s call pattern.

    Args:
        task_fn: callable taking one task; returns surf-shaped dict.
        tasks: flat list — typically a Cartesian product of (outer, chunk).
        max_workers: ThreadPool size. Defaults to env
            `BINANCE_ALPHA_CHUNK_WORKERS` (or 7). Caller should pass 8 to
            match v0.7.22 baseline `run_parallel` cap (surf throttles
            past 8).

    Returns:
        list of per-task dicts in input order.
    """
    if not tasks:
        return []
    workers = max_workers if max_workers is not None else _DEFAULT_WORKERS
    workers = max(1, min(workers, len(tasks)))
    results: list[dict[str, Any] | None] = [None] * len(tasks)
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="flat_task",
    ) as ex:
        fut_to_idx = {ex.submit(task_fn, t): i for i, t in enumerate(tasks)}
        for fut in concurrent.futures.as_completed(fut_to_idx):
            i = fut_to_idx[fut]
            try:
                results[i] = fut.result()
            except Exception as e:
                results[i] = {
                    "_error": f"{type(e).__name__}: {e}"[:200],
                    "data": [],
                }
    return [r if r is not None else {"_error": "no result", "data": []} for r in results]


# --------------------------- result merger ---------------------------

def merge_chunked_rows(
    rows_per_chunk: Iterable[Iterable[dict[str, Any]]],
    key_field: str,
    sum_fields: list[str] | None = None,
    min_fields: list[str] | None = None,
    max_fields: list[str] | None = None,
    count_fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Per-chunk grouped rows → single grouped result.

    For every distinct value of `key_field`, sum/min/max/count the named
    fields across all chunks. Rows missing a field contribute 0/None as
    appropriate. Returns a list ordered by descending total of the
    FIRST `sum_fields` entry (so the caller's "top N" downstream slicing
    sees the same ordering they would have got from a single-window
    SQL `ORDER BY ... DESC`).

    SUM / MIN / MAX / COUNT are distributive over the chunk partition,
    so this merge is mathematically equivalent to a single-window
    group-by — assuming the chunks are non-overlapping (which
    `chunked_dates` guarantees).

    Args:
        rows_per_chunk: iterable of per-chunk row lists.
        key_field: name of the group-by column in each row.
        sum_fields / min_fields / max_fields / count_fields: column names
            to combine. Empty list / None means skip.

    Returns:
        list of merged row dicts, ordered by descending first sum field
        (or by `key_field` ascending when no sum fields were given).
    """
    sum_fields = sum_fields or []
    min_fields = min_fields or []
    max_fields = max_fields or []
    count_fields = count_fields or []
    merged: dict[Any, dict[str, Any]] = {}
    for chunk_rows in rows_per_chunk:
        for row in (chunk_rows or []):
            key = row.get(key_field)
            if key is None:
                continue
            target = merged.setdefault(key, {key_field: key})
            for f in sum_fields:
                try:
                    target[f] = (target.get(f) or 0) + (float(row.get(f) or 0))
                except (TypeError, ValueError):
                    target[f] = target.get(f) or 0
            for f in min_fields:
                v = row.get(f)
                if v is None:
                    continue
                cur = target.get(f)
                target[f] = v if cur is None else min(cur, v)
            for f in max_fields:
                v = row.get(f)
                if v is None:
                    continue
                cur = target.get(f)
                target[f] = v if cur is None else max(cur, v)
            for f in count_fields:
                try:
                    target[f] = (target.get(f) or 0) + int(row.get(f) or 0)
                except (TypeError, ValueError):
                    target[f] = target.get(f) or 0
    if sum_fields:
        return sorted(
            merged.values(),
            key=lambda r: r.get(sum_fields[0]) or 0,
            reverse=True,
        )
    return sorted(merged.values(), key=lambda r: r.get(key_field))


# --------------------------- diagnostic ---------------------------

def chunk_summary(chunks: list[tuple[str, str]]) -> str:
    """Human-readable summary for log lines. e.g.
    `7 chunks · 2024-10-25..2026-06-07 (90d each, last 30d)`.
    """
    if not chunks:
        return "0 chunks"
    first_floor = chunks[0][0]
    last_ceiling = chunks[-1][1]
    last_width = (
        date.fromisoformat(chunks[-1][1]) - date.fromisoformat(chunks[-1][0])
    ).days + 1
    full_width = (
        date.fromisoformat(chunks[0][1]) - date.fromisoformat(chunks[0][0])
    ).days + 1
    tail = "" if last_width == full_width else f", last {last_width}d"
    return (
        f"{len(chunks)} chunks · {first_floor}..{last_ceiling} "
        f"({full_width}d each{tail})"
    )
