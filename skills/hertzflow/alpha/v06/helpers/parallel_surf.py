#!/usr/bin/env python3
"""parallel_surf.py — fire N independent surf onchain-sql queries in parallel.

Usage as a CLI:
    python3 parallel_surf.py q1.json q2.json q3.json  -> r1.json r2.json r3.json
    (output files share the input filename with .out.json suffix instead of .json)

Usage as a module:
    from parallel_surf import run_parallel
    results = run_parallel(['q1.json', 'q2.json', 'q3.json'])
    # results = {'q1.json': parsed_json, 'q2.json': parsed_json, ...}

Each query JSON file follows surf's input format:
    {"max_rows": N, "sql": "SELECT ..."}

The helper spawns N concurrent `surf onchain-sql @<file>` subprocesses. The
shell-layer parallelism is sufficient because each surf invocation is a
self-contained HTTP round-trip; surf does not share state across processes.

Recommended max concurrency: 8. Surf's server-side per-account concurrency
limit kicks in past that, returning 429-style throttling. The helper does
NOT enforce this — caller chooses how many JSON files to pass.

Cost: each query independently bills credits; parallel does not save credits,
only wall clock. For BABYSHARK forensic ~10 queries: sequential ~5 min,
parallel-8 ~40 sec. Cost identical either way.

v0.5.7 — wall-clock optimization.
v0.7.13 — per-query transient-error retry with jittered backoff (issue #1 Bug 1).
"""

from __future__ import annotations

import argparse
import concurrent.futures as _cf
import json
import random
import re
import subprocess
import sys
import time
from datetime import date, timedelta
import os
from pathlib import Path

# v0.9.9 CRITICAL deadlock fix (user report 2026-06-17): hard per-attempt
# subprocess timeout for `surf onchain-sql`. Without it, a hung surf CLI
# (stuck network connection) blocks subprocess.run forever → ThreadPool
# worker never returns → pipeline deadlocks at futex_wait, CPU 0%. Chunks
# are sized to fit surf's 30s budget; 90s gives headroom for a slow-but-
# progressing query while still catching a truly stuck one. Override via
# env for debugging against a slow link.
_SURF_SUBPROCESS_TIMEOUT = int(os.environ.get("BINANCE_ALPHA_SURF_SUBPROCESS_TIMEOUT", "90"))

# v0.9.1: surf 365-day window guard. Large tables enforce a 365-day
# block_date window. Any SQL bumping the limit returns INVALID_REQUEST.
# These tables are subject to the rule (per surf error responses observed
# 2026-06-14 SIREN forensic):
_SURF_LARGE_TABLES = (
    "bsc_transfers", "bsc_dex_trades",
    "ethereum_transfers", "ethereum_dex_trades",
    "arbitrum_transfers", "arbitrum_dex_trades",
    "base_transfers", "base_dex_trades",
    "polygon_transfers", "polygon_dex_trades",
    "optimism_transfers", "optimism_dex_trades",
)
_BLOCK_DATE_RE = re.compile(
    r"""block_date\s*>=\s*['"]?(\d{4}-\d{2}-\d{2})['"]?""",
    re.IGNORECASE,
)
# Match `today() - <N>` / `today()- <N>` — these are surf-safe by construction
# as long as N <= 365. We require N <= 364 to be conservative (matches the
# surf_constraints helper).
_TODAY_MINUS_RE = re.compile(
    r"""block_date\s*>=\s*today\(\)\s*-\s*(\d+)""",
    re.IGNORECASE,
)


def _check_surf_365_day_window(payload: str, input_path: str) -> dict | None:
    """Pre-flight check: refuse SQL that violates surf's 365-day window on
    large transfer / dex_trades tables. Returns an error dict if violated,
    None if safe.

    Implementation: parse JSON payload to get the SQL string, scan for
    `block_date >=` against any `_SURF_LARGE_TABLES` table, and verify
    the floor date is within 364 days of today. The check is permissive:
    `today() - N` forms with N <= 364 are accepted; only literal
    `'YYYY-MM-DD'` dates that are >364 days back trigger the refusal.
    """
    try:
        body = json.loads(payload)
        sql = body.get("sql") or ""
    except (json.JSONDecodeError, AttributeError):
        return None  # Not a JSON-body call; let the surf server validate.
    if not sql:
        return None
    sql_lower = sql.lower()
    # If the SQL doesn't reference any of the large tables, no enforcement.
    if not any(t in sql_lower for t in _SURF_LARGE_TABLES):
        return None
    safe_floor = date.today() - timedelta(days=364)
    # Check literal `block_date >= 'YYYY-MM-DD'` patterns.
    for m in _BLOCK_DATE_RE.finditer(sql):
        try:
            d = date.fromisoformat(m.group(1))
        except ValueError:
            continue
        if d < safe_floor:
            return {
                "error": {
                    "code": "INVALID_REQUEST_GUARD",
                    "message": (
                        f"surf 365-day window guard (v0.9.1): SQL in "
                        f"{input_path} uses block_date >= '{m.group(1)}' "
                        f"against a large surf table, but {m.group(1)} is "
                        f"older than surf's 364-day safe floor "
                        f"({safe_floor.isoformat()}). Caller MUST wrap "
                        f"date_floor / listing_date with "
                        f"helpers.surf_constraints.surf_safe_date_floor() "
                        f"before constructing the query. Pre-flight refused "
                        f"to avoid the silent-loss-of-data bug (SIREN "
                        f"2026-06-14: dump_tracker $0 vs on-chain $45.7M)."
                    ),
                }
            }
    # `today() - N` forms — only accept N <= 364.
    for m in _TODAY_MINUS_RE.finditer(sql):
        try:
            n = int(m.group(1))
        except ValueError:
            continue
        if n > 364:
            return {
                "error": {
                    "code": "INVALID_REQUEST_GUARD",
                    "message": (
                        f"surf 365-day window guard (v0.9.1): SQL in "
                        f"{input_path} uses block_date >= today() - {n} "
                        f"against a large surf table, but {n} exceeds the "
                        f"364-day safe floor. Reduce the window or split "
                        f"the query."
                    ),
                }
            }
    return None


# adversarial review MEDIUM #2: a request/validation error (bad SQL, unknown column) is
# PERMANENT — retrying it 4× just wastes time and multiplies load across the 8
# parallel workers. Fast-fail those; everything else (429 / 5xx / timeout /
# truncated-JSON-under-load) is treated as transient and retried. Note the
# @file-vs-stdin INVALID_REQUEST is already resolved by the stdin-pipe
# fallback within a single attempt, so a residual INVALID_REQUEST here is
# a real one.
_PERMANENT_ERROR_MARKERS = (
    "invalid_request", "syntax", "unknown identifier", "does not exist",
    "doesn't exist", "illegal", "cannot parse", "missing column",
    "unknown table", "type mismatch",
)


def _is_transient_error(resp: dict) -> bool:
    """True if an error response is worth retrying (transient), False if it is
    a permanent request/schema error that will never succeed on retry."""
    err = resp.get("error", {})
    blob = (str(err.get("code", "")) + " " + str(err.get("message", ""))).lower()
    return not any(m in blob for m in _PERMANENT_ERROR_MARKERS)


def _run_one(input_path: str, max_attempts: int = 4) -> tuple[str, dict, float]:
    """Run a single surf query with transient-error retry. Returns
    (input_path, parsed_response, elapsed_s).

    v0.5.9 (adversarial review BABYSHARK 2026-05-23 field test):
    Some surf CLI versions accept `surf onchain-sql @<file>`, others require
    `surf onchain-sql --json` with the JSON body via STDIN. the review's Win11
    surf version rejected the @file form, returning INVALID_REQUEST despite
    the helper claiming success. Fix: try @file first; if it returns an API
    error containing 'INVALID_REQUEST' / 'Send a JSON object' / 'not a JSON
    object' (the surf CLI's complaint about @file syntax), fall back to
    stdin-piped JSON via `--json`.

    v0.7.13 (issue #1 Bug 1): added exponential-backoff retry on TRANSIENT
    surf failures (429 Too Many Requests / subprocess non-zero exit / 5xx /
    JSON-decode / top-level surf "error"). Before this, a single 429 surfaced
    as a hard {"error": ...}; on rule_11's sub-dumper balance backfill that
    silently dropped the backfill and left `dumped_pct=None`, which then
    crashed section_alloc / forensic_pipeline. run_parallel fans out up to 8
    of these concurrently, so a burst of 429s ("drop a CA" concurrent runs)
    is exactly the failure mode — backoff carries jitter so the 8 workers do
    NOT retry in lockstep and re-trigger the rate limit. Mirrors
    section_a_scope._run_surf_with_retry (4 attempts, ~1/3/7s).
    """
    payload = Path(input_path).read_text(encoding="utf-8")
    last_resp: dict = {"error": {"code": "NO_ATTEMPT", "message": "no attempt made"}}
    last_elapsed = 0.0

    # v0.9.1: pre-flight 365-day window guard. surf enforces a 365-day
    # block_date window on bsc_transfers / bsc_dex_trades (and the analogous
    # ethereum_/arbitrum_/base_/polygon_/optimism_ tables). Any SQL that
    # bumps that limit returns INVALID_REQUEST and is silently consumed by
    # the section. SIREN 2026-06-14 lost dump_tracker entirely this way
    # ($0 confirmed_sellout vs. EmberCN-observed $45.7M on-chain). Guard
    # scans the payload for `block_date >= '<YYYY-MM-DD>'` against a large
    # table and refuses to run if the date is >364 days old, returning a
    # clear error pointing the caller at helpers.surf_constraints.
    _guard_err = _check_surf_365_day_window(payload, input_path)
    if _guard_err is not None:
        return (input_path, _guard_err, 0.0)

    # v0.9.4: track attempts + wall time for credit accounting. Even failed
    # retry attempts get billed (timeout retry storms must be visible).
    _attempts_billed = 0
    _seconds_total = 0.0
    for attempt in range(1, max_attempts + 1):
        _attempts_billed += 1
        t0 = time.perf_counter()
        # v0.9.9 CRITICAL (deadlock fix, user report 2026-06-17 CA
        # 0x5dbde81f...): subprocess.run had NO timeout. When the surf CLI
        # hangs on a stuck network connection (connected but server never
        # responds), subprocess.run blocks FOREVER → the ThreadPoolExecutor
        # worker never returns → run_parallel's as_completed waits forever
        # → the whole pipeline deadlocks at futex_wait, CPU 0%, no network.
        # rule_11's chunked mint lookup (run_parallel → _run_one) was the
        # exact hang site (46+ min). section_a_scope._run_surf_with_retry
        # already had a timeout — this path was the gap. Hard cap each
        # attempt; TimeoutExpired is treated as a transient error so the
        # existing retry/backoff handles it, then fails loud after
        # max_attempts instead of hanging.
        try:
            # Attempt 1: @file form (older surf CLI / current alpha.40)
            proc = subprocess.run(
                ["surf", "onchain-sql", f"@{input_path}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                check=False, timeout=_SURF_SUBPROCESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - t0
            _seconds_total += elapsed
            resp = {"error": {"code": "SURF_TIMEOUT",
                              "message": f"surf onchain-sql hung > {_SURF_SUBPROCESS_TIMEOUT}s (killed)"}}
            last_resp, last_elapsed = resp, elapsed
            if attempt < max_attempts:
                time.sleep(min(2 ** attempt - 1, 7) + random.uniform(0, 0.5 * attempt))
                continue
            _record_credit(None, _seconds_total, _attempts_billed, success=False)
            return (input_path, resp, elapsed)
        elapsed = time.perf_counter() - t0

        # Detect "surf CLI doesn't grok @file" — these markers come from surf's
        # own server-side validator response when the @file syntax is not parsed
        # client-side and the literal "@/path" string is sent as the SQL.
        output = proc.stdout + proc.stderr
        surf_cli_mismatch = (
            "INVALID_REQUEST" in output and "Send a JSON object" in output
        ) or "not a JSON object" in output

        if proc.returncode != 0 or surf_cli_mismatch:
            # v0.8.7.2: fall back to stdin-piped JSON, NO --json flag. surf
            # CLI's --json is now a global output-format flag (alias for
            # `-o json`) and is rejected by onchain-sql when the API spec
            # cache is stale (manifests as "unknown flag: --json", see
            # ESPORTS report 2026-06-12). Default output is already JSON,
            # so --json is redundant — dropping it removes the spec-cache
            # dependency entirely.
            t0 = time.perf_counter()
            try:
                proc = subprocess.run(
                    ["surf", "onchain-sql"],
                    input=payload,
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    check=False, timeout=_SURF_SUBPROCESS_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                elapsed = time.perf_counter() - t0
                _seconds_total += elapsed
                resp = {"error": {"code": "SURF_TIMEOUT",
                                  "message": f"surf onchain-sql (stdin) hung > {_SURF_SUBPROCESS_TIMEOUT}s (killed)"}}
                last_resp, last_elapsed = resp, elapsed
                if attempt < max_attempts:
                    time.sleep(min(2 ** attempt - 1, 7) + random.uniform(0, 0.5 * attempt))
                    continue
                _record_credit(None, _seconds_total, _attempts_billed, success=False)
                return (input_path, resp, elapsed)
            elapsed = time.perf_counter() - t0

        _seconds_total += elapsed
        if proc.returncode != 0:
            resp: dict = {"error": {"code": "SURF_EXIT", "message": proc.stderr.strip() or proc.stdout.strip()[:500]}}
        else:
            try:
                resp = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                resp = {"error": {"code": "PARSE_ERROR", "message": str(e), "raw": proc.stdout[:500]}}

        # Success = a response that is not a dict carrying an "error" key.
        if not (isinstance(resp, dict) and "error" in resp):
            _record_credit(resp, _seconds_total, _attempts_billed, success=True)
            return (input_path, resp, elapsed)

        # Permanent request/schema error → fail fast (no point retrying).
        if not _is_transient_error(resp):
            _record_credit(None, _seconds_total, _attempts_billed, success=False)
            return (input_path, resp, elapsed)

        # Transient — back off (with jitter) and retry.
        last_resp, last_elapsed = resp, elapsed
        if attempt < max_attempts:
            time.sleep(min(2 ** attempt - 1, 7) + random.uniform(0, 0.5 * attempt))

    _record_credit(None, _seconds_total, _attempts_billed, success=False)
    return (input_path, last_resp, last_elapsed)


def _record_credit(resp: dict | None, seconds: float, attempts: int, success: bool) -> None:
    """v0.9.4: report this query's surf usage to the section_a_scope
    credit accumulator. Lazy import to avoid circular import (section_a_scope
    imports run_parallel from here). Silently no-ops if section_a_scope can't
    be imported — credit accounting must NEVER break the pipeline."""
    try:
        from section_a_scope import _surf_credit_add  # lazy: break cycle
    except Exception:
        return
    credits = 0.0
    if resp:
        try:
            credits = float((resp.get("meta") or {}).get("credits_used") or 0)
        except (TypeError, ValueError, AttributeError):
            credits = 0.0
    try:
        _surf_credit_add(
            credits=credits, seconds=seconds,
            attempts=attempts, success=success,
        )
    except Exception:
        pass


def run_parallel(input_paths: list[str], max_workers: int = 8) -> dict[str, dict]:
    """Run all input queries in parallel. Returns {input_path: response_json}.

    max_workers caps concurrency. Surf's server side throttles past 8 — keep
    default unless you've verified your account tier supports more.
    """
    results: dict[str, dict] = {}
    timings: dict[str, float] = {}
    with _cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_run_one, p): p for p in input_paths}
        for fut in _cf.as_completed(futures):
            path, resp, elapsed = fut.result()
            results[path] = resp
            timings[path] = elapsed
    return results, timings  # type: ignore[return-value]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("inputs", nargs="+", help="Query JSON files (surf onchain-sql input format)")
    p.add_argument(
        "--max-workers", type=int, default=8,
        help="Max concurrent surf calls (default 8; surf throttles above this)",
    )
    p.add_argument(
        "--out-suffix", default=".out.json",
        help="Suffix for output files. Default: .out.json (so q1.json -> q1.out.json)",
    )
    p.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-query timing summary on stderr.",
    )
    args = p.parse_args()

    # Validate inputs exist before launching anything.
    missing = [p for p in args.inputs if not Path(p).is_file()]
    if missing:
        print(f"REFUSED: input files not found: {missing}", file=sys.stderr)
        return 1

    t0 = time.perf_counter()
    results, timings = run_parallel(args.inputs, max_workers=args.max_workers)
    total = time.perf_counter() - t0

    # Write each result to <input>.out.json
    for in_path, resp in results.items():
        out_path = Path(in_path).with_suffix(args.out_suffix) if args.out_suffix.startswith(".") else Path(in_path).parent / (Path(in_path).stem + args.out_suffix)
        # If suffix doesn't start with `.`, treat as append.
        if not args.out_suffix.startswith("."):
            out_path = Path(in_path).with_name(Path(in_path).stem + args.out_suffix)
        out_path.write_text(json.dumps(resp, ensure_ascii=False, indent=2), encoding="utf-8")

    if not args.quiet:
        # v0.5.9 (adversarial review Win11 feedback): print success summary to STDOUT, not
        # stderr. PowerShell renders stderr as red NativeCommandError record
        # even when exit code is 0, which looked like a failure to operators.
        # Stdout is the right channel for success; only ACTUAL errors go to
        # stderr.
        print(f"OK: {len(results)} queries done in {total:.1f}s "
              f"(max worker concurrency = {args.max_workers})")
        for path, secs in sorted(timings.items(), key=lambda x: -x[1]):
            err = results[path].get("error")
            tag = "ERR" if err else "OK "
            credits = results[path].get("meta", {}).get("credits_used", "?")
            line = f"  [{tag}] {secs:5.1f}s  credits={credits}  {path}"
            if err:
                print(line, file=sys.stderr)
            else:
                print(line)

    # Exit non-zero if ANY query failed.
    any_err = any("error" in r for r in results.values())
    return 1 if any_err else 0


if __name__ == "__main__":
    sys.exit(main())
