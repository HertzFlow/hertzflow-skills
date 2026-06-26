#!/usr/bin/env python3
"""cross_sym_registry.py — Universal Alpha BSC top-100 holders cache.

v0.7 forward-detection foundation. Maintains a user-local cache of every
active Alpha BSC token's top-100 holders, with a reverse index keyed by
holder address. Enables O(1) lookup of "which Alpha tokens does this
wallet hold a top-100 position in?".

Design constraints:
  - User-local cache: `~/.binance-alpha-data/cross_sym_registry.json`
  - Lazy refresh: TTL 7 days, refresh on stale OR forced
  - Universe scope: BSC chain (chainId 56) + 24h vol > $100K (active)
  - User-configurable via SCOPE env: 'active' (default) | 'full' | 'top100'
  - Refresh cost: ~$0.75-2 per call (1 credit per token, ~$0.005-0.01)
  - All Surf calls run via the user's authenticated CLI; no central
    service, no telemetry.

Concurrency: refresh uses ThreadPoolExecutor with bounded workers (8)
to stay under Surf API rate limits while keeping wall-clock low.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

# ----- Module constants -----

DEFAULT_CACHE_DIR = Path.home() / ".binance-alpha-data"
DEFAULT_CACHE_PATH = DEFAULT_CACHE_DIR / "cross_sym_registry.json"
DEFAULT_LOCK_PATH = DEFAULT_CACHE_DIR / "cross_sym_registry.lock"
DEFAULT_TTL_SECS = 7 * 86400          # 7 days
DEFAULT_LOCK_TIMEOUT_SECS = 120       # max time to wait for another refresher
DEFAULT_LOCK_STALE_SECS = 600         # treat lock as stale after 10 min (orphan)
DEFAULT_HOLDERS_PER_TOKEN = 100
DEFAULT_ACTIVE_VOL_THRESHOLD_USD = 100_000.0
DEFAULT_TOP_N_BY_VOL = 100
DEFAULT_PARALLEL_WORKERS = 8
DEFAULT_SCHEMA_VERSION = "0.7.0"
DEFAULT_RETRY_MAX = 2                 # retries per Surf call on retryable errors
DEFAULT_RETRY_BASE_SECS = 1.5         # exponential backoff base
MIN_COVERAGE_RATIO = 0.7              # refresh must capture ≥70% of universe to commit

ALPHA_TOKEN_LIST_URL = (
    "https://www.binance.com/bapi/defi/v1/public/wallet-direct/"
    "buw/wallet/cex/alpha/all/token/list"
)
BSC_CHAIN_ID = "56"


# ----- Errors -----

class RegistryError(Exception):
    """Raised when the registry cannot be loaded or refreshed."""


class SurfCallError(RegistryError):
    """Raised when a Surf CLI call fails unexpectedly."""


# ----- Public API -----

def get_reverse_index(
    *,
    cache_path: Path = DEFAULT_CACHE_PATH,
    lock_path: Path = DEFAULT_LOCK_PATH,
    ttl_secs: int = DEFAULT_TTL_SECS,
    force_refresh: bool = False,
    scope: str = "active",
    verbose: bool = False,
) -> dict[str, Any]:
    """Return the reverse index. Refreshes lazily if cache is stale.

    audit P1a fixes applied:
      - Cross-process refresh lock (no thundering herd)
      - Stale-cache fallback on refresh failure
      - Minimum coverage guard (reject low-coverage refresh)
      - Schema validation on loaded cache

    Returns:
        dict with shape:
        {
            "_schema_version": str,
            "snapshot_ts": int,
            "scope": str,
            "n_tokens": int,
            "reverse_index": {addr_lower: [{sym, ca, pct, rank, balance}, ...]}
        }

    Raises:
        RegistryError if neither cached nor refreshable.
    """
    cached = _load_cache(cache_path)
    if cached is not None and not force_refresh:
        age = int(time.time()) - cached.get("snapshot_ts", 0)
        if age < ttl_secs:
            if verbose:
                print(f"[cross_sym_registry] cache hit (age {age // 60}min)", file=sys.stderr)
            return cached
        if verbose:
            print(
                f"[cross_sym_registry] cache stale (age {age // 3600}h > TTL {ttl_secs // 3600}h), refreshing",
                file=sys.stderr,
            )
    elif verbose:
        print("[cross_sym_registry] no cache, building from scratch", file=sys.stderr)

    # Cross-process lock: another invocation may already be refreshing.
    # Wait briefly; if it finishes, just use its result.
    lock_owned = _acquire_lock(lock_path, verbose=verbose)
    try:
        if not lock_owned:
            # Someone else is refreshing or held lock. Re-read cache after waiting.
            if verbose:
                print("[cross_sym_registry] another process refreshing, re-reading cache", file=sys.stderr)
            cached2 = _load_cache(cache_path)
            if cached2 and (int(time.time()) - cached2.get("snapshot_ts", 0)) < ttl_secs:
                return cached2
            # Their refresh failed or still running too long — fall through and
            # try ourselves (best-effort)

        try:
            refreshed = refresh(scope=scope, verbose=verbose)
        except RegistryError as e:
            if verbose:
                print(f"[cross_sym_registry] refresh failed ({e}); falling back to stale cache if any", file=sys.stderr)
            if cached is not None:
                # Stale-cache fallback: better than nothing
                cached["_stale_fallback"] = True
                cached["_refresh_error"] = str(e)
                return cached
            raise

        # Coverage guard: don't commit a low-coverage refresh
        n_ok = refreshed.get("n_tokens", 0)
        n_universe = refreshed.get("n_universe", 0)
        if n_universe > 0 and n_ok / n_universe < MIN_COVERAGE_RATIO:
            if verbose:
                print(
                    f"[cross_sym_registry] refresh coverage {n_ok}/{n_universe} "
                    f"({100*n_ok/n_universe:.0f}%) < {MIN_COVERAGE_RATIO*100:.0f}%; "
                    f"keeping stale cache",
                    file=sys.stderr,
                )
            if cached is not None:
                cached["_stale_fallback"] = True
                cached["_low_coverage_skip"] = f"{n_ok}/{n_universe}"
                return cached
            # No prior cache and low coverage — still better than nothing, but warn
            refreshed["_low_coverage"] = True

        _save_cache(cache_path, refreshed)
        return refreshed
    finally:
        if lock_owned:
            _release_lock(lock_path)


def lookup(addr: str, registry: dict | None = None) -> list[dict]:
    """O(1) reverse lookup. Returns list of token entries the address
    is a top-100 holder in.

    Each entry: {sym, ca, pct, rank, balance}
    Returns [] if not in any tracked token's top-100.
    """
    if registry is None:
        registry = get_reverse_index()
    addr_lower = addr.lower()
    return list(registry.get("reverse_index", {}).get(addr_lower, []))


def refresh(
    *,
    scope: str = "active",
    holders_per_token: int = DEFAULT_HOLDERS_PER_TOKEN,
    workers: int = DEFAULT_PARALLEL_WORKERS,
    verbose: bool = False,
) -> dict[str, Any]:
    """Force a registry refresh from Surf. Does NOT write cache (caller does).

    Steps:
      1. Fetch Alpha token list from Binance API
      2. Filter to BSC + scope (active/full/top100)
      3. Parallel surf token-holders for each
      4. Build reverse index
    """
    if scope not in ("active", "full", "top100"):
        raise RegistryError(f"unknown scope: {scope!r}")

    tokens = _fetch_alpha_universe(scope=scope, verbose=verbose)
    if verbose:
        print(f"[cross_sym_registry] universe size: {len(tokens)} tokens", file=sys.stderr)

    if not tokens:
        raise RegistryError("Alpha token universe is empty after filtering")

    holders_by_token: dict[str, list[dict]] = {}

    def _fetch_one(token: dict) -> tuple[str, list[dict] | None]:
        ca = token["ca"]
        try:
            holders = _surf_token_holders(ca, limit=holders_per_token)
            return ca, holders
        except SurfCallError as e:
            if verbose:
                print(f"  [cross_sym_registry] skipping {token['sym']}: {e}", file=sys.stderr)
            return ca, None

    n_ok = 0
    n_fail = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_token = {ex.submit(_fetch_one, t): t for t in tokens}
        for fut in as_completed(future_to_token):
            ca, holders = fut.result()
            if holders is None:
                n_fail += 1
                continue
            holders_by_token[ca] = holders
            n_ok += 1

    if verbose:
        print(
            f"[cross_sym_registry] fetched {n_ok}/{len(tokens)} tokens ({n_fail} failed)",
            file=sys.stderr,
        )

    reverse_index = _build_reverse_index(tokens, holders_by_token)

    return {
        "_schema_version": DEFAULT_SCHEMA_VERSION,
        "snapshot_ts": int(time.time()),
        "scope": scope,
        "n_tokens": n_ok,
        "n_universe": len(tokens),
        "n_fetch_failed": n_fail,
        "reverse_index": reverse_index,
    }


# ----- Internals -----

def _load_cache(path: Path) -> dict | None:
    """Load cache with light schema validation. Returns None on any failure."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    # Schema validation: reject obviously-bad shapes
    if not isinstance(data, dict):
        return None
    if not isinstance(data.get("snapshot_ts"), int):
        return None
    if not isinstance(data.get("reverse_index"), dict):
        return None
    return data


def _save_cache(path: Path, data: dict) -> None:
    """Atomic write with unique temp name to avoid concurrent-writer clobber.

    audit P1a fix: previously used fixed `.tmp` suffix, two concurrent
    refreshes would clobber each other's temp file. Now uses uuid-suffixed
    temp file per write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        # If os.replace failed, clean up the orphan tmp
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _acquire_lock(lock_path: Path, *, verbose: bool = False) -> bool:
    """Try to acquire a cross-process refresh lock.

    Returns True if we own the lock. False if another process holds it
    (caller should re-read cache and use it).

    Uses O_CREAT|O_EXCL for race-free creation. Stale locks (older than
    DEFAULT_LOCK_STALE_SECS) are forcibly removed and re-acquired.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + DEFAULT_LOCK_TIMEOUT_SECS
    pid = os.getpid()
    payload = f"{pid}:{int(time.time())}\n".encode()
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, payload)
            os.close(fd)
            return True
        except FileExistsError:
            pass
        # Check if existing lock is stale
        try:
            mtime = lock_path.stat().st_mtime
            if time.time() - mtime > DEFAULT_LOCK_STALE_SECS:
                if verbose:
                    print(f"[cross_sym_registry] removing stale lock (age {int(time.time()-mtime)}s)", file=sys.stderr)
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                continue
        except OSError:
            pass
        if time.time() >= deadline:
            return False   # give up, fall back to other process's result
        time.sleep(2.0)


def _release_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except OSError:
        pass


def _fetch_alpha_universe(*, scope: str, verbose: bool) -> list[dict]:
    """Fetch Binance Alpha listing and filter by scope.

    Returns list of {sym, name, ca, volume24h}.
    """
    import urllib.request
    req = urllib.request.Request(
        ALPHA_TOKEN_LIST_URL,
        headers={"User-Agent": "binance-alpha-skill/0.7"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise RegistryError(f"Alpha API fetch failed: {e}") from e

    raw = doc.get("data") or []
    bsc_tokens = []
    for t in raw:
        if t.get("chainId") != BSC_CHAIN_ID:
            continue
        ca = (t.get("contractAddress") or "").lower()
        if not ca.startswith("0x") or len(ca) != 42:
            continue
        vol = t.get("volume24h")
        try:
            vol_f = float(vol) if vol else 0.0
        except (ValueError, TypeError):
            vol_f = 0.0
        bsc_tokens.append({
            "sym": (t.get("symbol") or "").upper(),
            "name": t.get("name") or "",
            "ca": ca,
            "volume24h": vol_f,
        })

    if scope == "full":
        return bsc_tokens

    if scope == "active":
        return [t for t in bsc_tokens if t["volume24h"] > DEFAULT_ACTIVE_VOL_THRESHOLD_USD]

    if scope == "top100":
        return sorted(bsc_tokens, key=lambda t: t["volume24h"], reverse=True)[:DEFAULT_TOP_N_BY_VOL]

    raise RegistryError(f"unknown scope: {scope!r}")


def _surf_token_holders(
    ca: str,
    *,
    limit: int,
    max_retries: int = DEFAULT_RETRY_MAX,
) -> list[dict]:
    """Call surf token-holders for one token. Returns list of holder dicts.

    audit P1a fix: bounded retry with exponential backoff + jitter
    for retryable Surf errors (rate-limit / timeout). Hard errors (bad
    address, auth) fail fast without retry.

    Returns list capped to `limit` (defensive, in case Surf returns more).
    """
    # Defensive: validate ca format before invoking subprocess
    if not (ca.startswith("0x") and len(ca) == 42):
        raise SurfCallError(f"invalid ca format: {ca!r}")

    # v0.7.20.1: kept hardcoded "bsc" intentionally — cross_sym_registry
    # is a BSC-only Alpha-token catalogue today (see bsc_tokens variable
    # in fetch_alpha_token_list above). Cross-chain registry support
    # tracked separately; once it lands this should accept a per-token
    # chain hint instead of reading the active forensic chain.
    cmd = [
        "surf", "token-holders",
        "--address", ca,
        "--chain", "bsc",
        "--limit", str(limit),
        "--include", "labels",
        "--json",
    ]

    last_err: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            raise SurfCallError(f"surf timed out for {ca}: {e}") from e
        except OSError as e:
            # OSError = surf binary missing / fork failure — not retryable
            raise SurfCallError(f"surf invocation failed for {ca}: {e}") from e

        if result.returncode == 0:
            try:
                doc = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise SurfCallError(f"surf returned non-JSON for {ca}: {e}") from e
            if doc.get("error"):
                # Check if retryable
                err = doc["error"]
                err_msg = err.get("message", "")
                if (err.get("retryable") or "TIMEOUT" in (err.get("code") or "")) and attempt < max_retries:
                    last_err = SurfCallError(f"retryable: {err_msg}")
                    _sleep_backoff(attempt)
                    continue
                raise SurfCallError(f"surf API error for {ca}: {err_msg}")
            holders = doc.get("data") or []
            return holders[:limit]   # defensive cap

        # Non-zero exit. Check stderr for hint at retryable.
        stderr = result.stderr.lower()
        if ("rate" in stderr or "timeout" in stderr or "503" in stderr or "429" in stderr) and attempt < max_retries:
            last_err = SurfCallError(f"retryable exit {result.returncode}")
            _sleep_backoff(attempt)
            continue
        raise SurfCallError(
            f"surf exited {result.returncode} for {ca}: {result.stderr[:200]}"
        )

    # Should not reach here, but just in case
    raise SurfCallError(f"surf exhausted retries for {ca}: {last_err}")


def _sleep_backoff(attempt: int) -> None:
    """Exponential backoff with full jitter."""
    delay = DEFAULT_RETRY_BASE_SECS * (2 ** attempt)
    delay = random.uniform(0, delay)
    time.sleep(delay)


def _build_reverse_index(
    tokens: list[dict],
    holders_by_token: dict[str, list[dict]],
) -> dict[str, list[dict]]:
    """Build addr_lower → [{sym, ca, pct, rank, balance, entity_name}, ...]."""
    index: dict[str, list[dict]] = {}
    by_ca = {t["ca"]: t for t in tokens}
    for ca, holders in holders_by_token.items():
        sym = by_ca.get(ca, {}).get("sym", "")
        for rank, h in enumerate(holders, 1):
            addr = (h.get("address") or "").lower()
            if not addr or not addr.startswith("0x"):
                continue
            entry = {
                "sym": sym,
                "ca": ca,
                "rank": rank,
                "pct": float(h.get("percentage", 0)),
                "balance": str(h.get("balance", "0")),  # keep precision, large numbers
            }
            ent_name = h.get("entity_name")
            if ent_name:
                entry["entity_name"] = ent_name
                entry["entity_type"] = h.get("entity_type", "")
            index.setdefault(addr, []).append(entry)

    # Sort each holder's appearances by pct descending (most concentrated first)
    for addr in index:
        index[addr].sort(key=lambda e: e["pct"], reverse=True)

    return index


# ----- CLI ------

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scope", default="active", choices=("active", "full", "top100"))
    ap.add_argument("--refresh", action="store_true", help="Force refresh even if cache fresh")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--lookup", metavar="ADDR", help="Lookup a single address and exit")
    args = ap.parse_args()

    if args.lookup:
        idx = get_reverse_index(verbose=args.verbose, scope=args.scope)
        hits = lookup(args.lookup, idx)
        print(json.dumps({
            "address": args.lookup.lower(),
            "n_hits": len(hits),
            "tokens": hits,
        }, ensure_ascii=False, indent=2))
    else:
        registry = get_reverse_index(
            force_refresh=args.refresh,
            scope=args.scope,
            verbose=args.verbose,
        )
        print(json.dumps({
            "snapshot_ts": registry["snapshot_ts"],
            "scope": registry["scope"],
            "n_tokens": registry["n_tokens"],
            "n_universe": registry.get("n_universe"),
            "n_fetch_failed": registry.get("n_fetch_failed"),
            "n_unique_addrs": len(registry["reverse_index"]),
        }, indent=2))
