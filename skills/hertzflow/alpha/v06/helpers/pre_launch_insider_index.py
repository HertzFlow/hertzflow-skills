#!/usr/bin/env python3
"""pre_launch_insider_index.py — Append-only m6 reverse map across all
tokens this user has run forensic reports on.

v0.7 cross-sym foundation. Every time forensic_pipeline.py completes
rule_11_backward_trace for a token, the pipeline appends that token's
m6_rows (pre-launch deployer outflow receivers) into this index. Over
time, builds a universal "addr → list of (token, dumped_pct,
received_amount)" map.

This index is **zero additional cost per report** — it piggy-backs on
data the pipeline already computes. Lookup is O(1) for "was this wallet
a pre-launch insider in any other token I've reported on?"

This is the KOL_MANAGER detection backbone: if a wallet shows up as a
pre-launch receiver in ≥2 different tokens, it's almost certainly
either a KOL manager / OTC desk / advisor allocation.

Design constraints:
  - User-local: `~/.binance-alpha-data/pre_launch_insider_index.json`
  - Append-only: idempotent re-runs don't duplicate entries
  - Atomic write (uuid-suffixed tmp + os.replace, same pattern as cross_sym_registry)
  - Cross-process safe (lock + unique tmp)
  - Schema validation on load (reject malformed cache)
  - NO surf calls — pure local data accumulation
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

# ----- Module constants -----

DEFAULT_INDEX_DIR = Path.home() / ".binance-alpha-data"
DEFAULT_INDEX_PATH = DEFAULT_INDEX_DIR / "pre_launch_insider_index.json"
DEFAULT_LOCK_PATH = DEFAULT_INDEX_DIR / "pre_launch_insider_index.lock"
DEFAULT_LOCK_TIMEOUT_SECS = 30
DEFAULT_LOCK_STALE_SECS = 300
DEFAULT_SCHEMA_VERSION = "0.7.0"


class IndexError_(Exception):
    """Raised when the index cannot be loaded or updated."""


# ----- Public API -----

def append_from_report(
    ca: str,
    sym: str,
    m6_rows: list[dict],
    *,
    index_path: Path = DEFAULT_INDEX_PATH,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> dict[str, int]:
    """Append a token's m6_rows (Rule 11 pre-launch receivers) into the index.

    Idempotent: re-running on the same (ca, addr) pair overwrites the
    entry rather than duplicating. This means re-running a report on the
    same token updates the dumped_pct / current_balance fields to latest.

    Args:
        ca: contract address (lowercase 0x-prefixed)
        sym: token symbol (e.g. "TOKEN")
        m6_rows: list of {addr, dumped_pct, received_from_deployer, current_balance, ...}

    Returns:
        {"n_new_addrs": int, "n_updated_addrs": int, "total_addrs_indexed": int}
    """
    ca_lower = ca.lower()
    if not (ca_lower.startswith("0x") and len(ca_lower) == 42):
        raise IndexError_(f"invalid ca: {ca!r}")

    # Acquire cross-process lock to avoid concurrent writers clobbering
    lock_owned = _acquire_lock(lock_path)
    try:
        if not lock_owned:
            raise IndexError_(
                "could not acquire pre_launch_insider_index lock (another process holding too long)"
            )

        existing = _load_index(index_path) or {
            "_schema_version": DEFAULT_SCHEMA_VERSION,
            "snapshot_ts": int(time.time()),
            "tokens": {},
            "reverse_index": {},
        }

        # Compute delta vs previous record for this CA (idempotent overwrite)
        existing_for_ca = existing["tokens"].get(ca_lower, {}).get("addrs", {})
        new_addrs = {}
        for r in m6_rows:
            addr = (r.get("addr") or "").lower()
            if not (addr.startswith("0x") and len(addr) == 42):
                continue
            new_addrs[addr] = {
                "dumped_pct": float(r.get("dumped_pct", 0)),
                "received_from_deployer": float(r.get("received_from_deployer", 0)),
                "current_balance": float(r.get("current_balance") or 0),
            }

        n_new = sum(1 for a in new_addrs if a not in existing_for_ca)
        n_updated = sum(1 for a in new_addrs if a in existing_for_ca)

        # Update tokens map
        existing["tokens"][ca_lower] = {
            "sym": sym.upper(),
            "ca": ca_lower,
            "last_updated_ts": int(time.time()),
            "addrs": new_addrs,
        }

        # Rebuild reverse_index from scratch each time (idempotent + simple).
        # Cost: O(N_tokens * avg_addrs_per_token), trivially fast for any
        # realistic N. The alternative (incremental update) is error-prone
        # because removing a previously-indexed token's entries from the
        # reverse_index requires careful bookkeeping.
        reverse: dict[str, list[dict]] = {}
        for ca2, tok_data in existing["tokens"].items():
            sym2 = tok_data.get("sym", "")
            for addr2, info in tok_data.get("addrs", {}).items():
                reverse.setdefault(addr2, []).append({
                    "sym": sym2,
                    "ca": ca2,
                    "dumped_pct": info.get("dumped_pct", 0),
                    "received_from_deployer": info.get("received_from_deployer", 0),
                    "current_balance": info.get("current_balance", 0),
                })

        # Sort each addr's appearances by (received_from_deployer DESC,
        # dumped_pct DESC) for stable ordering even with equal allocations.
        # adversarial review P1b audit tie-break recommendation.
        for addr in reverse:
            reverse[addr].sort(
                key=lambda e: (e["received_from_deployer"], e["dumped_pct"]),
                reverse=True,
            )

        existing["reverse_index"] = reverse
        existing["snapshot_ts"] = int(time.time())

        _save_index(index_path, existing)

        return {
            "n_new_addrs": n_new,
            "n_updated_addrs": n_updated,
            "total_addrs_indexed": len(reverse),
        }
    finally:
        if lock_owned:
            _release_lock(lock_path)


def lookup(
    addr: str,
    *,
    index_path: Path = DEFAULT_INDEX_PATH,
) -> list[dict]:
    """O(1) reverse lookup. Returns list of token entries where this
    address appears as a pre-launch receiver.

    Each entry: {sym, ca, dumped_pct, received_from_deployer, current_balance}
    Returns [] if not in any indexed token.

    This is a hot path during forensic reports — cache the index in
    caller if doing many lookups.
    """
    idx = _load_index(index_path)
    if not idx:
        return []
    return list(idx.get("reverse_index", {}).get(addr.lower(), []))


def load_full_index(
    *,
    index_path: Path = DEFAULT_INDEX_PATH,
) -> dict[str, Any]:
    """Load the full index. Used by callers doing many lookups (batch
    classification) — avoid re-reading the file per lookup."""
    return _load_index(index_path) or {
        "_schema_version": DEFAULT_SCHEMA_VERSION,
        "snapshot_ts": 0,
        "tokens": {},
        "reverse_index": {},
    }


# ----- Internals -----

def _load_index(path: Path) -> dict | None:
    """Load index with schema validation. Returns None on any failure."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    if not isinstance(data.get("tokens"), dict):
        return None
    if not isinstance(data.get("reverse_index"), dict):
        return None
    return data


def _save_index(path: Path, data: dict) -> None:
    """Atomic write with uuid-suffixed temp (no concurrent-writer clobber)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _acquire_lock(lock_path: Path) -> bool:
    """Same primitive as cross_sym_registry — O_EXCL create, stale-clean."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + DEFAULT_LOCK_TIMEOUT_SECS
    payload = f"{os.getpid()}:{int(time.time())}\n".encode()
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, payload)
            os.close(fd)
            return True
        except FileExistsError:
            pass
        try:
            mtime = lock_path.stat().st_mtime
            if time.time() - mtime > DEFAULT_LOCK_STALE_SECS:
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                continue
        except OSError:
            pass
        if time.time() >= deadline:
            return False
        time.sleep(0.5)


def _release_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except OSError:
        pass


# ----- CLI -----

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_lookup = sub.add_parser("lookup", help="Look up an address")
    p_lookup.add_argument("addr")
    p_stats = sub.add_parser("stats", help="Show index statistics")
    p_dump = sub.add_parser("dump", help="Dump full index as JSON")
    args = ap.parse_args()

    if args.cmd == "lookup":
        hits = lookup(args.addr)
        print(json.dumps({
            "address": args.addr.lower(),
            "n_hits": len(hits),
            "tokens": hits,
        }, ensure_ascii=False, indent=2))
    elif args.cmd == "stats":
        idx = load_full_index()
        print(json.dumps({
            "snapshot_ts": idx.get("snapshot_ts"),
            "n_tokens_indexed": len(idx.get("tokens", {})),
            "n_unique_addrs": len(idx.get("reverse_index", {})),
            "tokens": [
                {"sym": t.get("sym"), "ca": t.get("ca"), "n_addrs": len(t.get("addrs", {}))}
                for t in idx.get("tokens", {}).values()
            ],
        }, indent=2))
    elif args.cmd == "dump":
        idx = load_full_index()
        print(json.dumps(idx, ensure_ascii=False, indent=2))
