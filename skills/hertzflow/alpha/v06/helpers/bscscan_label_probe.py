#!/usr/bin/env python3
"""bscscan_label_probe.py — BscScan public-label resolver for BSC addresses.

Designed to catch shared-pool / DEX-router / CEX-infrastructure addresses
that Surf/Arkham don't label but BscScan publicly tags. This is a
critical anti-pollution layer for cross_sym detection — without it,
every Alpha-listed token will see Binance Alpha 2.0 Router Proxy
(0x73d8bd54f7cf5fab43fe4ef40a62d390644946db) as a "cross-sym whale"
because it routes trades for ~all Alpha tokens.

Usage:
    from bscscan_label_probe import resolve_labels, classify_label

    labels = resolve_labels([
        "0x73d8bd54f7cf5fab43fe4ef40a62d390644946db",
        "0x...",
    ])
    # labels = {addr: {"label": "Binance: Alpha 2.0 Router Proxy",
    #                  "classification": "SHARED_POOL_CUSTODIAL"}}

Cache:
    File at ~/.binance-alpha-data/bscscan_labels.json
    TTL 30 days. BscScan public labels change rarely.

Failure mode:
    On scrape error / Cloudflare block / timeout, returns
    classification="UNKNOWN" for the address. Caller decides whether
    to fail-closed (exclude unknown) or fail-open (keep unknown).
    For cross_sym: fail-OPEN (keep) since most unlabeled addresses
    are real wallets, not infrastructure.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable

# 30-day cache; BscScan labels rarely change once assigned.
CACHE_TTL_SECS = 30 * 86400
DEFAULT_CACHE_PATH = os.environ.get(
    "BINANCE_ALPHA_LABEL_CACHE",
    os.path.expanduser("~/.binance-alpha-data/bscscan_labels.json"),
)

# Address-classification regexes — applied to BscScan title text.
# Order matters: more specific patterns first.

# Curated lookalike for "Binance: Alpha 2.0 Router Proxy" — explicit so we
# don't rely on the generic CEX_GENERIC fallback to catch this one critical
# pattern (which polluted every Alpha cross_sym result before this helper).
DEX_ROUTER_RE = re.compile(
    r"^(Binance:\s*Alpha|PancakeSwap.*(Router|Vault|Universal)|"
    r"Universal Router|1inch|0x(?:\s|:)|Paraswap|OpenOcean|Beethoven|"
    r"Curve|Balancer|Uniswap.*Router|SushiSwap|Thena|Wombat|Mu\sFinance|"
    r"Biswap.*Router|ApeSwap.*Router|MDEX|BabySwap)\b",
    re.IGNORECASE,
)

PRIVACY_AGGREGATOR_RE = re.compile(
    r"^(ChangeNOW|FixedFloat|SimpleSwap|Sideshift|ThorSwap|"
    r"Tornado\s*Cash|Railgun|Cyclone|Aztec|Privacy\s*Pool)\b",
    re.IGNORECASE,
)

CROSS_CHAIN_BRIDGE_RE = re.compile(
    r"^(deBridge|Stargate|cBridge|LayerZero|Wormhole|Across|Squid|"
    r"Multichain|Synapse|Hop|Connext|Symbiosis|XY\s*Finance|Rubic|"
    r"Bridgers|Allbridge|Celer|Polyhedra|Orbiter)\b",
    re.IGNORECASE,
)

CEX_INFRA_KW = re.compile(
    r"\b(Hot Wallet|Cold Wallet|Deposit Funder|Deposit Wallet|"
    r"Withdrawal(?:s)?|Reserve|Treasury|MultiSender|Distributor|"
    r"Custody|Wallet\s*\d+)\b",
    re.IGNORECASE,
)

CEX_NAME_RE = re.compile(
    r"^(Binance|HTX|OKX|Gate|Bybit|MEXC|KuCoin|Bitget|Coinbase|"
    r"Kraken|Upbit|Bitfinex|Crypto\.com|Bitstamp|Bithumb|Bitkub|"
    r"Aster\b)",
    re.IGNORECASE,
)

ENS_NAMED_RE = re.compile(
    r"^[a-z0-9_-]+\.(eth|bnb|crypto|nft|dao|wallet|x|polygon|sol)\s*$",
    re.IGNORECASE,
)


def classify_label(label: str | None) -> str:
    """Map BscScan label text to one of:

    - SHARED_POOL_CUSTODIAL — drop from cross_sym (CEX/router/bridge)
    - PRIVACY_AGGREGATOR    — keep with anti_forensic flag
    - CROSS_CHAIN_BRIDGE    — keep with caveat
    - DEX_ROUTER            — drop from cross_sym
    - ENS_NAMED             — keep (highest signal)
    - UNKNOWN_LABELED       — has label but no classifier match
    - UNLABELED             — no BscScan label
    - UNKNOWN               — fetch failed
    """
    if label is None:
        return "UNLABELED"
    if not isinstance(label, str) or not label.strip():
        return "UNLABELED"
    if ENS_NAMED_RE.match(label):
        return "ENS_NAMED"
    if PRIVACY_AGGREGATOR_RE.match(label):
        return "PRIVACY_AGGREGATOR"
    if CROSS_CHAIN_BRIDGE_RE.match(label):
        return "CROSS_CHAIN_BRIDGE"
    if DEX_ROUTER_RE.match(label):
        return "DEX_ROUTER"
    if CEX_INFRA_KW.search(label) or CEX_NAME_RE.match(label):
        return "SHARED_POOL_CUSTODIAL"
    return "UNKNOWN_LABELED"


# Set of classifications that should be EXCLUDED from cross_sym whales —
# they are infrastructure, not operator wallets.
EXCLUDE_FROM_CROSS_SYM = frozenset({
    "SHARED_POOL_CUSTODIAL",
    "DEX_ROUTER",
})


def _load_cache(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        return json.load(open(path))
    except Exception:
        return {}


def _save_cache(cache: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fp:
        json.dump(cache, fp, indent=2)
    os.replace(tmp, path)


_TITLE_RE = re.compile(r"<title>([^<]+)</title>")


def _fetch_one(addr: str) -> tuple[str, str | None, str]:
    """Scrape BscScan for one address. Returns (addr, label, source)."""
    try:
        req = urllib.request.Request(
            f"https://bscscan.com/address/{addr}",
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X) "
                    "AppleWebKit/537.36"
                ),
            },
        )
        body = urllib.request.urlopen(req, timeout=12).read().decode(
            "utf-8", errors="ignore"
        )
    except Exception as e:
        return (addr, None, f"failed:{e}")
    # Prefer the explicit "Public Name Tag" if present — more reliable than
    # title which sometimes shows the contract name.
    pnt_match = re.search(
        r"Public Name Tag[^<]*<br\s*/?>\s*([^<']+?)'>", body
    )
    if pnt_match:
        return (addr, pnt_match.group(1).strip(), "scrape:pnt")
    # Fallback to <title>X | Address: 0x... | BscScan</title>.
    title_match = _TITLE_RE.search(body)
    if title_match:
        title = title_match.group(1).strip()
        parts = title.split(" | ")
        if parts and not parts[0].startswith("Address:"):
            return (addr, parts[0].strip(), "scrape:title")
    return (addr, None, "scrape:no_label")


def resolve_labels(
    addrs: Iterable[str],
    cache_path: str = DEFAULT_CACHE_PATH,
    workers: int = 8,
    verbose: bool = False,
) -> dict[str, dict]:
    """Resolve a batch of addresses to {label, classification}.

    Returns {addr_lower: {"label": str|None, "classification": str,
                         "fetched_at": int, "source": str}}.

    Hits cache first (30-day TTL); scrapes BscScan in parallel for misses.
    """
    addrs_lower = [a.lower() for a in addrs if a]
    if not addrs_lower:
        return {}

    cache = _load_cache(cache_path)
    now = int(time.time())
    out: dict[str, dict] = {}
    to_fetch: list[str] = []

    for a in addrs_lower:
        rec = cache.get(a)
        if rec and (now - rec.get("fetched_at", 0)) < CACHE_TTL_SECS:
            # Recompute classification in case classifier rules changed
            cls = classify_label(rec.get("label"))
            out[a] = {
                "label": rec.get("label"),
                "classification": cls,
                "source": "cache",
                "fetched_at": rec.get("fetched_at"),
            }
        else:
            to_fetch.append(a)

    if to_fetch:
        if verbose:
            print(
                f"[bscscan_label_probe] fetching {len(to_fetch)} addresses "
                f"({len(addrs_lower) - len(to_fetch)} cache hits)",
                file=sys.stderr,
            )
        with ThreadPoolExecutor(max_workers=min(workers, len(to_fetch))) as ex:
            for addr, label, source in ex.map(_fetch_one, to_fetch):
                cls = classify_label(label)
                if source.startswith("failed"):
                    cls = "UNKNOWN"
                out[addr] = {
                    "label": label,
                    "classification": cls,
                    "source": source,
                    "fetched_at": now,
                }
                # Persist to cache (only successful fetches; failures retried
                # next run instead of caching the failure for 30 days)
                if not source.startswith("failed"):
                    cache[addr] = {
                        "label": label,
                        "fetched_at": now,
                    }
        _save_cache(cache, cache_path)

    return out


def find_excluded(
    addrs: Iterable[str],
    cache_path: str = DEFAULT_CACHE_PATH,
    verbose: bool = False,
) -> set[str]:
    """Return the subset of `addrs` whose BscScan label classifies as
    SHARED_POOL_CUSTODIAL or DEX_ROUTER. Used by section_cross_sym to
    filter candidate whales before they reach the report.

    Fail-OPEN: UNKNOWN / UNLABELED / cache miss errors are NOT excluded.
    This means a transient BscScan outage degrades to noisier cross_sym
    results, not to data loss.
    """
    labels = resolve_labels(addrs, cache_path=cache_path, verbose=verbose)
    return {
        a for a, r in labels.items()
        if r["classification"] in EXCLUDE_FROM_CROSS_SYM
    }


# ============================================================
# CLI for ad-hoc inspection / cache warm-up
# ============================================================

def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("addresses", nargs="+", help="Addresses to resolve")
    ap.add_argument("--cache", default=DEFAULT_CACHE_PATH)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    labels = resolve_labels(
        args.addresses, cache_path=args.cache, verbose=args.verbose,
    )
    for addr, rec in labels.items():
        print(f"{addr}\t{rec['classification']}\t{rec.get('label')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
