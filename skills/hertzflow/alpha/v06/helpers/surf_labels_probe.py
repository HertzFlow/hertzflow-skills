#!/usr/bin/env python3
"""surf_labels_probe.py — v0.7.6 forensic helper.

Queries `surf wallet-labels-batch` (Arkham backend) for a batch of
addresses and classifies the labels into actionable categories. This
fills the gap left by relying only on `surf token-holders` response's
`entity_name`/`entity_type` fields, which are not always populated even
when Arkham has a high-confidence label.

The trigger case (2026-05-25):
- `0x26209d9f0dc3...` was a top-100 holder of JCT (15.5% supply) and
  appeared as a cross-sym candidate. Arkham labels it as "Bitget
  Deposit" with confidence 1.0, but the token-holders response had no
  `entity_name`. Result: the address was classified as a "cross-sym
  whale (identity TBD)" and emitted into the report's whale monitoring
  list, when it is in fact a Bitget exchange deposit address.

- `0xef7d88d12b63...` was identified as the "operator EOA" counterparty
  of the H wash circuit. Arkham labels it as PancakeSwap V3 Pool. The
  whole "closed-loop operator wash" framing was therefore wrong — the
  contract was trading against a DEX pool, not against an operator EOA.

Both bugs are downstream of the same root cause: the pipeline never
explicitly queried Arkham labels for the candidate set.

Output schema (per address):
    {
        "label": "Bitget Deposit" | None,        # raw Arkham label
        "entity_name": "PancakeSwap" | None,     # raw Arkham entity
        "entity_type": "dex" | "cex" | ...,
        "classification": "CEX_DEPOSIT" |
                          "CEX_HOT_WALLET" |
                          "DEX_POOL" |
                          "BRIDGE" |
                          "MARKET_MAKER" |
                          "OTHER_NAMED" |        # has label but not infra
                          "UNLABELED",
        "confidence": float,
    }

`EXCLUDE_FROM_CROSS_SYM` covers the classifications that should be
filtered out of cross-sym whale candidates (CEX_*, DEX_POOL, BRIDGE).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Iterable

SURF_TIMEOUT_SECS = 30

# Address regex — narrow allowlist for SQL/shell interpolation defense.
# v0.7.21.7: kept for legacy code paths; runtime now delegates to chain_router
# so Solana base58 candidates pass through alongside EVM 0x[…]{40}.
_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")

from chain_router import (  # v0.7.21.7
    is_valid_addr as _chain_is_valid_addr,
    get_active_chain as _chain_get_active,
)


def _addr_ok(a) -> bool:
    if not isinstance(a, str) or not a:
        return False
    if _chain_get_active() == "solana":
        return _chain_is_valid_addr(a)
    return _chain_is_valid_addr(a.lower())


def _norm_addr(a: str) -> str:
    return a if _chain_get_active() == "solana" else a.lower()

# Label classification patterns. Order matters: more specific first.
# Tested against Arkham's actual label naming convention as observed
# on BSC addresses 2026-05-25.

# CEX deposit addresses (where users send tokens to deposit to an exchange)
CEX_DEPOSIT_RE = re.compile(
    r"\b(Binance|Bitget|OKX|Gate|Bybit|MEXC|KuCoin|HTX|Coinbase|Kraken|"
    r"Bitfinex|Upbit|Bithumb|Crypto\.com)\s*Deposit\b",
    re.IGNORECASE,
)

# CEX hot wallets, cold wallets, withdrawals, reserves
CEX_HOT_RE = re.compile(
    r"\b(Binance|Bitget|OKX|Gate|Bybit|MEXC|KuCoin|HTX|Coinbase|Kraken|"
    r"Bitfinex|Upbit|Bithumb|Crypto\.com)"
    r"\s*(Hot|Cold|Withdrawal|Reserve|Treasury|Custody|Wallet|"
    r"Distributor|MultiSender)\b",
    re.IGNORECASE,
)

# DEX pool / vault / router
DEX_POOL_RE = re.compile(
    r"\b(V[23]\s*Pool|Pool\b|Vault\b|Router\b|Pair\b|LP\b|"
    r"Concentrated\s*Liquidity)\b",
    re.IGNORECASE,
)

# Self-identifying DEX terms — version-pools, concentrated-liquidity, AMM pairs.
# These are unambiguously DEX even without a protocol-name prefix, so they do NOT
# need the DEX_PROTOCOL_NAMES gate (which only exists to keep a bare "Pool"/"Vault"
# from sweeping in staking/mining pools). Fixes a bare "V3 Pool" Arkham label
# (conf 1.0) falling to OTHER_NAMED and then being mistaken for an operator wallet.
DEX_STRONG_RE = re.compile(
    r"\b(V[23]\s*Pool|Concentrated\s*Liquidity|AMM\s*Pair)\b",
    re.IGNORECASE,
)

DEX_PROTOCOL_NAMES = re.compile(
    r"^(PancakeSwap|Uniswap|SushiSwap|1inch|0x|Paraswap|Curve|Balancer|"
    r"Thena|Wombat|Biswap|ApeSwap|MDEX|BabySwap|Beethoven|Trader\s*Joe)",
    re.IGNORECASE,
)

# Cross-chain bridges
BRIDGE_RE = re.compile(
    r"\b(deBridge|Stargate|cBridge|LayerZero|Wormhole|Across|Squid|"
    r"Multichain|Synapse|Hop|Connext|Symbiosis|XY\s*Finance|Rubic|"
    r"Bridgers|Allbridge|Celer|Polyhedra|Orbiter|Bridge)\b",
    re.IGNORECASE,
)

# Market maker / arb desk (well-known firms)
MARKET_MAKER_RE = re.compile(
    r"\b(Wintermute|Jump|Cumberland|GSR|Amber|Genesis|B2C2|"
    r"Flow\s*Traders|XBTO|Galaxy\s*Digital)\b",
    re.IGNORECASE,
)


def classify_label(label: str | None,
                   entity_name: str | None,
                   entity_type: str | None) -> str:
    """Classify an Arkham label into a coarse category.

    `entity_type` (Arkham's structured field) wins over text-pattern
    matching when available — it's high-confidence categorical data.
    Falls back to label text and entity_name regex matching.
    """
    # Structured entity_type wins
    et = (entity_type or "").lower()
    if et == "cex":
        # Distinguish deposit vs hot via label text
        if label and CEX_DEPOSIT_RE.search(label):
            return "CEX_DEPOSIT"
        return "CEX_HOT_WALLET"
    if et == "dex":
        return "DEX_POOL"
    if et == "bridge":
        return "BRIDGE"
    if et in ("market_maker", "mm"):
        return "MARKET_MAKER"

    # Text-pattern fallback. Match against the entity_name AND the label, each on
    # its own (preserves intra-field adjacency, e.g. "Binance Wallet", without
    # creating false cross-field adjacency). Previously only `label` was checked, so
    # e.g. label "Proxy (EIP-1967 Transparent)" + entity "Binance Wallet" fell to
    # OTHER_NAMED — the "Binance Wallet" CEX signal was ignored — and the address was
    # then mistaken for an operator wallet. entity_name is checked first as the more
    # authoritative field.
    for text in (entity_name, label):
        if not text:
            continue
        if CEX_DEPOSIT_RE.search(text):
            return "CEX_DEPOSIT"
        if CEX_HOT_RE.search(text):
            return "CEX_HOT_WALLET"
        # self-identifying DEX terms (V2/V3 Pool, concentrated liquidity) need no
        # protocol-name prefix; a bare Pool/Vault/Router still requires a known
        # protocol to avoid sweeping in staking/mining pools.
        if DEX_STRONG_RE.search(text):
            return "DEX_POOL"
        if DEX_POOL_RE.search(text) and DEX_PROTOCOL_NAMES.match(entity_name or label or ""):
            return "DEX_POOL"
        if BRIDGE_RE.search(text):
            return "BRIDGE"
        if MARKET_MAKER_RE.search(text):
            return "MARKET_MAKER"

    if label or entity_name:
        return "OTHER_NAMED"
    return "UNLABELED"


def neutral_infra_kind(label: str | None,
                       entity_name: str | None = None,
                       entity_type: str | None = None) -> str | None:
    """Return 'cex' / 'dex' when (label, entity) identifies NEUTRAL infra — an
    exchange-custody / listing-channel wallet or a DEX liquidity pool — that is NOT
    a project insider, else None. Built on `classify_label`, so the CEX match
    requires brand+type adjacency (a bare brand mention does not qualify) — keeping
    listing / liquidity wallets out of the insider / operator sets without hiding a
    genuine insider whose label merely contains an exchange name. Deliberately does
    NOT treat vesting / multisig / treasury as neutral: those are project-controlled
    locked funds (operator-side), not neutral infra."""
    cls = classify_label(label, entity_name, entity_type)
    if cls in ("CEX_HOT_WALLET", "CEX_DEPOSIT"):
        return "cex"
    if cls == "DEX_POOL":
        return "dex"
    return None


# Classifications that should be removed from cross-sym whale candidates.
# DEX_POOL is in the list because cross-sym detection looks for OPERATOR
# wallets, and DEX pools are not operators — they're shared infrastructure.
# MARKET_MAKER stays out of the exclusion set: a well-known MM holding
# top positions across Alpha tokens is genuine signal (it IS a real
# operator class).
EXCLUDE_FROM_CROSS_SYM = frozenset({
    "CEX_DEPOSIT",
    "CEX_HOT_WALLET",
    "DEX_POOL",
    "BRIDGE",
})


class SurfLabelsError(Exception):
    """Raised on surf labels-batch infrastructure failure. Caller should
    catch and degrade gracefully (probe is enrichment, not gate)."""


def resolve_labels(addrs: Iterable[str], verbose: bool = False) -> dict[str, dict]:
    """Query `surf wallet-labels-batch` for the given addresses.

    Returns {addr_lower: {label, entity_name, entity_type, classification,
    confidence}}. UNLABELED entries are still returned (with classification
    UNLABELED) so callers can distinguish "queried, not labeled" from
    "not queried".

    Cost: 1 surf credit per batch, regardless of batch size (per surf
    docs, batch size limit is 100 addresses).
    """
    # v0.7.21.7: chain-aware normalization. EVM lowercases for label-key match;
    # Solana base58 preserved as-is (case-sensitive). Invalid addrs dropped.
    addrs_l = [_norm_addr(a or "") for a in addrs]
    addrs_l = [a for a in addrs_l if _addr_ok(a)]
    if not addrs_l:
        return {}

    out: dict[str, dict] = {}
    # Initialize all queried addrs to UNLABELED so caller knows what was
    # asked. Surf only returns rows for addresses that have data.
    for a in addrs_l:
        out[a] = {
            "label": None,
            "entity_name": None,
            "entity_type": None,
            "classification": "UNLABELED",
            "confidence": 0.0,
        }

    # v1.0.6 (ARX 2026-06-23): CHUNK at 20 + retry-with-backoff per chunk.
    # Two real failures this fixes:
    #   1. Large batch → surf returns INTERNAL_ERROR ("internal server error").
    #      An ARX 42-address consolidated batch failed EVERY retry because the
    #      error is the batch SIZE, not a transient hiccup — surf empirically
    #      drops above ~25 addrs (protocol_lockup_detector already chunks at 20).
    #      Previously this module sent the whole list in ONE call, so any token
    #      with >25 label candidates got ZERO labels → CEX / DEX-infra never
    #      separated → operator chip wildly wrong (ARX swung 10%/43%/98% between
    #      runs purely on label-fetch luck).
    #   2. Transient exit-4 / 429 / timeout on an individual chunk → retried via
    #      the same backoff helper onchain-sql uses.
    # Per-chunk SOFT failure: a failed chunk leaves its addrs UNLABELED but does
    # NOT sink the others. Raise only if EVERY chunk failed (callers fail-open).
    from section_a_scope import _run_surf_with_retry
    CHUNK = 20
    n_ok = 0
    n_fail = 0
    for i in range(0, len(addrs_l), CHUNK):
        chunk = addrs_l[i:i + CHUNK]
        cmd = ["surf", "wallet-labels-batch", "--addresses", ",".join(chunk)]
        doc, err = _run_surf_with_retry(
            cmd, base_timeout=SURF_TIMEOUT_SECS, max_attempts=4
        )
        if doc is None or doc.get("error"):
            n_fail += 1
            continue
        n_ok += 1
        for row in doc.get("data") or []:
            addr = _norm_addr(row.get("address") or "")
            if not addr or addr not in out:
                continue
            labels_list = row.get("labels") or []
            # Use top-confidence label
            top_label = max(labels_list, key=lambda x: x.get("confidence", 0)) if labels_list else {}
            label_text = top_label.get("label")
            confidence = float(top_label.get("confidence") or 0)
            entity_name = row.get("entity_name")
            entity_type = row.get("entity_type")
            cls = classify_label(label_text, entity_name, entity_type)
            out[addr] = {
                "label": label_text,
                "entity_name": entity_name,
                "entity_type": entity_type,
                "classification": cls,
                "confidence": confidence,
            }

    if n_ok == 0 and n_fail > 0:
        raise SurfLabelsError(
            f"surf wallet-labels-batch: all {n_fail} chunk(s) failed"
        )

    if verbose:
        from collections import Counter
        c = Counter(r["classification"] for r in out.values())
        print(
            f"[surf_labels_probe] {len(out)} addresses → {dict(c)}",
            file=sys.stderr,
        )
    return out


def find_excluded(addrs: Iterable[str], verbose: bool = False) -> set[str]:
    """Subset of `addrs` whose Arkham label classifies as
    CEX/DEX/Bridge infrastructure. Fail-OPEN on probe error."""
    try:
        labels = resolve_labels(addrs, verbose=verbose)
    except SurfLabelsError as e:
        if verbose:
            print(
                f"[surf_labels_probe] degrading gracefully: {e}",
                file=sys.stderr,
            )
        return set()
    return {
        a for a, r in labels.items()
        if r["classification"] in EXCLUDE_FROM_CROSS_SYM
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("addresses", nargs="+")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    labels = resolve_labels(args.addresses, verbose=args.verbose)
    for addr, rec in labels.items():
        print(
            f"{addr}\t{rec['classification']}\t"
            f"label={rec['label']}\tentity={rec['entity_name']}/{rec['entity_type']}\t"
            f"conf={rec['confidence']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
