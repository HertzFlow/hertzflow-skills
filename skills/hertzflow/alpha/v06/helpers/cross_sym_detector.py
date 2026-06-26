#!/usr/bin/env python3
"""cross_sym_detector.py — Forward-detection of cross-sym whale candidates.

v0.7 core logic. Given a fresh CA's top-100 holders + the universal
cross-sym registry, identifies wallets that are top-100 holders in ≥N
OTHER Alpha tokens. These are the candidates for downstream identity
classification (KOL_MANAGER / ACTIVE_MM / ARB_DESK / OTC_DESK / UNKNOWN_WHALE).

This module is PURE FUNCTIONAL — no I/O, no Surf calls. All inputs are
passed in (top_holders, excluded_addrs, registry). Section runner is
responsible for fetching those.

Filters applied (in order):
  1. Address excluded? (m6 / operator_relay / Arkham-labeled CEX/MM/bridge)
  2. Position size in current token < min_pct? (default 0.5%)
  3. Cross-sym count in OTHER tokens < min_cross_sym? (default 3)
  4. Rank-cap (top N candidates by cross_sym_count, default 5)

Why these defaults:
  - min_pct=0.5%: smaller positions are unlikely to be meaningful
    operators (would be retail-scale even with cross-sym pattern)
  - min_cross_sym=3: 1-2 hits could be coincidence (same wallet
    happens to hold 2 random Alpha tokens); 3+ is a strong portfolio
    signal
  - max=5: limits downstream identity-classification SQL cost per
    report (each candidate = 1 unified SQL)
"""

from __future__ import annotations

from typing import Any


# ----- Constants -----

DEFAULT_MIN_PCT = 0.5             # candidate must hold ≥0.5% of current CA's supply
DEFAULT_MIN_CROSS_SYM = 3         # appear in top-100 of ≥3 OTHER Alpha tokens
DEFAULT_MAX_CANDIDATES = 5        # cap downstream cost
DEFAULT_TOP_RANK_IN_OTHER = 100   # "top-100" in other tokens counts


# ----- Public API -----

def detect(
    ca: str,
    top_holders: list[dict],
    excluded_addrs: set[str],
    registry: dict[str, Any],
    *,
    min_pct: float = DEFAULT_MIN_PCT,
    min_cross_sym: int = DEFAULT_MIN_CROSS_SYM,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    top_rank_in_other: int = DEFAULT_TOP_RANK_IN_OTHER,
) -> list[dict]:
    """Detect cross-sym whale candidates for a fresh CA.

    Args:
        ca: current CA being analyzed (lowercase 0x address)
        top_holders: list of {address, balance, percentage, entity_name?, ...}
            from `surf token-holders`. Each holder is a dict.
        excluded_addrs: set of lowercase addresses to exclude from candidates
            (m6 receivers + operator_relay + Arkham-labeled).
        registry: output of cross_sym_registry.get_reverse_index().
            Must contain `reverse_index` dict.
        min_pct: minimum supply % in current CA (default 0.5%).
        min_cross_sym: minimum number of OTHER Alpha tokens the holder
            must appear in top-100 of (default 3).
        max_candidates: cap on returned candidates (default 5).
        top_rank_in_other: rank threshold within other tokens
            (default 100 = any top-100 appearance counts).

    Returns:
        Sorted list of candidate dicts, max length `max_candidates`.
        Each candidate is shaped:
        {
            "address": str (lowercase 0x),
            "this_token_pct": float,
            "this_token_balance": str (preserve precision),
            "cross_sym_count": int,
            "cross_sym_tokens": [
                {"sym": str, "ca": str, "pct": float, "rank": int}, ...
            ],
            "top_cross_sym_token": {"sym": str, "pct": float},  # by pct
            "arkham_label": str | None,  # always None at this stage
        }

        Sort key: cross_sym_count DESC, then top_cross_sym_pct DESC.
        Cap: max_candidates.
        Empty list if no qualifying candidates.
    """
    if not isinstance(registry, dict) or "reverse_index" not in registry:
        return []

    reverse_index = registry["reverse_index"]
    ca_lower = ca.lower()

    # v0.7 shape normalization: accept either surf token-holders shape
    # (`address`, `percentage`, `entity_name`) OR section_f_holders shape
    # (`addr`, `pct_of_total`, no entity). Internally use `address` + `percentage`.
    def _h_addr(h):
        return (h.get("address") or h.get("addr") or "").lower()
    def _h_pct(h):
        v = h.get("percentage") if h.get("percentage") is not None else h.get("pct_of_total")
        try:
            return float(v) if v is not None else 0
        except (ValueError, TypeError):
            return None   # signal malformed

    # adversarial review P2a audit fix: dedupe top_holders by address. Keep entry with
    # highest pct if duplicates appear. Defends against malformed input.
    holders_by_addr: dict[str, dict] = {}
    for holder in top_holders:
        addr = _h_addr(holder)
        if not addr:
            continue
        pct = _h_pct(holder)
        if pct is None:
            continue   # malformed pct, skip
        existing = holders_by_addr.get(addr)
        if existing is None or (_h_pct(existing) or 0) < pct:
            holders_by_addr[addr] = holder

    candidates: list[dict] = []

    for addr, holder in holders_by_addr.items():
        if addr in excluded_addrs:
            continue
        pct = _h_pct(holder)
        if pct is None or pct < min_pct:
            continue
        # Skip already-labeled entities (CEX hot, MM, bridge, etc.) — they're
        # not "whales" in the operator sense, they're infrastructure.
        # Only present in surf token-holders shape (entity_name field).
        if holder.get("entity_name"):
            continue

        # Cross-sym lookup with defensive type-coerce.
        # adversarial review P2a audit fix: rank/pct may be non-int from corrupt registry.
        appearances = reverse_index.get(addr, [])
        other_appearances = []
        seen_cas: set[str] = set()   # dedupe by ca (one entry per token)
        for a in appearances:
            ca_a = (a.get("ca") or "").lower()
            if not ca_a or ca_a == ca_lower:
                continue
            if ca_a in seen_cas:
                continue   # dedupe duplicate appearances of same ca
            try:
                rank_v = int(a.get("rank") or 9999)
            except (ValueError, TypeError):
                continue
            if rank_v > top_rank_in_other:
                continue
            try:
                pct_v = float(a.get("pct") or 0)
            except (ValueError, TypeError):
                pct_v = 0.0
            seen_cas.add(ca_a)
            other_appearances.append({"_obj": a, "ca": ca_a, "rank": rank_v, "pct": pct_v})

        if len(other_appearances) < min_cross_sym:
            continue

        # Build candidate entry (using coerced rank/pct values from above)
        top_cross_sym = max(other_appearances, key=lambda a: a["pct"])
        candidates.append({
            "address": addr,
            "this_token_pct": pct,
            "this_token_balance": str(holder.get("balance") or holder.get("total_in") or "0"),
            "cross_sym_count": len(other_appearances),
            "cross_sym_tokens": [
                {
                    "sym": a["_obj"].get("sym"),
                    "ca": a["ca"],
                    "pct": a["pct"],
                    "rank": a["rank"],
                }
                for a in other_appearances
            ],
            "top_cross_sym_token": {
                "sym": top_cross_sym["_obj"].get("sym"),
                "pct": top_cross_sym["pct"],
            },
            "arkham_label": None,  # entity_name filter already excluded labeled
        })

    # Sort: cross_sym_count DESC, then top_cross_sym pct DESC
    candidates.sort(
        key=lambda c: (c["cross_sym_count"], c["top_cross_sym_token"]["pct"]),
        reverse=True,
    )

    return candidates[:max_candidates]


# ----- CLI -----

if __name__ == "__main__":
    import argparse
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    import cross_sym_registry

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ca", required=True, help="Fresh CA to detect whales for")
    ap.add_argument("--top-holders-json", help="Path to a JSON file with top holders (output of surf token-holders --json)")
    ap.add_argument("--excluded", nargs="*", default=[], help="Addresses to exclude (m6, operator_relay, labeled)")
    ap.add_argument("--scope", default="active", choices=("active", "full", "top100"))
    ap.add_argument("--min-pct", type=float, default=DEFAULT_MIN_PCT)
    ap.add_argument("--min-cross-sym", type=int, default=DEFAULT_MIN_CROSS_SYM)
    ap.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if args.top_holders_json:
        holders_doc = json.loads(Path(args.top_holders_json).read_text(encoding="utf-8"))
        top_holders = holders_doc.get("data") if isinstance(holders_doc, dict) else holders_doc
    else:
        # Fetch fresh via surf
        # v0.7.20.1: route to active chain (was hardcoded bsc). This path
        # is the standalone CLI fallback; production pipeline calls
        # set_active_chain() before reaching here.
        from chain_router import get_active_chain
        import subprocess
        result = subprocess.run(
            ["surf", "token-holders", "--address", args.ca, "--chain", get_active_chain(),
             "--limit", "100", "--include", "labels", "--json"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        if result.returncode != 0:
            print(f"surf failed: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        top_holders = json.loads(result.stdout).get("data", [])

    registry = cross_sym_registry.get_reverse_index(
        scope=args.scope, verbose=args.verbose,
    )
    excluded = set(a.lower() for a in args.excluded)

    candidates = detect(
        args.ca, top_holders, excluded, registry,
        min_pct=args.min_pct,
        min_cross_sym=args.min_cross_sym,
        max_candidates=args.max_candidates,
    )

    print(json.dumps({
        "ca": args.ca,
        "n_candidates": len(candidates),
        "candidates": candidates,
    }, ensure_ascii=False, indent=2))
