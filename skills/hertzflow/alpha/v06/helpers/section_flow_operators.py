#!/usr/bin/env python3
"""section_flow_operators.py — v0.7.21 wrapper around flow_operator_detector.

Builds the candidate union (wash_infra candidates + dump_tracker top
sellers), feeds it into the detector, and shapes the output into the
skeleton schema documented in `v06/v0721_DESIGN.md`.

This section is intentionally thin — the detector does the SQL work,
this file just glues inputs and shapes the output dict.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))


_ALPHA_LIST_URL = (
    "https://www.binance.com/bapi/defi/v1/public/wallet-direct/"
    "buw/wallet/cex/alpha/all/token/list"
)

# Chain IDs we have surf SQL coverage on (mirrors chain_router supported set).
_EVM_CHAIN_IDS = {1, 10, 56, 137, 8453, 42161}


def fetch_alpha_token_meta(
    *, timeout_seconds: int = 10,
) -> dict[int, dict[str, str]]:
    """Return {chain_id: {ca_lower: symbol}} for every Alpha-listed token.

    v0.7.21.2: superset of v0.7.21's fetch_alpha_token_cas. The detector
    now needs the per-token symbol so the report can name *which*
    cross-Alpha tokens an operator runs on, not just the count.

    One curl, parsed locally. ~1 second, 0 surf credits.

    Returns {} on any failure; the detector treats the empty mapping as
    "skip the Alpha-scoped cross-token annotation" rather than failing.
    """
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout_seconds), _ALPHA_LIST_URL],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout_seconds + 2, check=False,
        )
        if proc.returncode != 0:
            return {}
        raw = json.loads(proc.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return {}
    rows = raw
    for _ in range(4):
        if isinstance(rows, list):
            break
        if isinstance(rows, dict):
            for key in ("data", "rows", "list"):
                if key in rows:
                    rows = rows[key]
                    break
            else:
                return {}
    if not isinstance(rows, list):
        return {}
    addr_re = re.compile(r"^0x[0-9a-f]{40}$")
    out: dict[int, dict[str, str]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        ca = (r.get("contractAddress") or "").lower()
        if not addr_re.fullmatch(ca):
            continue
        try:
            cid = int(r.get("chainId"))
        except (TypeError, ValueError):
            continue
        if cid not in _EVM_CHAIN_IDS:
            continue
        sym = (r.get("symbol") or "").upper() or "?"
        out.setdefault(cid, {})[ca] = sym
    return out


def fetch_alpha_token_cas(
    *, timeout_seconds: int = 10,
) -> dict[int, set[str]]:
    """Back-compat wrapper around fetch_alpha_token_meta — returns just the
    CA sets without symbol mapping. Kept so forensic_pipeline's existing
    import keeps working before v0.7.21.2 wiring lands.
    """
    meta = fetch_alpha_token_meta(timeout_seconds=timeout_seconds)
    return {cid: set(ca_to_sym.keys()) for cid, ca_to_sym in meta.items()}


def run(
    *,
    ca: str,
    listing_date: str | None,
    total_supply: int | None,
    wash_infra_candidates: list[str] | None = None,
    dump_top_sellers: list[str] | None = None,
    alpha_token_cas_base: set[str] | None = None,
    alpha_token_cas_bsc: set[str] | None = None,
    alpha_ca_to_sym_base: dict[str, str] | None = None,
    alpha_ca_to_sym_bsc: dict[str, str] | None = None,
    excluded_addrs: set[str] | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Section FLOW-OPERATORS entrypoint.

    Args:
        ca: subject contract address.
        listing_date: YYYY-MM-DD listing date (Alpha API).
        total_supply: subject token total supply (used by detector for
            MAX_NET_BALANCE_PCT filter).
        wash_infra_candidates: candidates already collected by
            section_wash_infra (top-100 holders + top-200 balanced +
            top-50 high-tx). Reused so we don't refetch.
        dump_top_sellers: top-200 DEX seller tx_from addresses surfaced
            by dump_tracker v0.7.21. Reused so we don't refetch.
        alpha_token_cas_base / alpha_token_cas_bsc: Alpha API CA sets
            per chain for cross-Alpha intersection (only the active
            chain set is queried — the other chain set is unused
            today, kept in the signature for future v0.7.22 cross-chain
            registry merge).
        excluded_addrs: addresses to drop from the candidate pool —
            same excluded set as cross_sym (m6 rows, op-relay, burn
            addresses, etc).

    Returns:
        Skeleton block dict (see v0721_DESIGN.md §Output schema).
        Always returns a well-formed dict; on detector failure the
        operators list is empty and `_error` is set.
    """
    if not listing_date:
        return _empty(reason="missing_listing_date")

    # Union of all candidate sources; excluded set drops m6 / burn / etc.
    excluded = {(a or "").lower() for a in (excluded_addrs or set())}
    seen: set[str] = set()
    union: list[str] = []
    for src in (wash_infra_candidates or [], dump_top_sellers or []):
        for a in src:
            a = (a or "").lower()
            if not a or a in excluded or a in seen:
                continue
            seen.add(a)
            union.append(a)

    if not union:
        return _empty(reason="no_candidates")

    if verbose:
        print(
            f"[section_flow_operators] candidate sources: "
            f"wash_infra={len(wash_infra_candidates or [])}, "
            f"dump_sellers={len(dump_top_sellers or [])}, "
            f"union after excluded={len(union)}",
            file=sys.stderr,
        )

    try:
        from flow_operator_detector import detect, FlowOperatorError
        operators, credits = detect(
            ca=ca,
            candidate_addrs=union,
            listing_date=listing_date,
            total_supply=total_supply,
            alpha_token_cas_base=alpha_token_cas_base,
            alpha_token_cas_bsc=alpha_token_cas_bsc,
            alpha_ca_to_sym_base=alpha_ca_to_sym_base,
            alpha_ca_to_sym_bsc=alpha_ca_to_sym_bsc,
        )
    except FlowOperatorError as e:
        if verbose:
            print(f"[section_flow_operators] detector input error: {e}",
                  file=sys.stderr)
        return _empty(reason=f"input_error: {e}", n_scanned=len(union))
    except Exception as e:
        if verbose:
            print(f"[section_flow_operators] unexpected error: {type(e).__name__}: {e}",
                  file=sys.stderr)
        return _empty(reason=f"unexpected_error: {type(e).__name__}",
                      n_scanned=len(union))

    if verbose:
        print(
            f"[section_flow_operators] {len(operators)} operators detected "
            f"from {len(union)} candidates (credits={credits})",
            file=sys.stderr,
        )

    return {
        "_pipeline_source": "section_flow_operators",
        "_n_candidates_scanned": len(union),
        "_credits_used": credits,
        "_status": "ok",
        "operators": operators,
        "summary_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
    }


def _empty(*, reason: str, n_scanned: int = 0,
           credits_used: int = 0) -> dict[str, Any]:
    return {
        "_pipeline_source": "section_flow_operators",
        "_n_candidates_scanned": n_scanned,
        "_credits_used": credits_used,
        "_status": "empty",
        "_reason": reason,
        "operators": [],
        "summary_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
    }
