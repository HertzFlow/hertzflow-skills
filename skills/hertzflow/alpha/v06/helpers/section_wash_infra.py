#!/usr/bin/env python3
"""section_wash_infra.py — v0.7.7 wash infrastructure section runner.

Runs `wash_infra_detector.detect_all` against a pre-narrowed candidate
set drawn from the current token's top-100 holders UNION the top-N
high-tx-count wallets (since wash-route executor addresses typically
don't hold top-100 balance — they just route). Emits the
`wash_infrastructure` skeleton section:

  {
    "wash_infrastructure": {
      "_pipeline_source": "section_wash_infra",
      "setups": [
        {
          # ALL locked (pipeline-derived from SQL, LLM cannot touch):
          "executor_X": str,
          "maker_buy_P": str,
          "maker_sell_Q": str,
          "atomic_pair_ratio": float,
          "p_drift_pct": float,
          "q_drift_pct": float,
          "p_tok_in": float,
          "q_tok_in": float,
          "tx_from_diversity": float,
          "classification": str,  # wash_infrastructure_{routed|operator_controlled|ambiguous}

          # writable (LLM fills, validator gates):
          "investigation_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        ...
      ],
      "summary_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
      "_credits_used": int,
      "_n_candidates_scanned": int,
    }
  }

Candidate-narrowing strategy:
  - top-100 holders (already fetched by section_cross_sym /
    section_f_holders).
  - PLUS top-N (default 50) high-tx-count wallets queried from
    bsc_transfers via 1 extra SQL. Catches pure-route executors
    (e.g. Binance Alpha 2.0 "Taker" addresses that wash through
    without accumulating balance — these never appear in top-100
    holders but are the prime executor candidates).
  - Drop addresses known to be CEX hot wallets, DEX pools, deployer.
  - Anything else with >=500 transfers AND atomic-pair ratio >=0.85
    survives. Most addresses fail at Step 0 (1 SQL) cheaply.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from chain_router import (  # v0.7.20 / v0.7.21.7
    transfers_table,
    dex_trades_table,
    is_valid_addr as _chain_is_valid_addr,
    get_active_chain as _chain_get_active,
)

sys.path.insert(0, str(Path(__file__).parent))

_SURF_TIMEOUT_SECS = 30
_ADDR_RE = re.compile(r"0x[0-9a-f]{40}")  # kept for legacy diagnostics
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _addr_ok(a) -> bool:
    """v0.7.21.7: chain-aware address validation.

    EVM lowercase; Solana base58 case-sensitive — delegated to chain_router.
    """
    if not isinstance(a, str) or not a:
        return False
    if _chain_get_active() == "solana":
        return _chain_is_valid_addr(a)
    return _chain_is_valid_addr(a.lower())


def _norm_addr(a: str) -> str:
    """Normalize for the active chain: lowercase EVM, preserve Solana case."""
    return a if _chain_get_active() == "solana" else a.lower()


PLACEHOLDER = "<LLM_NARRATIVE_PLACEHOLDER>"

# How many balanced both-side-active wallets to pull as additional
# candidates. 200 was chosen after H validation found that the real
# wash executor (0xa054, "Taker") sits at rank #155 on the balanced
# leaderboard — top-50 misses it entirely. Cost is bounded by the
# detector Step 0 (1 SQL/candidate) failing fast on non-wash addresses,
# total per-token max ~ $1-2 in the worst case. Top-50 was the
# original choice but was empirically insufficient.
_HIGH_TX_TOPN = 200


def _fetch_high_tx_candidates(
    ca: str,
    listing_date: str,
    top_n: int,
    verbose: bool = False,
) -> tuple[list[str], int]:
    """Pull top-N addresses by tx count on this CA since listing_date.

    1 surf SQL. Returns (addresses, credits_used). The credits are
    accounted separately so section_wash_infra.run() can roll them into
    its `_credits_used` total — without this the fetcher's SQL is
    silently free in the user-visible cost report.

    Inputs are pre-validated by caller (fullmatch regex) before they reach
    f-string interpolation, but we re-fullmatch here as a defense-in-depth.
    """
    if not _addr_ok(ca):
        if verbose:
            print(f"[section_wash_infra] _fetch_high_tx_candidates: bad ca", file=sys.stderr)
        return [], 0
    if not _DATE_RE.fullmatch(listing_date):
        if verbose:
            print(f"[section_wash_infra] _fetch_high_tx_candidates: bad date", file=sys.stderr)
        return [], 0
    # Cross-LLM audit LOW #3 fix: clamp top_n. Caller currently passes a
    # constant (_HIGH_TX_TOPN=50) so this is defensive; if a future caller
    # ever forwards user input, the clamp closes the LIMIT-injection door.
    top_n = max(1, min(int(top_n), 500))

    # v0.7.7 candidate strategy: pre-aggregate each leg (`from` and
    # `to` independently), INNER JOIN on address, then filter to
    # addresses that BOTH send AND receive ≥ MIN_LEG. This biases the
    # candidate set toward the actual wash signature (sends ≈ recvs)
    # and away from one-sided DEX pools / MM hot wallets that dominate
    # raw total-tx leaderboards. Empirical H validation: pure-route
    # 0xa054 with sends=2801/recvs=2801 was rank ~200 on raw total tx
    # (dominated by 0xef7d88 PancakeSwap V3 Pool etc.) but rank #1 on
    # the symmetric leaderboard. Without this fix the top-50 high-tx
    # source would never surface wash executors.
    #
    # Cross-LLM audit MEDIUM #1 covered: pre-aggregating per leg
    # bounds the intermediate to ~`N_distinct_from + N_distinct_to`
    # rows (chain-reality bounded), not the full tx slice.
    # Per-leg threshold of 250 ensures any returned candidate also
    # passes the detector's Step 0 entry filter (sends + recvs > 500),
    # avoiding the wasted 1-SQL-per-candidate cost of pulling addresses
    # that the detector immediately rejects.
    MIN_LEG_TX = 250
    sql = (
        "SELECT s.addr AS addr, s.n AS sends, r.n AS recvs, (s.n + r.n) AS total_tx "
        "FROM ("
        f"  SELECT `from` AS addr, count(*) AS n "
        f"  FROM {transfers_table()} "
        f"  WHERE contract_address = '{ca}' AND block_date >= '{listing_date}' "
        f"  GROUP BY `from`"
        ") s "
        "INNER JOIN ("
        f"  SELECT `to` AS addr, count(*) AS n "
        f"  FROM {transfers_table()} "
        f"  WHERE contract_address = '{ca}' AND block_date >= '{listing_date}' "
        f"  GROUP BY `to`"
        ") r ON s.addr = r.addr "
        f"WHERE s.n >= {MIN_LEG_TX} AND r.n >= {MIN_LEG_TX} "
        f"ORDER BY total_tx DESC LIMIT {top_n}"
    )
    body = json.dumps({"sql": sql, "max_rows": top_n})
    try:
        proc = subprocess.run(
            ["surf", "onchain-sql"],
            input=body, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=_SURF_TIMEOUT_SECS, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        if verbose:
            print(f"[section_wash_infra] high-tx surf failed: {e}", file=sys.stderr)
        return [], 0
    if proc.returncode != 0:
        if verbose:
            print(
                f"[section_wash_infra] high-tx surf exit {proc.returncode}: "
                f"{proc.stderr[:200]}",
                file=sys.stderr,
            )
        return [], 0
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], 0
    if doc.get("error"):
        if verbose:
            print(f"[section_wash_infra] high-tx surf API error: {doc['error']}", file=sys.stderr)
        return [], 0
    credits = int((doc.get("meta") or {}).get("credits_used") or 1)
    out = []
    for row in doc.get("data") or []:
        a_raw = row.get("addr") or ""
        a = _norm_addr(a_raw)
        if _addr_ok(a):
            out.append(a)
    return out, credits


def run(
    ca: str,
    top_holders: list[dict],
    excluded_addrs: set[str],
    *,
    listing_date: str | None = None,
    skip: bool = False,
    verbose: bool = False,
) -> dict:
    """Run the wash-infrastructure section for one CA.

    Args:
        ca: current contract address (lowercase 0x)
        top_holders: list of holder dicts from surf token-holders (must have
            `address` field; other fields ignored). Top-100 is sufficient.
        excluded_addrs: addresses already known to be benign infrastructure
            (CEX hot wallets, DEX pools, deployer, BscScan-labeled DEX
            routers, etc.). These are dropped from the candidate set
            BEFORE the SQL pipeline runs.
        listing_date: token TGE date (YYYY-MM-DD). Used to scope SQL.
        skip: if True, returns an empty section.
        verbose: print diagnostic to stderr.
    """
    if skip:
        if verbose:
            print("[section_wash_infra] skipped (skip=True)", file=sys.stderr)
        return _empty_section(reason="skipped_by_user")

    # v0.7.21.7: chain-aware case. EVM lowercase, Solana preserves base58.
    ca_lower = _norm_addr(ca or "")
    excluded_norm = {_norm_addr(x) for x in (excluded_addrs or set()) if x}

    # Source 1: top-100 holders (passes balance-based candidate set).
    holder_addrs: list[str] = []
    seen: set[str] = set()
    for h in top_holders:
        a_raw = h.get("address") or h.get("addr") or ""
        a = _norm_addr(a_raw)
        if not a or a in excluded_norm or a in seen:
            continue
        seen.add(a)
        holder_addrs.append(a)

    # Source 2: top-50 high-tx-count wallets. Catches pure-route
    # executors (e.g. Binance Alpha 2.0 wash routes that don't hold
    # top-100 balance — they just route token through). 1 extra SQL.
    high_tx_addrs: list[str] = []
    high_tx_credits = 0
    if listing_date:
        fetched, high_tx_credits = _fetch_high_tx_candidates(
            ca=ca_lower,
            listing_date=listing_date,
            top_n=_HIGH_TX_TOPN,
            verbose=verbose,
        )
        for a in fetched:
            if not a or a in excluded_norm or a in seen:
                continue
            seen.add(a)
            high_tx_addrs.append(a)
        if verbose:
            print(
                f"[section_wash_infra] candidate sources: "
                f"top-100 holders={len(holder_addrs)}, "
                f"high-tx fetched={len(fetched)} → kept {len(high_tx_addrs)} "
                f"(after dedupe + excluded), credits={high_tx_credits}",
                file=sys.stderr,
            )

    candidates = holder_addrs + high_tx_addrs

    if not candidates:
        if verbose:
            print(
                f"[section_wash_infra] 0 candidates after excluded filter "
                f"(top_holders={len(top_holders)}, excluded={len(excluded_addrs)})",
                file=sys.stderr,
            )
        return _empty_section(
            reason="no_candidates",
            n_scanned=0,
        )

    detector_meta: dict = {}
    try:
        from wash_infra_detector import detect_all, WashInfraError
        setups, detector_credits, detector_meta = detect_all(
            ca=ca_lower,
            candidate_addrs=candidates,
            listing_date=listing_date,
        )
    except WashInfraError as e:
        if verbose:
            print(f"[section_wash_infra] detector error: {e}", file=sys.stderr)
        return _empty_section(reason=f"detector_error: {e}",
                              n_scanned=len(candidates),
                              credits_used=high_tx_credits)
    except Exception as e:
        if verbose:
            print(f"[section_wash_infra] unexpected error: {e}", file=sys.stderr)
        return _empty_section(reason=f"unexpected_error: {type(e).__name__}",
                              n_scanned=len(candidates),
                              credits_used=high_tx_credits)
    credits_used = high_tx_credits + detector_credits

    # Attach writable narrative slot per setup, plus the section-level slot.
    enriched_setups = []
    for s in setups:
        s["investigation_narrative"] = PLACEHOLDER
        enriched_setups.append(s)

    if verbose:
        print(
            f"[section_wash_infra] {len(candidates)} candidates scanned, "
            f"{len(enriched_setups)} wash setups found, credits={credits_used}",
            file=sys.stderr,
        )

    # v0.7.19: ALWAYS emit `_truncated` (was only emitted on truncation in
    # v0.7.17, which made the render template's `{% if wash_infrastructure.
    # _truncated %}` access trip Jinja StrictUndefined when the scan
    # finished cleanly. Downstream LLM fill callers also had to manually
    # patch the key in to render — see feedback-no-subagent-for-fill.md
    # and COLLECT v0.7.18 sub-agent retry).
    truncated = bool(detector_meta.get("truncated"))
    out = {
        "_pipeline_source": "section_wash_infra",
        "setups": enriched_setups,
        "summary_narrative": PLACEHOLDER,
        "_credits_used": credits_used,
        "_n_candidates_scanned": len(candidates),
        "_truncated": truncated,
        "_truncation_meta": {
            "n_candidates_processed": detector_meta.get("n_candidates_processed"),
            "n_candidates_total": detector_meta.get("n_candidates_total"),
            "wall_clock_seconds_used": detector_meta.get("wall_clock_seconds_used"),
            "wall_clock_budget_seconds": detector_meta.get("wall_clock_budget_seconds"),
            # v0.7.23 follow-up: surface Step 0 batch-SQL surf failure as
            # a distinct marker so the render layer can warn "wash scan
            # never started" instead of either truncation or 0-hit.
            "step0_surf_failed": detector_meta.get("step0_surf_failed", False),
        } if truncated else None,
    }
    return out


def _empty_section(*, reason: str, n_scanned: int = 0, credits_used: int = 0) -> dict:
    return {
        "_pipeline_source": "section_wash_infra",
        "setups": [],
        "summary_narrative": PLACEHOLDER,
        "_credits_used": credits_used,
        "_n_candidates_scanned": n_scanned,
        "_skip_reason": reason,
    }
