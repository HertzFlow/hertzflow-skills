#!/usr/bin/env python3
"""identity_classifier.py — Deterministic identity classification for
cross-sym whale candidates.

v0.7 core. Given a candidate (address + cross_sym_tokens), this module:
  1. Runs ONE unified `surf onchain-sql` to fetch the candidate's last
     90 days of transfers across all cross_sym tokens
  2. Aggregates into an 11-dimensional behavior SIGNATURE (locked, Python-derived)
  3. Applies a STATIC ordered decision tree to classify identity (5 enums)
  4. Returns (signature, classification) — both fully locked, NO LLM input

The LLM only writes `identity_narrative` (explaining WHY this classification)
and `risk_assessment_narrative` — validator enforces those narratives
cite at least 2 of the locked signature fields.

5 identity enums (ordered evaluation, first hit wins):

  KOL_MANAGER                  — cross_sym ≥3 + pre_launch_insider ≥2
  ACTIVE_MM                    — bidirectional LP flow + high tx freq
  ARB_DESK                     — high CEX-side flow + short hold
  OTC_DESK                     — single large inflow + low freq
  UNKNOWN_WHALE_HIGH_CROSS_SYM — cross_sym ≥5 but no signature hit
  INSUFFICIENT_SIGNAL          — fallback

Design constraints:
  - 1 surf onchain-sql per candidate (not 5) → cost control
  - 90-day window (partition-narrow → no SQL timeout)
  - All thresholds are MODULE CONSTANTS (auditable, not magic numbers)
  - LLM cannot freelance identity — validator gates narrative
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any
from chain_router import transfers_table, dex_trades_table  # v0.7.20

# ----- Module constants -----

DEFAULT_WINDOW_DAYS = 30   # v0.7 acceptance fix: 90d query timed out on
                            # busy cross-sym whales. 30d still covers ARB
                            # (<7d hold) + most ACTIVE_MM cases; KOL_MANAGER
                            # detection doesn't depend on signature window.
SURF_SQL_TIMEOUT_SECS = 35

# Classification thresholds (auditable, not magic in branches)
KOL_MIN_CROSS_SYM = 3
KOL_MIN_PRE_LAUNCH_INSIDER = 2

MM_MIN_BIDIR_LP_RATIO = 0.40
MM_MIN_TX_COUNT_90D = 20   # v0.7 acceptance: scaled from 60→20 since
                            # default window dropped 90d→30d. ~3 tx/day
                            # remains the MM heuristic intent.

ARB_MIN_CEX_FLOW_TOTAL = 0.80   # inflow_from_cex + outflow_to_cex > 0.80
ARB_MAX_AVG_HOLD_DAYS = 7.0

OTC_MIN_LARGEST_INFLOW_PCT = 0.60
OTC_MAX_TX_COUNT_90D = 10

UNKNOWN_MIN_CROSS_SYM = 5


# ----- Public API -----

def compute_signature(
    addr: str,
    cross_sym_cas: list[str],
    *,
    cex_hot_addrs: set[str],
    dex_pool_addrs: set[str],
    deployer_addrs: set[str],
    insider_addrs: set[str],
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> dict[str, Any]:
    """Compute the 11-dim behavior signature for `addr` by running ONE
    unified surf onchain-sql across the candidate's cross_sym tokens.

    Args:
        addr: candidate address (lowercase 0x)
        cross_sym_cas: list of contract addresses to query transfers for
        cex_hot_addrs: set of known CEX hot wallet addrs (for counterparty tagging)
        dex_pool_addrs: set of known DEX main pool addrs
        deployer_addrs: set of known token deployer addrs
        insider_addrs: set of known pre-launch insider receiver addrs
            (from pre_launch_insider_index)
        window_days: lookback window (default 90d)

    Returns:
        {
            "addr": str,
            "n_cas_queried": int,
            "window_days": int,
            "tx_count_90d": int,
            "total_inflow_amount": float,
            "total_outflow_amount": float,
            "inflow_from_cex_pct": float,         # 0.0-1.0
            "inflow_from_dex_pct": float,
            "inflow_from_deployer_pct": float,
            "inflow_from_unlabeled_pct": float,
            "outflow_to_cex_pct": float,
            "outflow_to_dex_pct": float,
            "outflow_to_unlabeled_pct": float,
            "avg_hold_days": float,                # weighted by amount
            "single_largest_inflow_pct": float,
            "bidirectional_lp_flow_ratio": float,
            "_surf_credits_used": int,
        }

    Raises:
        ClassifierError on SQL or aggregation failure
    """
    if not cross_sym_cas:
        return _empty_signature(addr, window_days)
    # v0.7.21.7: chain-aware validation. EVM lowercases for SQL match; Solana
    # preserves base58 case (case-sensitive). _addr_ok delegates to chain_router.
    if not _addr_ok(addr):
        raise ClassifierError(f"invalid addr format: {addr!r}")

    _is_solana = _chain_get_active() == "solana"
    addr_norm = addr if _is_solana else addr.lower()
    cas_norm = list(cross_sym_cas) if _is_solana else [c.lower() for c in cross_sym_cas]
    for c in cas_norm:
        if not _addr_ok(c):
            raise ClassifierError(f"invalid ca in cross_sym_cas: {c!r}")

    rows, credits_used = _query_unified_transfers(addr_norm, cas_norm, window_days)
    sig = _aggregate_signature(
        addr_norm,
        rows,
        cas_norm,
        window_days,
        cex_hot_addrs={(a if _is_solana else a.lower()) for a in cex_hot_addrs},
        dex_pool_addrs={(a if _is_solana else a.lower()) for a in dex_pool_addrs},
        deployer_addrs={(a if _is_solana else a.lower()) for a in deployer_addrs},
        insider_addrs={(a if _is_solana else a.lower()) for a in insider_addrs},
    )
    sig["_surf_credits_used"] = credits_used
    return sig


def classify(
    signature: dict,
    *,
    cross_sym_count: int,
    pre_launch_insider_count: int,
) -> dict[str, Any]:
    """Apply the deterministic decision tree to (signature + context).

    Returns:
        {
            "identity_enum": str,
            "confidence": float (0-1),
            "evidence_required_fields": [str, ...]   # which locked fields
                                                      # the narrative MUST cite
        }

    NO LLM. Pure function of inputs. Same input → same output every time.
    """
    s = signature

    # Rule 1: KOL_MANAGER
    if (cross_sym_count >= KOL_MIN_CROSS_SYM
            and pre_launch_insider_count >= KOL_MIN_PRE_LAUNCH_INSIDER):
        return {
            "identity_enum": "KOL_MANAGER",
            "confidence": 0.90,
            "evidence_required_fields": [
                "cross_sym_count",
                "pre_launch_insider_count",
                "pre_launch_insider_tokens",
            ],
        }

    # Rule 2: ACTIVE_MM
    # adversarial review P2b audit fix: use >= so threshold = trigger (was strict >)
    if (s.get("bidirectional_lp_flow_ratio", 0) >= MM_MIN_BIDIR_LP_RATIO
            and s.get("tx_count_90d", 0) >= MM_MIN_TX_COUNT_90D):
        return {
            "identity_enum": "ACTIVE_MM",
            "confidence": 0.85,
            "evidence_required_fields": [
                "bidirectional_lp_flow_ratio",
                "tx_count_90d",
                "outflow_to_dex_pct",
            ],
        }

    # Rule 3: ARB_DESK
    cex_total = s.get("inflow_from_cex_pct", 0) + s.get("outflow_to_cex_pct", 0)
    if (cex_total >= ARB_MIN_CEX_FLOW_TOTAL
            and 0 < s.get("avg_hold_days", 999) <= ARB_MAX_AVG_HOLD_DAYS):
        return {
            "identity_enum": "ARB_DESK",
            "confidence": 0.80,
            "evidence_required_fields": [
                "inflow_from_cex_pct",
                "outflow_to_cex_pct",
                "avg_hold_days",
            ],
        }

    # Rule 4: OTC_DESK
    if (s.get("single_largest_inflow_pct", 0) >= OTC_MIN_LARGEST_INFLOW_PCT
            and 0 < s.get("tx_count_90d", 999) <= OTC_MAX_TX_COUNT_90D):
        return {
            "identity_enum": "OTC_DESK",
            "confidence": 0.75,
            "evidence_required_fields": [
                "single_largest_inflow_pct",
                "tx_count_90d",
            ],
        }

    # Rule 5: UNKNOWN_WHALE_HIGH_CROSS_SYM
    # v0.7.1: was [cross_sym_count] (only 1 field) but validator requires
    # ≥2 evidence cites — narrative could never satisfy. Add this_token_pct
    # so narrative can cite both "cross-sym count" + "% in this token".
    if cross_sym_count >= UNKNOWN_MIN_CROSS_SYM:
        return {
            "identity_enum": "UNKNOWN_WHALE_HIGH_CROSS_SYM",
            "confidence": 0.50,
            "evidence_required_fields": [
                "cross_sym_count",
                "this_token_pct",
                "top_cross_sym_token",
            ],
        }

    # Fallback
    return {
        "identity_enum": "INSUFFICIENT_SIGNAL",
        "confidence": 0.0,
        "evidence_required_fields": [],
    }


# ----- Errors -----

class ClassifierError(Exception):
    """Raised when classification cannot be completed."""


# ----- Internals -----

def _empty_signature(addr: str, window_days: int) -> dict:
    return {
        "addr": addr.lower(),
        "n_cas_queried": 0,
        "window_days": window_days,
        "tx_count_90d": 0,
        "total_inflow_amount": 0.0,
        "total_outflow_amount": 0.0,
        "inflow_from_cex_pct": 0.0,
        "inflow_from_dex_pct": 0.0,
        "inflow_from_deployer_pct": 0.0,
        "inflow_from_unlabeled_pct": 0.0,
        "outflow_to_cex_pct": 0.0,
        "outflow_to_dex_pct": 0.0,
        "outflow_to_unlabeled_pct": 0.0,
        "avg_hold_days": 0.0,
        "single_largest_inflow_pct": 0.0,
        "bidirectional_lp_flow_ratio": 0.0,
        "_surf_credits_used": 0,
    }


# Validator: chain-aware address format check (extra defense for SQL injection).
# v0.7.21.7: delegated to chain_router so Solana base58 candidates pass through.
_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")  # back-compat constant

from chain_router import (  # noqa: E402
    is_valid_addr as _chain_is_valid_addr,
    get_active_chain as _chain_get_active,
)


def _addr_ok(addr) -> bool:
    if not isinstance(addr, str) or not addr:
        return False
    if _chain_get_active() == "solana":
        return _chain_is_valid_addr(addr)
    return _chain_is_valid_addr(addr.lower())


def _query_unified_transfers(addr: str, cas: list[str], window_days: int) -> tuple[list[dict], int]:
    """ONE surf onchain-sql call. Returns list of transfer dicts.

    Filters: addr is from OR to, contract is one of cas, block_date in last
    window_days. Narrow date partition keeps query under timeout.

    SQL injection defense: addr + cas validated by regex BEFORE format string,
    so no user input flows into the SQL beyond validated 0x[a-f0-9]{40}.
    """
    if not _addr_ok(addr):
        raise ClassifierError(f"addr failed sanitization: {addr!r}")
    for c in cas:
        if not _addr_ok(c):
            raise ClassifierError(f"ca failed sanitization: {c!r}")

    # Build IN list as quoted literals (validated above)
    cas_in = ",".join(f"'{c}'" for c in cas)
    # v0.7.21.7: chain-aware case handling. Solana addresses are case-sensitive
    # base58 — wrapping in lower() would produce no matches.
    # v0.7.23 (surf-team 2026-06-09 reply #1): on BSC the EVM SQL must NOT
    # call lower() on contract_address / from / to in the WHERE clause.
    # The table is sorted by contract_address and has projections on
    # from/to; lower() forces a full table scan. addr + cas have already
    # been validated by `_addr_ok` (the regex `^0x[a-f0-9]{40}$` requires
    # lowercase), so the literals are guaranteed lowercase already —
    # querying the raw columns is correct and uses the index.
    if _chain_get_active() == "solana":
        sql = (
            f"SELECT \"from\" AS from_addr, \"to\" AS to_addr, "
            f"contract_address AS ca, amount, block_time "
            f"FROM {transfers_table()} "
            f"WHERE (\"from\" = '{addr}' OR \"to\" = '{addr}') "
            f"AND contract_address IN ({cas_in}) "
            f"AND block_date >= today() - {int(window_days)} "
            f"ORDER BY block_time"
        )
    else:
        sql = (
            f"SELECT \"from\" AS from_addr, \"to\" AS to_addr, "
            f"contract_address AS ca, amount, block_time "
            f"FROM {transfers_table()} "
            f"WHERE (\"from\" = '{addr}' OR \"to\" = '{addr}') "
            f"AND contract_address IN ({cas_in}) "
            f"AND block_date >= today() - {int(window_days)} "
            f"ORDER BY block_time"
        )

    body = json.dumps({"sql": sql, "max_rows": 5000})
    try:
        result = subprocess.run(
            ["surf", "onchain-sql"],
            input=body,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=SURF_SQL_TIMEOUT_SECS,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        raise ClassifierError(f"surf onchain-sql call failed: {e}") from e

    if result.returncode != 0:
        raise ClassifierError(
            f"surf onchain-sql exit {result.returncode}: {result.stderr[:300]}"
        )

    try:
        doc = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ClassifierError(f"surf onchain-sql returned non-JSON: {e}") from e

    if doc.get("error"):
        raise ClassifierError(
            f"surf onchain-sql API error: {doc['error'].get('message')}"
        )

    # v0.7.2: capture surf credits used from response meta. Used by
    # section_cross_sym to aggregate total cost into report footer.
    credits = int((doc.get("meta") or {}).get("credits_used") or 0)
    return doc.get("data") or [], credits


def _aggregate_signature(
    addr: str,
    rows: list[dict],
    cas: list[str],
    window_days: int,
    *,
    cex_hot_addrs: set[str],
    dex_pool_addrs: set[str],
    deployer_addrs: set[str],
    insider_addrs: set[str],
) -> dict:
    """Aggregate transfer rows into the 11-dim signature.

    Sub-pipeline:
      1. Partition rows into inflow / outflow based on addr position
      2. Tag each counterparty as CEX / DEX / deployer / unlabeled
         (insider tag is reserved for downstream — KOL signal is at
         pre_launch_insider count level, not flow level)
      3. Compute aggregates
    """
    sig = _empty_signature(addr, window_days)
    sig["n_cas_queried"] = len(cas)

    if not rows:
        return sig

    inflow_total = 0.0
    outflow_total = 0.0
    inflow_by_class = {"cex": 0.0, "dex": 0.0, "deployer": 0.0, "unlabeled": 0.0}
    outflow_by_class = {"cex": 0.0, "dex": 0.0, "deployer": 0.0, "unlabeled": 0.0}
    inflow_amounts = []   # for largest-inflow %
    lp_inflow = 0.0       # for bidirectional LP ratio
    lp_outflow = 0.0
    # avg_hold_days definition (v0.7.0): simple first-inflow-to-first-outflow
    # global span. Not amount-weighted (adversarial review P2b audit clarified). This is
    # crude but bounded; matches the ARB_DESK heuristic "round-trip within
    # 7 days" sufficiently well. v0.7.1+ may refine to FIFO-matched holds.
    inflow_times = []   # list of (amount, block_time) for in
    outflow_times = []  # list of (amount, block_time) for out
    n_valid_tx = 0      # adversarial review P2b audit fix: count only rows we actually
                        # processed (not raw row count which includes malformed)

    for r in rows:
        from_a = (r.get("from_addr") or "").lower()
        to_a = (r.get("to_addr") or "").lower()
        try:
            amt = float(r.get("amount") or 0)
        except (ValueError, TypeError):
            continue
        bt = r.get("block_time")
        try:
            bt_int = int(bt) if bt else 0
        except (ValueError, TypeError):
            bt_int = 0

        if to_a == addr:
            # inbound to candidate
            n_valid_tx += 1
            inflow_total += amt
            inflow_amounts.append(amt)
            inflow_times.append((amt, bt_int))
            cls = _classify_counterparty(
                from_a, cex_hot_addrs, dex_pool_addrs, deployer_addrs
            )
            inflow_by_class[cls] += amt
            if cls == "dex":
                lp_inflow += amt
        elif from_a == addr:
            # outbound from candidate
            n_valid_tx += 1
            outflow_total += amt
            outflow_times.append((amt, bt_int))
            cls = _classify_counterparty(
                to_a, cex_hot_addrs, dex_pool_addrs, deployer_addrs
            )
            outflow_by_class[cls] += amt
            if cls == "dex":
                lp_outflow += amt

    sig["tx_count_90d"] = n_valid_tx
    sig["total_inflow_amount"] = inflow_total
    sig["total_outflow_amount"] = outflow_total

    if inflow_total > 0:
        for k in inflow_by_class:
            sig[f"inflow_from_{k}_pct"] = inflow_by_class[k] / inflow_total
    if outflow_total > 0:
        for k in outflow_by_class:
            sig[f"outflow_to_{k}_pct"] = outflow_by_class[k] / outflow_total

    if inflow_amounts and inflow_total > 0:
        sig["single_largest_inflow_pct"] = max(inflow_amounts) / inflow_total

    # Bidirectional LP ratio: min(LP_in, LP_out) / max(LP_in, LP_out)
    lp_max = max(lp_inflow, lp_outflow)
    if lp_max > 0:
        sig["bidirectional_lp_flow_ratio"] = min(lp_inflow, lp_outflow) / lp_max

    # Average hold days: amount-weighted span from first inflow to first outflow.
    # If no outflow at all → 0 (handled by branch).
    if inflow_times and outflow_times:
        first_in_ts = min(t for _, t in inflow_times if t > 0) if any(t > 0 for _, t in inflow_times) else 0
        first_out_ts = min(t for _, t in outflow_times if t > 0) if any(t > 0 for _, t in outflow_times) else 0
        if first_in_ts > 0 and first_out_ts > first_in_ts:
            sig["avg_hold_days"] = (first_out_ts - first_in_ts) / 86400.0

    return sig


def _classify_counterparty(
    addr: str,
    cex_hot: set[str],
    dex: set[str],
    deployer: set[str],
) -> str:
    """Single counterparty → class string ('cex' | 'dex' | 'deployer' | 'unlabeled')."""
    if addr in cex_hot:
        return "cex"
    if addr in dex:
        return "dex"
    if addr in deployer:
        return "deployer"
    return "unlabeled"


# ----- CLI for manual testing -----

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--addr", required=True)
    ap.add_argument("--cas", nargs="+", required=True, help="Cross-sym CAs to query")
    ap.add_argument("--cex-hot", nargs="*", default=[])
    ap.add_argument("--dex", nargs="*", default=[])
    ap.add_argument("--deployer", nargs="*", default=[])
    ap.add_argument("--insider", nargs="*", default=[])
    ap.add_argument("--cross-sym-count", type=int, default=0)
    ap.add_argument("--pre-launch-insider-count", type=int, default=0)
    ap.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    args = ap.parse_args()

    sig = compute_signature(
        args.addr,
        args.cas,
        cex_hot_addrs=set(args.cex_hot),
        dex_pool_addrs=set(args.dex),
        deployer_addrs=set(args.deployer),
        insider_addrs=set(args.insider),
        window_days=args.window_days,
    )
    cls = classify(
        sig,
        cross_sym_count=args.cross_sym_count,
        pre_launch_insider_count=args.pre_launch_insider_count,
    )
    print(json.dumps({"signature": sig, "classification": cls}, indent=2))
