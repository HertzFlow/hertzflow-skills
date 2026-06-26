#!/usr/bin/env python3
"""section_f_holders.py — top-N holder snapshot (current on-chain balances).

Aggregates lifetime inflows - outflows per address from the chain transfers table (v0.7.20 chain-routed)
since `date_floor` (defaults to listing_date - 90d). Returns top 50 by current
balance for use by section_l_distribution (role classification) + the
holdings_distribution.role_rows / progress_bars output.

Single surf query (~$0.02). Burn / zero addresses filtered server-side.

v0.6 (2026-05-24, Phase B.4)
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from parallel_surf import run_parallel
from chain_router import transfers_table, dex_trades_table, burn_addrs as _chain_burn_addrs  # v0.7.20 / v0.7.21.7


# v0.7.21.7: kept for back-compat (EVM-default callers). For real use, prefer
# `chain_router.burn_addrs()` which returns the active-chain burn set
# (Solana System Program 1111…1111 / Incinerator on Solana, 0x0 / 0xdead on EVM).
_BURN_ADDRS = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}


def run(
    ca: str,
    *,
    listing_date: str,
    total_supply: int | None,
    limit: int = 50,
    workdir: Path | None = None,
    chain_decimals: int | None = None,
) -> dict[str, Any]:
    """Section F entrypoint — top-N holder snapshot via `surf token-holders`.

    v0.7.9 rewrite: previous implementation used an in-window SQL aggregate
    (`SUM(amount_raw_in) - SUM(amount_raw_out) since date_floor` on
    bsc_transfers) which computed a misleading "current balance" for pools
    that were deployed before listing_date (initial liquidity arrived
    pre-window, so the aggregate showed NEGATIVE balance and the pool was
    filtered out of top_holders entirely). ESPORTS PancakeSwap V3 pool
    `0x5bb59bb9...` was -1.55M tokens by the old SQL → never made top-50 →
    DEX 主池 row in holdings_distribution showed 0.

    Fix: use `surf token-holders` which returns actual point-in-time on-chain
    balance (no window aggregation, no negative-balance failure mode).
    Cost: ~1 surf credit. Same shape as old output minus `total_in`/`total_out`
    (which had no downstream consumer anyway).
    """
    # v0.7.20.1: route to active chain. Pre-v0.7.20.1 this hardcoded
    # "bsc" so any non-BSC token (Base PLAY etc.) silently got the BSC
    # mirror's top holders (LP/CEX deposit addresses) instead of the
    # real holder set on the primary chain. The result was
    # holdings_distribution.role_rows = all zeros even though
    # dump_tracker found the real insider tree.
    # v0.7.21.7: Solana base58 CAs are case-sensitive — don't lowercase.
    from chain_router import get_active_chain
    _is_sol = get_active_chain() == "solana"
    cmd = [
        "surf", "token-holders",
        "--address", ca if _is_sol else ca.lower(),
        "--chain", get_active_chain(),
        "--limit", str(limit),
        "--include", "labels",
        "--json",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=30, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"top_holders": [], "n_holders_queried": 0, "_error": str(e)[:200]}
    if proc.returncode != 0:
        return {
            "top_holders": [], "n_holders_queried": 0,
            "_error": f"surf token-holders exit {proc.returncode}: {proc.stderr[:200]}",
        }
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"top_holders": [], "n_holders_queried": 0, "_error": f"non-JSON: {e}"}
    if doc.get("error"):
        return {"top_holders": [], "n_holders_queried": 0, "_error": str(doc["error"])[:200]}

    top_holders = []
    # v0.7.20.2: track burn-address balances separately. Pre-v0.7.20.2 we
    # silently dropped 0xdead / 0x0 from top_holders, which let large
    # burned amounts (PLAY: 1B = 20% of supply) leak into the cross_sym
    # whales list as a fake "holder" rather than being reported as
    # permanently-removed supply. Now we collect them into a dedicated
    # field so downstream sections (alloc, ALLOC table) can show
    # "已销毁 X tokens (Y% 总供应)" explicitly.
    burn_balance = 0.0
    burn_addrs_with_balance: list[dict] = []
    # v0.7.21.7: chain-aware burn set + case. Solana base58 preserved.
    _active_burn = _chain_burn_addrs()
    # v0.7.21.9: SPL token balance normalisation. surf token-holders returns
    # `balance` as raw atomic units on Solana (1e6 / 1e9 lamports). On EVM
    # the surf endpoint already returns the human-readable balance, so the
    # divisor stays at 1.0. We accept None / unknown gracefully by treating
    # the balance as already-normalised (v0.7.21.8 behaviour).
    _balance_divisor = 1.0
    if _is_sol and isinstance(chain_decimals, int) and chain_decimals > 0:
        _balance_divisor = float(10 ** chain_decimals)
    for row in (doc.get("data") or []):
        addr_raw = row.get("address") or ""
        addr = addr_raw if _is_sol else addr_raw.lower()
        if not addr:
            continue
        try:
            balance_raw = float(row.get("balance") or 0)
        except (TypeError, ValueError):
            balance_raw = 0.0
        balance = balance_raw / _balance_divisor
        if addr in _active_burn or addr in _BURN_ADDRS:
            burn_balance += balance
            burn_addrs_with_balance.append({"addr": addr, "balance": balance})
            continue
        # v0.7.21.9: percentage comes from surf in canonical %, no
        # divisor adjustment needed. Only the fallback path (no
        # percentage field, divide by total_supply) is in normalised
        # units now that `balance` is normalised above.
        pct_raw = row.get("percentage")
        try:
            pct = float(pct_raw) if pct_raw is not None else (
                balance / total_supply * 100 if total_supply else None
            )
        except (TypeError, ValueError):
            pct = balance / total_supply * 100 if total_supply else None
        top_holders.append({
            "addr": addr,
            "balance": balance,
            # v0.7.9: total_in/total_out dropped — no downstream consumer.
            # Setting to None preserves dict shape for any defensive callers.
            "total_in": None,
            "total_out": None,
            "pct_of_total": pct,
            # v0.7.9: pass Arkham label data when surf returns it (used by
            # section_cross_sym anti-pollution layer downstream).
            "entity_name": row.get("entity_name") or (
                (row.get("label") or {}).get("entity_name") if isinstance(row.get("label"), dict) else None
            ),
            "entity_type": row.get("entity_type") or (
                (row.get("label") or {}).get("entity_type") if isinstance(row.get("label"), dict) else None
            ),
            "label": row.get("label"),
        })

    burn_pct_of_supply = (
        burn_balance / total_supply * 100 if (total_supply and total_supply > 0) else None
    )
    return {
        "top_holders": top_holders,
        "n_holders_queried": len(top_holders),
        # v0.7.20.2: burn-address bucket (0xdead / 0x0). Permanent supply
        # removal — not a holder. burn_balance is the total token balance
        # sitting at burn addresses; burn_pct_of_supply is that balance
        # divided by total_supply (None if total_supply missing).
        "burn_balance": burn_balance,
        "burn_pct_of_supply": burn_pct_of_supply,
        "burn_addrs": burn_addrs_with_balance,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("ca")
    ap.add_argument("--listing-date", required=True)
    ap.add_argument("--total-supply", type=int, required=False)
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()
    print(json.dumps(run(
        ca=args.ca, listing_date=args.listing_date,
        total_supply=args.total_supply, limit=args.limit,
    ), ensure_ascii=False, indent=2))
