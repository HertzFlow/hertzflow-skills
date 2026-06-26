#!/usr/bin/env python3
"""hidden_operator_activity.py — query whether the heuristically-flagged
hidden operator wallets (suspected_operator_reserve / fake_mining_cluster_member,
emitted by hidden_operator_enricher) have already begun realizing their
allocation on-chain.

# Why this exists (v0.8.3)

v0.8.2.1 added `hidden_operator_enricher` which appends heuristically-
identified operator-controlled wallets to monitoring_wallets[]. Users
then import paste.json into Binance Wallet / OKX wallet tracker to
monitor the addresses themselves.

But for the report itself, users wanted: a forensic summary — has the
hidden operator population already started realizing? If so, how much?
This module answers that by running the same (a)/(b) SQL the dump_tracker
runs against m6 insiders, but with the input set replaced by hidden
operator addresses pulled from monitoring_wallets[].

# Output

`skeleton["hidden_operator_activity"]` =
{
  "n_hidden_wallets_tracked": int,
  "confirmed_cex_tokens": float,        # (a) hidden → CEX deposit
  "confirmed_dex_tokens": float,        # (b) hidden own DEX swaps
  "confirmed_total_tokens": float,
  "confirmed_total_pct_circ": float | None,
  "confirmed_est_usd": float | None,    # tokens × median DEX price
  "n_distinct_cex_destinations": int,   # how many CEX deposit addrs
  "n_dex_swaps": int,                   # how many DEX swap rows
  "cex_destination_brands": [str],      # list of CEX brand names hit
  "_error": str | None,                 # only on hard SQL failure
}

# Render impact

`render_report.py` (真实派发段) shows a `🕵️ 隐藏庄家弹药历史动作` row
conditionally — only when `confirmed_total_tokens > 0`. The wording is
forensic ("有 / 无 已观察到的变现"), not alert-y.

# Surf cost

2 parallel SQL queries per token (reuses dump_tracker's
`fetch_apparatus_to_cex` and `fetch_apparatus_dex_sold` SQL helpers).
Estimated +10-30 credits/token (~3-10% bump over baseline). Time
impact 0s when run in parallel with the existing dump_tracker queue.

# Caveats

- Reuses the dump_tracker (a)/(b) algorithm exactly — same convention:
  CEX deposit = exit/sell (the off-chain CEX sale is unobservable on
  chain, treated as confirmed sell). DEX swap = directed sell from
  the hidden wallet itself.
- USD estimate uses the dump_tracker's DEX median price field
  (`dex_twap_usd_per_token`) when available; else None (display as "—").
- Stale historical allocation is NOT double-counted — we query 365d
  activity, no overlap with insider (a)/(b) because the hidden
  operator set is wallet-disjoint from the m6 insider set by
  construction (post-launch detector outputs vs pre-launch deployer
  outflow).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))


_HIDDEN_OPERATOR_ROLE_ENUMS = (
    "suspected_operator_reserve",
    "fake_mining_cluster_member",
)


def _collect_hidden_addresses(skel: dict) -> list[str]:
    """Extract hidden-operator wallet addresses from skeleton's
    monitoring_wallets[] list.

    Returns a sorted list of lowercase 0x-addresses.
    """
    addrs: set[str] = set()
    for w in (skel.get("monitoring_wallets") or []):
        if (w.get("monitor_role_enum") or "") in _HIDDEN_OPERATOR_ROLE_ENUMS:
            a = (w.get("addr_full") or w.get("address") or "").lower()
            if a and a.startswith("0x") and len(a) == 42:
                addrs.add(a)
    return sorted(addrs)


def probe_hidden_operator_activity(
    ca: str,
    skel: dict,
    date_floor: str | None = None,
) -> dict[str, Any]:
    """Probe (a)/(b) realization for the hidden operator wallet set.

    Args:
      ca: token contract address.
      skel: skeleton dict (read monitoring_wallets, meta, dump_tracking).
      date_floor: 'YYYY-MM-DD' lower bound. Defaults to dump_tracker's
        date_floor (alpha listing date) for consistency with (a)/(b)
        windows in the report.

    Returns the `hidden_operator_activity` dict (see module docstring).
    Errors are reported via `_error` field, never raised.
    """
    hidden = _collect_hidden_addresses(skel)
    if not hidden:
        return {
            "n_hidden_wallets_tracked": 0,
            "confirmed_cex_tokens": 0.0,
            "confirmed_dex_tokens": 0.0,
            "confirmed_total_tokens": 0.0,
            "confirmed_total_pct_circ": None,
            "confirmed_est_usd": None,
            "n_distinct_cex_destinations": 0,
            "n_dex_swaps": 0,
            "cex_destination_brands": [],
        }

    # Default date_floor mirrors dump_tracker convention (Alpha listing day).
    # v0.9.1: clamp to surf's 364-day safe window so old tokens (>365 day
    # listing age) don't INVALID_REQUEST on bsc_transfers / bsc_dex_trades.
    if not date_floor:
        meta = skel.get("meta") or {}
        date_floor = (
            meta.get("alpha_listing_date_utc")
            or meta.get("listing_date")
        )
    from surf_constraints import surf_safe_date_floor
    date_floor = surf_safe_date_floor(date_floor)

    # Reuse dump_tracker SQL helpers.
    try:
        from dump_tracker import fetch_apparatus_to_cex, fetch_apparatus_dex_sold
    except Exception as e:
        return {
            "n_hidden_wallets_tracked": len(hidden),
            "confirmed_cex_tokens": 0.0,
            "confirmed_dex_tokens": 0.0,
            "confirmed_total_tokens": 0.0,
            "confirmed_total_pct_circ": None,
            "confirmed_est_usd": None,
            "n_distinct_cex_destinations": 0,
            "n_dex_swaps": 0,
            "cex_destination_brands": [],
            "_error": f"import dump_tracker helpers failed: {str(e)[:120]}",
        }

    # (a) hidden → CEX deposit
    cex_res: dict[str, Any] = {}
    try:
        cex_res = fetch_apparatus_to_cex(ca, hidden, date_floor) or {}
    except Exception as e:
        cex_res = {"__ERR": f"cex query: {str(e)[:120]}"}

    # (b) hidden own DEX swaps
    dex_res: dict[str, Any] = {}
    try:
        dex_res = fetch_apparatus_dex_sold(ca, hidden, date_floor) or {}
    except Exception as e:
        dex_res = {"__ERR": f"dex query: {str(e)[:120]}"}

    cex_tokens = float(cex_res.get("cex_tokens") or 0)
    dex_tokens = float(dex_res.get("dex_sold_tokens") or 0)
    total_tokens = cex_tokens + dex_tokens

    n_swaps = int(dex_res.get("n_swaps") or 0)
    cex_labels = list(cex_res.get("cex_labels") or [])

    # Distinct CEX-destination count: labels are sometimes ['Binance',
    # 'Binance', 'OKX'] — dedupe for the report. Brand only, not address.
    cex_brands_dedup = sorted({lbl for lbl in cex_labels if lbl})

    # v0.8.3.1 audit MED #2 fix: prefer the hidden population's OWN
    # realized DEX USD (dex_sold_usd) when available. Falls back to m6
    # insider TWAP only when the hidden leg has no on-chain SUM amount_usd
    # available (rare). The render text discloses which source was used.
    hidden_dex_usd = float(dex_res.get("dex_sold_usd") or 0)
    dt = skel.get("dump_tracking") or {}
    twap = dt.get("apparatus_dex_twap_usd_per_token")
    confirmed_est_usd: float | None = None
    est_usd_source: str = "none"
    if hidden_dex_usd > 0 and total_tokens > 0:
        # Use realized DEX USD + extrapolate to CEX leg via the hidden
        # population's own implied price (hidden_dex_usd / dex_tokens).
        if dex_tokens > 0:
            hidden_implied_px = hidden_dex_usd / dex_tokens
            confirmed_est_usd = hidden_implied_px * total_tokens
            est_usd_source = "hidden_own_dex"
        else:
            confirmed_est_usd = hidden_dex_usd
            est_usd_source = "hidden_own_dex_only"
    elif twap and total_tokens > 0:
        try:
            confirmed_est_usd = float(twap) * total_tokens
            est_usd_source = "m6_insider_twap"
        except (ValueError, TypeError):
            confirmed_est_usd = None

    meta = skel.get("meta") or {}
    circ = meta.get("circulating_supply")
    pct_circ = None
    if circ and total_tokens > 0:
        try:
            pct_circ = total_tokens / float(circ) * 100
        except (ValueError, TypeError, ZeroDivisionError):
            pct_circ = None

    out = {
        "n_hidden_wallets_tracked": len(hidden),
        "confirmed_cex_tokens": cex_tokens,
        "confirmed_dex_tokens": dex_tokens,
        "confirmed_total_tokens": total_tokens,
        "confirmed_total_pct_circ": pct_circ,
        "confirmed_est_usd": confirmed_est_usd,
        "confirmed_est_usd_source": est_usd_source,
        "n_distinct_cex_destinations": len(cex_brands_dedup),
        "n_dex_swaps": n_swaps,
        "cex_destination_brands": cex_brands_dedup,
        "date_floor": date_floor,
    }
    # v0.8.3.1 audit HIGH #1 fix: surface ok=False as _error.
    # fetch_apparatus_to_cex / fetch_apparatus_dex_sold can return
    # {"ok": False, "error": ...} on failed SQL; silent treat-as-0
    # would let the render emit "未观察到变现" when both queries
    # actually failed.
    errs: list[str] = []
    if isinstance(cex_res, dict):
        if cex_res.get("__ERR"):
            errs.append(f"cex: {cex_res['__ERR']}")
        elif cex_res.get("ok") is False:
            errs.append(f"cex: ok=False {cex_res.get('error') or ''}")
    if isinstance(dex_res, dict):
        if dex_res.get("__ERR"):
            errs.append(f"dex: {dex_res['__ERR']}")
        elif dex_res.get("ok") is False:
            errs.append(f"dex: ok=False {dex_res.get('error') or ''}")
    err_str = " | ".join(e for e in errs if e)
    if err_str:
        out["_error"] = err_str
    return out


__all__ = ["probe_hidden_operator_activity"]
