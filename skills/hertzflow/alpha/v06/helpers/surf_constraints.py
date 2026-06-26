"""surf_constraints.py — shared helpers for adapting to Surf API policy.

Why (v0.9.1, 2026-06-14):

  Surf periodically tightens query constraints on its large on-chain
  ClickHouse tables. The current enforced limits we have to adapt to:

    bsc_transfers          ── 365-day block_date window
    bsc_dex_trades         ── 365-day block_date window
    ethereum_transfers     ── 365-day block_date window
    ethereum_dex_trades    ── 365-day block_date window
    (and the analogous tables on arbitrum/base/polygon/optimism)

  Older `dump_tracker.py` / `funding_source_attribution.py` / etc. wrote
  queries with `block_date >= '<listing_date>'`, which works for newly
  listed tokens but **fails with INVALID_REQUEST** for tokens older than
  ~365 days (e.g. SIREN, listed 2025-02-19, age 480 days as of 2026-06-14).

  Discovered when SIREN forensic 2026-06-14 returned
  `dump_tracking.confirmed_net_sellout_usd = $0` despite EmberCN observing
  $45.7M of confirmed CEX sell-out over 2 days on-chain. Diagnosis: the
  surf `INVALID_REQUEST` killed the dump_tracker SQL silently, the rest
  of the pipeline continued, the report shipped with `$0` confirmed sell.

  Same root-cause category as the v0.8.7.2 `--json` flag drop — surf's
  policy changed, our hardcoded query didn't adapt. This helper exists
  so the adaptation lives in one place; future surf policy changes only
  touch this file.

Convention:

  Call `surf_safe_date_floor(listing_date)` everywhere you'd previously
  written `date_floor = listing_date or "2020-01-01"`. The returned
  string is guaranteed to satisfy surf's 365-day rule for large tables,
  while still using the listing_date when the token is newer than the
  window.

Edge cases:

  - If the token is older than 365 days, queries can only see the most
    recent ~364 days. Anything before that is invisible to dump_tracker
    / funding_attribution / wash_infra etc.
  - This is acceptable for trade-decision context (most users care about
    "is the operator dumping NOW", not "was the operator dumping 18
    months ago"). The report header should surface this constraint so
    the user knows the window is bounded.
"""
from __future__ import annotations

from datetime import date, timedelta

# Conservative 1-day buffer below the published 365-day limit, so a
# query bumping into the limit at boundary still passes (surf's window
# is inclusive of today, so today-364 gives a 365-row window).
SURF_LARGE_TABLE_WINDOW_DAYS = 364


def surf_earliest_date_floor() -> str:
    """The earliest `block_date >= '<X>'` you can safely use on surf's
    large tables. Returns a `YYYY-MM-DD` ISO date string. Recomputed
    every call (no caching) so a long-running pipeline that crosses
    midnight UTC stays correct."""
    return (date.today() - timedelta(days=SURF_LARGE_TABLE_WINDOW_DAYS)).isoformat()


def surf_safe_date_floor(listing_date: str | None,
                         fallback: str = "2020-01-01") -> str:
    """Clamp `listing_date` so it never falls before surf's 365-day
    window. Mirrors the old `date_floor = listing_date or fallback`
    idiom but adapts the floor to surf policy.

    Args:
        listing_date: ISO date string `YYYY-MM-DD`, or None.
        fallback: legacy default for tokens without a known listing
            date (only kicks in if the token is so new there's no
            listing record AND the caller didn't want the 364-day
            window — almost never the right choice today).

    Returns:
        ISO date string usable directly in
        `block_date >= '{returned_value}'` query fragments.
    """
    earliest_safe = surf_earliest_date_floor()
    candidate = listing_date or fallback
    # ISO `YYYY-MM-DD` strings sort lexically the same as chronologically.
    if candidate < earliest_safe:
        return earliest_safe
    return candidate


__all__ = [
    "SURF_LARGE_TABLE_WINDOW_DAYS",
    "surf_earliest_date_floor",
    "surf_safe_date_floor",
]
