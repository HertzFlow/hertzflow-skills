"""recent_mint_events.py — v1.2.14 (product spec 2026-07-01, TAC).

Recent MINT-EVENT detection (fresh supply created from the 0x0 black-hole), surfaced
at HIGH priority in the 一屏结论 / 速读.

WHY THIS EXISTS
===============
`discover_mint_authorities` answers WHO can mint and HOW MUCH total, but NOT WHEN — it
carries no timestamp, so a large recent mint (the operator creating fresh ammo, often
the pump source) was invisible to a reader of the 一屏结论 / 速读. TAC (2026-07-01): a
164.2M-token mint on 06-29 (317 tx from 0x0) was the pump source per external on-chain
watchers, yet the report only showed the mint authorities' *held balance* with no date.

A large mint from 0x0 is a time-sensitive operator action ("new ammo just created") and
belongs next to the recent fan-out / consolidation row — with a timestamp.

Design (cheap: 1 SQL, daily GROUP BY over a lookback window on one chain)
  SELECT toDate(block_time) AS d, sum(minted), count() FROM transfers
  WHERE from = 0x0 GROUP BY d
Then in Python: mark days whose minted >= `min_pct_circ`% of circulating as SIGNIFICANT,
and flag the largest SIGNIFICANT mint whose date is within `recent_window_days` of today.
We report the FACT (large mint at date T, % of supply) — NOT a causal "pump source"
claim; the copy asks the reader to corroborate with price / perp OI.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable

from chain_router import transfers_table, decimals_factor_str

_ZERO = "0x0000000000000000000000000000000000000000"

_SQL_MINT_BY_DAY = (
    "SELECT toDate(block_time) AS d, "
    "sum(toFloat64(toDecimal256(amount_raw,0))/{df}) AS minted, count() AS n_tx "
    "FROM {transfers} WHERE contract_address='{ca}' AND \"from\"='" + _ZERO + "' "
    "AND block_date >= '{floor}' GROUP BY d ORDER BY d DESC LIMIT 400"
)


def _default_run_sql(sql: str) -> dict[str, Any] | None:
    from section_a_scope import _run_surf_with_retry
    import json as _json
    doc, _err = _run_surf_with_retry(
        ["surf", "onchain-sql"],
        stdin=_json.dumps({"sql": sql, "max_rows": 400}), base_timeout=40,
        max_attempts=4,
    )
    return doc


def _to_iso_date(d: Any) -> str | None:
    """surf may return toDate() as a 'YYYY-MM-DD' string or a unix-seconds integer."""
    if d is None:
        return None
    s = str(d)
    if s.isdigit():
        try:
            return datetime.fromtimestamp(int(s), tz=timezone.utc).date().isoformat()
        except (ValueError, OSError, OverflowError):
            return None
    return s[:10]


def detect_recent_mint_events(
    *,
    ca: str,
    circ_supply: float,
    recent_window_days: int = 14,
    min_pct_circ: float = 1.0,
    lookback_days: int = 120,
    today: date | None = None,
    run_sql: Callable[[str], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Detect recent significant mint events (fresh supply from 0x0).

    circ_supply:        circulating supply; a mint DAY is SIGNIFICANT when its minted
                        total is >= min_pct_circ% of it (0 circ → nothing significant).
    recent_window_days: a significant mint is surfaced as a headline only if its date is
                        within this many days of `today`.
    Returns a dict stored on skeleton.recent_mint_events and read by screen_summary.
    """
    run_sql = run_sql or _default_run_sql
    # UTC (chain block dates are UTC) so days_ago can't drift ±1 vs a host in another tz.
    today = today or datetime.now(timezone.utc).date()
    ca_lc = (ca or "").lower()
    floor = (today - timedelta(days=max(recent_window_days, lookback_days))).isoformat()
    sql = _SQL_MINT_BY_DAY.format(
        df=decimals_factor_str(), transfers=transfers_table(), ca=ca_lc, floor=floor)

    out: dict[str, Any] = {
        "recent_window_days": recent_window_days,
        "min_pct_circ": min_pct_circ,
        "lookback_days": lookback_days,
        "mint_days": [],
        "significant_mints": [],
        "has_recent_significant_mint": False,
        "top_recent_mint": None,
        "recent_significant_total": 0.0,
        "_error": None,
    }
    try:
        doc = run_sql(sql)
    except Exception as e:  # noqa: BLE001
        out["_error"] = str(e)[:150]
        return out
    if not doc:
        out["_error"] = "surf_no_doc"
        return out

    try:
        circ = float(circ_supply or 0)
    except (TypeError, ValueError):
        circ = 0.0
    floor_tokens = circ * (min_pct_circ / 100.0) if circ > 0 else float("inf")

    days: list[dict[str, Any]] = []
    for r in (doc.get("data") or []):
        # v1.2.14 (adversarial review nit): keep ALL row parsing local so a malformed
        # minted / n_tx / date can never throw out of the helper — skip the bad row.
        try:
            iso = _to_iso_date(r.get("d"))
            if not iso:
                continue
            minted = float(r.get("minted") or 0)
            days_ago = (today - date.fromisoformat(iso)).days
            rec = {
                "date": iso,
                "minted": minted,
                "n_tx": int(r.get("n_tx") or 0),
                "pct_circ": (minted / circ * 100) if circ > 0 else 0.0,
                "days_ago": days_ago,
            }
        except (TypeError, ValueError):
            continue
        days.append(rec)

    days.sort(key=lambda x: x["date"], reverse=True)
    out["mint_days"] = days
    significant = [d for d in days if d["minted"] >= floor_tokens]
    out["significant_mints"] = significant

    recent_sig = [d for d in significant if 0 <= d["days_ago"] <= recent_window_days]
    if recent_sig:
        out["has_recent_significant_mint"] = True
        out["recent_significant_total"] = sum(d["minted"] for d in recent_sig)
        # headline = the LARGEST recent significant mint day
        out["top_recent_mint"] = max(recent_sig, key=lambda x: x["minted"])
    return out
