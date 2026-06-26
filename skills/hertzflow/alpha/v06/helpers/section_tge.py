#!/usr/bin/env python3
"""section_tge.py — TGE anchors (LP creation + Alpha open + key price multipliers).

Returns tge.rows[] in the format render_report expects. Uses Alpha API listing_ts
and surf for first DEX swap timestamp.

v0.6 (2026-05-24, Phase B.3)
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import sys

sys.path.insert(0, str(Path(__file__).parent))
from parallel_surf import run_parallel
from i18n import t   # v0.6.2 i18n
from chain_router import transfers_table, dex_trades_table, get_active_chain as _chain_get_active  # v0.7.20 / v0.7.21.7


def _fmt_ts(ts: int | float | None) -> str:
    if ts is None:
        return "—"
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return str(ts)


def _ratio(current: float | None, base: float | None) -> str:
    if not current or not base:
        return "—"
    if base == 0:
        return "∞"
    return f"{current/base:.2f}×"


def run(
    ca: str,
    *,
    alpha_listing_ts_ms: int,
    pool_addr: str | None,
    current_price_usd: float | None,
    workdir: Path | None = None,
) -> dict[str, Any]:
    """Section TGE entrypoint.

    Args:
        ca: contract address
        alpha_listing_ts_ms: from Alpha API (Section A)
        pool_addr: main DEX pool (from section_liq.discover_main_pool)
        current_price_usd: current price (from section_liq)
    """
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="tge_"))
    workdir = Path(workdir)
    workdir.mkdir(exist_ok=True, parents=True)

    lp_creation_ts: int | None = None
    lp_first_price: float | None = None

    # v0.7.21.8: only run the LP-first-trade probe on chains with surf SQL
    # coverage. Solana has no `agent.solana_transfers` table — pre-skip
    # saves a wasted UNKNOWN_TABLE round-trip.
    from chain_router import sql_supported as _sql_supported
    if pool_addr and _sql_supported():
        # First transfer where pool is involved = LP creation time
        q = workdir / "q_lp_first.json"
        q.write_text(json.dumps({
            "max_rows": 1,
            "sql": (
                f"SELECT block_time FROM {transfers_table()} "
                f"WHERE contract_address = '{ca if _chain_get_active() == 'solana' else ca.lower()}' "
                f"AND (\"to\" = '{pool_addr}' OR \"from\" = '{pool_addr}') "
                f"AND block_date >= '2026-01-01' "
                f"ORDER BY block_time LIMIT 1"
            ),
        }), encoding="utf-8")
        results, _ = run_parallel([str(q)])
        resp = results[str(q)]
        if "error" not in resp and resp.get("data"):
            lp_creation_ts = resp["data"][0].get("block_time")

    # Alpha open ≈ alpha_listing_ts; price ≈ first sniper buy price (heuristic)
    # For v0.6 phase B.3 simple: approximate Alpha open price as ~current_price/multiplier
    # (we know it's almost always pumped from open). Without per-tx price index,
    # leave as null and let LLM narrate based on multiplier.
    alpha_open_ts = int(alpha_listing_ts_ms / 1000) if alpha_listing_ts_ms else None

    dash = t("common.none_dash")
    rows = [
        {
            "label": t("section.tge.label_lp_first"),
            "time": _fmt_ts(lp_creation_ts),
            "price": dash,  # tx-level price not indexed in v0.6 phase B
            "vs_current": dash,
        },
        {
            "label": t("section.tge.label_alpha_first"),
            "time": _fmt_ts(alpha_open_ts),
            "price": dash,
            "vs_current": dash,
        },
        {
            "label": t("section.tge.label_current_price"),
            "time": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"),
            "price": f"**${current_price_usd:.4f}**" if current_price_usd else dash,
            "vs_current": "1.00×",
        },
    ]

    return {
        "lp_creation_ts": lp_creation_ts,
        "alpha_open_ts": alpha_open_ts,
        "current_price_usd": current_price_usd,
        "rows": rows,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("ca")
    ap.add_argument("--alpha-listing-ts-ms", type=int, required=True)
    ap.add_argument("--pool-addr", required=False)
    ap.add_argument("--current-price-usd", type=float, required=False)
    args = ap.parse_args()
    print(json.dumps(run(
        ca=args.ca, alpha_listing_ts_ms=args.alpha_listing_ts_ms,
        pool_addr=args.pool_addr, current_price_usd=args.current_price_usd,
    ), ensure_ascii=False, indent=2))
