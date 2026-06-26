#!/usr/bin/env python3
"""section_anomaly_72h.py — Section ANOMALY: recent 24-72h large transfer detection.

Closes one of the review's documented v0.5.9 failures: the review's a token's report had
`anomaly.waves = []` despite documented $7.4M single transfer in last 72h.
v0.6 fix: pipeline AUTO-EMITS Wave 3 (近 72h activity) into waves_proposal
when recent surf data shows >= 1 transfer above threshold. LLM cannot
skip it.

## Inputs
- ca: contract address
- evidence_graph: shared EvidenceGraph instance (events added in-place)
- threshold_token_amount: minimum tokens for a transfer to count (default 100k)

## Output
Returns:
```python
{
  "n_recent_events": int,
  "wave3_proposal": {  # or None if no qualifying events
    "emoji": "🟡" | "🟠" | "🔴",  # severity by aggregate volume
    "title": "第三波 近 72h 异常活动",
    "ts_range": "YYYY-MM-DD ~ YYYY-MM-DD UTC",
    "status_text": "持续中" | "已收尾",
    "events": [{evt_ref, ts, from_to, amount, nature: "<LLM_PLACEHOLDER>"}],
  },
  "actors": [list of distinct addresses that appear in events],  # for monitoring_wallets
}
```

v0.6 (2026-05-24)
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from parallel_surf import run_parallel
from evidence_graph import EvidenceGraph
from i18n import t   # v0.6.2 i18n
from chain_router import transfers_table, dex_trades_table, get_active_chain as _chain_get_active  # v0.7.20 / v0.7.21.7
from chain_router import decimals_factor_str  # v0.9.7


SQL_RECENT_72H = """SELECT block_time, "from" AS sender, "to" AS receiver, toFloat64(toDecimal256(amount_raw,0))/{decimals_factor} AS amt, tx_hash FROM {transfers} WHERE contract_address = '{ca}' AND block_date >= today() - 4 AND toDecimal256(amount_raw,0)/{decimals_factor} >= {threshold} ORDER BY block_time DESC LIMIT 100"""


def _ts_to_iso(ts: int | str) -> str:
    if isinstance(ts, str):
        return ts
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(ts)


def _ts_to_date(ts: int | str) -> str:
    if isinstance(ts, str):
        return ts.split(" ")[0] if " " in ts else ts
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return str(ts)


def run(
    ca: str,
    evidence_graph: EvidenceGraph,
    *,
    threshold_token_amount: int = 100_000,
    price_usd: float | None = None,
    workdir: Path | None = None,
) -> dict[str, Any]:
    """Run Section ANOMALY. Mutates evidence_graph in-place.

    Args:
        ca: lowercase 0x address.
        evidence_graph: shared graph (events appended as evt_NNN of type recent_transfer).
        threshold_token_amount: minimum tokens for a transfer to be flagged.
            Default 100k — caller can pass a token-specific threshold.
        price_usd: optional current price. If provided, each event's
            usd_value gets populated. Without it, validator's
            event_matches_narrative can't match $-mentions in narrative.
        workdir: temp dir for surf query files.
    """
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="anom72h_"))
    workdir = Path(workdir)
    workdir.mkdir(exist_ok=True, parents=True)

    q = workdir / "q_anom72h.json"
    q.write_text(
        json.dumps({
            "max_rows": 100,
            # v0.7.21.7: chain-aware case. Solana base58 CAs must NOT be lowercased.
            "sql": SQL_RECENT_72H.format(ca=(ca if _chain_get_active() == "solana" else ca.lower()), threshold=int(threshold_token_amount), transfers=transfers_table(), dex_trades=dex_trades_table(), decimals_factor=decimals_factor_str()),
        }),
        encoding="utf-8",
    )
    results, _ = run_parallel([str(q)])
    resp = results[str(q)]
    if "error" in resp:
        return {
            "n_recent_events": 0,
            "wave3_proposal": None,
            "actors": [],
            "_error": resp["error"],
        }

    rows = resp.get("data", [])
    if not rows:
        return {
            "n_recent_events": 0,
            "wave3_proposal": None,
            "actors": [],
        }

    # Add each transfer as recent_transfer event to evidence_graph
    wave3_events: list[dict[str, Any]] = []
    actors: set[str] = set()
    ts_list = []

    # Take top 8 by amount for narrative compactness (rest still in evidence_graph)
    sorted_rows = sorted(rows, key=lambda r: r.get("amt", 0), reverse=True)
    for row in sorted_rows:
        ts = row.get("block_time")
        amt = float(row.get("amt", 0))
        from_a = row.get("sender", "")
        to_a = row.get("receiver", "")
        tx = row.get("tx_hash")
        usd_value = (amt * price_usd) if price_usd else None

        evt_ref = evidence_graph.add_event(
            type="recent_transfer",
            ts=ts,
            amount=amt,
            from_addr=from_a,
            to_addr=to_a,
            tx_hash=tx,
            usd_value=usd_value,
        )
        # v0.7.21.7: Solana addresses are case-sensitive; only lowercase on EVM.
        if _chain_get_active() == "solana":
            actors.add(from_a)
            actors.add(to_a)
        else:
            actors.add(from_a.lower())
            actors.add(to_a.lower())
        ts_list.append(ts)

        if len(wave3_events) < 8:  # cap narrative wave at 8 events
            usd_str = f"${usd_value:,.0f}" if usd_value else f"{amt:,.0f} tokens"
            wave3_events.append({
                "evt_ref": evt_ref,
                "ts": _ts_to_iso(ts),
                "hours_ago_text": "<LLM_NARRATIVE_PLACEHOLDER>",
                "from_to": f"`{from_a[:10]}…` → `{to_a[:10]}…`",
                "amount": usd_str if usd_value else f"{amt:,.0f} tokens",
                "nature": "<LLM_NARRATIVE_PLACEHOLDER>",
            })

    # Severity by aggregate amount
    total_amt = sum(float(r.get("amt", 0)) for r in rows)
    total_usd = (total_amt * price_usd) if price_usd else None
    if total_usd and total_usd >= 5_000_000:
        emoji = "🔴"
    elif total_usd and total_usd >= 1_000_000:
        emoji = "🟠"
    else:
        emoji = "🟡"

    ts_min = min(ts_list) if ts_list else None
    ts_max = max(ts_list) if ts_list else None

    wave3_proposal = {
        "emoji": emoji,
        "title": t("anomaly.wave_title.recent_72h"),
        "ts_range": f"{_ts_to_date(ts_min)} ~ {_ts_to_date(ts_max)} UTC" if ts_min else t("anomaly.wave_title.recent_72h"),
        "status_text": "<LLM_NARRATIVE_PLACEHOLDER>",
        "events": wave3_events,
        "_pipeline_locked_fields": ["evt_ref", "ts", "from_to", "amount"],
    }

    # beta.3 fix: surface LIMIT-cap truncation signal. When `len(rows) == 100`
    # we hit the SQL LIMIT — actual event count may be higher. ZEST 3-sym
    # test hit this: count=100 reported, true count probably 200+. Without
    # this flag, LLM narrative says "15 events / 100 events" as if it were
    # the full window total — false precision.
    LIMIT = 100
    was_truncated = len(rows) >= LIMIT
    return {
        "n_recent_events": len(rows),
        "was_truncated": was_truncated,
        "limit": LIMIT,
        "wave3_proposal": wave3_proposal,
        "actors": sorted(actors),
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("ca")
    ap.add_argument("--threshold", type=int, default=100_000)
    ap.add_argument("--price", type=float, default=None)
    args = ap.parse_args()

    eg = EvidenceGraph()
    out = run(args.ca, eg, threshold_token_amount=args.threshold, price_usd=args.price)
    out["_evidence_graph_count"] = eg.count_by_kind()
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
