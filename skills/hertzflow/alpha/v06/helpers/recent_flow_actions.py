"""recent_flow_actions.py — v1.2.9 (product spec 2026-06-29).

Near-72h FAN-OUT (an operator source spraying to many EOAs) + CONSOLIDATION (many
EOAs concentrating into a CEX / hub) detection, surfaced at HIGHEST priority in the
一屏结论 / 速读.

WHY THIS EXISTS
===============
`discover_cex_fanout_hubs` only keeps a hub whose TOP SENDER is a CEX — it is built
for the "pull from Gate hot wallet → hub → sub-wallets" pattern. It MISSES a
MINT-AUTHORITY / cluster-hub source fanning out to fresh sockpuppets, which is the
pre-dump *seeding* signal. JCT/Janction (2026-06-29): a mint-authority Gnosis Safe
fanned out to 50 EOAs in the last 72h (~120-234M tokens each, one tx each) — a
textbook "mint → seed 50 wallets → they'll deposit to CEX / dump" move, and it was
invisible to every existing detector (cex_fanout wants a CEX source; anomaly_72h
truncated the events; rule_11/mint_authority don't look at *recent* fan-out shape).

This detector answers the recurring operator question: "is the operator, RIGHT NOW
(72h), preparing the next dump — seeding wallets (fan-out) or cashing out
(consolidation to CEX)?"

Design (cheap: 2 SQL over a 3-day window on one chain)
  1. fan-out:      GROUP BY `from`  HAVING count(distinct `to`)  >= min_counterparties
  2. consolidation:GROUP BY `to`    HAVING count(distinct `from`)>= min_counterparties
Then classify each hub in Python against the operator / CEX / infra address sets, and
drop bidirectional wash-bots (a hub that is a TOP node in BOTH lists = MM churner, not
a distribution/consolidation action).
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Callable

from chain_router import transfers_table, decimals_factor_str

_SURF_MAX_LOOKBACK_DAYS = 365

_SQL_FANOUT = (
    'SELECT "from" AS hub, count(DISTINCT "to") AS n_cp, count() AS n_tx, '
    "sum(toFloat64(toDecimal256(amount_raw,0))/{df}) AS total "
    "FROM {transfers} WHERE contract_address='{ca}' AND block_date >= '{floor}' "
    "AND \"to\" NOT IN ('0x0000000000000000000000000000000000000000',"
    "'0x000000000000000000000000000000000000dead') "
    "GROUP BY hub HAVING n_cp >= {min_cp} ORDER BY n_cp DESC LIMIT 40"
)
_SQL_CONSOLIDATE = (
    'SELECT "to" AS hub, count(DISTINCT "from") AS n_cp, count() AS n_tx, '
    "sum(toFloat64(toDecimal256(amount_raw,0))/{df}) AS total "
    "FROM {transfers} WHERE contract_address='{ca}' AND block_date >= '{floor}' "
    "GROUP BY hub HAVING n_cp >= {min_cp} ORDER BY n_cp DESC LIMIT 40"
)


def _default_run_sql(sql: str) -> dict[str, Any] | None:
    from section_a_scope import _run_surf_with_retry
    import json as _json
    doc, _err = _run_surf_with_retry(
        ["surf", "onchain-sql"],
        stdin=_json.dumps({"sql": sql, "max_rows": 100}), base_timeout=40,
        max_attempts=4,
    )
    return doc


def _norm(a: str | None) -> str:
    return (a or "").lower()


def detect_recent_flow_actions(
    *,
    ca: str,
    operator_addrs: set[str] | None = None,
    cex_addrs: set[str] | None = None,
    infra_addrs: set[str] | None = None,
    window_days: int = 3,
    min_counterparties: int = 10,
    run_sql: Callable[[str], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Detect operator-source fan-out + CEX consolidation in the last `window_days`.

    operator_addrs: mint authorities + cluster hubs + suspected reserves + deployer.
    cex_addrs:      CEX deposit / hot-wallet addresses (resolve_labels CEX class).
    infra_addrs:    DEX pools / routers — neutral, excluded from being flagged.
    Returns a dict stored on skeleton.recent_flow_actions and read by screen_summary.
    """
    operator_addrs = {_norm(a) for a in (operator_addrs or set()) if a}
    cex_addrs = {_norm(a) for a in (cex_addrs or set()) if a}
    infra_addrs = {_norm(a) for a in (infra_addrs or set()) if a}
    run_sql = run_sql or _default_run_sql

    ca_lc = _norm(ca)
    floor = (date.today() - timedelta(days=max(1, window_days))).isoformat()
    df = decimals_factor_str()
    transfers = transfers_table()

    def _rows(sql_tpl: str) -> list[dict[str, Any]]:
        sql = sql_tpl.format(df=df, transfers=transfers, ca=ca_lc, floor=floor,
                             min_cp=int(min_counterparties))
        try:
            doc = run_sql(sql)
        except Exception as e:  # noqa: BLE001
            return [{"__err": str(e)[:120]}]
        if not doc:
            return [{"__err": "surf_no_doc"}]
        return doc.get("data") or []

    fan_rows = _rows(_SQL_FANOUT)
    con_rows = _rows(_SQL_CONSOLIDATE)
    err = next((r["__err"] for r in (fan_rows + con_rows) if "__err" in r), None)
    fan_rows = [r for r in fan_rows if "__err" not in r]
    con_rows = [r for r in con_rows if "__err" not in r]

    # bidirectional = wash-bot / MM churner: a hub that is a top node in BOTH lists.
    fan_hubs = {_norm(r.get("hub")) for r in fan_rows}
    con_hubs = {_norm(r.get("hub")) for r in con_rows}
    bidirectional = fan_hubs & con_hubs

    def _mk(r: dict[str, Any], side: str) -> dict[str, Any]:
        hub = _norm(r.get("hub"))
        is_op = hub in operator_addrs
        is_cex = hub in cex_addrs
        is_infra = hub in infra_addrs
        is_wash = hub in bidirectional
        # Check the SEMANTIC role first: a CEX / operator / DEX hub is bidirectional
        # by nature (a CEX both receives and pays out), so the wash-churn exclusion
        # (bidirectional) must apply ONLY to *unknown* hubs — otherwise a genuine CEX
        # consolidation gets wrongly dropped as "wash".
        if side == "fanout":
            # operator-source fan-out = pre-dump seeding (the JCT case). A DEX
            # router / CEX fanning out is just swaps / withdrawals → infra, not a signal.
            if is_op:
                kind = "operator_source_fanout"
            elif is_infra or is_cex:
                kind = "infra_fanout"
            elif is_wash:
                kind = "wash_churn"
            else:
                kind = "unknown_hub_fanout"   # possible hidden operator hub
        else:  # consolidation
            if is_cex:
                kind = "cex_consolidation"     # active cashing out (the signal)
            elif is_op:
                kind = "operator_consolidation"
            elif is_infra:
                kind = "infra_consolidation"   # EOAs → DEX pool = selling
            elif is_wash:
                kind = "wash_churn"
            else:
                kind = "unknown_hub_consolidation"
        return {
            "hub": hub, "n_counterparties": int(r.get("n_cp") or 0),
            "n_tx": int(r.get("n_tx") or 0), "total_tokens": float(r.get("total") or 0),
            "kind": kind, "is_operator": is_op, "is_cex": is_cex,
        }

    fanout = [_mk(r, "fanout") for r in fan_rows]
    consolidation = [_mk(r, "consolidation") for r in con_rows]

    # the signal actions retail must see first. v1.2.12: keep the CONFIRMED-
    # operator source fan-out separate from the UNKNOWN-hub fan-out — the former
    # is the top-priority 🔴 headline, the latter a 🟡 疑似批量分发 medium row
    # (product spec 2026-07-01, TAC: an 88-wallet unknown-hub 72h fan-out was suppressed
    # entirely). top_operator_fanout must NOT be contaminated by unknown hubs.
    op_fanout = [a for a in fanout if a["kind"] == "operator_source_fanout"]
    unknown_fanout = [a for a in fanout if a["kind"] == "unknown_hub_fanout"]
    cex_con = [a for a in consolidation if a["kind"] == "cex_consolidation"]

    return {
        "window_days": window_days,
        "min_counterparties": min_counterparties,
        "fanout": fanout,
        "consolidation": consolidation,
        "has_operator_fanout": bool(op_fanout),
        "has_unknown_fanout": bool(unknown_fanout),
        "has_cex_consolidation": bool(cex_con),
        "n_operator_fanout": len(op_fanout),
        "n_unknown_fanout": len(unknown_fanout),
        "n_cex_consolidation": len(cex_con),
        "top_operator_fanout": max(op_fanout, key=lambda a: a["n_counterparties"], default=None),
        "top_unknown_fanout": max(unknown_fanout, key=lambda a: a["n_counterparties"], default=None),
        "top_cex_consolidation": max(cex_con, key=lambda a: a["n_counterparties"], default=None),
        "_error": err,
    }
