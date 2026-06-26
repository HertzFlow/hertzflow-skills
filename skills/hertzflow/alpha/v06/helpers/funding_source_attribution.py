"""v0.7.23.1: Funding source attribution for high-value addresses.

Reverse approach to "矿币 / bridge / airdrop distribution modelling".

Standard rule_11 (deployer → m6 → m4) assumes a single deployer is the
distribution authority. Tokens like Humanity Protocol, Aethir-class
mining tokens, Polyhedra-class bridge tokens, and vesting-airdrop
tokens violate this — the deployer is a placeholder; real distribution
flows via bridge mint contracts, vesting contracts, or airdrop reward
contracts. Forward-decoding the distribution mechanism is surf-load-
intensive (cluster hub detection across thousands of mining receivers)
and depends on an unstable threshold (n_senders ≥ 10 etc.).

Reverse approach instead: take the high-value addresses surfaced by
existing detectors (wash_infra P/Q, flow_operators op_addrs, rule_11
m6 receivers, dump_tracker insider_addrs, top_holders top-N) and ask
"where did each addr's token come from": mint vs DEX buy vs CEX
withdraw vs P2P transfer. A wallet with 87% mint origin + heavy DEX
dump activity is operator-mined-then-dumped; 92% DEX buy + heavy dump
is normal retail PnL-taker. The classification answers the user's
real question ("是不是庄家在出货") without decoding the mining
mechanism.

One batch SQL (group by addr, source) covers up to ~200 addresses
within surf's 30s budget.
"""
from __future__ import annotations

import json
import os
from datetime import date, timedelta
from typing import Any

from chain_router import (
    is_valid_addr as _chain_is_valid_addr,
    transfers_table,
    dex_trades_table,
    decimals_factor_str,
)
from window_chunker import (  # v0.9.4
    chunked_dates,
    parallel_run_chunked,
    merge_chunked_rows,
    chunk_summary,
)

# surf enforces a 365-day window on `bsc_transfers` queries (and the
# equivalent on other chains). Any wider span is rejected upfront with
# INVALID_REQUEST. The helper clamps caller-supplied date_floor to today
# - 365d so a listing-anchored floor like (listing - 365d) doesn't blow
# up when the token has been listed for more than a year.
_SURF_MAX_LOOKBACK_DAYS = 365

# v0.9.4 round-2 adversarial review fix #1: surf onchain-sql hard-caps max_rows at
# 10000 (adversarial review CLO bug report 2026-06-12, confirmed in section_a_scope
# error parsing comment). Stay safely below the cap for chunk_top_n
# computations so default pipeline call (`top_n=100` → naive
# `chunk_top_n = top_n * 100 = 10000` → `max_rows=10010`) doesn't
# every-chunk-fail with INVALID_REQUEST.
_SURF_SAFE_MAX_ROWS = 9000

# v0.9.4: same heuristic as rule_11._is_short_window — short windows
# collapse to a single chunk; long windows split to chunk_days=90.
# Override via env on tokens where the default proves wrong (timeouts
# at 200d → lower; surf back to normal → raise toward 400-500d).
_SHORT_WINDOW_DAYS = int(os.environ.get("BINANCE_ALPHA_SHORT_WINDOW_DAYS", "300"))


def _is_short_window(floor: str, ceiling: str | None = None) -> bool:
    floor_d = date.fromisoformat(floor)
    ceiling_d = date.fromisoformat(ceiling) if ceiling else date.today()
    return (ceiling_d - floor_d).days <= _SHORT_WINDOW_DAYS


def _single_chunk_or_chunker_dates(
    floor: str, ceiling: str | None = None, chunk_days: int = 90,
) -> list[tuple[str, str]]:
    if _is_short_window(floor, ceiling):
        ceiling_concrete = ceiling or date.today().isoformat()
        return [(floor, ceiling_concrete)]
    return chunked_dates(floor, ceiling or date.today().isoformat(), chunk_days=chunk_days)


def _run_chunk_via_surf(sql: str, max_rows: int = 5000, base_timeout: int = 40) -> dict[str, Any]:
    """v0.9.4: surf onchain-sql call shaped for parallel_run_chunked. Returns
    {data: [...], _error?: str, meta: {...}}. Threads section_a_scope's retry
    wrapper so 429 / transient surf errors get the same backoff treatment as
    single-shot queries. Unlike rule_11's _run_one_chunk (which writes a
    workdir file), this uses stdin so funding_attribution doesn't need a
    workdir passed in.
    """
    from section_a_scope import _run_surf_with_retry
    try:
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": max_rows}),
            base_timeout=base_timeout, max_attempts=4,
        )
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"[:200], "data": []}
    if not doc:
        return {"_error": err or "surf returned no doc", "data": []}
    return {"data": doc.get("data") or [], "meta": doc.get("meta") or {}}

_DEAD = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}
_ZERO_ADDR = "0x0000000000000000000000000000000000000000"
# Unmatchable sentinel for empty IN lists. ClickHouse rejects IN ()
# and the bare literal NULL has unpredictable semantics with strict
# comparisons; a literal that no real address can match preserves
# CASE branch ordering without false positives.
_IN_SENTINEL = "('0xffffffffffffffffffffffffffffffffffffffff')"


def _clean_addrs(addrs: list[str] | None) -> list[str]:
    """Dedup + lowercase + validate. Drops zero/burn addrs."""
    out: list[str] = []
    seen: set[str] = set()
    for a in (addrs or []):
        if not a:
            continue
        a = a.lower()
        if a in seen or a in _DEAD:
            continue
        if not _chain_is_valid_addr(a):
            continue
        seen.add(a)
        out.append(a)
    return out


def _empty_summary() -> dict[str, int]:
    return {
        "n_addrs_queried": 0, "n_addrs_with_data": 0,
        "n_mining_fed": 0, "n_dex_fed": 0,
        "n_p2p_fed": 0, "n_cex_fed": 0,
    }


def _build_source_sql(
    *,
    ca: str,
    high_value_addrs: list[str],
    dex_pair_addrs: list[str],
    cex_addrs: list[str],
    date_floor: str,
) -> str:
    """Single batch SQL classifying incoming transfers by source.

    Each row of the result: (addr, source, sum(amt), count). source ∈
    {mint, dex_buy, cex_withdraw, p2p}. Mint is detected by
    from=0x0; dex_buy by from ∈ known DEX pair set; cex_withdraw by
    from ∈ known CEX custody set; else p2p_transfer.

    All address values interpolated into the SQL are forced to lowercase
    here (defensive — attribute_funding's _clean_addrs already does this
    upstream, but the helper is also called directly by tests). The SQL
    never wraps lower() on column values (surf-team anti-pattern: it
    prevents projection-skip optimisation, exactly what slowed SKYAI).
    """
    ca_lc = ca.lower()
    high_lc = [a.lower() for a in high_value_addrs]
    dex_lc = [a.lower() for a in dex_pair_addrs]
    cex_lc = [a.lower() for a in cex_addrs]
    high_in = "(" + ",".join(f"'{a}'" for a in high_lc) + ")"
    dex_in = (
        "(" + ",".join(f"'{a}'" for a in dex_lc) + ")"
        if dex_lc else _IN_SENTINEL
    )
    cex_in = (
        "(" + ",".join(f"'{a}'" for a in cex_lc) + ")"
        if cex_lc else _IN_SENTINEL
    )
    sql = (
        "SELECT \"to\" AS addr, "
        "CASE "
        f"  WHEN \"from\" = '{_ZERO_ADDR}' THEN 'mint' "
        f"  WHEN \"from\" IN {dex_in} THEN 'dex_buy' "
        f"  WHEN \"from\" IN {cex_in} THEN 'cex_withdraw' "
        "  ELSE 'p2p' END AS source, "
        f"sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amt, "
        "count() AS n_tx "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca_lc}' "
        f"AND \"to\" IN {high_in} "
        f"AND block_date >= '{date_floor}' "
        "GROUP BY addr, source"
    )
    return sql


def attribute_funding(
    *,
    ca: str,
    high_value_addrs: list[str],
    dex_pair_addrs: list[str] | None = None,
    cex_addrs: list[str] | None = None,
    date_floor: str = "2020-01-01",
    max_addrs: int = 200,
) -> dict[str, Any]:
    """Classify each high-value address's incoming token by source type.

    Args:
        ca: contract address (lowercased internally for EVM).
        high_value_addrs: addresses to classify. Capped to max_addrs.
        dex_pair_addrs: known DEX pair / pool addresses (from
            section_a chain_lp_realtime). Empty list ⇒ no dex_buy
            classification — all non-mint flows fall into p2p.
        cex_addrs: known CEX custody addresses (from identity
            classifier). Empty list ⇒ no cex_withdraw classification.
        date_floor: 'YYYY-MM-DD'. Earliest block_date to scan.
        max_addrs: hard cap on input list (prevents SQL bloat).

    Returns: dict with keys:
        attributions: {addr → per-addr classification dict}
        summary: counts by primary source
        _debug: SQL diagnostics
        _error: only present on hard failure
    """
    ca = (ca or "").lower()
    if not ca or not _chain_is_valid_addr(ca):
        return {
            "attributions": {}, "summary": _empty_summary(),
            "_error": f"invalid ca: {ca!r}",
        }

    addrs = _clean_addrs(high_value_addrs)
    truncated_n = max(0, len(addrs) - max_addrs)
    addrs = addrs[:max_addrs]

    # surf enforces a 365-day block_date window — clamp the caller's
    # floor up if it's older. Forensic callers naturally pass listing-365d
    # which can pre-date today-365d for tokens listed > 1 year ago.
    surf_window_floor = (date.today() - timedelta(days=_SURF_MAX_LOOKBACK_DAYS)).isoformat()
    if date_floor < surf_window_floor:
        date_floor_clamped = surf_window_floor
    else:
        date_floor_clamped = date_floor

    if not addrs:
        return {
            "attributions": {}, "summary": _empty_summary(),
            "_debug": {
                "sql_truncated_addr_n": truncated_n,
                "lookup_window_floor": date_floor,
                "n_dex_pairs_known": len(_clean_addrs(dex_pair_addrs)),
                "n_cex_known": len(_clean_addrs(cex_addrs)),
            },
        }

    dex_pairs = _clean_addrs(dex_pair_addrs)
    cex_a = _clean_addrs(cex_addrs)

    sql = _build_source_sql(
        ca=ca, high_value_addrs=addrs,
        dex_pair_addrs=dex_pairs, cex_addrs=cex_a,
        date_floor=date_floor_clamped,
    )

    try:
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({
                "sql": sql,
                # 4 sources × addrs + headroom for orphan rows.
                "max_rows": max(len(addrs) * 4 + 100, 500),
            }),
            base_timeout=60,
            max_attempts=4,  # v0.7.23 surf-team cooperation pattern
        )
    except Exception as e:
        doc, err = None, f"exception: {str(e)[:120]}"

    if not doc:
        return {
            "attributions": {}, "summary": _empty_summary(),
            "_error": err or "surf returned no doc",
            "_debug": {
                "sql_truncated_addr_n": truncated_n,
                "lookup_window_floor": date_floor_clamped,
                "lookup_window_floor_requested": date_floor,
                "n_dex_pairs_known": len(dex_pairs),
                "n_cex_known": len(cex_a),
            },
        }

    per_addr: dict[str, dict[str, Any]] = {}
    for row in (doc.get("data") or []):
        a = (row.get("addr") or "").lower()
        if not a:
            continue
        src = row.get("source") or "p2p"
        if src not in {"mint", "dex_buy", "cex_withdraw", "p2p"}:
            src = "p2p"
        try:
            amt = float(row.get("amt") or 0)
        except (TypeError, ValueError):
            amt = 0.0
        try:
            n_tx = int(row.get("n_tx") or 0)
        except (TypeError, ValueError):
            n_tx = 0
        bucket = per_addr.setdefault(a, {
            "mint": 0.0, "dex_buy": 0.0, "cex_withdraw": 0.0, "p2p": 0.0,
            "n_tx": {"mint": 0, "dex_buy": 0, "cex_withdraw": 0, "p2p": 0},
        })
        bucket[src] += amt
        bucket["n_tx"][src] = bucket["n_tx"].get(src, 0) + n_tx

    attributions: dict[str, dict[str, Any]] = {}
    n_mining = n_dex = n_p2p = n_cex = 0
    for a in addrs:
        b = per_addr.get(a) or {
            "mint": 0.0, "dex_buy": 0.0, "cex_withdraw": 0.0, "p2p": 0.0,
            "n_tx": {"mint": 0, "dex_buy": 0, "cex_withdraw": 0, "p2p": 0},
        }
        total = b["mint"] + b["dex_buy"] + b["cex_withdraw"] + b["p2p"]
        if total > 0:
            mint_pct = b["mint"] / total
            dex_pct = b["dex_buy"] / total
            cex_pct = b["cex_withdraw"] / total
            p2p_pct = b["p2p"] / total
            primary = max(
                ("mint", "dex_buy", "cex_withdraw", "p2p"),
                key=lambda k: b[k],
            )
        else:
            mint_pct = dex_pct = cex_pct = p2p_pct = None
            primary = None
        is_mining_fed = mint_pct is not None and mint_pct >= 0.50
        attributions[a] = {
            "mint": b["mint"], "dex_buy": b["dex_buy"],
            "cex_withdraw": b["cex_withdraw"], "p2p": b["p2p"],
            "n_tx": b["n_tx"], "total": total,
            "mint_pct": mint_pct, "dex_buy_pct": dex_pct,
            "cex_withdraw_pct": cex_pct, "p2p_pct": p2p_pct,
            "primary_source": primary,
            "is_mining_fed": is_mining_fed,
        }
        if primary == "mint":
            n_mining += 1
        elif primary == "dex_buy":
            n_dex += 1
        elif primary == "p2p":
            n_p2p += 1
        elif primary == "cex_withdraw":
            n_cex += 1

    summary = {
        "n_addrs_queried": len(addrs),
        "n_addrs_with_data": sum(1 for v in attributions.values() if v["total"] > 0),
        "n_mining_fed": n_mining,
        "n_dex_fed": n_dex,
        "n_p2p_fed": n_p2p,
        "n_cex_fed": n_cex,
    }

    return {
        "attributions": attributions, "summary": summary,
        "_debug": {
            "sql_truncated_addr_n": truncated_n,
            "lookup_window_floor": date_floor_clamped,
            "lookup_window_floor_requested": date_floor,
            "n_dex_pairs_known": len(dex_pairs),
            "n_cex_known": len(cex_a),
        },
    }


# ---------------------------------------------------------------------------
# v0.7.23.2: mining-fed wallet outflow detector
# ---------------------------------------------------------------------------
#
# attribute_funding() above tells us which high-value addresses received their
# tokens via mint (= are operators of bridge / mining / vesting contracts).
# v0.7.23.1 stopped there — the report flagged mining-fed wallets but didn't
# tell retail what they DID with the tokens. Now we follow up: for each
# mining-fed address, query its 365d DEX swap-sells (token_sold = ca,
# tx_from = addr) and its outgoing transfer destinations. That tells the
# reader "operator X received Y tokens from mint, dumped Z on DEX for $USD,
# routed W to destinations D1/D2/D3". This is the data dump_tracker (a)(b)
# would have surfaced if rule_11's m6 had been populated; here we recover it
# from the funding-attribution result instead, fixing the false-zero on
# mining-token forensic runs.

# v0.7.24a: discover mint authorities — top from-0x0 minters by amount in
# 365d window. Mint authorities are bridge/staking/airdrop contracts that
# physically issue new supply on-chain. They are NOT necessarily in the
# high_value_addrs set that attribute_funding scans (they only receive 0x0
# transfers, not P2P), so the v0.7.23.x mining_fed_outflows path misses
# them. Specifically: 0x6aa22cb8 (H bridge contract) minted 132.5B H over
# 30d and self-DEX-dumped 19.8B (≈ $3M) — never surfaced before.
_SQL_FIND_MINT_AUTHORITIES = """SELECT "to" AS authority, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS total_minted, count() AS n_mints FROM {transfers} WHERE contract_address = '{ca_lc}' AND "from" = '0x0000000000000000000000000000000000000000' AND block_date >= '{date_floor}' GROUP BY authority ORDER BY total_minted DESC LIMIT {top_n}"""

_SQL_MINING_FED_DEX_SELL = """SELECT tx_from AS addr, count() AS n_swaps, sum(token_sold_amount) AS tokens_sold, sum(if(amount_usd > 0, amount_usd, 0)) AS sold_usd FROM {dex_trades} WHERE token_sold_address = '{ca_lc}' AND tx_from IN {in_list} AND block_date >= '{date_floor}' GROUP BY addr ORDER BY tokens_sold DESC"""

_SQL_MINING_FED_OUTFLOWS = """SELECT "from" AS src, "to" AS dest, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt, count() AS n_tx FROM {transfers} WHERE contract_address = '{ca_lc}' AND "from" IN {in_list} AND "to" != '0x0000000000000000000000000000000000000000' AND "to" != '0x000000000000000000000000000000000000dead' AND block_date >= '{date_floor}' GROUP BY src, dest ORDER BY amt DESC LIMIT 200"""

# v0.7.24e.1: merged outflows + balances in 1 UNION ALL SQL. Both query
# the same transfers partition (contract + block_date filter) so
# ClickHouse can scan once. Row type marked by `rt` column. Python pivots.
# Saves 1 surf round-trip + 1 credit per query_mining_fed_outflows call
# (and v0.7.24a mint_authority_dumps reuses same helper → 2 saves total
# per pipeline).
_SQL_MINING_FED_TRANSFERS_MERGED = """WITH ins AS (SELECT "to" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date >= '{date_floor}' AND "to" IN {in_list} GROUP BY a), outs AS (SELECT "from" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date >= '{date_floor}' AND "from" IN {in_list} GROUP BY a) SELECT 'balance' AS rt, r.a AS src, '' AS dest, COALESCE(ins.amt, 0) AS amt, 0 AS n_tx, COALESCE(ins.amt, 0) - COALESCE(outs.amt, 0) AS balance, COALESCE(outs.amt, 0) AS total_out FROM (SELECT arrayJoin({array_list}) AS a) r LEFT JOIN ins ON r.a = ins.a LEFT JOIN outs ON r.a = outs.a UNION ALL SELECT 'outflow' AS rt, "from" AS src, "to" AS dest, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt, count() AS n_tx, 0 AS balance, 0 AS total_out FROM {transfers} WHERE contract_address = '{ca_lc}' AND "from" IN {in_list} AND "to" != '0x0000000000000000000000000000000000000000' AND "to" != '0x000000000000000000000000000000000000dead' AND block_date >= '{date_floor}' GROUP BY src, dest"""

# v0.7.23.4: per-addr current balance = sum(in) − sum(out) over the 365d
# window. Mining-fed wallets fully unwound (balance ≈ 0 after dump) read as
# "已 dump 完毕" stock; wallets still holding read as "还在累积/未完全出货".
_SQL_MINING_FED_BALANCES = """WITH ins AS (SELECT "to" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date >= '{date_floor}' AND "to" IN {in_list} GROUP BY a), outs AS (SELECT "from" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date >= '{date_floor}' AND "from" IN {in_list} GROUP BY a) SELECT r.a AS addr, COALESCE(ins.amt, 0) AS total_in, COALESCE(outs.amt, 0) AS total_out, COALESCE(ins.amt, 0) - COALESCE(outs.amt, 0) AS balance FROM (SELECT arrayJoin({array_list}) AS a) r LEFT JOIN ins ON r.a = ins.a LEFT JOIN outs ON r.a = outs.a"""


def query_mining_fed_outflows(
    *,
    ca: str,
    mining_fed_addrs: list[str],
    date_floor: str = "2020-01-01",
    max_addrs: int = 30,
) -> dict[str, Any]:
    """For each mining-fed address, surface DEX dump activity + top
    outflow destinations.

    Args:
        ca: contract address.
        mining_fed_addrs: addresses with is_mining_fed=True from
            attribute_funding(). Capped to max_addrs (mining-fed
            addresses are typically <10 per token; cap defends against
            pathological cases).
        date_floor: 'YYYY-MM-DD'. Same surf 365-day window clamp as
            attribute_funding.
        max_addrs: hard cap.

    Returns dict:
        per_addr: {
          addr: {
            "dex_sells": {"n_swaps": int, "tokens_sold": float,
                          "sold_usd": float},
            "top_destinations": [
              {"dest": addr, "amt": float, "n_tx": int}, ...
            ],
            "total_outflow_tokens": float,
          }
        }
        summary: {
          "n_addrs_with_dex_sells": int,
          "total_dex_sold_tokens": float,
          "total_dex_sold_usd": float,
          "total_outflow_tokens": float,
        }
        _debug, _error (on hard failure).
    """
    ca = (ca or "").lower()
    if not ca or not _chain_is_valid_addr(ca):
        return {
            "per_addr": {}, "summary": _empty_mfo_summary(),
            "_error": f"invalid ca: {ca!r}",
        }

    addrs = _clean_addrs(mining_fed_addrs)
    truncated_n = max(0, len(addrs) - max_addrs)
    addrs = addrs[:max_addrs]
    if not addrs:
        return {
            "per_addr": {}, "summary": _empty_mfo_summary(),
            "_debug": {"sql_truncated_addr_n": truncated_n,
                       "lookup_window_floor": date_floor},
        }

    # Clamp to surf 365-day window (same logic as attribute_funding).
    surf_window_floor = (date.today() - timedelta(days=_SURF_MAX_LOOKBACK_DAYS)).isoformat()
    date_floor_clamped = surf_window_floor if date_floor < surf_window_floor else date_floor

    in_list = "(" + ",".join(f"'{a}'" for a in addrs) + ")"
    array_list = "[" + ",".join(f"'{a}'" for a in addrs) + "]"
    sql_sell = _SQL_MINING_FED_DEX_SELL.format(
        dex_trades=dex_trades_table(), decimals_factor=decimals_factor_str(), ca_lc=ca,
        in_list=in_list, date_floor=date_floor_clamped,
    )
    # v0.7.24e.1: merged outflows + balances into 1 SQL (UNION ALL)
    sql_transfers_merged = _SQL_MINING_FED_TRANSFERS_MERGED.format(
        transfers=transfers_table(), decimals_factor=decimals_factor_str(), ca_lc=ca,
        in_list=in_list, array_list=array_list,
        date_floor=date_floor_clamped,
    )

    try:
        from section_a_scope import _run_surf_with_retry
        doc_sell, err_sell = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql_sell, "max_rows": max_addrs + 10}),
            base_timeout=60, max_attempts=4,
        )
        doc_transfers, err_transfers = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql_transfers_merged, "max_rows": max_addrs + 210}),
            base_timeout=60, max_attempts=4,
        )
    except Exception as e:
        return {
            "per_addr": {}, "summary": _empty_mfo_summary(),
            "_error": f"exception: {str(e)[:120]}",
            "_debug": {"sql_truncated_addr_n": truncated_n,
                       "lookup_window_floor": date_floor_clamped},
        }

    if not doc_sell and not doc_transfers:
        return {
            "per_addr": {}, "summary": _empty_mfo_summary(),
            "_error": f"both queries failed: sell={err_sell}; transfers={err_transfers}",
            "_debug": {"sql_truncated_addr_n": truncated_n,
                       "lookup_window_floor": date_floor_clamped},
        }

    # v0.7.24e.1: split merged result by rt column → simulate doc_bal + doc_out
    # Same per-row schema as before so downstream loops untouched.
    doc_bal = None
    doc_out = None
    if doc_transfers:
        bal_rows = []
        out_rows = []
        for r in (doc_transfers.get("data") or []):
            rt = (r.get("rt") or "")
            if rt == "balance":
                bal_rows.append({
                    "addr": r.get("src"),
                    "total_in": r.get("amt"),
                    "total_out": r.get("total_out"),
                    "balance": r.get("balance"),
                })
            elif rt == "outflow":
                out_rows.append({
                    "src": r.get("src"), "dest": r.get("dest"),
                    "amt": r.get("amt"), "n_tx": r.get("n_tx"),
                })
        # Sort outflows by amt desc + apply implicit LIMIT 200 (Python-side
        # since UNION ALL can't have per-branch LIMIT without subquery)
        out_rows.sort(key=lambda r: float(r.get("amt") or 0), reverse=True)
        doc_bal = {"data": bal_rows}
        doc_out = {"data": out_rows[:200]}

    per_addr: dict[str, dict[str, Any]] = {a: {
        "dex_sells": {"n_swaps": 0, "tokens_sold": 0.0, "sold_usd": 0.0},
        "top_destinations": [],
        "total_outflow_tokens": 0.0,
        # v0.7.23.4: current balance (in − out over 365d window). For
        # mining-fed wallets that fully unwound, balance ≈ 0 reads as
        # "dumped clean"; balance > 0 means operator still sitting on
        # unsold mint.
        "current_balance": 0.0,
        "total_in_365d": 0.0,
        "total_out_365d": 0.0,
    } for a in addrs}

    # v0.7.23.4: stitch in per-addr balance from the third query
    if doc_bal:
        for row in (doc_bal.get("data") or []):
            a = (row.get("addr") or "").lower()
            if a not in per_addr:
                continue
            try:
                per_addr[a]["current_balance"] = float(row.get("balance") or 0)
                per_addr[a]["total_in_365d"] = float(row.get("total_in") or 0)
                per_addr[a]["total_out_365d"] = float(row.get("total_out") or 0)
            except (TypeError, ValueError):
                pass

    if doc_sell:
        for row in (doc_sell.get("data") or []):
            a = (row.get("addr") or "").lower()
            if a not in per_addr:
                continue
            per_addr[a]["dex_sells"] = {
                "n_swaps": int(row.get("n_swaps") or 0),
                "tokens_sold": float(row.get("tokens_sold") or 0),
                "sold_usd": float(row.get("sold_usd") or 0),
            }

    if doc_out:
        # Group outflows by source addr, keep top destinations per source.
        for row in (doc_out.get("data") or []):
            src = (row.get("src") or "").lower()
            dest = (row.get("dest") or "").lower()
            amt = float(row.get("amt") or 0)
            n_tx = int(row.get("n_tx") or 0)
            if src not in per_addr or amt <= 0:
                continue
            per_addr[src]["total_outflow_tokens"] += amt
            per_addr[src]["top_destinations"].append({
                "dest": dest, "amt": amt, "n_tx": n_tx,
            })
        # Trim each addr's top destinations to top 5
        # v0.8.2.2 audit HIGH #1 fix: also expose true destination
        # count (before slicing) so fake_mining_detector can gate the
        # `low_destination_count` signal on actual data, not the trimmed
        # top 5. Without this every clamped slice always tripped the
        # signal and real mining distributions would mis-fire.
        for a, v in per_addr.items():
            v["top_destinations"].sort(key=lambda d: d["amt"], reverse=True)
            v["n_destinations_total"] = len(v["top_destinations"])
            v["top_destinations"] = v["top_destinations"][:5]

    summary = {
        "n_addrs_with_dex_sells": sum(
            1 for v in per_addr.values() if v["dex_sells"]["n_swaps"] > 0
        ),
        "total_dex_sold_tokens": sum(
            v["dex_sells"]["tokens_sold"] for v in per_addr.values()
        ),
        "total_dex_sold_usd": sum(
            v["dex_sells"]["sold_usd"] for v in per_addr.values()
        ),
        "total_outflow_tokens": sum(
            v["total_outflow_tokens"] for v in per_addr.values()
        ),
        # v0.7.23.4: aggregate current balance across all mining-fed wallets.
        # Reads as "operator pool still sitting on this much potential dump."
        "total_current_balance": sum(
            v["current_balance"] for v in per_addr.values()
        ),
        "n_addrs": len(per_addr),
    }
    return {
        "per_addr": per_addr, "summary": summary,
        "_debug": {
            "sql_truncated_addr_n": truncated_n,
            "lookup_window_floor": date_floor_clamped,
            "lookup_window_floor_requested": date_floor,
        },
    }


def _empty_mfo_summary() -> dict[str, Any]:
    return {
        "n_addrs_with_dex_sells": 0,
        "total_dex_sold_tokens": 0.0,
        "total_dex_sold_usd": 0.0,
        "total_outflow_tokens": 0.0,
    }


def discover_mint_authorities(
    *,
    ca: str,
    date_floor: str = "2020-01-01",
    exclude_addrs: list[str] | None = None,
    top_n: int = 10,
    min_pct_supply: float = 0.001,
    total_supply: float | None = None,
) -> dict[str, Any]:
    """v0.7.24a: enumerate top mint authorities (top from-0x0 minters).

    Bridge / staking / airdrop / vesting contracts that issue new supply by
    receiving from the zero address. Distinct from "deployer" (which the
    project may name as the human EOA placeholder) and distinct from
    "mining-fed wallets" (which receive their tokens from mint authorities,
    not from 0x0 directly).

    Args:
        ca: contract address.
        date_floor: 'YYYY-MM-DD'. Same surf 365-day window clamp.
        exclude_addrs: deployer + already-known mining-fed addrs to skip
            (we don't want to double-count their dump activity in the
            downstream render).
        top_n: SQL LIMIT on minter list.
        min_pct_supply: drop authorities that mint less than this fraction
            of total_supply (filters noise — small mint sources like
            occasional reward drips).
        total_supply: Alpha-API nominal supply. Used to compute mint_pct
            per authority and to filter via min_pct_supply.

    Returns dict:
        authorities: list of {addr, total_minted, mint_pct_supply,
                              n_mints, is_excluded: bool}
        summary: {n_authorities, total_minted_aggregate}
        _debug: {sql_floor, exclude_n}
        _error: only on hard failure.
    """
    ca = (ca or "").lower()
    if not ca or not _chain_is_valid_addr(ca):
        return {
            "authorities": [], "summary": {
                "n_authorities": 0, "total_minted_aggregate": 0.0,
            },
            "_error": f"invalid ca: {ca!r}",
        }

    surf_window_floor = (date.today() - timedelta(days=_SURF_MAX_LOOKBACK_DAYS)).isoformat()
    date_floor_clamped = surf_window_floor if date_floor < surf_window_floor else date_floor

    exclude_set = {a.lower() for a in _clean_addrs(exclude_addrs)}

    sql = _SQL_FIND_MINT_AUTHORITIES.format(
        transfers=transfers_table(), decimals_factor=decimals_factor_str(), ca_lc=ca,
        date_floor=date_floor_clamped, top_n=top_n,
    )

    try:
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": top_n + 10}),
            base_timeout=60, max_attempts=4,
        )
    except Exception as e:
        return {
            "authorities": [], "summary": {
                "n_authorities": 0, "total_minted_aggregate": 0.0,
            },
            "_error": f"exception: {str(e)[:120]}",
        }

    if not doc:
        return {
            "authorities": [], "summary": {
                "n_authorities": 0, "total_minted_aggregate": 0.0,
            },
            "_error": err or "surf returned no doc",
        }

    authorities: list[dict[str, Any]] = []
    total_minted_agg = 0.0
    min_amt = (total_supply * min_pct_supply) if total_supply else 0.0
    for row in (doc.get("data") or []):
        addr = (row.get("authority") or "").lower()
        if not _chain_is_valid_addr(addr) or addr in _DEAD:
            continue
        try:
            amt = float(row.get("total_minted") or 0)
            n_mints = int(row.get("n_mints") or 0)
        except (TypeError, ValueError):
            continue
        if amt < min_amt:
            continue
        mint_pct = (amt / total_supply * 100) if (total_supply and total_supply > 0) else None
        is_excluded = addr in exclude_set
        authorities.append({
            "addr": addr,
            "total_minted": amt,
            "mint_pct_supply": mint_pct,
            "n_mints": n_mints,
            "is_excluded": is_excluded,
        })
        if not is_excluded:
            total_minted_agg += amt

    return {
        "authorities": authorities,
        "summary": {
            "n_authorities": sum(1 for a in authorities if not a["is_excluded"]),
            "total_minted_aggregate": total_minted_agg,
        },
        "_debug": {
            "sql_floor": date_floor_clamped,
            "exclude_n": len(exclude_set),
            "min_pct_supply_filter": min_pct_supply,
        },
    }


# v0.7.24b: high-throughput dump trace SQL — detect wallets that received
# a large quantity of tokens but cleared out (balance ≈ 0), via many txs.
# Catches sss_crypto's @sss_crypto thread addresses (0x47a6e4e1: 79k tx,
# 30.6M throughput, 0 balance) which all existing detectors miss because:
#  - rule_11: deployer placeholder, m6 empty
#  - wash_infra: pattern is not atomic
#  - flow_operators: 60d window (these dumped 60d ago)
#  - mining_fed: balance is below the mint-fed threshold (they receive
#    via p2p from authorities, not directly from 0x0)
#  - mint_authority: they're receivers, not 0x0-issuers
#  - top_holders: balance ≈ 0 keeps them off top-30
_SQL_HIGH_THROUGHPUT = """WITH ins AS (SELECT "to" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt_in, count() AS n_in FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date >= '{date_floor}' GROUP BY addr), outs AS (SELECT "from" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt_out, count() AS n_out FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date >= '{date_floor}' GROUP BY addr) SELECT ins.addr, ins.amt_in AS total_in, COALESCE(outs.amt_out, 0) AS total_out, ins.amt_in - COALESCE(outs.amt_out, 0) AS balance, ins.n_in + COALESCE(outs.n_out, 0) AS n_tx FROM ins LEFT JOIN outs ON ins.addr = outs.addr WHERE ins.amt_in >= {min_throughput} AND ins.amt_in <= {max_throughput} AND abs(ins.amt_in - COALESCE(outs.amt_out, 0)) < ins.amt_in * {max_balance_frac} AND ins.n_in + COALESCE(outs.n_out, 0) >= {min_n_tx} AND ins.addr != '0x0000000000000000000000000000000000000000' AND ins.addr != '0x000000000000000000000000000000000000dead' ORDER BY ins.amt_in DESC LIMIT {top_n}"""

# v0.9.4 + audit fixes: chunkable variant. Per-chunk SQL uses BETWEEN
# (partition pruning) so each chunk only scans ~30d of bsc_transfers. The
# 2-layer CTE form is preserved per chunk because at 30d window the ins/outs
# materialization is small enough that ClickHouse handles it inside 30s.
#
# Filters that survive per-chunk:
#   - addr != 0x0 / 0xdead (correctness — these are noise)
#   - amt_in >= chunk_min_in (1% floor of global threshold; bounds result
#     size without divisor undercount, see chunk_min_in comment)
#   - amt_in <= max_throughput (adversarial review Fix 2: this filter is MONOTONIC —
#     per-chunk amt_in ≤ global amt_in, so per-chunk > max implies global
#     > max. Safe to pre-filter at SQL. Without this, wash bots with huge
#     per-chunk amt_in fill the LIMIT and push real operators out.)
#
# Filters MOVED to Python post-merge (cannot apply per-chunk correctly):
#   - min_throughput (totals only known after merge)
#   - max_balance_frac (balance = sum_in - sum_out, totals)
#   - min_n_tx (count distributes via merge)
#   - ORDER BY amt_in DESC LIMIT top_n (global top)
#
# chunk_top_n is a per-chunk safety cap. Caller queries LIMIT chunk_top_n+1
# and fails loud if exactly chunk_top_n+1 rows returned (adversarial review Fix 2:
# truncation detection — capped chunk = incomplete merge input, must NOT
# emit clean empty findings).
_SQL_HIGH_THROUGHPUT_CHUNK = """WITH ins AS (SELECT "to" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt_in, count() AS n_in FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}' GROUP BY addr), outs AS (SELECT "from" AS addr, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt_out, count() AS n_out FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}' GROUP BY addr) SELECT ins.addr AS addr, ins.amt_in AS total_in, COALESCE(outs.amt_out, 0) AS total_out, ins.n_in AS n_in, COALESCE(outs.n_out, 0) AS n_out FROM ins LEFT JOIN outs ON ins.addr = outs.addr WHERE ins.amt_in >= {chunk_min_in} AND ins.amt_in <= {max_throughput} AND ins.addr != '0x0000000000000000000000000000000000000000' AND ins.addr != '0x000000000000000000000000000000000000dead' ORDER BY ins.amt_in DESC LIMIT {chunk_top_n_plus_1}"""


def discover_high_throughput_dumpers(
    *,
    ca: str,
    date_floor: str = "2020-01-01",
    exclude_addrs: list[str] | None = None,
    min_throughput: float = 1_000_000.0,
    max_throughput: float | None = None,
    max_balance_frac: float = 0.05,
    min_n_tx: int = 1000,
    top_n: int = 50,
    total_supply: float | None = None,
) -> dict[str, Any]:
    """v0.7.24b: enumerate wallets with high-throughput / clean-dump pattern.

    Detect operator wallets that have ingested a large quantity of tokens
    over the 365d window but cleared out (balance ≈ 0), via many txs. The
    sss_crypto Twitter forensic thread on H called out exactly this pattern:
    0x47a6e4e1 received 30.6M, sent 30.5M (residual 0.09M), 79,048 txs over
    365d. These operators are deliberately invisible to:
      - rule_11 (deployer placeholder model)
      - wash_infra (P→X→Q async, not atomic)
      - flow_operators (60d window misses earlier dump)
      - mining_fed (receive via p2p from authorities, not directly from 0x0)
      - mint_authority (they're receivers, not 0x0-issuers)
      - top_holders (balance ≈ 0 keeps them off the table)

    Default thresholds tuned to H/sss_crypto cohort:
      - min_throughput=1M: filters small dust; 0x47a6e4e1 has 30.6M
      - max_balance_frac=0.05: balance within 5% of throughput counts as
        "cleared out"; 0x47a6e4e1 has 92k residual on 30.6M = 0.3%
      - min_n_tx=1000: filters one-shot transfers; 0x47a6e4e1 has 79k

    Args:
        ca: contract address.
        date_floor: 'YYYY-MM-DD', surf 365d window clamp applied.
        exclude_addrs: addrs already covered by other detectors (mining-fed,
            mint authority, deployer) — don't double-surface them.
        min_throughput: minimum tokens received in window.
        max_balance_frac: fraction of throughput allowed as residual balance.
        min_n_tx: minimum (in_count + out_count) tx count.
        top_n: SQL LIMIT (cap on output rows).

    Returns:
        {
          "dumpers": list of {addr, total_in, total_out, balance, n_tx,
                              throughput_pct_supply, is_excluded},
          "summary": {n_dumpers, total_throughput, total_throughput_pct_supply},
          "_debug": {date_floor_clamped, min_throughput, ...},
          "_error": only on hard failure.
        }
    """
    ca = (ca or "").lower()
    if not ca or not _chain_is_valid_addr(ca):
        return {
            "dumpers": [], "summary": {
                "n_dumpers": 0, "total_throughput": 0.0,
            },
            "_error": f"invalid ca: {ca!r}",
        }

    surf_window_floor = (date.today() - timedelta(days=_SURF_MAX_LOOKBACK_DAYS)).isoformat()
    date_floor_clamped = surf_window_floor if date_floor < surf_window_floor else date_floor
    exclude_set = {a.lower() for a in _clean_addrs(exclude_addrs)}

    # v0.7.24b filter: wash bots can churn 100M-8B tokens (1-80% of nominal
    # supply churned multiple times). They are NOT clean-dump operators —
    # they cycle the same liquidity many times. Operator allocation dumps
    # (sss_crypto thread profile: 0x47a6e4e1 = 30M / 0.3% nominal) sit
    # below 5% of nominal supply. Default cap = 5% of nominal supply.
    # Above that, the wallet is almost certainly a wash bot / MM / DEX
    # router, not a one-shot operator wallet liquidating an allocation.
    if max_throughput is None:
        max_throughput = (float(total_supply) * 0.05) if total_supply else 5e17

    # v0.9.4 + audit fix 5: chunked path for long windows. Short windows
    # collapse to a single chunk → SQL shape preserved as BETWEEN, identical
    # behavior to v0.9.3 single-shot. Long windows split to 30d chunks
    # (NOT 90d — funding_attribution heavy CTE is per-chunk heavier than
    # rule_11's selective mint queries, so 90d may still hit 30s budget on
    # EVAA-class tokens. 30d × 12-13 chunks is a known-safe budget).
    transfers = transfers_table()
    chunks = _single_chunk_or_chunker_dates(date_floor_clamped, None, chunk_days=30)
    # Per-chunk min_in floor: use 1% of global threshold (NOT divide by
    # N_chunks). Reason: an N_chunks divisor undercounts wallets whose
    # throughput is uneven across chunks. 1% floor (= 10K for 1M threshold)
    # keeps all chunks contributing to the global total. Hard floor 1000
    # to bound result size on partitions with millions of dust addrs.
    chunk_min_in = max(1000.0, float(min_throughput) * 0.01)
    # v0.9.4 round-2 adversarial review Fix 1: cap chunk_top_n below surf 10K max_rows
    # ceiling. Naïve top_n * 100 with default top_n=100 yields 10000 →
    # LIMIT 10001 → max_rows 10010 → every chunk rejected. Stay safe.
    chunk_top_n = min(top_n * 100, _SURF_SAFE_MAX_ROWS - 10)

    def _sql_fn(chunk_floor: str, chunk_ceiling: str) -> dict[str, Any]:
        # adversarial review Fix 2: LIMIT chunk_top_n + 1. If response has exactly
        # that many rows, the chunk was capped → not a complete merge
        # input → must propagate as truncation error, not silently merge.
        sql = _SQL_HIGH_THROUGHPUT_CHUNK.format(
            transfers=transfers, ca_lc=ca,
            chunk_floor=chunk_floor, chunk_ceiling=chunk_ceiling,
            chunk_min_in=chunk_min_in, max_throughput=max_throughput,
            chunk_top_n_plus_1=chunk_top_n + 1,
         decimals_factor=decimals_factor_str())
        return _run_chunk_via_surf(sql, max_rows=chunk_top_n + 10, base_timeout=40)

    chunk_results = parallel_run_chunked(_sql_fn, chunks)
    errs = [r.get("_error") for r in chunk_results if r.get("_error")]
    rows_per_chunk = [r.get("data") or [] for r in chunk_results]

    # adversarial review Fix 2: detect per-chunk truncation. If any chunk returned
    # exactly chunk_top_n + 1 rows, the LIMIT was hit → chunk's contribution
    # to the global merge is incomplete → fail loud.
    truncated_chunks = sum(
        1 for r in rows_per_chunk if len(r) > chunk_top_n
    )

    # adversarial review Fix 1 (CRITICAL): partial chunk error → empty + _error. v0.9.3
    # single-shot semantics were "either complete data or hard error" —
    # silently returning partial data from k of N chunks is a NEW silent
    # failure mode where a true operator concentrated in the failing chunk
    # vanishes from the result. Match v0.9.3 strictness: any chunk error
    # → empty result + _error so caller behaves the same as before.
    if errs or truncated_chunks > 0:
        return {
            "dumpers": [], "summary": {
                "n_dumpers": 0, "total_throughput": 0.0,
            },
            "_error": (
                f"{len(errs)}/{len(chunks)} chunks errored, "
                f"{truncated_chunks}/{len(chunks)} chunks truncated at LIMIT; "
                f"first chunk error: {errs[0] if errs else 'none'}"
            ),
            "_debug": {
                "date_floor_clamped": date_floor_clamped,
                "chunks": chunk_summary(chunks),
                "chunk_errs": len(errs),
                "chunk_truncated": truncated_chunks,
            },
        }

    # Merge by addr — SUM is distributive over the chunk partition.
    # n_in / n_out are per-chunk counts; total n_tx = sum(n_in)+sum(n_out).
    merged = merge_chunked_rows(
        rows_per_chunk, key_field="addr",
        sum_fields=["total_in", "total_out", "n_in", "n_out"],
    )

    # Apply Python-side filters (moved from SQL HAVING / WHERE):
    #   min_throughput / max_throughput, max_balance_frac, min_n_tx
    # Order by total_in DESC, LIMIT top_n — matches v0.9.3 single-shot
    # ORDER BY ins.amt_in DESC LIMIT top_n semantics.
    dumpers: list[dict[str, Any]] = []
    total_through = 0.0
    for r in merged:
        addr = (r.get("addr") or "").lower()
        if not _chain_is_valid_addr(addr) or addr in _DEAD:
            continue
        tin = float(r.get("total_in") or 0)
        tout = float(r.get("total_out") or 0)
        bal = tin - tout
        n_tx = int((r.get("n_in") or 0) + (r.get("n_out") or 0))
        # Python-side filters (parity with v0.9.3 SQL HAVING):
        if tin < min_throughput or tin > max_throughput:
            continue
        if tin > 0 and abs(bal) >= tin * max_balance_frac:
            continue
        if n_tx < min_n_tx:
            continue
        is_excluded = addr in exclude_set
        dumpers.append({
            "addr": addr,
            "total_in": tin,
            "total_out": tout,
            "balance": bal,
            "n_tx": n_tx,
            "is_excluded": is_excluded,
        })
    # Sort + LIMIT (matches v0.9.3 ORDER BY ins.amt_in DESC LIMIT top_n)
    dumpers.sort(key=lambda d: d["total_in"], reverse=True)
    dumpers = dumpers[:top_n]
    for d in dumpers:
        if not d["is_excluded"]:
            total_through += d["total_in"]

    return {
        "dumpers": dumpers,
        "summary": {
            "n_dumpers": sum(1 for d in dumpers if not d["is_excluded"]),
            "total_throughput": total_through,
        },
        "_debug": {
            "date_floor_clamped": date_floor_clamped,
            "min_throughput": min_throughput,
            "max_balance_frac": max_balance_frac,
            "min_n_tx": min_n_tx,
            "exclude_n": len(exclude_set),
            "chunks": chunk_summary(chunks),
            "chunk_min_in": chunk_min_in,
            "chunk_errs": len(errs),
        },
    }


# v0.7.24e: CEX deposit fan-out detector — catch sss_crypto Twitter thread
# profile (BEAT 2026-05-21: Gate.io 热钱包 → 1 hub → 10 sub-wallets each
# holding 0.1%+ supply). Pattern: operator pulls allocation from CEX hot
# wallet, routes through one intermediate hub, splits to N fresh wallets
# to disperse top100 concentration signal.
#
# Two-phase SQL: (1) find hub candidates by fan-out signature, (2) per-hub
# senders + recipients. Python label filter narrows to true CEX-origin
# fan-out.
_SQL_FANOUT_HUB_CANDIDATES = """WITH recipient_amounts AS (SELECT "from" AS hub, "to" AS recipient, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS rec_amt FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date >= '{date_floor}' AND "to" != '0x0000000000000000000000000000000000000000' AND "to" != '0x000000000000000000000000000000000000dead' GROUP BY hub, recipient HAVING rec_amt >= {min_per_recipient}) SELECT hub, count() AS n_recipients, sum(rec_amt) AS total_out, min(rec_amt) AS min_per, avg(rec_amt) AS avg_per FROM recipient_amounts GROUP BY hub HAVING n_recipients BETWEEN {min_recipients} AND {max_recipients} AND total_out >= {min_total_out} ORDER BY total_out DESC LIMIT {top_n}"""

# v0.9.4 + audit fixes: chunkable variant. Per-chunk SQL outputs raw
# (hub, recipient, rec_amt) pairs — the outer GROUP BY hub + hub-level
# HAVING happens entirely in Python after the per-(hub, recipient) merge.
#
# Per-chunk filter `rec_amt >= chunk_min_rec_amt` uses a 1% floor (NOT
# N_chunks divisor — see discover_high_throughput_dumpers comment for
# undercount-avoidance rationale). addr != 0x0 / 0xdead enforced in WHERE
# rather than HAVING (same effect, cheaper on the ClickHouse plan).
#
# LIMIT chunk_top_pairs+1: adversarial review Fix 3 — caller queries with +1 cap and
# fails loud if exactly chunk_top_pairs+1 rows returned (truncation
# detected). Without truncation detect, a capped chunk silently feeds
# incomplete data to the hub merge, where junk pairs can mask a real
# operator hub.
_SQL_FANOUT_HUB_CANDIDATES_CHUNK = """SELECT "from" AS hub, "to" AS recipient, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS rec_amt FROM {transfers} WHERE contract_address = '{ca_lc}' AND block_date BETWEEN '{chunk_floor}' AND '{chunk_ceiling}' AND "to" != '0x0000000000000000000000000000000000000000' AND "to" != '0x000000000000000000000000000000000000dead' GROUP BY hub, recipient HAVING rec_amt >= {chunk_min_rec_amt} ORDER BY rec_amt DESC LIMIT {chunk_top_pairs_plus_1}"""

# v0.7.24e.1: merge senders + recipients into 1 UNION ALL SQL.
# Both subqueries use IN {hub_in_list} on the same transfers table /
# date_floor; ClickHouse scans the partition once for the union. Saves
# 1 round-trip + 1 surf credit. Output rows tagged by `rt` column
# ('sender' or 'recipient'), Python pivots by rt.
# v0.8.1 audit CRITICAL fix: the original UNION ALL query shared
# one max_rows budget between sender + recipient rows, with no ORDER BY,
# so a hub with many small recipients could silently truncate (top
# senders could even be dropped). Split into two queries with explicit
# ORDER BY amt DESC + sentinel rows so the caller can detect truncation
# and fail-loud rather than emit a stale net metric.
_SQL_FANOUT_HUB_SENDERS = """SELECT "to" AS hub, "from" AS counterparty, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt, count() AS n_tx, min(block_time) AS first_tx FROM {transfers} WHERE contract_address = '{ca_lc}' AND "to" IN {hub_in_list} AND block_date >= '{date_floor}' GROUP BY hub, counterparty ORDER BY amt DESC"""
_SQL_FANOUT_HUB_RECIPIENTS = """SELECT "from" AS hub, "to" AS counterparty, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor}) AS amt, count() AS n_tx, min(block_time) AS first_tx FROM {transfers} WHERE contract_address = '{ca_lc}' AND "from" IN {hub_in_list} AND block_date >= '{date_floor}' AND "to" != '0x0000000000000000000000000000000000000000' AND "to" != '0x000000000000000000000000000000000000dead' GROUP BY hub, counterparty ORDER BY amt DESC"""


def discover_cex_fanout_hubs(
    *,
    ca: str,
    date_floor: str = "2020-01-01",
    min_recipients: int = 5,
    max_recipients: int = 50,
    min_per_recipient: float = 100_000.0,
    min_total_out: float = 1_000_000.0,
    top_n_hubs: int = 30,
    max_recipients_per_hub_display: int = 20,
) -> dict[str, Any]:
    """v0.7.24e: detect CEX-deposit fan-out hubs.

    sss_crypto's BEAT thread (2026-05-21) catalogued the pattern: 11.4M
    BEAT pulled from Gate hot wallet → 1 intermediate hub → 10 sub-wallets
    each holding 0.1%+ supply. Designed to disperse top100 concentration
    signal so retail sees "well-distributed" holders. Our existing
    detectors miss it: rule_11 looks at deployer mint origin, mint_authority
    looks at 0x0 transfers, high_throughput needs n_tx ≥ 1000 (these hubs
    have ~11 txs total).

    Filter: hub has 5-50 recipients each receiving ≥ 100K tokens AND total
    outflow ≥ 1M tokens. Then per-hub, the TOP sender must be a
    CEX_DEPOSIT or CEX_HOT_WALLET classified address (Arkham label). DEX
    routers / mint contracts excluded by this filter.

    Args:
        ca: contract address.
        date_floor: 'YYYY-MM-DD', surf 365d window clamp applied.
        min_recipients/max_recipients: tunable hub fan-out range.
        min_per_recipient: each recipient must receive ≥ this many tokens
            (filters DEX routers' dust transfers to retail buyers).
        min_total_out: hub outflow must be ≥ this total.
        top_n_hubs: SQL LIMIT for hub candidates.
        max_recipients_per_hub_display: cap recipient list per hub in output.

    Returns:
        {
          "hubs": [{addr, n_recipients, total_out_tokens, cex_source, cex_source_label,
                    cex_source_inflow_tokens, top_recipients: [{addr, amt, n_tx}], ...}],
          "summary": {
              "n_confirmed_hubs": int,
              "n_candidate_hubs": int,
              "total_cex_inflow_tokens": float,
              "total_fanout_recipients": int,
          },
          "_debug": {date_floor_clamped, ...},
          "_error": only on hard failure.
        }
    """
    ca = (ca or "").lower()
    if not ca or not _chain_is_valid_addr(ca):
        return {
            "hubs": [], "summary": _empty_fanout_summary(),
            "_error": f"invalid ca: {ca!r}",
        }

    surf_window_floor = (date.today() - timedelta(days=_SURF_MAX_LOOKBACK_DAYS)).isoformat()
    date_floor_clamped = surf_window_floor if date_floor < surf_window_floor else date_floor

    # v0.9.4 + audit fix 5: Phase 1 chunked. Short windows collapse to
    # single chunk (no regression for new tokens). Long windows split to
    # 30d chunks (heavier than rule_11 per-chunk; 90d may still hit 30s
    # budget on EVAA-class tokens).
    transfers = transfers_table()
    chunks = _single_chunk_or_chunker_dates(date_floor_clamped, None, chunk_days=30)
    # Per-chunk per-(hub, recipient) min: 1% of global threshold.
    chunk_min_rec_amt = max(1000.0, float(min_per_recipient) * 0.01)
    # Per-chunk LIMIT: bounded below surf max_rows cap so default pipeline
    # call (top_n_hubs=30, max_recipients=50 → naïve 30*50*5=7500) stays
    # under 9000 budget. Same _SURF_SAFE_MAX_ROWS guard as high_throughput.
    chunk_top_pairs = min(_SURF_SAFE_MAX_ROWS, top_n_hubs * max_recipients * 5)

    def _sql_fn(chunk_floor: str, chunk_ceiling: str) -> dict[str, Any]:
        # adversarial review Fix 3: LIMIT+1 truncation detection.
        sql = _SQL_FANOUT_HUB_CANDIDATES_CHUNK.format(
            transfers=transfers, ca_lc=ca,
            chunk_floor=chunk_floor, chunk_ceiling=chunk_ceiling,
            chunk_min_rec_amt=chunk_min_rec_amt,
            chunk_top_pairs_plus_1=chunk_top_pairs + 1,
         decimals_factor=decimals_factor_str())
        return _run_chunk_via_surf(sql, max_rows=chunk_top_pairs + 10, base_timeout=40)

    chunk_results = parallel_run_chunked(_sql_fn, chunks)
    errs_p1 = [r.get("_error") for r in chunk_results if r.get("_error")]
    rows_per_chunk_p1 = [r.get("data") or [] for r in chunk_results]
    # adversarial review Fix 3: detect per-chunk truncation.
    truncated_p1 = sum(1 for r in rows_per_chunk_p1 if len(r) > chunk_top_pairs)

    # adversarial review Fix 1 (CRITICAL): partial chunk error / truncation → empty +
    # _error. v0.9.3 single-shot semantics. A capped chunk full of junk
    # pairs would silently mask a real operator hub in Python merge.
    if errs_p1 or truncated_p1 > 0:
        return {
            "hubs": [], "summary": _empty_fanout_summary(),
            "_error": (
                f"phase1 {len(errs_p1)}/{len(chunks)} chunks errored, "
                f"{truncated_p1}/{len(chunks)} chunks truncated at LIMIT; "
                f"first: {errs_p1[0] if errs_p1 else 'none'}"
            ),
            "_debug": {"date_floor_clamped": date_floor_clamped,
                       "chunks": chunk_summary(chunks),
                       "chunk_errs_p1": len(errs_p1),
                       "chunk_truncated_p1": truncated_p1},
        }

    pair_rows: list[dict[str, Any]] = []
    for r in rows_per_chunk_p1:
        pair_rows.extend(r)

    # Python merge: SUM rec_amt by (hub, recipient) across chunks
    pair_totals: dict[tuple[str, str], float] = {}
    for row in pair_rows:
        h = (row.get("hub") or "").lower()
        rc = (row.get("recipient") or "").lower()
        if not h or not rc:
            continue
        try:
            pair_totals[(h, rc)] = pair_totals.get((h, rc), 0.0) + float(row.get("rec_amt") or 0)
        except (TypeError, ValueError):
            continue

    # Apply per-recipient filter (parity with v0.9.3 inner HAVING)
    pair_totals = {k: v for k, v in pair_totals.items() if v >= min_per_recipient}

    # Group by hub: count recipients, sum total_out, min/avg per recipient
    hub_aggs: dict[str, dict[str, Any]] = {}
    for (h, rc), amt in pair_totals.items():
        agg = hub_aggs.setdefault(h, {
            "hub": h, "n_recipients": 0, "total_out": 0.0,
            "min_per": float("inf"), "amt_sum": 0.0,
        })
        agg["n_recipients"] += 1
        agg["total_out"] += amt
        agg["amt_sum"] += amt
        if amt < agg["min_per"]:
            agg["min_per"] = amt

    # Apply hub-level filter (parity with v0.9.3 outer HAVING)
    hub_candidates: list[dict[str, Any]] = []
    for h, agg in hub_aggs.items():
        if not (min_recipients <= agg["n_recipients"] <= max_recipients):
            continue
        if agg["total_out"] < min_total_out:
            continue
        hub_candidates.append({
            "hub": h, "n_recipients": agg["n_recipients"],
            "total_out": agg["total_out"],
            "min_per": agg["min_per"],
            "avg_per": agg["amt_sum"] / max(1, agg["n_recipients"]),
        })
    hub_candidates.sort(key=lambda r: r["total_out"], reverse=True)
    hub_candidates = hub_candidates[:top_n_hubs]

    if not hub_candidates:
        return {
            "hubs": [], "summary": {
                "n_confirmed_hubs": 0, "n_candidate_hubs": 0,
                "total_cex_inflow_tokens": 0.0,
                "total_fanout_recipients": 0,
            },
            "_debug": {"date_floor_clamped": date_floor_clamped,
                       "chunks": chunk_summary(chunks),
                       "chunk_errs_p1": len(errs_p1)},
        }

    hub_addrs = [(r.get("hub") or "").lower() for r in hub_candidates]
    hub_addrs = [a for a in hub_addrs if _chain_is_valid_addr(a)]
    if not hub_addrs:
        return {"hubs": [], "summary": _empty_fanout_summary(), "_debug": {}}

    hub_in_list = "(" + ",".join(f"'{a}'" for a in hub_addrs) + ")"

    # v0.8.1 audit CRITICAL fix: split Phase 2 into 2 queries to
    # give each its own max_rows budget + explicit ORDER BY for stable
    # truncation. Truncation now detected per-query and surfaced via
    # `_phase2_truncated` so behavior_classifier can refuse to emit a
    # net % claim when the input is incomplete.
    # v0.8.5.0 — cap fix (用户 review 2026-06-11 + adversarial review JCT skeleton dump):
    # - recipients_max_rows 之前 = 30 hubs × 1000 + 5 = 30005, > surf 10K cap
    #   导致 SQL 整个 fail returned 0 rows. 改 9000 (< 10K) 接受 truncation
    #   但至少有数据.
    # - senders_max_rows 之前 = 30 × 30 + 5 = 905, 不撞 cap 但 truncated 因
    #   single hub 可能 senders > 30. 提到 9000 上限 (< 10K) + per_hub_cap 300.
    # v0.8.5.4 — 用户 review (2026-06-12 CLO 案例): "fan-out recipients
    # 钱包一定要统计完整, 因为这些一定是庄家弹药". 之前 16 candidate hubs ×
    # 300 = 4805 < 9000 cap → CLO recipients 4805/4805 truncated.
    # 直接拉满 surf 10K cap (9000), 不再 multiply by N_hubs.
    SURF_MAX_ROWS_CAP = 9000      # < surf 10K hard limit, 留 1K headroom
    sql_senders = _SQL_FANOUT_HUB_SENDERS.format(
        transfers=transfers_table(), decimals_factor=decimals_factor_str(), ca_lc=ca,
        hub_in_list=hub_in_list, date_floor=date_floor_clamped,
    )
    sql_recipients = _SQL_FANOUT_HUB_RECIPIENTS.format(
        transfers=transfers_table(), decimals_factor=decimals_factor_str(), ca_lc=ca,
        hub_in_list=hub_in_list, date_floor=date_floor_clamped,
    )
    senders_max_rows = SURF_MAX_ROWS_CAP
    recipients_max_rows = SURF_MAX_ROWS_CAP

    try:
        doc_senders, err_senders = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql_senders, "max_rows": senders_max_rows}),
            base_timeout=60, max_attempts=4,
        )
    except Exception as e:
        return {
            "hubs": [], "summary": _empty_fanout_summary(),
            "_error": f"phase2 senders exception: {str(e)[:120]}",
        }
    # v0.9.4 round-2 adversarial review Fix 2: Phase 2 surf failure must fail loud.
    # Pre-fix: doc_senders=None silently became empty sender_rows → all
    # candidate hubs dropped because no top_sender resolved → returned
    # `hubs: []` with no _error. Caller treats clean empty as "no hubs
    # found" instead of "lookup failed".
    if not doc_senders:
        return {
            "hubs": [], "summary": _empty_fanout_summary(),
            "_error": f"phase2 senders surf failed: {err_senders or 'no doc'}",
        }
    try:
        doc_recipients, err_recipients = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql_recipients, "max_rows": recipients_max_rows}),
            base_timeout=60, max_attempts=4,
        )
    except Exception as e:
        return {
            "hubs": [], "summary": _empty_fanout_summary(),
            "_error": f"phase2 recipients exception: {str(e)[:120]}",
        }
    # Same fail-loud guard for recipients side. Without it, hubs can be
    # confirmed (top_sender resolved CEX) but `net_fanout_tokens_total=0`
    # because all recipient_rows are empty — false "no fan-out" verdict.
    if not doc_recipients:
        return {
            "hubs": [], "summary": _empty_fanout_summary(),
            "_error": f"phase2 recipients surf failed: {err_recipients or 'no doc'}",
        }

    # Truncation detection: if the returned row count equals or exceeds
    # the cap, the result set was likely clipped — net metrics computed
    # from this would silently understate fan-out and must NOT be emitted.
    sender_rows = doc_senders.get("data") or []
    recipient_rows = doc_recipients.get("data") or []
    senders_truncated = len(sender_rows) >= senders_max_rows
    recipients_truncated = len(recipient_rows) >= recipients_max_rows

    senders_per_hub: dict[str, list] = {}
    recipients_per_hub: dict[str, list] = {}
    for r in sender_rows:
        h = (r.get("hub") or "").lower()
        senders_per_hub.setdefault(h, []).append({
            "hub": h,
            "source": (r.get("counterparty") or "").lower(),
            "amt": r.get("amt"),
            "n_tx": r.get("n_tx"),
            "first_tx": r.get("first_tx"),
        })
    for r in recipient_rows:
        h = (r.get("hub") or "").lower()
        recipients_per_hub.setdefault(h, []).append({
            "hub": h,
            "recipient": (r.get("counterparty") or "").lower(),
            "amt": r.get("amt"),
            "n_tx": r.get("n_tx"),
            "first_tx": r.get("first_tx"),
        })

    # Determine top sender per hub (most amount in) — we'll resolve_labels on these
    top_senders: dict[str, dict] = {}
    for h, senders in senders_per_hub.items():
        senders_sorted = sorted(senders, key=lambda x: float(x.get("amt") or 0), reverse=True)
        if senders_sorted:
            top_senders[h] = senders_sorted[0]

    # v0.8.5.4: 用户 review 2026-06-12 — fan-out recipients 必须完整.
    # 如果 bulk recipients SQL truncated (≥ 9000 rows), 对每个 hub 跑
    # 单独 query 拿 LIMIT 1000 each, override recipients_per_hub. 保证
    # 每个 hub 的 fan-out 出口钱包都被捕获. 成本: confirmed hub count
    # × 1 SQL × ~3 credits ≈ 10-30 extra credits/token (高 fan-out 场景).
    if recipients_truncated:
        import sys as _sys
        print(f"[fanout] recipients bulk truncated ({len(recipient_rows)}/{recipients_max_rows}), "
              f"falling back to per-hub queries for {len(hub_addrs)} hubs", file=_sys.stderr)
        per_hub_complete: dict[str, list] = {}
        for hub_addr in hub_addrs:
            sql_per_hub = (
                f"SELECT '{hub_addr}' AS hub, \"to\" AS counterparty, "
                f"sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amt, "
                f"count() AS n_tx, min(block_time) AS first_tx "
                f"FROM {transfers_table()} "
                f"WHERE contract_address = '{ca}' AND \"from\" = '{hub_addr}' "
                f"AND block_date >= '{date_floor_clamped}' "
                f"AND \"to\" != '0x0000000000000000000000000000000000000000' "
                f"AND \"to\" != '0x000000000000000000000000000000000000dead' "
                f"GROUP BY counterparty ORDER BY amt DESC LIMIT 1000"
            )
            # v0.9.4 round-2 adversarial review Fix 3: bump max_attempts 2 → 4 for parity
            # with all other phase-2 / chunk surf calls (4 = repo retry
            # standard, see _run_surf_with_retry docstring). Per-hub recipient
            # data is load-bearing for `net_fanout_tokens_total` — a single
            # silent failure here previously produced bulk-fallback data
            # silently and dropped the truncation signal.
            per_hub_err: str | None = None
            try:
                d_per, per_hub_err = _run_surf_with_retry(
                    ["surf", "onchain-sql"],
                    stdin=json.dumps({"sql": sql_per_hub, "max_rows": 1005}),
                    base_timeout=30, max_attempts=4,
                )
                if d_per:
                    rows = (d_per.get("data") or [])
                    per_hub_complete[hub_addr] = [{
                        "hub": hub_addr,
                        "recipient": (r.get("counterparty") or "").lower(),
                        "amt": r.get("amt"),
                        "n_tx": r.get("n_tx"),
                        "first_tx": r.get("first_tx"),
                    } for r in rows]
                else:
                    # adversarial review Fix 3: surf failed (None doc). Preserve bulk
                    # partial rows for this hub AND set recipients_truncated
                    # = True so the downstream net% claim is gated.
                    print(f"[fanout] per-hub surf failed for {hub_addr[:14]}: "
                          f"{per_hub_err or 'no doc'}", file=_sys.stderr)
                    per_hub_complete[hub_addr] = recipients_per_hub.get(hub_addr, [])
                    recipients_truncated = True
            except Exception as e:
                print(f"[fanout] per-hub query failed for {hub_addr[:14]}: {e}", file=_sys.stderr)
                # 保留 bulk 部分数据 fallback
                per_hub_complete[hub_addr] = recipients_per_hub.get(hub_addr, [])
                recipients_truncated = True
        # Override recipients_per_hub with complete data
        recipients_per_hub = per_hub_complete
        # adversarial review Fix 3 (revised): truncation flag uses BOTH the bulk
        # truncation signal we just OR'd into recipients_truncated AND
        # the "any hub has ≥ 1000 recipients" check from before. Bulk
        # surf failures no longer mask incomplete data as "complete".
        any_per_hub_full = any(len(rs) >= 1000 for rs in per_hub_complete.values())
        recipients_truncated = recipients_truncated or any_per_hub_full

    # Resolve Arkham labels for top senders
    unique_source_addrs = list({
        (s.get("source") or "").lower() for s in top_senders.values()
        if s.get("source") and _chain_is_valid_addr((s.get("source") or "").lower())
    })
    source_labels: dict[str, dict] = {}
    if unique_source_addrs:
        try:
            from surf_labels_probe import resolve_labels as _resolve_labels
            source_labels = _resolve_labels(unique_source_addrs)
        except Exception as e:
            import sys as _sys
            print(f"[fanout] label resolve failed (non-fatal): {e}", file=_sys.stderr)
            source_labels = {}

    # Filter: only confirmed CEX-origin hubs
    CEX_CLS = {"CEX_DEPOSIT", "CEX_HOT_WALLET"}
    confirmed_hubs: list[dict[str, Any]] = []
    total_cex_inflow = 0.0
    total_fanout_recipients = 0

    # v0.8.1 first pass: collect confirmed-hub addr set BEFORE per-hub
    # net computation, so the inter-hub-loopback exclusion uses the full
    # set (not the partial set being built).
    confirmed_hub_addrs: set[str] = set()
    for hub_data in hub_candidates:
        hub = (hub_data.get("hub") or "").lower()
        if hub not in top_senders:
            continue
        src = (top_senders[hub].get("source") or "").lower()
        src_cls = (source_labels.get(src) or {}).get("classification") or "UNLABELED"
        if src_cls in CEX_CLS:
            confirmed_hub_addrs.add(hub)

    # v0.8.1: also collect ALL CEX-source addrs (the top-sender into each
    # confirmed hub) so we can identify outflows that loop back to the
    # same CEX brand (e.g. hub → its own Gate Deposit). These do NOT
    # represent retail fan-out — they are funding-source round-trips.
    all_cex_source_addrs: set[str] = set()
    for hub in confirmed_hub_addrs:
        src = (top_senders[hub].get("source") or "").lower()
        if src and _chain_is_valid_addr(src):
            all_cex_source_addrs.add(src)

    for hub_data in hub_candidates:
        hub = (hub_data.get("hub") or "").lower()
        if hub not in top_senders:
            continue
        top_send = top_senders[hub]
        src = (top_send.get("source") or "").lower()
        src_label = source_labels.get(src) or {}
        src_cls = src_label.get("classification") or "UNLABELED"
        if src_cls not in CEX_CLS:
            continue

        # v0.8.1: compute NET fan-out from the trustworthy Phase 2
        # recipient list (not the broken Phase 1 total_out which is
        # SQL-layer inconsistent — see velvet handoff 2026-06-11).
        # Two flavors of net:
        #   - net_fanout_tokens (transparency): sums all non-loopback
        #     recipients regardless of per-recipient amount.
        #   - net_structured_fanout_tokens: sums only recipients
        #     receiving ≥ min_per_recipient (matches Phase 1 hub-shape
        #     semantic; this is the input A2 size claim should use).
        # Exclusions (same for both):
        #   - The hub's own CEX source (round-trip loopback)
        #   - All other confirmed CEX-sources (cross-hub loopback)
        #   - All other confirmed fanout hubs (inter-hub shuffle)
        all_recipients = recipients_per_hub.get(hub, [])
        net_tokens = 0.0
        net_recipient_addrs: set[str] = set()
        net_structured_tokens = 0.0
        net_structured_recipient_addrs: set[str] = set()
        loopback_tokens = 0.0
        inter_hub_tokens = 0.0
        for r in all_recipients:
            r_addr = (r.get("recipient") or "").lower()
            r_amt = float(r.get("amt") or 0.0)
            if not r_addr:
                continue
            if r_addr in all_cex_source_addrs:
                loopback_tokens += r_amt
                continue
            if r_addr in confirmed_hub_addrs and r_addr != hub:
                inter_hub_tokens += r_amt
                continue
            net_tokens += r_amt
            net_recipient_addrs.add(r_addr)
            if r_amt >= min_per_recipient:
                net_structured_tokens += r_amt
                net_structured_recipient_addrs.add(r_addr)

        # Display top-N recipients sorted by amount (excluding loopbacks
        # so the table matches the net calc). UNCLASSIFIED amounts
        # (= net) are what shows up in the report.
        display_recipients = sorted(
            (r for r in all_recipients
             if (r.get("recipient") or "").lower() in net_recipient_addrs),
            key=lambda x: float(x.get("amt") or 0), reverse=True,
        )[:max_recipients_per_hub_display]
        cex_inflow_amt = float(top_send.get("amt") or 0)
        n_recip = int(hub_data.get("n_recipients") or 0)
        confirmed_hubs.append({
            "addr": hub,
            "n_recipients": n_recip,
            # v0.8.1 DEPRECATED metric — kept for back-compat / debug.
            # SQL-layer inconsistent vs the Phase 2 recipient detail.
            # Do NOT use for size claims. See net_fanout_tokens below.
            "total_out_tokens": float(hub_data.get("total_out") or 0),
            "min_per_recipient": float(hub_data.get("min_per") or 0),
            "avg_per_recipient": float(hub_data.get("avg_per") or 0),
            # v0.8.1 NEW metrics — derived from Phase 2 recipient detail.
            # net_fanout_tokens = floor on retail-routed amount; this is
            # what feeds fanout_pct_supply in behavior_classifier.
            "net_fanout_tokens": net_tokens,
            "net_fanout_recipients": len(net_recipient_addrs),
            # v0.8.1 audit MED fix: structured variant matches Phase 1
            # ≥ min_per_recipient gate used to define "hub shape".
            # Used by A2 size claim to keep the semantic consistent.
            "net_structured_fanout_tokens": net_structured_tokens,
            "net_structured_recipients": len(net_structured_recipient_addrs),
            "loopback_to_cex_tokens": loopback_tokens,
            "inter_hub_shuffle_tokens": inter_hub_tokens,
            # v0.8.1 audit HIGH fix: raw recipient address sets so the
            # summary dedup uses ALL net recipients, not the display top
            # 20 capped slice. Stored with underscore prefix to mark as
            # internal aggregation use (not a stable consumer field).
            "_net_recipient_addrs_raw": sorted(net_recipient_addrs),
            "_net_structured_recipient_addrs_raw": sorted(net_structured_recipient_addrs),
            "cex_source": src,
            "cex_source_label": src_label.get("label"),
            "cex_source_entity": src_label.get("entity_name"),
            "cex_source_classification": src_cls,
            "cex_source_inflow_tokens": cex_inflow_amt,
            "cex_source_n_tx": int(top_send.get("n_tx") or 0),
            "top_recipients": [
                {
                    "addr": (r.get("recipient") or "").lower(),
                    "amt": float(r.get("amt") or 0),
                    "n_tx": int(r.get("n_tx") or 0),
                }
                for r in display_recipients
            ],
        })
        total_cex_inflow += cex_inflow_amt
        total_fanout_recipients += n_recip

    # v0.8.1: aggregate net metrics across hubs for the report header.
    # net_fanout_tokens_total is the floor on retail-routed amount —
    # this is what should drive A2 fanout_pct_supply, not the broken
    # total_out_tokens.
    net_fanout_tokens_total = sum(
        h.get("net_fanout_tokens") or 0.0 for h in confirmed_hubs
    )
    loopback_to_cex_total = sum(
        h.get("loopback_to_cex_tokens") or 0.0 for h in confirmed_hubs
    )
    inter_hub_shuffle_total = sum(
        h.get("inter_hub_shuffle_tokens") or 0.0 for h in confirmed_hubs
    )
    # v0.8.1 audit HIGH fix: dedupe across hubs using the RAW
    # net recipient set (not display-capped top_recipients). Previously
    # used top_recipients which is sliced to N=20 for display, so the
    # global unique count silently understated.
    all_net_recipients_raw: set[str] = set()
    for h in confirmed_hubs:
        for a in (h.get("_net_recipient_addrs_raw") or []):
            if a:
                all_net_recipients_raw.add(a)
    # Threshold-respecting variant: only recipients each receiving ≥
    # min_per_recipient (matches Phase 1 "structured fan-out" semantic).
    # Used by behavior_classifier for A2 size claim.
    net_structured_tokens_total = sum(
        h.get("net_structured_fanout_tokens") or 0.0 for h in confirmed_hubs
    )
    all_net_structured_recipients: set[str] = set()
    for h in confirmed_hubs:
        for a in (h.get("_net_structured_recipient_addrs_raw") or []):
            if a:
                all_net_structured_recipients.add(a)

    return {
        "hubs": confirmed_hubs,
        "summary": {
            "n_confirmed_hubs": len(confirmed_hubs),
            "n_candidate_hubs": len(hub_candidates),
            "total_cex_inflow_tokens": total_cex_inflow,
            "total_fanout_recipients": total_fanout_recipients,
            # v0.8.1 — NET metrics (Phase 2 detail-derived).
            #
            # net_fanout_tokens_total: includes ALL net recipients
            #   regardless of per-recipient amount (transparency floor).
            # net_structured_fanout_tokens_total: ≥ min_per_recipient
            #   only (matches Phase 1 hub-shape semantic; this is the
            #   right input for A2 size claim).
            "net_fanout_tokens_total": net_fanout_tokens_total,
            "net_fanout_unique_recipients": len(all_net_recipients_raw),
            "net_structured_fanout_tokens_total": net_structured_tokens_total,
            "net_structured_unique_recipients": len(all_net_structured_recipients),
            "loopback_to_cex_tokens_total": loopback_to_cex_total,
            "inter_hub_shuffle_tokens_total": inter_hub_shuffle_total,
            # v0.8.1 audit CRITICAL fix: truncation propagation.
            # Downstream code (behavior_classifier) MUST refuse to emit
            # net % claims when these are True.
            "_phase2_senders_truncated": senders_truncated,
            "_phase2_recipients_truncated": recipients_truncated,
            "_phase2_complete": not (senders_truncated or recipients_truncated),
        },
        "_debug": {
            "date_floor_clamped": date_floor_clamped,
            "min_recipients": min_recipients,
            "max_recipients": max_recipients,
            "min_per_recipient": min_per_recipient,
            "min_total_out": min_total_out,
            "senders_max_rows": senders_max_rows,
            "recipients_max_rows": recipients_max_rows,
            "senders_returned_rows": len(sender_rows),
            "recipients_returned_rows": len(recipient_rows),
        },
    }


def _empty_fanout_summary() -> dict[str, Any]:
    return {
        "n_confirmed_hubs": 0,
        "n_candidate_hubs": 0,
        "total_cex_inflow_tokens": 0.0,
        "total_fanout_recipients": 0,
    }
