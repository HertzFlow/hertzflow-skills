#!/usr/bin/env python3
"""dump_tracker.py — entity-level realized-sell ("派发"/Wyckoff distribution)
tracking, distinct from wallet-to-wallet transfers ("分发").

Why (Phase 2, 2026-05-27):

  v0.7.10.x `dumped_pct` is wallet-level outflow — it counts ANY transfer
  out (to another wallet, to a vesting contract, to an exchange) as
  "distributed". The user wants the Wyckoff sense of 派发: an entity (and
  its wallet cluster) actually SELLING — tokens reaching a CEX deposit, a
  DEX swap, or a cross-chain bridge. A wallet shuffling tokens to its own
  next address is 分发 (transfer), not 派发 (sell).

Cost design (validated 2026-05-27):

  Pulling the whole-token transfer graph (even segmented + parallel) is too
  heavy — `GROUP BY from,to` over monthly bsc_transfers partitions ran
  >350s before being killed. INSTEAD this module is purely POST-PROCESSING
  of rule_11's already-fetched graph:
    - rule_11 already pulled deployer → receivers → m6 sub-receivers and
      each dumper's `dumper_destinations` (targeted WHERE from=addr queries,
      which are fast). That graph is in memory.
    - We classify the terminal/destination nodes via Arkham (batch) into
      CEX-custody / DEX-infra / bridge = SELL terminals.
    - A "sell" = token amount flowing from a cluster wallet (or its m6
      descendants) into a sell terminal.
    - One `surf market-price` series query values every sell at its
      timestamp (in-memory binary search, no per-sell query).
  Net new on-chain cost: 0 transfer SQL + 1 price query + label batches
  (mostly reused from rule_11's enrichment). Wall-clock +20-30s.

Output (consumed by the skeleton's dump_tracking block + verdict + render).

NOTE: v0.7.12 replaced the earlier per-cluster disposal shape (clusters[] with
per-cluster sold_tokens / est_profit_usd) with a single conservation-safe
CONFIRMED-SOLD LOWER BOUND. Per-entity profit attribution was dropped on
purpose: `received_from_deployer` is a flow that double-counts on relays, so
per-entity disposal could not be attributed without over-claiming. The headline
is now the aggregate confirmed lower bound + a single estimated-proceeds figure
(`confirmed_total_tokens × robust median DEX price`; insiders are zero-cost
genesis allocations, so estimated proceeds ≈ realized profit):

  {
    "insider_n_wallets": int,
    # CONFIRMED-SOLD LOWER BOUND (a) insider→CEX-deposit + (b) insider DEX swaps,
    # capped at (total_supply − tree_holds) by stock conservation:
    "confirmed_cex_tokens": float, "confirmed_cex_pct": float | None,
    "confirmed_cex_labels": [str, ...],
    "confirmed_dex_tokens": float, "confirmed_dex_pct": float | None,
    "confirmed_dex_swaps": int,
    "confirmed_total_tokens": float, "confirmed_total_pct": float | None,
    "confirmed_est_profit_usd": float | None,   # 估算套现 = total × median px
    "confirmed_capped": bool,                    # floor clamped to the ceiling
    # v0.7.19.4: split fields.
    # TREE holdings (stock, ALL traced wallets incl. lockup + exit-infra) —
    # conservation anchor for `max_left` / confirmed_capped:
    "tree_holds_tokens": float, "tree_holds_pct_supply": float | None,
    # PURE insider holdings (stock, EXCLUDING Arkham-confirmed
    # protocol_lockup + cex_custody + dex_infra) — narrative anchor:
    "pure_insider_holds_tokens": float, "pure_insider_holds_pct_supply": float | None,
    # Backward-compat alias for the (now misleading) old field name —
    # points at tree_holds, kept so external consumers don't break:
    "insider_holds_tokens": float, "insider_holds_pct_supply": float | None,
    "median_price_usd": float | None,
    # Wash context:
    "wash_dominated": bool, "n_dex_sellers": int,
    "total_dex_swaps": int, "top_seller_swaps": int,
    "buckets_complete": bool,                    # False → a query failed; floor may undercount
  }
"""

from __future__ import annotations

import bisect
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from chain_router import transfers_table, dex_trades_table  # v0.7.20
from chain_router import decimals_factor_str  # v0.9.7
from pathlib import Path
from push_airdrop_detector import fetch_push_airdrop_recipients  # v0.8.1
from typing import Any

# v0.7.19: parallelize the 4 independent surf SQL queries in `run()`.
# Each query is independent (no inter-query data dependency) and goes
# through `_run_surf_with_retry` which itself handles per-attempt
# back-off — so submitting all 4 at once cannot create more concurrent
# surf calls than max_workers=4 would anyway. Override via env if a
# future token's fan-out spikes credit usage past safe levels.
DUMP_TRACKER_WORKERS = max(1, int(
    os.environ.get("BINANCE_ALPHA_DUMP_TRACKER_WORKERS", "4")
))

sys.path.insert(0, str(Path(__file__).parent))

# SQL-injection guard (adversarial review MEDIUM #4): every address / CA reaching an
# f-string SQL must pass `chain_router.is_valid_addr` for the active
# chain. v0.7.21.7: chain-aware — EVM 0x40-hex on EVM chains, Solana
# base58 32-44 on Solana. Pre-v0.7.21.7 this was hardcoded EVM, which
# silently swallowed every base58 address downstream — dump_tracker
# returned empty on Solana even after Section A accepted the CA.
from chain_router import is_valid_addr as _chain_is_valid_addr  # noqa: E402
from chain_router import get_active_chain as _chain_get_active  # noqa: E402

# Kept for any out-of-pipeline caller; the SQL helpers below use
# `_chain_is_valid_addr` so behaviour follows the router.
_HEX_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")


def _clean_addrs(addrs: list[str]) -> list[str]:
    """Keep only addresses that pass the active chain's format check,
    de-duplicated + sorted. EVM normalises case (lowercase); Solana
    base58 is case-sensitive and preserved as-is."""
    is_solana = _chain_get_active() == "solana"
    if is_solana:
        return sorted({a for a in addrs if a and _chain_is_valid_addr(a)})
    return sorted({
        a.lower() for a in addrs
        if a and _chain_is_valid_addr(a.lower())
    })


def _valid_ca(ca: str) -> str:
    """Return the validated CA (lowercased on EVM, preserved on Solana)
    iff it passes the active chain's format check, else '' so callers'
    `if not ca` guards short-circuit to a safe empty result."""
    if not ca:
        return ""
    if _chain_get_active() == "solana":
        return ca if _chain_is_valid_addr(ca) else ""
    ca_lower = ca.lower()
    return ca_lower if _chain_is_valid_addr(ca_lower) else ""


def fetch_current_balances(ca: str, wallets: list[str], date_floor: str) -> dict[str, float]:
    """Current token balance per wallet via one bsc_transfers in/out CTE.

    balance = sum(in) − sum(out) since date_floor. Used to anchor the
    apparatus disposed amount on STOCK (conservation-safe), since rule_11
    only computes balances for depth-1 receivers (deep relays are None).
    """
    ca = _valid_ca(ca)
    wallets = _clean_addrs(wallets)
    if not wallets or not ca:
        return {}
    arr = "[" + ",".join(f"'{w}'" for w in wallets) + "]"
    sql = (
        f"WITH ins AS (SELECT \"to\" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amt "
        f"FROM {transfers_table()} WHERE contract_address='{ca.lower()}' AND block_date >= '{date_floor}' GROUP BY a), "
        f"outs AS (SELECT \"from\" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amt "
        f"FROM {transfers_table()} WHERE contract_address='{ca.lower()}' AND block_date >= '{date_floor}' GROUP BY a) "
        "SELECT r.a AS a, COALESCE(ins.amt,0) - COALESCE(outs.amt,0) AS bal "
        f"FROM (SELECT arrayJoin({arr}) AS a) r LEFT JOIN ins ON r.a=ins.a LEFT JOIN outs ON r.a=outs.a"
    )
    try:
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": 500}), base_timeout=60,
            max_attempts=4,  # v0.7.23 per surf-team guidance (2026-06-09): "30s+ query retried 3× = load×3, exacerbates contention → backoff or fail loud, not brute-force retry". 4 attempts is the client-side cooperation pattern, not a vendor-outage fallback.
        )
    except Exception as e:
        doc, err = None, f"exception: {str(e)[:120]}"
    if not doc:
        # audit H6 fix: surface surf failure via sentinel key so the
        # caller can mark `balances_ok=False` and trip buckets_complete.
        # Returning a plain {} silently zeroes pure_insider_holds /
        # tree_holds downstream, indistinguishable from a token with no
        # wallet activity.
        return {"__ERR": err or "surf returned no doc"}
    out: dict[str, float] = {}
    for r in (doc.get("data") or []):
        a = (r.get("a") or "").lower()
        if a:
            try:
                out[a] = float(r.get("bal") or 0)
            except (TypeError, ValueError):
                out[a] = 0.0
    return out


def fetch_dex_sell_profile(ca: str, from_date: str) -> dict[str, Any]:
    """One bsc_dex_trades query → token-level sell profile for the wash /
    pricing narrative. Returns:
      {
        "median_price_usd": float | None,   # robust price (amount_usd/token);
                                             # median defeats MEV/aggregator
                                             # garbage amount_usd outliers
        "n_sellers": int, "total_swaps": int,
        "top_seller_swaps": int,            # max swaps by one tx_from
        "wash_dominated": bool,             # top seller >1000 swaps OR
                                            # swaps/sellers > 50 → wash bots
      }
    """
    ca = _valid_ca(ca)
    if not ca:
        return {}
    sql = (
        "SELECT tx_from AS w, count() AS n, "
        "median(amount_usd / nullIf(token_sold_amount,0)) AS unit_px "
        f"FROM {dex_trades_table()} WHERE token_sold_address='{ca.lower()}' "
        f"AND block_date >= '{from_date}' AND amount_usd > 0 AND token_sold_amount > 0 "
        "GROUP BY w ORDER BY n DESC LIMIT 200"
    )
    try:
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": 200}), base_timeout=40,
            max_attempts=4,  # v0.7.23 per surf-team guidance (2026-06-09): "30s+ query retried 3× = load×3, exacerbates contention → backoff or fail loud, not brute-force retry". 4 attempts is the client-side cooperation pattern, not a vendor-outage fallback.
        )
    except Exception as e:
        doc, err = None, f"exception: {str(e)[:120]}"
    if not doc:
        # audit H6 fix: sentinel error key — caller checks and
        # marks profile_ok=False to feed buckets_complete. Empty dict
        # would silently zero wash_dominated / top_seller_addrs.
        return {"__ERR": err or "surf returned no doc"}
    rows = doc.get("data") or []
    if not rows:
        return {"median_price_usd": None, "n_sellers": 0, "total_swaps": 0,
                "top_seller_swaps": 0, "wash_dominated": False}
    # Robust unit price = median across sellers of their per-seller median
    # unit price, then clamp insane values (>1e6 $/token is garbage).
    pxs = sorted(
        p for r in rows
        if (p := r.get("unit_px")) is not None and 0 < float(p) < 1e6
    )
    median_px = pxs[len(pxs) // 2] if pxs else None
    total_swaps = sum(int(r.get("n") or 0) for r in rows)
    top_swaps = max((int(r.get("n") or 0) for r in rows), default=0)
    n_sellers = len(rows)
    wash_dominated = top_swaps > 1000 or (n_sellers and total_swaps / n_sellers > 50)
    # v0.7.21: expose the seller address list so flow_operator_detector
    # can reuse it without paying for a second SQL. Rows already come
    # ordered by swap count DESC from the SELECT, so the list is the
    # ordered top sellers (cap 200 — matches the LIMIT clause).
    top_sellers = [
        str(r.get("w") or "").lower() for r in rows
        if r.get("w") and _HEX_ADDR_RE.match(str(r.get("w")).lower())
    ]
    return {
        "median_price_usd": float(median_px) if median_px else None,
        "n_sellers": n_sellers,
        "total_swaps": total_swaps,
        "top_seller_swaps": top_swaps,
        "wash_dominated": bool(wash_dominated),
        "top_seller_addrs": top_sellers,
    }


def fetch_apparatus_dex_sold(ca: str, wallets: list[str], from_date: str) -> dict[str, Any]:
    """(b) tokens the APPARATUS WALLETS THEMSELVES sold on DEX.

    dex_trades token_sold=CA AND tx_from IN apparatus → these are confirmed
    on-chain sells BY the insider wallets (real buyer paid the other side).
    Returns {"dex_sold_tokens": float, "n_swaps": int,
             "dex_sold_usd": float, "dex_twap_usd_per_token": float | None}.

    v0.7.21.10: also SUM(amount_usd) on the same query so the caller can
    build a "Net Sell Out" estimate that uses the apparatus' own
    time-weighted-average price (TWAP) rather than the wash-inflatable
    `fetch_dex_sell_profile.median_price_usd`. Zero new credits — same
    table / filter / partition, just two extra SELECT columns.

    Note: gross swap volume (wash-inflatable if an apparatus wallet itself
    wash-trades); caller caps confirmed total at net outflow.
    """
    ca = _valid_ca(ca)
    wallets = _clean_addrs(wallets)
    if not wallets or not ca:
        return {"dex_sold_tokens": 0.0, "n_swaps": 0,
                "dex_sold_usd": 0.0, "dex_twap_usd_per_token": None}
    in_list = ",".join(f"'{w}'" for w in wallets)
    # v0.9.2: per-window split via SQL CASE WHEN — same partition scan,
    # same surf cost, just extra SELECT columns. EmberCN-style short-term
    # alarms ("过去 14 小时套现 $27.7M") need 7d / 30d breakdown to be
    # comparable to our previously-only-cumulative number.
    sql = (
        "SELECT sum(token_sold_amount) AS sold, count() AS n, "
        # v0.7.21.10: amount_usd already on the row in surf's dex_trades
        # schema; ClickHouse SUM is free against the existing partition
        # scan. Filter `amount_usd > 0` defends against the
        # NULL / 0 rows surf occasionally emits for MEV-aggregator txs
        # without a priced quote leg.
        "sum(if(amount_usd > 0, amount_usd, 0)) AS sold_usd, "
        # Per-window splits
        "sum(if(block_date >= today() - 7, token_sold_amount, 0)) AS sold_7d, "
        "sum(if(block_date >= today() - 7, if(amount_usd > 0, amount_usd, 0), 0)) AS sold_usd_7d, "
        "countIf(block_date >= today() - 7) AS n_7d, "
        "sum(if(block_date >= today() - 30, token_sold_amount, 0)) AS sold_30d, "
        "sum(if(block_date >= today() - 30, if(amount_usd > 0, amount_usd, 0), 0)) AS sold_usd_30d, "
        "countIf(block_date >= today() - 30) AS n_30d "
        f"FROM {dex_trades_table()} WHERE token_sold_address='{ca.lower()}' "
        f"AND tx_from IN ({in_list}) AND block_date >= '{from_date}'"
    )
    try:
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": 5}), base_timeout=40,
            max_attempts=4,  # v0.7.23 per surf-team guidance (2026-06-09): "30s+ query retried 3× = load×3, exacerbates contention → backoff or fail loud, not brute-force retry". 4 attempts is the client-side cooperation pattern, not a vendor-outage fallback.
        )
    except Exception as e:
        doc, err = None, str(e)[:120]
    # ok=False means the query never succeeded (surf throttled past all
    # retries) — caller must NOT treat the 0 as a real "no DEX sells", it is
    # unknown. A flaked 0 would silently understate confirmed disposal.
    if not doc:
        return {"dex_sold_tokens": 0.0, "n_swaps": 0,
                "dex_sold_usd": 0.0, "dex_twap_usd_per_token": None,
                "ok": False, "error": err}
    rows = doc.get("data") or []
    r = rows[0] if rows else {}
    sold = float(r.get("sold") or 0)
    sold_usd = float(r.get("sold_usd") or 0)
    # TWAP = volume-weighted average price the apparatus actually got. Defaults
    # to None when there is no DEX swap (avoids divide-by-zero into 0).
    twap = (sold_usd / sold) if sold > 0 and sold_usd > 0 else None
    sold_7d = float(r.get("sold_7d") or 0)
    sold_usd_7d = float(r.get("sold_usd_7d") or 0)
    sold_30d = float(r.get("sold_30d") or 0)
    sold_usd_30d = float(r.get("sold_usd_30d") or 0)
    return {
        "dex_sold_tokens": sold,
        "n_swaps": int(r.get("n") or 0),
        "dex_sold_usd": sold_usd,
        "dex_twap_usd_per_token": twap,
        # v0.9.2: per-window split
        "dex_sold_tokens_7d": sold_7d,
        "dex_sold_usd_7d": sold_usd_7d,
        "n_swaps_7d": int(r.get("n_7d") or 0),
        "dex_sold_tokens_30d": sold_30d,
        "dex_sold_usd_30d": sold_usd_30d,
        "n_swaps_30d": int(r.get("n_30d") or 0),
        "ok": True,
    }


def fetch_apparatus_to_cex(ca: str, wallets: list[str], from_date: str) -> dict[str, Any]:
    """(a) tokens the APPARATUS transferred to CEX-deposit addresses.

    One query: transfers FROM apparatus wallets GROUP BY destination; then
    Arkham-classify destinations and sum those routed to a CEX. CEX deposit
    addresses are sinks (tokens go in, get swept internally, don't return to
    the depositor), so cumulative transfer ≈ net deposited. Convention:
    deposit to CEX = exit/sell (the actual sale is off-chain).

    Returns {"cex_tokens": float, "cex_labels": [str]}.
    """
    ca = _valid_ca(ca)
    wallets = _clean_addrs(wallets)
    if not wallets or not ca:
        return {"cex_tokens": 0.0, "cex_labels": []}
    in_list = ",".join(f"'{w}'" for w in wallets)
    # v0.9.2: per-dest per-window split. Total still GROUP BY dest so
    # the Arkham classification flow downstream is unchanged; the bucket
    # columns let the caller compute confirmed_cex_tokens_7d / _30d at
    # post-process time (sum of per-dest bucket if dest classified CEX).
    sql = (
        'SELECT "to" AS dest, '
        f'sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS tok, '
        'sum(if(block_date >= today() - 7, '
        f'       toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}, 0)) AS tok_7d, '
        'sum(if(block_date >= today() - 30, '
        f'       toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}, 0)) AS tok_30d '
        f"FROM {transfers_table()} WHERE contract_address='{ca.lower()}' "
        f'AND "from" IN ({in_list}) AND block_date >= \'{from_date}\' '
        "GROUP BY dest ORDER BY tok DESC LIMIT 100"
    )
    try:
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": 100}), base_timeout=60,
            max_attempts=4,  # v0.7.23 per surf-team guidance (2026-06-09): "30s+ query retried 3× = load×3, exacerbates contention → backoff or fail loud, not brute-force retry". 4 attempts is the client-side cooperation pattern, not a vendor-outage fallback.
        )
    except Exception as e:
        doc, err = None, str(e)[:120]
    # ok=False means surf never returned (throttled past all retries); the 0
    # is unknown, not a real "no CEX deposits" — see fetch_apparatus_dex_sold.
    if not doc:
        return {"cex_tokens": 0.0, "cex_labels": [], "ok": False, "error": err}
    dests = [(r.get("dest") or "").lower() for r in (doc.get("data") or []) if r.get("dest")]
    apparatus_set = set(wallets)
    # Exclude apparatus-internal transfers; classify external destinations.
    ext = [d for d in dests if d not in apparatus_set]
    from protocol_lockup_detector import enrich_addresses_with_lockup_classification
    cls = enrich_addresses_with_lockup_classification(ext) if ext else {}
    cex_tokens = 0.0
    cex_tokens_7d = 0.0
    cex_tokens_30d = 0.0
    cex_labels: list[str] = []
    for r in (doc.get("data") or []):
        d = (r.get("dest") or "").lower()
        if d in apparatus_set:
            continue
        c = cls.get(d) or {}
        if c.get("is_cex_custody"):
            cex_tokens += float(r.get("tok") or 0)
            cex_tokens_7d += float(r.get("tok_7d") or 0)
            cex_tokens_30d += float(r.get("tok_30d") or 0)
            lab = c.get("display_label")
            if lab and lab not in cex_labels:
                cex_labels.append(lab)
    return {
        "cex_tokens": cex_tokens,
        # v0.9.2: per-window CEX-routed tokens (subset of cex_tokens
        # where the transfer's block_date is within the window).
        "cex_tokens_7d": cex_tokens_7d,
        "cex_tokens_30d": cex_tokens_30d,
        "cex_labels": cex_labels[:5],
        "ok": True,
    }


def _sane_effective_price(dex_px: float | None,
                          spot_px: float | None) -> float | None:
    """v1.2.5 (SLX 2026-06-29): bound a DEX-derived per-token price by the
    reliable spot price before using it to value the CEX disposal leg.

    The DEX prices (twap / median) are computed from surf `dex_trades.amount`,
    which surf decimal-adjusts assuming 18 decimals. For a non-18-decimal token
    (SLX = 8) the token amount is mis-scaled by 10^(18-d), so the implied
    USD/token EXPLODES (SLX: $243B/token → a $2.7e18 CEX estimate). Spot price
    comes from a different source (Alpha API / LP), so it is trustworthy.

    Rule: if there is a usable spot price, reject a DEX price that is >100x or
    <0.01x spot (decimals-broken) and fall back to spot. The 100x band keeps
    legitimate new-token volatility; a decimals break is ≥10^9x for common
    6/8/9-decimal tokens, so it is always caught. With no spot price we cannot
    sanity-check, so the DEX price is returned unchanged (legacy behaviour).
    """
    if spot_px and spot_px > 0:
        if not dex_px or not (0.01 * spot_px <= dex_px <= 100 * spot_px):
            return spot_px
    return dex_px


# ---- main entry ----


def run(
    *,
    rule11: dict[str, Any],
    ca: str,
    symbol: str,
    listing_ts_ms: int | None,
    listing_date: str | None,
    circulating_supply: float | None,
    total_supply: float | None,
    extra_receivers: list[dict] | None = None,
    spot_price_usd: float | None = None,
) -> dict[str, Any]:
    """Insider disposal ("派发") tracking — CONFIRMED-SOLD LOWER BOUND only.

    Methodology (2026-05-28 redesign, leader call — see
    reference_dump_vs_distribution_methodology §6):

    We report ONLY what the chain can prove, because that is the number a
    holder should act on (defensive posture). We deliberately DROPPED the
    "allocation − current balance" upper bound: allocation was a SUM of
    `received_from_deployer`, a FLOW that double-counts whenever the deployer
    round-trips / relays tokens (R2 cycled ~1B through 4 wallets, each logged
    ~1B → a 1013%-of-circulating, >total-supply impossibility). An upper bound
    that is routinely wrong is worse than no upper bound.

    What we report:
    * CONFIRMED-SOLD LOWER BOUND = (a) transfers from insider wallets into
      CEX-deposit addresses (deposit = sale by convention; fill is off-chain)
      + (b) insider wallets' OWN DEX swaps selling the token (token_sold=CA,
      tx_from ∈ insiders → a real buyer paid). Both are DIRECTED exits, so no
      round-trip double-count. (a)+(b) is a FLOOR: true selling is at least
      this, possibly more via routes we cannot label.
    * CURRENT INSIDER HOLDINGS (stock) = Σ current balance of the insider set
      — round-trip-immune (≤ total supply always). Includes still-locked
      vesting, so it is "% of supply under insider control", not free float.
    * PRICE = robust median DEX unit price (defeats amount_usd outliers);
      est. proceeds = confirmed_total × median.
    * Insider set = all traced rule_11 receivers EXCEPT exit infrastructure
      (cex_custody / dex_infra are destinations, not insider-held wallets).

    Args:
        rule11: raw rule_11 return (pre_launch_receivers).
        ca / symbol / listing_ts_ms / listing_date / circulating_supply /
        total_supply: from Section A.
    """
    receivers = list(rule11.get("pre_launch_receivers", []) or [])
    # v0.8.6.6: mining mode fallback — when rule_11 m6 lineage is empty
    # (cross-chain bridge / mining token w/ placeholder deployer), pipeline
    # injects mining cluster wallets (mint_authority + ht_dumpers + fanout +
    # cluster_graph union) as synthetic receivers so dump_tracker (a)/(b)
    # CEX/DEX confirmed-sell SQL runs against them. Unlocks "confirmed net
    # sellout" estimation for mining-class tokens (JCT/AOP/BTX previously
    # all showed '无法 reliably 估算').
    if extra_receivers:
        seen = {(r.get("addr") or "").lower() for r in receivers if r.get("addr")}
        for er in extra_receivers:
            ea = (er.get("addr") or "").lower()
            if ea and ea not in seen:
                receivers.append(er)
                seen.add(ea)
    dumper_dests = rule11.get("dumper_destinations", {}) or {}
    recv_by_addr: dict[str, dict] = {
        (r.get("addr") or "").lower(): r for r in receivers
    }
    circ = circulating_supply or total_supply or 0
    if not listing_date and listing_ts_ms:
        from datetime import datetime, timezone
        listing_date = datetime.fromtimestamp(listing_ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")

    # v0.9.1: surf enforces a 365-day block_date window on bsc_transfers /
    # bsc_dex_trades (discovered via SIREN 2026-06-14, listing 2025-02-19,
    # age 480 days → INVALID_REQUEST → confirmed_sellout silently $0).
    # Clamp date_floor to the 364-day safe window via surf_constraints.
    from surf_constraints import surf_safe_date_floor
    date_floor = surf_safe_date_floor(listing_date)

    # ── INSIDER SET ── all traced wallets EXCEPT exit infrastructure.
    # CEX-deposit / DEX-router addresses are destinations (tokens there have
    # LEFT insider control), not insider-held wallets — excluded from both the
    # source set (a)/(b) and the holdings stock. No depth / allocation logic:
    # we don't sum the `received_from_deployer` flow at all anymore (it
    # double-counts on round-trips), so the whole apparatus/perimeter/_depth
    # machinery is gone.
    #
    # v0.8.1: also detect & exclude PUSH AIRDROP RECIPIENTS. A `disperse`-
    # style batch transfer from the deployer to >=50 distinct retail
    # wallets in the pre-launch window is a retail airdrop — those EOAs
    # are not insiders, and counting their post-launch sells as "insider
    # 真实变现" inflates the (a)+(b) floor. Detection is one surf SQL
    # against the deployer-outflow tx window. See push_airdrop_detector
    # module docstring for threshold rationale (= 50 conservative).
    deployer_addr = (rule11.get("deployer") or "").lower() or None
    # v0.9.1: same 365-day clamp as date_floor above. The pre-launch
    # window for push-airdrop detection is bounded to listing_date itself,
    # so for old tokens this falls back to the 364-day surf safe floor.
    trace_floor = surf_safe_date_floor(
        rule11.get("trace_floor") or rule11.get("date_floor")
    )
    push_airdrop_result: dict[str, Any] = {}
    push_airdrop_set: set[str] = set()
    if deployer_addr and listing_date:
        try:
            push_airdrop_result = fetch_push_airdrop_recipients(
                ca, deployer_addr, trace_floor, listing_date,
                total_supply=float(total_supply) if total_supply else None,
            ) or {}
        except Exception as e:
            push_airdrop_result = {"__ERR": f"detector exception: {str(e)[:120]}",
                                   "airdrop_recipients": []}
        push_airdrop_set = {
            a.lower() for a in push_airdrop_result.get("airdrop_recipients") or []
            if isinstance(a, str) and a
        }

    insider_addrs = sorted({
        (r.get("addr") or "").lower() for r in receivers
        if r.get("addr")
        and not (r.get("is_cex_custody") or r.get("is_dex_infra"))
        and (r.get("addr") or "").lower() not in push_airdrop_set
    })
    # `supply` (the conservation ceiling for the cap + the %-supply denominator)
    # must be the REAL total supply — NOT a circulating fallback. circulating is
    # smaller than total, so using it as the "total" ceiling would over-cap the
    # floor downward and spuriously trip confirmed_capped (adversarial review HIGH #1). When
    # total_supply is unknown we simply do not cap (no reliable ceiling).
    supply = float(total_supply) if total_supply else None

    def _pct(x):
        return (x / circ * 100) if circ else None

    # TREE HOLDINGS prep — figure out which addresses need a balance fetch.
    # `missing` is computed UP-FRONT so the balance query can run alongside
    # the 3 confirmed-disposal queries in the parallel pool below.
    all_addrs = sorted({(r.get("addr") or "").lower() for r in receivers if r.get("addr")})
    known_bal = {
        (r.get("addr") or "").lower(): float(r.get("current_balance") or 0)
        for r in receivers if r.get("current_balance") is not None
    }
    missing = [a for a in all_addrs if a not in known_bal]

    # v0.7.19: 4 independent surf SQL queries run in parallel (was serial,
    # ~270s on COLLECT). Each `_run_surf_with_retry` call handles its own
    # back-off so the parallel pool does NOT amplify retry pressure — it
    # just collapses 4× sequential waits into max-of-4. Empirically
    # COLLECT drops from 270s → ~80s.
    #
    #   (a) insider → CEX-deposit (FLOOR component, gross flow capped later)
    #   (b) insider OWN DEX swaps of CA (FLOOR component, directed exit)
    #   (c) dex_sell_profile (median price + wash signal context)
    #   (d) current_balances for receivers whose balance rule_11 did not pre-fill
    #
    # All four are independent — no inter-query data dependency.
    def _fetch_cex():
        return fetch_apparatus_to_cex(ca, insider_addrs, date_floor)

    def _fetch_dex_sold():
        return fetch_apparatus_dex_sold(ca, insider_addrs, date_floor)

    def _fetch_profile():
        return fetch_dex_sell_profile(ca, date_floor) or {}

    def _fetch_balances():
        return fetch_current_balances(ca, missing, date_floor) if missing else {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=DUMP_TRACKER_WORKERS,
        thread_name_prefix="dump_tracker",
    ) as _ex:
        _fut_cex = _ex.submit(_fetch_cex)
        _fut_dex = _ex.submit(_fetch_dex_sold)
        _fut_prof = _ex.submit(_fetch_profile)
        _fut_bal = _ex.submit(_fetch_balances)
        # Defensive: a worker that raises propagates via .result(); we
        # default each bucket to its empty-shape so a single bad surf
        # response cannot crash the whole dump_tracker section. The
        # buckets_complete flag downstream will trip if cex/dexb came
        # back with ok=False.
        try:
            cex = _fut_cex.result()
        except Exception as e:
            print(f"[dump_tracker] cex fetch worker raised: {type(e).__name__}: {e}",
                  file=sys.stderr)
            cex = {"cex_tokens": 0.0, "cex_labels": [], "ok": False,
                   "error": f"{type(e).__name__}: {e}"[:120]}
        try:
            dexb = _fut_dex.result()
        except Exception as e:
            print(f"[dump_tracker] dex_sold fetch worker raised: {type(e).__name__}: {e}",
                  file=sys.stderr)
            dexb = {"dex_sold_tokens": 0.0, "n_swaps": 0, "ok": False,
                    "error": f"{type(e).__name__}: {e}"[:120]}
        try:
            profile = _fut_prof.result()
        except Exception as e:
            print(f"[dump_tracker] profile fetch worker raised: {type(e).__name__}: {e}",
                  file=sys.stderr)
            profile = {}
        try:
            fetched_bal = _fut_bal.result()
        except Exception as e:
            print(f"[dump_tracker] balances fetch worker raised: {type(e).__name__}: {e}",
                  file=sys.stderr)
            fetched_bal = {}

    # audit H6 fix: detect surf failure via sentinel __ERR key.
    # fetch_dex_sell_profile() and fetch_current_balances() now return
    # {"__ERR": <reason>} on transport failure instead of a plain {}.
    # Without this check, a surf 429 storm silently zeroes wash_dominated
    # / pure_insider_holds / top_seller_addrs while the report says
    # "buckets_complete: true" — a false-clean forensic.
    profile_ok = not (isinstance(profile, dict) and "__ERR" in profile)
    if not profile_ok:
        profile_err = profile.get("__ERR", "unknown")
        print(
            f"[dump_tracker] dex_sell_profile surf-failed: {profile_err}",
            file=sys.stderr,
        )
        # Replace the sentinel with an empty dict so downstream .get()
        # calls still work; the profile_ok flag captures the failure.
        profile = {}
    balances_ok = not (isinstance(fetched_bal, dict) and "__ERR" in fetched_bal)
    if not balances_ok:
        balances_err = fetched_bal.get("__ERR", "unknown")
        print(
            f"[dump_tracker] current_balances surf-failed: {balances_err}",
            file=sys.stderr,
        )
        fetched_bal = {}

    cex_tokens = cex.get("cex_tokens", 0.0)
    dex_tokens = dexb.get("dex_sold_tokens", 0.0)
    confirmed_raw = cex_tokens + dex_tokens
    # v0.9.2: per-window splits. Source columns added in the SQL via
    # CASE WHEN block_date >= today() - N, so zero extra surf credits.
    # These let users reconcile against short-horizon alerts (e.g.
    # EmberCN-style "过去 14 小时套现 $X") without our number being
    # dominated by 364-day cumulative.
    cex_tokens_7d = cex.get("cex_tokens_7d", 0.0)
    cex_tokens_30d = cex.get("cex_tokens_30d", 0.0)
    dex_tokens_7d = dexb.get("dex_sold_tokens_7d", 0.0)
    dex_tokens_30d = dexb.get("dex_sold_tokens_30d", 0.0)
    dex_real_usd_7d = float(dexb.get("dex_sold_usd_7d") or 0)
    dex_real_usd_30d = float(dexb.get("dex_sold_usd_30d") or 0)
    # ok=False = surf threw past all retries → the bucket's 0 is unknown, not a
    # real zero; flag so the report says "floor incomplete" not a false low.
    # audit H6: extended from (cex + dexb) to also require profile +
    # balances. A surf failure on EITHER profile or balances zeroes
    # downstream forensic claims (wash_dominated false-negative, etc.).
    # v0.8.1 audit HIGH fix: include push_airdrop detector status.
    # If it errored, we fall through to keeping ALL pre_launch_receivers in
    # the insider set (fail-open to old false-positive). Mark untrusted so
    # the report can disclose the partial-completeness state.
    push_airdrop_ok = push_airdrop_result.get("__ERR") is None or not deployer_addr
    buckets_complete = (
        bool(cex.get("ok")) and bool(dexb.get("ok"))
        and profile_ok and balances_ok and push_airdrop_ok
    )

    # TREE HOLDINGS (stock) — Σ current balance of the ENTIRE traced set (ALL
    # receivers, INCLUDING lockup/vesting and exit-infra-labelled wallets that
    # still hold a balance). This is the clean conservation anchor: balances
    # are stocks, never double-count, always ≤ total supply. total − tree_holds
    # = what physically LEFT the traced tree to end-buyers. (R2: tree holds 972M
    # = 97.3%; only ~27M left — the earlier 1013% was pure flow double-count.
    # Do NOT exclude exit-infra here: tokens sitting in a Binance-omnibus /
    # router wallet have not reached an end-buyer yet, so they are still "in the
    # tree" for the conservation bound — excluding them wrongly inflates "left".)
    tree_holds = sum(known_bal.get(a, fetched_bal.get(a, 0.0)) for a in all_addrs)

    # CONSERVATION CAP on the floor (stock guard). The (a) CEX bucket is a gross
    # directed flow; CEX deposit→sweep→re-deposit round-trips can inflate it
    # past what physically left the tree. The tree can only have SOLD what is no
    # longer in ANY traced wallet: max_left = total_supply − tree_holds (pure
    # stock, round-trip-immune). Cap confirmed-sold at that ceiling so the floor
    # stays physically valid. (R2: raw gross 135M > max_left 27M → capped; the
    # gross CEX flow was round-trip-inflated.)
    max_left = max(supply - tree_holds, 0.0) if supply else None
    confirmed_capped = (max_left is not None) and (confirmed_raw > max_left * 1.001)
    confirmed_total = min(confirmed_raw, max_left) if max_left is not None else confirmed_raw

    # Robust median DEX price (defeats amount_usd outliers) + wash signal.
    # `profile` was already filled in parallel above (v0.7.19); only the
    # median_px / wash-signal extraction happens here.
    # v1.2.5: bound median_px at the source — it is also decimals-broken for
    # non-18-decimal tokens (same surf dex_trades amount), and it feeds BOTH
    # confirmed_profit below AND the cex_effective_px fallback later. Bounding
    # here makes every downstream use sane.
    median_px = _sane_effective_price(profile.get("median_price_usd"), spot_price_usd)
    confirmed_profit = (confirmed_total * median_px) if (median_px and confirmed_total) else None

    # v0.7.21.10: NET SELL OUT (Net Sell Out / 确认净卖出)
    #
    # Gross Sell Out (above, `confirmed_est_profit_usd`) = confirmed_total ×
    # median price. Two problems on a wash-dominated token:
    #
    #   (1) median price across 200 top sellers is wash-inflatable — bot
    #       atomic round-trips ship token at MEV-aggregator quote prices
    #       that drag the per-seller median up; LAB ships median $2.91
    #       vs the apparatus' actual TWAP $0.88 (3.3× over-estimate).
    #
    #   (2) CEX deposit tokens are assumed to clear at median price even
    #       though the apparatus never directly traded at that level —
    #       they trade once they leave the exchange omnibus and we cannot
    #       see that leg.
    #
    # Net Sell Out is the apparatus' best on-chain-evidenced estimate:
    #
    #   - DEX leg: SUM(amount_usd) the apparatus themselves got on every
    #     swap (real settlement, time-weighted by ClickHouse partition).
    #     Free — fetched by the same SQL as `dex_sold_tokens` after
    #     v0.7.21.10.
    #
    #   - CEX leg: cex_tokens × apparatus DEX TWAP. The apparatus traded
    #     the same token in the same window; their TWAP is the closest
    #     time-weighted price we have. Falls back to median_px when DEX
    #     leg is empty (apparatus never self-swapped → no TWAP), and to
    #     None when both are unavailable.
    #
    # Net Sell Out is therefore strictly ≤ Gross Sell Out on
    # wash-dominated tokens (LAB: ≈ $131M vs Gross $389M) and ≈ equal on
    # clean tokens (no wash, TWAP ≈ median).
    dex_real_usd = float(dexb.get("dex_sold_usd") or 0)
    dex_twap_px = dexb.get("dex_twap_usd_per_token")
    # Effective price for the CEX leg: prefer the apparatus' own TWAP,
    # fall back to median_px (legacy estimator) when DEX leg is empty.
    cex_effective_px = _sane_effective_price(
        dex_twap_px if dex_twap_px else median_px, spot_price_usd)
    cex_value_usd = (cex_tokens * cex_effective_px) if (cex_effective_px and cex_tokens) else None
    if cex_value_usd is not None and dex_real_usd > 0:
        net_sellout_usd = cex_value_usd + dex_real_usd
    elif cex_value_usd is not None:
        net_sellout_usd = cex_value_usd
    elif dex_real_usd > 0:
        net_sellout_usd = dex_real_usd
    else:
        net_sellout_usd = None
    # v0.9.2: per-window Net Sell Out (same formula, just constrained to
    # the time bucket's CEX/DEX flows).
    cex_value_usd_7d = (cex_tokens_7d * cex_effective_px) if (cex_effective_px and cex_tokens_7d) else None
    cex_value_usd_30d = (cex_tokens_30d * cex_effective_px) if (cex_effective_px and cex_tokens_30d) else None
    def _net(_cex_usd, _dex_usd):
        if _cex_usd is not None and _dex_usd > 0:
            return _cex_usd + _dex_usd
        if _cex_usd is not None:
            return _cex_usd
        if _dex_usd > 0:
            return _dex_usd
        return None
    net_sellout_usd_7d = _net(cex_value_usd_7d, dex_real_usd_7d)
    net_sellout_usd_30d = _net(cex_value_usd_30d, dex_real_usd_30d)
    # Per-window totals (token-side) — capped same as cumulative.
    confirmed_total_7d = min(cex_tokens_7d + dex_tokens_7d, max_left or float("inf")) if (cex_tokens_7d + dex_tokens_7d) > 0 else 0.0
    confirmed_total_30d = min(cex_tokens_30d + dex_tokens_30d, max_left or float("inf")) if (cex_tokens_30d + dex_tokens_30d) > 0 else 0.0
    # Cap Net at Gross — Net should never exceed Gross in well-defined
    # cases (TWAP ≤ median in wash + TWAP > median is rare but possible
    # for clean tokens on a falling market). When Net > Gross by more
    # than 5% it almost certainly means the apparatus traded post-pump,
    # which is fine information but should be flagged as an upward
    # revision rather than a cap-breach.
    net_above_gross_pct = None
    if (confirmed_profit is not None and net_sellout_usd is not None
            and confirmed_profit > 0):
        net_above_gross_pct = (net_sellout_usd / confirmed_profit - 1.0) * 100.0

    tree_holds_pct_supply = (tree_holds / supply * 100) if supply else None

    # v0.7.19.4: split tree_holds (with lockup, conservation anchor) vs
    # pure_insider_holds (without lockup, narrative anchor). The old
    # field name `insider_holds_*` was semantically tree_holds — it
    # included Arkham-confirmed vesting / multisig / treasury / dex_infra
    # / cex_custody wallets, because the conservation cap math needs the
    # full stock (tokens sitting in a vesting contract have not reached
    # an end-buyer and so are still "in the tree" for the round-trip-
    # immune ceiling). But narrative templates paraphrased the field as
    # "内幕方 N 钱包仍掌控 X% 总供应", conflating vesting (public
    # schedule) with insider 潜伏 (opaque hand). User reading COLLECT
    # v0.7.19 caught the bug: vesting + Gnosis Safe at 80% supply were
    # narrated as "insider hoarding 80%" → misleading EXIT_IF_HOLDING
    # framing. Right fix: keep tree_holds as the conservation anchor
    # (used by max_left + confirmed_capped math), expose a SEPARATE
    # pure_insider_holds that excludes Arkham-labeled lockup wallets,
    # and have the render template cite pure_insider_holds in the
    # narrative table while keeping tree_holds in the conservation row.
    receivers_by_addr = {(r.get("addr") or "").lower(): r for r in receivers}
    pure_insider_holds = 0.0
    for a in all_addrs:
        r = receivers_by_addr.get(a) or {}
        # Skip Arkham-confirmed lockup wallets — they are NOT insider
        # potential dump pressure, their release is public schedule.
        if r.get("is_protocol_lockup"):
            continue
        # Exit-infra (cex_custody / dex_infra) wallets are destinations,
        # not insider holdings — tokens sitting in a Binance omnibus or
        # PancakeSwap router are not under insider control any more.
        if r.get("is_cex_custody") or r.get("is_dex_infra"):
            continue
        # v0.8.1: airdrop platform / claim distributor residuals are
        # earmarked for retail — un-claimed pool stock, not insider
        # potential dump pressure. is_protocol_lockup already covers
        # this when set by classifier (we routed is_airdrop_platform
        # into is_protocol_lockup), but be explicit for code clarity.
        if r.get("is_airdrop_platform"):
            continue
        # v0.8.1: push-airdrop retail recipients — flagged by SQL
        # detector above. Their balance is retail-held, not insider
        # potential. Removed from BOTH insider_addrs (so (a)/(b) skip)
        # AND pure_insider_holds (so the潜伏抛压 % does not inflate).
        if a in push_airdrop_set:
            continue
        bal = known_bal.get(a, fetched_bal.get(a, 0.0))
        pure_insider_holds += bal
    pure_insider_holds_pct_supply = (
        (pure_insider_holds / supply * 100) if supply else None
    )

    return {
        "insider_n_wallets": len(insider_addrs),
        # CONFIRMED-SOLD LOWER BOUND (a)+(b) — the headline. % of circulating.
        "confirmed_cex_tokens": cex_tokens,
        "confirmed_cex_pct": _pct(cex_tokens),
        "confirmed_cex_labels": cex.get("cex_labels", []),
        "confirmed_dex_tokens": dex_tokens,
        "confirmed_dex_pct": _pct(dex_tokens),
        "confirmed_dex_swaps": dexb.get("n_swaps", 0),
        "confirmed_total_tokens": confirmed_total,
        "confirmed_total_pct": _pct(confirmed_total),
        # v0.7.21.10: Gross Sell Out — historical name `confirmed_est_profit_usd`
        # kept for back-compat (Field-Authority locked field name); the render
        # template + i18n now label it "Gross Sell Out (确认毛卖出)".
        "confirmed_est_profit_usd": confirmed_profit,
        # v0.7.21.10: Net Sell Out — apparatus' time-weighted estimate.
        # DEX leg from real SUM(amount_usd); CEX leg from cex_tokens × DEX TWAP.
        # Strictly ≤ Gross on wash-dominated tokens (LAB: ≈ $131M vs $389M).
        "confirmed_net_sellout_usd": net_sellout_usd,
        # v0.9.2: per-window splits. EmberCN-style short-horizon alerts
        # reconcile against the 7d/30d numbers; the cumulative remains as
        # the long-horizon "this token has been getting harvested" signal.
        # Numbers are subsets of the cumulative: _7d ≤ _30d ≤ cumulative.
        "confirmed_net_sellout_usd_7d": net_sellout_usd_7d,
        "confirmed_net_sellout_usd_30d": net_sellout_usd_30d,
        "confirmed_cex_tokens_7d": cex_tokens_7d,
        "confirmed_cex_tokens_30d": cex_tokens_30d,
        "confirmed_dex_tokens_7d": dex_tokens_7d,
        "confirmed_dex_tokens_30d": dex_tokens_30d,
        "confirmed_dex_real_usd_7d": dex_real_usd_7d if dex_real_usd_7d > 0 else None,
        "confirmed_dex_real_usd_30d": dex_real_usd_30d if dex_real_usd_30d > 0 else None,
        "confirmed_total_tokens_7d": confirmed_total_7d,
        "confirmed_total_tokens_30d": confirmed_total_30d,
        "confirmed_total_pct_7d": _pct(confirmed_total_7d),
        "confirmed_total_pct_30d": _pct(confirmed_total_30d),
        # Breakdown components so the render template (and any audit reader)
        # can show the user how the Net number was constructed without
        # re-deriving from the raw SQL.
        "confirmed_dex_real_usd": dex_real_usd if dex_real_usd > 0 else None,
        "confirmed_cex_estimated_usd": cex_value_usd,
        # v1.2.5: report the EFFECTIVE per-token price actually used (spot-bounded),
        # not the raw DEX twap — otherwise a decimals-broken $243B/token leaks into
        # the rendered net-sellout line even though the USD value is now sane.
        "apparatus_dex_twap_usd_per_token": cex_effective_px,
        # Diagnostic only — Net should be < Gross on wash tokens; > Gross
        # signals the apparatus traded into a price spike (rare but valid).
        "net_above_gross_pct": net_above_gross_pct,
        # True = floor hit the stock conservation ceiling (total − holdings):
        # the gross CEX/DEX flow exceeded what physically left insider wallets
        # (round-trips), so the floor was clamped down to stay valid.
        "confirmed_capped": confirmed_capped,
        # v0.7.19.4: TREE holdings (stock, ALL traced wallets incl. lockup +
        # exit-infra) — conservation anchor for `max_left` / confirmed_capped.
        # Used by render's "内幕树当前持有 (含未解锁锁仓)" row.
        "tree_holds_tokens": tree_holds,
        "tree_holds_pct_supply": tree_holds_pct_supply,
        # v0.7.19.4: PURE insider holdings (stock, EXCLUDING Arkham-confirmed
        # protocol_lockup + cex_custody + dex_infra) — narrative anchor.
        # Used by render's "纯内幕当前持有 (不含 vesting / 多签 / 中转)" row
        # and by the verdict one-liner, so the report no longer paraphrases
        # vesting as "insider 抛压".
        "pure_insider_holds_tokens": pure_insider_holds,
        "pure_insider_holds_pct_supply": pure_insider_holds_pct_supply,
        # v0.7.19.4 backward-compat alias for any external consumer (none
        # known in-tree): keep the old name pointing at tree_holds so a
        # consumer that didn't read the changelog still gets the
        # conservation-anchor value. Internal render template + skeleton
        # writer use the new explicit names.
        "insider_holds_tokens": tree_holds,
        "insider_holds_pct_supply": tree_holds_pct_supply,
        "median_price_usd": median_px,
        # Context: is the token's DEX selling bot-laundered?
        "wash_dominated": profile.get("wash_dominated", False),
        "n_dex_sellers": profile.get("n_sellers", 0),
        "total_dex_swaps": profile.get("total_swaps", 0),
        "top_seller_swaps": profile.get("top_seller_swaps", 0),
        # v0.7.21: expose the seller address list (up to 200, sorted by
        # swap count DESC) so flow_operator_detector reuses dump_tracker's
        # already-paid SQL instead of refetching. Empty when DEX profile
        # fetch failed.
        "top_seller_addrs": profile.get("top_seller_addrs", []),
        # False = a confirmation query failed past all retries → floor may undercount.
        "buckets_complete": buckets_complete,
        # v0.8.1: push airdrop detector audit trail. n=0 means no batch
        # transfer in the pre-launch window passed the threshold (project
        # did not push-airdrop, or did it through a claim contract instead
        # — claim contracts trigger is_airdrop_platform below). Diagnostic
        # so the report can show "N retail recipients excluded from insider
        # set, M tokens diverted" and the user can sanity-check the call.
        "push_airdrop_n_recipients": int(push_airdrop_result.get("n_recipients") or 0),
        "push_airdrop_n_tx": int(push_airdrop_result.get("n_tx") or 0),
        "push_airdrop_tokens_total": float(push_airdrop_result.get("tokens_airdropped_total") or 0.0),
        "push_airdrop_threshold_used": int(push_airdrop_result.get("_threshold_used") or 0),
        "push_airdrop_max_recipients_per_tx": int(push_airdrop_result.get("max_recipients_per_tx") or 0),
        "push_airdrop_error": push_airdrop_result.get("__ERR"),
        # v0.8.1: airdrop-platform (third-party distribution) count among
        # receivers. >0 = at least one Arkham-labeled launchpad / task /
        # SaaS contract held un-claimed retail stock; its balance was
        # removed from pure_insider_holds.
        "airdrop_platform_n_wallets": sum(
            1 for r in receivers if r.get("is_airdrop_platform")
        ),
    }
