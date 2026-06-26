#!/usr/bin/env python3
"""section_liq.py — Section LIQ: Alpha 5% depth + DEX main pool + LP 24h flow.

Output:
- current_price_usd (from DexScreener best pair)
- dex_pool_addr (highest-liquidity pair for the token)
- dex_pool_liquidity_usd
- dex_pool_volume_24h_usd
- alpha_5pct_depth_usd_est (heuristic from alpha_vol_24h, since no public
  order-book API for Alpha-only tokens is documented in v0.6)
- lp_24h_flow_pct (% change in pool token balance via surf)
- liq_rows[] for report
- decision_action numeric slots (pipeline replaces stubs in decision_action_block)
- decision_anchors_partial[] entries

v0.6 (2026-05-24, Phase B.1)
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
import sys

sys.path.insert(0, str(Path(__file__).parent))
from parallel_surf import run_parallel
from i18n import t   # v0.6.2 i18n
from chain_router import (  # v0.7.20 / v0.7.21.7 / v0.7.21.8
    transfers_table,
    dex_trades_table,
    get_active_chain as _chain_get_active,
    sql_supported as _sql_supported,
    decimals_factor_str,
)


def _curl_json(url: str, timeout: int = 8) -> dict | None:
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout), url],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
            timeout=timeout + 5,   # v0.9.9: subprocess ceiling > curl --max-time (deadlock guard)
        )
        if proc.returncode != 0:
            return None
        return json.loads(proc.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


# v0.9.8 (BR 2026-06-17 LP bug): chain_router prefix → DexScreener chainId.
# DexScreener uses its own chain slugs; map the skill's active-chain prefix.
#
# v1.0.3 (O 2026-06-20): the pipeline calls fetch_dexscreener_main_pool with
# `meta.primary_chain`, which is a CoinGecko PLATFORM NAME (binance-smart-chain),
# NOT a chain_router prefix (bsc). Since v0.9.8 the lookup silently returned
# None for every chain whose CoinGecko name != its prefix — bsc / arbitrum /
# polygon / optimism (i.e. MOST Binance Alpha tokens) — so DexScreener LP fell
# through to the surf-token-holders fallback (no USD) and the report showed LP
# as 数据缺失 / None. ETH + Base happened to work only because their CoinGecko
# name == their prefix. We now accept BOTH formats so the lookup can't break on
# whichever the caller passes.
_DEXSCREENER_CHAIN_MAP = {
    # chain_router prefixes
    "bsc": "bsc",
    "ethereum": "ethereum",
    "base": "base",
    "arbitrum": "arbitrum",
    "polygon": "polygon",
    "optimism": "optimism",
    "avalanche": "avalanche",
    "solana": "solana",
    # CoinGecko platform names (the primary_chain format the pipeline passes)
    "binance-smart-chain": "bsc",
    "arbitrum-one": "arbitrum",
    "polygon-pos": "polygon",
    "optimistic-ethereum": "optimism",
}


def fetch_dexscreener_main_pool(
    ca: str, active_chain: str, anchor_price: float | None = None,
) -> dict[str, Any] | None:
    """v0.9.8 root-cause fix for the BR $34.95 LP bug.

    The surf-token-holders + Arkham-label LP path (discover_main_pool) is
    fragile two ways, both hit by BR (Bedrock):
      1. Arkham labels are async — a freshly-active PancakeSwap V3 pool
         may not yet carry entity_type=dex at fetch time, so the real
         main pool is missed and LP reads None / a wrong pool.
      2. V4 singleton trap — PancakeSwap/Uniswap V4 store ALL pools'
         tokens in ONE `PoolManager` singleton (0x000...4444). Arkham
         labels it `PoolManager`, the regex `\\bpool\\b` matches it, and
         the skill treats its meaningless shared-vault balance as the
         token's LP (BR: 207 tokens = $34.95 vs real $1M V3 pool).

    DexScreener reads on-chain pool RESERVES directly (no Arkham
    dependency, no singleton confusion), so it is the authoritative LP
    source. Returns the highest-liquidity pool on `active_chain`:
        {pool_addr, price_usd, liquidity_usd, volume_24h_usd, fdv,
         market_cap, dex_id, _source: "dexscreener"}
    or None on any failure (caller falls back to the surf path).
    """
    if not ca:
        return None
    # adversarial review Finding 9 (MED): Solana base58 mint addresses are CASE-SENSITIVE.
    # `ca.lower()` corrupts them. Only lowercase EVM (0x-hex, case-insensitive).
    if active_chain == "solana":
        ca_norm = ca
    else:
        ca_norm = ca.lower()
    ca = ca_norm
    ds_chain = _DEXSCREENER_CHAIN_MAP.get(active_chain)
    doc = _curl_json(
        f"https://api.dexscreener.com/latest/dex/tokens/{ca}", timeout=8,
    )
    if not doc or not isinstance(doc.get("pairs"), list):
        return None
    # adversarial review Finding 9: case-aware address comparison helper.
    _cmp = (lambda a: a) if active_chain == "solana" else (lambda a: (a or "").lower())
    # Filter to the active chain + token as BASE token, pick max LP.
    # CRITICAL (adversarial review-flagged): DexScreener's `priceUsd` always refers to
    # the BASE token. BR has 2 pairs where it is the QUOTE (e.g. "Vyx/BR")
    # — those pairs' priceUsd is the OTHER token's price (Vyx $0.0198), not
    # BR's. If such a quote-pair had max LP we'd report the wrong price.
    # Restricting to baseToken==ca guarantees price_usd is the subject
    # token's price. Quote-side pools are typically small and excluding
    # them is the correct trade-off (price correctness > marginal LP
    # completeness; the surf fallback still sees them).
    if ds_chain is None:
        # Unknown chain mapping — refuse to guess across chains (would
        # pick a pool on the wrong chain). Fall back to surf path.
        return None
    # First pass: collect base-pair candidates + their prices, so we can
    # compute a consensus price for the corrupted-pair filter below.
    raw = []
    for p in doc["pairs"]:
        if (p.get("chainId") or "").lower() != ds_chain:
            continue
        base = _cmp((p.get("baseToken") or {}).get("address"))
        if base != ca:
            continue
        lp = (p.get("liquidity") or {}).get("usd")
        if lp is None:
            continue
        try:
            px = float(p.get("priceUsd")) if p.get("priceUsd") else None
        except (TypeError, ValueError):
            px = None
        raw.append((p, float(lp), px))
    if not raw:
        return None

    # v1.0.0 (O / o1.exchange 2026-06-18) + adversarial review v1.0.0 R1 hardening:
    # corrupted-pair price filter. DexScreener listed a $900M "pool" for O
    # with priceUsd 4.5e26 and $62 24h vol — a broken/fabricated pair.
    #
    # Anchor priority (most → least trustworthy):
    #   1. surf RTI price (`anchor_price` arg) — an EXTERNAL aggregate
    #      (CEX+DEX, surf project-detail) NOT derived from any single
    #      DexScreener pair, so a fake/wash pool cannot poison it. This is
    #      the adversarial review R1 Finding-1 fix: max-vol self-anchor is defeatable by
    #      a well-funded wash that fakes $50M vol → becomes the anchor →
    #      real pools wrongly rejected. An external anchor closes that hole.
    #   2. Highest-24h-VOLUME priced pool — fallback when surf has no
    #      price. Volume is hard (not impossible) to fake; weaker but
    #      better than nothing.
    if anchor_price and anchor_price > 0:
        _anchor = anchor_price
    else:
        _anchor = None
        _anchor_vol = -1.0
        for p, lp, px in raw:
            if px and px > 0:
                v = (p.get("volume") or {}).get("h24") or 0
                if v > _anchor_vol:
                    _anchor_vol = v
                    _anchor = px

    candidates = []
    for p, lp, px in raw:
        txns = p.get("txns") or {}
        h24 = txns.get("h24") or {}
        n_tx = (h24.get("buys") or 0) + (h24.get("sells") or 0)
        vol24 = (p.get("volume") or {}).get("h24") or 0
        has_activity = (n_tx > 0) or (vol24 > 0)

        # Price present: corrupted-price reject (deviates > 5x from anchor).
        if px and px > 0:
            if _anchor and _anchor > 0:
                ratio = px / _anchor
                if ratio > 5.0 or ratio < 0.2:
                    continue   # price disagrees with the token's true price ⇒ fake
        else:
            # adversarial review R1 Finding 2 (HIGH): a large pool with NO price is a
            # corrupted-pair bypass — it skips the price filter and could
            # win on fake LP. A real pool always reports a price. Demote
            # any >$50K no-price pool so it loses to a real priced pool.
            if lp > 50_000:
                has_activity = False

        # v1.0.0 turnover demote: a >$50K pool with near-zero vol/LP
        # turnover is dead/fake even if vol > 0 (O garbage: $62 on $900M =
        # 7e-8). Demote below real pools. Small pools (<$50K) exempt
        # (legit quiet new pools). Demote-not-reject: a sleepy big pool
        # that is the ONLY candidate still gets picked (low-confidence).
        if lp > 50_000:
            turnover = (vol24 / lp) if lp else 0
            if turnover < 0.0001:
                has_activity = False
        candidates.append((has_activity, lp, p))

    if not candidates:
        return None
    # Sort: pools WITH real activity first, then by LP desc. A fake
    # high-LP pool (corrupted price filtered out, or near-zero turnover
    # demoted) loses to any real pool.
    candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
    _has_activity, lp_usd, best = candidates[0]
    try:
        price = float(best.get("priceUsd")) if best.get("priceUsd") else None
    except (TypeError, ValueError):
        price = None
    return {
        "pool_addr": _cmp(best.get("pairAddress")) or None,
        "price_usd": price,
        "liquidity_usd": lp_usd,
        "volume_24h_usd": (best.get("volume") or {}).get("h24"),
        "fdv": best.get("fdv"),
        "market_cap": best.get("marketCap"),
        "dex_id": best.get("dexId"),
        # adversarial review Finding 1: flag low-confidence picks (no real 24h activity)
        # so the report / downstream can treat the LP as unverified.
        "_lp_low_confidence": not _has_activity,
        "_source": "dexscreener",
    }


def discover_main_pool(
    ca: str,
    scope_chain_lp: dict[str, dict[str, Any]] | None = None,
    scope_realtime_token_info: dict[str, Any] | None = None,
    primary_chain: str | None = None,
) -> dict[str, Any]:
    """v0.7.10: Pick main DEX pool from surf real-time data (no DexScreener).

    Reads pre-computed `chain_lp_realtime` (surf token-holders + DEX-label
    classification per chain) and `realtime_token_info` (surf project-detail
    aggregate price/vol/FDV). Falls back to "no pool" only when surf returned
    no DEX-labeled holders.

    Returns same shape as v0.6/v0.7.9:
        {
            "pool_addr": "0x..." or None,
            "price_usd": float or None,
            "liquidity_usd": float or None,
            "volume_24h_usd": float or None,   # aggregate cross-chain (CEX+DEX)
            "fdv": float or None,
            "_status": "OK" | "NOT_FOUND" | "API_DOWN",
        }
    """
    chain_lp = scope_chain_lp or {}
    rti = scope_realtime_token_info or {}

    # v0.9.8 (BR 2026-06-17): DexScreener is the AUTHORITATIVE LP source.
    # It reads on-chain pool reserves directly — no Arkham-label dependency,
    # no V4-singleton confusion (the two bugs that gave BR a $34.95 LP for
    # a token with a real $1M PancakeSwap V3 pool). The surf-token-holders
    # path below remains as a fallback for when DexScreener is down or has
    # no listing.
    _ds_chain = primary_chain or _chain_get_active()
    # adversarial review v1.0.0 R1 Finding 1: pass surf RTI price as the EXTERNAL price
    # anchor so a fake/wash DexScreener pool can't self-anchor the
    # corrupted-price filter. surf project-detail price is a cross-chain
    # CEX+DEX aggregate, independent of any single DexScreener pair.
    try:
        _rti_px = rti.get("price_usd")
        _rti_px = float(_rti_px) if _rti_px not in (None, "") else None
    except (TypeError, ValueError):
        _rti_px = None
    _ds = fetch_dexscreener_main_pool(ca, _ds_chain, anchor_price=_rti_px)
    if _ds and _ds.get("liquidity_usd") is not None:
        # Keep surf project-detail aggregate vol/fdv (cross-chain CEX+DEX)
        # as primary; DexScreener vol/fdv is single-pool DEX-only. adversarial review
        # Finding 5 (LOW): track which source actually supplied each so the
        # report note doesn't falsely claim "surf project-detail" when the
        # DexScreener fallback was used.
        _vol_from_surf = rti.get("volume_24h_usd") is not None
        _fdv_from_surf = rti.get("fdv_usd") is not None
        return {
            "pool_addr": _ds.get("pool_addr"),
            "price_usd": _ds.get("price_usd") if _ds.get("price_usd") is not None
                         else rti.get("price_usd"),
            "liquidity_usd": _ds.get("liquidity_usd"),
            "volume_24h_usd": rti.get("volume_24h_usd") if _vol_from_surf
                              else _ds.get("volume_24h_usd"),
            "fdv": rti.get("fdv_usd") if _fdv_from_surf else _ds.get("fdv"),
            "volume_source": "surf" if _vol_from_surf else "dexscreener",
            "fdv_source": "surf" if _fdv_from_surf else "dexscreener",
            "lp_low_confidence": bool(_ds.get("_lp_low_confidence")),
            "_status": "OK",
            "_source": "dexscreener",
        }

    # Pick pool from the primary chain's surf top_pool_addr; if primary not
    # set, fall back to the chain with the highest lp_usd across all entries.
    chain_entry: dict[str, Any] = {}
    if primary_chain and primary_chain in chain_lp:
        chain_entry = chain_lp[primary_chain] or {}
    if not chain_entry or not chain_entry.get("top_pool_addr"):
        # Pick max-lp_usd chain that has a top_pool_addr.
        cands = [
            (p, v) for p, v in chain_lp.items()
            if v.get("top_pool_addr") and (v.get("lp_usd") or 0) > 0
        ]
        if cands:
            cands.sort(key=lambda kv: kv[1].get("lp_usd") or 0, reverse=True)
            _, chain_entry = cands[0]

    pool_addr = chain_entry.get("top_pool_addr")
    lp_usd = chain_entry.get("lp_usd")
    price_usd = rti.get("price_usd")
    vol_24h_usd = rti.get("volume_24h_usd")
    fdv = rti.get("fdv_usd")

    if not pool_addr and (not rti or not rti.get("fetch_ok")):
        # Neither surf token-holders nor project-detail produced anything.
        return {"pool_addr": None, "price_usd": None, "liquidity_usd": None,
                "volume_24h_usd": None, "fdv": None, "_status": "API_DOWN"}
    if not pool_addr:
        return {"pool_addr": None, "price_usd": price_usd, "liquidity_usd": None,
                "volume_24h_usd": vol_24h_usd, "fdv": fdv, "_status": "NOT_FOUND"}

    return {
        "pool_addr": pool_addr,
        "price_usd": price_usd,
        "liquidity_usd": lp_usd,
        "volume_24h_usd": vol_24h_usd,
        "fdv": fdv,
        "_status": "OK",
    }


def lp_24h_flow(ca: str, pool_addr: str | None, workdir: Path | None = None) -> dict[str, Any]:
    """Surf query: pool token in/out in last 24h.

    Returns {lp_in_tokens, lp_out_tokens, net_pct} or empty dict if no pool.

    v0.7.21.8: skip on chains without surf onchain-sql coverage (Solana).
    The query would hit UNKNOWN_TABLE and waste a credit.
    """
    if not pool_addr:
        return {}
    if not _sql_supported():
        return {"_skip_reason": "surf_no_sql_solana"}
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="lp24_"))
    workdir = Path(workdir)
    workdir.mkdir(exist_ok=True, parents=True)

    q = workdir / "q_lp24.json"
    q.write_text(json.dumps({
        "max_rows": 2,
        "sql": (
            f"SELECT "
            f"sum(if(\"to\" = '{pool_addr}', toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}, 0)) AS lp_in, "
            f"sum(if(\"from\" = '{pool_addr}', toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}, 0)) AS lp_out "
            f"FROM {transfers_table()} "
            f"WHERE contract_address = '{ca if _chain_get_active() == 'solana' else ca.lower()}' "
            f"AND block_time >= now() - INTERVAL 1 DAY "
            f"AND block_date >= today() - 2"
        ),
    }), encoding="utf-8")
    results, _ = run_parallel([str(q)])
    resp = results[str(q)]
    if "error" in resp:
        return {"_error": resp["error"]}
    data = (resp.get("data") or [{}])[0]
    lp_in = float(data.get("lp_in", 0) or 0)
    lp_out = float(data.get("lp_out", 0) or 0)
    net_pct = ((lp_in - lp_out) / lp_in * 100.0) if lp_in > 1 else 0.0
    return {"lp_in_tokens": lp_in, "lp_out_tokens": lp_out, "net_pct": round(net_pct, 2)}


def run(
    ca: str,
    symbol: str,
    alpha_vol_24h_usd: float | None = None,
    alpha_price_usd: float | None = None,
    scope_chain_lp: dict[str, dict[str, Any]] | None = None,
    scope_realtime_token_info: dict[str, Any] | None = None,
    primary_chain: str | None = None,
) -> dict[str, Any]:
    """Section LIQ entrypoint.

    v0.7.10: takes surf realtime scope data (chain_lp_realtime,
    realtime_token_info, primary_chain) — no more DexScreener fetch. Same
    output shape as v0.7.9 so downstream consumers (decision_summary,
    decision_anchors) don't need changes.

    Args:
        ca: contract address
        symbol: e.g. "TOKEN"
        alpha_vol_24h_usd: from Section A, used to estimate Alpha 5% depth
        scope_chain_lp: scope["chain_lp_realtime"] from section_a (surf
            token-holders + DEX-label real-time LP per chain).
        scope_realtime_token_info: scope["realtime_token_info"] (surf
            project-detail aggregate price/vol/FDV).
        primary_chain: scope["primary_chain"] — which chain's pool to surface.

    Returns full LIQ data + decision anchors + decision_action numeric updates.
    """
    pool = discover_main_pool(
        ca,
        scope_chain_lp=scope_chain_lp,
        scope_realtime_token_info=scope_realtime_token_info,
        primary_chain=primary_chain,
    )
    flow = lp_24h_flow(ca, pool.get("pool_addr"))

    # Alpha 5% depth heuristic: vol_24h / 96 (15-min slice) * 0.05 (5% slip)
    # Real API for order book on Alpha-only tokens is not publicly stable;
    # heuristic gives an order-of-magnitude estimate. Phase B+ may replace
    # with verified endpoint or accept INSUFFICIENT_DATA marker.
    alpha_5pct_depth_est = None
    if alpha_vol_24h_usd:
        alpha_5pct_depth_est = int(alpha_vol_24h_usd / 96 * 0.05)

    # Decision action numeric slots (replaces stub $30000 from pipeline alpha.3)
    # Tranche max = Alpha 5% depth ÷ 3 batches (conservative)
    tranche_max_usd = (
        max(int(alpha_5pct_depth_est / 3), 1000)
        if alpha_5pct_depth_est else 10000
    )
    # v0.7.16: price fallback chain. surf project-detail can NOT_FOUND a real
    # listed token (GUA — listed 3 months, still not indexed). In that case
    # `pool["price_usd"]` is None and every downstream price cell (TGE table,
    # stop-loss trigger, ALLOC USD figures) renders as "—". Per the user
    # directive (memory feedback_binance_alpha_vol_must_fetch.md), the Alpha
    # token-list endpoint IS the source of truth for Alpha-listed price/vol —
    # use it as a fallback. (dump_tracker.median_price_usd is wired in by the
    # pipeline as a last-resort fallback after dump_tracker runs.)
    # adversarial review HIGH#2: `or alpha_price_usd` would treat a legit 0 as missing.
    # crypto price = 0 is exotic but possible (paused listing / fresh launch
    # with no swaps yet) → preserve the surf 0 instead of silently swapping to
    # the Alpha API value. Same `is not None` guard on stop_loss.
    _pool_price = pool.get("price_usd")
    current_price = _pool_price if _pool_price is not None else alpha_price_usd
    stop_loss_trigger_price = (current_price * 0.85) if current_price is not None else None

    # v0.6.2: anchors + notes via i18n. Values stay as f-strings (data + format).
    dash = t("common.none_dash")
    liq_rows = [
        {
            "anchor": t("section.liq.label_5pct_depth"),
            "value": f"${alpha_5pct_depth_est:,.0f}" if alpha_5pct_depth_est else dash,
            "note": t("section.liq.note_5pct_depth"),
        },
        {
            "anchor": t("section.liq.label_dex_lp"),
            "value": f"${pool['liquidity_usd']:,.0f}" if pool.get("liquidity_usd") else dash,
            "note": (
                f"surf {pool['pool_addr'][:10]}…" if pool.get("pool_addr")
                else t("section.liq.note_no_pool")
            ),
        },
        {
            "anchor": t("section.liq.label_dex_vol"),
            "value": f"${pool['volume_24h_usd']:,.0f}" if pool.get("volume_24h_usd") else dash,
            "note": t("sec2.liq_note_dex_vol_source"),
        },
        {
            "anchor": t("section.liq.label_lp_flow"),
            "value": (
                t("section.liq.value_lp_flow_full",
                  net_pct=flow.get("net_pct"),
                  lp_in=flow.get("lp_in_tokens", 0),
                  lp_out=flow.get("lp_out_tokens", 0))
                if flow.get("lp_in_tokens") else dash
            ),
            # v0.7.21.8: don't surface a bogus "surf agent.solana_transfers"
            # source on a chain whose SQL table doesn't exist. The skip is
            # decided by chain_router.sql_supported() rather than the flow
            # dict because lp_24h_flow returns {} (no skip key) when there
            # is no pool_addr to query, which on Solana is the common case.
            "note": (
                t("sec2.liq_note_lp_flow_no_sql")
                if not _sql_supported()
                else f"surf {transfers_table()}"
            ),
        },
        {
            "anchor": t("section.liq.label_dex_addr"),
            "value": f"`{pool['pool_addr']}`" if pool.get("pool_addr") else dash,
            "note": (
                t("section.liq.note_dex_addr", fdv=int(pool['fdv']))
                if pool.get("fdv") else ""
            ),
        },
    ]

    # Decision anchors fragments (pipeline merges into report_data.decision_anchors)
    decision_anchors_partial = [
        {
            "anchor": t("section.liq.decision_anchor_alpha_5pct"),
            "value": f"${alpha_5pct_depth_est:,.0f}" if alpha_5pct_depth_est else t("common.unknown"),
            "status": (
                t("section.liq.status_depth_good") if (alpha_5pct_depth_est or 0) >= 50000
                else t("section.liq.status_depth_medium") if (alpha_5pct_depth_est or 0) >= 5000
                else t("section.liq.status_depth_thin")
            ),
        },
        {
            "anchor": t("section.liq.decision_anchor_dex_lp_usd"),
            "value": f"${pool['liquidity_usd']:,.0f}" if pool.get("liquidity_usd") else dash,
            "status": "🟢" if (pool.get("liquidity_usd") or 0) >= 200000
                     else "🟡" if (pool.get("liquidity_usd") or 0) >= 50000
                     else "🔴",
        },
        {
            "anchor": t("section.liq.label_lp_flow"),
            "value": f"{flow.get('net_pct'):+.2f}%" if "net_pct" in flow else dash,
            "status": "🟢" if abs(flow.get("net_pct") or 0) < 5
                     else "🟡" if abs(flow.get("net_pct") or 0) < 20
                     else "🔴",
        },
    ]

    return {
        "current_price_usd": current_price,
        "dex_pool_addr": pool.get("pool_addr"),
        "dex_pool_liquidity_usd": pool.get("liquidity_usd"),
        "dex_pool_volume_24h_usd": pool.get("volume_24h_usd"),
        "fdv": pool.get("fdv"),
        "alpha_5pct_depth_usd_est": alpha_5pct_depth_est,
        "lp_24h_flow": flow,
        "liq_rows": liq_rows,
        "decision_anchors_partial": decision_anchors_partial,
        # Numeric updates for decision_action_block
        "decision_action_overrides": {
            "tranche_max_usd": tranche_max_usd,
            "stop_loss_trigger_price": round(stop_loss_trigger_price, 6) if stop_loss_trigger_price else None,
        },
        "_probes": {
            "dexscreener": pool["_status"],
            "lp_flow_surf": "OK" if flow else "NO_POOL",
        },
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("ca")
    ap.add_argument("symbol")
    ap.add_argument("--alpha-vol-24h-usd", type=float, default=None)
    args = ap.parse_args()
    result = run(args.ca, args.symbol, alpha_vol_24h_usd=args.alpha_vol_24h_usd)
    print(json.dumps(result, ensure_ascii=False, indent=2))
