"""v0.7.26 — Deterministic behavior classifier.

Translates raw 检测器 outputs into 10 multi-label "庄家行为画像"
categories (4 大类: 筹码准备 / 成交制造 / 出货行为 / 协同结构).

Thresholds calibrated via v0.7.25.5 backtest on 8 historical
skeleton.json files (BSC tokens + 2 Solana abort negatives). See
v0725_5_CALIBRATION.md for empirical evidence and threshold delta vs
ChatGPT v0.8 spec.

SCOPE / CONTEXT:
  This classifier targets ONLY Context B (per M47 methodology context
  selection): crypto-operator-driven Binance Alpha tokens, where
  insider / operator behavior dominates and frequentist-friendly
  liquid-market thresholds (Context A) do not apply.

  Do NOT use these thresholds on Context A assets (BTC / ETH /
  large-cap CEX-listed tokens) without re-calibration — the wash bot
  share floor (0.05) would falsely flag legit HFT activity, and the
  "insider hold ≥2%" trigger would falsely flag legit VC / treasury
  positions.

CALIBRATION CAVEATS (small n=8 sample):
  - LOO-sensitivity: each of H/JCT/BEAT does heavy lifting in the
    sample (jackknife removes any → ≥1 threshold's STRONG count drops
    by 1). See scripts/v0725_5_calibration_data.md.
  - D1 STRONG ≥ 4 — derived from sample max=3 (H only). Lowered from
    ChatGPT's ≥5 to enable future fire, but UNVALIDATED.
  - C2 MEDIUM/WEAK never fire in 8-token sample. Kept in code for
    future mid-range hits.
  - Schedule v0.8 expanded calibration (n ≥ 30).

Architecture (per ChatGPT v3 spec):
  raw_detectors → behavior_classifier → monitoring_ranker (v0.7.27)
  → markdown_renderer

The classifier is the *only* place that decides "what is happening
on-chain". Renderer should never invent labels — it just translates the
classifier's output into human-readable narrative.

Output shape:
  {
    "active_labels": [str],      # all non-OFF labels, sorted by severity
    "primary_behavior": str,     # highest-severity single label, or None
    "by_label": {
      "<label_id>": {
        "severity": str,           # STRONG / MEDIUM / WEAK / OFF
        "category": str,           # A/B/C/D
        "trigger_metrics": {...},  # raw inputs that fired the trigger
        "human_summary_zh": str    # 1-sentence Chinese description
      }
    }
  }

Multi-label by design: A1 + B1 + C3 + D2 can all be active on the same
token. ChatGPT's earlier mutex gates (e.g. A1 trigger required
anomaly < 10) were dropped after calibration showed they suppress true
positives.
"""
from __future__ import annotations

from typing import Any

from i18n import t   # v0.6.2 i18n

# ----------------------------------------------------------------------
# Severity ranking (used to pick primary_behavior + sort active_labels)
# ----------------------------------------------------------------------
_SEVERITY_RANK = {"STRONG": 3, "MEDIUM": 2, "WEAK": 1, "OFF": 0}

# Behavior labels grouped by category. Order within each category =
# priority for primary_behavior tiebreak when multiple labels share
# the highest severity.
_BEHAVIOR_ORDER = [
    "A1", "A2", "A3",   # 筹码准备
    "B1", "B2",         # 成交制造
    "C1", "C2", "C3",   # 出货行为
    "D1", "D2",         # 协同结构
]

_CATEGORY_OF = {
    "A1": "A", "A2": "A", "A3": "A",
    "B1": "B", "B2": "B",
    "C1": "C", "C2": "C", "C3": "C",
    "D1": "D", "D2": "D",
}

# v0.6.2 i18n: built lazily (at build_profile call time) so the active
# language set by the pipeline is honored. Enum keys (A1/B1/... and
# A/B/C/D) are stable; only the display values are translated.
def _label_names_zh() -> dict:
    return {
        "A1": t("behavior.label_name.A1"),
        "A2": t("behavior.label_name.A2"),
        "A3": t("behavior.label_name.A3"),
        "B1": t("behavior.label_name.B1"),
        "B2": t("behavior.label_name.B2"),
        "C1": t("behavior.label_name.C1"),
        "C2": t("behavior.label_name.C2"),
        "C3": t("behavior.label_name.C3"),
        "D1": t("behavior.label_name.D1"),
        "D2": t("behavior.label_name.D2"),
    }


def _category_names_zh() -> dict:
    return {
        "A": t("behavior.category_name.A"),
        "B": t("behavior.category_name.B"),
        "C": t("behavior.category_name.C"),
        "D": t("behavior.category_name.D"),
    }


def _g(d: Any, *keys: str, default: Any = None) -> Any:
    """Safe nested .get() — returns default if any link in chain missing."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _len(d: Any, *keys: str) -> int:
    v = _g(d, *keys, default=[])
    return len(v) if isinstance(v, (list, dict)) else 0


def derive_metrics(skel: dict) -> dict:
    """Compute the raw metric set used by all 10 behavior triggers.

    Calibration-tested field paths (v0.7.25.5):
      - funding_attribution.mint_authorities.authorities[] (NOT
        mint_authority_dumps, which is a separate empty-shell key)
      - high_throughput_dumpers.dumpers[].total_in (NOT total_in_tokens)
      - Both honor is_excluded flag to skip infra-mint addresses.
    """
    m: dict[str, Any] = {}

    # Meta
    m["symbol"] = _g(skel, "meta", "symbol")
    m["total_supply"] = _g(skel, "meta", "total_supply") or 0
    m["circ_supply"] = _g(skel, "meta", "circulating_supply") or 0
    m["mcap_usd"] = _g(skel, "meta", "alpha_market_cap_usd")
    m["vol_24h_usd"] = _g(skel, "meta", "alpha_vol_24h_usd")
    m["lp_usd"] = _g(skel, "meta", "alpha_liquidity_usd")

    # Lineage / m6
    m["m6_quiet"] = _g(skel, "lineage", "m6", "n_quiet") or 0
    m["m6_full"] = _g(skel, "lineage", "m6", "n_full_dumper") or 0

    # Dump tracker.
    # v0.8.6.7: use dump_tracking_mining net_sellout if larger than m6-only.
    # Mining fallback insider = m6 + mint_authority + cluster + ht + fanout +
    # wcg cluster (100-200 wallets vs m6 0-50). For cluster-heavy / cross-
    # chain / mining tokens, mining fallback catches the real $X — m6 only
    # missed it. Pick max so non-mining tokens (Velvet/COLLECT) unchanged.
    dt = skel.get("dump_tracking") or {}
    dtm = skel.get("dump_tracking_mining") or {}
    base_net = dt.get("confirmed_net_sellout_usd") or 0
    mining_net = dtm.get("confirmed_net_sellout_usd") or 0
    if mining_net > base_net and not dtm.get("_error"):
        dt = dtm  # prefer mining fallback for ALL dt-derived signals
    m["pure_insider_pct"] = dt.get("pure_insider_holds_pct_supply") or 0
    m["wash_dominated"] = bool(dt.get("wash_dominated") or False)
    m["wash_swap_count"] = dt.get("total_dex_swaps") or 0
    m["wash_top_bot_swaps"] = dt.get("top_seller_swaps") or 0
    m["wash_n_dex_sellers"] = dt.get("n_dex_sellers") or 0
    m["wash_top_bot_share"] = (
        m["wash_top_bot_swaps"] / m["wash_swap_count"]
        if m["wash_swap_count"] else 0.0
    )
    m["confirmed_cex_tokens"] = dt.get("confirmed_cex_tokens") or 0
    m["confirmed_dex_tokens"] = dt.get("confirmed_dex_tokens") or 0
    m["net_sellout_usd"] = dt.get("confirmed_net_sellout_usd") or 0
    m["sell_pct_circ"] = (
        ((m["confirmed_cex_tokens"] + m["confirmed_dex_tokens"]) / m["circ_supply"] * 100)
        if m["circ_supply"] else 0.0
    )

    # 72h anomaly + truncation flag.
    # v0.7.25.5 calibration: detector caps at 100. STRONG must include
    # `count >= 50 OR truncated` so saturated tokens (h/jct = 100) fire
    # STRONG rather than being indistinguishable from a real "exactly 50".
    anomaly_summary = _g(skel, "anomaly", "detector_summary", default=[]) or []
    recent_n = 0
    recent_truncated = False
    for d in anomaly_summary:
        lbl = d.get("label") or ""
        if "72h" in lbl or "近期" in lbl or "异常" in lbl.lower():
            cnt = d.get("count") or 0
            if cnt > recent_n:
                recent_n = cnt
            # "truncated" flag in label or count exactly hitting cap.
            if "truncated" in lbl.lower() or cnt >= 100:
                recent_truncated = True
    m["anomaly_72h_count"] = recent_n
    m["anomaly_72h_truncated"] = recent_truncated

    # Cross-sym
    m["cross_sym_count"] = _len(skel, "cross_sym", "whales")

    # Funding attribution — mint authority
    # v0.7.25.5: skeleton lacks `current_balance_tokens`. Closest is
    # `mint_pct_supply` (lifetime mint% of circ supply), capped at 100%
    # to neutralize inflationary mints (h's 0x6aa22cb8 = 1325%).
    auth_obj = _g(skel, "funding_attribution", "mint_authorities", default={}) or {}
    auth = auth_obj.get("authorities") or []
    auth_active = [a for a in auth if not a.get("is_excluded", False)]
    m["mint_authority_count"] = len(auth_active)
    auth_max_pct = max((a.get("mint_pct_supply") or 0 for a in auth_active), default=0)
    auth_sum_pct = sum((a.get("mint_pct_supply") or 0) for a in auth_active)
    m["mint_pct_supply_max"] = min(auth_max_pct, 100.0)
    m["mint_pct_supply_sum"] = min(auth_sum_pct, 100.0)

    # Funding attribution — high throughput
    htd = _g(skel, "funding_attribution", "high_throughput_dumpers", "dumpers", default=[]) or []
    htd_active = [h for h in htd if not h.get("is_excluded", False)]
    m["high_throughput_count"] = len(htd_active)
    htd_total_in = sum((h.get("total_in") or 0) for h in htd_active)
    m["high_throughput_total_in_pct_supply"] = (
        htd_total_in / m["total_supply"] * 100 if m["total_supply"] else 0.0
    )

    # Funding attribution — CEX fan-out
    #
    # v0.8.1: use net_structured_fanout (Phase 2 recipient-detail
    # derived, ≥ min_per_recipient gate matching Phase 1 hub-shape
    # semantic) instead of broken total_out_tokens (Phase 1 SQL-layer
    # inconsistent, 13x inflated on VELVET).
    #
    # audit FIXES applied:
    #   - HIGH: refuse to fall back to broken total_out_tokens (gross)
    #     when net is missing — emit `fanout_metric_stale=True` so the
    #     classifier downstream can mark A2 size claim as unavailable.
    #   - CRITICAL: respect _phase2_complete flag from
    #     discover_cex_fanout_hubs — when False, Phase 2 SQL truncated
    #     and the net metric is an undercount.
    #   - HIGH: use net_structured_recipients for recipient count (not
    #     Phase 1 gross n_recipients which includes loopbacks).
    hubs = _g(skel, "funding_attribution", "cex_fanout_hubs", "hubs", default=[]) or []
    fanout_summary = _g(skel, "funding_attribution", "cex_fanout_hubs", "summary",
                       default={}) or {}
    m["fanout_hub_count"] = len(hubs)

    # Net-structured tokens preferred. Falls back to net (no threshold)
    # if structured missing. Refuses gross. Marks stale if neither net.
    if "net_structured_fanout_tokens_total" in fanout_summary:
        fanout_out_tokens = float(
            fanout_summary.get("net_structured_fanout_tokens_total") or 0.0
        )
        m["fanout_metric_stale"] = False
        m["fanout_metric_source"] = "net_structured"
    elif "net_fanout_tokens_total" in fanout_summary:
        fanout_out_tokens = float(fanout_summary.get("net_fanout_tokens_total") or 0.0)
        m["fanout_metric_stale"] = False
        m["fanout_metric_source"] = "net"
    elif hubs and "net_structured_fanout_tokens" in (hubs[0] or {}):
        fanout_out_tokens = sum(
            (h.get("net_structured_fanout_tokens") or 0) for h in hubs
        )
        m["fanout_metric_stale"] = False
        m["fanout_metric_source"] = "net_structured"
    elif hubs and "net_fanout_tokens" in (hubs[0] or {}):
        fanout_out_tokens = sum((h.get("net_fanout_tokens") or 0) for h in hubs)
        m["fanout_metric_stale"] = False
        m["fanout_metric_source"] = "net"
    else:
        # Legacy skeleton (pre-v0.8.1) lacks net metrics.
        # DO NOT silently fall back to total_out_tokens — that is the
        # broken gross that triggered the VELVET incident. Mark stale.
        fanout_out_tokens = 0.0
        m["fanout_metric_stale"] = True
        m["fanout_metric_source"] = "stale_legacy_skeleton"

    # Truncation guard: even if net metrics exist, if Phase 2 was
    # truncated we have an undercount. Mark stale so A2 can downgrade.
    phase2_complete = fanout_summary.get("_phase2_complete")
    if phase2_complete is False:
        m["fanout_metric_stale"] = True
        m["fanout_metric_source"] = "phase2_truncated"

    # Recipient count: prefer net-structured-unique > net-unique >
    # Phase 1 gross sum.
    if "net_structured_unique_recipients" in fanout_summary:
        fanout_recipients = int(
            fanout_summary.get("net_structured_unique_recipients") or 0
        )
    elif "net_fanout_unique_recipients" in fanout_summary:
        fanout_recipients = int(fanout_summary.get("net_fanout_unique_recipients") or 0)
    else:
        fanout_recipients = sum((h.get("n_recipients") or 0) for h in hubs)

    m["fanout_recipients_total"] = fanout_recipients
    m["fanout_total_pct_supply"] = (
        fanout_out_tokens / m["total_supply"] * 100 if m["total_supply"] else 0.0
    )
    # v0.8.1.2: also expose 占当前流通 % — A2 narrative uses this as
    # primary because circulating supply is what users actually trade
    # against (locked vesting / treasury stock is not in market).
    m["fanout_total_pct_circ"] = (
        fanout_out_tokens / m["circ_supply"] * 100 if m["circ_supply"] else None
    )

    # Multi-chain
    platforms = _g(skel, "meta", "coingecko_platforms", default={}) or {}
    m["coingecko_chain_count"] = len(platforms)
    mc = _g(skel, "funding_attribution", "multi_chain", default={}) or {}
    non_primary_chains = [k for k in mc.keys() if not k.startswith("_")]
    m["non_primary_chain_count"] = len(non_primary_chains)

    # B2 fake liquidity ratios
    if m["vol_24h_usd"] and m["lp_usd"] and m["lp_usd"] > 0:
        m["vol_lp_ratio"] = m["vol_24h_usd"] / m["lp_usd"]
    else:
        m["vol_lp_ratio"] = None
    if m["lp_usd"] and m["mcap_usd"] and m["mcap_usd"] > 0:
        m["lp_mcap_ratio"] = m["lp_usd"] / m["mcap_usd"]
    else:
        m["lp_mcap_ratio"] = None

    return m


def _label(severity: str, category: str, trigger_metrics: dict, human_summary: str) -> dict:
    return {
        "severity": severity,
        "category": category,
        "trigger_metrics": trigger_metrics,
        "human_summary_zh": human_summary,
    }


def classify(m: dict) -> dict:
    """Apply calibrated triggers. Returns per-label severity + metric
    snapshot + 1-sentence summary."""
    out: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # A1 ACCUMULATION_IDLE
    # v0.7.25.5 CALIBRATION DELTA: dropped ChatGPT's `anomaly_72h < 10`
    # precondition. Empirical: all wash-dominated hold-tokens also have
    # anomaly ≥ 10 → A1+C3 multi-label co-occurrence is normal, not mutex.
    #
    # v0.7.26.1 adversarial review CRITICAL fix: A1 must use ONLY pure_insider_pct
    # (current balance from dump_tracker), NOT mint_pct_supply (which is
    # lifetime mint — a mint authority that minted 100% supply but then
    # distributed it all is NOT "still holding"). Mint authority supply-
    # source semantics belong to A3, not A1.
    # ------------------------------------------------------------------
    key_holder_pct = m["pure_insider_pct"]
    a1_trigger = (
        key_holder_pct >= 2.0
        and m["sell_pct_circ"] <= 1.0
    )
    if a1_trigger and key_holder_pct >= 5.0:
        sev = "STRONG"
    elif a1_trigger and key_holder_pct >= 2.0:
        sev = "MEDIUM"
    else:
        sev = "OFF"
    if sev != "OFF":
        # v0.7.26.1 adversarial review HIGH fix: rephrase to avoid banned words
        # ("持有"/"卖出"). Use 链上侦测-neutral terminology: "余额" for
        # current 余额, "确认流出" for confirmed sells. Also handles
        # MED finding: A1+C1 co-fire narrative is now consistent
        # ("集中余额未流出" describes the state regardless of small C1
        # confirmed dumps).
        out["A1"] = _label(
            sev, "A",
            {"pure_insider_pct": round(key_holder_pct, 2),
             "sell_pct_circ": round(m["sell_pct_circ"], 3)},
            t("behavior.summary.A1", key_holder_pct=key_holder_pct)
        )
    else:
        out["A1"] = _label("OFF", "A", {}, "")

    # ------------------------------------------------------------------
    # A2 FANOUT_CONTROL
    #
    # v0.8.1 audit fix: when fanout_metric_stale=True (legacy
    # skeleton without v0.8.1 net metrics, OR Phase 2 SQL truncated),
    # the size claim is unreliable. Pattern detection (hubs >= 3) is
    # still valid (it doesn't depend on the broken total_out). So we
    # downgrade STRONG → MEDIUM when stale and suppress the % number
    # from the human summary, replacing with a "未刷新 / 截断" caveat.
    # ------------------------------------------------------------------
    hubs = m["fanout_hub_count"]
    fout = m["fanout_total_pct_supply"]
    rcpts = m["fanout_recipients_total"]
    stale = bool(m.get("fanout_metric_stale"))
    metric_source = m.get("fanout_metric_source") or "unknown"
    if hubs >= 3 or fout >= 2.0 or rcpts >= 30:
        sev = "STRONG"
    elif hubs >= 1 or fout >= 0.5:
        sev = "MEDIUM"
    else:
        sev = "OFF"
    if stale and sev == "STRONG":
        # Pattern can still be STRONG by hub count alone, but without a
        # trusted size we downgrade to MEDIUM and mark the metric.
        sev = "MEDIUM"
    if sev != "OFF":
        if stale:
            summary_zh = t("behavior.summary.A2_stale",
                           hubs=hubs, metric_source=metric_source)
        else:
            fout_circ = m.get("fanout_total_pct_circ")
            if fout_circ is not None:
                summary_zh = t("behavior.summary.A2_circ",
                               hubs=hubs, rcpts=rcpts,
                               fout_circ=fout_circ, fout=fout)
            else:
                summary_zh = t("behavior.summary.A2_supply",
                               hubs=hubs, rcpts=rcpts, fout=fout)
        out["A2"] = _label(
            sev, "A",
            {"fanout_hubs": hubs, "fanout_recipients": rcpts,
             "fanout_pct_supply": round(fout, 2),
             "fanout_metric_stale": stale,
             "fanout_metric_source": metric_source},
            summary_zh,
        )
    else:
        out["A2"] = _label("OFF", "A", {}, "")

    # ------------------------------------------------------------------
    # A3 MINT_SUPPLY_SOURCE
    # v0.7.25.5: ChatGPT's "balance_pct" doesn't exist on skeleton.
    # Using mint_pct_supply (lifetime mint%, cap 100% for inflationary).
    # ------------------------------------------------------------------
    mint_max = m["mint_pct_supply_max"]
    mint_sum = m["mint_pct_supply_sum"]
    mint_count = m["mint_authority_count"]
    if mint_max >= 5.0 or mint_sum >= 10.0:
        sev = "STRONG"
    elif mint_max >= 1.0 or mint_sum >= 1.0:
        sev = "MEDIUM"
    elif mint_count >= 1:
        sev = "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        out["A3"] = _label(
            sev, "A",
            {"mint_authorities": mint_count,
             "mint_pct_supply_max": round(mint_max, 2),
             "mint_pct_supply_sum": round(mint_sum, 2)},
            t("behavior.summary.A3", mint_count=mint_count, mint_sum=mint_sum)
        )
    else:
        out["A3"] = _label("OFF", "A", {}, "")

    # ------------------------------------------------------------------
    # B1 WASH_VOLUME — keep verbatim per calibration
    # ------------------------------------------------------------------
    swap = m["wash_swap_count"]
    share = m["wash_top_bot_share"]
    sellers = m["wash_n_dex_sellers"]
    if swap >= 100_000 and share >= 0.05:
        sev = "STRONG"
    elif swap >= 10_000 and 0 < sellers <= 300:
        sev = "MEDIUM"
    elif m["wash_dominated"]:
        sev = "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        # v0.7.26.1 adversarial review HIGH fix: "卖家"→"参与方"; "接盘"→"成交承接" to
        # avoid banned-word "卖" substring.
        out["B1"] = _label(
            sev, "B",
            {"wash_swap_count": swap, "wash_top_bot_share": round(share, 3),
             "wash_n_dex_addrs": sellers},
            t("behavior.summary.B1", swap=swap, sellers=sellers,
              share_pct=share * 100)
        )
    else:
        out["B1"] = _label("OFF", "B", {}, "")

    # ------------------------------------------------------------------
    # B2 FAKE_LIQUIDITY — keep verbatim (composite vol/LP + LP/mcap)
    # ------------------------------------------------------------------
    vol_lp = m["vol_lp_ratio"]
    lp_mcap = m["lp_mcap_ratio"]
    lp_usd = m["lp_usd"]
    if (vol_lp is not None and vol_lp >= 20) or (lp_usd is not None and lp_usd < 5_000 and lp_usd > 0):
        sev = "STRONG"
    elif (
        (vol_lp is not None and vol_lp >= 10)
        or (lp_usd is not None and lp_usd < 20_000 and lp_usd > 0)
        or (lp_mcap is not None and lp_mcap < 0.02)
    ):
        sev = "MEDIUM"
    elif vol_lp is not None and vol_lp >= 5:
        sev = "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        # v0.7.26.1 adversarial review HIGH fix: "进出"→"成交" to avoid banned word.
        out["B2"] = _label(
            sev, "B",
            {"vol_lp_ratio": round(vol_lp, 2) if vol_lp else None,
             "lp_mcap_ratio": round(lp_mcap, 4) if lp_mcap else None,
             "lp_usd": lp_usd},
            t("behavior.summary.B2_ratio", vol_lp=vol_lp, lp_mcap=lp_mcap)
            if vol_lp is not None and lp_mcap is not None
            else t("behavior.summary.B2_thin", lp_usd=lp_usd)
        )
    else:
        out["B2"] = _label("OFF", "B", {}, "")

    # ------------------------------------------------------------------
    # C1 DIRECT_DUMP — keep verbatim
    # ------------------------------------------------------------------
    net_sell = m["net_sellout_usd"]
    sell_pct = m["sell_pct_circ"]
    if net_sell >= 100_000 or sell_pct >= 2.0:
        sev = "STRONG"
    elif net_sell >= 10_000 or sell_pct >= 0.2:
        sev = "MEDIUM"
    elif m["confirmed_cex_tokens"] > 0 or m["confirmed_dex_tokens"] > 0:
        sev = "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        # v0.7.26.1 adversarial review HIGH fix: "确认卖出"→"链上确认流出 (CEX 充值 + DEX swap)"
        # to avoid banned-word "卖" substring. 链上侦测-neutral.
        out["C1"] = _label(
            sev, "C",
            {"net_sellout_usd": round(net_sell, 0),
             "sell_pct_circ": round(sell_pct, 3)},
            t("behavior.summary.C1", net_sell=net_sell, sell_pct=sell_pct)
        )
    else:
        out["C1"] = _label("OFF", "C", {}, "")

    # ------------------------------------------------------------------
    # C2 HISTORICAL_OPERATOR_DUMP
    # v0.7.25.5 CALIBRATION DELTA: collapse 3-tier to STRONG/OFF binary.
    # Detector is exhaustive (count = 0 or ≥50); MEDIUM/WEAK never fire
    # in 8-token sample.
    # ------------------------------------------------------------------
    ht_count = m["high_throughput_count"]
    ht_pct = m["high_throughput_total_in_pct_supply"]
    if ht_count >= 50 or ht_pct >= 10.0:
        sev = "STRONG"
    elif ht_count >= 5 or ht_pct >= 1.0:
        # v0.7.25.5 noted MEDIUM/WEAK rarely fire in sample, but keep them
        # so that future tokens with mid-range detector hits aren't lost.
        sev = "MEDIUM" if ht_count >= 10 else "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        out["C2"] = _label(
            sev, "C",
            {"ht_operator_count": ht_count,
             "ht_throughput_pct_supply": round(ht_pct, 2)},
            t("behavior.summary.C2", ht_count=ht_count, ht_pct=ht_pct)
        )
    else:
        out["C2"] = _label("OFF", "C", {}, "")

    # ------------------------------------------------------------------
    # C3 RECENT_ANOMALY_TRANSFER
    # v0.7.25.5 CALIBRATION DELTA: STRONG also fires on detector
    # truncation (count cap = 100). Saturated signal indistinguishable
    # from real ≥50 — treat as STRONG.
    # ------------------------------------------------------------------
    a72 = m["anomaly_72h_count"]
    trunc = m["anomaly_72h_truncated"]
    if a72 >= 50 or trunc:
        sev = "STRONG"
    elif a72 >= 10:
        sev = "MEDIUM"
    elif a72 >= 5:
        sev = "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        trunc_note = t("behavior.summary.C3_trunc_note") if trunc and a72 >= 100 else ""
        out["C3"] = _label(
            sev, "C",
            {"anomaly_72h_count": a72, "truncated": trunc},
            t("behavior.summary.C3", a72=a72, trunc_note=trunc_note)
        )
    else:
        out["C3"] = _label("OFF", "C", {}, "")

    # ------------------------------------------------------------------
    # D1 CROSS_ALPHA
    # v0.7.25.5 CALIBRATION DELTA: lower STRONG ≥5 → ≥4.
    # Sample max=3 means ≥5 never fires; flagged for v0.8 expanded
    # calibration. Per-whale active/inactive sub-type (D1A/B/C) deferred
    # to monitoring_ranker (v0.7.27).
    # ------------------------------------------------------------------
    cs = m["cross_sym_count"]
    if cs >= 4:
        sev = "STRONG"
    elif cs >= 3:
        sev = "MEDIUM"
    elif cs >= 1:
        sev = "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        # v0.7.26.1 adversarial review HIGH fix: "持有"/"持仓"→"余额命中" to avoid banned
        # word. Forensic-neutral describes detected cross-token presence.
        out["D1"] = _label(
            sev, "D",
            {"cross_sym_whales": cs},
            t("behavior.summary.D1", cs=cs)
        )
    else:
        out["D1"] = _label("OFF", "D", {}, "")

    # ------------------------------------------------------------------
    # D2 MULTICHAIN_COORDINATION — keep verbatim
    # ------------------------------------------------------------------
    non_prim = m["non_primary_chain_count"]
    cg = m["coingecko_chain_count"]
    if non_prim >= 2:
        sev = "STRONG"
    elif non_prim >= 1:
        sev = "MEDIUM"
    elif cg >= 2:
        sev = "WEAK"
    else:
        sev = "OFF"
    if sev != "OFF":
        out["D2"] = _label(
            sev, "D",
            {"non_primary_chains": non_prim, "cg_chains": cg},
            t("behavior.summary.D2", cg=cg, non_prim=non_prim)
        )
    else:
        out["D2"] = _label("OFF", "D", {}, "")

    return out


def build_profile(skel: dict) -> dict:
    """Top-level entry point. Compute metrics, classify, package into
    skeleton-injectable behavior_profile dict.
    """
    m = derive_metrics(skel)
    by_label = classify(m)

    # active_labels: non-OFF, sorted by severity (STRONG first), then by
    # category/order for stable ties.
    active = []
    for lid in _BEHAVIOR_ORDER:
        if lid in by_label and by_label[lid]["severity"] != "OFF":
            active.append(lid)
    active.sort(
        key=lambda lid: (
            -_SEVERITY_RANK[by_label[lid]["severity"]],
            _BEHAVIOR_ORDER.index(lid),
        )
    )
    primary = active[0] if active else None

    return {
        "_schema_version": "v0.7.26",
        # v0.7.26 self-audit: chain-of-custody marker so downstream
        # consumers (monitoring_ranker v0.7.27, future Context A
        # promotion) can detect calibration scope mismatch.
        "_calibrated_for": "context_B_crypto_operator",
        "_calibration_sample_size": 8,
        "_calibration_doc": "v0725_5_CALIBRATION.md",
        "active_labels": active,
        "primary_behavior": primary,
        "by_label": by_label,
        "category_order": ["A", "B", "C", "D"],
        "category_names_zh": _category_names_zh(),
        "label_names_zh": _label_names_zh(),
    }
