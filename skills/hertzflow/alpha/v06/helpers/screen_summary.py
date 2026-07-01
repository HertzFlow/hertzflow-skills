"""screen_summary.py — v0.8.7.0

Deterministic 6-dimension "一屏结论" summary for report top.

# Why this exists

ChatGPT review (2026-06-12 BEAT v0.8.6.6 report): "第一屏没有把信息压成
交易者真正要的 3 个判断 (阶段 / 筹码 / 最近动). 数据已有, 但分散在
速读 / 行为画像 / 真实派发 / 风险聚合多段, 用户得拼."

This helper builds a deterministic 6-dimension TL;DR table emitted to
skeleton.screen_summary, rendered as `## 0. 一屏结论` at report top.

# 6 维度

| 维度 | Source | Label / Evidence |
|---|---|---|
| 1. 当前阶段 | chain_state (5-tier) + risk_score | 派发进行中 / 派完离场 / 潜伏未派 / 蓄筹观察 |
| 2. 筹码结构 | op_pct + retail_pct + cex_pool_pct | 高控盘+外部抛压低 / 中等控盘 / 分散散户主导 |
| 3. 成交质量 | wash_top_bot_share + wash_swap_count | 24h vol 不可信 / 部分 wash / 成交相对真实 |
| 4. 供应风险 | mint_authorities + mint_pct_supply_sum | 高供应源 / 存在供应源 / 无 mint |
| 5. 盘口阶段 | mcap + lp/mcap + vol/lp + price_change_24h | 高市值+薄承接 / 中等承接 / 低位 |
| 6. 监控重点 | 综合上述 5 维度 | "盯继续派发路径" / "盯首次派发" / "盯拉盘信号" |

# Determinism

All thresholds pre-registered (M35). No LLM input. Single source of
truth for first-screen narrative.

# i18n (v0.9.x)

All user-facing strings are externalized to lang/<lang>.json via t().
Each dim builder also carries a language-independent `_state` token so
downstream logic (_one_sentence / _dim_monitor) branches on state, not
on translated label text.

# Thresholds (pre-registered)

- 高控盘 op_pct ≥ 70%
- 中等控盘 op_pct 40-70%
- 分散 op_pct < 40%
- 外部抛压低 retail_pct < 8%
- 中等抛压 retail_pct 8-25%
- 高抛压 retail_pct ≥ 25%
- vol 不可信 wash_top_bot_share > 10%
- 部分 wash share 5-10%
- 高供应源 mint_pct_supply_sum > 20%
- 高市值 mcap > 1B USD
- 中市值 mcap 100M - 1B
- 低市值 mcap < 100M
- 薄承接 lp_usd/mcap < 0.01
- 拉升中 price_change_24h > 15%
- 大跌 price_change_24h < -10%
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from i18n import t   # v0.9.x i18n


# v1.0.5 (ARX 2026-06-22): DEX / CEX infrastructure must never count as
# 项目方可控筹码 (operator). surf/Arkham labels these; we exclude them so a real
# liquidity POOL (project liquidity, e.g. "Cake-LP"/"V3 Pool") still counts as
# operator while DEX routers / aggregators / bridges / yield-vaults / pool-
# managers and public CEX hot wallets do not.
#
# adversarial review v1.0.5 R1/R2: reuse the canonical custody vocabulary
# (protocol_lockup_detector.CEX_CUSTODY_LABEL_RE) for complete CEX coverage,
# and a router/bridge/aggregator/diamond/pool-manager regex for DEX infra.
# "vault" is infra ONLY with a DeFi protocol co-occurring (so "Team Vault" /
# "Treasury Vault" stay operator); a CEX brand match is skipped for VC arms
# ("Coinbase Ventures", "Binance Labs"); LP pools ("... Pool" / "Cake-LP")
# are NOT matched.
import re as _re

try:
    from protocol_lockup_detector import CEX_CUSTODY_LABEL_RE as _CEX_RE
except Exception:  # pragma: no cover - defensive
    _CEX_RE = _re.compile(
        r"\b(binance|coinbase|okx|bybit|bitget|gate\.?io|kucoin|mexc|htx|huobi|"
        r"kraken|bitfinex|upbit|bithumb|crypto\.com|gemini|bitstamp|bingx|"
        r"whitebit|lbank|coinex|bitmart)\b", _re.IGNORECASE)

# adversarial review v1.0.5 R3: each alternative is anchored / context-constrained so bare
# common words ("diamond", "socket", "...router" inside one token) don't false-
# positive on project labels (e.g. "Diamond Hands Treasury", "Socket Capital",
# "AlphaRouter Team").
_DEX_ROUTER_INFRA_RE = _re.compile(
    r"\brouter\b|\baggregator\b|\bpool\s*manager\b|\bpoolmanager\b|"
    r"\bpermit2\b|\bexchange\s*proxy\b|"
    r"\b1inch\b|\bparaswap\b|\bkyber\w*\b|\bopenocean\b|\b0x\s*(?:protocol|exchange)\b|"
    r"\bstargate\b|\bhop\s*protocol\b|\bacross\s*protocol\b|\bsquid\s*router\b|"
    r"\bsynapse\s*(?:protocol|bridge)\b|\bceler\b|"
    r"\bsocket\s*(?:protocol|gateway|bridge)\b|\brango\b|\brubic\b|"
    r"li\.?fi\s*diamond",
    _re.IGNORECASE,
)
# Kept in sync with protocol_lockup_detector.DEX_VAULT_PROTOCOL_RE so a DeFi yield
# vault (Gamma / Arrakis / Pancake / Lido / ...) is recognized identically by the
# chip three-way and the source classifier.
_VAULT_PROTOCOL_RE = _re.compile(
    r"\b(pancake\w*|uniswap|sushi\w*|curve|balancer|beefy|yearn|thena|"
    r"wombat|apeswap|trader\s*joe|biswap|mdex|venus|alpaca|autofarm|"
    r"convex|aura|tokemak|gamma|arrakis|ichi|reaper|frax|lido|maker|"
    r"stakedao|harvest|badger|idle|enzyme|sommelier|morpho|aave|compound|gmx|pendle)\b",
    _re.IGNORECASE,
)
_VC_ARM_RE = _re.compile(r"\b(ventures|labs|capital|partners|incubat|accelerat)\b", _re.IGNORECASE)  # not "fund": exchange Insurance/SAFU/Reserve Fund IS CEX
# monitoring roles that, when already correctly assigned, mark neutral infra.
_NEUTRAL_INFRA_ROLES = frozenset({
    "router_aggregator", "dex_pool", "public_cex_hot_wallet",
})


def _is_neutral_infra_label(label: str) -> bool:
    """True if a surf/Arkham label marks DEX/CEX infrastructure that is NOT
    operator-controlled supply: a DEX router / aggregator / bridge / diamond /
    pool-manager, a DeFi yield-VAULT (vault + a protocol name), or a public CEX
    hot wallet. A genuine liquidity POOL, project treasury / team vault, or VC
    arm is NOT matched."""
    lab = label or ""
    if not lab:
        return False
    if _DEX_ROUTER_INFRA_RE.search(lab):
        return True
    # DEX/yield vault — only when a protocol name co-occurs.
    if "vault" in lab.lower() and _VAULT_PROTOCOL_RE.search(lab):
        return True
    # CEX custody — but not a VC arm ("Coinbase Ventures", "Binance Labs").
    if _CEX_RE.search(lab) and not _VC_ARM_RE.search(lab):
        return True
    # NOTE (v1.2.2): a bare DEX liquidity POOL ("V3 Pool") is intentionally NOT
    # matched here — `test_neutral_infra_label_matcher` pins that, because the
    # supply-chain chip three-way counts a pool's balance as circulating liquidity
    # (not operator, not "verifiable retail"). Reclassifying pools as neutral would
    # change the chip denominator + needs an end-to-end retail-bucket skip; out of
    # scope for the operator/insider-mislabel fix. Routers / aggregators / pool-
    # MANAGERS (the V4 singleton) are still matched above via _DEX_ROUTER_INFRA_RE.
    return False


def compute_neutral_infra_addrs(skel: dict[str, Any]) -> list[str]:
    """v1.0.5: addresses that must be EXCLUDED from the operator bucket because
    surf/Arkham labels them as DEX/CEX infrastructure. Computed ONCE in the
    pipeline and stored at skeleton['_neutral_infra_addrs'] so the Python chip
    math (_compute_chip_3way) and the jinja 真实派发 classifier read the SAME
    set — keeping headline == detail (the v1.0.4 parity invariant).

    Sources: top_holders_classified.label_text (any chain/category) +
    monitoring_wallets whose role is already a neutral-infra role.
    """
    out: set[str] = set()
    clp = (skel.get("meta") or {}).get("chain_lp_realtime") or {}
    for chain_data in clp.values():
        thc = (chain_data or {}).get("top_holders_classified") or {}
        for cat_data in thc.values():
            if not isinstance(cat_data, dict):
                continue
            for h in cat_data.get("top") or []:
                if _is_neutral_infra_label(h.get("label_text") or h.get("label") or ""):
                    out.add((h.get("addr") or "").lower())
    for w in skel.get("monitoring_wallets") or []:
        if (w.get("monitor_role_enum") or "") in _NEUTRAL_INFRA_ROLES:
            out.add((w.get("addr_full") or "").lower())
    out.discard("")
    return sorted(out)


def _compute_chip_3way(
    skel: dict[str, Any], out: dict | None = None
) -> tuple[float, float, float, float]:
    """Compute 庄家 / 交易所中转池 / 可验证非庄家方抛压 的 % 流通.

    v0.8.7.3: mirrors render_report.py top-100 classifier (jinja chunk
    line 700-1040) so 一屏结论 段可以显示跟"真实派发"段一致的 3 桶 %.
    Simplified: skips fanout/wcg-vs-top100 overlap subtraction (≤0.5pp
    rounding vs render-side output). Validated against velvet_v0872 case:
    op=96.4 vs render 96.5, cex=2.4 vs 2.4, retail=1.1 vs 1.1.

    v1.2.11 (TAC 2026-07-01): two operator-concealment fixes —
      (1) mint-authority WALLET balances are already-minted operator ammo, not
          "unminted reserve", so they go to the OPERATOR union (was: vest-skip,
          which hid TAC's 8 mint authorities = 326.6M = 42% of BSC supply →
          "100% 非庄家"). A wallet balance is by definition minted.
      (2) an UNLABELLED top holder ≥ 1% of the on-chain holder-snapshot supply is
          an operator-suspect whale, NOT verifiable dispersed retail — folded
          into operator (TAC's residual 88M + 38M equal-chunk wallets).

    `out` (optional): if given, populated with the concealment detail so the
    caller can annotate the headline — {"n_suspect_whales", "suspect_tokens",
    "mint_op_tokens", "n_mint_op"}.

    Returns: (operator_pct, cex_pct, retail_pct, implied_circ_tokens)
    """
    meta = skel.get("meta") or {}
    primary_chain = meta.get("primary_chain")
    clp = meta.get("chain_lp_realtime") or {}
    thc = (clp.get(primary_chain) or {}).get("top_holders_classified") or {}

    # v1.0.4 (adversarial review): the operator union below keys on
    # monitoring_wallets[].monitor_role_enum, assigned by
    # annotate_monitoring_wallets. If that step FAILED (its try/except records
    # `monitoring_summary._error`), the roles are absent/partial and op_union
    # would be falsely empty → a misleading 分散 headline. Degrade to MISSING
    # (honest 数据缺失) instead of silently under-classifying operators.
    if ((skel.get("monitoring_summary") or {}).get("_error")):
        return 0.0, 0.0, 0.0, 0.0

    # Build vest_set (genuine time-locked vesting ONLY — render line 811-834).
    # v1.2.11: mint authorities are NO LONGER put here. A mint-authority wallet
    # BALANCE is already-minted, dumpable operator supply — not "unminted
    # reserve" (which = mint-cap − minted, never a wallet balance). They now go
    # to op_union below (see mint_op_addrs).
    vest_addrs = set()
    for h in (thc.get("vesting") or {}).get("top") or []:
        vest_addrs.add((h.get("addr") or "").lower())
    auths = (skel.get("funding_attribution") or {}).get("mint_authorities", {}).get(
        "authorities"
    ) or []
    mint_op_addrs = {(auth.get("addr") or "").lower() for auth in auths}

    # Build op_union: deployer + detector-hits + clusters + section_a operator
    # categories (multisig / treasury / airdrop_platform / lp from
    # top_holders_classified). Render line 765-846.
    OP_ROLES = {
        "deployer", "suspected_operator_reserve", "fake_mining_cluster_member",
        "cross_alpha_inactive_whale", "anomaly_participant",
        "public_cex_hot_wallet", "cex_fanout_hub", "cex_fanout_recipient",
        "flow_operator", "high_throughput_dumper", "mining_fed_operator",
        "mint_authority",
    }
    # v1.0.5 (ARX 2026-06-22): build a NEUTRAL-INFRA exclusion set so DEX
    # routers / pools / vaults / aggregators and public CEX hot wallets never
    # land in the operator bucket. surf/Arkham DOES label these (e.g.
    # "PancakeSwap | Vault", "Binance Wallet"), and monitoring_ranker HAS the
    # router/CEX override — but lineage-derived monitoring_wallets entries
    # carry the label in top_holders_classified.label_text, NOT in
    # arkham_entity_name, so the override never fired and the address kept its
    # lineage role (deployer) → counted as 项目方可控. We now exclude by the
    # holder-classification label_text directly (independent of the monitoring
    # role), keyed on the SAME entity table monitoring_ranker uses.
    # Read the pipeline-computed set when present (single source of truth →
    # headline == jinja 真实派发 detail); fall back to computing it for unit
    # tests / standalone calls.
    if "_neutral_infra_addrs" in skel:
        neutral_infra = {a.lower() for a in (skel.get("_neutral_infra_addrs") or [])}
    else:
        neutral_infra = set(compute_neutral_infra_addrs(skel))

    op_union = set()
    for w in skel.get("monitoring_wallets") or []:
        if w.get("monitor_role_enum") in OP_ROLES:
            op_union.add((w.get("addr_full") or "").lower())
    for cat in ("multisig", "treasury", "airdrop_platform", "lp"):
        for h in (thc.get(cat) or {}).get("top") or []:
            op_union.add((h.get("addr") or "").lower())
    for cluster in (skel.get("wallet_cluster_graph") or {}).get("clusters") or []:
        for a in cluster.get("addrs") or []:
            op_union.add(a.lower())
    op_union |= mint_op_addrs  # v1.2.11: mint-authority held balance = operator ammo
    op_union -= neutral_infra  # DEX/CEX infra is never 项目方可控筹码

    # v1.0.4 (O 2026-06-20): mirror the render-side tail EXACTLY so the
    # headline can never diverge from the 真实派发 detail. Build the fanout-
    # recipient + cluster address sets first, so the top-100 pass can measure
    # how much of each tail is ALREADY counted in top-100 (the overlap that
    # render subtracts at render_report.py:937 / :965). Skipping this
    # (pre-v1.0.4) double-counted fanout/cluster tails on tokens where those
    # wallets appear in top holders — adversarial review caught it; O has neither so it
    # only surfaced as a latent parity gap.
    cfh = (skel.get("funding_attribution") or {}).get("cex_fanout_hubs") or {}
    fanout_recipient_addrs = set()
    for h in (cfh.get("hubs") or []):
        for a in (h.get("_net_structured_recipient_addrs_raw") or []):
            if a:
                fanout_recipient_addrs.add(a.lower())
    cluster_addrs = set()
    for cluster in (skel.get("wallet_cluster_graph") or {}).get("clusters") or []:
        for a in (cluster.get("addrs") or []):
            cluster_addrs.add(a.lower())

    # v1.2.11 whale floor: a top holder that reaches the retail fallthrough
    # (i.e. NOT vesting, NOT a CEX category, NOT in the operator union, NOT
    # neutral infra) yet holds ≥ 1% of the token's CIRCULATING supply is not
    # verifiable dispersed retail — it is an operator-suspect whale (TAC:
    # 0x6cd06aaf holding 88M). Such a holder may carry a surf/Arkham label; what
    # matters is it was not classified as operator, so we treat it as unverified.
    # Keyed on Alpha circulating_supply (true float), NOT the thin surf snapshot:
    # in a thin snapshot even genuine retail is a large % of the few holders
    # returned, so a snapshot-relative floor would misfire. When
    # circulating_supply is unknown the floor is 0 → guard disabled (conservative
    # — never guess a whale from a thin snapshot alone). NOTE (adversarial review
    # nit, backlog): for a multi-chain mirror the circ is GLOBAL, so a chain-local
    # operator shard < 1% global circ can be missed — acceptable here (the failure
    # mode fixed was false-dispersed), split/mirror uses supply_chain_overhang for
    # the headline.
    WHALE_PCT = 0.01
    circ_supply = float(meta.get("circulating_supply") or 0)
    whale_floor = circ_supply * WHALE_PCT

    # Classify top-100 (vest first → cex by category → operator by union →
    # whale-suspect → retail fallthrough). Render line 857-879. Also accumulate
    # fanout/cluster overlap with top-100 for strict tail subtraction below.
    op_tok = cex_tok = retail_tok = 0.0
    suspect_tok = mint_op_tok = 0.0
    n_suspect = n_mint_op = 0
    fanout_overlap = cluster_overlap = 0.0
    for cat in ("vesting", "multisig", "treasury", "airdrop_platform",
                "cex", "lp", "unclassified"):
        for h in (thc.get(cat) or {}).get("top") or []:
            addr = (h.get("addr") or "").lower()
            bal = float(h.get("balance") or 0)
            if addr in fanout_recipient_addrs:
                fanout_overlap += bal
            if addr in cluster_addrs:
                cluster_overlap += bal
            if addr in vest_addrs:
                continue  # genuine time-locked vesting, skip
            if cat == "cex":
                cex_tok += bal
            elif addr in op_union:
                op_tok += bal
                if addr in mint_op_addrs:
                    mint_op_tok += bal
                    n_mint_op += 1
            elif (whale_floor > 0 and bal >= whale_floor
                  and addr not in neutral_infra):
                # unverified top holder ≥ 1% circulating → operator-suspect, not
                # retail. neutral_infra (DEX/CEX vaults/routers) is NEVER a whale
                # here — it was deliberately excluded from the operator union.
                op_tok += bal
                suspect_tok += bal
                n_suspect += 1
            else:
                retail_tok += bal

    # Tail additions = cluster/fanout balance held OUTSIDE top-100 only
    # (total minus the in-top-100 overlap already bucketed above). Mirrors
    # render_report.py:937 (_cex_fanout_tail) + :965 (_cluster_tail).
    fanout_net = float(
        (cfh.get("summary") or {}).get("net_structured_fanout_tokens_total") or 0
    )
    fanout_tail = max(0.0, fanout_net - fanout_overlap)
    cluster_total = 0.0
    for cluster in (skel.get("wallet_cluster_graph") or {}).get("clusters") or []:
        _ct = float(cluster.get("cluster_balance_total_tokens") or 0)
        # adversarial review v1.0.5 R1: a neutral-infra cluster member OUTSIDE top-100 would
        # otherwise re-enter the operator bucket via cluster_tail. Subtract its
        # balance using the per-member addr_balances the detector emits.
        _bal = cluster.get("addr_balances") or {}
        _bal_lc = {str(k).lower(): v for k, v in _bal.items()}
        _infra_in_cluster = sum(
            float(_bal_lc.get(a.lower()) or 0)
            for a in (cluster.get("addrs") or [])
            if a.lower() in neutral_infra
        )
        cluster_total += max(0.0, _ct - _infra_in_cluster)
    cluster_tail = max(0.0, cluster_total - cluster_overlap)

    op_with_tail = op_tok + fanout_tail + cluster_tail
    implied_circ = op_with_tail + cex_tok + retail_tok
    if out is not None:
        out.update({
            "n_suspect_whales": n_suspect,
            "suspect_tokens": suspect_tok,
            "mint_op_tokens": mint_op_tok,
            "n_mint_op": n_mint_op,
        })
    if implied_circ == 0:
        return 0.0, 0.0, 0.0, 0.0
    return (
        op_with_tail / implied_circ * 100,
        cex_tok / implied_circ * 100,
        retail_tok / implied_circ * 100,
        implied_circ,
    )


def build_screen_summary(skel: dict[str, Any]) -> dict[str, Any]:
    """Build deterministic 7-dimension TL;DR summary.

    v0.8.7.3: split old "筹码结构" dim into two:
      - 筹码结构 — 3 buckets (庄家 / 交易所 / 非庄家) as % of circ
      - 内幕/庄家现货套现情况 — 已确认 insider 变现 + 交易所提币分发 净 %

    Also translates all English jargon (cex_fanout / insider / recipients /
    ht_dumper / bot / mint authority) to Chinese in user-facing evidence.

    Returns:
        {
          "dimensions": [
            {"name": "当前阶段", "label": "🔴 派发进行中", "evidence": "..."},
            ...  # 7 dims total
          ],
          "one_sentence": "...",  # deterministic 1-sentence summary
        }
    """
    meta = skel.get("meta") or {}
    dump_tracking = skel.get("dump_tracking") or {}
    dump_tracking_mining = skel.get("dump_tracking_mining") or {}
    # v0.8.6.7 mining fallback: prefer larger net_sellout
    base_net = dump_tracking.get("confirmed_net_sellout_usd") or 0
    mining_net = dump_tracking_mining.get("confirmed_net_sellout_usd") or 0
    if mining_net > base_net and not dump_tracking_mining.get("_error"):
        dump_tracking = dump_tracking_mining

    fa = skel.get("funding_attribution") or {}
    bp = skel.get("behavior_profile") or {}
    anomaly = skel.get("anomaly") or {}
    chain_state = skel.get("chain_state") or "CLEAN"
    risk_score = skel.get("chain_state_risk_score") or 0
    holders = skel.get("holdings_distribution") or {}

    # Numbers — fields prefixed `alpha_` (from Alpha API response)
    circ = float(meta.get("circulating_supply") or 0)
    total_supply = float(meta.get("total_supply") or 0)
    mcap = float(meta.get("alpha_market_cap_usd") or meta.get("market_cap_usd") or 0)
    lp_usd = float(meta.get("alpha_liquidity_usd") or meta.get("lp_usd") or 0)
    vol_24h = float(meta.get("alpha_vol_24h_usd") or meta.get("alpha_volume_24h_usd") or 0)
    price_change_24h = float(meta.get("alpha_percent_change_24h") or 0)
    depth_5pct = float(meta.get("liq_5pct_depth_usd") or (vol_24h / 96 * 0.05) or 0)

    # Confirmed sell
    net_sellout = float(dump_tracking.get("confirmed_net_sellout_usd") or 0)
    sell_pct_circ = float(dump_tracking.get("confirmed_total_pct") or 0)
    wash_dominated = bool(dump_tracking.get("wash_dominated") or False)
    wash_swap_count = int(dump_tracking.get("total_dex_swaps") or 0)
    top_seller_swaps = int(dump_tracking.get("top_seller_swaps") or 0)
    wash_top_bot_share = (top_seller_swaps / wash_swap_count) if wash_swap_count else 0.0

    # Mint
    mint_auths = (fa.get("mint_authorities") or {}).get("authorities") or []
    n_mint_auth = sum(1 for a in mint_auths if not a.get("is_excluded"))
    total_mint_sum = sum(float(a.get("total_minted") or 0)
                         for a in mint_auths if not a.get("is_excluded"))
    mint_pct_supply = (total_mint_sum / total_supply * 100) if total_supply else 0

    # ht dumpers throughput
    ht_dumpers = (fa.get("high_throughput_dumpers") or {}).get("dumpers") or []
    ht_throughput_total = sum(float(d.get("total_out") or 0) for d in ht_dumpers)
    ht_throughput_pct = (ht_throughput_total / circ * 100) if circ else 0

    # cex fanout
    cfh_sum = (fa.get("cex_fanout_hubs") or {}).get("summary") or {}
    fanout_net = float(cfh_sum.get("net_structured_fanout_tokens_total") or 0)
    fanout_recipients = int(cfh_sum.get("net_structured_unique_recipients") or 0)

    # Anomaly waves
    recent_n_72h = 0
    for d in (anomaly.get("detector_summary") or []):
        lbl = d.get("label") or ""
        if "72h" in lbl or "近期" in lbl:
            recent_n_72h = int(d.get("count") or 0)
            break

    # Chip structure (from holdings_distribution-derived or render-side calc)
    # Pipeline does NOT pre-compute these; we use skel's chip pcts if added,
    # otherwise fall back to dump_tracking + meta heuristics.
    # NOTE: render-side computes _operator_topdown_in_circ_pct via jinja —
    # we need a Python-side equivalent. For now, infer from confirmed sells +
    # cex_fanout net + ht throughput as proxy.
    # TODO: better to wire render's _operator_topdown_in_circ to skel; for v0.8.7.0
    # MVP, use confirmed_sell + net_fanout as proxy "operator visible footprint".
    operator_pct_proxy = min(100.0, sell_pct_circ + (fanout_net / circ * 100 if circ else 0))

    # ==================== Dimension 1: 当前阶段 ====================
    dim_phase = _dim_phase(chain_state, risk_score, sell_pct_circ, recent_n_72h, net_sellout)

    # ==================== Dimension 2: 筹码结构 (v0.8.7.3 new) ============
    # v1.1.0 (CAP): for a multi-chain token whose Alpha listing is a mirror, the
    # single-chain chip measures the wrong slice (CAP BSC 1.4% → "🟢 分散 22.9%").
    # When supply_chain_overhang.split is True the buckets were recomputed on the
    # CANONICAL supply chain (operator/relay/non_operator % of circulating, with
    # the genesis reserve excluded as a locked overhang) — use those instead so
    # the headline matches the corrected 真实派发 detail.
    _sco = skel.get("supply_chain_overhang") or {}
    _sco_ok = bool(_sco.get("split")) and not _sco.get("_error") and (
        _sco.get("operator_pct") is not None)
    _chip_extra: dict[str, Any] = {}
    if _sco_ok:
        op_pct = float(_sco.get("operator_pct") or 0)
        cex_pct = float(_sco.get("relay_pct") or 0)
        retail_pct = float(_sco.get("non_operator_pct") or 0)
    else:
        op_pct, cex_pct, retail_pct, _implied_circ = _compute_chip_3way(
            skel, out=_chip_extra)
    dim_chip_struct = _dim_chip_struct(op_pct, cex_pct, retail_pct,
                                       overhang=_sco if _sco_ok else None,
                                       chip_extra=_chip_extra)

    # ==================== Dimension 3: 内幕/庄家现货套现情况 (was 筹码结构) ====
    dim_insider_dump = _dim_insider_dump(op_pct, sell_pct_circ, fanout_net, circ)

    # ==================== Dimension 4: 成交质量 ====================
    dim_volume = _dim_volume(wash_dominated, wash_swap_count, top_seller_swaps,
                             wash_top_bot_share)

    # ==================== Dimension 5: 供应风险 ====================
    dim_supply = _dim_supply(n_mint_auth, mint_pct_supply, ht_throughput_pct,
                             len(ht_dumpers))

    # ==================== Dimension 6: 盘口阶段 ====================
    dim_market = _dim_market(mcap, lp_usd, vol_24h, depth_5pct, price_change_24h)

    # ==================== Dimension 7: 监控重点 ====================
    dim_monitor = _dim_monitor(dim_phase, dim_chip_struct, dim_supply,
                               fanout_recipients, n_mint_auth, recent_n_72h,
                               len(ht_dumpers))

    dims = [dim_phase, dim_chip_struct, dim_insider_dump, dim_volume,
            dim_supply, dim_market, dim_monitor]

    # v1.2.0: primary-sale (CCA / IDO) dimension — inserted right after 筹码结构
    # when a public-sale pool was detected; omitted entirely otherwise.
    dim_primary_sale = _dim_primary_sale(skel.get("primary_sales"))
    if dim_primary_sale:
        dims.insert(2, dim_primary_sale)

    # v1.2.9 (product spec 2026-06-29): 近 72h 分发/归集动作 — HIGHEST priority. A live operator
    # fan-out (pre-dump seeding) / CEX consolidation (cashing out) goes to the very top
    # of the 一屏结论, above everything else. Omitted when nothing recent.
    dim_recent_flow = _dim_recent_flow(
        skel.get("recent_flow_actions"),
        circ_supply=float((skel.get("meta") or {}).get("circulating_supply") or 0))
    if dim_recent_flow:
        dims.insert(0, dim_recent_flow)

    # v1.2.14 (product spec 2026-07-01, TAC): 近期铸新事件 — a large fresh mint from 0x0 =
    # operator creating new ammo (often the pump source). Time-sensitive, so it goes
    # to the very top too. Inserted AFTER recent_flow so it lands at index 0 (above
    # the fan-out row) — a fresh mint precedes the fan-out/dump chain.
    dim_recent_mint = _dim_recent_mint(skel.get("recent_mint_events"))
    if dim_recent_mint:
        dims.insert(0, dim_recent_mint)

    # ==================== One-sentence summary ====================
    one_sentence = _one_sentence(dim_phase, dim_chip_struct, dim_volume,
                                  dim_supply, dim_market)

    return {
        "dimensions": dims,
        "one_sentence": one_sentence,
    }


# ---- Per-dimension builders ----

def _dim_phase(chain_state: str, risk: int, sell_pct: float, recent_72h: int,
               net_sellout: float) -> dict:
    """Dimension 1: 当前阶段 — reuse chain_state 5-tier + augment with net_sellout.

    `_state` token (stable across langs):
      DISTRIBUTING / RECENT_UNCONFIRMED / DUMPED / DORMANT / WATCH / CLEAN
    """
    if chain_state == "RECENT_DISTRIBUTION":
        if sell_pct > 5 or net_sellout > 1_000_000:
            label = t("screen.phase_label_distributing")
            state = "DISTRIBUTING"
        else:
            label = t("screen.phase_label_recent_unconfirmed")
            state = "RECENT_UNCONFIRMED"
        evidence = t("screen.phase_ev_recent_anomaly", recent_72h=recent_72h)
        if net_sellout > 0:
            evidence += t("screen.phase_ev_confirmed_realized", net_sellout=net_sellout)
    elif chain_state == "OPERATOR_DUMPED":
        label = t("screen.phase_label_dumped")
        state = "DUMPED"
        evidence = t("screen.phase_ev_dumped")
    elif chain_state == "DORMANT_INSIDER_RISK":
        label = t("screen.phase_label_dormant")
        state = "DORMANT"
        evidence = t("screen.phase_ev_dormant")
    elif chain_state == "WATCH":
        label = t("screen.phase_label_watch")
        state = "WATCH"
        evidence = t("screen.phase_ev_watch", recent_72h=recent_72h)
    else:  # CLEAN
        label = t("screen.phase_label_clean")
        state = "CLEAN"
        evidence = t("screen.phase_ev_clean")
    return {"name": t("screen.dim_name_phase"), "label": label,
            "evidence": evidence, "_state": state}


def _dim_chip_struct(op_pct: float, cex_pct: float, retail_pct: float,
                     overhang: dict | None = None,
                     chip_extra: dict | None = None) -> dict:
    """Dimension 2 (v0.8.7.3 new): 筹码结构 — 3 桶 % only.

    User feedback (velvet_v0872 review 2026-06-13): 每一项后面只要给 %,
    绝对值让用户到下方 "真实派发" 段自己看. Same algorithm as render-side
    top-100 chip classifier (see _compute_chip_3way docstring).

    v1.1.0 (CAP): `overhang` (supply_chain_overhang dict) is passed for a
    multi-chain mirror token — the 3 buckets are % of CIRCULATING on the
    canonical supply chain, and a locked overhang note is appended.

    `_state` token: HIGH / MID / DISPERSED / MISSING
    """
    # v1.0.2 (H 2026-06-20): MISSING (数据缺失) must mean "no classified holders
    # at all", NOT "op_pct == 0". A token that is genuinely retail-dominated
    # (op=0 but cex/retail > 0) is DISPERSED, not data-missing — labelling it
    # 数据缺失 wrongly implies a pipeline failure. Only all-three-zero (the
    # classifier read nothing) is truly MISSING.
    if op_pct >= 70:
        label = t("screen.chip_label_high")
        state = "HIGH"
    elif op_pct >= 40:
        label = t("screen.chip_label_mid")
        state = "MID"
    elif (op_pct + cex_pct + retail_pct) > 0:
        label = t("screen.chip_label_dispersed")
        state = "DISPERSED"
    else:
        label = t("screen.chip_label_missing")
        state = "MISSING"
    evidence = t("screen.chip_ev", op_pct=op_pct, cex_pct=cex_pct,
                 retail_pct=retail_pct)
    # v1.2.11: explain WHY operator is high when the chip folded mint-authority
    # ammo and/or unlabelled whales into the operator bucket, so the 🔴 headline
    # is transparent (not a black box).
    if chip_extra:
        n_mint = int(chip_extra.get("n_mint_op") or 0)
        n_whale = int(chip_extra.get("n_suspect_whales") or 0)
        parts = []
        if n_mint:
            parts.append(t("screen.chip_ev_concealed_mint", n=n_mint))
        if n_whale:
            parts.append(t("screen.chip_ev_concealed_whale", n=n_whale))
        if parts:
            evidence += t("screen.chip_ev_concealed_wrap", detail=" + ".join(parts))
    if overhang:
        evidence += t(
            "screen.chip_ev_supply_overhang",
            supply_chain=overhang.get("supply_chain_label") or overhang.get("supply_chain") or "",
            locked_pct=float(overhang.get("locked_pct_of_total") or 0),
        )
    return {"name": t("screen.dim_name_chip"), "label": label,
            "evidence": evidence, "_state": state}


# v1.2.12: an unknown-hub fan-out must reach this many recipients in-window
# before it surfaces as a 🟡 疑似批量分发 medium row — keeps trivial churn out
# while still catching TAC's 88-wallet hub. min_counterparties (SQL floor) is 10.
_UNKNOWN_FANOUT_MEDIUM_MIN = 20


def _dim_recent_flow(rf: dict | None, circ_supply: float = 0.0) -> dict | None:
    """Dimension (v1.2.9, product spec 2026-06-29): 近 72h 分发/归集动作 — a top-priority
    headline row. Two severities:
      🔴 HIGH — a CONFIRMED operator is acting NOW: a mint-authority / cluster hub
        fanning out to many EOAs (pre-dump seeding), or many EOAs consolidating
        into a CEX (active cashing out).
      🟠 MEDIUM (v1.2.12, product spec 2026-07-01, TAC) — a large UNKNOWN hub fanning out
        to ≥ _UNKNOWN_FANOUT_MEDIUM_MIN wallets in-window ("疑似批量分发"). The
        source is not a verified operator/CEX, so it is flagged as 疑似 (needs
        manual review), NOT presented as confirmed operator. Previously this was
        suppressed entirely (adversarial review v1.2.9 kept it out of the TOP row)
        — the fix keeps confirmed-operator at 🔴 and gives the unknown hub its 🟠.

    `circ_supply` (optional): circulating supply, used to show the distributed
    amount as a % of float so a tiny batch (TAC: 807K = 0.017% of circ) is not
    mistaken for a large one.
    Returns None when nothing recent, so the row is omitted rather than empty."""
    if not isinstance(rf, dict) or rf.get("_error"):
        return None
    op = rf.get("has_operator_fanout")
    cx = rf.get("has_cex_consolidation")
    wd = rf.get("window_days") or 3
    tf = rf.get("top_operator_fanout") or {}
    tc = rf.get("top_cex_consolidation") or {}
    if op and cx:
        state, label = "FANOUT_AND_CONSOLIDATION", t("screen.rf_label_both")
        evidence = t("screen.rf_ev_both", wd=wd, fan_n=tf.get("n_counterparties", 0),
                     fan_hub=(tf.get("hub") or "")[:10],
                     con_n=tc.get("n_counterparties", 0), con_hub=(tc.get("hub") or "")[:10])
    elif op:
        state, label = "OPERATOR_FANOUT", t("screen.rf_label_operator_fanout")
        evidence = t("screen.rf_ev_operator_fanout", wd=wd,
                     n=tf.get("n_counterparties", 0), hub=(tf.get("hub") or "")[:10])
    elif cx:
        state, label = "CEX_CONSOLIDATION", t("screen.rf_label_cex_consolidation")
        evidence = t("screen.rf_ev_cex_consolidation", wd=wd,
                     n=tc.get("n_counterparties", 0), hub=(tc.get("hub") or "")[:10])
    else:
        # 🟠 medium: a large unknown-hub batch distribution (源头未验证).
        tu = rf.get("top_unknown_fanout") or {}
        n = int(tu.get("n_counterparties") or 0)
        if n < _UNKNOWN_FANOUT_MEDIUM_MIN:
            return None
        toks = float(tu.get("total_tokens") or 0)
        pct = (toks / circ_supply * 100) if circ_supply > 0 else 0.0
        state, label = "SUSPECTED_BATCH_DISTRIBUTION", t("screen.rf_label_unknown_fanout")
        evidence = t("screen.rf_ev_unknown_fanout", wd=wd, n=n,
                     hub=(tu.get("hub") or "")[:10],
                     tokens="{:,.0f}".format(toks), pct_circ=pct)
    return {"name": t("screen.dim_name_recent_flow"), "label": label,
            "evidence": evidence, "_state": state}


def _dim_recent_mint(rm: dict | None) -> dict | None:
    """Dimension (v1.2.14, product spec 2026-07-01, TAC): 近期铸新 — a large fresh mint from the
    0x0 black-hole within the recent window = operator creating new ammo (often the pump
    source). Surfaces the DATE + amount + % of supply so the reader sees WHEN the ammo
    was created, not just that mint authorities hold a balance. Returns None when no
    significant recent mint (dimension omitted). Framed as fact + "corroborate with
    price / perp OI", NOT a bare causal pump claim."""
    if not isinstance(rm, dict) or rm.get("_error"):
        return None
    if not rm.get("has_recent_significant_mint"):
        return None
    top = rm.get("top_recent_mint") or {}
    minted = float(top.get("minted") or 0)
    if minted <= 0:
        return None
    n_more = max(0, len(rm.get("significant_mints") or []) - 1)
    evidence = t(
        "screen.rm_ev",
        wd=int(rm.get("recent_window_days") or 14),
        date=top.get("date") or "?",
        days_ago=int(top.get("days_ago") or 0),
        tokens="{:,.0f}".format(minted),
        pct=float(top.get("pct_circ") or 0),
        n_tx=int(top.get("n_tx") or 0),
    )
    if n_more > 0:
        evidence += t("screen.rm_ev_more", n_more=n_more)
    return {
        "name": t("screen.dim_name_recent_mint"),
        "label": t("screen.rm_label"),
        "evidence": evidence,
        "_state": "RECENT_MINT",
    }


def _dim_primary_sale(ps: dict | None) -> dict | None:
    """Dimension (v1.2.0): 一级公募分配 — surfaces the top public-sale pool's share
    of circulating, recipient count, top-10 concentration and KOL count directly in
    the headline. Returns None when no public sale was detected (dimension omitted).

    `_state` token: CONCENTRATED / SEMI / DISPERSED
    """
    if not ps or not ps.get("pools"):
        return None
    p = (ps.get("pools") or [{}])[0]
    pct = float(p.get("pct_of_circulating") or 0)
    top10 = float(p.get("top10_pct") or 0)
    n = int(p.get("n_recipients") or 0)
    n_kol = int(p.get("n_named_recipients") or 0)
    if top10 >= 50:
        label = t("screen.psa_label_concentrated")
        state = "CONCENTRATED"
    elif top10 >= 30:
        label = t("screen.psa_label_semi")
        state = "SEMI"
    else:
        label = t("screen.psa_label_dispersed")
        state = "DISPERSED"
    evidence = t("screen.psa_ev", pct=pct,
                 tokens="{:,.0f}".format(p.get("tokens_distributed") or 0),
                 n=n, top10=top10, n_kol=n_kol)
    return {"name": t("screen.dim_name_psa"), "label": label,
            "evidence": evidence, "_state": state}


def _dim_insider_dump(op_pct: float, sell_pct: float, fanout_net: float,
                       circ: float) -> dict:
    """Dimension 3 (v0.8.7.3 renamed from old 筹码结构): 内幕/庄家现货套现情况.

    User feedback (velvet_v0872 review 2026-06-13): 原"筹码结构"label 让位给
    3 桶版, 这里仍显示 insider 已变现 + 交易所提币分发 (cex_fanout) 净 % 流通,
    但 name 改成更准确的"内幕/庄家现货套现情况" + 所有英文术语翻译成中文.

    `_state` token: HEAVY / PARTIAL / LIGHT / NONE
    """
    fanout_pct = (fanout_net / circ * 100) if circ else 0
    if sell_pct >= 20 or fanout_pct >= 30:
        label = t("screen.insider_label_heavy")
        state = "HEAVY"
    elif sell_pct >= 5 or fanout_pct >= 10:
        label = t("screen.insider_label_partial")
        state = "PARTIAL"
    elif sell_pct > 0 or fanout_pct > 0:
        label = t("screen.insider_label_light")
        state = "LIGHT"
    else:
        label = t("screen.insider_label_none")
        state = "NONE"
    evidence = t("screen.insider_ev", sell_pct=sell_pct, fanout_pct=fanout_pct)
    return {"name": t("screen.dim_name_insider"), "label": label,
            "evidence": evidence, "_state": state}


def _dim_volume(wash_dominated: bool, wash_swap_count: int, top_seller_swaps: int,
                wash_top_bot_share: float) -> dict:
    """Dimension 4: 成交质量 — wash share. v0.8.7.3: bot → 机器人 中文化.

    `_state` token: WASH_DOMINATED / PARTIAL_WASH / REAL / NO_DATA
    """
    if wash_dominated or wash_top_bot_share > 0.10:
        label = t("screen.volume_label_wash_dominated")
        state = "WASH_DOMINATED"
        evidence = t("screen.volume_ev_full", wash_swap_count=wash_swap_count,
                     bot_share=wash_top_bot_share * 100)
    elif wash_top_bot_share > 0.05:
        label = t("screen.volume_label_partial_wash")
        state = "PARTIAL_WASH"
        evidence = t("screen.volume_ev_short", wash_swap_count=wash_swap_count,
                     bot_share=wash_top_bot_share * 100)
    elif wash_swap_count > 0:
        label = t("screen.volume_label_real")
        state = "REAL"
        evidence = t("screen.volume_ev_short", wash_swap_count=wash_swap_count,
                     bot_share=wash_top_bot_share * 100)
    else:
        label = t("screen.volume_label_no_data")
        state = "NO_DATA"
        evidence = t("screen.volume_ev_no_data")
    return {"name": t("screen.dim_name_volume"), "label": label,
            "evidence": evidence, "_state": state}


def _dim_supply(n_mint_auth: int, mint_pct_supply: float, ht_throughput_pct: float,
                n_ht: int) -> dict:
    """Dimension 5: 供应风险 — 铸币权限 + 高频清仓累计过账.

    v0.8.7.3: ht_dumper → 高频清仓钱包, mint authority → 铸币权限, bridge → 跨链桥
    全中文化.

    `_state` token: MINT_HIGH / MINT_LIMITED / HT_SHOWN / NONE
    """
    if n_mint_auth > 0 and mint_pct_supply > 20:
        label = t("screen.supply_label_mint_high")
        state = "MINT_HIGH"
        evidence = t("screen.supply_ev_mint_high", n_mint_auth=n_mint_auth,
                     mint_pct_supply=mint_pct_supply)
    elif n_mint_auth > 0:
        label = t("screen.supply_label_mint_limited")
        state = "MINT_LIMITED"
        evidence = t("screen.supply_ev_mint_limited", n_mint_auth=n_mint_auth,
                     mint_pct_supply=mint_pct_supply)
    elif n_ht > 50 and ht_throughput_pct > 50:
        label = t("screen.supply_label_ht_shown")
        state = "HT_SHOWN"
        evidence = t("screen.supply_ev_ht_shown", n_ht=n_ht,
                     ht_throughput_pct=ht_throughput_pct)
    else:
        label = t("screen.supply_label_none")
        state = "NONE"
        evidence = t("screen.supply_ev_none")
    return {"name": t("screen.dim_name_supply"), "label": label,
            "evidence": evidence, "_state": state}


def _dim_market(mcap: float, lp_usd: float, vol_24h: float, depth_5pct: float,
                price_change_24h: float) -> dict:
    """Dimension 5: 盘口阶段 — mcap + LP + price + depth.

    `_state` token captures mcap tier + thin + price move so _one_sentence
    can branch without substring-matching the translated label.
    """
    lp_mcap_ratio = (lp_usd / mcap) if mcap else 0
    vol_lp_ratio = (vol_24h / lp_usd) if lp_usd else 0
    parts = []
    if mcap >= 1_000_000_000:
        parts.append(t("screen.market_ev_mcap_m", mcap_m=mcap / 1e6))
    elif mcap >= 100_000_000:
        parts.append(t("screen.market_ev_mcap_m", mcap_m=mcap / 1e6))
    elif mcap > 0:
        parts.append(t("screen.market_ev_mcap_m1", mcap_m=mcap / 1e6))
    if depth_5pct > 0:
        parts.append(t("screen.market_ev_depth", depth_5pct=depth_5pct))
    if lp_mcap_ratio > 0:
        parts.append(t("screen.market_ev_lp_mcap", lp_mcap_ratio=lp_mcap_ratio))
    if vol_lp_ratio > 0:
        parts.append(t("screen.market_ev_vol_lp", vol_lp_ratio=vol_lp_ratio))
    if price_change_24h > 15:
        price_state = "PUMP"
    elif price_change_24h < -10:
        price_state = "DUMP"
    elif abs(price_change_24h) > 5:
        price_state = "VOLATILE"
    else:
        price_state = "STABLE"
    parts.append(t("screen.market_ev_24h", price_change_24h=price_change_24h))

    thin = lp_mcap_ratio > 0 and lp_mcap_ratio < 0.01
    if mcap >= 1_000_000_000 and thin:
        label = t("screen.market_label_high_thin")
        mcap_state = "HIGH"
    elif mcap >= 1_000_000_000:
        label = t("screen.market_label_high")
        mcap_state = "HIGH"
    elif mcap >= 100_000_000 and thin:
        label = t("screen.market_label_mid_thin")
        mcap_state = "MID"
    elif mcap >= 100_000_000:
        label = t("screen.market_label_mid")
        mcap_state = "MID"
    elif mcap > 0:
        label = t("screen.market_label_low")
        mcap_state = "LOW"
    else:
        label = t("screen.market_label_missing")
        mcap_state = "MISSING"
    if price_state == "PUMP":
        label = label + t("screen.market_label_suffix_pump")
    elif price_state == "DUMP":
        label = label + t("screen.market_label_suffix_dump")
    evidence = "; ".join(parts) if parts else t("screen.market_ev_missing")
    return {"name": t("screen.dim_name_market"), "label": label,
            "evidence": evidence, "_state": mcap_state, "_price_state": price_state}


def _dim_monitor(dim_phase: dict, dim_chip: dict, dim_supply: dict,
                 fanout_recipients: int, n_mint_auth: int, recent_72h: int,
                 n_ht: int) -> dict:
    """Dimension 7: 监控重点 — derive from other dims.

    v0.8.7.3: 全部英文术语翻译中文 — mint authority → 铸币权限, CEX fan-out
    hub + recipients → 交易所提币分发集散方 + 接收方, ht_dumper → 高频清仓钱包,
    detector → 检测器, cluster → 集群.
    """
    phase_state = dim_phase.get("_state")
    items = []
    if phase_state in ("DISTRIBUTING", "RECENT_UNCONFIRMED"):
        items.append(t("screen.monitor_item_recent_anomaly"))
    if n_mint_auth > 0:
        items.append(t("screen.monitor_item_mint_auth"))
    if fanout_recipients > 5:
        items.append(t("screen.monitor_item_cex_fanout"))
    if n_ht > 50:
        items.append(t("screen.monitor_item_ht"))
    if phase_state == "DUMPED":
        items.append(t("screen.monitor_item_new_cycle"))
    if not items:
        items.append(t("screen.monitor_item_default"))

    # NOTE: original matched substring "派发" in the phase label, which only
    # the DISTRIBUTING label ("派发进行中") contains. Preserve exactly.
    label = (t("screen.monitor_label_track_dump")
             if phase_state == "DISTRIBUTING"
             else t("screen.monitor_label_baseline"))
    evidence = t("screen.monitor_item_sep").join(items)
    return {"name": t("screen.dim_name_monitor"), "label": label,
            "evidence": evidence, "_state": phase_state}


def _one_sentence(dim_phase: dict, dim_chip: dict, dim_volume: dict,
                  dim_supply: dict, dim_market: dict) -> str:
    """Deterministic 1-sentence summary.

    Branches on language-independent `_state` tokens (not translated label
    substrings), so it produces correct output in zh and en.
    """
    parts = []
    parts.append(t(f"screen.one_sentence_phase.{dim_phase.get('_state')}"))
    parts.append(t(f"screen.one_sentence_chip.{dim_chip.get('_state')}"))
    if dim_volume.get("_state") == "WASH_DOMINATED":
        parts.append(t("screen.one_sentence_wash"))
    # NOTE: original logic matched substring "高" in the supply label, which
    # (quirk) only the HT_SHOWN label ("高频清仓已显现") contains — NOT the
    # mint-high label. Preserve that exact behavior via the state token.
    if dim_supply.get("_state") == "HT_SHOWN":
        parts.append(t("screen.one_sentence_supply"))
    if dim_market.get("_state") == "HIGH":
        parts.append(t("screen.one_sentence_high_mcap"))
    return t("screen.one_sentence_join").join(parts) + t("screen.one_sentence_period")


__all__ = ["build_screen_summary"]
