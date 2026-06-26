"""v0.7.27 — Deterministic monitoring address ranker.

Translates the pipeline-built monitoring_wallets[] (free-text role,
emoji-status) into 4-tier monitor levels (CRITICAL / HIGH / NORMAL /
NOT_TRACKED) using a deterministic Python score formula. retail then
pastes monitoring_paste.json into Binance Wallet / OKX without being
drowned by 50-100 same-weight entries.

Architecture (per ChatGPT v0.8 spec):
  raw_detectors → behavior_classifier → monitoring_ranker → renderer

The ranker is the *only* place that decides "what does retail track".
behavior_classifier supplies the source_behaviors set per address so
score can apply behavior linkage bonuses without extra surf SQL.

Output shape per monitoring_wallets[i] (added in-place):
  {
    ... existing fields (address, role, status_emoji, etc.) ...,
    "monitor_level": str,        # CRITICAL / HIGH / NORMAL / NOT_TRACKED
    "monitor_score": int,        # raw score (negative = penalty short-circuit)
    "monitor_reason": str,       # 1-line zh: why this level
    "monitor_role_enum": str,    # canonical role (e.g. mint_authority)
    "source_behaviors": [str],   # behavior IDs that contributed (A1-D2)
    "trigger_summary": str,      # what to watch for
  }

Score formula (calibration: ChatGPT v0.8 spec section 4.3 — derived from
operator behavior heuristic. NOT empirically calibrated yet; v0.8 expanded
calibration will validate on n ≥ 30 tokens):

  score = ROLE_BASE_SCORE[role]
        + balance_pct_bonus   (>=1% supply +2, >=0.1% +1)
        + flow_pct_365d_bonus (>=1% supply +2, >=0.1% +1)
        + recency_bonus       (72h +3 / 7d +2 / 60d +1)
        + behavior_linkage    (A2/A3/C1 +3, C2/D1 +2, B1 +1)

  if router/aggregator OR public CEX hot wallet: score = -999 (NOT_TRACKED hard)

  Level: score >= 8 → CRITICAL
         score >= 5 → HIGH
         score >= 2 → NORMAL
         else       → NOT_TRACKED

CONTEXT B ONLY (per M47): same context as behavior_classifier. Do NOT
apply to liquid trad market addresses without re-calibration — e.g.
"insider hold ≥ 1%" trigger would false-flag legit VC / treasury
positions on BTC/ETH.
"""
from __future__ import annotations

from typing import Any

from i18n import t   # v0.6.2 i18n

# ----------------------------------------------------------------------
# Role base scores. Higher = more "this address moving is signal".
# Negative = NOT_TRACKED hard (infra / public CEX — they always move,
# never carries information about operator intent).
# ----------------------------------------------------------------------
ROLE_BASE_SCORE = {
    # Tier 1: any movement is operator-level signal
    "mint_authority": 6,
    "bridge_contract": 6,
    "cex_fanout_hub": 6,
    # v0.8.2: heuristically-flagged large unlabeled holders likely to be
    # project reserve / operator warehouse / VC OTC / MM cold storage.
    # Velvet/COLLECT/JCT test: these are the addresses outside m6/A2/LP
    # that hold ≥10% circulating + zero Arkham label. Any movement (especially
    # fanout to multiple EOAs / deposit to CEX / direct DEX sell) is a
    # high-confidence operator-action signal.
    "suspected_operator_reserve": 6,
    # v0.8.2: addresses receiving from a fake-mining mint authority cluster
    # (per fake_mining_detector). They look like miners on the surface but
    # are operator-controlled EOAs that received 0.5-3% supply each in
    # 1-3 lump transactions. Treat as operator allocation, not retail mining.
    "fake_mining_cluster_member": 6,

    # Tier 2: confirmed/observed actor with clear forensic role
    "direct_dumper": 5,
    "deployer": 5,
    "treasury_vesting": 4,
    "high_throughput_operator": 4,
    "fanout_recipient": 4,
    "anomaly_participant": 4,
    "cross_alpha_active_operator": 4,

    # Tier 3: secondary signal, watch but not primary
    "cex_deposit_destination": 3,
    "cross_alpha_inactive_whale": 2,
    "unknown_top_holder": 2,
    "dex_pool": 2,

    # NOT_TRACKED hard
    "router_aggregator": -999,
    "public_cex_hot_wallet": -999,

    # Fallback
    "other": 1,
}

# ----------------------------------------------------------------------
# Free-text role string → canonical role enum.
# Order matters (longest/most-specific match first). Pipeline-emitted
# strings come from forensic_pipeline._build_monitoring_wallets + the
# v0.7.21 fan-out / v0.7.24 mint-authority / high-throughput additions.
# ----------------------------------------------------------------------
_ROLE_STRING_MAP: list[tuple[str, str]] = [
    # Existing pipeline emissions (from _build_monitoring_wallets)
    ("项目方部署钱包", "deployer"),
    ("项目方钱包", "deployer"),
    ("已分完内幕钱包", "deployer"),
    ("分发中内幕钱包", "deployer"),
    ("分发中钱包", "deployer"),
    ("潜伏钱包", "deployer"),
    # Short-form (v0.7.27 fix: zest fixture uses "已分完钱包" without 内幕,
    # match shorter prefix). Place AFTER longer variants so "已分完内幕钱包"
    # still wins on real pipeline strings.
    ("已分完", "deployer"),
    ("分发中", "deployer"),
    ("庄家中转地", "deployer"),
    # Legacy 派发 wordings — keep mapping so old skeletons stay consistent.
    ("已派完内幕钱包", "deployer"),
    ("派发中内幕钱包", "deployer"),
    ("派发中钱包", "deployer"),
    ("已派完", "deployer"),
    ("派发中", "deployer"),
    ("近 72h 异常大单参与方", "anomaly_participant"),
    ("近期异常活动钱包", "anomaly_participant"),
    ("跨币大户", "cross_alpha_inactive_whale"),
    ("DEX 主池", "dex_pool"),
    ("DEX pool", "dex_pool"),
    # v0.7.24 mint authority + fan-out additions
    ("mint authority", "mint_authority"),
    ("Mint authority", "mint_authority"),
    ("CEX fan-out hub", "cex_fanout_hub"),
    ("fan-out hub", "cex_fanout_hub"),
    ("fan-out recipient", "fanout_recipient"),
    ("fanout recipient", "fanout_recipient"),
    ("high-throughput operator", "high_throughput_operator"),
    ("high throughput operator", "high_throughput_operator"),
    ("operator", "anomaly_participant"),
    # PLAY/JCT flow_operator names
    ("LP", "dex_pool"),
]

# Regex to extract "持 XX.XX% 总供应" / "(持 N%)" patterns from 工作流-emitted
# role/alert strings when no separate balance_tokens field is present.
# v0.7.27 zest fixture case: "庄家中转地 (持 85.40% 总供应)" carries the 85.4
# in the role string itself; without parsing it we lose CRITICAL signal.
import re as _re
_PCT_FROM_ROLE = _re.compile(r"持\s*(\d+\.?\d*)\s*%")

# ----------------------------------------------------------------------
# Arkham label → role override. If Arkham label says DEX router or
# CEX hot wallet, override pipeline role assignment.
# ----------------------------------------------------------------------
_ARKHAM_LABEL_OVERRIDES = {
    # Routers / aggregators — never useful to track
    "1inch": "router_aggregator",
    "PancakeSwap": "router_aggregator",
    "OKX DEX": "router_aggregator",
    "Uniswap": "router_aggregator",
    "OpenOcean": "router_aggregator",
    # Public CEX hot wallets — don't track (will dwarf all signals)
    "Binance": "public_cex_hot_wallet",
    "Bybit": "public_cex_hot_wallet",
    "OKX": "public_cex_hot_wallet",
    "Bitget": "public_cex_hot_wallet",
}

_ARKHAM_CLASSIFICATION_OVERRIDES = {
    "DEX_ROUTER": "router_aggregator",
    "DEX_POOL": "dex_pool",
    "DEX_AGGREGATOR": "router_aggregator",
    "CEX_HOT_WALLET": "public_cex_hot_wallet",
}


def _canonical_role(w: dict, public_cex_addrs: set[str]) -> str:
    """Map a monitoring_wallet entry's free-text role + Arkham label to
    a canonical role enum. Arkham label takes precedence on overrides
    (routers / public CEX) since pipeline role strings can mis-flag
    these as 'operator'.

    v0.7.27.1 adversarial review HIGH fix: cross-reference `public_cex_addrs` set
    (built from funding_attribution.cex_fanout_hubs[].cex_source*) so
    Bitget / KuCoin / etc hot wallets get NOT_TRACKED even when the
    pipeline-built monitoring_wallets entry doesn't carry the Arkham
    classification field (e.g. the JCT 0x1ab4973a Bitget hot wallet
    case)."""
    addr_lower = (w.get("addr_full") or w.get("address") or "").lower()
    if addr_lower and addr_lower in public_cex_addrs:
        return "public_cex_hot_wallet"
    # v0.8.2: pre-set monitor_role_enum (from hidden_operator_enricher)
    # takes precedence over re-canonicalization. The enricher categorizes
    # forensically-derived roles that cannot be inferred from free-text
    # role / Arkham label alone.
    # v0.8.2.2 audit LOW #6 fix: use `_is_enricher_assigned=True`
    # flag instead of a hardcoded enum allowlist, so future enricher roles
    # don't silently get re-canonicalized to "other".
    preset = (w.get("monitor_role_enum") or "").strip()
    if w.get("_is_enricher_assigned") and preset and preset in ROLE_BASE_SCORE:
        return preset
    # 1) Arkham classification (most reliable)
    arkham_cls = (w.get("arkham_classification") or "").strip()
    if arkham_cls in _ARKHAM_CLASSIFICATION_OVERRIDES:
        return _ARKHAM_CLASSIFICATION_OVERRIDES[arkham_cls]
    # 2) Arkham entity name (string match — case-sensitive on common entities)
    arkham_entity = (w.get("arkham_entity_name") or "").strip()
    for entity, role in _ARKHAM_LABEL_OVERRIDES.items():
        if entity.lower() in arkham_entity.lower():
            return role
    # 3) Pipeline free-text role string
    role_str = (w.get("role") or "").strip()
    for needle, role_enum in _ROLE_STRING_MAP:
        if needle in role_str:
            return role_enum
    return "other"


def _public_cex_address_set(skel: dict) -> set[str]:
    """v0.7.27.1 adversarial review HIGH fix: build address set of known public CEX
    hot wallets / deposit addresses from funding_attribution. These are
    pre-classified by surf Arkham labels at the detector stage. By
    cross-referencing this set against monitoring_wallets[].addr_full
    we catch CEX addresses the pipeline emit didn't label.
    """
    out: set[str] = set()
    fa = skel.get("funding_attribution") or {}
    hubs = ((fa.get("cex_fanout_hubs") or {}).get("hubs") or [])
    for h in hubs:
        addr = (h.get("cex_source") or "").lower()
        cls = (h.get("cex_source_classification") or "").upper()
        if addr and cls in ("CEX_HOT_WALLET", "CEX_DEPOSIT"):
            out.add(addr)
    # destination_label_summary often carries top CEX destinations too.
    dest = (fa.get("destination_label_summary") or {})
    for cls_key in ("CEX_HOT_WALLET", "CEX_DEPOSIT"):
        for d in (dest.get(cls_key) or []):
            addr = (d.get("addr") or d.get("address") or "").lower()
            if addr:
                out.add(addr)
    return out


def _balance_pct_supply(w: dict, total_supply: float | int | None) -> float:
    """Get balance % of total supply from monitoring_wallet entry.

    Two paths: explicit `balance_tokens` / `balance` numeric field
    (preferred), or regex-extracted "持 XX.XX% 总供应" from the role
    string (工作流 emits this format on 顶 持币人 / 庄家中转地
    wallets when the address holds significant supply but the entry
    doesn't carry a numeric balance field). Tolerates missing — 0."""
    bal = w.get("balance_tokens") or w.get("balance") or 0
    if total_supply and total_supply > 0 and bal:
        return (bal / total_supply) * 100
    # Fallback: parse "持 XX% 总供应" from role string.
    role_str = w.get("role") or ""
    m = _PCT_FROM_ROLE.search(role_str)
    if m:
        try:
            return float(m.group(1))
        except (TypeError, ValueError):
            pass
    return 0.0


def _flow_pct_supply(w: dict, total_supply: float | int | None) -> float:
    """Get 365d throughput flow % of total supply. Currently uses
    pipeline-emitted `total_in_tokens` / `total_in` field if present."""
    flow = w.get("total_in_tokens") or w.get("total_in") or 0
    if total_supply and total_supply > 0:
        return (flow / total_supply) * 100
    return 0.0


def _active_recency(w: dict) -> tuple[bool, bool, bool]:
    """Return (active_72h, active_7d, active_60d). Conservative: if no
    recency hint present, returns all False (no recency bonus).

    Pipeline-emitted markers we can use:
      - `last_active_days_ago`: int, from cross_sym or anomaly section
      - `recent_anomaly_participant`: bool from anomaly tagging
      - status_emoji ∈ {🔴 → active, 🟠 → high but not necessarily 72h}
    """
    days = w.get("last_active_days_ago")
    if isinstance(days, (int, float)):
        return (days <= 3, days <= 7, days <= 60)
    # Heuristic: anomaly participants are by definition 72h-active
    role_str = (w.get("role") or "").strip()
    if "72h" in role_str or "近期" in role_str:
        return (True, True, True)
    return (False, False, False)


def _behavior_linkage_set(skel: dict) -> dict[str, set[str]]:
    """Extract per-behavior address sets from skeleton for set-membership
    linkage checks. This is the v0.7.27 implementation of ChatGPT's spec
    `linked_to_X` semantics — we read addresses from each detector's
    output directly rather than via SQL trace (saves surf cost).

    v0.7.27.1 adversarial review HIGH fix: C1 must be INSIDER dumpers (intersection
    of dump_tracker top sellers AND lineage.m6 insider tree), not the
    full top_seller_addrs list which includes wash bots and unrelated
    high-frequency sellers. B1 uses top_seller_addrs as-is (it really
    IS "top DEX sellers when wash_dominated", which is the wash bot
    population), no longer copies the contaminated C1 set.
    """
    sets: dict[str, set[str]] = {
        "A2": set(),   # CEX fan-out hubs + recipients
        "A3": set(),   # mint authorities
        "B1": set(),   # wash bot top DEX sellers (when wash_dominated)
        "C1": set(),   # INSIDER dumpers — m6 ∩ top_seller_addrs
        "C2": set(),   # high-throughput operators
        "D1": set(),   # cross-alpha whales
    }
    fa = skel.get("funding_attribution") or {}

    # A2: CEX fan-out (hubs + recipients)
    hubs = ((fa.get("cex_fanout_hubs") or {}).get("hubs") or [])
    for h in hubs:
        addr = (h.get("addr") or "").lower()
        if addr:
            sets["A2"].add(addr)
        for r in (h.get("top_recipients") or []):
            ra = (r.get("addr") or "").lower()
            if ra:
                sets["A2"].add(ra)

    # A3: mint authorities (only non-excluded)
    auths = ((fa.get("mint_authorities") or {}).get("authorities") or [])
    for a in auths:
        if a.get("is_excluded"):
            continue
        addr = (a.get("addr") or "").lower()
        if addr:
            sets["A3"].add(addr)

    # Build the m6 insider address set for C1 intersection.
    m6_addrs: set[str] = set()
    for r in ((skel.get("lineage") or {}).get("m6") or {}).get("rows") or []:
        addr = (r.get("address") or r.get("addr") or "").lower()
        if addr:
            m6_addrs.add(addr)

    # B1 + C1 from dump_tracker.top_seller_addrs.
    dt = skel.get("dump_tracking") or {}
    top_sellers = set()
    for addr in (dt.get("top_seller_addrs") or []):
        if isinstance(addr, str) and addr:
            top_sellers.add(addr.lower())

    # C1: INSIDER dumpers = m6 ∩ top_sellers. If m6 is empty (mining /
    # bridge token), C1 set is empty — A3 / C2 / etc cover those tokens.
    if m6_addrs:
        sets["C1"] = top_sellers & m6_addrs
    # else: leave C1 empty rather than mass-tagging top sellers.

    # B1: wash bot top sellers — ONLY when wash_dominated. Use top_sellers
    # directly (acknowledging it's "top sellers in a wash-dominated token"
    # which is the wash bot population by construction). NO LONGER copies
    # C1's contaminated set.
    if dt.get("wash_dominated"):
        sets["B1"] = top_sellers

    # C2: high-throughput operators (only non-excluded)
    htd = ((fa.get("high_throughput_dumpers") or {}).get("dumpers") or [])
    for h in htd:
        if h.get("is_excluded"):
            continue
        addr = (h.get("addr") or "").lower()
        if addr:
            sets["C2"].add(addr)

    # D1: cross_sym whales
    for w in ((skel.get("cross_sym") or {}).get("whales") or []):
        addr = (w.get("address") or "").lower()
        if addr:
            sets["D1"].add(addr)

    return sets


def _score(
    role_enum: str,
    balance_pct: float,
    flow_pct: float,
    active_72h: bool,
    active_7d: bool,
    active_60d: bool,
    source_behaviors: list[str],
) -> int:
    """Apply the v0.7.27 deterministic score formula."""
    base = ROLE_BASE_SCORE.get(role_enum, 1)
    if base < 0:
        return base   # NOT_TRACKED hard penalty short-circuits

    s = base

    # Balance bonus — v0.7.27 self-fix: added >=10% / >=50% tiers so a
    # single wallet holding 85% supply lands CRITICAL on balance alone
    # (deployer base 5 + balance 5 = 10 → CRITICAL). Without these tiers
    # the score capped at base+2 and even pure operator concentration
    # only made HIGH.
    if balance_pct >= 50.0:
        s += 5
    elif balance_pct >= 10.0:
        s += 3
    elif balance_pct >= 1.0:
        s += 2
    elif balance_pct >= 0.1:
        s += 1

    # 365d throughput bonus — same expanded tiering.
    if flow_pct >= 50.0:
        s += 5
    elif flow_pct >= 10.0:
        s += 3
    elif flow_pct >= 1.0:
        s += 2
    elif flow_pct >= 0.1:
        s += 1

    # Recency bonus (priority: 72h > 7d > 60d, single tier)
    if active_72h:
        s += 3
    elif active_7d:
        s += 2
    elif active_60d:
        s += 1

    # Behavior linkage
    linkage_bonus = {
        "A2": 3, "A3": 3, "C1": 3,
        "C2": 2, "D1": 2,
        "B1": 1,
    }
    for bid in source_behaviors:
        s += linkage_bonus.get(bid, 0)

    return s


def _level_from_score(score: int) -> str:
    if score < 0:
        return "NOT_TRACKED"
    if score >= 8:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score >= 2:
        return "NORMAL"
    return "NOT_TRACKED"


# v0.7.27.1 adversarial review HIGH fix: rephrase to avoid banned words (持有/卖出/派/
# 进出/卖家/减仓/加仓). All 链上侦测-neutral facts about chain state.
# v0.6.2 i18n: values are i18n keys, resolved via t() at lookup time (after
# the pipeline / caller has set the active lang).
_REASON_ZH = {
    "mint_authority": "mon.reason_mint_authority",
    "bridge_contract": "mon.reason_bridge_contract",
    "cex_fanout_hub": "mon.reason_cex_fanout_hub",
    # v0.8.2 新加 (v0.8.2.2 audit MED #4 fix: 去掉 bare English
    # `mint` / `allocation` / implementation name `fake_mining_detector`,
    # 改用中文术语).
    "suspected_operator_reserve": "mon.reason_suspected_operator_reserve",
    "fake_mining_cluster_member": "mon.reason_fake_mining_cluster_member",
    "direct_dumper": "mon.reason_direct_dumper",
    "deployer": "mon.reason_deployer",
    "treasury_vesting": "mon.reason_treasury_vesting",
    "high_throughput_operator": "mon.reason_high_throughput_operator",
    "fanout_recipient": "mon.reason_fanout_recipient",
    "anomaly_participant": "mon.reason_anomaly_participant",
    "cross_alpha_active_operator": "mon.reason_cross_alpha_active_operator",
    "cross_alpha_inactive_whale": "mon.reason_cross_alpha_inactive_whale",
    "cex_deposit_destination": "mon.reason_cex_deposit_destination",
    "unknown_top_holder": "mon.reason_unknown_top_holder",
    "dex_pool": "mon.reason_dex_pool",
    "router_aggregator": "mon.reason_router_aggregator",
    "public_cex_hot_wallet": "mon.reason_public_cex_hot_wallet",
    "other": "mon.reason_other",
}

# v0.8.2: trigger_summary per role — forensic descriptors (NOT alerts).
# This skill is forensic — it does not push notifications. The role text
# explains what type of operator-side wallet the address is, and what
# kind of chain behavior would be relevant when the user manually checks
# it. The user reads chain activity in their own wallet tracker
# (Binance / OKX bulk import via paste.json), then cross-references
# with the 真实派发段 of the same report to estimate USD realized.
# v0.6.2 i18n: values are i18n keys, resolved via t() at lookup time.
_TRIGGER_ZH = {
    "suspected_operator_reserve": "mon.trigger_suspected_operator_reserve",
    "fake_mining_cluster_member": "mon.trigger_fake_mining_cluster_member",
}


def annotate_monitoring_wallets(skel: dict) -> list[dict]:
    """Top-level entry. Reads skeleton.monitoring_wallets[] and the
    behavior linkage sets, returns the SAME list with each entry
    annotated in-place. Caller can also call this on filled.json
    post-render to refresh.

    Returns: the annotated list (also mutates entries in place).
    """
    wallets = skel.get("monitoring_wallets") or []
    if not wallets:
        return wallets

    behavior_sets = _behavior_linkage_set(skel)
    public_cex_addrs = _public_cex_address_set(skel)
    total_supply = (skel.get("meta") or {}).get("total_supply")

    for w in wallets:
        # 1) Canonical role
        role_enum = _canonical_role(w, public_cex_addrs)
        # 2) Pull features
        balance_pct = _balance_pct_supply(w, total_supply)
        flow_pct = _flow_pct_supply(w, total_supply)
        a72, a7, a60 = _active_recency(w)
        # 3) Behavior linkage from address sets
        addr_lower = (w.get("addr_full") or w.get("address") or "").lower()
        source_behaviors = [
            bid for bid, addrs in behavior_sets.items() if addr_lower in addrs
        ]
        # 4) Score → level
        score = _score(role_enum, balance_pct, flow_pct, a72, a7, a60, source_behaviors)
        level = _level_from_score(score)
        # 5) Reason + trigger summary
        reason = t(_REASON_ZH.get(role_enum, _REASON_ZH["other"]))
        # v0.8.2: heuristic-derived hidden operator roles get their own
        # neutral trigger descriptor; other roles fall back to the
        # level-based descriptor.
        if role_enum in _TRIGGER_ZH:
            trigger = t(_TRIGGER_ZH[role_enum])
        elif level == "CRITICAL":
            trigger = t("mon.trigger_critical", behaviors=",".join(source_behaviors) or t("mon.behaviors_none"))
        elif level == "HIGH":
            # v0.8.0.3: use ≥ instead of > so md_cell HTML-escape doesn't
            # convert to &gt; in render output ("DEX 路由" is the
            # translation regression — restored to "DEX 路由" once).
            trigger = t("mon.trigger_high")
        elif level == "NORMAL":
            trigger = t("mon.trigger_normal")
        else:
            trigger = t("mon.trigger_not_tracked")

        # 6) Annotate
        w["monitor_level"] = level
        w["monitor_score"] = score
        w["monitor_role_enum"] = role_enum
        w["monitor_reason"] = reason
        w["source_behaviors"] = source_behaviors
        w["trigger_summary"] = trigger

    return wallets


def summary_by_level(wallets: list[dict]) -> dict[str, int]:
    """Return tally of {level: count} across the annotated list."""
    out = {"CRITICAL": 0, "HIGH": 0, "NORMAL": 0, "NOT_TRACKED": 0}
    for w in wallets or []:
        lvl = w.get("monitor_level") or "NOT_TRACKED"
        out[lvl] = out.get(lvl, 0) + 1
    return out
