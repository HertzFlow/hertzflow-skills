"""v0.7.28 — Deterministic address role resolver + cross-link index.

Walks all detector outputs in the skeleton, collects EVERY address that
appears (whether in mint_authorities / cex_fanout_hubs / high_throughput
/ monitoring_wallets / etc), groups by addr, picks the highest-priority
primary_role per address, emits skeleton.address_role_index keyed by
lowercased address.

Goal: stop the report from repeating the same wallet's full card
across 4 sections. The render template uses the index to:
  - Show full card ONLY in the address's primary_role section.
  - Replace duplicate card with a compact link badge in other sections.
  - Append the index to machine_readable_json so LLMs / AI 二次研究 can
    cross-reference even without following markdown anchors.

Selective dedupe scope (v0.7.28):
  - high_throughput_dumpers list: dedupe (highest duplicate ratio —
    JCT has ~80% of HT operators also in fan-out hub recipients).
  - fan-out hub recipients list: dedupe.
  - mining-fed wallet outflows: KEEP FULL (only 2-5 entries, info
    density too high to summarize).
  - monitoring_wallets: KEEP ALL (retail needs to import), add a
    "primary: X" badge column.
  - mint_authorities section: KEEP FULL (only 2-8 entries typically).

This balances retail size reduction (-25-35% on dense JCT/H reports)
with LLM safety net (index always dumped to JSON tail).
"""
from __future__ import annotations

from typing import Any

from i18n import t   # v0.6.2 i18n

# ----------------------------------------------------------------------
# Role priority — highest priority FIRST. When an address appears under
# multiple roles, primary_role = the one earliest in this list.
# ----------------------------------------------------------------------
ROLE_PRIORITY = [
    "mint_authority",           # supply source — every move is signal
    "cex_fanout_hub",            # control point — upstream of recipients
    "direct_dumper",             # confirmed insider sell action
    "high_throughput_operator",  # historical sweeper
    "fanout_recipient",          # downstream sub-wallet
    "anomaly_participant",       # near-term observable
    "cross_alpha_whale",         # cross-token presence
    "deployer",                  # static role, info-only without activity
    "treasury_vesting",          # known time-table actor
    "unknown_top_holder",        # generic large holder
    "dex_pool",                  # infra (DEX main pool)
    "router_aggregator",         # infra (DEX router)
    "public_cex_hot_wallet",     # infra (public CEX hot wallet)
    "other",
]


# ----------------------------------------------------------------------
# Section anchor + zh label for primary role. Render template uses these
# to assemble the compact "[→ 详见 X 段]" link.
# Anchors are the markdown section IDs auto-generated from the H2
# headings (kebab-case of the Chinese title). render_report.py keeps
# these stable via inline anchor tags where helpful.
# ----------------------------------------------------------------------
# v0.7.28.1 adversarial review HIGH fix: explicit anchors emit as `<a id="X"></a>`
# right BEFORE the corresponding heading (render_report.py injects these
# at v0.7.28.1+). Don't rely on markdown auto-anchor heuristics which
# vary across renderers and break on Chinese/emoji/parens.
# v0.7.28.1 adversarial review HIGH fix: rename labels to avoid banned words
# ("派" in "真实派发", "进场" in "进场上限"). 链上侦测-neutral.
# v0.6.2 i18n: `label_key` holds an i18n key; the user-facing label is
# resolved via t() at build time (after the pipeline calls set_lang), so
# the same SECTION_INFO produces zh or en labels per active language.
SECTION_INFO = {
    "mint_authority": {
        "anchor": "section-bridge-mint",
        "label_key": "addr_role.section_label.mint_authority",
    },
    "cex_fanout_hub": {
        "anchor": "section-cex-fanout",
        "label_key": "addr_role.section_label.cex_fanout_hub",
    },
    "fanout_recipient": {
        "anchor": "section-cex-fanout",
        "label_key": "addr_role.section_label.fanout_recipient",
    },
    "direct_dumper": {
        "anchor": "section-real-distribution",
        "label_key": "addr_role.section_label.direct_dumper",
    },
    "high_throughput_operator": {
        "anchor": "section-high-throughput",
        "label_key": "addr_role.section_label.high_throughput_operator",
    },
    "anomaly_participant": {
        "anchor": "section-recent-anomaly",
        "label_key": "addr_role.section_label.anomaly_participant",
    },
    "cross_alpha_whale": {
        "anchor": "section-cross-sym",
        "label_key": "addr_role.section_label.cross_alpha_whale",
    },
    "deployer": {
        "anchor": "section-alloc",
        "label_key": "section.alloc.title",
    },
    "treasury_vesting": {
        "anchor": "section-alloc",
        "label_key": "section.alloc.title",
    },
    "dex_pool": {
        "anchor": "section-liq",
        "label_key": "addr_role.section_label.dex_pool",
    },
    "router_aggregator": {
        "anchor": "section-monitoring",
        "label_key": "addr_role.section_label.monitoring",
    },
    "public_cex_hot_wallet": {
        "anchor": "section-monitoring",
        "label_key": "addr_role.section_label.monitoring",
    },
    "unknown_top_holder": {
        "anchor": "section-holdings",
        "label_key": "addr_role.section_label.unknown_top_holder",
    },
    "other": {
        "anchor": "section-monitoring",
        "label_key": "addr_role.section_label.monitoring",
    },
}


def _norm_addr(a: Any) -> str:
    """Lowercase + strip. Returns empty string on None/non-str."""
    if not isinstance(a, str):
        return ""
    return a.strip().lower()


def _collect_addresses_per_role(skel: dict) -> dict[str, set[str]]:
    """Walk every detector list and collect addresses observed per role.
    Output: {role_enum: set[addr_lower]}.

    Defensive against missing keys / detector skips — every list is
    optional. Solana abort tokens (FARTCOIN, JELLYJELLY) will return
    mostly-empty sets.
    """
    out: dict[str, set[str]] = {role: set() for role in ROLE_PRIORITY}

    fa = skel.get("funding_attribution") or {}

    # mint_authority (only non-excluded)
    for a in ((fa.get("mint_authorities") or {}).get("authorities") or []):
        if a.get("is_excluded"):
            continue
        addr = _norm_addr(a.get("addr"))
        if addr:
            out["mint_authority"].add(addr)

    # cex_fanout_hub + fanout_recipient
    for h in ((fa.get("cex_fanout_hubs") or {}).get("hubs") or []):
        haddr = _norm_addr(h.get("addr"))
        if haddr:
            out["cex_fanout_hub"].add(haddr)
        for r in (h.get("top_recipients") or []):
            raddr = _norm_addr(r.get("addr"))
            if raddr:
                out["fanout_recipient"].add(raddr)

    # high_throughput_operator (only non-excluded)
    for d in ((fa.get("high_throughput_dumpers") or {}).get("dumpers") or []):
        if d.get("is_excluded"):
            continue
        addr = _norm_addr(d.get("addr"))
        if addr:
            out["high_throughput_operator"].add(addr)

    # direct_dumper — m6 ∩ top_seller_addrs (matches behavior_classifier C1
    # semantics: insider-confirmed dump path, not generic top sellers).
    # v0.7.28.1 adversarial review HIGH fix: skeleton m6 rows use `addr_full`, not
    # `address`/`addr`. The previous lookup never matched, so direct_dumper
    # set was always empty on real skeletons.
    m6_addrs: set[str] = set()
    for r in ((skel.get("lineage") or {}).get("m6") or {}).get("rows") or []:
        addr = _norm_addr(
            r.get("addr_full") or r.get("address") or r.get("addr")
        )
        if addr:
            m6_addrs.add(addr)
    dt = skel.get("dump_tracking") or {}
    top_sellers = {_norm_addr(a) for a in (dt.get("top_seller_addrs") or []) if a}
    out["direct_dumper"] = (m6_addrs & top_sellers) if m6_addrs else set()

    # cross_alpha_whale
    for w in ((skel.get("cross_sym") or {}).get("whales") or []):
        addr = _norm_addr(w.get("address"))
        if addr:
            out["cross_alpha_whale"].add(addr)

    # deployer — only the deployer_addr itself. M6 rows are NOT
    # deployer-class (they're direct_dumper / anomaly_participant);
    # v0.7.28.1 adversarial review MED fix: comment previously said "flowchart_nodes
    # + m6" which over-claimed. Now correctly reflects code.
    lineage = skel.get("lineage") or {}
    dep = _norm_addr(lineage.get("deployer_addr"))
    if dep:
        out["deployer"].add(dep)
    # treasury_vesting — from cross_sym.role_classification Arkham hits
    for w in ((skel.get("cross_sym") or {}).get("whales") or []):
        if (w.get("arkham_label") or "").lower() in ("vesting", "treasury", "multisig"):
            addr = _norm_addr(w.get("address"))
            if addr:
                out["treasury_vesting"].add(addr)

    # anomaly_participant — from anomaly.waves[].events[].from_to addrs.
    # v0.7.28.1 adversarial review MED fix: previous split-on-arrow logic was loose
    # ("0xabc(label)→0xdef" → invalid pseudo-address "0xabc(label)").
    # Use strict EVM-address regex over the whole from_to string. EVM
    # addresses cannot contain → or parens, so regex is unambiguous.
    import re as _re_local
    _evm_addr_re = _re_local.compile(r"\b0x[a-fA-F0-9]{40}\b")
    for w in (skel.get("anomaly") or {}).get("waves") or []:
        for ev in w.get("events") or []:
            ft = ev.get("from_to") or ""
            for match in _evm_addr_re.findall(ft):
                addr = _norm_addr(match)
                if addr:
                    out["anomaly_participant"].add(addr)

    # monitoring_wallets — entries already carry role enum from
    # monitoring_ranker (v0.7.27). Cross-feed router/public_cex_hot/
    # dex_pool/unknown_top_holder/other roles into the index.
    for w in (skel.get("monitoring_wallets") or []):
        addr = _norm_addr(w.get("addr_full") or w.get("address"))
        if not addr:
            continue
        rid = w.get("monitor_role_enum") or ""
        if rid == "router_aggregator":
            out["router_aggregator"].add(addr)
        elif rid == "public_cex_hot_wallet":
            out["public_cex_hot_wallet"].add(addr)
        elif rid == "dex_pool":
            out["dex_pool"].add(addr)
        elif rid == "unknown_top_holder":
            out["unknown_top_holder"].add(addr)
        elif rid == "other":
            out["other"].add(addr)

    return out


def build_address_role_index(skel: dict) -> dict[str, dict]:
    """Top-level entry. Returns the address_role_index keyed by
    lowercased address:

      {
        "0x055a3b37...": {
          "primary_role": "cex_fanout_hub",
          "all_roles": ["cex_fanout_hub", "fanout_recipient", "high_throughput_operator"],
          "primary_section_anchor": "cex-fanout",
          "primary_section_label_zh": "🎯 CEX 提币 大规模分发 控筹",
          "addr_short": "0x055a3b37"
        },
        ...
      }
    """
    per_role = _collect_addresses_per_role(skel)
    all_addrs: set[str] = set()
    for s in per_role.values():
        all_addrs.update(s)

    index: dict[str, dict] = {}
    for addr in all_addrs:
        roles = [r for r in ROLE_PRIORITY if addr in per_role[r]]
        primary = roles[0] if roles else "other"
        info = SECTION_INFO.get(primary, SECTION_INFO["other"])
        index[addr] = {
            "primary_role": primary,
            "all_roles": roles,
            "primary_section_anchor": info["anchor"],
            "primary_section_label_zh": t(info["label_key"]),
            "addr_short": addr[:10] if addr.startswith("0x") else addr[:8],
        }
    return index


def is_primary_in_section(
    addr: str,
    section_role: str,
    address_role_index: dict[str, dict],
) -> bool:
    """Render helper: given an address and the section's role enum
    (e.g. 'high_throughput_operator' for the 🌊 high-throughput section),
    return True if THIS section is the address's primary section — i.e.
    show full card. Return False if primary is elsewhere — show compact
    cross-link.

    For fan-out section, treat both 'cex_fanout_hub' and 'fanout_recipient'
    as matching since they share the same anchor.
    """
    if not addr:
        return True  # safe default: full card if no addr to look up
    entry = address_role_index.get(_norm_addr(addr))
    if not entry:
        return True  # never seen elsewhere → full card
    pr = entry.get("primary_role")
    if pr == section_role:
        return True
    # fan-out hub + recipient share the same section
    if section_role == "cex_fanout_hub" and pr == "fanout_recipient":
        return True
    if section_role == "fanout_recipient" and pr == "cex_fanout_hub":
        return True
    return False


def cross_link_badge_zh(
    addr: str,
    address_role_index: dict[str, dict],
) -> str:
    """Render helper: return 1-line Chinese cross-link badge for compact
    display. e.g. "[🎯 primary: 🎯 CEX 提币 大规模分发 控筹](#cex-大规模分发)".
    Falls back to empty string if address is not in index.
    """
    entry = address_role_index.get(_norm_addr(addr))
    if not entry:
        return ""
    return (
        f"[🎯 primary: {entry['primary_section_label_zh']}]"
        f"(#{entry['primary_section_anchor']})"
    )
