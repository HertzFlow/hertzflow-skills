#!/usr/bin/env python3
"""section_l_distribution.py — role-based holdings distribution + lineage flowchart.

Pure aggregation. Consumes:
- top_holders (from section_f_holders)
- rule11 outputs (deployer, pre_launch_receivers, quiet_wallets,
  dumper_destinations)
- dex_pool_addr (from section_liq.discover_main_pool)

Classifies every top holder into a closed-enum role, aggregates into
holdings_distribution.role_rows + progress_bars, and pushes lineage
flowchart nodes (node_NNN) / edges via the shared EvidenceGraph.

Role enum (closed):
  DEX_POOL          — matches dex_pool_addr
  DEPLOYER          — matches deployer address
  RULE11_QUIET      — in rule11.quiet_wallets, dumped_pct = 0
  RULE11_PARTIAL    — rule11 receiver with 0 < dumped_pct < 95
  RULE11_FULL       — rule11 receiver with dumped_pct >= 95 (rare to still hold)
  OPERATOR_RELAY    — dumper-destination holding >= 1% total supply (likely
                      operator/insider rotation wallet, NOT retail fan-out)
  DUMPER_DEST       — dumper-destination holding < 1% total supply (retail fan-out)
  OTHER             — everything else (organic + retail + unclassified)

v0.6 (2026-05-24, Phase B.4)
v0.6.0-beta.3 (2026-05-24): split DUMPER_DEST into OPERATOR_RELAY +
DUMPER_DEST based on holding size. ZEST 3-sym test exposed: when 3
wallets receive 90.44% supply from a Rule 11 dumper, they're operator
relay wallets (the real holders to monitor), not "retail fan-out". The
unified DUMPER_DEST label misled the reader.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from evidence_graph import EvidenceGraph
from i18n import t   # v0.6.2 i18n
from chain_router import get_active_chain as _chain_get_active  # v0.7.21.7


def _norm_addr(a) -> str:
    """v0.7.21.7: chain-aware case. EVM lowercases (case-insensitive);
    Solana base58 preserves case (case-sensitive)."""
    if not isinstance(a, str) or not a:
        return ""
    return a if _chain_get_active() == "solana" else a.lower()


def _role_label(role: str) -> str:
    """v0.6.2: lookup role label via i18n (was hardcoded _ROLE_LABELS dict).
    Active lang is set by forensic_pipeline main() before build_skeleton runs."""
    return t(f"role.{role}.label")


def _arkham_lockup_from_top_holders(top_addrs: list[str]) -> set[str]:
    """v0.9.7 fix #1 (FOLKS Sablier 2026-06-16): batch Arkham label lookup
    on Top 50 holders, return set of addrs whose label matches the
    vesting/multisig/treasury regex (= "project-controlled supply pool",
    not retail).

    Why: rule_11 receivers only cover m6 depth-1 wallets. Vesting
    contracts often sit 2-3 hops down (treasury → Sablier funder →
    Sablier Lockup → recipients). They land in Top 50 holders but were
    classified as "OTHER" because lockup_set didn't include them.
    FOLKS empirical: Sablier Lockup NFT held 4.22M FOLKS (27.7% of
    circulating) as "其他 (散户+未分类)" in v0.9.6.

    Cost: 1 wallet-labels-batch call (~1-2 credits / 50 addrs). Same
    helper used by rule_11 / cross_sym / flow_operators sections.

    Failure-safe: any error returns empty set → caller fallback is
    v0.9.6 behavior (m6-only lockup_set). Never regresses.
    """
    if not top_addrs:
        return set()
    try:
        from surf_labels_probe import resolve_labels
        from surf_labels_probe import neutral_infra_kind as _neutral_infra_kind
        from protocol_lockup_detector import (
            VESTING_LABEL_RE,
            MULTISIG_LABEL_RE,
            TREASURY_LABEL_RE,
        )
    except Exception as e:
        import sys as _sys
        print(f"[section_l] arkham lockup probe import failed (non-fatal): {e}",
              file=_sys.stderr)
        return set()
    # v0.9.7 fix (post-FOLKS 2026-06-16): surf wallet-labels-batch docs say
    # 100-address limit, but empirical test (FOLKS Top 50 ran into exit 4
    # `INTERNAL_ERROR`) shows surf crashes at ~25 addresses. Chunk into 20
    # per call so 50 holders = 3 surf calls (still cheap, +1-2 credits each).
    BATCH = 20
    labels: dict[str, dict] = {}
    # v0.9.7 adversarial review Finding 8 (LOW): per-chunk try so a single chunk failure
    # doesn't discard the labels from chunks that DID succeed. Pre-fix the
    # whole loop was in one try → chunk 2 failing threw away chunk 1's
    # vesting hits.
    n_chunk_errs = 0
    for i in range(0, len(top_addrs), BATCH):
        chunk = top_addrs[i:i + BATCH]
        try:
            chunk_labels = resolve_labels(chunk) or {}
            labels.update(chunk_labels)
        except Exception as e:
            n_chunk_errs += 1
            import sys as _sys
            print(f"[section_l] arkham lockup probe chunk failed (non-fatal, "
                  f"keeping {len(labels)} labels so far): {e}", file=_sys.stderr)
    if not labels:
        return set()
    extra: set[str] = set()
    for addr, info in labels.items():
        if not isinstance(info, dict):
            continue
        text_parts = []
        for k in ("label", "entity_name"):
            v = info.get(k)
            if v and isinstance(v, str):
                text_parts.append(v)
        label_text = " | ".join(text_parts)
        if not label_text:
            continue
        # ANY of vesting / multisig / treasury → PROJECT_LOCKUP bucket.
        # The 3 regexes are pre-built in protocol_lockup_detector and
        # tested cross-token.
        if (VESTING_LABEL_RE.search(label_text)
                or MULTISIG_LABEL_RE.search(label_text)
                or TREASURY_LABEL_RE.search(label_text)):
            extra.add(_norm_addr(addr))
        elif _neutral_infra_kind(info.get("label"), info.get("entity_name"),
                                 info.get("entity_type")):
            # CEX custody / DEX pool — the docstring above (v0.7.10.3) already
            # documents that DEX-infra / CEX-custody receivers belong in this
            # separated-from-insiders bucket, but the implementation only matched
            # vesting/multisig/treasury, so a "Binance Wallet" or a bare "V3 Pool"
            # top-holder that was a dumper-destination leaked into OPERATOR_RELAY.
            extra.add(_norm_addr(addr))
    return extra


# Closed enum list (was _ROLE_LABELS keys). Used by `for role in _ROLE_LABELS_KEYS`
# iteration order — kept stable for deterministic output.
# v0.7.10.3: PROJECT_LOCKUP inserted after DEPLOYER — vesting / multisig /
# treasury / DEX-infra / CEX-custody receivers (Arkham-verified) separated
# from genuine quiet insider candidates.
_ROLE_LABELS_KEYS = (
    "DEX_POOL", "DEPLOYER", "PROJECT_LOCKUP", "RULE11_QUIET",
    "RULE11_PARTIAL", "RULE11_FULL", "OPERATOR_RELAY", "DUMPER_DEST", "OTHER",
)

# Role → node type for EvidenceGraph.add_node (closed enum)
_ROLE_NODE_TYPE = {
    "DEX_POOL": "lp_pool",
    "DEPLOYER": "deployer",
    "PROJECT_LOCKUP": "project_lockup",
    "RULE11_QUIET": "quiet_wallet",
    "RULE11_PARTIAL": "dumper",
    "RULE11_FULL": "dumper",
    "OPERATOR_RELAY": "dumper",     # treat as upstream of fan-out
    "DUMPER_DEST": "retail_fanout",
    "OTHER": "active_holder",
}

# Holding-size threshold (% of total supply) above which a dumper destination
# is reclassified as OPERATOR_RELAY rather than DUMPER_DEST. 1% chosen
# empirically — ZEST had 3 wallets at 30%/8.3%/4.1%, all clearly operator
# tier; a 0.05% retail fan-out destination wouldn't have triggered.
_OPERATOR_RELAY_PCT_THRESHOLD = 1.0


def _progress_bar_relative(pct: float, *, max_pct: float, width: int = 20) -> str:
    """Bar scaled to the dataset max for cross-role visual comparison.

    Useful for "which role dominates" but visually misleading on its own —
    a 0.01% role next to a 0.005% role renders at full bar. Always emit
    next to an absolute bar (`_progress_bar_absolute`) per cross-LLM audit
    alpha.8 audit MEDIUM finding.
    """
    if pct is None or pct <= 0 or not max_pct:
        return "░" * width
    filled = min(width, int(round(pct / max_pct * width)))
    return "█" * filled + "░" * (width - filled)


def _progress_bar_absolute(pct: float, *, width: int = 20) -> str:
    """Bar scaled to 0-100% of total supply for absolute exposure magnitude.

    A 0.01% role renders as one cell; a 50% role renders as half-bar.
    Visual salience matches absolute risk magnitude — peer to the
    relative bar, not a replacement.
    """
    if pct is None or pct <= 0:
        return "░" * width
    filled = min(width, int(round(pct / 100 * width)))
    return "█" * filled + "░" * (width - filled)


def _classify(
    addr: str,
    *,
    deployer: str | None,
    dex_pool: str | None,
    quiet_set: set,
    partial_set: set,
    full_set: set,
    dumper_dest_set: set,
    holder_pct: float | None = None,
    lockup_set: set | None = None,
) -> str:
    """Classify an address against the closed role enum.

    `holder_pct` is the holder's % of total supply (top_holders entry's
    pct_of_total). Used to split DUMPER_DEST into OPERATOR_RELAY for
    high-concentration recipients.

    `lockup_set` (v0.7.10.3) is the set of receiver addresses Arkham-labeled
    vesting / multisig / treasury / DEX-infra / CEX-custody. Checked AHEAD of
    quiet/partial/full so a lockup contract with dumped_pct=0 is labeled
    PROJECT_LOCKUP, not RULE11_QUIET.
    """
    a = _norm_addr(addr)
    if dex_pool and a == _norm_addr(dex_pool):
        return "DEX_POOL"
    if deployer and a == _norm_addr(deployer):
        return "DEPLOYER"
    if lockup_set and a in lockup_set:
        return "PROJECT_LOCKUP"
    if a in quiet_set:
        return "RULE11_QUIET"
    if a in partial_set:
        return "RULE11_PARTIAL"
    if a in full_set:
        return "RULE11_FULL"
    if a in dumper_dest_set:
        # Threshold split: >=1% supply → operator relay, else retail fan-out
        # adversarial review beta.3 audit MED: holder_pct from upstream top_holders dict
        # could be None / NaN / non-numeric / Infinity under schema drift.
        # adversarial review beta.4 8th audit MED: NaN guard via `pct == pct` was correct
        # but Infinity passed through and upgraded to OPERATOR_RELAY (inf
        # >= 1.0). Use math.isfinite() — rejects NaN AND ±Infinity in one
        # check. Fail-safe to DUMPER_DEST (less-alarming label) on any
        # invalid value.
        try:
            pct_float = float(holder_pct) if holder_pct is not None else None
            if pct_float is not None and math.isfinite(pct_float) and \
                    pct_float >= _OPERATOR_RELAY_PCT_THRESHOLD:
                return "OPERATOR_RELAY"
        except (TypeError, ValueError):
            pass   # invalid type → treat as missing → DUMPER_DEST
        return "DUMPER_DEST"
    return "OTHER"


def run(
    *,
    top_holders: list[dict],
    rule11: dict,
    dex_pool_addr: str | None,
    total_supply: int | None,
    current_price_usd: float | None,
    eg: EvidenceGraph,
) -> dict[str, Any]:
    """Section L entrypoint — role classification + lineage flowchart build.

    Mutates `eg` in place (adds node_NNN entries). Returns rows/bars/nodes/edges
    for the report skeleton.
    """
    deployer = rule11.get("deployer")
    receivers = rule11.get("pre_launch_receivers", []) or []
    quiet_wallets = rule11.get("quiet_wallets", []) or []

    # v0.7.10.3: lockup_set wins over quiet/partial/full bucket — any
    # receiver Arkham-labeled vesting/multisig/treasury/DEX-infra/CEX-custody
    # gets PROJECT_LOCKUP regardless of dumped_pct.
    lockup_set = {_norm_addr(r["addr"]) for r in receivers if r.get("is_protocol_lockup")}

    # v0.9.7 fix #1 (FOLKS Sablier 漏报 2026-06-16): Top 50 holders 也跑
    # Arkham label lookup, vesting/multisig/treasury 关键词命中的加进
    # lockup_set. 旧版 lockup_set 只来自 m6 受方 (deployer 直接下游, 深度
    # 1), 漏掉所有深度 ≥2 的 vesting 合约 (FOLKS Sablier Lockup 通过
    # treasury → SablierBatchLockup → Sablier Lockup NFT 三跳深度, 不在
    # m6 set 里). 后果: Sablier 4.22M tokens (27.7% 流通) 被归类为
    # "其他 (散户+未分类)", 实际是项目方分发池.
    #
    # 成本: 1 surf wallet-labels-batch / 50 addrs ≈ 1-2 credits. 几乎免费.
    # Failure mode: surf 失败/标签缺失 → 跟旧版 fallback 行为完全一致 (空
    # set 加进 lockup_set 没影响). 永不退化, 只增量加分.
    top_holder_addrs = [
        _norm_addr(h.get("addr") or "") for h in top_holders
        if h.get("addr")
    ]
    arkham_lockup_extra = _arkham_lockup_from_top_holders(top_holder_addrs)
    if arkham_lockup_extra:
        lockup_set = lockup_set | arkham_lockup_extra
    # v0.7.13 (issue #1 Bug 1): dumped_pct may be None ("unknown") for a
    # sub-dumper whose backfill failed — guard so it is excluded from each
    # bucket instead of crashing `0 < None < 95`.
    # v1.2.8: shared genuine-quiet predicate (requires a real ≥1-token balance) so
    # 0-value address-poisoning decoys are not labelled 潜伏 here while the alloc
    # table / detector exclude them — adversarial review flagged the divergence.
    from rule_11_backward_trace import is_genuine_quiet_holder
    quiet_set = {
        _norm_addr(r["addr"]) for r in receivers if is_genuine_quiet_holder(r)
    }
    partial_set = {
        _norm_addr(r["addr"]) for r in receivers
        if r.get("dumped_pct") is not None and 0 < r["dumped_pct"] < 95
        and not r.get("is_protocol_lockup")
    }
    full_set = {
        _norm_addr(r["addr"]) for r in receivers
        if r.get("dumped_pct") is not None and r["dumped_pct"] >= 95
        and not r.get("is_protocol_lockup")
    }

    dumper_destinations = rule11.get("dumper_destinations", {}) or {}
    dumper_dest_set: set[str] = set()
    for _, dests in dumper_destinations.items():
        for d in dests:
            to_addr = _norm_addr(d.get("to") or "")
            if to_addr:
                dumper_dest_set.add(to_addr)

    # ---- Classify + aggregate per role ----
    by_role: dict[str, list[dict]] = {k: [] for k in _ROLE_LABELS_KEYS}
    for h in top_holders:
        role = _classify(
            h["addr"], deployer=deployer, dex_pool=dex_pool_addr,
            quiet_set=quiet_set, partial_set=partial_set,
            full_set=full_set, dumper_dest_set=dumper_dest_set,
            holder_pct=h.get("pct_of_total"),
            lockup_set=lockup_set,
        )
        by_role[role].append(h)

    role_rows = []
    for role in _ROLE_LABELS_KEYS:
        members = by_role[role]
        if not members and role not in ("DEX_POOL", "DEPLOYER", "RULE11_QUIET"):
            # Skip empty rows except for mandatory anchors
            continue
        total_balance = sum(m["balance"] for m in members)
        pct = (total_balance / total_supply * 100) if total_supply else None
        usd = (total_balance * current_price_usd) if current_price_usd else None
        top_addr = members[0]["addr"] if members else None
        role_rows.append({
            "role": role,
            "role_label": _role_label(role),
            "n_wallets": len(members),
            "total_balance": total_balance,
            "pct_of_total": pct,
            "usd_value": usd,
            "top_addr_short": top_addr[:10] + "…" if top_addr else None,
            "top_addr_full": top_addr,
        })

    max_pct = max((r["pct_of_total"] or 0) for r in role_rows) or 1.0
    progress_bars = []
    for r in role_rows:
        pct = r["pct_of_total"]
        head = f"{r['total_balance']:,.0f} tokens"
        if pct is not None:
            head += f" ({pct:.2f}%"
            if r["usd_value"]:
                head += f" / ${r['usd_value']:,.0f})"
            else:
                head += ")"
        progress_bars.append({
            "role": r["role"],
            "label": r["role_label"],
            "pct": pct,
            # Dual encoding (cross-LLM audit fix):
            # - `bar` is relative-to-dataset-max (best for cross-role visual)
            # - `bar_absolute` is 0-100% of total supply (true exposure scale)
            # Template renders both side-by-side so a 0.01% role can't look
            # like a 100% role just because it's the dataset max.
            "bar": _progress_bar_relative(pct or 0, max_pct=max_pct),
            "bar_absolute": _progress_bar_absolute(pct or 0),
            "value_text": head,
        })

    # ---- Build lineage flowchart nodes + edges ----
    flowchart_nodes: list[dict] = []
    flowchart_edges: list[dict] = []

    # Deployer node (always present if Rule 11 found one)
    deployer_node_ref: str | None = None
    if deployer:
        deployer_node_ref = eg.add_node(
            type="deployer", addr=deployer, label_hint=t("role.DEPLOYER.label_with_hint"),
        )
        flowchart_nodes.append({
            "node_ref": deployer_node_ref,
            "role": "DEPLOYER",
            "addr_short": deployer[:10] + "…",
        })

    # DEX pool node
    pool_node_ref: str | None = None
    if dex_pool_addr:
        pool_node_ref = eg.add_node(
            type="lp_pool", addr=dex_pool_addr, label_hint=t("role.DEX_POOL.label"),
        )
        flowchart_nodes.append({
            "node_ref": pool_node_ref,
            "role": "DEX_POOL",
            "addr_short": dex_pool_addr[:10] + "…",
        })

    # addr (lowercase full) → node_ref. The single source of truth for node
    # identity. We previously deduped destinations via 10-char addr_short
    # prefix match, which cross-LLM audit on alpha.8 flagged as HIGH —
    # two distinct full addresses with the same first 10 chars (1 in 2^40,
    # but actively gameable by an attacker generating a colliding key) would
    # collapse onto one node, sending edges to the wrong entity. Because
    # lineage.flowchart_nodes/edges is `locked` in field_authority, that
    # corruption would become immutable evidence. Full-address keying closes
    # the surface.
    addr_to_node_ref: dict[str, str] = {}
    if deployer_node_ref:
        addr_to_node_ref[_norm_addr(deployer)] = deployer_node_ref
    if pool_node_ref and dex_pool_addr:
        addr_to_node_ref[_norm_addr(dex_pool_addr)] = pool_node_ref

    # Receiver nodes (every Rule 11 pre-launch receiver gets a node)
    from rule_11_backward_trace import is_genuine_quiet_holder, is_zero_balance_decoy
    receiver_node_refs: dict[str, str] = {}
    for r in receivers:
        addr = r["addr"]
        # v1.2.8: skip 0-value address-poisoning decoys — they received nothing and
        # hold nothing, so they are not real distribution nodes (look-alike-prefix
        # noise that previously got typed 潜伏 here).
        if is_zero_balance_decoy(r):
            continue
        # `or 0`: a sub-dumper whose backfill never confirmed could be None;
        # treat unknown as 0 here so node typing / the `{dumped:.0f}%` label
        # below never crash (v0.7.13 issue #1 Bug 1 defense-in-depth).
        dumped = r.get("dumped_pct") or 0
        if dumped >= 95:
            ntype = "dumper"
        elif is_genuine_quiet_holder(r):
            ntype = "quiet_wallet"
        else:
            ntype = "dumper"
        nref = eg.add_node(
            type=ntype, addr=addr,
            balance=r.get("current_balance"),
            label_hint=t("sec1.lineage.label_hint_receiver", dumped=dumped),
        )
        receiver_node_refs[_norm_addr(addr)] = nref
        addr_to_node_ref[_norm_addr(addr)] = nref
        flowchart_nodes.append({
            "node_ref": nref,
            "role": (
                "RULE11_QUIET" if dumped == 0
                else "RULE11_FULL" if dumped >= 95
                else "RULE11_PARTIAL"
            ),
            "addr_short": addr[:10] + "…",
            "dumped_pct": dumped,
        })
        # Edge: deployer → receiver
        if deployer_node_ref:
            flowchart_edges.append({
                "from_node_ref": deployer_node_ref,
                "to_node_ref": nref,
                "amount": r.get("received_from_deployer"),
                "evt_ref": r.get("evt_ref"),
                "kind": "pre_launch_outflow",
            })

    # Top dumper destinations — fan-out
    for dumper_addr, dests in dumper_destinations.items():
        from_ref = receiver_node_refs.get(_norm_addr(dumper_addr))
        if not from_ref:
            continue
        for d in dests[:3]:  # top 3 destinations per dumper
            to_addr = d.get("to")
            if not to_addr:
                continue
            # Dedup by FULL lowercase address (not addr_short prefix —
            # see audit fix note above).
            to_key = _norm_addr(to_addr)
            to_ref = addr_to_node_ref.get(to_key)
            if to_ref is None:
                to_ref = eg.add_node(
                    type="retail_fanout", addr=to_addr,
                    label_hint=t("sec1.lineage.label_hint_fanout", dumper_short=dumper_addr[:10]),
                )
                addr_to_node_ref[to_key] = to_ref
                flowchart_nodes.append({
                    "node_ref": to_ref,
                    "role": "DUMPER_DEST",
                    "addr_short": to_addr[:10] + "…",
                })
            flowchart_edges.append({
                "from_node_ref": from_ref,
                "to_node_ref": to_ref,
                "amount": d.get("total_amt"),
                "evt_ref": d.get("evt_ref"),
                "kind": "dumper_distribution",
            })

    # beta.3: surface every OPERATOR_RELAY member address (not just the top)
    # so monitoring_wallets in pipeline can list all high-concentration
    # dumper-destination wallets, not lose the 2nd/3rd biggest.
    operator_relay_members = [
        {"addr": m["addr"], "balance": m["balance"], "pct_of_total": m.get("pct_of_total")}
        for m in by_role.get("OPERATOR_RELAY", [])
    ]

    # beta.6 (audit ZEST): sync flowchart_nodes role — addresses that
    # got upgraded to OPERATOR_RELAY in role_rows should also show
    # OPERATOR_RELAY (not DUMPER_DEST) in the flowchart.
    #
    # beta.7 (cross-LLM audit): also MATERIALIZE OPERATOR_RELAY
    # members that aren't in flowchart_nodes yet. Pre-beta.7 only walked
    # existing DUMPER_DEST nodes to relabel; an OPERATOR_RELAY address
    # that didn't make it into top-3-dumper-destinations would be in
    # role_rows + monitoring but absent from flowchart — cross-section
    # inconsistency the audit caught.
    relay_addrs = {_norm_addr(m["addr"]) for m in operator_relay_members}

    # First pass: relabel existing nodes that match.
    relabeled_addrs: set[str] = set()
    for node in flowchart_nodes:
        node_ref = node.get("node_ref")
        eg_entry = eg.lookup(node_ref) if node_ref else None
        if not eg_entry:
            continue
        node_addr = _norm_addr(eg_entry.get("addr") or "")
        if node_addr in relay_addrs:
            if node.get("role") == "DUMPER_DEST":
                node["role"] = "OPERATOR_RELAY"
            relabeled_addrs.add(node_addr)

    # Second pass: any OPERATOR_RELAY member NOT yet in flowchart →
    # materialize as a new node with provenance edge from the deployer
    # (best-known anchor) so the graph is complete.
    missing = [a for a in relay_addrs if a not in relabeled_addrs]
    if missing and deployer_node_ref:
        for addr in missing:
            # Look up member to get balance/pct for label_hint
            member = next(
                (m for m in operator_relay_members if _norm_addr(m["addr"]) == addr),
                None,
            )
            pct = (member.get("pct_of_total") or 0) if member else 0
            new_ref = eg.add_node(
                type="dumper",
                addr=addr,
                balance=(member.get("balance") if member else None),
                label_hint=t("sec1.lineage.label_hint_operator_relay", pct=pct),
            )
            addr_to_node_ref[addr] = new_ref
            flowchart_nodes.append({
                "node_ref": new_ref,
                "role": "OPERATOR_RELAY",
                "addr_short": addr[:10] + "…",
            })
            # Edge: link via deployer-anchor; exact intermediate path may
            # be multi-hop so we mark `kind=indirect_to_operator_relay`
            # to distinguish from direct dumper_distribution.
            flowchart_edges.append({
                "from_node_ref": deployer_node_ref,
                "to_node_ref": new_ref,
                "amount": (member.get("balance") if member else None),
                "evt_ref": None,
                "kind": "indirect_to_operator_relay",
            })

    return {
        "role_rows": role_rows,
        "progress_bars": progress_bars,
        "flowchart_nodes": flowchart_nodes,
        "flowchart_edges": flowchart_edges,
        "operator_relay_members": operator_relay_members,
        "n_top_holders_classified": len(top_holders),
        "n_other": sum(1 for r in role_rows if r["role"] == "OTHER"),
    }
