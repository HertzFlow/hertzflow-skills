#!/usr/bin/env python3
"""hidden_operator_enricher.py — append heuristically-flagged
"hidden operator" wallets to the monitoring_wallets list.

# Why this exists (v0.8.2)

The 5-bucket disjoint accounting (operator-controlled vs non-operator
pressure) systematically under-counts operator-side balance when
Arkham labels are sparse. Velvet / COLLECT / JCT review surfaced two
patterns:

  1. **Suspected operator reserve** — top-100 holder ≥ 10% circulating
     with no Arkham label. Examples:
       - COLLECT `0xf27d6fc930db`  441.9% 流通 no label (mint reserve)
       - COLLECT `0x692253941d1f`  16.8% 流通 no label
       - JCT     `0xe0b5ed319707`  36.1% 流通 (= one of the mint
                                   authorities — its current balance is
                                   un-distributed supply)

  2. **Fake mining cluster members** — destinations of a mint authority
     classified as `is_fake_mining_cluster` by fake_mining_detector.
     These addresses received 0.5-3% supply each in 1-3 large
     transactions — i.e. they look like operator-controlled allocation
     wallets, not retail miners. Adding them to the watch list lets the
     user track them when they start fanning-out / depositing to CEX /
     selling on DEX.

This enricher is FORENSIC — it does not alert or push. It only
appends rows to `skeleton.monitoring_wallets[]` so the downstream
`annotate_monitoring_wallets` + `monitoring_export` pipeline carries
them into `monitoring_paste.json`. The user imports the paste file
into Binance / OKX wallet tracker and reads on-chain activity
manually.

# Inputs (skeleton fields read)

- `funding_attribution.mint_authority_dumps.per_addr` — for
  fake-mining cluster destinations.
- `meta.total_supply` and `meta.circulating_supply` — for % calc.
- `monitoring_wallets[].addr_full` — for de-duplication against
  already-known wallets.

NOTE: This module does NOT call surf. The "suspected_operator_reserve"
heuristic needs a `top_holders_label_classified` field on the skeleton
that section_a / dump_tracker would need to emit. That wiring is left
for v0.8.3 — see the v0.8.2 PR description. For now this enricher
handles fake-mining cluster members only (the highest-confidence
signal, derived from already-collected mint_authority_dumps data).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from fake_mining_detector import classify_token_mining_mode
from i18n import t   # v0.6.2 i18n

# Threshold for suspected_operator_reserve heuristic.
# v0.8.4.5: 10% → 3% (Velvet review caught miss — top unclassified at
# 8% / 7.7% / 5.3% all skipped at 10% threshold. Lowering to 3% catches
# medium-sized op aliases. Trade-off: more false positives among 3-7%
# whales who might be legit large retail / VC OTC buyers. Mitigation:
# emit `_arkham_classification: UNLABELED` + monitoring_paste lets the
# user vet each one. The forensic value is in capturing the pattern,
# not making zero-FP claims.
SUSPECTED_RESERVE_MIN_PCT_CIRCULATING = 3.0


def _norm_addr(a: Any) -> str:
    if not a or not isinstance(a, str):
        return ""
    return a.lower().strip()


def enrich_monitoring_with_hidden_operators(skel: dict) -> dict:
    """Append heuristically-flagged hidden operator wallets to
    `skel["monitoring_wallets"]` if not already present.

    Returns the same skeleton (mutated in place).
    """
    meta = skel.get("meta") or {}
    total_supply = float(meta.get("total_supply") or 0) or None

    wallets = skel.get("monitoring_wallets") or []
    seen: set[str] = {
        _norm_addr(w.get("addr_full") or w.get("address"))
        for w in wallets
    }
    seen.discard("")

    n_seed = max(
        (int(w.get("n") or 0) for w in wallets), default=0
    )
    next_n = n_seed + 1

    # ===========================================================
    # Pattern 2: Fake mining cluster members
    # (derived from already-collected mint_authority_dumps data —
    # no extra surf calls needed)
    # ===========================================================
    fa = skel.get("funding_attribution") or {}
    mad = fa.get("mint_authority_dumps") or {}
    mining_mode = classify_token_mining_mode(mad, total_supply=total_supply)

    if mining_mode["is_fake_mining_distribution"]:
        per_addr = (mad.get("per_addr") or {})
        for auth_addr, auth_class in (
            mining_mode["per_authority_classifications"].items()
        ):
            if not auth_class.get("is_fake_mining_cluster"):
                continue
            data = per_addr.get(auth_addr) or {}
            for dest in (data.get("top_destinations") or []):
                d_addr = _norm_addr(dest.get("dest"))
                if not d_addr or d_addr in seen:
                    continue
                amt = float(dest.get("amt") or 0)
                pct_supply = (amt / total_supply * 100) if total_supply else 0
                # v0.8.2.2 audit HIGH #2 fix: do NOT write
                # historical received amt into balance_tokens. The ranker
                # interprets balance_tokens as current balance and would
                # promote already-emptied recipients to CRITICAL based on
                # historical allocation size. Use None + dedicated
                # _allocation_received_tokens field. monitoring_export's
                # balance-filter will see None and fall through to the
                # role-based keep rule (fake_mining_cluster_member has
                # Tier 1 score so it's exported regardless of balance).
                wallets.append({
                    "n": next_n,
                    "addr_short": d_addr[:10],
                    "addr_full": d_addr,
                    "role": t("sec2.hidden_op_role_fake_mining_cluster"),
                    "status_emoji": "🟡",
                    "balance_tokens": None,
                    "recent_activity_72h": False,
                    "monitor_role_enum": "fake_mining_cluster_member",
                    "_is_enricher_assigned": True,
                    "_received_from_mint_authority": auth_addr,
                    "_allocation_received_tokens": amt,
                    "_allocation_received_pct_supply": pct_supply,
                    "_arkham_label": dest.get("arkham_label"),
                    "_arkham_classification": dest.get(
                        "arkham_classification"
                    ) or "UNLABELED",
                    "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
                })
                seen.add(d_addr)
                next_n += 1

    # ===========================================================
    # Pattern 1: Suspected operator reserve (≥ 10% 流通 + no label)
    # v0.8.4: Iterates meta.chain_lp_realtime.<chain>.top_holders_classified
    # which section_a_scope.py now emits (one classification pass per
    # surf chain probe, no extra cost). Pulls top unclassified holders
    # ≥ 10% circulating + appends to monitoring as
    # `suspected_operator_reserve`.
    # ===========================================================
    circulating = float(meta.get("circulating_supply") or 0) or None
    if circulating and circulating > 0:
        clp = meta.get("chain_lp_realtime") or {}
        for chain_name, chain_data in (clp or {}).items():
            if not isinstance(chain_data, dict):
                continue
            classified = chain_data.get("top_holders_classified") or {}
            if not isinstance(classified, dict) or "_error" in classified:
                continue
            unclass = classified.get("unclassified") or {}
            for h in (unclass.get("top") or []):
                addr = _norm_addr(h.get("addr"))
                if not addr or addr in seen:
                    continue
                bal = float(h.get("balance") or 0)
                if bal <= 0:
                    continue
                pct_circ = bal / circulating * 100
                if pct_circ < SUSPECTED_RESERVE_MIN_PCT_CIRCULATING:
                    continue
                wallets.append({
                    "n": next_n,
                    "addr_short": addr[:10],
                    "addr_full": addr,
                    "role": t("sec2.hidden_op_role_suspected_reserve"),
                    "status_emoji": "🟡",
                    # Heuristic-flagged: balance is current (surf
                    # token-holders returns current balance). Setting
                    # balance_tokens so ranker picks up the size.
                    "balance_tokens": bal,
                    "recent_activity_72h": False,
                    "monitor_role_enum": "suspected_operator_reserve",
                    "_is_enricher_assigned": True,
                    "_suspected_chain": chain_name,
                    "_pct_circulating_at_detection": pct_circ,
                    "_arkham_label": h.get("label_text") or None,
                    "_arkham_classification": "UNLABELED",
                    "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
                })
                seen.add(addr)
                next_n += 1

    skel["monitoring_wallets"] = wallets
    return skel


__all__ = [
    "enrich_monitoring_with_hidden_operators",
    "SUSPECTED_RESERVE_MIN_PCT_CIRCULATING",
]
