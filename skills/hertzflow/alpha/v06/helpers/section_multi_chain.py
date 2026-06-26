#!/usr/bin/env python3
"""section_multi_chain.py — multi-chain coverage check (v0.6 phase B.3 minimal).

For most Alpha tokens, supply_chain == trading_venue_chain == BSC. Phase B.3
minimal version assumes single-chain BSC + RPC totalSupply sanity check.

Phase C+ (or v0.7) may add CoinGecko platforms lookup for true cross-chain
detection (ETH wrapper / Base wrapper / Solana primary).

v0.6 (2026-05-24, Phase B.3)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from i18n import t   # v0.6.2 i18n


# CoinGecko platform ids (+ defensive aliases) that mean "BSC is the real main
# chain". The CANONICAL value emitted by section_a_scope.derive_primary_chain
# is "binance-smart-chain" (CoinGecko platforms key, see section_a_scope.py:670
# `return "binance-smart-chain", "lp_zero_fallback_bsc"`). The rest are
# defensive entries for any future variant (etherscan-style "bnb-smart-chain",
# chain-id "56", short forms) — if upstream ever emits one of these the
# verdict still resolves correctly instead of silently downgrading to "mirror"
# / partial coverage (adversarial review LOW #2). Keep this set in lockstep with the
# canonical emitter; if a new platform id appears upstream, add it here.
_BSC_PRIMARY_ALIASES = {
    "binance-smart-chain",   # canonical (CoinGecko platforms)
    "bnb-smart-chain",       # etherscan-style variant
    "bsc", "bnb", "binance",
    "56",                    # chain id
}


def run(
    *,
    chain_label: str,
    total_supply: int | None,
    primary_chain: str | None = None,
    holder_snapshot_mode: bool = False,
) -> dict[str, Any]:
    """Section MULTI-CHAIN entrypoint. v0.6.2: all labels via i18n.

    v0.7.14 (issue #1): align with the banner's meta.primary_chain. `chain_label`
    is the VENUE chain (always "BSC" for a BSC-listed token, even a cross-chain
    mirror); `primary_chain` (CoinGecko platform id from scope) is the real main
    battlefield. The old `chain_label == "BSC"` test always read True and
    reported "单链 / 完整覆盖", contradicting a banner that said the main chain
    is elsewhere (ZEST → stacks). Decide on `primary_chain` when it is known.
    """
    if primary_chain:
        is_bsc_primary = primary_chain.strip().lower() in _BSC_PRIMARY_ALIASES
    else:
        # No cross-chain signal available → fall back to the venue chain.
        is_bsc_primary = chain_label == "BSC"

    chain_name = t(f"section.multi_chain.chain_name_{chain_label}")
    if chain_name.startswith("[MISSING:"):
        chain_name = chain_label   # fall back to enum

    main_chain_value = (
        t("section.multi_chain.value_main_chain", chain=chain_label, chain_name=chain_name)
        if is_bsc_primary
        else t("section.multi_chain.value_main_chain_mirror",
               primary=primary_chain, venue=chain_label)
    )
    cross_chain_value = (
        t("section.multi_chain.value_cross_chain_single") if is_bsc_primary
        else t("section.multi_chain.value_cross_chain_mirror",
               primary=primary_chain, venue=chain_label)
    )
    # v0.7.20.1: when primary_chain != BSC, supply / trading rows must say
    # the primary chain, not the BSC venue label. Pre-v0.7.20.1 we hard-
    # wired chain_label here, so the supply row said "BSC, totalSupply 5B"
    # even for a Base PLAY token whose supply lives on Base.
    supply_chain_for_row = chain_label if is_bsc_primary else (primary_chain or chain_label)
    trading_chain_for_row = chain_label if is_bsc_primary else (primary_chain or chain_label)

    # v0.7.21.8: holder-snapshot chains (Solana) have no BSC mirror and no
    # `agent.{chain}_*` SQL table. Override the "BSC 镜像端 → 主链 X"
    # framing with a clean "single-chain Solana, SQL coverage unavailable"
    # description so the multi-chain section stops claiming forensic SQL
    # was routed to the primary chain when it was actually skipped.
    if holder_snapshot_mode:
        main_chain_value = t(
            "section.multi_chain.value_main_chain_holder_snapshot",
            primary=primary_chain or chain_label,
            venue=chain_label,
        )
        cross_chain_value = t(
            "section.multi_chain.value_cross_chain_holder_snapshot",
            primary=primary_chain or chain_label,
        )
        coverage_value = t(
            "section.multi_chain.value_coverage_holder_snapshot",
            primary=primary_chain or chain_label,
        )
        gate_note_value = t(
            "section.multi_chain.gate_note_holder_snapshot",
            primary=primary_chain or chain_label,
        )
    else:
        coverage_value = (
            t("section.multi_chain.value_full_coverage") if is_bsc_primary
            else t("section.multi_chain.value_coverage_partial", primary=primary_chain)
        )
        gate_note_value = (
            t("section.multi_chain.gate_note_ok") if is_bsc_primary
            else t("section.multi_chain.gate_note_non_bsc", primary=primary_chain)
        )

    rows = [
        {
            "item": t("section.multi_chain.label_main_chain"),
            "value": main_chain_value,
        },
        {
            "item": t("section.multi_chain.label_supply_chain"),
            "value": (
                t("section.multi_chain.value_supply_chain_with_total",
                  chain=supply_chain_for_row, total=total_supply)
                if total_supply
                else t("section.multi_chain.value_supply_chain", chain=supply_chain_for_row)
            ),
        },
        {
            "item": t("section.multi_chain.label_trading_chain"),
            "value": t("section.multi_chain.value_trading_chain", chain=trading_chain_for_row),
        },
        {
            "item": t("section.multi_chain.label_cross_chain"),
            "value": cross_chain_value,
        },
        {
            "item": t("section.multi_chain.label_coverage"),
            "value": coverage_value,
        },
    ]

    return {
        # v0.7.20.1: a cross-chain mirror IS now single-chain forensic
        # coverage on the primary chain (the v0.7.20 SQL router fetches
        # m6 / transfers / wash / holdings from the primary chain partition).
        # The flag stays True for both: it means "pipeline forensic is
        # single-chain coverage" — which is correct in both cases.
        # v0.7.21.8: still True on holder-snapshot chains — there literally is
        # only one chain involved (no BSC mirror); coverage is "single chain,
        # snapshot only" rather than "single chain, full SQL".
        "single_chain": True,
        "chain_label": chain_label,
        "primary_chain": primary_chain,
        "is_bsc_primary": is_bsc_primary,
        "holder_snapshot_mode": holder_snapshot_mode,
        "rows": rows,
        "gate_note": gate_note_value,
    }
