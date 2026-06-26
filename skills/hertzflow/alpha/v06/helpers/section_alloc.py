#!/usr/bin/env python3
"""section_alloc.py — Project allocation breakdown (aggregates Rule 11 outputs).

This section is mostly aggregation of Rule 11 backward trace data + Alpha
API metadata. No additional surf queries needed in v0.6 phase B.3.

v0.6 (2026-05-24, Phase B.3)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from i18n import t   # v0.6.2 i18n


def run(
    *,
    total_supply: int | None,
    circulating_supply: int | None,
    rule11: dict,
    current_price_usd: float | None = None,
    burn_balance: float | None = None,
    burn_pct_of_supply: float | None = None,
) -> dict[str, Any]:
    """Section ALLOC entrypoint.

    Args:
        total_supply / circulating_supply: from Section A
        rule11: result of rule_11_backward_trace.run() — uses pre_launch_receivers
        current_price_usd: from section_liq
        burn_balance / burn_pct_of_supply: v0.7.20.2 — tokens permanently
            sitting at 0xdead / 0x0 burn addresses, surfaced as a dedicated
            ALLOC row instead of being silently dropped (or, worse, leaking
            into cross_sym whales as the PLAY case). Pass from
            section_f_holders' new `burn_balance` / `burn_pct_of_supply`
            fields. None / 0 → no burn row emitted.
    """
    receivers = rule11.get("pre_launch_receivers", []) or []
    # v0.7.10.3: split quiet (dumped_pct == 0) into project-side lockup
    # (vesting / multisig / treasury / DEX-infra / CEX-custody — Arkham
    # confirmed, NOT insider) vs. genuine quiet insider candidates.
    # v0.7.13 (issue #1 Bug 1): dumped_pct can be None for recursive sub-dumpers
    # whose balance backfill returned no value (e.g. surf 429 exhausted retries).
    # None means "unknown", NOT zero — guard every comparison so an unknown is
    # excluded from each bucket rather than crashing `0 < None < 95`. Its balance
    # still counts in receivers_cumulative_balance below.
    quiet_all = [r for r in receivers if r.get("dumped_pct") == 0]
    lockup_quiet = [r for r in quiet_all if r.get("is_protocol_lockup")]
    quiet = [r for r in quiet_all if not r.get("is_protocol_lockup")]
    partial = [r for r in receivers
               if r.get("dumped_pct") is not None and 0 < r["dumped_pct"] < 95]
    full = [r for r in receivers
            if r.get("dumped_pct") is not None and r["dumped_pct"] >= 95]

    n_receivers = len(receivers)
    deployer = rule11.get("deployer", "—")

    # Cumulative balances. `or 0`: an unconfirmed-backfill sub-dumper may carry
    # current_balance=None — count unknown as 0 in these stock sums rather than
    # crashing `float + None` (v0.7.13 issue #1 Bug 1).
    quiet_balance = sum((r.get("current_balance") or 0) for r in quiet)
    lockup_balance = sum((r.get("current_balance") or 0) for r in lockup_quiet)
    partial_balance = sum((r.get("current_balance") or 0) for r in partial)
    # NOTE: do NOT sum `received_from_deployer` here — it is a FLOW that
    # double-counts on deployer round-trips / relays (R2: 4 wallets each logged
    # ~total supply → sum > total). Use balance (stock) sums only.
    receivers_cumulative_balance = sum((r.get("current_balance") or 0) for r in receivers)

    def _pct_of_total(x: float) -> str:
        if not total_supply or total_supply == 0:
            return "—"
        return f"{x/total_supply*100:.2f}%"

    def _usd(tokens: float) -> str:
        if not current_price_usd:
            return "—"
        return f"${tokens*current_price_usd:,.0f}"

    # v0.6.2: all labels via i18n. Values mix data + literal token suffix.
    # When total_supply is None, _pct_of_total returns "—", which we feed as
    # a string into format() — yaml templates use {pct} as plain str.
    def _pct(x):
        if not total_supply:
            return t("common.none_dash")
        return f"{x/total_supply*100:.2f}"

    def _usd_str(tokens):
        if not current_price_usd:
            return t("common.none_dash")
        return f"{int(tokens*current_price_usd):,}"

    rows = [
        {
            "item": t("section.alloc.label_alpha_quota"),
            "value": t("section.alloc.value_not_disclosed"),
            "source": t("section.alloc.source_alpha_no_field"),
        },
        {
            "item": (
                t("section.alloc.label_deployer_balance", addr=f"{deployer[:10]}…")
                if deployer else t("section.alloc.label_deployer_balance", addr="—")
            ),
            "value": (
                t("section.alloc.value_deployer_empty") if (deployer and n_receivers > 0)
                else t("common.unknown")
            ),
            "source": t("section.alloc.source_deployer_trace"),
        },
        {
            "item": t("section.alloc.label_insider_total", n=n_receivers),
            "value": t(
                "section.alloc.value_insider_total",
                tokens=int(receivers_cumulative_balance),
                pct=_pct(receivers_cumulative_balance),
            ),
            "source": t("section.alloc.source_insider_total"),
        },
        {
            "item": t("section.alloc.label_quiet_total", n=len(quiet)),
            "value": t(
                "section.alloc.value_quiet_total",
                tokens=int(quiet_balance),
                pct=_pct(quiet_balance),
                usd=_usd_str(quiet_balance),
            ),
            "source": t("section.alloc.source_quiet_total"),
        },
        {
            "item": t("section.alloc.label_full_dumper", n=len(full)),
            "value": t("section.alloc.value_full_dumper"),
            "source": t("section.alloc.source_full_dumper"),
        },
    ]

    # v0.7.10.3: surface project-side / infrastructure lockup balance as a
    # separate row when any vesting/multisig/treasury/DEX-infra/CEX-custody
    # wallet was detected. Without this, the "潜伏钱包" row silently absorbed
    # them and the report read like e.g. 79% of supply was insider-held.
    if lockup_quiet:
        breakdown = ", ".join(
            f"{r.get('arkham_label') or '—'} ({r.get('addr','')[:10]}…)"
            for r in sorted(lockup_quiet, key=lambda x: x.get("current_balance", 0), reverse=True)[:5]
        )
        usd_part = f" / ${_usd_str(lockup_balance)}" if current_price_usd else ""
        rows.append({
            "item": t("sec1.alloc.label_lockup", n=len(lockup_quiet)),
            "value": t(
                "sec1.alloc.value_lockup",
                tokens=int(lockup_balance),
                pct=_pct(lockup_balance),
                usd_part=usd_part,
            ),
            "source": t("sec1.alloc.source_lockup", breakdown=breakdown),
        })

    # v0.7.20.2: 已销毁 (burn) row. 0xdead / 0x0 持仓代表永久退出流通的供应,
    # 不是任何持有者. 来源 section_f_holders.burn_balance.
    if burn_balance and burn_balance > 0:
        burn_pct_str = (
            f"{burn_pct_of_supply:.2f}" if burn_pct_of_supply is not None else _pct(burn_balance)
        )
        rows.append({
            "item": t("section.alloc.label_burn"),
            "value": t(
                "section.alloc.value_burn",
                tokens=int(burn_balance),
                pct=burn_pct_str,
                usd=_usd_str(burn_balance),
            ),
            "source": t("section.alloc.source_burn"),
        })

    return {
        "n_receivers": n_receivers,
        "n_quiet": len(quiet),
        "n_quiet_lockup": len(lockup_quiet),
        "n_partial": len(partial),
        "n_full": len(full),
        "quiet_balance_tokens": quiet_balance,
        "quiet_balance_pct_total": (
            quiet_balance / total_supply * 100 if total_supply else None
        ),
        "lockup_balance_tokens": lockup_balance,
        "lockup_balance_pct_total": (
            lockup_balance / total_supply * 100 if total_supply else None
        ),
        "burn_balance_tokens": burn_balance or 0,
        "burn_balance_pct_total": burn_pct_of_supply,
        "rows": rows,
    }
