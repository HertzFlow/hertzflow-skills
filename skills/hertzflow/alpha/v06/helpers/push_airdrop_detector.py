#!/usr/bin/env python3
"""push_airdrop_detector.py — identify retail "push" airdrop recipients
in the pre-launch deployer-outflow window so dump_tracker does not
mis-classify them as insiders.

# Why this exists (v0.8.1)

`pre_launch_receivers` is everyone who received tokens directly from the
deployer between `trace_floor` and `alpha_listing_date`. That set is the
basis for the "insider" universe used to compute `confirmed_total_tokens`
(a)+(b) — the "确认毛卖出" metric.

Failure case: if the project did a `disperse`-style push airdrop to N
retail wallets (`deployer → batch_transfer → 5,000 EOAs`) before listing,
every one of those EOAs lands in `pre_launch_receivers` and their post-
listing sells inflate the "insider 真实变现" number. Pull / Merkle-claim
airdrops do NOT trigger this — retail wallets receive from the claim
contract, not the deployer, so they never enter `pre_launch_receivers`.

# Heuristic

A pre-launch deployer outflow tx is classified as a push-airdrop
distribution iff:

  COUNT(DISTINCT to_addr) within one tx_hash  >=  PUSH_MIN_RECIPIENTS

Default threshold = 50. Rationale:
  - VC / team allocation rounds use Gnosis Safe multi-call or hand-
    submitted batches, typically <= 20 recipients per tx (often 1).
  - Retail airdrop disperse libraries (disperse.app, gas-optimized
    multi-send) emit transactions with 50-1000 recipients.
  - 50 is conservative: it accepts a few false negatives (a VC round
    with 50+ allocations in one tx is unusual but possible) in
    exchange for near-zero false positives on the retail side.

# Output

Every recipient address appearing in any tx that crosses the threshold
is labeled `is_push_airdrop_recipient`. Those addresses are excluded
from `insider_addrs` (so their CEX deposits / DEX swaps no longer
inflate the (a)+(b) confirmed-sellout floor).

Conservative semantics:
  - We exclude from the INSIDER set, not from the holdings tree. The
    tokens are still tracked for supply accounting; we just no longer
    attribute their post-launch sells to insider exit.
  - This is one-way: a wallet flagged via this detector stays flagged
    even if it also received a separate "VC-shaped" allocation. The
    rare false positive of misclassifying a hybrid wallet is preferred
    over the systemic false positive of treating every airdrop recipient
    as an insider.

Cost: 1 surf transfers query per CA, time-bounded to the rule_11 window
(deployer outflows are sparse so the GROUP BY is cheap).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from chain_router import transfers_table  # v0.7.20
from chain_router import decimals_factor_str  # v0.9.7

_HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Threshold rationale documented in module docstring. Exposed as constant
# so calibration scripts can sweep it if a token-class-specific override
# is ever needed (e.g. Solana SPL programs that batch differently).
PUSH_MIN_RECIPIENTS = 50

# v0.8.1 audit MED fix: shape guard. A push airdrop's per-recipient
# amount is small (each retail wallet gets a tiny fraction of supply). A
# large delegated VC/MM allocation batch that happens to have 50+ unique
# recipients (rare but possible) would otherwise be fully excluded from
# insiders by the simple count gate. We additionally require the mean
# per-recipient amount in the flagged tx to be at most this fraction of
# supply. Default 0.1% supply: typical retail airdrop = $1-100/wallet
# (well under 0.01% supply); typical VC allocation = 1-5% supply / wallet
# (well over 0.1%). 0.1% sits comfortably in the gap.
PUSH_MAX_MEAN_PER_RECIPIENT_PCT_SUPPLY = 0.1


def _valid_ca(ca: str | None) -> str | None:
    if not ca or not isinstance(ca, str):
        return None
    if not _HEX_ADDR_RE.match(ca):
        return None
    return ca.lower()


def _valid_addr(a: str | None) -> str | None:
    if not a or not isinstance(a, str):
        return None
    a = a.lower()
    if not _HEX_ADDR_RE.match(a):
        return None
    return a


def fetch_push_airdrop_recipients(
    ca: str,
    deployer: str,
    trace_floor: str,
    listing_date: str,
    *,
    min_recipients: int = PUSH_MIN_RECIPIENTS,
    total_supply: float | None = None,
    max_mean_per_recipient_pct_supply: float = PUSH_MAX_MEAN_PER_RECIPIENT_PCT_SUPPLY,
) -> dict[str, Any]:
    """Identify push-airdrop batch transfers in the pre-launch deployer
    outflow window.

    Args:
      ca: token contract address (lower-cased internally).
      deployer: rule_11-derived deployer address.
      trace_floor: 'YYYY-MM-DD' lower bound for the pre-launch trace.
      listing_date: 'YYYY-MM-DD' Alpha-listing date (inclusive upper).
      min_recipients: distinct-to-addr threshold per tx_hash. Default 50.

    Returns:
      {
        "airdrop_tx_hashes": [str],          # tx hashes flagged
        "airdrop_recipients": [str],         # lowercase 0x recipients
        "n_tx": int,
        "n_recipients": int,
        "tokens_airdropped_total": float,    # sum across all flagged tx
        "mean_recipients_per_tx": float,
        "max_recipients_per_tx": int,
      }
    On surf error returns {"__ERR": str, "airdrop_recipients": []} so the
    caller can fail-loud without breaking downstream insider_addrs logic.
    On no-pattern returns the dict with empty arrays — distinguishable
    from error by absence of __ERR.
    """
    ca = _valid_ca(ca)
    deployer = _valid_addr(deployer)
    if not ca or not deployer:
        return {"airdrop_recipients": [], "airdrop_tx_hashes": [],
                "n_tx": 0, "n_recipients": 0,
                "tokens_airdropped_total": 0.0,
                "mean_recipients_per_tx": 0.0,
                "max_recipients_per_tx": 0}

    transfers = transfers_table()
    # v0.8.1 audit MED #2 + LOW fix: amount-shape gate. Push
    # airdrops have small per-recipient amounts (each retail wallet
    # gets <0.1% supply typically). Add a `HAVING avg(amt) <= cap`
    # filter in the inner CTE so a 50-receiver VC allocation tx (where
    # each VC gets 0.5-5% supply) does NOT flag as push airdrop.
    # audit LOW #1 also fixed: explicit GROUP BY (recipient, tx)
    # in the outer query so multi-log txs collapse to one row per
    # (recipient, tx, amount).
    mean_cap_raw_supply = None
    if total_supply and total_supply > 0:
        mean_cap_raw_supply = (total_supply * max_mean_per_recipient_pct_supply / 100.0)
    cap_clause = (
        f' AND avg(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) <= {mean_cap_raw_supply}'
        if mean_cap_raw_supply is not None else ''
    )
    sql = (
        f'WITH flagged_tx AS ('
        f' SELECT tx_hash,'
        f' count(DISTINCT "to") AS n_to,'
        f' avg(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS mean_amt'
        f' FROM {transfers}'
        f" WHERE contract_address = '{ca}'"
        f' AND "from" = \'{deployer}\''
        f" AND block_date BETWEEN '{trace_floor}' AND '{listing_date}'"
        f' GROUP BY tx_hash'
        f' HAVING n_to >= {min_recipients}'
        f'{cap_clause}'
        f') '
        f'SELECT "to" AS recipient, tx_hash,'
        f' sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amount'
        f' FROM {transfers}'
        f" WHERE contract_address = '{ca}'"
        f' AND "from" = \'{deployer}\''
        f" AND block_date BETWEEN '{trace_floor}' AND '{listing_date}'"
        f' AND tx_hash IN (SELECT tx_hash FROM flagged_tx)'
        f' GROUP BY recipient, tx_hash'
    )
    try:
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            # v0.8.5.2: 50000 撞 surf 10K cap → INVALID_REQUEST → 整 SQL fail
            # → buckets_complete=false 误触发 "dump_tracker 不可信" banner.
            # adversarial review CLO bug report 2026-06-12. push-airdrop pattern 通常
            # < 1K recipients per tx batch, 10K 足够.
            stdin=json.dumps({"sql": sql, "max_rows": 10000}),
            base_timeout=60,
            max_attempts=4,
        )
    except Exception as e:
        doc, err = None, f"exception: {str(e)[:120]}"

    if not doc:
        return {"__ERR": err or "surf returned no doc",
                "airdrop_recipients": [], "airdrop_tx_hashes": [],
                "n_tx": 0, "n_recipients": 0,
                "tokens_airdropped_total": 0.0,
                "mean_recipients_per_tx": 0.0,
                "max_recipients_per_tx": 0}

    rows = doc.get("data") or []
    if not rows:
        return {"airdrop_recipients": [], "airdrop_tx_hashes": [],
                "n_tx": 0, "n_recipients": 0,
                "tokens_airdropped_total": 0.0,
                "mean_recipients_per_tx": 0.0,
                "max_recipients_per_tx": 0}

    recipients: set[str] = set()
    tx_hashes: set[str] = set()
    tx_recipient_counts: dict[str, int] = {}
    total_amt = 0.0
    for r in rows:
        recipient = r.get("recipient") or ""
        if isinstance(recipient, str):
            recipient = recipient.lower()
        if not _HEX_ADDR_RE.match(recipient or ""):
            continue
        tx = r.get("tx_hash") or ""
        if not isinstance(tx, str) or not tx:
            continue
        amt = r.get("amount")
        try:
            amt_f = float(amt) if amt is not None else 0.0
        except (TypeError, ValueError):
            amt_f = 0.0
        recipients.add(recipient)
        tx_hashes.add(tx)
        tx_recipient_counts[tx] = tx_recipient_counts.get(tx, 0) + 1
        total_amt += amt_f

    if not recipients:
        return {"airdrop_recipients": [], "airdrop_tx_hashes": [],
                "n_tx": 0, "n_recipients": 0,
                "tokens_airdropped_total": 0.0,
                "mean_recipients_per_tx": 0.0,
                "max_recipients_per_tx": 0}

    counts = list(tx_recipient_counts.values())
    return {
        "airdrop_tx_hashes": sorted(tx_hashes),
        "airdrop_recipients": sorted(recipients),
        "n_tx": len(tx_hashes),
        "n_recipients": len(recipients),
        "tokens_airdropped_total": float(total_amt),
        "mean_recipients_per_tx": (sum(counts) / len(counts)) if counts else 0.0,
        "max_recipients_per_tx": max(counts) if counts else 0,
        "_threshold_used": min_recipients,
    }


__all__ = ["fetch_push_airdrop_recipients", "PUSH_MIN_RECIPIENTS"]
