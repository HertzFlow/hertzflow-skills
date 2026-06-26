#!/usr/bin/env python3
"""fake_mining_detector.py — distinguish real mining tokens from
"fake mining" operator clusters that use mint-contract distribution as
camouflage for wholesale token allocation.

# Why this exists (v0.8.2)

JCT (Janction) review surfaced the case: a token can present itself as
mining-distributed (mint_authorities exist, mint contract has large
outflows to many addresses) but actually be an operator-cluster
distribution — mint contract → ~10-50 operator-controlled EOAs → DEX
sell or warehouse. The generic "mining token" disjoint accounting then
inflates the "non-operator pressure" bucket by including the cluster
EOAs as if they were retail miners.

Real mining (e.g. Bitcoin pool distributions, established staking
rewards) has a power-law distribution: thousands of recipient
addresses, small per-recipient amounts (< 0.01% supply per reward),
many transactions per recipient, identifiable mining pool Arkham labels
on a meaningful fraction of them.

Fake mining operator clusters have the opposite shape: < 50
recipients, 0.5-3% supply per recipient, 1-3 transactions per
recipient, all UNLABELED.

# Heuristic (5 signals, ≥2 required to flag fake)

| # | Signal | Real mining | Fake mining (operator cluster) |
|---|---|---|---|
| 1 | distinct destinations per mint authority | ≥ 500 | ≤ 50 |
| 2 | mean tokens received per destination as % total supply | < 0.01% | ≥ 0.5% |
| 3 | mean tx count per destination | ≥ 100 (continuous small rewards) | ≤ 10 (large lump sums) |
| 4 | fraction of UNLABELED destinations | ≤ 50% (mining pools labeled) | ≥ 80% |
| 5 | top-10 destination share of total minted | < 20% (power-law tail dominates) | ≥ 80% (oligarchy concentration) |

Conservative gate: ≥ 2 signals must trip per mint authority. Across
multiple authorities, the verdict is the union — if any authority
trips, the whole token is flagged.

# Effect on disjoint bucket accounting

When `is_fake_mining_distribution=True`:
  - mint contract reserve (current balance) → moved to operator-ammo
    bucket (project-controlled, not retail-bound supply).
  - Already-distributed tokens (mint - reserve) → most of it landed in
    operator cluster (not real miners), should be excluded from
    "non-operator pressure" upper-bound estimate.

When `is_fake_mining_distribution=False` AND mint_authorities exist:
  - mint contract reserve → separate "mid-term supply pressure" bucket
    (not immediate sell pressure, but dilutes future pump windows).
  - Already-distributed tokens → mostly in real miner wallets, retains
    immediate sell pressure status.

# Caveats

- A token can have one fake-mining mint authority + one real-mining
  one (rare hybrid). Per-authority flag is preserved so caller can
  refine accounting per authority.
- 5 signals collapse to top-destination shape only — the detector does
  NOT chase funding-source clusters (a stricter detector would verify
  the destinations also share a common funder, but that needs an extra
  surf query per destination).
- Threshold values chosen conservative on the "real mining" side to
  avoid mis-flagging genuine mining pool distributions. Calibration
  against more tokens (real and fake) is a v0.8.3 backlog item.
"""

from __future__ import annotations

from typing import Any

# Thresholds — documented in docstring above
FAKE_MINING_MAX_DEST_COUNT = 50
FAKE_MINING_MIN_MEAN_PCT_SUPPLY = 0.5   # ≥ 0.5% supply per dest
FAKE_MINING_MAX_MEAN_TX_COUNT = 10
FAKE_MINING_MIN_UNLABELED_FRAC = 0.80
FAKE_MINING_MIN_TOP10_SHARE = 0.80
FAKE_MINING_MIN_SIGNALS = 2

# Real mining (positive identification) — used to flag genuine mining
# tokens so the disjoint accounting can apply mid-term-supply-pressure
# semantics correctly.
REAL_MINING_MIN_DEST_COUNT = 500
REAL_MINING_MAX_MEAN_PCT_SUPPLY = 0.01  # < 0.01% per dest


def classify_mining_authority(
    auth_data: dict[str, Any],
    total_supply: float | None = None,
) -> dict[str, Any]:
    """Classify a single mint authority by its outflow distribution.

    Args:
      auth_data: per-authority entry from
        `funding_attribution.mint_authority_dumps.per_addr[addr]`. We
        use:
          - `top_destinations`: [{dest, amt, n_tx, arkham_label,
                                  arkham_classification}, ...]
          - `total_minted` (optional, for top-10-share calc)
      total_supply: token total supply (for pct calc). When None,
        per-recipient % signal is skipped — fewer signals available
        but other 4 still gate.

    Returns:
      {
        "n_destinations_visible": int,
        "mean_pct_supply_per_dest": float | None,
        "mean_n_tx_per_dest": float,
        "unlabeled_fraction": float,
        "top10_share_of_total": float | None,
        "signals_tripped": [str],     # subset of 5 signal names
        "n_signals_tripped": int,
        "is_fake_mining_cluster": bool,
        "is_real_mining_pool": bool,
      }
    """
    dests = auth_data.get("top_destinations") or []
    n_visible = len(dests)
    # v0.8.2.2 audit HIGH #1 fix: prefer the SQL-emitted
    # `n_destinations_total` (true count before Python-side [:5] slice)
    # for the low-count signal. When absent (legacy skeleton), the signal
    # is marked indeterminate and not tripped.
    n_destinations_true = auth_data.get("n_destinations_total")
    total_minted = float(auth_data.get("total_minted") or 0)

    # Compute distributions
    if n_visible == 0:
        return {
            "n_destinations_visible": 0,
            "mean_pct_supply_per_dest": None,
            "mean_n_tx_per_dest": 0,
            "unlabeled_fraction": 0,
            "top10_share_of_total": None,
            "signals_tripped": [],
            "n_signals_tripped": 0,
            "is_fake_mining_cluster": False,
            "is_real_mining_pool": False,
        }

    total_amt = sum(float(d.get("amt") or 0) for d in dests)
    mean_amt = total_amt / n_visible if n_visible else 0
    mean_pct_supply = (mean_amt / total_supply * 100) if total_supply else None
    mean_n_tx = sum(int(d.get("n_tx") or 0) for d in dests) / n_visible if n_visible else 0
    unlabeled = sum(
        1 for d in dests
        if not d.get("arkham_label")
        and (d.get("arkham_classification") or "UNLABELED") == "UNLABELED"
    )
    unlabeled_frac = unlabeled / n_visible if n_visible else 0

    # Top 10 share — Phase 2 surf returns sorted descending so first 10
    # are largest. If total_minted available, use it as denominator;
    # otherwise use sum of visible (less accurate but available).
    top10_share = None
    if dests:
        top10_amt = sum(float(d.get("amt") or 0) for d in dests[:10])
        denom = total_minted if total_minted else total_amt
        if denom > 0:
            top10_share = top10_amt / denom

    # Trip signals
    signals: list[str] = []
    # v0.8.2.2 audit HIGH #1 fix: signal 1 must gate on the TRUE
    # destination count, not the [:5] sliced view. n_destinations_total
    # is emitted by funding_source_attribution v0.8.2.2+. When absent
    # (legacy skeleton), we DON'T trip — better to under-flag than to
    # systematically false-positive on real mining tokens.
    if (n_destinations_true is not None
            and n_destinations_true <= FAKE_MINING_MAX_DEST_COUNT):
        signals.append("low_destination_count")
    if mean_pct_supply is not None and mean_pct_supply >= FAKE_MINING_MIN_MEAN_PCT_SUPPLY:
        signals.append("high_mean_pct_per_dest")
    if mean_n_tx <= FAKE_MINING_MAX_MEAN_TX_COUNT:
        signals.append("low_mean_tx_per_dest")
    if unlabeled_frac >= FAKE_MINING_MIN_UNLABELED_FRAC:
        signals.append("high_unlabeled_fraction")
    if top10_share is not None and top10_share >= FAKE_MINING_MIN_TOP10_SHARE:
        signals.append("top10_oligarchy")

    is_fake = len(signals) >= FAKE_MINING_MIN_SIGNALS

    # v0.8.2.2 audit MED #1 fix: positive real-mining ID requires
    # the TRUE destination count (n_destinations_total), not the visible
    # top-5 slice. Until SQL surfaces a count > REAL_MINING_MIN_DEST_COUNT
    # we cannot positively identify any token as real mining. The fix is
    # to gate on n_destinations_true; legacy skeletons (no field) get
    # `is_real_mining_pool=False` rather than always-False.
    is_real = (
        n_destinations_true is not None
        and n_destinations_true >= REAL_MINING_MIN_DEST_COUNT
        and (mean_pct_supply is not None and mean_pct_supply < REAL_MINING_MAX_MEAN_PCT_SUPPLY)
        and mean_n_tx > FAKE_MINING_MAX_MEAN_TX_COUNT
        and unlabeled_frac < FAKE_MINING_MIN_UNLABELED_FRAC
    )

    return {
        "n_destinations_visible": n_visible,
        "n_destinations_total": n_destinations_true,  # may be None on legacy
        "mean_pct_supply_per_dest": mean_pct_supply,
        "mean_n_tx_per_dest": mean_n_tx,
        "unlabeled_fraction": unlabeled_frac,
        "top10_share_of_total": top10_share,
        "signals_tripped": signals,
        "n_signals_tripped": len(signals),
        "is_fake_mining_cluster": is_fake,
        "is_real_mining_pool": is_real,
    }


def classify_token_mining_mode(
    mint_authority_dumps: dict[str, Any],
    total_supply: float | None = None,
) -> dict[str, Any]:
    """Aggregate per-authority classifications into a single token-level
    flag.

    Args:
      mint_authority_dumps: skeleton `funding_attribution.mint_authority_dumps`.
      total_supply: token total supply.

    Returns:
      {
        "is_mining_token": bool,                # any mint authorities exist
        "is_fake_mining_distribution": bool,    # any authority looks fake
        "is_real_mining_distribution": bool,    # all authorities look real
        "per_authority_classifications": {addr: per_auth_result, ...},
        "n_authorities_total": int,
        "n_fake_authorities": int,
        "n_real_authorities": int,
      }
    """
    if not mint_authority_dumps:
        return {
            "is_mining_token": False,
            "is_fake_mining_distribution": False,
            "is_real_mining_distribution": False,
            "per_authority_classifications": {},
            "n_authorities_total": 0,
            "n_fake_authorities": 0,
            "n_real_authorities": 0,
        }
    per_addr = mint_authority_dumps.get("per_addr") or {}
    per_class: dict[str, dict] = {}
    n_fake = 0
    n_real = 0
    for addr, data in per_addr.items():
        res = classify_mining_authority(data, total_supply=total_supply)
        per_class[addr] = res
        if res["is_fake_mining_cluster"]:
            n_fake += 1
        if res["is_real_mining_pool"]:
            n_real += 1

    n_total = len(per_addr)
    return {
        "is_mining_token": n_total > 0,
        "is_fake_mining_distribution": n_fake > 0,
        "is_real_mining_distribution": n_real == n_total and n_total > 0,
        "per_authority_classifications": per_class,
        "n_authorities_total": n_total,
        "n_fake_authorities": n_fake,
        "n_real_authorities": n_real,
    }


__all__ = [
    "classify_mining_authority",
    "classify_token_mining_mode",
    "FAKE_MINING_MAX_DEST_COUNT",
    "FAKE_MINING_MIN_MEAN_PCT_SUPPLY",
    "FAKE_MINING_MAX_MEAN_TX_COUNT",
    "FAKE_MINING_MIN_UNLABELED_FRAC",
    "FAKE_MINING_MIN_TOP10_SHARE",
    "FAKE_MINING_MIN_SIGNALS",
    "REAL_MINING_MIN_DEST_COUNT",
    "REAL_MINING_MAX_MEAN_PCT_SUPPLY",
]
