#!/usr/bin/env python3
"""protocol_lockup_detector.py — classify a holder as project-side /
infrastructure (vesting / multisig / treasury / DEX-infra / CEX-custody)
vs. unlabeled (a genuine insider candidate).

Why this exists (v0.7.10.3):

  rule_11_backward_trace is a pure transfer-graph analysis — it follows
  "who sent tokens to whom" and labels every pre-listing receiver as an
  "insider". It has no identity awareness. Two failure cases this caused:

  1. COLLECT (2026-05-26): largest "quiet wallet" `0xf27d6fc9…` (79% of
     supply, dumped_pct=0) is Arkham-labeled "Vesting (Proxy)" — the
     project's lockup contract, NOT an insider hoarding. 2nd quiet wallet
     `0x1ac06807…` is "Gnosis Safe Proxy" (multisig).
  2. COLLECT m6 partial-dumper `0x73d8bd54…` is Arkham-labeled
     "Binance Wallet" (entity_type="misc", NOT "cex") — Binance Alpha's
     omnibus custody wallet. It's #1 holder in ~105 Alpha projects at 50%+
     each because Alpha user holdings are custodied there. Its transfers
     are user buys/sells, NOT insider distribution.

  This module batch-queries Arkham labels and classifies each address so
  rule_11 / verdict / alloc / section_l can exclude infrastructure from
  the "insider" framing.

Consumed by:
  - rule_11_backward_trace (enrich pre_launch_receivers)
  - _derive_verdict_enum (exclude protocol lockups from quiet_with_size)
  - section_alloc (separate "项目方锁仓/基建" row from "未分内幕")
  - section_l_distribution (PROJECT_LOCKUP role)

Cost: one `surf wallet-labels-batch` call per chunk of 20 addresses.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))


# ---- label classification (pure-Python, no I/O) ----

VESTING_LABEL_RE = re.compile(
    # v0.8.2 fix: no word boundary on vendor brand names so camelcase
    # labels like `SablierLockup` / `HedgeyLock` / `StreamflowVesting` get
    # caught. Velvet test: top other `SablierLockup` 107% 流通 was missed
    # because `\bsablier\b` doesn't match mid-camelcase.
    r"("
    r"\bvesting\b|"
    r"\b(lockup|locker)\b|"
    r"sablier|streamflow|hedgey|vyper\s*finance|"
    r"unicrypt|team\s*finance|pinklock|dx\s*lock"
    r")",
    re.IGNORECASE,
)

MULTISIG_LABEL_RE = re.compile(
    r"\b("
    r"gnosis\s*safe|safe\s*proxy|safe\s*module|"
    r"multisig|multi-sig|"
    r"squads"
    r")\b",
    re.IGNORECASE,
)

TREASURY_LABEL_RE = re.compile(
    r"\b(treasury|dao\s*treasury|foundation\s*wallet)\b",
    re.IGNORECASE,
)

# DEX / bridge / DeFi router infra (third-party, not insider).
#
# v0.8.2 additions:
#   - PoolManager (UniV4 / PancakeV4 singleton pool manager). H token
#     top-2 holder showed `PoolManager` 254% 流通, was unclassified.
#   - Universal Router (Uniswap Universal Router contracts).
#   - V4 hooks / hook contracts.
DEX_INFRA_LABEL_RE = re.compile(
    r"\b("
    r"dex\s*router|"
    r"pancake\w*\s*router|uniswap\w*\s*router|sushi\w*\s*router|"
    r"universal\s*router|"
    r"pool\s*manager|poolmanager|"
    r"vault|"
    r"lifi\s*diamond|"
    r"stargate|hop\s*protocol|across\s*protocol|squid\s*router|"
    r"v[2-4]\s*pool|liquidity\s*pool|"
    r"v[2-4]\s*hook|hooks\b"
    r")\b",
    re.IGNORECASE,
)

# CEX custody / exchange omnibus wallets. CRITICAL: Arkham labels these
# inconsistently — "Binance Wallet" has entity_type="misc", not "cex". So
# we match on entity_name / label text containing an exchange brand, not
# just entity_type. Covers hot/cold/deposit/withdrawal/custody variants.
#
# v0.8.1 brand list expansion (false-positive mitigation):
#   - Tier 1 (was already covered): top 19 majors
#   - Tier 2/3 added: smaller CEX that run launchpool / IEO / airdrop
#     programs — same shape as Tier 1, just less labeled
#   - Tier 1 launchpool sub-platforms are covered by the brand match
#     alone (CEX_CUSTODY_LABEL_RE matches `Binance: Launchpool` because
#     "binance" appears; trailing wallet/hot/cold keyword is optional)
_CEX_BRANDS = (
    # Tier 1 (v0.7.x baseline)
    r"binance|coinbase|okx|okex|bybit|bitget|gate\.?io|gate\s|kucoin|"
    r"mexc|htx|huobi|kraken|bitfinex|upbit|bithumb|crypto\.com|"
    r"gemini|bitstamp|bitkub|backpack|aster|"
    # Tier 2/3 (v0.8.1 add) — also run launchpool / IEO / airdrop programs
    r"bingx|phemex|whitebit|pionex|probit|digifinex|lbank|bitrue|"
    r"coinex|bitmart|tapbit|hotbit|xt\.?com|deepcoin|biconomy|toobit|"
    r"hashkey|cryptocom"
)
CEX_CUSTODY_LABEL_RE = re.compile(
    r"\b(" + _CEX_BRANDS + r")\b"
    r"(.*\b(wallet|hot|cold|deposit|withdrawal|custody|reserve|exchange|launchpool|launchpad|hodler|megadrop|jumpstart|earn|cryptopedia|spotlight|kickstarter|prime)\b)?",
    re.IGNORECASE,
)

# v0.8.1: third-party distribution platforms (not CEX, not DEX, but
# project-side allocation channels). False-positive mitigation for the
# "deployer → claim contract → retail self-claim" pattern (Pattern B/D):
#   - DEX launchpads / IDO platforms — project mints to platform pool
#     wallet, retail buys/claims, platform wallet's residual stock is
#     not insider-controlled (it's earmarked for ongoing public sale).
#   - Task / quest platforms — same shape; project funds the campaign
#     and the platform contract holds the unclaimed remainder.
#   - Airdrop SaaS (vesting / streaming / claim distributors) — the
#     contract holds the un-claimed remainder on behalf of retail,
#     not the project-side hand. Distinct from VESTING_LABEL_RE (which
#     covers per-allocation lockups, not retail claim distributors).
#
# Effect: matched wallets are flagged is_airdrop_platform → excluded
# from `pure_insider_holds_pct_supply` (potential-dump-pressure metric)
# but KEPT in `insider_addrs` because their reclaim / admin-withdraw
# events ARE genuine insider actions (the project still controls the
# admin key). Conservative on both edges.
_LAUNCHPAD_BRANDS = (
    r"dao\s*maker|polkastarter|seedify|trustpad|gamefi\.?org|"
    r"bscpad|camelot|fjord|sushi\s*miso|raydium\s*acceleraytor|"
    r"impossible\s*finance|red\s*kite|trader\s*joe\s*launch|"
    r"copper\s*launch|balancer\s*lbp"
)
_TASK_PLATFORM_BRANDS = (
    r"galxe|layer3|taskon|questn|rabbit\s*hole|gitcoin\s*passport|"
    r"zealy|guild\.xyz|cred\s*protocol"
)
_AIRDROP_SAAS_BRANDS = (
    r"hedgey|sablier|superfluid|llamapay|magna|coinvise|merkle\s*distributor|"
    r"merkl\b|jiritsu|wallet3|disco\.xyz"
)
_AIRDROP_KEYWORDS = (
    # v0.8.1 audit MED #1 fix: bare `airdrop` is too broad — Arkham
    # labels like "Airdrop Recipient" or "Project Airdrop Wallet" would
    # match and exclude actual retail/insider EOAs. Require an explicit
    # distributor-shaped suffix (claim/contract/distributor/pool/campaign)
    # or pair with `merkle/launchpool/emission/allocation/reward`.
    # audit LOW #2 fix: also catch camelcase `AirdropClaim` by
    # adding `airdrop\s*claim` explicitly and allowing optional space
    # between the airdrop prefix and the trailing keyword.
    r"airdrop\s*(claim|contract|distributor|pool|campaign|claim\s*contract)|"
    r"merkle\s*distributor|launchpool\s*distributor|"
    r"campaign\s*pool|emission\s*contract|"
    r"allocation\s*pool|reward\s*distributor|"
    r"claim\s*contract"
)
AIRDROP_PLATFORM_LABEL_RE = re.compile(
    r"\b("
    + _LAUNCHPAD_BRANDS + r"|"
    + _TASK_PLATFORM_BRANDS + r"|"
    + _AIRDROP_SAAS_BRANDS + r"|"
    + _AIRDROP_KEYWORDS
    + r")\b",
    re.IGNORECASE,
)


def classify_protocol_lockup(
    arkham_label_text: str | None = None,
    entity_name: str | None = None,
    entity_type: str | None = None,
    raw_labels: list[dict] | None = None,
) -> dict[str, Any]:
    """Classify a single Arkham label response.

    Returns dict with is_vesting / is_multisig / is_treasury / is_dex_infra
    / is_cex_custody / is_protocol_lockup (any) / label_match / display_label.
    """
    candidates: list[str] = []
    if arkham_label_text:
        candidates.append(str(arkham_label_text))
    if entity_name:
        candidates.append(str(entity_name))
    for lbl in (raw_labels or []):
        if isinstance(lbl, dict) and lbl.get("label"):
            candidates.append(str(lbl["label"]))
    text = " ".join(candidates).strip()
    et = (entity_type or "").lower()

    is_vesting = bool(VESTING_LABEL_RE.search(text))
    is_multisig = bool(MULTISIG_LABEL_RE.search(text))
    is_treasury = bool(TREASURY_LABEL_RE.search(text))
    is_dex_infra = bool(DEX_INFRA_LABEL_RE.search(text))
    # CEX custody: brand name in label text, OR Arkham entity_type=cex/exchange.
    # dex_infra takes PRECEDENCE: a label like "Dex Router (OKX)" is OKX's DEX
    # aggregator router (a swap venue), NOT an OKX exchange deposit — the CEX
    # brand regex would otherwise match "OKX" and miscount router transfers as
    # CEX deposits (R2 inflated confirmed-CEX to 183% this way).
    # v0.8.2 fix: orphan generic CEX label heuristic. Surf sometimes
    # returns `Cold Wallet` / `Hot Wallet` / `Deposit` / `Withdrawal`
    # labels with no entity_name (brand) and no entity_type="cex" — these
    # are CEX wallets with weak Arkham metadata. JCT test: `0x26209d9f0dc3`
    # had label `Cold Wallet` only, was classified as "other" / 散户. We
    # heuristically catch these as CEX provided they don't match dex_infra
    # or other lockup classes.
    # v0.8.2.2 audit LOW #5 fix: exclude generic deposit / withdrawal
    # labels that are paired with bridge / staking / project context words
    # (e.g. a bridge contract labeled "Bridge Deposit Address" should not
    # be classified as CEX). The CEX heuristic now requires either:
    #   (a) a bare wallet keyword (`Cold Wallet` / `Hot Wallet`) — high-
    #       confidence CEX-shape, OR
    #   (b) a deposit/withdrawal keyword WITHOUT a non-CEX context word.
    _ORPHAN_CEX_HIGH_CONF_RE = re.compile(
        r"\b(cold\s*wallet|hot\s*wallet|exchange\s*(wallet|reserve))\b",
        re.IGNORECASE,
    )
    _ORPHAN_CEX_LOW_CONF_RE = re.compile(
        r"\b(deposit\s*(wallet|address)?|withdrawal\s*(wallet|address)?)\b",
        re.IGNORECASE,
    )
    _NON_CEX_CONTEXT_RE = re.compile(
        r"\b(bridge|staking|stake|claim|distribut|reward|"
        r"airdrop|emission|allocation|launchpad|launchpool|"
        r"vesting|lockup|multisig|treasury|dao|protocol|"
        r"vault|pool|router)\b",
        re.IGNORECASE,
    )
    _orphan_high = bool(_ORPHAN_CEX_HIGH_CONF_RE.search(text))
    _orphan_low = bool(_ORPHAN_CEX_LOW_CONF_RE.search(text))
    _has_non_cex_context = bool(_NON_CEX_CONTEXT_RE.search(text))
    _orphan_cex_match = (
        _orphan_high
        or (_orphan_low and not _has_non_cex_context)
    )
    is_cex_custody = (
        (bool(CEX_CUSTODY_LABEL_RE.search(text)) or et in ("cex", "exchange")
         or (_orphan_cex_match
             and not is_vesting and not is_multisig and not is_treasury))
        and not is_dex_infra
    )
    # v0.8.1: third-party distribution platforms — launchpads, task /
    # quest platforms, airdrop SaaS, generic claim-distributor contracts.
    # The contract's residual balance belongs to retail (un-claimed pool),
    # not to the project-side hand.
    #
    # PRECEDENCE: dex_infra > cex_custody > vesting > multisig > treasury
    # > airdrop_platform. Reasoning per audit LOW #1:
    #   - A `DAO Treasury Airdrop Campaign` wallet should be classified
    #     as treasury (project-side hand), not airdrop_platform (retail
    #     un-claimed pool).
    #   - A `Gnosis Safe Airdrop Admin` is a multisig with admin power
    #     over the campaign, also project-side.
    is_airdrop_platform = (
        bool(AIRDROP_PLATFORM_LABEL_RE.search(text))
        and not is_dex_infra
        and not is_cex_custody
        and not is_vesting
        and not is_multisig
        and not is_treasury
    )

    is_protocol_lockup = (
        is_vesting or is_multisig or is_treasury or is_dex_infra or is_cex_custody
        or is_airdrop_platform
    )

    display = None
    if is_protocol_lockup:
        for lbl in (raw_labels or []):
            if isinstance(lbl, dict) and lbl.get("label"):
                cand = str(lbl["label"])
                if (VESTING_LABEL_RE.search(cand) or MULTISIG_LABEL_RE.search(cand)
                        or TREASURY_LABEL_RE.search(cand) or DEX_INFRA_LABEL_RE.search(cand)
                        or CEX_CUSTODY_LABEL_RE.search(cand)
                        or AIRDROP_PLATFORM_LABEL_RE.search(cand)):
                    display = cand
                    break
        if not display and entity_name:
            display = str(entity_name)
        if not display:
            display = text[:60]

    match = None
    for regex in (VESTING_LABEL_RE, MULTISIG_LABEL_RE, TREASURY_LABEL_RE,
                  DEX_INFRA_LABEL_RE, CEX_CUSTODY_LABEL_RE,
                  AIRDROP_PLATFORM_LABEL_RE):
        m = regex.search(text)
        if m:
            match = m.group(0)
            break

    return {
        "is_vesting": is_vesting,
        "is_multisig": is_multisig,
        "is_treasury": is_treasury,
        "is_dex_infra": is_dex_infra,
        "is_cex_custody": is_cex_custody,
        "is_airdrop_platform": is_airdrop_platform,
        "is_protocol_lockup": is_protocol_lockup,
        "label_match": match,
        "display_label": display,
    }


# ---- batch surf lookup ----

def fetch_arkham_labels_batch(addresses: list[str]) -> dict[str, dict]:
    """Call `surf wallet-labels-batch` in chunks of 20.

    surf silently drops the entire response above ~25 addresses
    (empirically verified 2026-05-26 on COLLECT 55-addr run: CHUNK=30
    returned 0 rows, CHUNK=20 returned 13 labeled rows). Stick to 20.

    Returns {addr_lower: {entity_name, entity_type, labels}}. Addresses
    Arkham has no entry for are absent from the dict.
    """
    if not addresses:
        return {}
    addrs = sorted({a.lower() for a in addresses if a})
    if not addrs:
        return {}

    CHUNK = 20
    out: dict[str, dict] = {}
    for i in range(0, len(addrs), CHUNK):
        chunk = addrs[i:i + CHUNK]
        cmd = ["surf", "wallet-labels-batch", "--addresses", ",".join(chunk), "--json"]
        from section_a_scope import _run_surf_with_retry
        doc, err = _run_surf_with_retry(cmd, base_timeout=20)
        if doc is None:
            continue   # chunk failed even with retry; addresses fall through as unlabeled
        for row in (doc.get("data") or []):
            addr = (row.get("address") or "").lower()
            if not addr:
                continue
            label_blob = row.get("label") if isinstance(row.get("label"), dict) else None
            out[addr] = {
                "entity_name": row.get("entity_name") or (label_blob or {}).get("entity_name"),
                "entity_type": row.get("entity_type") or (label_blob or {}).get("entity_type"),
                "labels": row.get("labels") or (label_blob or {}).get("labels") or [],
            }
    return out


def enrich_addresses_with_lockup_classification(
    addresses: list[str],
) -> dict[str, dict]:
    """Batch query Arkham + classify each address.

    Returns {addr_lower: {arkham, is_vesting, is_multisig, is_treasury,
    is_dex_infra, is_cex_custody, is_protocol_lockup, label_match,
    display_label}}.
    """
    arkham = fetch_arkham_labels_batch(addresses)
    out: dict[str, dict] = {}
    for addr in {a.lower() for a in addresses if a}:
        ark = arkham.get(addr)
        if ark:
            cls = classify_protocol_lockup(
                entity_name=ark.get("entity_name"),
                entity_type=ark.get("entity_type"),
                raw_labels=ark.get("labels"),
            )
            out[addr] = {"arkham": ark, **cls}
        else:
            out[addr] = {
                "arkham": None,
                "is_vesting": False, "is_multisig": False,
                "is_treasury": False, "is_dex_infra": False,
                "is_cex_custody": False, "is_airdrop_platform": False,
                "is_protocol_lockup": False,
                "label_match": None, "display_label": None,
            }
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("addresses", nargs="+", help="Addresses to classify")
    args = ap.parse_args()
    print(json.dumps(
        enrich_addresses_with_lockup_classification(args.addresses),
        indent=2, ensure_ascii=False,
    ))
