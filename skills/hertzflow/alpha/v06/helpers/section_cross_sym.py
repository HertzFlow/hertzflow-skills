#!/usr/bin/env python3
"""section_cross_sym.py — v0.7 cross-sym section runner.

Wires together:
  - cross_sym_registry (universal cache)
  - pre_launch_insider_index (append-only m6 history)
  - cross_sym_detector (find candidates)
  - identity_classifier (compute signature + classify)

Emits the `cross_sym` section of the skeleton:

  {
    "cross_sym": {
      "_pipeline_source": "section_cross_sym",
      "whales": [
        {
          # ALL locked (pipeline-computed, LLM cannot touch):
          "address": str,
          "this_token_pct": float,
          "this_token_balance": str,
          "cross_sym_count": int,
          "cross_sym_tokens": [{sym, ca, pct, rank}, ...],
          "top_cross_sym_token": {sym, pct},
          "arkham_label": str | null,
          "pre_launch_insider_count": int,
          "pre_launch_insider_tokens": [{sym, ca, dumped_pct, ...}, ...],
          "behavior_signature": {11 dims},

          # derived_locked (pipeline-computed from signature, LLM cannot touch):
          "identity_classification_enum": str,
          "confidence_score": float,
          "evidence_required_fields": [str, ...],

          # writable (LLM fills, validator gates):
          "identity_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
          "risk_assessment_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        ...
      ],
      "summary_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
      "_scope": "active|full|top100",
      "_registry_age_secs": int,
      "_credits_used": int,
    }
  }

Side-effect: this section ALSO appends the current report's m6_rows to
the pre_launch_insider_index — so subsequent reports benefit from this
report's data.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from i18n import t   # v0.6.2 i18n
import cross_sym_registry
import cross_sym_detector
import identity_classifier
import pre_launch_insider_index


PLACEHOLDER = "<LLM_NARRATIVE_PLACEHOLDER>"


def _derive_behavior_hint(role_classification: dict | None) -> str | None:
    """v0.7.24d: derive evidence-aware behavior hint from role_classifier output.

    The earlier generic narrative template ("暗示 systematic 操盘") wrote
    same copy regardless of whether the candidate was a 24KB market-maker
    bot framework or a small unknown contract. Now we distinguish based on
    size_tier (contract code size) + step6_netflow.shape (selling vs holding
    pattern). LLMs writing the narrative get a factual hint instead of a
    template.

    Returns None when role_classification or required evidence not present.
    """
    if not role_classification:
        return None
    evid = role_classification.get("evidence") or {}
    step1 = evid.get("step1_contract") or {}
    step6 = evid.get("step6_netflow") or {}
    size_tier = step1.get("size_tier")
    is_contract = step1.get("is_contract")
    netflow_shape = step6.get("shape")

    # Map size_tier → plain-language behavior class. Source: role_classifier
    # taxonomy where FULL_MM ≈ 24KB+ contract that smells like Wintermute /
    # Jump / Cumberland MM bot framework; LITE_MM ≈ smaller MM bot;
    # PROXY_OR_SIMPLE ≈ thin proxy/forwarder contract; EOA ≈ user wallet.
    if not is_contract:
        base = t("sec1.cross_sym.behavior_base_eoa")
    elif size_tier == "FULL_MM":
        base = t("sec1.cross_sym.behavior_base_full_mm")
    elif size_tier == "LITE_MM":
        base = t("sec1.cross_sym.behavior_base_lite_mm")
    elif size_tier == "PROXY_OR_SIMPLE":
        base = t("sec1.cross_sym.behavior_base_proxy_simple")
    else:
        base = t("sec1.cross_sym.behavior_base_contract_generic",
                 size_tier=size_tier or t("common.unknown"))

    # Augment with netflow direction
    if netflow_shape == "net_seller":
        flow = t("sec1.cross_sym.flow_net_seller")
    elif netflow_shape == "net_holder":
        flow = t("sec1.cross_sym.flow_net_holder")
    elif netflow_shape == "accumulating":
        flow = t("sec1.cross_sym.flow_accumulating")
    elif netflow_shape == "balanced":
        flow = t("sec1.cross_sym.flow_balanced")
    elif netflow_shape:
        flow = t("sec1.cross_sym.flow_generic", netflow_shape=netflow_shape)
    else:
        flow = t("sec1.cross_sym.flow_unknown")

    return t("sec1.cross_sym.behavior_hint_join", base=base, flow=flow)


def run(
    ca: str,
    sym: str,
    top_holders: list[dict],
    m6_rows: list[dict],
    op_relay_addrs: list[str],
    cex_hot_addrs: set[str],
    dex_pool_addrs: set[str],
    deployer_addrs: set[str],
    *,
    scope: str | None = None,
    skip_cross_sym: bool = False,
    verbose: bool = False,
    listing_date: str | None = None,
    total_supply: float | int | None = None,
) -> dict:
    """Run the cross-sym section for one CA.

    Returns the `cross_sym` section dict ready for skeleton injection.

    Args:
        ca: current contract address (lowercase 0x)
        sym: current token symbol
        top_holders: from section_f_holders (list of holder dicts from
            surf token-holders output, with `address`, `balance`,
            `percentage`, optional `entity_name`)
        m6_rows: from rule_11_backward_trace (list of receivers — used
            BOTH as excluded_addrs AND appended to insider index)
        op_relay_addrs: from section_l_distribution operator_relay_members
        cex_hot_addrs: set of known CEX hot wallet addrs (from Arkham labels
            on top_holders + curated list)
        dex_pool_addrs: set of known DEX main pool addrs (from section_liq)
        deployer_addrs: set of known deployer addrs (from rule_11)

    Configuration:
        scope: override cross_sym_registry scope ('active'|'full'|'top100')
            Defaults: env CROSS_SYM_SCOPE, falls back to 'active'.
        skip_cross_sym: if True, skip entirely (returns empty section)
        verbose: print diagnostic to stderr
    """
    sym_upper = sym.upper()
    # v0.7.21.7: chain-aware case. EVM lowercases (case-insensitive);
    # Solana base58 must preserve case (case-sensitive).
    from chain_router import get_active_chain as _chain_get_active
    _is_solana = _chain_get_active() == "solana"
    def _norm(a: str) -> str:
        return a if _is_solana else (a or "").lower()
    ca_lower = _norm(ca)

    # Side effect: ALWAYS append m6 to the insider index BEFORE skip check.
    # Even when user opts out of cross-sym detection, accumulating the
    # insider index is free and benefits future reports.
    try:
        idx_res = pre_launch_insider_index.append_from_report(
            ca=ca_lower, sym=sym_upper, m6_rows=m6_rows,
        )
        if verbose:
            print(
                f"[section_cross_sym] insider index updated: "
                f"{idx_res['n_new_addrs']} new, {idx_res['n_updated_addrs']} updated, "
                f"total {idx_res['total_addrs_indexed']} addrs",
                file=sys.stderr,
            )
    except pre_launch_insider_index.IndexError_ as e:
        if verbose:
            print(f"[section_cross_sym] insider index append failed: {e}", file=sys.stderr)

    if skip_cross_sym:
        if verbose:
            print("[section_cross_sym] skipped (skip_cross_sym=True)", file=sys.stderr)
        return _empty_section(reason="skipped_by_user")

    # Determine scope (CLI arg > env var > default)
    if scope is None:
        scope = os.environ.get("CROSS_SYM_SCOPE", "active")
    if scope not in ("active", "full", "top100"):
        if verbose:
            print(f"[section_cross_sym] unknown scope {scope!r}, defaulting to 'active'", file=sys.stderr)
        scope = "active"

    # v0.7 acceptance fix: fetch CURRENT CA's top-100 holders directly from
    # surf (NOT from section_f_holders.top_holders, which uses different pct
    # calculation that filters out 0.5%+ candidates incorrectly). The
    # extra cost is ~1 surf credit (~$0.005) and gives us the same pct
    # values used by the registry, so detector thresholds work consistently.
    fresh_top_holders = _fetch_top_holders_from_surf(ca_lower, verbose=verbose)
    # v0.7.23.2 fix: surf token-holders returns `percentage` field computed against
    # CHAIN-actual supply (which includes inflationary bridge-mint over-mints),
    # not the Alpha-API NOMINAL supply. For tokens like H (Humanity Protocol)
    # where chain mint reached ~103B against nominal 10B, surf percentage is
    # ~10x canonical %, producing "this_token_pct: 2229%" for a wallet that
    # actually holds 22.29% of nominal supply. Recompute from balance /
    # Alpha total_supply × 100 so the report aligns with the rest of the
    # forensic numbers. Falls through to surf's pct only when total_supply
    # is unavailable.
    if total_supply and total_supply > 0 and fresh_top_holders:
        for _h in fresh_top_holders:
            try:
                _bal = float(_h.get("balance") or 0)
                _h["percentage"] = _bal / float(total_supply) * 100
            except (TypeError, ValueError):
                pass
    if not fresh_top_holders:
        # Fall back to passed-in holders (better than nothing)
        if verbose:
            print(f"[section_cross_sym] surf token-holders failed, falling back to passed top_holders", file=sys.stderr)
        fresh_top_holders = top_holders

    # Load registry (lazy refresh if stale)
    t0 = time.time()
    try:
        registry = cross_sym_registry.get_reverse_index(scope=scope, verbose=verbose)
    except cross_sym_registry.RegistryError as e:
        if verbose:
            print(f"[section_cross_sym] registry unavailable: {e}", file=sys.stderr)
        return _empty_section(reason=f"registry_error: {e}")

    registry_age = int(time.time()) - registry.get("snapshot_ts", 0)
    if verbose:
        print(
            f"[section_cross_sym] registry: {registry.get('n_tokens')} tokens, "
            f"age {registry_age // 60} min, scope {registry.get('scope')}",
            file=sys.stderr,
        )

    # v0.7.6: credits_used initialized here (before Arkham probe) so the
    # probe call can increment it.
    credits_used = 0

    # Build excluded set
    excluded = set()
    # v0.7.20.2 / v0.7.21.7: burn-address family. EVM 0xdead / 0x0;
    # Solana System Program 1111…1111 / Incinerator. Permanent supply
    # removal, not holders — they were silently surfacing as cross-sym
    # whales (PLAY's 0xdead held 20% of supply and was matching 19 other
    # Alpha tokens because every burn-and-deploy template uses the same
    # address). Burn supply is reported in section_alloc instead.
    from chain_router import burn_addrs as _chain_burn_addrs
    excluded.update(_chain_burn_addrs())
    for r in m6_rows:
        a = _norm(r.get("addr") or "")
        if a:
            excluded.add(a)
    for a in op_relay_addrs:
        a_n = _norm(a or "")
        if a_n:
            excluded.add(a_n)
    excluded.update({_norm(a) for a in (cex_hot_addrs or set()) if a})

    # v0.7.6 anti-pollution layer 1 of 2: Arkham labels (read inline).
    # The `surf token-holders` response ALREADY nests Arkham label data
    # per holder under `label.labels[]` — there is no need for a
    # separate wallet-labels-batch RPC (and that call hits "too many
    # args" failures at 100-address batches anyway). We just walk the
    # response we already have.
    #
    # Trigger cases (2026-05-25):
    #   - 0x26209d... = "Bitget Deposit" (CEX_DEPOSIT) → was surfacing
    #     as JCT cross-sym whale w/ "dormant VC bag" narrative.
    #   - 0xef7d88... = PancakeSwap V3 Pool (DEX_POOL) → mis-identified
    #     as the operator EOA in H's wash investigation, creating a
    #     wrong "closed-loop operator wash" narrative.
    arkham_label_map: dict[str, dict] = {}
    try:
        from surf_labels_probe import classify_label, EXCLUDE_FROM_CROSS_SYM as _ARKHAM_EXCLUDE
        for h in fresh_top_holders:
            addr = _norm(h.get("address") or h.get("addr") or "")
            if not addr:
                continue
            # surf token-holders nests labels under `label.labels[]`; also
            # `entity_name` / `entity_type` are sometimes top-level.
            label_blob = h.get("label") or {}
            labels_list = label_blob.get("labels") if isinstance(label_blob, dict) else None
            top_lbl = max(labels_list, key=lambda x: x.get("confidence", 0)) if labels_list else {}
            label_text = (top_lbl or {}).get("label")
            confidence = float((top_lbl or {}).get("confidence") or 0)
            entity_name = h.get("entity_name") or (label_blob.get("entity_name") if isinstance(label_blob, dict) else None)
            entity_type = h.get("entity_type") or (label_blob.get("entity_type") if isinstance(label_blob, dict) else None)
            cls = classify_label(label_text, entity_name, entity_type)
            arkham_label_map[addr] = {
                "label": label_text,
                "entity_name": entity_name,
                "entity_type": entity_type,
                "classification": cls,
                "confidence": confidence,
            }
        arkham_excluded = {
            a for a, r in arkham_label_map.items()
            if r["classification"] in _ARKHAM_EXCLUDE
        }
        excluded.update(arkham_excluded)
        if verbose and arkham_excluded:
            sample = [(a[:14], arkham_label_map[a]["label"]) for a in list(arkham_excluded)[:5]]
            print(
                f"[section_cross_sym] Arkham label exclusion: "
                f"{len(arkham_excluded)} addresses: {sample}",
                file=sys.stderr,
            )
    except Exception as e:
        if verbose:
            print(
                f"[section_cross_sym] Arkham label inline read failed "
                f"(degrading gracefully): {e}",
                file=sys.stderr,
            )

    # v0.7.4 anti-pollution layer 2 of 2: BscScan public-label probe.
    # Catches shared-pool / DEX-router / CEX-infrastructure addresses
    # that Surf/Arkham don't label (and `entity_name` therefore misses).
    # The trigger case: 0x73d8bd54f7cf5fab43fe4ef40a62d390644946db is
    # "Binance: Alpha 2.0 Router Proxy" — it appears as a top-100 holder
    # in essentially every Alpha-listed token, so without this filter
    # it dominates every report's cross_sym whales as a false "operator
    # across 100+ Alpha tokens" pattern.
    try:
        from bscscan_label_probe import find_excluded as _bscscan_find_excluded
        candidate_addrs = [
            _norm(h.get("address") or h.get("addr") or "")
            for h in fresh_top_holders
        ]
        candidate_addrs = [a for a in candidate_addrs if a and a not in excluded]
        bscscan_excluded = _bscscan_find_excluded(
            candidate_addrs, verbose=verbose,
        )
        excluded.update(bscscan_excluded)
        if verbose and bscscan_excluded:
            print(
                f"[section_cross_sym] BscScan label probe excluded "
                f"{len(bscscan_excluded)} addresses (DEX_ROUTER / "
                f"SHARED_POOL_CUSTODIAL): {list(bscscan_excluded)[:3]}",
                file=sys.stderr,
            )
    except Exception as e:
        if verbose:
            print(
                f"[section_cross_sym] BscScan label probe failed "
                f"(degrading gracefully): {e}",
                file=sys.stderr,
            )

    # Detect candidates (uses fresh top_holders with surf pct, not section_f_holders shape)
    candidates = cross_sym_detector.detect(
        ca=ca_lower,
        top_holders=fresh_top_holders,
        excluded_addrs=excluded,
        registry=registry,
    )
    if verbose:
        print(f"[section_cross_sym] detected {len(candidates)} candidates", file=sys.stderr)

    if not candidates:
        return _empty_section(
            reason="no_candidates",
            scope=scope,
            registry_age_secs=registry_age,
        )

    # Per-candidate: pre-launch insider lookup + behavior signature + classify
    insider_idx_full = pre_launch_insider_index.load_full_index()
    insider_addrs = set(insider_idx_full.get("reverse_index", {}).keys())

    enriched = []
    for cand in candidates:
        # v0.7.6: surface real Arkham label data (previously hardcoded None
        # by cross_sym_detector). If Arkham labeled this address but it
        # didn't match an EXCLUDE_FROM_CROSS_SYM class (e.g. MARKET_MAKER
        # or OTHER_NAMED), the candidate stayed in the list — surface the
        # label so the report can render it accurately.
        addr_lower = _norm(cand.get("address") or "")
        arkham_rec = arkham_label_map.get(addr_lower) or {}
        if arkham_rec.get("label") or arkham_rec.get("entity_name"):
            cand["arkham_label"] = (
                arkham_rec.get("label")
                or f"{arkham_rec.get('entity_name')} ({arkham_rec.get('entity_type')})"
            )
        # else cand["arkham_label"] remains None (set by detector)

        # Pre-launch insider lookup (free — local index)
        pre_launch_hits = pre_launch_insider_index.lookup(cand["address"])
        # Exclude the current token's own m6 row (we already excluded the address
        # via `excluded` set above, but defensive)
        pre_launch_hits = [
            h for h in pre_launch_hits if _norm(h.get("ca", "")) != ca_lower
        ]
        cand["pre_launch_insider_count"] = len(pre_launch_hits)
        cand["pre_launch_insider_tokens"] = pre_launch_hits

        # Behavior signature (1 surf SQL per candidate)
        cross_sym_cas = [t.get("ca") for t in cand.get("cross_sym_tokens", []) if t.get("ca")]
        try:
            sig = identity_classifier.compute_signature(
                addr=cand["address"],
                cross_sym_cas=cross_sym_cas,
                cex_hot_addrs=cex_hot_addrs,
                dex_pool_addrs=dex_pool_addrs,
                deployer_addrs=deployer_addrs,
                insider_addrs=insider_addrs,
            )
        except identity_classifier.ClassifierError as e:
            if verbose:
                print(
                    f"[section_cross_sym] signature failed for {cand['address']}: {e}",
                    file=sys.stderr,
                )
            sig = identity_classifier._empty_signature(cand["address"], 90)
        cand["behavior_signature"] = sig
        credits_used += int(sig.get("_surf_credits_used") or 0)

        # v0.7.7: wash detection lives in its own section (section_wash_infra).
        # That section runs the 5-step on-chain pure-signature pipeline
        # (atomic-pair tx, dominant counterparty concentration, P+Q drift,
        # tx_from diversity) which supersedes v0.7.5's narrow "operator
        # EOA ↔ controlled contract" wash_distributor_probe heuristic.
        cls = identity_classifier.classify(
            signature=sig,
            cross_sym_count=cand["cross_sym_count"],
            pre_launch_insider_count=cand["pre_launch_insider_count"],
        )
        cand["identity_classification_enum"] = cls["identity_enum"]
        cand["confidence_score"] = cls["confidence"]
        cand["evidence_required_fields"] = cls["evidence_required_fields"]

        # v0.7.7: 6-step whale role classifier. Pure on-chain, no Arkham
        # label dependency. Outputs deterministic role + evidence chain that
        # replaces the v0.7's vague "UNKNOWN_WHALE_HIGH_CROSS_SYM" with
        # something the report can actually act on (insider_allocation_holder
        # / dex_mm_bot / dex_mm_bot_unwinding / retail_holder / etc.)
        try:
            from role_classifier import classify as _role_classify, RoleClassifierError
            role_result, role_credits = _role_classify(
                addr=cand["address"],
                ca=ca_lower,
                listing_date=listing_date,
            )
            cand["role_classification"] = role_result
            credits_used += role_credits
            if verbose:
                print(
                    f"[section_cross_sym] role for {cand['address'][:14]}: "
                    f"{role_result['role']} (conf {role_result['confidence']:.2f}, "
                    f"credits {role_credits})",
                    file=sys.stderr,
                )
        except RoleClassifierError as e:
            if verbose:
                print(
                    f"[section_cross_sym] role classifier failed for "
                    f"{cand['address']}: {e}",
                    file=sys.stderr,
                )
            cand["role_classification"] = None
        except Exception as e:
            if verbose:
                print(
                    f"[section_cross_sym] role classifier unexpected error: {e}",
                    file=sys.stderr,
                )
            cand["role_classification"] = None

        # v0.7.24d: behavior_hint derived from role_classification evidence —
        # gives LLMs writing the narrative slots a factual evidence-based
        # starting point. Earlier templates wrote generic "暗示 systematic
        # 操盘 不是单 token 持有" copy regardless of size_tier; user pointed
        # out 24KB FULL_MM contract is a market-making bot framework, not
        # operator. Now we surface the distinction explicitly.
        cand["behavior_hint"] = _derive_behavior_hint(cand.get("role_classification"))

        # Writable narrative slots
        cand["identity_narrative"] = PLACEHOLDER
        cand["risk_assessment_narrative"] = PLACEHOLDER
        enriched.append(cand)

    return {
        "_pipeline_source": "section_cross_sym",
        "whales": enriched,
        "summary_narrative": PLACEHOLDER,
        "_scope": scope,
        "_registry_age_secs": registry_age,
        "_credits_used": credits_used,
    }


def _fetch_top_holders_from_surf(ca: str, *, limit: int = 100, verbose: bool = False) -> list[dict]:
    """Fetch surf token-holders top-100 for the given CA.

    Returns list of {address, balance, percentage, entity_name?, entity_type?}.
    Returns [] on any failure (caller falls back to passed-in holders).

    Used by section_cross_sym to bypass section_f_holders' different pct
    calculation. ~1 surf credit per call (~$0.005).
    """
    # v0.7.20.1: route to active chain (was hardcoded bsc).
    from chain_router import get_active_chain
    cmd = ["surf", "token-holders", "--address", ca, "--chain", get_active_chain(),
           "--limit", str(limit), "--include", "labels", "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False)
    except (subprocess.TimeoutExpired, OSError) as e:
        if verbose:
            print(f"[section_cross_sym] surf token-holders failed: {e}", file=sys.stderr)
        return []
    if result.returncode != 0:
        if verbose:
            print(f"[section_cross_sym] surf token-holders exit {result.returncode}: {result.stderr[:200]}", file=sys.stderr)
        return []
    try:
        doc = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if doc.get("error"):
        return []
    return doc.get("data") or []


def _empty_section(
    *,
    reason: str,
    scope: str | None = None,
    registry_age_secs: int | None = None,
) -> dict:
    """Return a well-formed empty section."""
    return {
        "_pipeline_source": "section_cross_sym",
        "whales": [],
        "summary_narrative": PLACEHOLDER,
        "_scope": scope,
        "_registry_age_secs": registry_age_secs,
        "_credits_used": 0,
        "_skip_reason": reason,
    }
