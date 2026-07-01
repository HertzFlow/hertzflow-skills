#!/usr/bin/env python3
"""forensic_pipeline.py — v0.6 main orchestrator.

Reads a CA, runs all forensic Section helpers in 4 dependency-aware rounds,
populates an EvidenceGraph, and outputs `report_data_skeleton.json` with:
  - Locked fields (data + structure) fully populated.
  - Writable fields (narrative) as "<LLM_NARRATIVE_PLACEHOLDER>" stubs.

LLM then fills the placeholders. validate_report_data.py + render_report.py
take it from there.

## Usage (CLI)

```bash
python3 forensic_pipeline.py 0x595deaad1eb5476ff1e649fdb7efc36f1e4679cc
# -> writes report_data_skeleton.json to ./
```

Or with explicit output:
```bash
python3 forensic_pipeline.py --ca 0x... --out /tmp/skeleton.json
```

## v0.6 phase 1 scope (this commit)

Implements Section A (scope) + Rule 11 (backward trace + evidence graph +
waves_proposal). Remaining sections (F/L/M/anomaly/liq/cex/tge/alloc/etc)
will be wired in subsequent commits — pipeline is designed to grow without
re-architecting.

v0.6 (2026-05-24)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "helpers"))

from _version import __version__ as SKILL_VERSION
from evidence_graph import EvidenceGraph
from section_a_scope import run as section_a_run
from chain_router import (  # v0.7.20 / v0.7.21.7 / v0.7.21.8
    set_active_chain,
    UnsupportedChainError,
    get_active_chain,
    sql_supported as _chain_sql_supported,
    requires_holder_snapshot as _chain_requires_holder_snapshot,
)


# v0.7.21.8: surf onchain-sql skip-reason. Used by sections whose SQL
# would target a non-existent `agent.{chain}_*` table (currently only
# Solana). render_report.py and i18n surface this verbatim so the
# user can tell "0 hits because forensic detector didn't find anything"
# apart from "section never ran because surf has no SQL coverage on
# this chain".
_SOLANA_SQL_SKIP_REASON = "surf_no_sql_solana"


def _holder_snapshot_empty_rule11() -> dict:
    """v0.7.21.8: empty rule_11 result that survives every downstream
    consumer (alloc, distribution, monitoring, render). Distinct from
    v0.7.1's mint-outside-90d degradation via `_skip_reason` so the
    report banner can tell "deployer trace failed" apart from "Solana
    has no surf SQL"."""
    return {
        "deployer": None,
        "mint_evt_ref": None,
        "mint_ts": None,
        "pre_launch_receivers": [],
        "quiet_wallets": [],
        "dumper_destinations": {},
        "waves_proposal": [],
        "summary_text": "",
        "_trace_unavailable": True,
        "_skip_reason": _SOLANA_SQL_SKIP_REASON,
    }


def _holder_snapshot_empty_anomaly() -> dict:
    return {
        "n_recent_events": 0,
        "wave3_proposal": None,
        "actors": [],
        "_skip_reason": _SOLANA_SQL_SKIP_REASON,
    }


def _holder_snapshot_empty_dump_tracking() -> dict:
    return {
        "insider_n_wallets": 0,
        "confirmed_cex_tokens": 0, "confirmed_dex_tokens": 0,
        "confirmed_total_tokens": 0, "confirmed_total_pct": None,
        "confirmed_est_profit_usd": None, "confirmed_capped": False,
        # v0.7.21.10: Net Sell Out fields — None on holder-snapshot chains
        # (no surf SQL coverage means no DEX swap aggregation possible).
        "confirmed_net_sellout_usd": None,
        "confirmed_dex_real_usd": None,
        "confirmed_cex_estimated_usd": None,
        "apparatus_dex_twap_usd_per_token": None,
        "net_above_gross_pct": None,
        "tree_holds_tokens": 0, "tree_holds_pct_supply": None,
        "pure_insider_holds_tokens": 0, "pure_insider_holds_pct_supply": None,
        "insider_holds_tokens": 0, "insider_holds_pct_supply": None,
        "buckets_complete": False,
        "top_seller_addrs": [],
        "_skip_reason": _SOLANA_SQL_SKIP_REASON,
    }


def _holder_snapshot_empty_cross_sym() -> dict:
    return {
        "_pipeline_source": "section_cross_sym",
        "whales": [],
        "summary_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        "_scope": None,
        "_registry_age_secs": None,
        "_credits_used": 0,
        "_skip_reason": _SOLANA_SQL_SKIP_REASON,
    }


def _holder_snapshot_empty_wash_infra() -> dict:
    return {
        "_pipeline_source": "section_wash_infra",
        "setups": [],
        "summary_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        "_credits_used": 0,
        "_skip_reason": _SOLANA_SQL_SKIP_REASON,
        "_truncated": False,
        "_truncation_meta": None,
        # v0.7.21.8: render template uses `_n_candidates_scanned` in its
        # "0 hits" banner; supply 0 so the StrictUndefined check passes
        # before the template's skip-reason branch swaps the message text.
        "_n_candidates_scanned": 0,
    }


def _holder_snapshot_empty_flow_operators() -> dict:
    return {
        "_pipeline_source": "section_flow_operators",
        "operators": [],
        "summary_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        "_credits_used": 0,
        "_skip_reason": _SOLANA_SQL_SKIP_REASON,
        # v0.7.21.8: render template reads this field on the 0-hit branch.
        # Provide 0 so the StrictUndefined check passes.
        "_n_candidates_scanned": 0,
    }


def _norm_addr(a) -> str:
    """v0.7.21.7: chain-aware address normalization for set membership.

    EVM lowercases (case-insensitive). Solana base58 preserves case
    (System Program & SPL token addresses are case-sensitive). Returns
    "" for falsy / non-string inputs so caller dedupe logic still works.
    """
    if not isinstance(a, str) or not a:
        return ""
    return a if get_active_chain() == "solana" else a.lower()
from rule_11_backward_trace import run_backward_trace
from dump_tracker import run as dump_tracker_run
from section_anomaly_72h import run as section_anomaly_run
from section_cex_trace import run as section_cex_trace_run
from section_liq import run as section_liq_run, discover_main_pool
from section_tge import run as section_tge_run
from section_alloc import run as section_alloc_run
from section_multi_chain import run as section_multi_chain_run
from section_f_holders import run as section_f_holders_run
from section_l_distribution import run as section_l_distribution_run
from section_cross_sym import run as section_cross_sym_run   # v0.7
from section_wash_infra import run as section_wash_infra_run   # v0.7.7
from section_flow_operators import (
    run as section_flow_operators_run,
    fetch_alpha_token_cas as _fetch_alpha_token_cas,
    fetch_alpha_token_meta as _fetch_alpha_token_meta,
)  # v0.7.21 / .2
from funding_source_attribution import (
    attribute_funding as _attribute_funding,
    query_mining_fed_outflows as _query_mining_fed_outflows,  # v0.7.23.2
    discover_mint_authorities as _discover_mint_authorities,  # v0.7.24a
    discover_high_throughput_dumpers as _discover_high_throughput_dumpers,  # v0.7.24b
    discover_cex_fanout_hubs as _discover_cex_fanout_hubs,  # v0.7.24e
)  # v0.7.23.1
import monitoring_export
sys.path.insert(0, str(Path(__file__).parent / "helpers"))
from i18n import t as _i18n_t, get_lang as _i18n_get_lang   # v0.6.2 i18n


def _days_since(date_str: str | None) -> int:
    """Days since YYYY-MM-DD until now. Returns 99999 if date is None."""
    if not date_str:
        return 99999
    try:
        from datetime import date, datetime, timezone
        d = date.fromisoformat(date_str)
        now = datetime.now(tz=timezone.utc).date()
        return (now - d).days
    except (ValueError, TypeError):
        return 99999


def _derive_verdict_enum(rule11: dict, anomaly72: dict) -> tuple[str, str, str]:
    """Pipeline-derive verdict.enum from raw signals (no LLM, no freelancing).

    Returns (enum, cn_label, baseline).

    Heuristic (intentionally simple — v0.7 may refine):
    - If Rule 11 found quiet wallets holding >= 5M tokens: EXIT_IF_HOLDING
    - If any pre_launch_receiver has dumped_pct >= 95% with non-trivial size:
      EXIT_IF_HOLDING (active distribution detected)
    - If anomaly72 has >= 10 events: EXIT_IF_HOLDING
    - If anomaly72 has >= 3 events: WAIT
    - Otherwise: ADVISORY
    """
    # v0.7.10.3: exclude project-side / infra lockups (vesting / multisig /
    # treasury / DEX-infra / CEX-custody, per Arkham) — they are not insider
    # hoarding. Previously COLLECT's 79% vesting contract and the Binance
    # omnibus custody wallet flipped these signals True.
    quiet_with_size = any(
        r["dumped_pct"] == 0
        and r["received_from_deployer"] >= 5_000_000
        and not r.get("is_protocol_lockup", False)
        for r in rule11.get("pre_launch_receivers", [])
    )
    active_full_dumper = any(
        r.get("dumped_pct") is not None and r["dumped_pct"] >= 95
        and r["received_from_deployer"] >= 5_000_000
        and not r.get("is_protocol_lockup", False)
        for r in rule11.get("pre_launch_receivers", [])
    )
    recent_n = anomaly72.get("n_recent_events", 0)

    # v0.6.2: cn_label looked up via i18n (verdict.cn_label.<ENUM>).
    if quiet_with_size or active_full_dumper or recent_n >= 10:
        enum = "EXIT_IF_HOLDING"
        return (enum, _i18n_t(f"verdict.cn_label.{enum}"), "AVOID")
    if recent_n >= 3:
        enum = "WAIT"
        return (enum, _i18n_t(f"verdict.cn_label.{enum}"), "WAIT")
    enum = "ADVISORY"
    return (enum, _i18n_t(f"verdict.cn_label.{enum}"), "ADVISORY")


def _derive_action_enum(verdict_enum: str) -> str:
    """Map verdict.enum → decision_action_block.immediate_action.action_enum."""
    return {
        "ENTER": "buy",
        "HOLD": "hold",
        "WAIT": "wait",
        "AVOID": "wait",
        "EXIT_IF_HOLDING": "sell",
        "ADVISORY": "wait",
        "INSUFFICIENT_DATA": "wait",
    }.get(verdict_enum, "wait")


def _receiver_infra_kind(r: dict) -> str | None:
    """'cex' / 'dex' if a rule_11 receiver is NEUTRAL infra (exchange custody / DEX
    pool — not a project insider), else None. Used everywhere a rule_11 receiver
    feeds an insider/operator set (monitoring roles, pre-launch / dumper detector
    counts, canonical-chain operator set, primary-sale seed) so listing-channel +
    liquidity wallets stay out. Vesting / multisig / treasury are NOT neutral —
    they are operator-controlled.

    Trusts the upstream is_cex_custody / is_dex_infra flags (now reliable: the source
    classifier `classify_protocol_lockup` excludes VC arms like "Binance Labs" from
    CEX and requires a yield/DEX protocol for a bare "Vault", so a VC investor /
    operator vault is NOT dropped), then re-derives strictly from the Arkham label
    for receivers whose enrich path left the flags unset."""
    if r.get("is_cex_custody"):
        return "cex"
    if r.get("is_dex_infra"):
        return "dex"
    lbl = r.get("arkham_label")
    if lbl:
        try:
            from surf_labels_probe import neutral_infra_kind
            return neutral_infra_kind(lbl, lbl, None)
        except Exception:
            return None
    return None


def _build_monitoring_wallets(rule11: dict, anomaly72: dict, eg,
                              distribution: dict | None = None,
                              cross_sym: dict | None = None,
                              flow_operators: dict | None = None) -> list[dict]:
    """Pipeline emits the monitoring_wallets list. LLM only fills .alert narrative.

    Priority list:
    1. Deployer (always #1)
    2. Each m6.row (Rule 11 quiet, partial dumper, full dumper)
    3. Cross-sym mega-wallets (v0.7.3 fix — top-100 holders that also hold
       ≥N other Alpha tokens; deterministic forward-detection of
       cross-token operators / KOL managers / desk wallets)
    4. OPERATOR_RELAY wallets from distribution (dumper-destinations holding
       ≥1% supply)
    5. Top 5 distinct actors from 72h anomaly events (deduped against above)
    6. v0.7.21.1: ALL flow_operators (60+ for PLAY) — every detected
       single-operator / cross-Alpha / async-wash wallet enters the
       monitoring list so monitoring_paste.json carries them. The
       report shows top 10 inline with narrative; the rest live in the
       paste file so the user never has to read skeleton.json.
    """
    wallets = []
    n = 1

    # 1. Deployer (balance assumed 0 — pipeline doesn't query deployer balance;
    #    if downstream filter needs proof, it has status_emoji + role text.)
    deployer = rule11.get("deployer")
    if deployer:
        wallets.append({
            "n": n,
            "addr_short": deployer[:10],
            "addr_full": deployer,
            "role": _i18n_t("monitoring.role_deployer_full"),
            "status_emoji": "🟡",
            # beta.12: balance_tokens added for monitoring_export filter
            # (drop wallets where balance==0 AND no recent activity).
            # Deployer balance is typically 0 in v0.6 pipeline output.
            "balance_tokens": 0,
            "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
        })
        n += 1

    # 2. Each m6 row
    seen_addrs = {_norm_addr(deployer)} if deployer else set()
    for r in rule11.get("pre_launch_receivers", []):
        addr = _norm_addr(r["addr"])
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)
        # Identity-aware relabel: a deployer-receiver that is actually CEX custody
        # (e.g. "Binance Wallet" — the Alpha listing channel) or a DEX pool (the
        # deployer seeding liquidity) is NOT a project insider and must not be shown
        # as "项目方内幕分发". Trust the upstream infra flags, but defensively
        # re-derive from the Arkham label too — enrich paths differ in which flags
        # they set, e.g. a bare "V3 Pool" can arrive with is_dex_infra unset. Setting
        # arkham_classification / entity makes monitoring_ranker canonicalize the
        # wallet to dex_pool / public_cex_hot_wallet instead of deployer/insider.
        _lbl = r.get("arkham_label")
        _infra = _receiver_infra_kind(r)   # 'cex' / 'dex' / None (NOT vesting/treasury)
        _w = {
            "n": n,
            "addr_short": r["addr"][:10],
            "addr_full": r["addr"],
            "balance_tokens": float(r.get("current_balance") or 0),
            "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
        }
        if _infra == "cex":
            _w["role"] = _i18n_t("monitoring.role_cex_custody", label=(_lbl or "CEX"))
            _w["status_emoji"] = "⚪"
            _w["arkham_classification"] = "CEX_HOT_WALLET"
            _w["arkham_entity_name"] = _lbl or ""
        elif _infra == "dex":
            _w["role"] = _i18n_t("monitoring.role_dex_pool", label=(_lbl or "DEX"))
            _w["status_emoji"] = "⚪"
            _w["arkham_classification"] = "DEX_POOL"
            _w["arkham_entity_name"] = _lbl or ""
        else:
            # `or 0`: unknown (unconfirmed-backfill) dumped_pct → 0 so the comparisons
            # + `dp=` kwargs can't crash on None (v0.7.13 defense-in-depth).
            dp = r.get("dumped_pct") or 0
            if dp == 0.0:
                _w["role"] = _i18n_t("monitoring.role_quiet_full_with_balance",
                                     balance=r["current_balance"])
                _w["status_emoji"] = "🔴"
            elif dp >= 95.0:
                _w["role"] = _i18n_t("monitoring.role_full_dumper_with_pct", dp=dp)
                _w["status_emoji"] = "🟢"  # green: largely past
            else:
                _w["role"] = _i18n_t("monitoring.role_partial_with_pct", dp=dp)
                _w["status_emoji"] = "🟠"
        wallets.append(_w)
        n += 1

    # 3. Cross-sym mega-wallets (v0.7.3) — top-100 holders that also hold
    #    significant positions in other Alpha tokens. These are the highest-
    #    value forward-tracking targets: cross-token operators / KOL
    #    managers / desk wallets. Surface all of them (typically 0-5 per
    #    token) so the user can monitor exit moves across the cohort.
    cross_sym_count = 0
    if cross_sym:
        for whale in (cross_sym.get("whales") or []):
            addr = _norm_addr(whale.get("address") or "")
            if not addr or addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            pct = whale.get("this_token_pct") or 0
            n_cross = whale.get("cross_sym_count") or 0
            cls = whale.get("identity_classification_enum") or "UNKNOWN_WHALE"
            wallets.append({
                "n": n,
                "addr_short": addr[:10],
                "addr_full": addr,
                "role": _i18n_t(
                    "monitoring.role_cross_sym_whale",
                    pct=pct, n_cross=n_cross, cls=cls,
                ),
                "status_emoji": "🟣",   # purple — cross-token mega
                "balance_tokens": float(whale.get("this_token_balance") or 0),
                "cross_sym_count": n_cross,
                "identity_classification_enum": cls,
                "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
            })
            n += 1
            cross_sym_count += 1

    # 4. OPERATOR_RELAY wallets from distribution (beta.3 fix: dumper
    #    destinations holding ≥1% supply are insider concentration points,
    #    NOT retail fan-out. Surface ALL of them, not just the top one.)
    relay_count = 0
    if distribution:
        for member in distribution.get("operator_relay_members", []):
            addr = _norm_addr(member.get("addr") or "")
            if not addr or addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            pct = member.get("pct_of_total") or 0
            wallets.append({
                "n": n,
                "addr_short": addr[:10],
                "addr_full": addr,
                "role": _i18n_t("monitoring.role_operator_relay_with_pct", pct=pct),
                "status_emoji": "🔴",
                "balance_tokens": float(member.get("balance") or 0),
                "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
            })
            n += 1
            relay_count += 1

    # 5. Top 5 distinct actors from 72h anomaly
    for actor_addr in (anomaly72.get("actors") or [])[:50]:
        if actor_addr in seen_addrs:
            continue
        # Skip zero address (mint events) and obvious system addresses
        if actor_addr in ("0x0000000000000000000000000000000000000000", "0x"):
            continue
        seen_addrs.add(actor_addr)
        wallets.append({
            "n": n,
            "addr_short": actor_addr[:10],
            "addr_full": actor_addr,
            "role": _i18n_t("monitoring.role_anomaly_72h"),
            "status_emoji": "🟡",
            # 72h actors: balance unknown but recent activity is the signal,
            # not balance. Filter keeps these regardless of balance.
            "balance_tokens": None,
            "recent_activity_72h": True,
            "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
        })
        n += 1
        # v0.7.3: include cross_sym_count in the cap so cross-sym whales
        # don't push out 72h actors.
        if n > 1 + len(rule11.get("pre_launch_receivers", [])) + cross_sym_count + relay_count + 5:
            break

    # 6. v0.7.21.1: all flow_operators enter monitoring. The summary table
    # in the report shows top 10 with narrative; the rest (PLAY case ~52)
    # live here so monitoring_paste.json includes them. Without this step
    # the user would have to read skeleton.json to track the long tail,
    # which the design explicitly rules out.
    if flow_operators:
        for op in (flow_operators.get("operators") or []):
            addr = _norm_addr(op.get("addr") or "")
            if not addr or addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            sub = op.get("sub_class") or "UNCLASSIFIED_SINGLE_OPERATOR"
            n_tx = op.get("n_tx_this_token") or 0
            n_alpha = op.get("cross_alpha_token_count") or 0
            wallets.append({
                "n": n,
                "addr_short": addr[:10],
                "addr_full": addr,
                "role": _i18n_t(
                    "monitoring.role_flow_operator",
                    sub=sub, n_tx=n_tx, n_alpha=n_alpha,
                ),
                "status_emoji": "🤖",
                # Flow operators have low net inventory by definition —
                # the signal is FLOW not balance, so balance is OK to
                # carry as-is; monitoring_export's balance filter is
                # bypassed via the recent_activity flag below.
                "balance_tokens": float(op.get("net_balance_this_token") or 0),
                "recent_activity_72h": True,
                "sub_class": sub,
                "alert": "<LLM_NARRATIVE_PLACEHOLDER>",
            })
            n += 1

    return wallets


def _fetch_current_price_usd(pair_address: str | None) -> float | None:
    """Best-effort current price via DexScreener pair lookup. Returns None
    on any failure — caller's pipeline shouldn't break on price-fetch errors.
    """
    if not pair_address:
        return None
    import subprocess
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", "5",
             f"https://api.dexscreener.com/latest/dex/pairs/bsc/{pair_address}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        )
        if proc.returncode != 0:
            return None
        doc = json.loads(proc.stdout)
        price = (doc.get("pair") or {}).get("priceUsd")
        return float(price) if price else None
    except Exception:
        return None


def build_skeleton(
    ca: str,
    alpha_listing_date: str | None = None,
    checkpoint_path: Path | None = None,
) -> dict:
    """Run full pipeline + return report_data_skeleton dict.

    `alpha_listing_date` optional — pipeline derives it from Section A's
    Alpha API result if not provided.

    v0.7.17: `checkpoint_path` — if given, the pipeline writes a partial
    skeleton dump to this path after every section completes. A long tail
    section (wash_infra_detector, cross_sym) being interrupted no longer
    leaves the user with zero artifact — they still have the partial.
    """
    t_start = time.perf_counter()
    timings: dict[str, float] = {}
    raw_sections: dict[str, "object"] = {}

    # v0.9.4: snapshot surf credit cumulative state BEFORE any sections
    # run. Pipeline finalization (return path) subtracts to get this CA's
    # credit usage. Long-lived daemons that build_skeleton multiple times
    # need this delta — module-global counter would otherwise add prior
    # runs into the current CA's number.
    try:
        # NOTE: use bare `section_a_scope` import (NOT `helpers.section_a_scope`).
        # Python caches modules by import name — `helpers.section_a_scope` and
        # `section_a_scope` resolve to TWO module instances even though backed
        # by the same .py file. parallel_surf's lazy hook writes to the bare
        # name; pipeline must read the same instance.
        from section_a_scope import _surf_credit_snapshot as _credit_snap
        _credits_before_snapshot = _credit_snap()
    except Exception:
        _credits_before_snapshot = {
            "credits": 0.0, "calls": 0, "seconds": 0.0, "attempts": 0,
        }

    # v0.7.20 adversarial review Round 2 HIGH fix: reset the chain router to a known
    # default at the START of every build_skeleton call. In a single-shot
    # CLI this is a no-op (router defaults to "bsc"), but if a long-lived
    # process (daemon / batch wrapper) reuses the module between runs, a
    # prior call's chain leaks into this run. Resetting up front means
    # every build_skeleton starts from the same baseline regardless of
    # prior state, then routes to the Alpha-API chain after Section A.
    set_active_chain("bsc")

    def _ck(name: str, value):
        """Stash a section's raw output + (best-effort) write the partial
        skeleton to disk. Errors are logged but never block the pipeline.

        v0.7.17 audit MEDIUM #1: atomic write (temp + rename) so a
        SIGKILL during the write never leaves a torn JSON file that a
        downstream inspector would parse as gibberish.

        v0.7.23: emit a one-line per-section timing breakdown to stderr
        so live monitoring sees per-section cost without parsing JSON.
        Format: `[timing] section_x: 12.3s (total 45.6s)`.
        """
        raw_sections[name] = value
        section_t = timings.get(name)
        if section_t is not None:
            total_t = time.perf_counter() - t_start
            print(
                f"[timing] {name}: {section_t:.1f}s "
                f"(total {total_t:.1f}s)",
                file=sys.stderr, flush=True,
            )
        if checkpoint_path is None:
            return
        try:
            partial = {
                "_status": "in_progress",
                "_last_section_completed": name,
                "_pipeline_timings": dict(timings),
                "_raw_sections": raw_sections,
            }
            data = (
                json.dumps(partial, ensure_ascii=False, indent=2, default=str)
                .encode("utf-8")
            )
            tmp = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, checkpoint_path)  # atomic on POSIX + Windows
        except Exception as e:
            print(f"[checkpoint] write failed ({name}): {e}",
                  file=sys.stderr, flush=True)

    # Initialize evidence graph (single instance shared across all sections)
    eg = EvidenceGraph()

    # ---------- Round 0: Section A (scope confirmation + Spot graduation) ----------
    t = time.perf_counter()
    scope = section_a_run(ca)
    timings["section_a"] = time.perf_counter() - t
    _ck("section_a", scope)

    if not scope.get("scope_ok"):
        return {
            "_status": "abort",
            "_reason": scope.get("reason"),
            "_detail": scope.get("detail"),
            "_timings": timings,
        }

    # v0.7.20: route subsequent SQL helpers to the chain Alpha API reported
    # for this token. Pre-v0.7.20 every helper hardcoded `agent.bsc_transfers`,
    # so a Base / Ethereum / Arbitrum / Polygon / Optimism / Solana token
    # silently fell through to BSC tables and produced an empty forensic
    # report. The PLAY (chainId 8453, Base) rerun is what surfaced this gap;
    # see [[binance-alpha-v0720]] for the full incident write-up. Failure
    # to map the chain_id is fail-loud (raises UnsupportedChainError) — a
    # silent BSC fallback would re-create the exact bug we're fixing.
    #
    # adversarial review Round 2 MEDIUM fix: chain_id MUST be present here. If Section A
    # returned `scope_ok=True` but no chain_id, that's an Alpha API contract
    # violation we cannot route around. Treat as abort, not as "use whatever
    # the router was set to last run" (which would silently route to BSC
    # default in a fresh process, or to the prior run's chain in a long-
    # lived process — exactly the leak adversarial review round 2 flagged).
    chain_id = scope.get("chain_id")
    if not chain_id:
        return {
            "_status": "abort",
            "_reason": "missing_chain_id",
            "_detail": (
                "Section A returned scope_ok but no chain_id — Alpha API "
                "contract violation. Cannot route SQL safely."
            ),
            "_timings": timings,
        }
    try:
        active_chain = set_active_chain(chain_id)
    except UnsupportedChainError as e:
        return {
            "_status": "abort",
            "_reason": "unsupported_chain",
            "_detail": str(e),
            "_timings": timings,
        }
    scope["_active_chain"] = active_chain
    # v0.7.21.8: Solana has no surf onchain-sql coverage (no
    # `agent.solana_*` tables; verified 2026-06-02). Pipeline switches to
    # HOLDER_SNAPSHOT mode — SQL-based detectors (rule_11 / dump_tracker /
    # wash_infra / flow_operators / cross_sym / anomaly_72h / liq SQL /
    # tge LP-first-trade / l_distribution dumper-destinations) short-
    # circuit with `_skip_reason="surf_no_sql_solana"`. The REST-based
    # sections (section_a Alpha API, section_f_holders token-holders,
    # section_alloc, monitoring_export) still run normally.
    holder_snapshot_mode = _chain_requires_holder_snapshot()
    scope["_holder_snapshot_mode"] = holder_snapshot_mode
    scope["_sql_supported"] = _chain_sql_supported()

    # If caller didn't supply alpha_listing_date, use Alpha API's
    if alpha_listing_date is None:
        alpha_listing_date = scope.get("alpha_listing_date_utc")

    # ---------- Round 1: Rule 11 backward trace ----------
    # v0.7.21.8: skip entirely on chains without surf onchain-sql (Solana).
    # Pre-v0.7.21.8 the SQL hit UNKNOWN_TABLE error and rule_11 fell into
    # its `error` branch, which then degraded to the same empty payload —
    # but spent ~30s waiting for surf to return the error first. Short-
    # circuiting saves that round-trip and tags the skip with a distinct
    # reason so the report can explain it accurately.
    t = time.perf_counter()
    if holder_snapshot_mode:
        rule11 = _holder_snapshot_empty_rule11()
    else:
        rule11 = run_backward_trace(
            ca=ca,
            alpha_listing_date=alpha_listing_date,
            evidence_graph=eg,  # shared instance
        )
    timings["rule_11"] = time.perf_counter() - t
    _ck("rule_11", rule11)

    # v0.7.1: deployer-trace failure (mint event outside 90d window — common
    # for tokens listed >3 months ago) used to abort the entire pipeline.
    # Now we degrade gracefully: replace with empty trace, let downstream
    # sections (anomaly_72h, liq, cross_sym, holdings, ...) continue.
    # Cross-sym whale detection in particular does NOT need deployer trace.
    if "error" in rule11:
        rule11 = {
            "deployer": None,
            "mint_evt_ref": None,
            "mint_ts": None,
            "pre_launch_receivers": [],
            "quiet_wallets": [],
            "dumper_destinations": {},
            "waves_proposal": [],
            "summary_text": "",
            "_trace_unavailable": True,   # internal flag for downstream
        }

    # ---------- Round 2a: discover main pool + price (cheap, feeds Section ANOMALY usd_value) ----------
    t = time.perf_counter()
    pool_info = discover_main_pool(ca)
    price_usd = pool_info.get("price_usd")
    timings["pool_discovery"] = time.perf_counter() - t
    _ck("pool_discovery", pool_info)

    # ---------- Round 2b: Section ANOMALY (recent 24-72h, events get usd_value) ----------
    # v0.7.21.8: SQL-only — skip on Solana.
    t = time.perf_counter()
    if holder_snapshot_mode:
        anomaly72 = _holder_snapshot_empty_anomaly()
    else:
        anomaly72 = section_anomaly_run(
            ca=ca,
            evidence_graph=eg,
            threshold_token_amount=100_000,
            price_usd=price_usd,
        )
    timings["section_anomaly_72h"] = time.perf_counter() - t
    _ck("section_anomaly_72h", anomaly72)

    # ---------- Round 3: Section CEX-TRACE (Binance/Aster/Bitget perp probe) ----------
    # Refines tier_classification from S1 stub → real S1/S2/S3
    t = time.perf_counter()
    cex_trace = section_cex_trace_run(
        symbol=scope["symbol"],
        alpha_listing_date=alpha_listing_date,
    )
    timings["section_cex_trace"] = time.perf_counter() - t
    _ck("section_cex_trace", cex_trace)

    # ---------- Round 4: Section LIQ (Alpha 5% depth + DEX pool + LP 24h flow) ----------
    t = time.perf_counter()
    liq = section_liq_run(
        ca=ca,
        symbol=scope["symbol"],
        alpha_vol_24h_usd=scope.get("alpha_vol_24h_usd"),
        # v0.7.16: Alpha price fallback when surf project-detail is unavailable.
        alpha_price_usd=scope.get("alpha_price_usd"),
        # v0.7.10: pass scope's surf-realtime LP / token_info so section_liq
        # reads pool / price / vol from already-fetched data instead of
        # calling DexScreener.
        scope_chain_lp=scope.get("chain_lp_realtime"),
        scope_realtime_token_info=scope.get("realtime_token_info"),
        primary_chain=scope.get("primary_chain"),
    )
    timings["section_liq"] = time.perf_counter() - t
    _ck("section_liq", liq)

    # ---------- Round 5: section_tge + section_multi_chain + section_f_holders + section_alloc ----------
    # v0.7.20.2: section_f_holders moved EARLIER (was in Round 6) so its
    # burn_balance / burn_pct_of_supply can feed into section_alloc as
    # a dedicated "已销毁" row. Pre-v0.7.20.2 the burn tokens (PLAY: 1B
    # = 20% of supply at 0xdead) were silently dropped from top_holders
    # and the user could only spot the 20% sitting at 0xdead by reading
    # the cross_sym whales section — where they wrongly appeared as a
    # "candidate operator", because 0xdead matches across most Alpha
    # tokens (every burn-and-deploy template uses the same address).
    t = time.perf_counter()
    tge = section_tge_run(
        ca=ca,
        alpha_listing_ts_ms=scope.get("alpha_listing_ts_ms"),
        pool_addr=liq.get("dex_pool_addr"),
        current_price_usd=liq.get("current_price_usd"),
    )
    holders = section_f_holders_run(
        ca=ca,
        listing_date=scope.get("alpha_listing_date_utc"),
        # v0.7.21.9: on holder-snapshot chains prefer the on-chain
        # `chain_total_supply_ui` (Solana RPC `getTokenSupply`) over the
        # Alpha API snapshot. They drift on inflationary mints — JELLYJELLY
        # ships 999,966,701 on-chain vs 999,999,099 Alpha — and using the
        # chain value keeps the % math consistent with the normalised
        # balance below.
        total_supply=(
            scope.get("chain_total_supply_ui")
            if scope.get("chain_total_supply_ui") is not None
            else scope.get("total_supply")
        ),
        limit=50,
        # v0.7.21.9: SPL decimals so the helper can divide raw lamport
        # balances surf token-holders returns. None on EVM (already
        # normalised) and on Solana-RPC fallback (then we surface raw
        # lamports with no divisor — same as v0.7.21.8 behaviour).
        chain_decimals=scope.get("chain_decimals"),
    )
    alloc = section_alloc_run(
        total_supply=scope.get("total_supply"),
        circulating_supply=scope.get("circulating_supply"),
        rule11=rule11,
        current_price_usd=liq.get("current_price_usd"),
        burn_balance=holders.get("burn_balance"),
        burn_pct_of_supply=holders.get("burn_pct_of_supply"),
    )
    multi_chain = section_multi_chain_run(
        chain_label=scope["chain_label"],
        total_supply=scope.get("total_supply"),
        # v0.7.14 (issue #1): align MULTI-CHAIN with the banner's primary_chain
        # so a cross-chain mirror (ZEST → stacks) isn't reported as BSC single-chain.
        # v0.7.21.8: prefer the active SQL-routing chain on holder-snapshot
        # chains so we don't report a Base wrapper for a Solana token.
        primary_chain=(
            get_active_chain() if holder_snapshot_mode
            else scope.get("primary_chain")
        ),
        holder_snapshot_mode=holder_snapshot_mode,
    )
    timings["section_tge_alloc_multi_chain"] = time.perf_counter() - t
    _ck("section_tge_alloc_multi_chain", {"tge": tge, "alloc": alloc, "multi_chain": multi_chain, "holders": holders})

    # ---------- Phase 2: entity-level sell tracking (真实派发 Sell-to-CEX/DEX) ----------
    # Post-processes rule_11's already-fetched graph (0 new transfer SQL):
    # classifies dumper destinations via Arkham, sums flow into CEX/DEX sell
    # terminals, values via one market-price series query. Distinct from
    # wallet-level dumped_pct (which counts any transfer as "distributed").
    t = time.perf_counter()
    if holder_snapshot_mode:
        # v0.7.21.8: dump_tracker is entirely SQL-based — skip on Solana.
        dump_tracking = _holder_snapshot_empty_dump_tracking()
    else:
        try:
            dump_tracking = dump_tracker_run(
                rule11=rule11,
                ca=ca,
                symbol=scope.get("symbol"),
                listing_ts_ms=scope.get("alpha_listing_ts_ms"),
                listing_date=scope.get("alpha_listing_date_utc"),
                circulating_supply=scope.get("circulating_supply"),
                total_supply=scope.get("total_supply"),
                # v1.2.5: reliable spot price to sanity-bound the DEX-derived
                # per-token price (guards non-18-decimal USD overflow, e.g. SLX).
                spot_price_usd=liq.get("current_price_usd"),
            )
        except Exception as e:
            import sys as _sys
            print(f"[dump_tracker] failed (non-fatal): {e}", file=_sys.stderr)
            # v0.7.12: fallback must use the CURRENT Opt1 keys (not legacy
            # clusters/total_sold_*) and carry _error so a hard failure surfaces as
            # "data unavailable", not a silent "0 confirmed sold" (adversarial review LOW #6).
            dump_tracking = {
                "insider_n_wallets": 0,
                "confirmed_cex_tokens": 0, "confirmed_dex_tokens": 0,
                "confirmed_total_tokens": 0, "confirmed_total_pct": None,
                "confirmed_est_profit_usd": None, "confirmed_capped": False,
                # v0.7.21.10: Net Sell Out fields — None on dump_tracker failure
                # so render template `is not none` checks gracefully skip rows.
                "confirmed_net_sellout_usd": None,
                "confirmed_dex_real_usd": None,
                "confirmed_cex_estimated_usd": None,
                "apparatus_dex_twap_usd_per_token": None,
                "net_above_gross_pct": None,
                # v0.7.19.4: include the new split fields in the fallback
                # so render template can rely on them being present.
                "tree_holds_tokens": 0, "tree_holds_pct_supply": None,
                "pure_insider_holds_tokens": 0, "pure_insider_holds_pct_supply": None,
                "insider_holds_tokens": 0, "insider_holds_pct_supply": None,
                "buckets_complete": False, "_error": str(e)[:200],
            }
    timings["dump_tracker"] = time.perf_counter() - t
    _ck("dump_tracker", dump_tracking)

    # ---------- Round 6: section_l_distribution (Phase B.4) ----------
    # v0.7.20.2: section_f_holders moved into Round 5 so its burn_balance
    # can feed section_alloc. Round 6 keeps section_l_distribution which
    # consumes the same top_holders.
    t = time.perf_counter()
    distribution = section_l_distribution_run(
        top_holders=holders["top_holders"],
        rule11=rule11,
        dex_pool_addr=liq.get("dex_pool_addr"),
        # v0.7.21.9: same chain_total_supply preference as section_f_holders
        # so the % math stays consistent (both helpers sum normalised
        # balances now).
        total_supply=(
            scope.get("chain_total_supply_ui")
            if scope.get("chain_total_supply_ui") is not None
            else scope.get("total_supply")
        ),
        current_price_usd=liq.get("current_price_usd"),
        eg=eg,
    )
    timings["section_f_l_distribution"] = time.perf_counter() - t
    _ck("section_f_l_distribution", {"holders": holders, "distribution": distribution})

    # ---------- Round 7: section_cross_sym (Phase v0.7) ----------
    # Forward-detect cross-sym whale candidates (e.g. 0xb5893a55 type:
    # single wallet that's a top-100 holder across many Alpha tokens).
    # Side-effect: also appends the current report's m6_rows to the
    # local pre_launch_insider index for future cross-sym lookups.
    t = time.perf_counter()
    # Collect counterparty class hints used by identity_classifier signature SQL
    cex_hot_addrs = set()
    for h in holders.get("top_holders", []):
        if h.get("entity_type") == "cex":
            addr = _norm_addr(h.get("address") or "")
            if addr:
                cex_hot_addrs.add(addr)
    dex_pool_addrs = set()
    if liq.get("dex_pool_addr"):
        dex_pool_addrs.add(_norm_addr(liq["dex_pool_addr"]))
    deployer_addrs = set()
    if rule11.get("deployer"):
        deployer_addrs.add(_norm_addr(rule11["deployer"]))
    op_relay_addrs = [
        m.get("addr", "") for m in (distribution.get("operator_relay_members") or [])
        if m.get("addr")
    ]
    # v0.8.4.9: cross_sym 整段 skip (render 已删, registry refresh 也 disabled).
    # 抓到的 wallet 多是 router / MEV bot, 真"跨币种庄家"罕见 (< 5%).
    # 节省 ~30 credits/run + cold-start 190 credits (registry build).
    cross_sym = _holder_snapshot_empty_cross_sym()
    timings["section_cross_sym"] = time.perf_counter() - t
    _ck("section_cross_sym", cross_sym)

    # ---------- Round 7b: section_wash_infra (v0.7.7) ----------
    # 5-step pure on-chain wash infrastructure detection (no Arkham label
    # dependency). Replaces v0.7.5's narrow wash_distributor_probe (which
    # was empirically misclassifying DEX pools as operator EOAs). Scans
    # top-100 holders minus benign infra (CEX hot wallets, DEX pools,
    # deployer) for the X / P / Q wash triplet signature.
    # v0.8.4.9.9: section_wash_infra 整段 skip (render 已删).
    # 用户 review: Alpha 类 token 用户默认 expect wash trade, "对敲占 X%"
    # 数字对决策无价值. 庄家筹码状况 / 内幕变现 / mint_authority 持仓
    # 都跟 wash_infra detector 无关. 节省 ~350 credits/token (~70%
    # wash budget) ≈ $1.75/token. 跟 v0.8.4.9 删 flow_operators +
    # cross_sym 同 pattern.
    t = time.perf_counter()
    wash_infrastructure = _holder_snapshot_empty_wash_infra()
    timings["section_wash_infra"] = time.perf_counter() - t
    _ck("section_wash_infra", wash_infrastructure)

    # ---------- Round 7c: section_flow_operators (v0.7.21) ----------
    # Flow-based wallet detector — catches cross-Alpha trading operators
    # and single-operator asynchronous wash (P→X→Q across separate txs).
    # Both are invisible to v0.7.20.2: cross_sym is stock-based, wash_infra
    # requires atomic_pair_ratio ≥ 0.85. See v0721_DESIGN.md.
    #
    # Candidate union = top-50 holders (already fetched) + dump_tracker's
    # top-200 DEX sellers (already fetched). Three batch SQL queries on
    # the union (no per-candidate calls) + one Arkham label batch.
    # Excluded set mirrors cross_sym (m6 / op-relay / burn / cex_hot).
    # v0.8.4.9: section_flow_operators 整段 skip (render 已删).
    # 用户 review: 实际抓的 wallet 多是 PancakeSwap router MEV/sandwich bot,
    # 不是项目方操盘, 对决策无价值. 节省 ~10 credits + 1.5-2s wall time.
    t = time.perf_counter()
    flow_operators_block = _holder_snapshot_empty_flow_operators()
    timings["section_flow_operators"] = time.perf_counter() - t
    _ck("section_flow_operators", flow_operators_block)

    # ---------- Round 8: Funding source attribution (v0.7.23.1) ----------
    # Reverse-direction classifier for the high-value addresses surfaced by
    # earlier rounds (wash_infra P/Q/X, flow_operators, rule_11 receivers,
    # top_holders). One batch SQL: classifies each address's INCOMING token
    # by source — mint (= 0x0, e.g. bridge / staking / airdrop mint contract,
    # i.e. "矿币" distribution), dex_buy (= known DEX pair pool), or p2p
    # (everything else, including CEX withdraws that we cannot label).
    #
    # The output `mint_pct` tells retail whether a wallet's balance came from
    # mining the token (high mint% = operator who mined an airdrop / sockpuppet
    # cluster) or from real DEX buy pressure (high dex_buy% = retail PnL-taker).
    # This is independent of how the token's distribution mechanism is
    # implemented — works the same for standard deployer-anchored tokens
    # (COLLECT, LAB), bridge mint authority tokens (Humanity / H), and
    # mining-airdrop tokens (Aethir-class). Replaces the abandoned forward
    # cluster-hub trace (see v0.7.23.1 design doc).
    t = time.perf_counter()
    high_value_addrs: list[str] = []
    seen_hv: set[str] = set()

    def _add_hv(addr_raw):
        if not addr_raw:
            return
        a = _norm_addr(addr_raw)
        if not a or a in seen_hv:
            return
        seen_hv.add(a)
        high_value_addrs.append(a)

    # wash_infra setup actors (P/Q + executor X)
    for _setup in (wash_infrastructure.get("setups") or []):
        for _k in ("maker_buy_P", "maker_sell_Q", "executor_X"):
            _add_hv(_setup.get(_k))
    # flow_operators full operator set
    for _op in (flow_operators_block.get("operators") or []):
        _add_hv(_op.get("addr"))
    # rule_11 m6 receivers (pre-launch insiders)
    for _r in (rule11.get("pre_launch_receivers") or []):
        _add_hv(_r.get("addr"))
    # dump_tracker top-seller addrs (real dumpers surfaced by dex_sell_profile —
    # may not overlap with m6 receivers when the token uses non-standard
    # distribution; audit M2 fix).
    for _seller in (dump_tracking.get("top_seller_addrs") or []):
        _add_hv(_seller)
    # top holders top-30 (real-time concentration)
    for _h in (holders.get("top_holders") or [])[:30]:
        _add_hv(_h.get("addr"))

    # Pre-cap snapshot for truncation visibility (audit M1 fix).
    _hv_pre_cap = len(high_value_addrs)

    # DEX pair pool addresses from realtime LP detector (section_a)
    dex_pair_addrs: list[str] = []
    _chain_lp = scope.get("chain_lp_realtime") or {}
    if isinstance(_chain_lp, dict):
        for _chain_data in _chain_lp.values():
            if isinstance(_chain_data, dict):
                _top = _chain_data.get("top_pool_addr")
                if _top:
                    dex_pair_addrs.append(_top)

    # date_floor: listing - 365d. Hardcoded window covers the vast majority of
    # pre/post-launch insider activity without bloating the SQL beyond surf's
    # 30s budget. Floor 2020-01-01 only if no listing date available.
    _listing_iso = scope.get("alpha_listing_date_utc")
    if _listing_iso:
        try:
            from datetime import date as _date, timedelta as _td
            _ld = _date.fromisoformat(_listing_iso[:10])
            _date_floor = (_ld - _td(days=365)).isoformat()
        except (ValueError, TypeError):
            _date_floor = "2020-01-01"
    else:
        _date_floor = "2020-01-01"

    try:
        if holder_snapshot_mode:
            # Solana: SQL detector skipped (no bsc_transfers analog).
            funding_attribution = {
                "attributions": {}, "summary": {
                    "n_addrs_queried": 0, "n_addrs_with_data": 0,
                    "n_mining_fed": 0, "n_dex_fed": 0,
                    "n_p2p_fed": 0, "n_cex_fed": 0,
                },
                "_skipped": _SOLANA_SQL_SKIP_REASON,
            }
        elif not high_value_addrs:
            funding_attribution = {
                "attributions": {}, "summary": {
                    "n_addrs_queried": 0, "n_addrs_with_data": 0,
                    "n_mining_fed": 0, "n_dex_fed": 0,
                    "n_p2p_fed": 0, "n_cex_fed": 0,
                },
                "_skipped": "no_high_value_addrs_surfaced",
            }
        else:
            funding_attribution = _attribute_funding(
                ca=scope["contract_address"],
                high_value_addrs=high_value_addrs,
                dex_pair_addrs=dex_pair_addrs,
                cex_addrs=None,  # v0.7.23.1: CEX label set TBD in v0.7.24 — for
                                 # now CEX withdraws fall under p2p (the report
                                 # surfaces this caveat in the funding section).
                date_floor=_date_floor,
                max_addrs=200,
            )
    except Exception as _e:
        import sys as _sys
        print(f"[funding_attribution] failed (non-fatal): {_e}", file=_sys.stderr)
        funding_attribution = {
            "attributions": {}, "summary": {
                "n_addrs_queried": len(high_value_addrs),
                "n_addrs_with_data": 0, "n_mining_fed": 0,
                "n_dex_fed": 0, "n_p2p_fed": 0, "n_cex_fed": 0,
            },
            "_error": str(_e)[:200],
        }

    # v0.7.23.2: follow-up — for each mining-fed address surfaced by
    # attribute_funding, query its DEX dump activity + top outflow destinations.
    # This recovers the (a)(b) confirmed-sell signal that dump_tracker misses
    # when rule_11's m6 trace is empty (mining/bridge token case: H, Aethir-
    # class, Polyhedra-class). The data is attached to funding_attribution
    # so the render template can show "operator X dumped Y tokens for $Z USD"
    # alongside the mint% column.
    if isinstance(funding_attribution, dict) and funding_attribution.get("attributions"):
        _mining_fed_addrs = [
            a for a, v in funding_attribution["attributions"].items()
            if v.get("is_mining_fed")
        ]
        if _mining_fed_addrs:
            try:
                _mfo = _query_mining_fed_outflows(
                    ca=scope["contract_address"],
                    mining_fed_addrs=_mining_fed_addrs,
                    date_floor=_date_floor,
                    max_addrs=30,
                )
                funding_attribution["mining_fed_outflows"] = _mfo
                import sys as _sys
                _mfo_sum = _mfo.get("summary", {})
                print(
                    f"[funding_attribution] mining_fed_outflows: "
                    f"{len(_mining_fed_addrs)} addrs queried, "
                    f"{_mfo_sum.get('n_addrs_with_dex_sells', 0)} with DEX sells, "
                    f"total ${_mfo_sum.get('total_dex_sold_usd', 0):,.0f} dumped",
                    file=_sys.stderr,
                )
            except Exception as _e:
                import sys as _sys
                print(
                    f"[funding_attribution] mining_fed_outflows failed (non-fatal): {_e}",
                    file=_sys.stderr,
                )
                funding_attribution["mining_fed_outflows"] = {
                    "per_addr": {}, "summary": {}, "_error": str(_e)[:200],
                }

    # v0.7.24a: mint authority discovery + their self-DEX-dump.
    # mint_authorities are bridge/staking/airdrop contracts that physically
    # receive 0x0 transfers (issue new supply). They typically don't appear
    # in funding_attribution.high_value_addrs (which surveys detector-
    # surfaced wallets), so the v0.7.23.x mining_fed_outflows path misses
    # them entirely. H run uncovered 0x6aa22cb8 (bridge) minted 132.5B
    # over 30d and self-DEX-dumped 19.8B (≈ $3M) — invisible until now.
    #
    # Exclusion logic: skip addrs already covered by mining_fed_outflows
    # (those got rolled into the (b) row) + skip deployer (rule_11 path).
    # Remaining authorities go through the same query_mining_fed_outflows
    # helper to fetch DEX sells + outflows + current balance.
    if isinstance(funding_attribution, dict) and scope.get("contract_address") and not holder_snapshot_mode:
        _mining_fed_addrs_set = {
            a for a, v in (funding_attribution.get("attributions") or {}).items()
            if v.get("is_mining_fed")
        }
        _deployer_addr = (rule11.get("deployer") or "")
        _exclude_for_auth = sorted(_mining_fed_addrs_set | ({_deployer_addr} if _deployer_addr else set()))
        try:
            _auth_disco = _discover_mint_authorities(
                ca=scope["contract_address"],
                date_floor=_date_floor,
                exclude_addrs=_exclude_for_auth,
                top_n=10,
                min_pct_supply=0.001,  # drop authorities < 0.1% nominal supply
                total_supply=scope.get("total_supply"),
            )
        except Exception as _e:
            import sys as _sys
            print(f"[funding_attribution] mint_authority discovery failed (non-fatal): {_e}",
                  file=_sys.stderr)
            _auth_disco = {"authorities": [], "summary": {}, "_error": str(_e)[:200]}

        funding_attribution["mint_authorities"] = _auth_disco

        # v0.7.24a.1: Arkham label resolution for mint authorities. Most are
        # v0.7.24e.2 (A3): mint authority labels deferred to single
        # consolidated batch at end of Round 8. Skip inline call — flagged
        # for post-hoc apply.

        # Step 2: for the non-excluded authorities, fetch their dump activity
        # using the same query_mining_fed_outflows helper (the per-addr +
        # summary + current_balance schema is identical).
        _auth_addrs_for_dump = [
            a["addr"] for a in (_auth_disco.get("authorities") or [])
            if not a.get("is_excluded")
        ]
        if _auth_addrs_for_dump:
            try:
                _auth_dump = _query_mining_fed_outflows(
                    ca=scope["contract_address"],
                    mining_fed_addrs=_auth_addrs_for_dump,
                    date_floor=_date_floor,
                    max_addrs=30,
                )
                # Stitch the disco mint_pct_supply data into per_addr so
                # render template can show "minted N% supply, dumped X".
                _disco_by_addr = {a["addr"]: a for a in (_auth_disco.get("authorities") or [])}
                for _addr, _v in (_auth_dump.get("per_addr") or {}).items():
                    _d = _disco_by_addr.get(_addr) or {}
                    _v["total_minted"] = _d.get("total_minted") or 0.0
                    _v["mint_pct_supply"] = _d.get("mint_pct_supply")
                    _v["n_mints"] = _d.get("n_mints") or 0
                funding_attribution["mint_authority_dumps"] = _auth_dump
                import sys as _sys
                _mad_sum = _auth_dump.get("summary", {})
                print(
                    f"[funding_attribution] mint_authority_dumps: "
                    f"{len(_auth_addrs_for_dump)} authorities, "
                    f"{_mad_sum.get('n_addrs_with_dex_sells', 0)} with DEX sells, "
                    f"total ${_mad_sum.get('total_dex_sold_usd', 0):,.0f} self-dumped",
                    file=_sys.stderr,
                )
            except Exception as _e:
                import sys as _sys
                print(f"[funding_attribution] mint_authority_dumps failed (non-fatal): {_e}",
                      file=_sys.stderr)
                funding_attribution["mint_authority_dumps"] = {
                    "per_addr": {}, "summary": {}, "_error": str(_e)[:200],
                }

    # v0.7.24b: high-throughput dump trace — find operator wallets that
    # received a meaningful allocation (1M-5% nominal supply) and dumped
    # ~all of it (balance ≈ 0) via many txs (n_tx ≥ 1000). Catches the
    # sss_crypto Twitter thread profile (0x47a6e4e1: 30M tokens / 79k tx
    # cleared out) which all v0.7.23.x detectors missed. Excludes addrs
    # already covered by mining_fed + mint_authority + deployer.
    if isinstance(funding_attribution, dict) and not holder_snapshot_mode:
        _ht_exclude = set(_exclude_for_auth) | {a["addr"] for a in (_auth_disco.get("authorities") or []) if not a.get("is_excluded")}
        try:
            _ht_disco = _discover_high_throughput_dumpers(
                ca=scope["contract_address"],
                date_floor=_date_floor,
                exclude_addrs=sorted(_ht_exclude),
                min_throughput=1_000_000.0,
                max_balance_frac=0.05,
                min_n_tx=1000,
                top_n=100,
                total_supply=scope.get("total_supply"),
            )
        except Exception as _e:
            import sys as _sys
            print(f"[funding_attribution] high_throughput discovery failed (non-fatal): {_e}",
                  file=_sys.stderr)
            _ht_disco = {"dumpers": [], "summary": {}, "_error": str(_e)[:200]}

        # v0.7.24e.2 (A3): high_throughput dumper labels deferred to
        # single consolidated batch at end of Round 8. is_infra + summary
        # recompute also deferred.
        _operator_dumpers = [
            d for d in (_ht_disco.get("dumpers") or [])
            if not d.get("is_excluded")
        ]
        _ht_disco["summary"] = {
            "n_dumpers": len(_operator_dumpers),
            "total_throughput": sum(d.get("total_in", 0) for d in _operator_dumpers),
            "n_dumpers_pre_filter": _ht_disco.get("summary", {}).get("n_dumpers", 0),
        }
        funding_attribution["high_throughput_dumpers"] = _ht_disco
        import sys as _sys
        print(
            f"[funding_attribution] high_throughput_dumpers: "
            f"{len(_operator_dumpers)} operator dumpers "
            f"(pre-infra-filter {len((_ht_disco.get('dumpers') or []))}), "
            f"total throughput {sum(d.get('total_in', 0) for d in _operator_dumpers):,.0f} tokens",
            file=_sys.stderr,
        )

    # v0.7.24a.1: resolve Arkham labels for top destinations of mining-fed
    # v0.7.24e.2 (A3): destination labels deferred to consolidated batch at
    # end of Round 8. Original logic was a separate resolve_labels call.
    # Now folded into the mega-batch + apply step below.
    if False and isinstance(funding_attribution, dict) and not holder_snapshot_mode:
        try:
            from surf_labels_probe import resolve_labels as _resolve_labels
            _dest_addrs: set[str] = set()
            for _mfo_key in ("mining_fed_outflows", "mint_authority_dumps"):
                _mfo_dict = funding_attribution.get(_mfo_key) or {}
                for _wallet, _wallet_data in (_mfo_dict.get("per_addr") or {}).items():
                    for _d in (_wallet_data.get("top_destinations") or []):
                        _dest = (_d.get("dest") or "").lower()
                        if _dest:
                            _dest_addrs.add(_dest)
            if _dest_addrs:
                _dest_labels = _resolve_labels(sorted(_dest_addrs))
                pass  # deferred (A3)
        except Exception as _e:
            import sys as _sys
            print(f"[funding_attribution] destination label resolve failed (non-fatal): {_e}",
                  file=_sys.stderr)

    # v0.7.24e: CEX deposit fan-out detection. sss_crypto Twitter thread
    # documented BEAT pattern (Gate.io hot wallet → 1 hub → 10 sub-wallets
    # each holding 0.1%+ supply). Operators pull allocation from CEX, route
    # through a hub, fan out to dispense the top100 concentration signal.
    # No existing detector catches this — rule_11 (deployer mint), wash_infra
    # (P/Q atomic), flow_operators (cross-Alpha 5+), mining_fed (mint primary),
    # mint_authority (from=0x0), high_throughput (n_tx >= 1000) all miss.
    # SSS_crypto BEAT verification: 2 confirmed hubs (KuCoin Deposit / MEXC
    # Deposit), 29 fan-out recipients, 1.88M tokens from CEX.
    if isinstance(funding_attribution, dict) and not holder_snapshot_mode:
        try:
            _fanout_disco = _discover_cex_fanout_hubs(
                ca=scope["contract_address"],
                date_floor=_date_floor,
                min_recipients=5, max_recipients=50,
                min_per_recipient=100_000.0,
                min_total_out=1_000_000.0,
                top_n_hubs=30,
                max_recipients_per_hub_display=20,
            )
            funding_attribution["cex_fanout_hubs"] = _fanout_disco
            import sys as _sys
            _fo_sum = _fanout_disco.get("summary", {})
            print(
                f"[funding_attribution] cex_fanout_hubs: "
                f"{_fo_sum.get('n_confirmed_hubs', 0)} confirmed CEX-source hubs "
                f"(from {_fo_sum.get('n_candidate_hubs', 0)} candidates), "
                f"{_fo_sum.get('total_fanout_recipients', 0)} fan-out recipients, "
                f"{_fo_sum.get('total_cex_inflow_tokens', 0):,.0f} tokens from CEX",
                file=_sys.stderr,
            )
        except Exception as _e:
            import sys as _sys
            print(f"[funding_attribution] cex_fanout_hubs failed (non-fatal): {_e}",
                  file=_sys.stderr)
            funding_attribution["cex_fanout_hubs"] = {
                "hubs": [], "summary": {}, "_error": str(_e)[:200],
            }

    # v0.7.24c: Multi-chain dump trace. CoinGecko platforms data tells us
    # which chains have this token deployed. For chains other than primary
    # (= where scope.contract_address lives), run mint authority + high-
    # throughput dumper detection. Catches Eleve's H finding: 0x9e995952
    # on Ethereum dumped 140M H ($22M USD), invisible to BSC pipeline.
    if isinstance(funding_attribution, dict) and scope.get("coingecko_platforms") and not holder_snapshot_mode:
        try:
            from chain_router import (
                chain_lock as _chain_lock,
                sql_supported as _sql_supported,
                get_active_chain as _get_active_chain,
            )
            # CoinGecko platform slug → chain_router prefix
            _CG_TO_CHAIN = {
                "ethereum": "ethereum",
                "binance-smart-chain": "bsc",
                "arbitrum-one": "arbitrum",
                "base": "base",
                "polygon-pos": "polygon",
                "optimistic-ethereum": "optimism",
            }
            _primary_chain = _get_active_chain()
            _cross_chain_results: dict[str, Any] = {}
            # v0.9.7 fix (FOLKS 9-chain 2026-06-16): gate cross-chain
            # forensic by LP threshold. FOLKS empirical: 7 non-primary
            # chains × full mint/throughput scan = +7 min, ALL return 0
            # because FOLKS only has meaningful activity on BSC + ETH +
            # Avalanche. Pre-v0.9.7 skill ran forensic on every CG-mapped
            # chain blindly. Now: skip chains with LP < $10K (no real
            # activity → no operator to find).
            _MULTI_CHAIN_MIN_LP_USD = float(
                os.environ.get("BINANCE_ALPHA_MULTI_CHAIN_MIN_LP_USD", "10000")
            )
            _chain_lp_realtime = scope.get("chain_lp_realtime") or {}
            for _cg_platform, _ca_on_chain in (scope.get("coingecko_platforms") or {}).items():
                _chain_short = _CG_TO_CHAIN.get(_cg_platform)
                if not _chain_short or _chain_short == _primary_chain:
                    continue
                if not _ca_on_chain:
                    continue
                # LP gate: skip chains with KNOWN-low liquidity. adversarial review
                # v0.9.7 Finding 5 (HIGH): distinguish "LP probe failed
                # (unknown)" from "LP genuinely low". A failed surf probe
                # leaves lp_usd=None — that is NOT evidence the chain is
                # dead, so we must NOT skip on it (would silently miss an
                # active chain whose probe flaked). Only skip when LP is
                # KNOWN and below threshold. Unknown LP → scan anyway
                # (correctness > speed for the unknown case).
                _chain_lp_entry = _chain_lp_realtime.get(_chain_short) or {}
                _lp_usd = _chain_lp_entry.get("lp_usd")
                _lp_probe_failed = bool(_chain_lp_entry.get("_error")) or (
                    _chain_lp_entry.get("surf_supported") and _lp_usd is None
                    and _chain_lp_entry.get("n_dex_pools") is None
                )
                if _lp_usd is not None and _lp_usd < _MULTI_CHAIN_MIN_LP_USD:
                    _cross_chain_results[_chain_short] = {
                        "ca": _ca_on_chain, "cg_platform": _cg_platform,
                        "_skipped": (
                            f"LP ${_lp_usd:.0f} < ${_MULTI_CHAIN_MIN_LP_USD:.0f} threshold "
                            f"— chain has no meaningful activity to forensic"
                        ),
                    }
                    continue
                if _lp_usd is None and not _lp_probe_failed:
                    # LP probe ran cleanly + found 0 pools = genuinely no
                    # DEX market on this chain → skip (same as low LP).
                    if (_chain_lp_entry.get("n_dex_pools") or 0) == 0:
                        _cross_chain_results[_chain_short] = {
                            "ca": _ca_on_chain, "cg_platform": _cg_platform,
                            "_skipped": "0 DEX pools on this chain — no market to forensic",
                        }
                        continue
                # Else: lp_usd known >= threshold, OR lp_usd unknown due to
                # probe failure → scan (don't silently skip an active chain).
                try:
                    with _chain_lock(_chain_short):
                        if not _sql_supported():
                            _cross_chain_results[_chain_short] = {
                                "ca": _ca_on_chain, "cg_platform": _cg_platform,
                                "_skipped": f"surf has no agent.{_chain_short}_transfers table",
                            }
                            continue
                        # v0.9.7 adversarial review Finding 4 (MEDIUM): set the SECONDARY
                        # chain's token decimals before its SQL runs. The
                        # bridged/mirror deployment may have different decimals
                        # than the primary (e.g. 18 on BSC, 6 on a bridge
                        # mint). Without this, the secondary chain's
                        # mint/throughput thresholds use the primary divisor
                        # and mis-scale. Save + restore around the scan so the
                        # primary chain's decimals aren't leaked back.
                        from chain_router import (
                            get_token_decimals as _get_tok_dec,
                            set_token_decimals as _set_tok_dec,
                        )
                        from section_a_scope import _fetch_evm_token_decimals
                        # Capture primary decimals, then do EVERYTHING
                        # (fetch + set + scan) inside try so the finally
                        # unconditionally restores — even if the secondary
                        # decimals RPC or set throws. Pre-bulletproof version
                        # had fetch/set outside the try; a throw there would
                        # leak secondary decimals into the rest of the
                        # pipeline (every later section uses the wrong divisor).
                        _saved_decimals = _get_tok_dec()
                        _chain_id_for_rpc = {
                            "ethereum": "1", "bsc": "56", "polygon": "137",
                            "base": "8453", "arbitrum": "42161",
                            "optimism": "10", "avalanche": "43114",
                        }.get(_chain_short)
                        try:
                            _sec_dec = _fetch_evm_token_decimals(
                                _ca_on_chain, _chain_id_for_rpc,
                            )
                            _set_tok_dec(_sec_dec)  # None → fallback 18 internally
                            _mc_auth = _discover_mint_authorities(
                                ca=_ca_on_chain, date_floor=_date_floor,
                                top_n=10, min_pct_supply=0.001,
                                total_supply=scope.get("total_supply"),
                            )
                            _mc_ht = _discover_high_throughput_dumpers(
                                ca=_ca_on_chain, date_floor=_date_floor,
                                min_throughput=1_000_000.0, max_balance_frac=0.25,
                                min_n_tx=500, top_n=50,
                                total_supply=scope.get("total_supply"),
                            )
                        finally:
                            _set_tok_dec(_saved_decimals)  # restore primary, always
                        # v0.7.24e.2 (A3): multi_chain mint_auth + ht labels
                        # deferred to consolidated batch at end of Round 8.

                        _cross_chain_results[_chain_short] = {
                            "ca": _ca_on_chain, "cg_platform": _cg_platform,
                            "mint_authorities": _mc_auth,
                            "high_throughput_dumpers": _mc_ht,
                        }
                        import sys as _sys
                        print(
                            f"[multi_chain] {_chain_short} ({_ca_on_chain}): "
                            f"{_mc_auth.get('summary', {}).get('n_authorities', 0)} mint authorities, "
                            f"{_mc_ht.get('summary', {}).get('n_dumpers', 0)} ht dumpers",
                            file=_sys.stderr,
                        )
                except Exception as _ce:
                    import sys as _sys
                    print(f"[multi_chain] {_chain_short} failed: {_ce}", file=_sys.stderr)
                    _cross_chain_results[_chain_short] = {
                        "ca": _ca_on_chain, "cg_platform": _cg_platform,
                        "_error": str(_ce)[:200],
                    }
            if _cross_chain_results:
                funding_attribution["multi_chain"] = _cross_chain_results
        except Exception as _e:
            import sys as _sys
            print(f"[multi_chain] outer failed (non-fatal): {_e}", file=_sys.stderr)

    # v0.7.24e.2 (A3): consolidated label batch. Earlier each detector
    # invoked surf wallet-labels-batch separately (mint_auth + destinations +
    # ht + multi_chain × N chains × 2 detectors = 4-7 calls × 3-5s = 15-25s
    # cumulative). Now all addrs needing labels are collected into a single
    # set and resolved in 1 batch, then applied back to each detector dict.
    # Saves ~12-20s + ~25-35 credits per pipeline run. The cex_fanout helper
    # keeps its internal label call because it uses the result to filter
    # candidates (gate-decision), not post-hoc enrichment.
    if isinstance(funding_attribution, dict) and not holder_snapshot_mode:
        try:
            _label_addrs_union: set[str] = set()
            # 1. Mint authority addrs (primary chain)
            for _a in (funding_attribution.get("mint_authorities", {}).get("authorities") or []):
                if _a.get("addr"):
                    _label_addrs_union.add(_a["addr"].lower())
            # 2. mining_fed_outflows + mint_authority_dumps top destinations
            for _key in ("mining_fed_outflows", "mint_authority_dumps"):
                _block = funding_attribution.get(_key) or {}
                for _wallet, _wallet_data in (_block.get("per_addr") or {}).items():
                    for _d in (_wallet_data.get("top_destinations") or []):
                        _dest = (_d.get("dest") or "").lower()
                        if _dest:
                            _label_addrs_union.add(_dest)
            # 3. high_throughput dumpers (primary chain)
            for _d in (funding_attribution.get("high_throughput_dumpers", {}).get("dumpers") or []):
                if _d.get("addr") and not _d.get("is_excluded"):
                    _label_addrs_union.add(_d["addr"].lower())
            # 4. Multi-chain mint authorities + ht dumpers
            for _chain_name, _mc_data in (funding_attribution.get("multi_chain") or {}).items():
                for _a in (_mc_data.get("mint_authorities", {}).get("authorities") or []):
                    if _a.get("addr"):
                        _label_addrs_union.add(_a["addr"].lower())
                for _d in (_mc_data.get("high_throughput_dumpers", {}).get("dumpers") or []):
                    if _d.get("addr") and not _d.get("is_excluded"):
                        _label_addrs_union.add(_d["addr"].lower())

            _consolidated_labels: dict[str, dict] = {}
            # v0.7.24e.3 (A4): cap label batch at 500 unique addrs to avoid
            # surf wallet-labels-batch timing out on PLAY-class tokens that
            # surface 1000+ high-throughput operators. For those, label the
            # first 500 by detection order — others render as UNLABELED but
            # the report still surfaces them.
            _LABEL_BATCH_CAP = 500
            if _label_addrs_union:
                _sorted = sorted(_label_addrs_union)
                _capped = _sorted[:_LABEL_BATCH_CAP]
                _dropped = len(_sorted) - len(_capped)
                try:
                    from surf_labels_probe import resolve_labels as _resolve_labels
                    _consolidated_labels = _resolve_labels(_capped)
                    import sys as _sys
                    print(
                        f"[funding_attribution] A3 consolidated label batch: "
                        f"{len(_capped)} unique addrs in 1 surf call"
                        + (f" (A4 cap: dropped {_dropped} above {_LABEL_BATCH_CAP})" if _dropped else "")
                        + " (saved 3-5 separate batches)",
                        file=_sys.stderr,
                    )
                except Exception as _le:
                    import sys as _sys
                    print(f"[funding_attribution] A3 consolidated label batch failed (non-fatal): {_le}",
                          file=_sys.stderr)

            # Post-hoc apply: walk each detector dict, apply labels +
            # recompute filters (is_infra) where needed.
            _INFRA_CLS = {"DEX_POOL", "CEX_DEPOSIT", "CEX_HOT_WALLET"}

            def _apply_label(rec):
                _lab = _consolidated_labels.get((rec.get("addr") or "").lower()) or {}
                rec["arkham_label"] = _lab.get("label")
                rec["arkham_entity_name"] = _lab.get("entity_name")
                rec["arkham_entity_type"] = _lab.get("entity_type")
                rec["arkham_classification"] = _lab.get("classification") or "UNLABELED"

            # Apply to mint authorities (primary)
            for _a in (funding_attribution.get("mint_authorities", {}).get("authorities") or []):
                _apply_label(_a)

            # Apply to top destinations + recompute destination_label_summary
            _cex_classes = {"CEX_DEPOSIT", "CEX_HOT_WALLET"}
            _cex_total = 0.0
            _dex_pool_total = 0.0
            for _key in ("mining_fed_outflows", "mint_authority_dumps"):
                _block = funding_attribution.get(_key) or {}
                for _wallet, _wallet_data in (_block.get("per_addr") or {}).items():
                    for _d in (_wallet_data.get("top_destinations") or []):
                        _dest = (_d.get("dest") or "").lower()
                        _lab = _consolidated_labels.get(_dest) or {}
                        _d["arkham_label"] = _lab.get("label")
                        _d["arkham_entity_name"] = _lab.get("entity_name")
                        _d["arkham_classification"] = _lab.get("classification") or "UNLABELED"
                        _amt = float(_d.get("amt") or 0)
                        _cls = _d["arkham_classification"]
                        if _cls in _cex_classes:
                            _cex_total += _amt
                        elif _cls == "DEX_POOL":
                            _dex_pool_total += _amt
            funding_attribution["destination_label_summary"] = {
                "cex_deposit_tokens": _cex_total,
                "dex_pool_tokens": _dex_pool_total,
                "n_destinations_labeled": sum(
                    1 for v in _consolidated_labels.values() if v.get("classification")
                ),
            }

            # Apply to primary high_throughput + recompute is_infra + summary
            _ht_block = funding_attribution.get("high_throughput_dumpers") or {}
            for _d in (_ht_block.get("dumpers") or []):
                _apply_label(_d)
                _d["is_infra"] = _d.get("arkham_classification") in _INFRA_CLS
            _ht_op_dumpers = [
                d for d in (_ht_block.get("dumpers") or [])
                if not d.get("is_excluded") and not d.get("is_infra")
            ]
            if _ht_block.get("dumpers"):
                _ht_block["summary"] = {
                    "n_dumpers": len(_ht_op_dumpers),
                    "total_throughput": sum(d.get("total_in", 0) for d in _ht_op_dumpers),
                    "n_dumpers_pre_filter": len(_ht_block.get("dumpers") or []),
                }

            # Apply to multi_chain — same pattern per chain
            for _chain_name, _mc_data in (funding_attribution.get("multi_chain") or {}).items():
                for _a in (_mc_data.get("mint_authorities", {}).get("authorities") or []):
                    _apply_label(_a)
                _mc_ht_block = _mc_data.get("high_throughput_dumpers") or {}
                for _d in (_mc_ht_block.get("dumpers") or []):
                    _apply_label(_d)
                    _d["is_infra"] = _d.get("arkham_classification") in _INFRA_CLS
                _mc_ht_op = [
                    d for d in (_mc_ht_block.get("dumpers") or [])
                    if not d.get("is_excluded") and not d.get("is_infra")
                ]
                if _mc_ht_block.get("dumpers"):
                    _mc_ht_block["summary"] = {
                        "n_dumpers": len(_mc_ht_op),
                        "total_throughput": sum(d.get("total_in", 0) for d in _mc_ht_op),
                        "n_dumpers_pre_filter": len(_mc_ht_block.get("dumpers") or []),
                    }
        except Exception as _e:
            import sys as _sys
            print(f"[funding_attribution] A3 post-hoc apply failed (non-fatal): {_e}",
                  file=_sys.stderr)

    # audit M1 fix: surface input-side truncation in pipeline log + the
    # report (via _debug.pipeline_truncated_n). silent loss of high-value addrs
    # past max_addrs=200 is the same class of bug as v0.7.23's dump_tracker
    # silent zero — visible-fail is the convention.
    _hv_dropped_input = max(0, _hv_pre_cap - 200)
    if _hv_dropped_input > 0:
        import sys as _sys
        print(
            f"[funding_attribution] high_value_addrs cap 200 — "
            f"truncated {_hv_dropped_input} from {_hv_pre_cap} total "
            f"(wash → flow → m6 → dump-sellers → top-30 holders priority)",
            file=_sys.stderr,
        )
        # Inject into _debug so the render template surfaces it. attribute_funding
        # already returns sql_truncated_addr_n from internal cap, but here we
        # report the upstream pipeline cap separately.
        if isinstance(funding_attribution, dict):
            _dbg = funding_attribution.setdefault("_debug", {})
            _dbg["pipeline_truncated_n"] = _hv_dropped_input
            _dbg["pipeline_input_total"] = _hv_pre_cap
    # v0.8.6.5.0: Build _master_cluster_addrs — union of all detector cluster
    # wallet sets. Single source of truth for "项目方控钱包" candidates, used
    # by wallet_cluster_graph (next section) + render to avoid dedup logic
    # across multiple detector outputs. Python union only — 0 extra surf calls.
    if isinstance(funding_attribution, dict) and not holder_snapshot_mode:
        _master = set()
        # 1. mint_authorities (主 mint 权限)
        for _a in (funding_attribution.get("mint_authorities", {}).get("authorities") or []):
            _addr = (_a.get("addr") or "").lower()
            if _addr:
                _master.add(_addr)
        # 2. mint_authority_dumps destinations (mint → cluster)
        _mad = funding_attribution.get("mint_authority_dumps", {}).get("per_addr") or {}
        for _auth, _data in _mad.items():
            for _d in (_data.get("top_destinations") or []):
                _addr = (_d.get("dest") or "").lower()
                if _addr:
                    _master.add(_addr)
        # 3. mining_fed_outflows targets
        _mfo = funding_attribution.get("mining_fed_outflows", {}).get("per_addr") or {}
        for _src, _data in _mfo.items():
            for _d in (_data.get("top_destinations") or []):
                _addr = (_d.get("dest") or "").lower()
                if _addr:
                    _master.add(_addr)
        # 4. high_throughput_dumpers
        for _d in (funding_attribution.get("high_throughput_dumpers", {}).get("dumpers") or []):
            _addr = (_d.get("addr") or "").lower()
            if _addr:
                _master.add(_addr)
        # 5. cex_fanout_hubs (hubs + recipients)
        _cfh = funding_attribution.get("cex_fanout_hubs", {})
        for _h in (_cfh.get("hubs") or []):
            _hub_addr = (_h.get("addr") or "").lower()
            if _hub_addr:
                _master.add(_hub_addr)
            for _r in (_h.get("_net_structured_recipient_addrs_raw") or []):
                if _r:
                    _master.add(_r.lower())
        # 6. deployer (m6 root)
        if rule11 and isinstance(rule11, dict):
            _dpl = (rule11.get("deployer") or "").lower()
            if _dpl:
                _master.add(_dpl)
            # 6b. m6 谱系 dumpers (rule_11 抓的 d1-d4)
            for _d_block in (rule11.get("dumpers") or {}).values() if isinstance(rule11.get("dumpers"), dict) else []:
                for _d in (_d_block or []):
                    _addr = (_d.get("addr") if isinstance(_d, dict) else _d) or ""
                    if isinstance(_addr, str) and _addr:
                        _master.add(_addr.lower())
        funding_attribution["_master_cluster_addrs"] = sorted(_master)
        import sys as _sys
        print(f"[funding_attribution] _master_cluster_addrs union: {len(_master)} wallets "
              f"(across mint_auth + cluster + ht + fanout + m6)", file=_sys.stderr)
    timings["funding_attribution"] = time.perf_counter() - t
    _ck("funding_attribution", funding_attribution)

    # ---------- Round 7d: wallet_cluster_graph (v0.8.6.5.0) ----------
    # Bidirectional IN-filter SQL to find wallet-to-wallet edges among
    # candidate set (master_cluster + top_holders ≥ 0.1% + cex_fanout
    # recipients). Catches Bubblemaps-style "looks-like-retail wallets
    # actually transferring to each other" clusters that single-direction
    # detectors miss. Surf-compliant: chunked sequential SQL, max_rows 9000.
    t = time.perf_counter()
    wallet_cluster_graph: dict = {"clusters": [], "summary": {}, "_pipeline_source": "wallet_cluster_graph"}
    if isinstance(funding_attribution, dict) and not holder_snapshot_mode:
        try:
            from wallet_cluster_graph_detector import discover_wallet_cluster_graph

            # Build candidate list: master_cluster + top_holders ≥ 0.1% supply
            _master_set = set(funding_attribution.get("_master_cluster_addrs") or [])
            _candidates = set(_master_set)
            _total_supply = scope.get("total_supply") or 0
            _min_top_holder = _total_supply * 0.001 if _total_supply else 0  # 0.1% supply
            _top_holder_only = set()
            for _h in (holders.get("top_holders") or []):
                _bal = _h.get("balance_tokens") if isinstance(_h, dict) else 0
                _addr = _h.get("address") if isinstance(_h, dict) else None
                if _addr and (not _min_top_holder or (_bal or 0) >= _min_top_holder):
                    _candidates.add(_addr.lower())
                    if _addr.lower() not in _master_set:
                        _top_holder_only.add(_addr.lower())
            # v0.8.6.5.2 adversarial review M5: source categorization for n_new metric
            _source_cat: dict[str, str] = {}
            for _a in _master_set:
                _source_cat[_a] = "master_cluster"
            for _a in _top_holder_only:
                _source_cat[_a] = "top_holder_only"

            # Reuse Arkham labels from cex_fanout (saves label resolve call)
            _arkham_labels: dict = {}
            _cfh_block = funding_attribution.get("cex_fanout_hubs", {}) or {}
            for _h in (_cfh_block.get("hubs") or []):
                _src = (_h.get("cex_source") or "").lower()
                if _src:
                    _arkham_labels[_src] = {
                        "classification": _h.get("cex_source_classification"),
                        "label": _h.get("cex_source_label"),
                        "entity_name": _h.get("cex_source_entity"),
                    }

            wallet_cluster_graph = discover_wallet_cluster_graph(
                ca=scope["contract_address"],
                candidates=sorted(_candidates),
                total_supply=_total_supply,
                date_floor=_date_floor,
                arkham_labels=_arkham_labels,
                resolve_candidate_labels=True,  # adversarial review M1 fix
                source_categorization=_source_cat,  # adversarial review M5 fix
            )
            import sys as _sys
            _wcg_sum = wallet_cluster_graph.get("summary", {})
            print(
                f"[wallet_cluster_graph] {_wcg_sum.get('n_clusters', 0)} clusters / "
                f"{_wcg_sum.get('n_cluster_addrs_total', 0)} cluster addrs / "
                f"{_wcg_sum.get('n_candidates_input', 0)} candidates → "
                f"{_wcg_sum.get('n_candidates_post_l1', 0)} post-L1 / "
                f"{_wcg_sum.get('n_edges_total', 0)} edges / "
                f"{_wcg_sum.get('n_chunks_run', 0)} chunks",
                file=_sys.stderr,
            )
        except Exception as _e:
            import sys as _sys
            print(f"[wallet_cluster_graph] failed (non-fatal): {_e}", file=_sys.stderr)
            wallet_cluster_graph = {"clusters": [], "summary": {}, "_error": str(_e)[:200]}
    timings["wallet_cluster_graph"] = time.perf_counter() - t
    _ck("wallet_cluster_graph", wallet_cluster_graph)

    # ---------- Round 7e: dump_tracker mining-mode fallback (v0.8.6.6) ----------
    # Build extra_receivers from funding_attribution + wcg cluster, rerun
    # dump_tracker with mining cluster as insider list. Unlocks confirmed
    # net sellout for cross-chain bridge / mining tokens (JCT/AOP/BTX/BEAT)
    # where rule_11 m6 lineage is empty/sparse.
    t = time.perf_counter()
    dump_tracking_mining: dict = {}
    if (isinstance(funding_attribution, dict) and not holder_snapshot_mode
            and isinstance(dump_tracking, dict)
            and (not dump_tracking.get("confirmed_net_sellout_usd")
                 or dump_tracking.get("confirmed_total_pct", 0) < 1.0)):
        try:
            mining_addrs: set[str] = set()
            for _a in (funding_attribution.get("mint_authorities", {}).get("authorities") or []):
                _addr = (_a.get("addr") or "").lower()
                if _addr:
                    mining_addrs.add(_addr)
            for _auth, _data in (funding_attribution.get("mint_authority_dumps", {}).get("per_addr") or {}).items():
                for _d in (_data.get("top_destinations") or []):
                    _addr = (_d.get("dest") or "").lower()
                    if _addr:
                        mining_addrs.add(_addr)
            for _src, _data in (funding_attribution.get("mining_fed_outflows", {}).get("per_addr") or {}).items():
                for _d in (_data.get("top_destinations") or []):
                    _addr = (_d.get("dest") or "").lower()
                    if _addr:
                        mining_addrs.add(_addr)
            for _d in (funding_attribution.get("high_throughput_dumpers", {}).get("dumpers") or []):
                _addr = (_d.get("addr") or "").lower()
                if _addr:
                    mining_addrs.add(_addr)
            for _h in (funding_attribution.get("cex_fanout_hubs", {}).get("hubs") or []):
                _hub = (_h.get("addr") or "").lower()
                if _hub:
                    mining_addrs.add(_hub)
                for _r in (_h.get("_net_structured_recipient_addrs_raw") or []):
                    if _r:
                        mining_addrs.add(_r.lower())
            for _cluster in (wallet_cluster_graph.get("clusters") or []):
                for _a in (_cluster.get("addrs") or []):
                    mining_addrs.add(_a.lower())
            mining_addrs.discard("")
            extra_receivers = [{"addr": a, "is_cex_custody": False, "is_dex_infra": False}
                               for a in sorted(mining_addrs)]
            if len(extra_receivers) >= 3:  # bother only if enough mining cluster
                dump_tracking_mining = dump_tracker_run(
                    rule11=rule11,
                    ca=ca,
                    symbol=scope.get("symbol"),
                    listing_ts_ms=scope.get("alpha_listing_ts_ms"),
                    listing_date=scope.get("alpha_listing_date_utc"),
                    circulating_supply=scope.get("circulating_supply"),
                    total_supply=scope.get("total_supply"),
                    extra_receivers=extra_receivers,
                    # v1.2.5: same spot-price guard as the main call (codex HIGH)
                    # — without it non-18-decimal mining tokens still overflow.
                    spot_price_usd=liq.get("current_price_usd"),
                )
                import sys as _sys
                _dtm = dump_tracking_mining
                print(f"[dump_tracker_mining] cluster={len(extra_receivers)} wallets, "
                      f"confirmed_total={_dtm.get('confirmed_total_tokens', 0):,.0f} tokens "
                      f"({(_dtm.get('confirmed_total_pct') or 0):.2f}% circ) "
                      f"net_sellout_usd={(_dtm.get('confirmed_net_sellout_usd') or 0):,.0f}",
                      file=_sys.stderr)
        except Exception as _e:
            import sys as _sys
            print(f"[dump_tracker_mining] failed (non-fatal): {_e}", file=_sys.stderr)
            dump_tracking_mining = {"_error": str(_e)[:200]}
    timings["dump_tracker_mining"] = time.perf_counter() - t
    _ck("dump_tracker_mining", dump_tracking_mining)

    # ---------- Round 7f: multi-chain supply-overhang (R3/R5/R6, CAP) ----------
    # A token whose Alpha listing is a small MIRROR (CAP: BSC 1.4%) while the
    # bulk of supply + real operator control lives on another surf-SQL chain
    # (CAP: Ethereum 99.6%) is measured by the single-chain chip on the wrong
    # slice → "🟢 分散 22.9%" when the truth is "~90% 控盘 + 84.5% 锁仓 overhang".
    # detect_multichain_split (surf-only, 0 extra credit — reuses the per-chain
    # holders section_a already fetched) gates this; on a split we recompute the
    # 真实派发 buckets on the canonical supply chain by REUSING _compute_chip_3way
    # (operator union from mint-authority lineage + wallet cluster graph), with
    # the genesis reserve excluded as a locked overhang. SQL runs under
    # chain_lock(supply_chain) via the proven _run_surf_with_retry path (NOT
    # rule_11/run_parallel). BSC-native / single-chain tokens never split → 0
    # added cost. Solana is excluded (HOLDER_SNAPSHOT, no agent.solana_* tables).
    t = time.perf_counter()
    supply_chain_overhang: dict = {}
    if not holder_snapshot_mode:
        try:
            from helpers.section_a_scope import detect_multichain_split
            from helpers.supply_chain_overhang import compute_supply_chain_overhang
            _split_info = detect_multichain_split(
                chain_lp_realtime=scope.get("chain_lp_realtime") or {},
                coingecko_platforms=scope.get("coingecko_platforms") or {},
                alpha_chain_id=scope.get("chain_id"),
            )
            if _split_info.get("split"):
                import sys as _sys
                print(
                    f"[supply_chain_overhang] split detected: Alpha={_split_info.get('alpha_prefix')} "
                    f"→ supply chain {_split_info.get('supply_prefix')} "
                    f"({_split_info.get('supply_pct_of_total')}% of cross-chain supply); "
                    f"recomputing 真实派发 on {_split_info.get('supply_ca')}",
                    file=_sys.stderr,
                )
                supply_chain_overhang = compute_supply_chain_overhang(
                    split=_split_info,
                    total_supply=scope.get("total_supply"),
                    circulating_supply=scope.get("circulating_supply"),
                    date_floor=_date_floor,
                    alpha_listing_date=scope.get("alpha_listing_date_utc"),
                    deployer_addr=(rule11.get("deployer") if isinstance(rule11, dict) else None),
                    symbol=scope.get("symbol"),
                )
                print(
                    f"[supply_chain_overhang] operator={supply_chain_overhang.get('operator_pct')}% "
                    f"relay={supply_chain_overhang.get('relay_pct')}% "
                    f"non_op={supply_chain_overhang.get('non_operator_pct')}% / "
                    f"locked overhang={supply_chain_overhang.get('locked_pct_of_total')}% of total "
                    f"({supply_chain_overhang.get('n_genesis_funded')} lineage-funded, "
                    f"{supply_chain_overhang.get('n_clusters')} clusters)"
                    + (f" ERROR={supply_chain_overhang.get('_error')}"
                       if supply_chain_overhang.get('_error') else ""),
                    file=_sys.stderr,
                )
            else:
                supply_chain_overhang = {"split": False}
        except Exception as _e:
            import sys as _sys
            print(f"[supply_chain_overhang] failed (non-fatal): {_e}", file=_sys.stderr)
            supply_chain_overhang = {"split": False, "_error": str(_e)[:200]}
    timings["supply_chain_overhang"] = time.perf_counter() - t
    _ck("supply_chain_overhang", supply_chain_overhang)

    # ---------- Round 7g: primary-sale (CCA / IDO) attribution — UNIVERSAL ----------
    # Self-check EVERY token for project public-distribution pools (CCA / IDO /
    # launchpad / airdrop redemption) and attribute insider/KOL capture. Multi-
    # chain split tokens reuse the supply-chain detection already computed inside
    # compute_supply_chain_overhang; single-chain tokens detect on the primary
    # chain using the deployer / pre-launch / mint-authority operator seed. Gated:
    # no operator-funded distribution pool → empty dict → render omits the section.
    t = time.perf_counter()
    primary_sales: dict = {}
    if not holder_snapshot_mode and scope.get("contract_address"):
        try:
            _sco_ps = (supply_chain_overhang.get("primary_sales")
                       if isinstance(supply_chain_overhang, dict) else None)
            _is_split = bool(isinstance(supply_chain_overhang, dict)
                             and supply_chain_overhang.get("split"))
            if isinstance(_sco_ps, dict) and _sco_ps.get("pools"):
                primary_sales = _sco_ps  # multi-chain: detected on the supply chain
            elif not _is_split:
                # single-chain ONLY. codex HIGH: never fall back to the Alpha listing
                # chain for a split/mirror token — its public sale lives on the
                # canonical supply chain (handled above); detecting on the mirror chain
                # would catch bridge activity with the wrong seed/denominator.
                from chain_router import set_active_chain as _psa_set_chain
                from helpers.supply_chain_overhang import _is_contract as _psa_is_contract
                from helpers.primary_sale_attribution import (
                    detect_primary_sale_pools as _psa_detect,
                    enrich_with_social as _psa_social,
                )
                _psa_prefix = (_psa_set_chain(chain_id) if chain_id else None)
                if _psa_prefix and _psa_prefix != "solana":
                    # FUNDING seed = treasury sources only (deployer / pre-launch /
                    # mint authorities) — narrow, for the operator-funded gate.
                    _psa_seed: set = set()
                    if isinstance(rule11, dict) and rule11.get("deployer"):
                        _psa_seed.add(_norm_addr(rule11["deployer"]))
                    _r11_recv = (rule11.get("pre_launch_receivers") or []) if isinstance(rule11, dict) else []
                    for _r in _r11_recv:
                        # parity with monitoring / counts / supply_chain: a CEX
                        # listing-channel or DEX pool receiver is not an operator and
                        # must not seed the primary-sale funding set (codex HIGH).
                        if _receiver_infra_kind(_r):
                            continue
                        _a = _norm_addr(_r.get("address") or _r.get("addr") or "")
                        if _a:
                            _psa_seed.add(_a)
                    if isinstance(funding_attribution, dict):
                        for _a in (funding_attribution.get("mint_authorities", {}).get("authorities") or []):
                            _ad = _norm_addr(_a.get("address") or _a.get("addr") or "")
                            if _ad:
                                _psa_seed.add(_ad)
                    # operator relay members are project-controlled distribution hubs
                    # (Safe/multisig-like) — add to BOTH the funding seed (so a
                    # Safe-funded single-chain CCA is not missed, codex HIGH) and the
                    # overlap set. Still far narrower than the full operator_set.
                    _relay = (distribution.get("operator_relay_members") or []) if isinstance(distribution, dict) else []
                    for _m in _relay:
                        _a = _norm_addr(_m.get("addr") or _m.get("address") or "")
                        if _a:
                            _psa_seed.add(_a)
                    _psa_overlap: set = set(_psa_seed)
                    _psa_pools = _psa_detect(
                        prefix=_psa_prefix, supply_ca=scope["contract_address"],
                        operator_seed=_psa_seed, operator_set=_psa_overlap,
                        total_supply=float(scope.get("total_supply") or 0),
                        circulating_supply=float(scope.get("circulating_supply") or 0),
                        date_floor=_date_floor, is_contract_fn=_psa_is_contract,
                        code_cache={}, listing_date=scope.get("alpha_listing_date_utc"),
                    )
                    if _psa_pools:
                        primary_sales = {"pools": _psa_pools, "chain": _psa_prefix}
                        if scope.get("symbol"):
                            primary_sales["social"] = _psa_social(scope["symbol"], _psa_pools)
        except Exception as _e:
            import sys as _sys
            print(f"[primary_sale] universal attribution failed (non-fatal): {_e}",
                  file=_sys.stderr)
            primary_sales = {"_error": str(_e)[:200]}
    timings["primary_sales"] = time.perf_counter() - t
    _ck("primary_sales", primary_sales)

    # Insider-only pre-launch receivers: exclude NEUTRAL infra (CEX custody / DEX
    # pool) so the "上线前内幕分发" / "已分完" detector counts don't include the
    # exchange listing-channel wallet or the liquidity pool as insider distribution.
    # (Vesting/multisig/treasury stay — they are project-controlled allocations.)
    _pre_recv = (rule11.get("pre_launch_receivers") or []) if isinstance(rule11, dict) else []
    _insider_recv = [r for r in _pre_recv if not _receiver_infra_kind(r)]

    # ---------- Build the skeleton report_data ----------
    # Locked sections (pipeline-populated)
    skeleton = {
        "_schema_version": SKILL_VERSION,
        "_pipeline_status": "ok",
        "_field_authority": {
            "locked": ["meta", "tier_classification", "evidence_graph",
                       "anomaly.waves[].events[].evt_ref",
                       "anomaly.waves[].events[].ts",
                       "anomaly.waves[].events[].amount",
                       "anomaly.waves[].events[].from_to",
                       "lineage.m6.rows",
                       # v0.7: cross-sym whale fields
                       "cross_sym.whales[].address",
                       "cross_sym.whales[].this_token_pct",
                       "cross_sym.whales[].this_token_balance",
                       "cross_sym.whales[].cross_sym_count",
                       "cross_sym.whales[].cross_sym_tokens",
                       "cross_sym.whales[].top_cross_sym_token",
                       "cross_sym.whales[].arkham_label",
                       "cross_sym.whales[].pre_launch_insider_count",
                       "cross_sym.whales[].pre_launch_insider_tokens",
                       "cross_sym.whales[].behavior_signature"],
            "derived_locked": ["cross_sym.whales[].identity_classification_enum",
                               "cross_sym.whales[].confidence_score",
                               "cross_sym.whales[].evidence_required_fields",
                               # v0.7.7 role classifier output (6-step on-chain)
                               "cross_sym.whales[].role_classification",
                               # v0.7.7 wash-infra detector output (5-step pure
                               # on-chain X/P/Q signature)
                               "wash_infrastructure.setups[].executor_X",
                               "wash_infrastructure.setups[].maker_buy_P",
                               "wash_infrastructure.setups[].maker_sell_Q",
                               "wash_infrastructure.setups[].atomic_pair_ratio",
                               "wash_infrastructure.setups[].p_drift_pct",
                               "wash_infrastructure.setups[].q_drift_pct",
                               "wash_infrastructure.setups[].p_tok_in",
                               "wash_infrastructure.setups[].q_tok_in",
                               "wash_infrastructure.setups[].tx_from_diversity",
                               "wash_infrastructure.setups[].classification"],
            "writable": ["verdict.one_liner", "anomaly.waves[].events[].nature",
                         "anomaly.detector_summary[].detail",
                         "anomaly.verdict_impact",
                         "*.interpretation",
                         "holdings_distribution.key_takeaways",
                         "lineage.m4_notes",
                         "monitoring_wallets[].alert",
                         "monitoring_footer",
                         # v0.7 narrative slots
                         "cross_sym.whales[].identity_narrative",
                         "cross_sym.whales[].risk_assessment_narrative",
                         "cross_sym.summary_narrative",
                         # v0.7.7 wash-infra narrative slots
                         "wash_infrastructure.setups[].investigation_narrative",
                         "wash_infrastructure.summary_narrative"],
        },

        "meta": {
            "symbol": scope["symbol"],
            "name": scope["name"],
            "contract_address": scope["contract_address"],
            "chain": scope["chain_label"],
            "chain_id": scope["chain_id"],
            "alpha_listing_date_utc": scope["alpha_listing_date_utc"],
            "total_supply": scope["total_supply"],
            "circulating_supply": scope["circulating_supply"],
            "circ_ratio": scope["circ_ratio"],
            "alpha_vol_24h_usd": scope["alpha_vol_24h_usd"],
            # v0.7.16: Alpha API token-list price + LP fields. Used by the
            # top-of-report token-info table as a fallback when surf
            # project-detail.token_info is NOT_FOUND (e.g. GUA — listed 3
            # months and still un-indexed by surf), so the header table is
            # never blank on a real Alpha-listed token.
            "alpha_price_usd": scope.get("alpha_price_usd"),
            "alpha_percent_change_24h": scope.get("alpha_percent_change_24h"),
            "alpha_market_cap_usd": scope.get("alpha_market_cap_usd"),
            "alpha_fdv_usd": scope.get("alpha_fdv_usd"),
            "alpha_liquidity_usd": scope.get("alpha_liquidity_usd"),
            "alpha_price_high_24h": scope.get("alpha_price_high_24h"),
            "alpha_price_low_24h": scope.get("alpha_price_low_24h"),
            "alpha_count_24h": scope.get("alpha_count_24h"),
            "alpha_holders": scope.get("alpha_holders"),
            "token_type_initial": scope["token_type_initial"],
            # v0.7.10: cross-chain truth via CoinGecko platforms + surf realtime
            # token-holders DEX-label LP comparison (no longer 24h-lagged
            # bsc_dex_trades aggregate). single_chain = True iff CoinGecko shows
            # only one deployment chain.
            "single_chain": (
                len(scope.get("coingecko_platforms") or {}) <= 1
            ),
            # v0.7.21.8: on holder-snapshot chains (Solana) the LP-based
            # derive_primary_chain can pick a wrapped-deployment chain
            # (FARTCOIN has a Base wrapper at 0x2f6c…, LP-only fallback
            # picked "base" even though the canonical chain is solana). Force
            # primary_chain to match the active SQL routing chain so the
            # report banners + blindspots + monitoring.chain are consistent.
            "primary_chain": (
                get_active_chain() if holder_snapshot_mode
                else scope.get("primary_chain")
            ),
            "primary_chain_derivation": (
                "holder_snapshot_uses_active_chain"
                if holder_snapshot_mode
                else scope.get("primary_chain_derivation")
            ),
            "coingecko_platforms": scope.get("coingecko_platforms") or {},
            "chain_lp_realtime": scope.get("chain_lp_realtime") or {},
            "realtime_token_info": scope.get("realtime_token_info") or {},
            # v0.7.9: surf BSC data availability snapshot (drives banner) —
            # historical SQL freshness only; not used to decide primary_chain
            # or LP/vol in v0.7.10.
            "data_freshness": scope.get("data_freshness") or {},
            # v0.6.2 audit HIGH #2: lock lang into skeleton.
            # render_report.py validates this matches its own --lang. Mismatch
            # = visible-fail (refuse render) instead of silent leak.
            "report_lang_locked": _i18n_get_lang(),
            # v0.7.21.8: surf onchain-sql coverage flag. True when the active
            # chain has no `agent.{chain}_*` tables (Solana). Render template
            # surfaces a top-of-report banner explaining why the SQL-only
            # forensic sections are absent.
            "_holder_snapshot_mode": holder_snapshot_mode,
            "_sql_supported": _chain_sql_supported(),
            # v0.7.21.9: SPL mint metadata (Solana). Lets the report header
            # show the on-chain `decimals` + show the chain-truth supply
            # next to the Alpha API snapshot when they differ. Both None on
            # EVM and on Solana RPC fallback.
            "chain_decimals": scope.get("chain_decimals"),
            "chain_total_supply_ui": scope.get("chain_total_supply_ui"),
        },

        # Tier — refined by section_cex_trace (no longer stub)
        "tier_classification": {
            "tier": cex_trace["tier"],
            "s1_date": cex_trace["s1_date"],
            "s2_date": cex_trace["s2_date"],
            "s3_date": cex_trace["s3_date"],
        },

        # Evidence graph (the centerpiece of v0.6)
        "evidence_graph": eg.to_dict(),

        # Lineage section: pipeline-built m6 + flowchart from Rule 11
        "lineage": {
            "_pipeline_source": "rule_11_backward_trace",
            "deployer_addr": rule11["deployer"],
            "mint_evt_ref": rule11["mint_evt_ref"],
            "m6": {
                "rows": [
                    {
                        "m6_ref": r["m6_ref"],
                        "addr_short": r["addr"][:10],
                        "addr_full": r["addr"],
                        "received_from_deployer": r["received_from_deployer"],
                        "current_balance": r["current_balance"],
                        "dumped_pct": r["dumped_pct"],
                        # v0.7.10.3: carry Arkham lockup classification so the
                        # m6 table can flag vesting / multisig / CEX-custody
                        # rows instead of presenting them as insiders.
                        "is_protocol_lockup": r.get("is_protocol_lockup", False),
                        "is_vesting": r.get("is_vesting", False),
                        "is_multisig": r.get("is_multisig", False),
                        "is_cex_custody": r.get("is_cex_custody", False),
                        # v1.2.2: also carry DEX-infra / treasury so the m6 table can
                        # flag a liquidity pool or treasury row, not just CEX/vesting.
                        "is_dex_infra": r.get("is_dex_infra", False),
                        "is_treasury": r.get("is_treasury", False),
                        "arkham_label": r.get("arkham_label"),
                        # LLM writes the interpretation
                        "identity_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
                        "status_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
                    }
                    for r in rule11["pre_launch_receivers"]
                ],
                "n_quiet": len(rule11["quiet_wallets"]),
                # consistency with the detector_summary counts: exclude neutral infra
                # (CEX/DEX) so the lineage dumper tally doesn't present a listing /
                # liquidity wallet as an insider partial/full dumper.
                "n_partial_dumper": sum(
                    1 for r in _insider_recv
                    if r.get("dumped_pct") is not None and 0 < r["dumped_pct"] < 95
                ),
                "n_full_dumper": sum(
                    1 for r in _insider_recv
                    if r.get("dumped_pct") is not None and r["dumped_pct"] >= 95
                ),
            },
            "m4_notes": [
                rule11["summary_text"],  # auto-derived locked summary
                "<LLM_NARRATIVE_PLACEHOLDER>",  # LLM adds interpretation bullets
                "<LLM_NARRATIVE_PLACEHOLDER>",
            ],
            # v0.7.14 (adversarial review HIGH #1): every number cited in m4_notes[0]'s
            # pipeline summary is exposed here as a locked numeric field so the
            # narrative-hallucination check's pool includes them. Lets us run
            # the check on ALL m4_notes indices (incl. 0) without false-positives,
            # closing the m4_notes[0] exemption bypass on writable content.
            "summary_locked_numbers": rule11.get("summary_locked_numbers", {}),
            "dumper_destinations_summary": {
                dumper_addr: {
                    "n_destinations": len(dests),
                    "top_destination_addr": dests[0]["to"] if dests else None,
                    "top_destination_evt_ref": dests[0]["evt_ref"] if dests else None,
                }
                for dumper_addr, dests in rule11["dumper_destinations"].items()
            },
            # Phase B.4 lineage flowchart (node_NNN into evidence_graph)
            "flowchart_nodes": distribution["flowchart_nodes"],
            "flowchart_edges": distribution["flowchart_edges"],
            # v0.9.6 Fix #3 (adversarial review Windows EVAA 2026-06-15 feedback):
            # step4 dumpers dropped due to chunk errors. Surface in
            # render Data Gap so the user knows about the trace incompleteness.
            "step4_skipped_dumpers": rule11.get("step4_skipped_dumpers", []),
            "n_step4_skipped_dumpers": rule11.get("n_step4_skipped_dumpers", 0),
            # v0.9.7 adversarial review R1 Finding 6 (HIGH): step4 budget-cap truncation.
            # When recursion_truncated, the verdict is a LOWER BOUND — N
            # sub-dumpers holding ~X tokens were not recursively expanded.
            # Surfaced so render Data Gap can disclose the under-count.
            "recursion_truncated": rule11.get("recursion_truncated", False),
            "n_sub_dumpers_skipped": rule11.get("n_sub_dumpers_skipped", 0),
            "n_sub_dumpers_skipped_tokens": rule11.get("n_sub_dumpers_skipped_tokens", 0.0),
        },

        # Anomaly waves: pipeline-built from Rule 11 waves_proposal + Section ANOMALY 72h
        "anomaly": {
            "waves": (
                rule11["waves_proposal"]
                + ([anomaly72["wave3_proposal"]] if anomaly72.get("wave3_proposal") else [])
            ),
            "rhythm": {
                "title": "<LLM_NARRATIVE_PLACEHOLDER>",
                "waves": [
                    {
                        "name": w["title"],
                        "ts_text": w["ts_range"],
                        "detail": "<LLM_NARRATIVE_PLACEHOLDER>",
                    }
                    for w in (
                        rule11["waves_proposal"]
                        + ([anomaly72["wave3_proposal"]] if anomaly72.get("wave3_proposal") else [])
                    )
                ],
            },
            "verdict_impact": "<LLM_NARRATIVE_PLACEHOLDER>",
            "detector_summary": [
                # Mandatory categories (R10 enforces presence). v0.6.2: labels via i18n.
                {
                    "emoji": "🔴" if len(_insider_recv) > 0 else "⚪",
                    "label": _i18n_t("anomaly.detector_label.pre_launch_distribution"),
                    "count": len(_insider_recv),  # excludes CEX/DEX neutral infra
                    "detail": "<LLM_NARRATIVE_PLACEHOLDER>",
                },
                {
                    "emoji": "🔴" if sum(
                        1 for r in _insider_recv
                        if r.get("dumped_pct") is not None and r["dumped_pct"] >= 95
                    ) > 0 else "⚪",
                    "label": _i18n_t("anomaly.detector_label.full_dumper_wallets"),
                    "count": sum(
                        1 for r in _insider_recv
                        if r.get("dumped_pct") is not None and r["dumped_pct"] >= 95
                    ),
                    "detail": "<LLM_NARRATIVE_PLACEHOLDER>",
                },
                {
                    "emoji": "🟠" if len(rule11["quiet_wallets"]) > 0 else "⚪",
                    "label": _i18n_t("anomaly.detector_label.quiet_wallets"),
                    "count": len(rule11["quiet_wallets"]),
                    "detail": "<LLM_NARRATIVE_PLACEHOLDER>",
                },
                {
                    "emoji": (
                        "🔴" if anomaly72["n_recent_events"] >= 10
                        else "🟠" if anomaly72["n_recent_events"] >= 3
                        else "🟡" if anomaly72["n_recent_events"] > 0
                        else "⚪"
                    ),
                    "label": (
                        _i18n_t("anomaly.detector_label.anomaly_72h_truncated",
                                limit=anomaly72.get("limit", 100))
                        if anomaly72.get("was_truncated")
                        else _i18n_t("anomaly.detector_label.anomaly_72h")
                    ),
                    "count": anomaly72["n_recent_events"],
                    "detail": "<LLM_NARRATIVE_PLACEHOLDER>",
                },
                # Phase 1.3+ categories (庄家归集 / LP 24h / Alpha 5% depth)
                # NOT emitted in alpha.3 — when pipeline can't produce data,
                # don't fabricate a detector entry. Validator R10 requires
                # >=3 detectors which we already satisfy (Rule 11 + 72h = 4).
                # Pipeline adds these back in phase B once section_liq +
                # section_cex_trace + hub detection are wired.
            ],
        },

        # Monitoring wallets: pipeline-emitted (audit regression restored)
        # Includes: deployer + every m6 row + top 5 distinct actors from 72h
        "monitoring_wallets": _build_monitoring_wallets(rule11, anomaly72, eg, distribution=distribution, cross_sym=cross_sym, flow_operators=flow_operators_block),

        # v0.7.9: 决策摘要 section. Top-of-report 5-line user-decision-centric
        # summary. Pipeline derives all numeric fields; LLM writes 1 line narrative.
        # User reads decision_summary FIRST, then drills into forensic detail.
        "decision_summary": {
            "_pipeline_source": "forensic_pipeline.decision_summary",
            # 主战场链 + 实时 LP (该链) + aggregate 24h vol (跨链 CEX+DEX)
            "primary_chain": scope.get("primary_chain"),
            "primary_chain_derivation": scope.get("primary_chain_derivation"),
            "primary_chain_lp_usd": (
                (scope.get("chain_lp_realtime") or {}).get(scope.get("primary_chain") or "", {}) or {}
            ).get("lp_usd"),
            "realtime_24h_vol_usd": (
                (scope.get("realtime_token_info") or {}).get("volume_24h_usd")
            ),
            "realtime_price_usd": (
                (scope.get("realtime_token_info") or {}).get("price_usd")
            ),
            # 建议动作 (从 verdict 镜像)
            "verdict_enum": _build_verdict_block(rule11, anomaly72).get("enum"),
            "verdict_cn_label": _build_verdict_block(rule11, anomaly72).get("cn_label"),
            # 进场上限 (从 section_liq 镜像)
            "entry_size_cap_usd": liq.get("alpha_5pct_depth_usd_est"),
            # 短期催化 (CEX listing date / unlock 上面已有部分数据)
            "short_term_catalysts": [
                row.get("status") + ": " + (row.get("exchange") or "") + " " + (row.get("ts") or "")
                for row in (cex_trace.get("rows") or [])
                if row.get("status") and "已上线" in (row.get("status") or "")
            ],
            # 盲区清单. v0.7.10: pipeline 历史 forensic (m6/transfers/wash) 仍只
            # 跑 BSC partition, 所以主战场 ≠ BSC 时, 实时 LP/vol 跨链能拿到, 但
            # 历史血统/异动 trace 只能在 BSC 镜像端 (常常浅或不存在). 这是真盲区,
            # 跟实时数据 EVM 覆盖广没冲突.
            # v0.7.21.8: prefer the active chain (matches what SQL got routed
            # to) over scope.primary_chain — for Solana the LP-based derivation
            # can pick a wrapper chain (FARTCOIN Base wrapper) that misleads
            # the blindspot label.
            "blindspots": [
                b for b in [
                    ((scope.get("data_freshness") or {}).get("warning")),
                    (
                        f"主战场 {get_active_chain()} 的链上 SQL 不在 surf 覆盖, forensic SQL 段全部跳过, 仅保留 Alpha 实时 + token-holders 快照"
                        if holder_snapshot_mode
                        else (
                            f"主战场 {scope.get('primary_chain')} 的历史血统/分发追溯不在 pipeline 覆盖范围 (仅 BSC 镜像端可查)"
                            if scope.get("primary_chain") and scope.get("primary_chain") != "binance-smart-chain"
                            else None
                        )
                    ),
                ] if b
            ],
            # writable: LLM 写一段中文叙述串起来
            "narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        },

        # Verdict — derived_locked, pipeline writes real values now (fix adversarial review
        # alpha.2 deadlock: previously placeholder caused R11/locked conflict)
        "verdict": _build_verdict_block(rule11, anomaly72),

        # decision_action_block — derived_locked numeric slots, writable narrative
        "decision_action_block": _build_decision_action_block(rule11, anomaly72, liq=liq),

        # cross_sym — v0.7 forward-detection of cross-sym whale candidates.
        # Each whale entry has:
        #   - locked: address, this_token_pct, cross_sym_count, etc.
        #   - derived_locked: identity_classification_enum, confidence_score,
        #                     role_classification (v0.7.7 6-step on-chain)
        #   - writable: identity_narrative, risk_assessment_narrative
        # Empty whales list is normal — most fresh CAs have no cross-sym whales.
        "cross_sym": cross_sym,

        # wash_infrastructure — v0.7.7 5-step pure on-chain wash detection.
        # Each setup entry exposes the X / P / Q triplet (executor + maker
        # buy-side + maker sell-side) plus the structural metrics that
        # confirm the wash signature (atomic-pair ratio, P+Q drift,
        # tx_from diversity). Replaces v0.7.5 wash_distributor_probe which
        # was empirically mis-fitting (DEX pool ↔ MM bot pattern was being
        # branded as "operator EOA ↔ controlled contract wash").
        "wash_infrastructure": wash_infrastructure,

        # v0.7.21: flow-based wallet detector — cross-Alpha trading
        # operators + single-operator async wash. Complementary to
        # wash_infrastructure (atomic-pair wash) — see v0721_DESIGN.md.
        "flow_operators": flow_operators_block,

        # v0.7.23.1: reverse-direction funding source classification for the
        # high-value addresses surfaced by all earlier detectors. Each addr
        # gets {mint, dex_buy, p2p} share so retail can read "this wallet
        # is mining-fed" vs "this wallet is real DEX buyer" without us having
        # to decode the token's specific distribution mechanism (bridge /
        # vesting / airdrop / standard deployer-anchored). Critical for
        # Aethir / Humanity / Polyhedra-class tokens where rule_11's standard
        # deployer→m6 trace returns empty.
        "funding_attribution": funding_attribution,

        # v0.8.6.5.0: wallet_cluster_graph — bidirectional IN-filter SQL,
        # connected components, 5-layer false-positive defense. Catches
        # Bubblemaps-style cluster patterns single-direction detectors miss.
        "wallet_cluster_graph": wallet_cluster_graph,
        # v1.1.0 (CAP): multi-chain supply-overhang. Present + split=True only
        # when the Alpha listing is a mirror and the canonical supply chain was
        # re-measured (operator/relay/non_operator % of circulating + locked
        # overhang). split=False (or absent) for single-chain tokens. Read by
        # screen_summary._compute_chip_3way override + render 真实派发 section.
        "supply_chain_overhang": supply_chain_overhang,
        # v1.2.0: primary-sale (CCA / IDO / launchpad) attribution — universal,
        # top-level so the render reads one place regardless of chain topology.
        "primary_sales": primary_sales,
        # v0.8.6.6: mining-mode dump_tracker fallback (extra_receivers =
        # mint_authority + cluster + ht + fanout + wcg cluster). Unlocks
        # confirmed net sellout for cross-chain bridge / mining tokens
        # where rule_11 m6 lineage is empty/sparse.
        "dump_tracking_mining": dump_tracking_mining,
        # v0.8.7.0: 6-dimension deterministic TL;DR for report top.
        # ChatGPT review: "第一屏没有把信息压成 3 个判断". screen_summary
        # builds 6 dims (阶段 / 筹码 / 成交质量 / 供应风险 / 盘口阶段 /
        # 监控重点) + 1-sentence summary, rendered as `## 0. 一屏结论`.
        # Built after main skeleton so it can read chain_state / dump_tracking
        # / behavior_profile etc. emitted earlier — see render path below.
        "screen_summary": None,  # filled after build via helpers.screen_summary

        # holdings_distribution — Phase B.4 wired with real role_rows + progress_bars
        "holdings_distribution": {
            "_pipeline_source": "section_f_holders + section_l_distribution",
            "role_rows": distribution["role_rows"],
            "progress_bars": distribution["progress_bars"],
            "n_top_holders_classified": distribution["n_top_holders_classified"],
            "key_takeaways": [
                "<LLM_NARRATIVE_PLACEHOLDER>",
                "<LLM_NARRATIVE_PLACEHOLDER>",
                "<LLM_NARRATIVE_PLACEHOLDER>",
            ],
        },

        # monitoring_footer — writable single-line footer
        "monitoring_footer": "<LLM_NARRATIVE_PLACEHOLDER>",

        # Section data (Phase B.3 real data, no longer stubs):
        "multi_chain": {
            "rows": multi_chain["rows"],
            "gate_note": multi_chain["gate_note"],
            "interpretation": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        "tge": {
            "rows": tge["rows"],
            "interpretation": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        "alloc": {
            "rows": alloc["rows"],
            "n_quiet": alloc["n_quiet"],
            "quiet_balance_pct_total": alloc["quiet_balance_pct_total"],
            "interpretation": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        # Phase 2: 真实派发 (entity-level sell to CEX/DEX). Pipeline-locked
        # data; LLM writes the interpretation only when clusters exist (else
        # pipeline sets a fixed line so the validator sees no placeholder in
        # a section the renderer skips anyway).
        "dump_tracking": {
            "_pipeline_source": "dump_tracker",
            # v0.7.12 (Opt1): CONFIRMED-SOLD LOWER BOUND + current holdings only.
            # The flow-summed "allocation − balance" upper bound was dropped — it
            # double-counted on deployer round-trips (R2 → >total-supply garbage).
            "insider_n_wallets": dump_tracking.get("insider_n_wallets", 0),
            # Confirmed-sold FLOOR: (a) insider→CEX-deposit + (b) insider DEX swaps.
            "confirmed_cex_tokens": dump_tracking.get("confirmed_cex_tokens", 0),
            "confirmed_cex_pct": dump_tracking.get("confirmed_cex_pct"),
            "confirmed_cex_labels": dump_tracking.get("confirmed_cex_labels", []),
            "confirmed_dex_tokens": dump_tracking.get("confirmed_dex_tokens", 0),
            "confirmed_dex_pct": dump_tracking.get("confirmed_dex_pct"),
            "confirmed_dex_swaps": dump_tracking.get("confirmed_dex_swaps", 0),
            "confirmed_total_tokens": dump_tracking.get("confirmed_total_tokens", 0),
            "confirmed_total_pct": dump_tracking.get("confirmed_total_pct"),
            "confirmed_est_profit_usd": dump_tracking.get("confirmed_est_profit_usd"),
            # v0.7.21.10: Net Sell Out (apparatus' time-weighted estimate).
            "confirmed_net_sellout_usd": dump_tracking.get("confirmed_net_sellout_usd"),
            "confirmed_dex_real_usd": dump_tracking.get("confirmed_dex_real_usd"),
            "confirmed_cex_estimated_usd": dump_tracking.get("confirmed_cex_estimated_usd"),
            # v0.9.2.1: per-window splits (7d / 30d) added in dump_tracker
            # run() — pass through whitelist so the render template + JSON
            # footer get them. Without this whitelist they're silently
            # stripped because v0.6 field authority demands explicit
            # enumeration. (v0.9.2 hotfix — discovered via CLO_v092 run
            # where dump_tracking main path produced the sellout, not the
            # mining fallback that wholesale-emits.)
            "confirmed_total_tokens_7d": dump_tracking.get("confirmed_total_tokens_7d"),
            "confirmed_total_tokens_30d": dump_tracking.get("confirmed_total_tokens_30d"),
            "confirmed_total_pct_7d": dump_tracking.get("confirmed_total_pct_7d"),
            "confirmed_total_pct_30d": dump_tracking.get("confirmed_total_pct_30d"),
            "confirmed_net_sellout_usd_7d": dump_tracking.get("confirmed_net_sellout_usd_7d"),
            "confirmed_net_sellout_usd_30d": dump_tracking.get("confirmed_net_sellout_usd_30d"),
            "confirmed_cex_tokens_7d": dump_tracking.get("confirmed_cex_tokens_7d"),
            "confirmed_cex_tokens_30d": dump_tracking.get("confirmed_cex_tokens_30d"),
            "confirmed_dex_tokens_7d": dump_tracking.get("confirmed_dex_tokens_7d"),
            "confirmed_dex_tokens_30d": dump_tracking.get("confirmed_dex_tokens_30d"),
            "confirmed_dex_real_usd_7d": dump_tracking.get("confirmed_dex_real_usd_7d"),
            "confirmed_dex_real_usd_30d": dump_tracking.get("confirmed_dex_real_usd_30d"),
            "apparatus_dex_twap_usd_per_token": dump_tracking.get("apparatus_dex_twap_usd_per_token"),
            "net_above_gross_pct": dump_tracking.get("net_above_gross_pct"),
            "confirmed_capped": dump_tracking.get("confirmed_capped", False),
            # v0.7.19.4: TREE holdings (with lockup + exit-infra) — conservation
            # anchor; render shows it as "内幕树当前持有 (含未解锁锁仓)".
            "tree_holds_tokens": dump_tracking.get("tree_holds_tokens", 0),
            "tree_holds_pct_supply": dump_tracking.get("tree_holds_pct_supply"),
            # v0.7.19.4: PURE insider holdings (excluding Arkham-confirmed
            # protocol_lockup + cex_custody + dex_infra) — narrative anchor.
            "pure_insider_holds_tokens": dump_tracking.get("pure_insider_holds_tokens", 0),
            "pure_insider_holds_pct_supply": dump_tracking.get("pure_insider_holds_pct_supply"),
            # Backward-compat alias (old name) — same value as tree_holds.
            # Render template uses the new explicit names; this stays for any
            # external consumer that hasn't read the v0.7.19.4 changelog.
            "insider_holds_tokens": dump_tracking.get("insider_holds_tokens", 0),
            "insider_holds_pct_supply": dump_tracking.get("insider_holds_pct_supply"),
            "median_price_usd": dump_tracking.get("median_price_usd"),
            "wash_dominated": dump_tracking.get("wash_dominated", False),
            "n_dex_sellers": dump_tracking.get("n_dex_sellers", 0),
            "total_dex_swaps": dump_tracking.get("total_dex_swaps", 0),
            "top_seller_swaps": dump_tracking.get("top_seller_swaps", 0),
            "buckets_complete": dump_tracking.get("buckets_complete", True),
            "interpretation": (
                "<LLM_NARRATIVE_PLACEHOLDER>"
                if (dump_tracking.get("confirmed_total_tokens") or 0) > 0
                else "未检测到 insider 向 CEX/DEX 的确认卖出 (链上无法确认的转账不计入)."
            ),
        },
        "cex_trace": {
            "rows": cex_trace["cex_trace_rows"],
            "new_catalyst": (
                _i18n_t("section.cex_trace.new_catalyst_none_14d")
                if not cex_trace["s2_date"] or _days_since(cex_trace["s2_date"]) >= 14
                else _i18n_t("section.cex_trace.new_catalyst_within_14d")
            ),
            "tier_explanation": _i18n_t(
                "section.cex_trace.tier_explanation",
                tier=cex_trace["tier"],
                tier_desc=_i18n_t(
                    "section.cex_trace.tier_desc_S2" if cex_trace["has_binance_perp"]
                    else "section.cex_trace.tier_desc_S1"
                ),
            ),
            "interpretation": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        "liq": {
            "rows": liq["liq_rows"],
            "current_price_usd": liq["current_price_usd"],
            "dex_pool_addr": liq["dex_pool_addr"],
            "dex_pool_liquidity_usd": liq["dex_pool_liquidity_usd"],
            "alpha_5pct_depth_usd_est": liq["alpha_5pct_depth_usd_est"],
            "lp_24h_flow": liq["lp_24h_flow"],
            "interpretation": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        "decision_anchors": liq["decision_anchors_partial"],

        "_pipeline_timings": timings,
        "_pipeline_total_seconds": time.perf_counter() - t_start,
    }

    # ---------- Round 9: behavior_classifier (v0.7.26) ----------
    # Deterministic multi-label classifier translates raw detector outputs
    # into 10 forensic-state labels (A1/A2/A3/B1/B2/C1/C2/C3/D1/D2).
    # Calibrated thresholds derived from 8-token backtest (v0725_5_CALIBRATION.md).
    # 0 surf cost — pure Python derive from the already-assembled skeleton.
    # If classifier raises (defensive: corrupt skeleton), inject an empty
    # profile rather than aborting the whole pipeline.
    try:
        from helpers.behavior_classifier import build_profile as _build_behavior_profile
        skeleton["behavior_profile"] = _build_behavior_profile(skeleton)
    except Exception as _e:
        import sys as _sys
        print(f"[behavior_classifier] failed (non-fatal): {_e}", file=_sys.stderr)
        skeleton["behavior_profile"] = {
            "_schema_version": "v0.7.26",
            "active_labels": [],
            "primary_behavior": None,
            "by_label": {},
            "_error": str(_e),
        }

    # ---------- Round 9.6: screen_summary (v0.8.7.0) ----------
    # 6-dimension deterministic TL;DR for `## 0. 一屏结论`. Built AFTER
    # behavior_profile so chain_state / risk_score etc. are populated.
    # Derive chain_state into skeleton (render reads same logic but emit
    # only to JSON footer — we need it on skel for screen_summary).
    try:
        from render_report import _derive_chain_state_neutral_5tier as _ds5
        _cs = _ds5(skeleton)
        skeleton["chain_state"] = _cs["subtype"]
        skeleton["chain_state_label"] = _cs["label"]
        skeleton["chain_state_risk_score"] = _cs["risk"]
    except Exception as _e:
        import sys as _sys
        print(f"[chain_state_derive] failed (non-fatal): {_e}", file=_sys.stderr)
    # ---------- Round 9.5: hidden_operator_enricher (v0.8.2) ----------
    # Append heuristically-flagged hidden operator wallets to
    # monitoring_wallets BEFORE annotate_monitoring_wallets so they get
    # scored + exported to paste.json. Currently only fake-mining
    # cluster members (from mint_authority_dumps detect → fake cluster).
    # 0 surf cost.
    try:
        from helpers.hidden_operator_enricher import enrich_monitoring_with_hidden_operators
        enrich_monitoring_with_hidden_operators(skeleton)
    except Exception as _e:
        import sys as _sys
        print(f"[hidden_operator_enricher] failed (non-fatal): {_e}", file=_sys.stderr)

    # ---------- Round 9.6: hidden_operator_activity (v0.8.3) ----------
    # Run (a)/(b) confirmed-sells query against the hidden operator set
    # to surface whether the heuristically-flagged wallets have already
    # started realizing. ~10-30 credits, parallelizable with dump_tracker
    # queries (currently sequential here for simplicity).
    try:
        from helpers.hidden_operator_activity import probe_hidden_operator_activity
        skeleton["hidden_operator_activity"] = probe_hidden_operator_activity(
            ca=skeleton.get("meta", {}).get("contract_address") or "",
            skel=skeleton,
        )
    except Exception as _e:
        import sys as _sys
        print(f"[hidden_operator_activity] failed (non-fatal): {_e}", file=_sys.stderr)
        # v0.8.3.1 audit HIGH #2 fix: return COMPLETE zero shape on
        # exception, not partial {"_error": ...} dict. Template uses
        # StrictUndefined; partial dict raises on `.n_hidden_wallets_tracked`
        # access in the elif branch.
        skeleton["hidden_operator_activity"] = {
            "n_hidden_wallets_tracked": 0,
            "confirmed_cex_tokens": 0.0,
            "confirmed_dex_tokens": 0.0,
            "confirmed_total_tokens": 0.0,
            "confirmed_total_pct_circ": None,
            "confirmed_est_usd": None,
            "confirmed_est_usd_source": "none",
            "n_distinct_cex_destinations": 0,
            "n_dex_swaps": 0,
            "cex_destination_brands": [],
            "date_floor": None,
            "_error": str(_e)[:120],
        }

    # ---------- Round 10: monitoring_ranker (v0.7.27) ----------
    # Deterministic per-wallet score → 4-tier level (CRITICAL / HIGH /
    # NORMAL / NOT_TRACKED). Annotates monitoring_wallets[] in-place.
    # paste.json export (downstream in render) sorts + filters by level.
    # 0 surf cost. Defensive try/except mirrors Round 9 pattern.
    try:
        from helpers.monitoring_ranker import annotate_monitoring_wallets, summary_by_level
        annotate_monitoring_wallets(skeleton)
        skeleton["monitoring_summary"] = {
            "_schema_version": "v0.7.27",
            "_calibrated_for": "context_B_crypto_operator",
            "level_counts": summary_by_level(skeleton.get("monitoring_wallets") or []),
        }
    except Exception as _e:
        import sys as _sys
        print(f"[monitoring_ranker] failed (non-fatal): {_e}", file=_sys.stderr)
        # v0.7.27.1 adversarial review MED fix: include `_calibrated_for` even on
        # failure path so validator (which fail-closes on absent locked
        # scalar paths) doesn't abort the whole render.
        skeleton["monitoring_summary"] = {
            "_schema_version": "v0.7.27",
            "_calibrated_for": "context_B_crypto_operator",
            "level_counts": {"CRITICAL": 0, "HIGH": 0, "NORMAL": 0, "NOT_TRACKED": 0},
            "_error": str(_e),
        }

    # ---------- Round 10.4: recent (72h) flow actions (v1.2.9) ----------
    # product spec 2026-06-29 (JCT/Janction): is the operator, RIGHT NOW, preparing the next
    # dump — a mint-authority / cluster hub fanning out to fresh sockpuppets, or many
    # EOAs consolidating into a CEX? cex_fanout only catches CEX-SOURCE fan-out and
    # missed JCT's mint-authority → 50-EOA seed. Cheap (2 SQL, 3-day window) on the
    # Alpha chain; surfaced at highest priority in 一屏结论 / 速读.
    try:
        from helpers.recent_flow_actions import detect_recent_flow_actions
        # v1.2.9 (codex MED): only clear operator-SOURCE roles — a fan-out FROM these
        # is a real seeding signal. Excludes fanout_recipient (a recipient, not a
        # source), treasury_vesting (a legit vesting distributor paying 10+ would
        # false-positive), and direct_dumper (already-sold, not a seeder).
        _op_roles = {"deployer", "mint_authority", "suspected_operator_reserve",
                     "fake_mining_cluster_member", "cex_fanout_hub",
                     "high_throughput_operator"}
        _cex_roles = {"public_cex_hot_wallet", "cex_deposit_destination"}
        _infra_roles = {"dex_pool", "router_aggregator"}
        _mw = skeleton.get("monitoring_wallets") or []
        _rf_op = {(_w.get("addr_full") or "").lower() for _w in _mw
                  if _w.get("monitor_role_enum") in _op_roles}
        _rf_cex = {(_w.get("addr_full") or "").lower() for _w in _mw
                   if _w.get("monitor_role_enum") in _cex_roles}
        _rf_infra = {(_w.get("addr_full") or "").lower() for _w in _mw
                     if _w.get("monitor_role_enum") in _infra_roles}
        # mint authorities from funding_attribution (may not all be in monitoring)
        for _a in ((funding_attribution.get("mint_authorities") or {}).get("authorities") or []):
            if _a.get("addr"):
                _rf_op.add(_a["addr"].lower())
        try:
            from chain_router import set_active_chain as _sac
            _sac(scope.get("chain_id"))
        except Exception:
            pass
        skeleton["recent_flow_actions"] = detect_recent_flow_actions(
            ca=ca, operator_addrs=_rf_op, cex_addrs=_rf_cex, infra_addrs=_rf_infra,
            window_days=3, min_counterparties=10,
        )
    except Exception as _e:
        import sys as _sys
        print(f"[recent_flow_actions] failed (non-fatal): {_e}", file=_sys.stderr)
        skeleton["recent_flow_actions"] = {"_error": str(_e)[:120]}

    # ---------- Round 10.45: recent_mint_events (v1.2.14) ----------
    # product spec 2026-07-01 (TAC): mint_authorities carries no timestamp, so a large RECENT
    # mint from 0x0 (operator creating fresh ammo — often the pump source) was invisible
    # in the 一屏结论 / 速读. Cheap (1 SQL, daily GROUP BY) on the Alpha chain; flags the
    # largest significant mint (>= 1% circ) within the recent window with its date.
    try:
        from helpers.recent_mint_events import detect_recent_mint_events
        try:
            from chain_router import set_active_chain as _sac2
            _sac2(scope.get("chain_id"))
        except Exception:
            pass
        _circ = float((skeleton.get("meta") or {}).get("circulating_supply") or 0)
        skeleton["recent_mint_events"] = detect_recent_mint_events(
            ca=ca, circ_supply=_circ, recent_window_days=14, min_pct_circ=1.0,
        )
    except Exception as _e:
        import sys as _sys
        print(f"[recent_mint_events] failed (non-fatal): {_e}", file=_sys.stderr)
        skeleton["recent_mint_events"] = {"_error": str(_e)[:120]}

    # ---------- Round 10.5: screen_summary (v1.0.4 — moved here) ----------
    # v1.0.4 (O 2026-06-20): build_screen_summary MUST run AFTER
    # annotate_monitoring_wallets (Round 10) + hidden_operator_enricher
    # (Round 9.5). The chip-structure 3-way (screen_summary._compute_chip_3way)
    # builds its operator union from monitoring_wallets[].monitor_role_enum,
    # which is ONLY assigned by annotate_monitoring_wallets. Built earlier (the
    # old Round 9 position), monitor_role_enum was still unset → op_union empty
    # → 一屏「筹码结构」reported operator 0.0% (假"分散") while the render-side
    # 真实派发 section — computed at render time, post-annotation — reported the
    # real operator % (e.g. O: 83.4% 高控盘). Same skeleton, contradictory
    # headline vs detail. Building here makes the headline use the identical
    # annotated data the detailed section does. chain_state (its other input)
    # is set in Round 9 above, so it is available.
    # v1.0.5 (ARX 2026-06-22): compute the neutral-infra exclusion set ONCE
    # (DEX/CEX infra that surf/Arkham labelled — must not count as operator).
    # Stored on the skeleton so the Python chip math AND the jinja 真实派发
    # classifier read the identical set → headline == detail.
    try:
        from helpers.screen_summary import compute_neutral_infra_addrs as _cni
        skeleton["_neutral_infra_addrs"] = _cni(skeleton)
    except Exception as _e:
        import sys as _sys
        print(f"[neutral_infra] failed (non-fatal): {_e}", file=_sys.stderr)
        skeleton["_neutral_infra_addrs"] = []
    try:
        from helpers.screen_summary import build_screen_summary as _build_screen_summary
        skeleton["screen_summary"] = _build_screen_summary(skeleton)
        import sys as _sys
        _ss = skeleton["screen_summary"]
        print(f"[screen_summary] {len(_ss.get('dimensions') or [])} dimensions, "
              f"one_sentence='{(_ss.get('one_sentence') or '')[:80]}'",
              file=_sys.stderr)
    except Exception as _e:
        import sys as _sys
        print(f"[screen_summary] failed (non-fatal): {_e}", file=_sys.stderr)
        skeleton["screen_summary"] = {"_error": str(_e)[:200]}

    # ---------- Round 11: address_role_resolver (v0.7.28) ----------
    # Build address_role_index — every address that appears across
    # detectors gets a primary_role + all_roles[] + cross-link target.
    # Render template uses this for selective dedupe (high_throughput +
    # fanout recipients sections only) + safety-net JSON dump in
    # machine_readable footer. 0 surf cost.
    try:
        from helpers.address_role_resolver import build_address_role_index
        skeleton["address_role_index"] = build_address_role_index(skeleton)
    except Exception as _e:
        import sys as _sys
        print(f"[address_role_resolver] failed (non-fatal): {_e}", file=_sys.stderr)
        skeleton["address_role_index"] = {}

    # v0.9.4: surf credit accounting. Pre-v0.9.4 the skeleton's three
    # `_credits_used=0` entries were leftover placeholders for skipped
    # detectors (cross_sym / wash / flow_operators). Now we record the
    # actual cumulative usage at top level so reports + monitoring can
    # show real cost per CA — and surface retry-storm waste (timeout
    # attempts billed for partial scan).
    try:
        # See entry-point comment: bare `section_a_scope` import — must match
        # the module instance parallel_surf writes to.
        from section_a_scope import _surf_credit_snapshot
        _credits_after = _surf_credit_snapshot()
        _b = _credits_before_snapshot
        skeleton["_surf_credits"] = {
            "credits_used": round(_credits_after["credits"] - _b["credits"], 2),
            "successful_calls": _credits_after["calls"] - _b["calls"],
            "billed_attempts": _credits_after["attempts"] - _b["attempts"],
            "wall_seconds": round(_credits_after["seconds"] - _b["seconds"], 2),
        }
    except Exception as _e:
        import sys as _sys
        print(f"[surf_credit_accounting] failed (non-fatal): {_e}", file=_sys.stderr)

    return skeleton


def _build_verdict_block(rule11: dict, anomaly72: dict) -> dict:
    enum, cn_label, baseline = _derive_verdict_enum(rule11, anomaly72)
    # next_tier is the enum the verdict CAN downgrade to (AVOID if currently
    # EXIT_IF_HOLDING, else same). Cross-LLM audit alpha.8 MEDIUM finding:
    # next_tier_cn was previously derived from `enum`, not `next_tier_enum`,
    # producing an (AVOID + 建议卖出) inconsistency for EXIT_IF_HOLDING cases.
    # Both fields must come from `next_tier_enum` to keep enum/label atomic.
    next_tier_enum = "AVOID" if enum == "EXIT_IF_HOLDING" else enum
    return {
        "enum": enum,
        "cn_label": cn_label,
        "baseline": baseline,
        "downgrade_applied": 1 if enum != baseline else 0,
        "next_tier_enum": next_tier_enum,
        "next_tier_cn": _i18n_t(f"verdict.cn_label.{next_tier_enum}"),
        "one_liner": "<LLM_NARRATIVE_PLACEHOLDER>",
    }


def _build_decision_action_block(rule11: dict, anomaly72: dict, liq: dict | None = None) -> dict:
    enum, _, _ = _derive_verdict_enum(rule11, anomaly72)
    action = _derive_action_enum(enum)
    # Pipeline-derived numeric slots (Phase B.1 fills from section_liq)
    liq = liq or {}
    overrides = liq.get("decision_action_overrides", {}) if liq else {}
    current_price = liq.get("current_price_usd")
    stop_trigger = overrides.get("stop_loss_trigger_price")

    return {
        "immediate_action": {
            "action_enum": action,
            "venue_enum": "alpha",
            "tranches_n": 3 if action == "sell" else 1,
            "tranche_max_usd": overrides.get("tranche_max_usd", 10000),
            "horizon_hours": 48 if action == "sell" else 0,
            "slippage_pct_cap": 3,
            "narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        "stop_loss": {
            "trigger_price_usd": stop_trigger,
            "current_price_usd": current_price,
            "delta_pct": (
                round((stop_trigger / current_price - 1) * 100, 1)
                if (stop_trigger and current_price) else None
            ),
            "rationale": "<LLM_NARRATIVE_PLACEHOLDER>",
        },
        # Re-entry conditions: pipeline pre-fills with Rule 11 quiet wallet
        # condition + circ-ratio threshold; LLM writes per-condition narrative.
        "re_entry_conditions": _build_re_entry_conditions(rule11, anomaly72),
    }


def _build_re_entry_conditions(rule11: dict, anomaly72: dict) -> list[dict]:
    """Pipeline-derived re-entry conditions. Each entry has condition_type +
    threshold + current_value (all locked), plus narrative (writable).

    v0.7.19.3 adversarial review MEDIUM#1: `quiet` set must exclude protocol_lockup
    wallets — vesting / multisig / treasury are NOT insider quiet
    candidates. Without this filter the "rule11_quiet_wallets_dumped_pct"
    re-entry condition would surface vesting contracts as if they were
    quiet insiders waiting to dump (the same vesting-vs-insider conflation
    that the COLLECT report's headline "潜伏 80% 抛压" came from).
    """
    conds = []
    quiet = [
        r for r in rule11.get("pre_launch_receivers", [])
        if r.get("dumped_pct") == 0
        and not r.get("is_protocol_lockup")
    ]
    if quiet:
        total_quiet = sum((r.get("current_balance") or 0) for r in quiet)
        conds.append({
            "condition_type": "rule11_quiet_wallets_dumped_pct",
            "threshold": 80,
            "current_value": 0,
            "narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        })
    conds.append({
        "condition_type": "alpha_anomaly_72h_event_count",
        "threshold": 0,
        "current_value": anomaly72.get("n_recent_events", 0),
        "narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
    })
    return conds


def main() -> int:
    # Beta.15: force UTF-8 stdout/stderr (Windows cp1252 chokes on
    # '→' / emoji / 中文 in progress prints). Same fix as render_report.py.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("ca", nargs="?", help="Contract address 0x... (positional or via --ca)")
    ap.add_argument("--ca", dest="ca_opt", default=None, help="Contract address")
    ap.add_argument("--alpha-listing-date", default=None,
                    help="YYYY-MM-DD. If omitted, derives from Alpha API.")
    # v0.6.1: --out-dir is new preferred CLI. It auto-creates the structured
    # layout: <out_dir>/.work/skeleton.json + <out_dir>/monitoring/.
    # --out is kept for backward compat (skeleton at exact path, monitoring
    # next to it). Pick whichever based on which flag user provides.
    ap.add_argument("--out-dir", dest="out_dir", default=None,
                    help="Output dir. v0.6.1 preferred. Auto-creates "
                         "<dir>/.work/skeleton.json + <dir>/monitoring/.")
    ap.add_argument("--out", default=None,
                    help="Legacy: skeleton.json file path. monitoring/ "
                         "written alongside. Use --out-dir for v0.6.1 layout.")
    # v0.6.2: --lang flag for i18n. Default zh (backward compat). When set
    # to "en", pipeline helpers emit English labels in skeleton; render
    # must be called with same --lang for consistency.
    ap.add_argument("--lang", default="zh", choices=("zh", "en"),
                    help="Pipeline output language for labels (default: zh).")
    args = ap.parse_args()

    # Set lang BEFORE build_skeleton() so all helpers using t() see correct lang.
    sys.path.insert(0, str(Path(__file__).parent / "helpers"))
    from i18n import set_lang
    set_lang(args.lang)

    # v0.6.5: silent update-check (24h cache, 3s timeout, non-blocking).
    # Prints i18n-localized one-liner to stderr if a newer version exists.
    # Disable via BINANCE_ALPHA_NO_UPDATE_CHECK=1.
    try:
        from update_check import check_for_update
        _u = check_for_update()
        # v0.9.5: auto-update on detection (audit Finding 1).
        # When update_check successfully ran `npx skills update hertzflow`,
        # the files on disk are now newer than what THIS process loaded.
        # Exit cleanly so the user can re-invoke and pick up the new code.
        # IMPORTANT: only the CLI entry-point may exit here. update_check
        # itself NEVER calls sys.exit (audit Finding 1: imported
        # library users like Discord bot batches must not be killed by
        # an upstream `check_for_update()` call).
        if isinstance(_u, dict) and _u.get("auto_updated"):
            return 0
    except SystemExit:
        raise   # never silently swallow SystemExit; preserve exit code
    except Exception:
        pass   # update check never blocks main pipeline

    ca = args.ca or args.ca_opt
    if not ca:
        ap.error("CA required (positional or --ca)")

    # Determine layout: --out-dir takes precedence; --out is legacy fallback;
    # default = current dir with v0.6.1 layout.
    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        work_dir = out_dir / ".work"
        work_dir.mkdir(parents=True, exist_ok=True)
        skeleton_path = work_dir / "skeleton.json"
        monitoring_parent = out_dir   # monitoring/ goes under out_dir, not under .work
    elif args.out:
        skeleton_path = Path(args.out)
        monitoring_parent = skeleton_path.parent
    else:
        # No flag → default v0.6.1 layout in current dir
        out_dir = Path(".")
        work_dir = out_dir / ".work"
        work_dir.mkdir(parents=True, exist_ok=True)
        skeleton_path = work_dir / "skeleton.json"
        monitoring_parent = out_dir

    # v0.7.17: banner moved from stderr → stdout. Windows PowerShell 5.1 turns
    # native-command stderr into a NativeCommandError record, which makes the
    # wrapper look like the pipeline crashed even though Python + surf are
    # still alive (Windows adversarial review BEAT rerun handoff 2026-05-28). audit
    # HIGH#1: if the caller chose `--out -` (stdout for the skeleton JSON),
    # writing a banner to stdout corrupts the JSON stream; in that case skip
    # the banner entirely (the file dest is stdout so stderr is the only
    # stream left for diagnostics, but PowerShell never sees `--out -`
    # because there is no `-` pseudo-path in the current CLI — guard anyway).
    _out_is_stdout = args.out is not None and args.out in ("-", "/dev/stdout")
    if not _out_is_stdout:
        print(f"forensic_pipeline.py v0.6 — CA={ca}", file=sys.stdout, flush=True)
    else:
        print(f"forensic_pipeline.py v0.6 — CA={ca}", file=sys.stderr, flush=True)

    # v0.7.17: incremental skeleton checkpoint. Each section dumps its raw
    # output to .work/skeleton_partial.json the moment it completes, so a long
    # tail section (e.g. wash_infra_detector at ~13 min on Windows-on-ARM
    # surf.exe x86_64 emulation) being interrupted by the user no longer
    # leaves them with zero durable output. After all sections finish, the
    # final assembled skeleton is written to skeleton.json as before.
    partial_path = skeleton_path.parent / "skeleton_partial.json"
    # audit HIGH#3: clear any stale checkpoint from a prior interrupted
    # run so the file `_last_section_completed` always reflects the CURRENT
    # invocation, never a previous one that died before its first _ck.
    try:
        if partial_path.exists():
            partial_path.unlink()
    except Exception as e:
        print(f"[checkpoint] stale cleanup failed: {e}", file=sys.stderr, flush=True)
    skeleton = build_skeleton(
        ca=ca, alpha_listing_date=args.alpha_listing_date,
        checkpoint_path=partial_path,
    )

    payload = json.dumps(skeleton, ensure_ascii=False, indent=2, default=str)
    skeleton_path.write_bytes(payload.encode("utf-8"))
    # audit HIGH#2: delete the checkpoint once the final skeleton is on
    # disk. Without this, a successful run leaves `skeleton_partial.json`
    # next to `skeleton.json` and an operator inspecting the directory cannot
    # tell whether the partial belongs to this run (now harmless) or a NEXT
    # invocation that has not yet started.
    try:
        if partial_path.exists():
            partial_path.unlink()
    except Exception as e:
        print(f"[checkpoint] final cleanup failed: {e}",
              file=sys.stderr, flush=True)

    status = skeleton.get("_status", "ok")
    timings = skeleton.get("_pipeline_timings", {})
    total = skeleton.get("_pipeline_total_seconds", 0)
    print(f"  status: {status}", file=sys.stderr)
    print(f"  total:  {total:.1f}s", file=sys.stderr)
    for k, v in timings.items():
        print(f"    {k}: {v:.1f}s", file=sys.stderr)
    print(f"  wrote: {skeleton_path} ({len(payload)} bytes)", file=sys.stderr)

    # v0.6.0-beta.3: monitoring_wallets multi-format export. Original v0.4.8
    # deliverable that v0.6 重写 dropped. v0.6.1 emits 2 files under
    # <out_dir>/monitoring/: paste.json + wallets_full.json.
    if status == "ok":
        meta = skeleton.get("meta", {})
        mw_export = monitoring_export.write_all(
            symbol=meta.get("symbol", "UNKNOWN"),
            chain=meta.get("chain", "BSC"),
            contract_address=meta.get("contract_address", ca),
            monitoring_wallets=skeleton.get("monitoring_wallets", []),
            out_dir=monitoring_parent,
            lang=args.lang,
        )
        print(f"  monitoring: {mw_export['n_wallets']} wallets → {mw_export['dir']}", file=sys.stderr)
        for fname in mw_export["files"]:
            print(f"    {fname}", file=sys.stderr)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
