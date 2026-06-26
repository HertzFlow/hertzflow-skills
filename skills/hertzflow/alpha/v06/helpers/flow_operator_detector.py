#!/usr/bin/env python3
"""flow_operator_detector.py — v0.7.21 flow-based wallet detector.

Captures two blind spots that v0.7.20.2 misses:

  1. Cross-Alpha trading operator — single EOA running the same
     strategy across many Alpha tokens; low single-token balance, high
     tx frequency. cross_sym detector is stock-based (top-100 holders ×
     multiple Alpha tokens), so a wallet with 0.005% of supply but 2k+
     txs is invisible there.

  2. Single-operator asynchronous wash (P → X → Q on separate txs) —
     two counterparties dominate flow, in ≈ out, but each leg is its
     own tx. wash_infra detector requires atomic_pair_ratio ≥ 0.85
     (both legs in one tx_hash), so the async pattern is invisible.

Both share the primary signal `tx_from_diversity < 0.05` (one upstream
signer drives every interaction with the wallet). Sub-class then splits
on counterparty structure and cross-Alpha activity.

See `v06/v0721_DESIGN.md` for the full spec, threshold rationale,
budget projection, and regression test list.

## Budget

Three batch SQL queries + one Arkham label batch. ~20-25 seconds
wall-clock and ~30-40 surf credits on top of v0.7.20.2's ~480 baseline.
Total report cost stays under $5.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from chain_router import (  # v0.7.20 / .21.7
    transfers_table, get_active_chain, chain_lock,
    is_valid_addr as _chain_is_valid_addr,
)

# v0.7.21.7: kept for back-compat callers that referenced this constant
# directly; the SQL-injection guard inside `detect` uses the chain-aware
# `_chain_is_valid_addr` so Solana base58 candidates pass through.
_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Pre-committed thresholds — see v0721_DESIGN.md §Thresholds.
# Do NOT tune to "rescue" a specific case; if a candidate doesn't meet
# the documented bar, document the miss rather than lowering it.
MIN_TX_THIS_TOKEN = 200
MAX_TX_FROM_DIVERSITY = 0.05
MIN_TOP2_RATIO = 0.80
MIN_CROSS_ALPHA_TOKENS = 5
MAX_NET_BALANCE_PCT = 0.5  # filters genuine holders who happen to trade

# Arkham label families that mark a counterparty as routing-class
# infrastructure (vs a plain EOA). Matched case-insensitive against the
# label_text and entity_type fields the same way section_cross_sym does.
_ROUTER_HINTS = (
    "router", "aggregator", "swap", "1inch", "okx", "pancake", "uniswap",
    "kyber", "paraswap", "0x protocol", "matcha", "alpha 2.0",
)
_CEX_HINTS = ("deposit", "cex", "exchange", "hot wallet", "binance", "kucoin",
              "okx exchange", "bybit", "mexc", "xt.com", "gate.io", "huobi",
              "kraken", "coinbase")


class FlowOperatorError(ValueError):
    """Raised on invalid input (bad addr / bad date / SQL injection guard)."""


def _validate_inputs(ca: str, candidates: list[str], listing_date: str) -> list[str]:
    """Reject anything that doesn't pass the active chain's address
    format (EVM 0x40-hex or Solana base58 32-44) and a YYYY-MM-DD date.

    Defence in depth — every input flows into SQL `IN (…)` clauses and we
    do NOT trust upstream to have validated. v0.7.21.7: chain-aware via
    `chain_router.is_valid_addr`, so Solana CAs no longer get rejected
    here even though Section A accepted them upstream.
    """
    is_solana = get_active_chain() == "solana"
    ca_norm = ca if is_solana else (ca or "").lower()
    if not _chain_is_valid_addr(ca_norm):
        raise FlowOperatorError(f"invalid ca: {ca!r}")
    if not _DATE_RE.fullmatch(listing_date or ""):
        raise FlowOperatorError(f"invalid listing_date: {listing_date!r}")
    clean: list[str] = []
    seen: set[str] = set()
    for a in candidates:
        a_norm = a if is_solana else (a or "").lower()
        if not _chain_is_valid_addr(a_norm):
            continue
        if a_norm in seen:
            continue
        seen.add(a_norm)
        clean.append(a_norm)
    return clean


_TRANSIENT_HINTS = (
    "429", "too many requests", "rate", "throttle", "timeout",
    "service unavailable", "503", "504", "temporarily",
)


def _is_transient(text: str) -> bool:
    lower = (text or "").lower()
    return any(h in lower for h in _TRANSIENT_HINTS)


def _run_sql(sql: str, max_rows: int = 500,
             max_attempts: int = 4) -> tuple[list[dict], int]:
    """Run one surf onchain-sql with exponential backoff retry.

    v0.7.21 hot-fix: section_flow_operators runs immediately after
    section_wash_infra, which fires ~1200 surf calls (154 candidates ×
    8 workers × 4-5 steps). The first PLAY v0.7.21 run captured
    section_flow_operators returning 0 operators and 0 credits while
    direct-call testing returned 1 + 25 — i.e. surf was 429-throttling
    every flow_operator SQL because wash_infra had just exhausted the
    rate budget. Adding retry brings flow_operator's success rate in
    the back-to-back scenario to ~100%.

    Returns ([], 0) only after all attempts fail; partial / non-
    transient errors return immediately.
    """
    last_err = ""
    for attempt in range(max_attempts):
        try:
            proc = subprocess.run(
                ["surf", "onchain-sql"],
                input=json.dumps({"sql": sql, "max_rows": max_rows}),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=60, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            last_err = str(e)
            if _is_transient(last_err) and attempt + 1 < max_attempts:
                import random
                import time as _t
                _t.sleep((2 ** attempt) * (0.5 + random.random()))
                continue
            print(f"[flow_operator_detector] surf failed: {last_err}", file=sys.stderr)
            return [], 0
        if proc.returncode != 0:
            last_err = (proc.stderr or "")[:300]
            if _is_transient(last_err) and attempt + 1 < max_attempts:
                import random
                import time as _t
                _t.sleep((2 ** attempt) * (0.5 + random.random()))
                continue
            print(
                f"[flow_operator_detector] surf exit {proc.returncode}: {last_err}",
                file=sys.stderr,
            )
            return [], 0
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return [], 0
        if doc.get("error"):
            err_text = str(doc.get("error"))
            if _is_transient(err_text) and attempt + 1 < max_attempts:
                import random
                import time as _t
                _t.sleep((2 ** attempt) * (0.5 + random.random()))
                continue
            print(
                f"[flow_operator_detector] surf API error: {err_text}",
                file=sys.stderr,
            )
            return [], 0
        rows = doc.get("data") or []
        credits = int((doc.get("meta") or {}).get("credits_used") or 0)
        return rows, credits
    print(
        f"[flow_operator_detector] surf retries exhausted ({max_attempts}): {last_err}",
        file=sys.stderr,
    )
    return [], 0


def _arkham_classify(label_text: str, entity_type: str, entity_name: str) -> str:
    """Categorise a counterparty by Arkham label hints.

    Returns one of: 'router', 'cex', 'eoa', 'other'.
    'other' = labelled but not router/cex (e.g. NFT contract).
    'eoa' = unlabelled (no Arkham entry) — treat as plain wallet.
    """
    text = " ".join(
        x for x in [label_text or "", entity_type or "", entity_name or ""]
    ).lower()
    if not text.strip():
        return "eoa"
    if any(h in text for h in _ROUTER_HINTS):
        return "router"
    if any(h in text for h in _CEX_HINTS):
        return "cex"
    return "other"


def _fetch_arkham_labels(addrs: list[str]) -> dict[str, dict]:
    """Batch wallet-labels-batch (max 100 per call). Returns {addr: {...}}.
    """
    if not addrs:
        return {}
    out: dict[str, dict] = {}
    # Chunk to 100 (surf cap).
    for i in range(0, len(addrs), 100):
        chunk = addrs[i:i + 100]
        try:
            proc = subprocess.run(
                ["surf", "wallet-labels-batch",
                 "--addresses", ",".join(chunk),
                 "--json"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=30, check=False,
            )
            if proc.returncode != 0:
                continue
            doc = json.loads(proc.stdout)
            for r in (doc.get("data") or []):
                a = (r.get("address") or "").lower()
                if not a:
                    continue
                # surf wallet-labels-batch can shape labels in either of
                # two ways depending on the dataset: nested under
                # `label.labels[]` (with confidence) or as a flat list
                # `labels[]` of strings. Handle both — v0.7.21 PLAY case
                # had 0xc8f6b8 in the flat-string form.
                label_blob = r.get("label") or {}
                top_label_text: str | None = None
                if isinstance(label_blob, dict):
                    inner = label_blob.get("labels")
                    if isinstance(inner, list) and inner:
                        # nested with confidence
                        try:
                            top = max(
                                inner,
                                key=lambda x: (
                                    x.get("confidence", 0)
                                    if isinstance(x, dict) else 0
                                ),
                            )
                            top_label_text = (top or {}).get("label") if isinstance(top, dict) else None
                        except (TypeError, ValueError):
                            top_label_text = None
                # Flat top-level labels list (string or dict elements).
                flat = r.get("labels")
                if not top_label_text and isinstance(flat, list) and flat:
                    first = flat[0]
                    top_label_text = first if isinstance(first, str) else (
                        first.get("label") if isinstance(first, dict) else None
                    )
                out[a] = {
                    "label_text": top_label_text,
                    "entity_name": r.get("entity_name") or (
                        label_blob.get("entity_name") if isinstance(label_blob, dict) else None
                    ),
                    "entity_type": r.get("entity_type") or (
                        label_blob.get("entity_type") if isinstance(label_blob, dict) else None
                    ),
                }
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            continue
    return out


def detect(
    *,
    ca: str,
    candidate_addrs: list[str],
    listing_date: str,
    total_supply: int | None,
    alpha_token_cas_base: set[str] | None = None,
    alpha_token_cas_bsc: set[str] | None = None,
    alpha_ca_to_sym_base: dict[str, str] | None = None,
    alpha_ca_to_sym_bsc: dict[str, str] | None = None,
    cross_alpha_window_days: int = 60,
) -> tuple[list[dict], int]:
    """v0.7.21 flow-based operator detector.

    Args:
        ca: subject token contract address (lower-case 0x40-hex).
        candidate_addrs: union of (wash_infra step-0 candidates) and
            (dump_tracker top-200 DEX sellers). The detector validates
            and dedupes — pass whatever's available.
        listing_date: YYYY-MM-DD, lower bound for the subject-token SQL.
        total_supply: token total supply, used to filter by
            MAX_NET_BALANCE_PCT (genuine holders, not bots).
        alpha_token_cas_base / alpha_token_cas_bsc: Alpha API token CA
            sets per chain. Used to compute `cross_alpha_token_count`
            (how many other Alpha tokens the candidate also touches).
            If None or empty, cross_alpha_token_count stays at 0.
        cross_alpha_window_days: lookback window for cross-Alpha scan.
            Default 60 days matches the design doc threshold.

    Returns:
        (operators, credits_used) — operators is a list of dicts (see
        v0721_DESIGN.md §Output schema) sorted by n_tx_this_token DESC.
        credits_used is the surf credit total for this detector run.

    Per the design doc, this never raises — surf failures degrade to
    empty operators / 0 credits and a stderr warning.
    """
    candidates = _validate_inputs(ca, candidate_addrs, listing_date)
    if not candidates:
        return [], 0

    credits_total = 0
    in_list = ",".join(f"'{a}'" for a in candidates)

    # ---- batch SQL 1: per-candidate stats on the SUBJECT token ------
    # diversity = count(DISTINCT tx_from) / count(*) per candidate.
    # Combined with n_tx and net flow in a single GROUP BY.
    transfers = transfers_table()
    sql_subject = (
        f"SELECT addr, "
        f"  count(DISTINCT tx_from) AS unique_origins, "
        f"  count(*) AS n_tx, "
        f"  sumIf(amount, role='sent') AS tok_out, "
        f"  sumIf(amount, role='recv') AS tok_in "
        f"FROM ("
        f"  SELECT `from` AS addr, amount, tx_from, 'sent' AS role "
        f"  FROM {transfers} "
        f"  WHERE contract_address='{ca.lower()}' "
        f"    AND block_date >= '{listing_date}' "
        f"    AND `from` IN ({in_list}) "
        f"  UNION ALL "
        f"  SELECT `to` AS addr, amount, tx_from, 'recv' AS role "
        f"  FROM {transfers} "
        f"  WHERE contract_address='{ca.lower()}' "
        f"    AND block_date >= '{listing_date}' "
        f"    AND `to` IN ({in_list}) "
        f") "
        f"GROUP BY addr"
    )
    # v0.7.21 hot-fix: surf caps max_rows at 10000. Subject stats SQL
    # returns one row per candidate so len(candidates)+10 is correct but
    # we clamp defensively in case future caller passes >9990 candidates.
    rows1, c1 = _run_sql(sql_subject, max_rows=min(len(candidates) + 10, 10000))
    credits_total += c1
    subject_stats: dict[str, dict] = {}
    for r in rows1:
        a = (r.get("addr") or "").lower()
        n_tx = int(r.get("n_tx") or 0)
        u_origin = int(r.get("unique_origins") or 0)
        tok_in = float(r.get("tok_in") or 0)
        tok_out = float(r.get("tok_out") or 0)
        net_balance = tok_in - tok_out
        diversity = (u_origin / n_tx) if n_tx > 0 else 1.0
        net_pct = (net_balance / total_supply * 100) if total_supply else None
        subject_stats[a] = {
            "n_tx": n_tx,
            "tx_from_diversity": diversity,
            "tok_in": tok_in,
            "tok_out": tok_out,
            "net_balance": net_balance,
            "net_balance_pct_supply": net_pct,
        }

    # Apply primary gate: single-operator + high enough frequency.
    survivors = [
        a for a, s in subject_stats.items()
        if s["n_tx"] >= MIN_TX_THIS_TOKEN
        and s["tx_from_diversity"] < MAX_TX_FROM_DIVERSITY
        and (s["net_balance_pct_supply"] is None
             or abs(s["net_balance_pct_supply"]) <= MAX_NET_BALANCE_PCT)
    ]
    if not survivors:
        return [], credits_total

    surv_list = ",".join(f"'{a}'" for a in survivors)

    # ---- batch SQL 2: top-2 counterparty per survivor on this token --
    # For each survivor compute total per-counterparty tx count, then
    # the helper picks top 2 in Python (window functions vary across
    # ClickHouse surf builds; staying portable).
    sql_cp = (
        f"SELECT addr, counterparty, count(*) AS n "
        f"FROM ( "
        f"  SELECT `from` AS addr, `to` AS counterparty "
        f"  FROM {transfers} "
        f"  WHERE contract_address='{ca.lower()}' "
        f"    AND block_date >= '{listing_date}' "
        f"    AND `from` IN ({surv_list}) "
        f"  UNION ALL "
        f"  SELECT `to` AS addr, `from` AS counterparty "
        f"  FROM {transfers} "
        f"  WHERE contract_address='{ca.lower()}' "
        f"    AND block_date >= '{listing_date}' "
        f"    AND `to` IN ({surv_list}) "
        f") "
        f"GROUP BY addr, counterparty"
    )
    # v0.7.21 hot-fix: surf caps max_rows at 10000. The PLAY case hit
    # this — 62 survivors × 200 = 12500, INVALID_REQUEST, zero rows back,
    # every operator got empty counterparty_top2 and got mis-classified
    # as UNCLASSIFIED_SINGLE_OPERATOR. Cap at the surf limit; in
    # practice a survivor has < 50 unique counterparties on the subject
    # token (most txs go through the same router / pool), so a per-
    # survivor budget of 50 fits well under the cap.
    rows2, c2 = _run_sql(sql_cp, max_rows=min(len(survivors) * 50 + 100, 10000))
    credits_total += c2
    cp_by_addr: dict[str, list[tuple[str, int]]] = {}
    _is_solana = get_active_chain() == "solana"
    for r in rows2:
        # Solana base58 is case-sensitive; EVM is case-insensitive.
        a = r.get("addr") or ""
        cp = r.get("counterparty") or ""
        if not _is_solana:
            a = a.lower()
            cp = cp.lower()
        if not (_chain_is_valid_addr(a) and _chain_is_valid_addr(cp)):
            continue
        cp_by_addr.setdefault(a, []).append((cp, int(r.get("n") or 0)))
    # Pick top-2 per addr, compute ratio
    top2_by_addr: dict[str, dict] = {}
    for a, cps in cp_by_addr.items():
        cps.sort(key=lambda t: t[1], reverse=True)
        total = sum(n for _, n in cps)
        if total <= 0:
            continue
        top2 = cps[:2]
        top2_n = sum(n for _, n in top2)
        top2_by_addr[a] = {
            "top2": [{"addr": cp, "n_tx": n} for cp, n in top2],
            "top2_ratio": top2_n / total,
        }

    # ---- batch SQL 3: cross-Alpha token count (60d, current chain) ---
    sql_cross = (
        f"SELECT addr, count(DISTINCT contract_address) AS n_tokens, "
        f"  count(*) AS n_tx "
        f"FROM ( "
        f"  SELECT `from` AS addr, contract_address "
        f"  FROM {transfers} "
        f"  WHERE block_date >= today() - {cross_alpha_window_days} "
        f"    AND `from` IN ({surv_list}) "
        f"  UNION ALL "
        f"  SELECT `to` AS addr, contract_address "
        f"  FROM {transfers} "
        f"  WHERE block_date >= today() - {cross_alpha_window_days} "
        f"    AND `to` IN ({surv_list}) "
        f") "
        f"GROUP BY addr"
    )
    rows3, c3 = _run_sql(sql_cross, max_rows=len(survivors) + 10)
    credits_total += c3
    # We can't list every contract_address per addr (too much); the
    # cross_alpha_token_count is an UPPER bound on Alpha matches. To
    # get the EXACT Alpha count we'd need contract_address per row,
    # which blows up the row count. Per design doc, we instead reuse
    # the SQL above for total distinct tokens and add a separate
    # SQL only for the Alpha-CA intersection if alpha sets are given.
    cross_stats: dict[str, dict] = {}
    for r in rows3:
        a = (r.get("addr") or "").lower()
        cross_stats[a] = {
            "cross_token_count_all": int(r.get("n_tokens") or 0),
            "n_tx_60d_all_tokens": int(r.get("n_tx") or 0),
        }

    # Optional: scope cross_token_count to Alpha tokens. Two SQL — one
    # for the active chain (the table chain_router currently points at),
    # one for BSC if BSC is NOT the active chain. The Alpha CA sets are
    # chain-specific (a token on Base has a different CA than a wrapper
    # on BSC, even when it's the "same" project), so we sum the per-chain
    # counts. PLAY case: active chain Base hits 3 Alpha tokens, BSC adds
    # 28 (the same operator runs on BSC too) → total 31, comfortably
    # above MIN_CROSS_ALPHA_TOKENS=5.

    # v0.7.21.2: per-survivor cross-Alpha token breakdown. For every
    # survivor we collect (sym, n_tx, chain) tuples so the report can
    # name *which* Alpha tokens the operator runs on (the design doc
    # called for a sub-table per operator, but v0.7.21 only kept the
    # count — user feedback caught the gap).
    cross_alpha_breakdown: dict[str, list[dict]] = {a: [] for a in survivors}

    def _run_alpha_scan(
        alpha_ca_set: set[str],
        ca_to_sym: dict[str, str],
        transfers_for_chain: str,
        chain_label: str,
    ) -> int:
        if not alpha_ca_set:
            return 0
        # Drop the subject token from the scan — we don't want
        # cross_alpha_token_count incrementing because of the report's
        # own token. v0.7.21.7: chain-aware — Solana CAs are case-sensitive,
        # EVM are lowercase. _chain_is_valid_addr handles both per active chain.
        if get_active_chain() == "solana":
            clean_set = {a for a in alpha_ca_set
                         if _chain_is_valid_addr(a) and a != ca}
        else:
            clean_set = {a.lower() for a in alpha_ca_set
                         if _chain_is_valid_addr(a.lower())
                         and a.lower() != ca.lower()}
        if not clean_set:
            return 0
        alpha_in = ",".join(f"'{a}'" for a in clean_set)
        sql_alpha = (
            f"SELECT addr, contract_address AS ca, count(*) AS n_tx "
            f"FROM ( "
            f"  SELECT `from` AS addr, contract_address "
            f"  FROM {transfers_for_chain} "
            f"  WHERE block_date >= today() - {cross_alpha_window_days} "
            f"    AND `from` IN ({surv_list}) "
            f"    AND contract_address IN ({alpha_in}) "
            f"  UNION ALL "
            f"  SELECT `to` AS addr, contract_address "
            f"  FROM {transfers_for_chain} "
            f"  WHERE block_date >= today() - {cross_alpha_window_days} "
            f"    AND `to` IN ({surv_list}) "
            f"    AND contract_address IN ({alpha_in}) "
            f") "
            f"GROUP BY addr, ca"
        )
        # Per design max_rows budget: 62 survivors × ~30 cross-Alpha tokens
        # ≈ 1860 worst case. Clamp at surf's 10K cap defensively.
        rows_alpha, c_alpha = _run_sql(
            sql_alpha,
            max_rows=min(len(survivors) * 200 + 100, 10000),
        )
        for r in rows_alpha:
            a = (r.get("addr") or "").lower()
            ca_hit = (r.get("ca") or "").lower()
            n_tx = int(r.get("n_tx") or 0)
            if a not in cross_stats or not ca_hit:
                continue
            cross_alpha_breakdown.setdefault(a, []).append({
                "ca": ca_hit,
                "sym": ca_to_sym.get(ca_hit, "?"),
                "chain": chain_label,
                "n_tx": n_tx,
            })
        return c_alpha

    active_chain = get_active_chain()
    if active_chain == "bsc":
        # Active chain is already BSC. Merge symbol maps so a CA listed
        # on both chains is still labelled.
        union_set = (alpha_token_cas_bsc or set()) | (alpha_token_cas_base or set())
        union_map = {**(alpha_ca_to_sym_base or {}), **(alpha_ca_to_sym_bsc or {})}
        credits_total += _run_alpha_scan(union_set, union_map, transfers_table(), "bsc")
    else:
        # Scan active chain first (PLAY: Base).
        credits_total += _run_alpha_scan(
            alpha_token_cas_base or set(),
            alpha_ca_to_sym_base or {},
            transfers_table(),
            active_chain,
        )
        # Then BSC — chain_lock flips the router for the BSC SQL and
        # restores on exit.
        if alpha_token_cas_bsc:
            try:
                with chain_lock("bsc"):
                    credits_total += _run_alpha_scan(
                        alpha_token_cas_bsc,
                        alpha_ca_to_sym_bsc or {},
                        transfers_table(),
                        "bsc",
                    )
            except Exception as e:
                print(
                    f"[flow_operator_detector] BSC cross-Alpha scan failed: {e}",
                    file=sys.stderr,
                )

    # v0.7.21.2: aggregate per-op count + FULL sorted breakdown (no cap).
    # User explicitly chose option B (full compact inline) over a top-N
    # cap — the report renders every cross-Alpha token in one
    # `sym(n_tx·chain) · sym(...) · ...` line per operator, so the user
    # never has to open skeleton.json to see the full list. Skeleton
    # grows ~140KB (62 ops × ~30 tokens × 80 bytes/entry) which is
    # well within acceptable bounds.
    for a in survivors:
        tokens = cross_alpha_breakdown.get(a) or []
        tokens.sort(key=lambda t: t["n_tx"], reverse=True)
        # Distinct (chain, ca) — the same CA may appear on both chains
        # (e.g. a bridged wrapper); we keep both rows so a future audit
        # can see the chain split. The count is over distinct (chain, ca).
        cross_stats[a]["cross_alpha_token_count"] = len(tokens)
        cross_stats[a]["cross_alpha_tokens"] = tokens

    # ---- Arkham labels for OPERATORS + top-2 counterparties --------
    # v0.8.0.2 fix (user catch): operators themselves were never labeled
    # — only counterparties. That meant a known router masquerading as
    # an operator survived classification + showed as "UNCLASSIFIED
    # single operator", and DEX_ARB_BOT vs ASYNC_WASH couldn't reflect
    # the operator's own arkham class. Merge survivor addresses into
    # the same label-resolution batch (0 extra surf round-trip —
    # _fetch_arkham_labels does one batched call regardless).
    label_addr_set: set[str] = set(survivors)
    for a in survivors:
        for cp in top2_by_addr.get(a, {}).get("top2", []):
            label_addr_set.add(cp["addr"])
    labels = _fetch_arkham_labels(sorted(label_addr_set))

    # ---- Assemble operator rows + sub-classification ----------------
    operators = []
    for a in survivors:
        s = subject_stats[a]
        top2 = top2_by_addr.get(a, {})
        cross = cross_stats.get(a, {})
        cp_top2 = top2.get("top2") or []
        # Annotate top-2 with Arkham classification
        annotated_top2 = []
        for cp in cp_top2:
            lbl = labels.get(cp["addr"]) or {}
            cls = _arkham_classify(
                lbl.get("label_text") or "",
                lbl.get("entity_type") or "",
                lbl.get("entity_name") or "",
            )
            annotated_top2.append({
                "addr": cp["addr"],
                "n_tx": cp["n_tx"],
                "arkham_class": cls,
                "arkham_label": lbl.get("label_text"),
                "arkham_entity_name": lbl.get("entity_name"),
            })

        # Sub-classification rules — see v0721_DESIGN.md §sub_class table.
        sub_classes = []
        top2_ratio = top2.get("top2_ratio", 0.0)
        cross_alpha = cross.get("cross_alpha_token_count", 0)
        if top2_ratio >= MIN_TOP2_RATIO and len(annotated_top2) == 2:
            classes = {cp["arkham_class"] for cp in annotated_top2}
            if classes <= {"router", "cex"} and classes:
                sub_classes.append("DEX_ARB_BOT")
            elif "eoa" in classes:
                sub_classes.append("ASYNC_WASH")
        if cross_alpha >= MIN_CROSS_ALPHA_TOKENS:
            sub_classes.append("CROSS_ALPHA_OPERATOR")

        if not sub_classes:
            # Survivors that pass diversity but match no sub-class are
            # still informative — flag as UNCLASSIFIED so the report can
            # surface them without forcing a category fit.
            sub_classes.append("UNCLASSIFIED_SINGLE_OPERATOR")

        # v0.8.0.2 fix: annotate operator self with arkham label.
        op_lbl = labels.get(a) or {}
        op_arkham_cls = _arkham_classify(
            op_lbl.get("label_text") or "",
            op_lbl.get("entity_type") or "",
            op_lbl.get("entity_name") or "",
        )
        operators.append({
            "addr": a,
            "sub_class": sub_classes[0],          # primary tag
            "sub_classes_all": sub_classes,        # full set
            # v0.8.0.2 — Arkham label for operator itself (was missing).
            # Caller (render_report.py) surfaces this in the FLOW
            # OPERATORS table column so a router/CEX hot wallet shows
            # the entity name + class instead of "UNCLASSIFIED".
            "arkham_label": op_lbl.get("label_text"),
            "arkham_entity_name": op_lbl.get("entity_name"),
            "arkham_entity_type": op_lbl.get("entity_type"),
            "arkham_classification": op_arkham_cls,
            "n_tx_this_token": s["n_tx"],
            "tx_from_diversity": s["tx_from_diversity"],
            "tok_in_this_token": s["tok_in"],
            "tok_out_this_token": s["tok_out"],
            "net_balance_this_token": s["net_balance"],
            "net_balance_pct_supply": s["net_balance_pct_supply"],
            "counterparty_top2_ratio": top2_ratio,
            "counterparty_top2": annotated_top2,
            "n_tx_60d_all_tokens": cross.get("n_tx_60d_all_tokens", 0),
            "cross_token_count_all": cross.get("cross_token_count_all", 0),
            "cross_alpha_token_count": cross_alpha,
            # v0.7.21.2: full per-Alpha-token breakdown — list of
            # {ca, sym, chain, n_tx}, sorted by n_tx DESC. Rendered as
            # one compact inline line per operator so the report covers
            # the whole cross-Alpha activity without pushing the user
            # to skeleton.json. Empty when alpha_ca_to_sym_* not passed.
            "cross_alpha_tokens": cross.get("cross_alpha_tokens", []),
            # v0.7.21.1: writable narrative slots so the report shows
            # plain-language analysis per operator (matches the cross_sym
            # whales pattern). LLM fills these with what this wallet IS
            # (identity_narrative) and how to use the information
            # (risk_assessment_narrative). The user reads the report,
            # not the skeleton — every operator needs to stand on its
            # own without the reader hunting for context in JSON.
            "identity_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
            "risk_assessment_narrative": "<LLM_NARRATIVE_PLACEHOLDER>",
        })

    operators.sort(key=lambda o: o["n_tx_this_token"], reverse=True)
    return operators, credits_total
