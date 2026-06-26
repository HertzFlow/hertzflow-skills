#!/usr/bin/env python3
"""role_classifier.py — v0.7.7 whale role classification.

Inputs: a cross-sym whale candidate (address + the token CA + listing date).
Output: deterministic role + evidence chain, derived purely from on-chain
behavior. Does NOT depend on Arkham labels (Arkham is used by the sibling
surf_labels_probe to filter known infrastructure BEFORE this classifier
runs, but here we work with what's left).

6-step decision tree (see reference_whale_role_and_wash_methodology.md
for the full doc):

  Step 1: EOA vs CONTRACT (eth_getCode → BSC RPC, free)
  Step 2: funder distribution (1 SQL)
  Step 3: recipient distribution (1 SQL)
  Step 4: upstream chain trace, max 3 hops by default (1-3 SQL)
  Step 5: temporal pattern derived from existing data (0 SQL)
  Step 6: net-flow derived (0 SQL)

Total: ~3-5 SQL per candidate. Returns role + confidence + evidence.

Role enum:
  insider_allocation_holder    — project-aligned, got lump sum on TGE
  active_multi_token_allocator — like above but actively manages many bags
  dex_mm_bot                   — MM contract trading vs LP
  retail_holder                — DEX-bought, long-held
  wash_infra_member            — part of a wash setup (defer to wash detector)
  unknown                      — insufficient signal
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any
from chain_router import (  # v0.7.20 / .21.7
    transfers_table, dex_trades_table,
    is_valid_addr as _chain_is_valid_addr,
    get_active_chain as _chain_get_active,
)

# Surf SQL timeout — narrower than CA-wide queries to fail fast
SURF_TIMEOUT_SECS = 30
# v0.7.21.7: kept for back-compat callers; chain-aware checks go through
# `_addr_ok` below so Solana base58 candidates survive the guard.
_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")


def _addr_ok(addr) -> bool:
    if not isinstance(addr, str) or not addr:
        return False
    if _chain_get_active() == "solana":
        return _chain_is_valid_addr(addr)
    return _chain_is_valid_addr(addr.lower())
MINT_ADDR = "0x0000000000000000000000000000000000000000"

# Binance Alpha 2.0 Router — well-known liquidation venue used by insiders
# to sell via off-chain orderbook without leaving DEX volume traces.
ALPHA_ROUTER_BSC = "0x73d8bd54f7cf5fab43fe4ef40a62d390644946db"


class RoleClassifierError(Exception):
    """Hard failure. Caller should catch and default classification to unknown."""


def _run_sql(sql: str, max_rows: int = 50) -> tuple[list[dict], int]:
    body = json.dumps({"sql": sql, "max_rows": max_rows})
    try:
        proc = subprocess.run(
            ["surf", "onchain-sql"],
            input=body, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=SURF_TIMEOUT_SECS, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        raise RoleClassifierError(f"surf onchain-sql failed: {e}") from e
    if proc.returncode != 0:
        raise RoleClassifierError(
            f"surf exit {proc.returncode}: {proc.stderr[:200]}"
        )
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RoleClassifierError(f"surf non-JSON: {e}") from e
    if doc.get("error"):
        raise RoleClassifierError(f"surf API error: {doc['error']}")
    credits = int((doc.get("meta") or {}).get("credits_used") or 1)
    return doc.get("data") or [], credits


def _eth_get_code(addr: str) -> tuple[str, int]:
    """Returns (code_hex, byte_count). 0x → EOA. Free RPC (no surf credits)."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [addr, "latest"],
        "id": 1,
    }
    try:
        proc = subprocess.run(
            ["curl", "-sS", "-X", "POST", "https://bsc-dataseed.binance.org",
             "-H", "Content-Type: application/json",
             "--max-time", "8",
             "-d", json.dumps(payload)],
            capture_output=True, text=True, check=False,
            timeout=13,   # v0.9.9: subprocess ceiling > curl --max-time 8 (deadlock guard)
        )
        result = json.loads(proc.stdout).get("result", "")
    except Exception:
        return "", 0
    if not result or not result.startswith("0x"):
        return "", 0
    code_bytes = (len(result) - 2) // 2
    return result, code_bytes


def _step1_eoa_vs_contract(addr: str) -> dict:
    """eth_getCode → EOA vs contract size tier. Free (no surf)."""
    code, code_bytes = _eth_get_code(addr)
    if code == "0x" or code_bytes == 0:
        return {"is_contract": False, "code_bytes": 0, "size_tier": "EOA"}
    if code_bytes < 5000:
        tier = "PROXY_OR_SIMPLE"
    elif code_bytes < 15000:
        tier = "LITE_MM"
    elif code_bytes < 50000:
        tier = "FULL_MM"
    else:
        tier = "COMPLEX_AGGREGATOR"
    return {"is_contract": True, "code_bytes": code_bytes, "size_tier": tier}


def _step2_funders(ca: str, addr: str, listing_date: str) -> tuple[dict, int]:
    """Who sent token to this addr? Returns top-funder pattern."""
    sql = (
        f"SELECT `from` AS funder, count(*) AS n, "
        f"sum(amount) AS tok, sum(coalesce(amount_usd,0)) AS usd, "
        f"min(block_time) AS first_ts "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' "
        f"AND block_date >= '{listing_date}' "
        f"AND `to` = '{addr}' "
        f"GROUP BY funder ORDER BY tok DESC LIMIT 5"
    )
    rows, credits = _run_sql(sql)
    if not rows:
        return {"pattern": "no_inflow", "top_funder": None, "total_in_tok": 0}, credits
    total_tok = sum(float(r.get("tok") or 0) for r in rows)
    top = rows[0]
    top_share = float(top.get("tok") or 0) / max(total_tok, 1)
    pattern = "unknown"
    if len(rows) == 1 and int(top.get("n") or 0) == 1:
        pattern = "single_lump"
    elif top_share > 0.9 and int(top.get("n") or 0) <= 3:
        pattern = "single_funder_few_tx"
    elif len(rows) >= 3:
        pattern = "multi_funder"
    return {
        "pattern": pattern,
        "top_funder": top.get("funder"),
        "top_funder_tok": float(top.get("tok") or 0),
        "top_funder_usd": float(top.get("usd") or 0),
        "top_funder_first_ts": int(top.get("first_ts") or 0),
        "top_share": top_share,
        "total_in_tok": total_tok,
    }, credits


def _step3_recipients(ca: str, addr: str, listing_date: str) -> tuple[dict, int]:
    """Where did this addr send token? Pattern reveals exit channel."""
    sql = (
        f"SELECT `to` AS dst, count(*) AS n, "
        f"sum(amount) AS tok, sum(coalesce(amount_usd,0)) AS usd "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' "
        f"AND block_date >= '{listing_date}' "
        f"AND `from` = '{addr}' "
        f"GROUP BY dst ORDER BY tok DESC LIMIT 5"
    )
    rows, credits = _run_sql(sql)
    if not rows:
        return {"pattern": "no_outflow", "top_recipient": None, "total_out_tok": 0}, credits
    total_tok = sum(float(r.get("tok") or 0) for r in rows)
    top = rows[0]
    top_share = float(top.get("tok") or 0) / max(total_tok, 1)
    top_addr = (top.get("dst") or "").lower()
    pattern = "unknown"
    if top_addr == ALPHA_ROUTER_BSC and top_share > 0.85:
        pattern = "alpha_router_dominant"   # 经 Alpha 卖 = insider 液体化
    elif top_share > 0.9:
        pattern = "single_destination"
    elif len(rows) >= 3 and top_share < 0.5:
        pattern = "distributed"
    return {
        "pattern": pattern,
        "top_recipient": top_addr,
        "top_share": top_share,
        "total_out_tok": total_tok,
    }, credits


def _step4_upstream_chain(ca: str, addr: str, max_hops: int = 3) -> tuple[dict, int]:
    """Walk backwards from addr → biggest funder → biggest funder → ...
    Stop when reach mint, cycle, or max_hops. Returns chain + reached_mint."""
    chain = [addr.lower()]
    credits_total = 0
    current = addr.lower()
    for hop in range(max_hops):
        sql = (
            f"SELECT `from` AS src, sum(amount) AS tok "
            f"FROM {transfers_table()} "
            f"WHERE contract_address = '{ca}' "
            f"AND block_date >= '2025-01-01' "
            f"AND `to` = '{current}' "
            f"GROUP BY src ORDER BY tok DESC LIMIT 1"
        )
        try:
            rows, c = _run_sql(sql)
            credits_total += c
        except RoleClassifierError:
            break
        if not rows:
            break
        top_src = (rows[0].get("src") or "").lower()
        if not top_src or top_src in chain:
            break
        chain.append(top_src)
        if top_src == MINT_ADDR:
            return {"chain": chain, "reached_mint": True, "hops": len(chain) - 1}, credits_total
        current = top_src
    return {"chain": chain, "reached_mint": False, "hops": len(chain) - 1}, credits_total


def _step5_temporal(ca: str, addr: str, listing_date: str,
                    funder_first_ts: int) -> dict:
    """Derive temporal pattern from funder timestamp + listing date.
    Free (no extra SQL — uses data from Step 2)."""
    if not funder_first_ts or not listing_date:
        return {"tge_proximity_minutes": None, "interpretation": "unknown"}
    try:
        from datetime import datetime, timezone, date
        # listing_date is YYYY-MM-DD; treat as UTC midnight (TGE actual time
        # may be later in the day — same-day window of ±24h covers that).
        listing_dt = datetime.combine(
            date.fromisoformat(listing_date), datetime.min.time(),
            tzinfo=timezone.utc,
        )
        funder_dt = datetime.fromtimestamp(funder_first_ts, tz=timezone.utc)
        delta_seconds = (funder_dt - listing_dt).total_seconds()
        delta_minutes = int(delta_seconds / 60)
    except Exception:
        return {"tge_proximity_minutes": None, "interpretation": "unknown"}
    interp = "unknown"
    # Thresholds: TGE listing date is given as date-only, so the actual TGE
    # event sits somewhere within ±24h of the date's UTC midnight. A "TGE-
    # aligned" event is anything from 24h before to 24h after the date,
    # which captures both pre-listing OTC settlements and same-day allocations.
    if -60 * 24 <= delta_minutes <= 60 * 24:
        interp = "tge_aligned"             # 上线日 ±24h = insider (lump-sum 通常发生在此窗口)
    elif delta_minutes < -60 * 24 * 7:
        interp = "pre_launch_insider"      # 上线前 7+ 天 = 早 insider (Round-1 投资者等)
    elif delta_minutes < -60 * 24:
        interp = "pre_launch_recent"       # 上线前 1-7 天 (= 公告期 / TGE-day 准备期)
    else:
        interp = "post_launch_acquisition" # 上线后 > 1 天 (= 二级市场买入, 不是 allocation)
    return {
        "tge_proximity_minutes": delta_minutes,
        "interpretation": interp,
    }


def _step6_netflow_signature(total_in_tok: float, total_out_tok: float) -> dict:
    """Net-flow shape inferred from Step 2 + Step 3 totals. Free (no SQL)."""
    if total_in_tok == 0 and total_out_tok == 0:
        return {"shape": "no_activity", "out_in_ratio": None}
    if total_in_tok == 0:
        return {"shape": "send_only", "out_in_ratio": float("inf")}
    ratio = total_out_tok / total_in_tok
    shape = "unknown"
    if abs(ratio - 1.0) < 0.001:
        shape = "perfect_round_trip"    # = wash / atomic-pair routing
    elif ratio < 0.1:
        shape = "accumulating"          # tok 收下后基本没动 = dormant bag
    elif ratio > 10:
        shape = "distributing"          # 卖出远超买入 (净卖出)
    elif 0.95 <= ratio <= 1.05:
        shape = "mm_balanced"           # MM 1:1 双向 with small drift
    elif ratio < 0.5:
        shape = "net_holder"            # 卖了一部分, 持大头
    else:
        shape = "net_seller"
    return {"shape": shape, "out_in_ratio": ratio}


def _decide_role(s1: dict, s2: dict, s3: dict, s4: dict, s5: dict, s6: dict) -> dict:
    """Combine 6 steps into a single role classification."""
    is_contract = s1.get("is_contract", False)
    size_tier = s1.get("size_tier", "EOA")
    funder_pat = s2.get("pattern", "unknown")
    recip_pat = s3.get("pattern", "unknown")
    reached_mint = s4.get("reached_mint", False)
    tge_interp = s5.get("interpretation", "unknown")
    flow_shape = s6.get("shape", "unknown")

    # MM bot path — contract in 15-50KB range with LP-dominant counterparties
    if is_contract and size_tier in ("LITE_MM", "FULL_MM", "COMPLEX_AGGREGATOR"):
        # wash infra: contract with perfect round-trip 1:1 flow
        if flow_shape == "perfect_round_trip":
            return {"role": "wash_infra_member", "confidence": 0.7,
                    "rationale": f"Contract with perfect round-trip flow {s6}"}
        # active MM: balanced buy/sell against LP
        if flow_shape == "mm_balanced" and recip_pat == "single_destination":
            return {
                "role": "dex_mm_bot",
                "confidence": 0.85,
                "rationale": (
                    f"Contract {size_tier} ({s1.get('code_bytes')} bytes), "
                    f"balanced 1:1 flow vs single LP destination"
                ),
            }
        # MM unwinding: was MM (LP-routed), now net-selling — common late-stage
        if (flow_shape in ("net_seller", "distributing")
                and recip_pat == "single_destination"):
            return {
                "role": "dex_mm_bot_unwinding",
                "confidence": 0.8,
                "rationale": (
                    f"Contract {size_tier} ({s1.get('code_bytes')} bytes), "
                    f"net-selling to single LP destination "
                    f"(out/in ratio {s6.get('out_in_ratio'):.2f}) — MM winding down"
                ),
            }

    # Insider allocation path (EOA + lump sum + reached mint + TGE-aligned + Alpha exit)
    if (not is_contract
            and funder_pat in ("single_lump", "single_funder_few_tx")
            and reached_mint
            and tge_interp in ("tge_aligned", "pre_launch_recent", "pre_launch_insider")
            and recip_pat == "alpha_router_dominant"):
        return {
            "role": "insider_allocation_holder",
            "confidence": 0.9,
            "rationale": (
                f"EOA + single lump from {s2.get('top_funder','?')[:12]} "
                f"({s5.get('tge_proximity_minutes')} min from TGE), "
                f"upstream {s4.get('hops')}-hop to mint, "
                f"exits via Alpha Router"
            ),
        }

    # Active multi-token allocator (cross-token activity needed; deferred — set by caller)
    # This branch returns insider but flags for caller upgrade based on cross-token check.

    # Insider but didn't sell via Alpha router (might hold long-term)
    if (not is_contract
            and funder_pat in ("single_lump", "single_funder_few_tx")
            and reached_mint
            and tge_interp in ("tge_aligned", "pre_launch_recent")):
        return {
            "role": "insider_allocation_holder",
            "confidence": 0.75,
            "rationale": (
                f"EOA + single lump near TGE + upstream-to-mint, but exit "
                f"pattern={recip_pat} (not Alpha-router dominant)"
            ),
        }

    # Retail / late buyer
    if (not is_contract
            and not reached_mint
            and flow_shape in ("accumulating", "net_holder")):
        return {
            "role": "retail_holder",
            "confidence": 0.6,
            "rationale": (
                f"EOA + multi-source funder + upstream stops outside mint chain "
                f"({s4.get('hops')} hops), holding {flow_shape}"
            ),
        }

    # Contract but small / unknown — proxy or aggregator
    if is_contract and size_tier == "PROXY_OR_SIMPLE":
        return {
            "role": "unknown_contract_small",
            "confidence": 0.4,
            "rationale": f"Small contract ({s1.get('code_bytes')} bytes), pattern inconclusive",
        }

    # Default: unknown
    return {
        "role": "unknown",
        "confidence": 0.3,
        "rationale": (
            f"Signals: contract={is_contract}/{size_tier} funder={funder_pat} "
            f"recip={recip_pat} mint={reached_mint} tge={tge_interp} flow={flow_shape}"
        ),
    }


def classify(addr: str, ca: str, listing_date: str | None = None) -> tuple[dict, int]:
    """Classify one whale candidate. Returns (result, credits_used).

    `result` shape:
        {
            "role": str,
            "confidence": float,
            "rationale": str,
            "evidence": {
                "step1_contract": {...},
                "step2_funder": {...},
                "step3_recipient": {...},
                "step4_upstream": {...},
                "step5_temporal": {...},
                "step6_netflow": {...},
            },
            "_credits_used": int,
        }
    """
    a = (addr or "").lower()
    c = (ca or "").lower()
    if not _addr_ok(a):
        raise RoleClassifierError(f"invalid addr: {addr!r}")
    if not _addr_ok(c):
        raise RoleClassifierError(f"invalid ca: {ca!r}")
    if not listing_date:
        listing_date = "2025-01-01"  # safe fallback
    # Cross-LLM security audit fix: use fullmatch — `re.match` lets `$`
    # match before a trailing `\n`, allowing newline-suffix SQL injection
    # via the listing_date interpolated into f-string SQL below.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", listing_date):
        raise RoleClassifierError(f"invalid listing_date: {listing_date!r}")

    credits = 0

    # Step 1 — free RPC
    s1 = _step1_eoa_vs_contract(a)

    # Steps 2 + 3 — 1 SQL each
    s2, c2 = _step2_funders(c, a, listing_date)
    credits += c2
    s3, c3 = _step3_recipients(c, a, listing_date)
    credits += c3

    # Step 4 — up to 3 SQL (max_hops default)
    s4, c4 = _step4_upstream_chain(c, a, max_hops=3)
    credits += c4

    # Steps 5 + 6 — derived, free
    s5 = _step5_temporal(c, a, listing_date,
                         funder_first_ts=s2.get("top_funder_first_ts") or 0)
    s6 = _step6_netflow_signature(
        total_in_tok=s2.get("total_in_tok") or 0,
        total_out_tok=s3.get("total_out_tok") or 0,
    )

    decision = _decide_role(s1, s2, s3, s4, s5, s6)
    decision["evidence"] = {
        "step1_contract": s1,
        "step2_funder": s2,
        "step3_recipient": s3,
        "step4_upstream": s4,
        "step5_temporal": s5,
        "step6_netflow": s6,
    }
    decision["_credits_used"] = credits
    return decision, credits


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--listing-date", default=None)
    args = ap.parse_args()
    try:
        result, credits = classify(args.addr, args.ca, listing_date=args.listing_date)
    except RoleClassifierError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    print(f"[surf credits: {credits}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
