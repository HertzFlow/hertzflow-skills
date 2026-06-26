"""supply_chain_overhang.py — v1.1.0 (CAP 2026-06-26 / rewritten 2026-06-27).

Accurate cross-chain 真实派发 (3-bucket) classification for the CANONICAL supply
chain of a multi-chain token, when Binance Alpha lists a small mirror but the
bulk of supply lives elsewhere.

Why this exists (CAP)
=====================
Alpha lists CAP as a BSC mirror (1.4% of supply); 99.6% of the 10B supply sits
on Ethereum — 84.5% in one unlabeled genesis-distribution contract
(0x0000…c3da) + the rest in project-controlled wallets fed by it through a
Gnosis Safe. The single-chain pipeline measured only the 1.4% BSC slice and
reported "🟢 分散 / operator 22.9%" when the truth is "~90% operator-controlled +
a massive locked overhang". the product spec ruled: the 3 buckets (庄家筹码 / 非庄家控制 /
中转) MUST be accurate — that is the #1 priority, cost is #2. See
[[multichain-chip-bucket-accuracy-spec]].

Design (REUSE the existing operator-union口径; anchor buckets to circulating)
===========================================================================
the product spec (2026-06-26, after rejecting a label-regex classifier three times): the
operator set is built by the SAME machinery the single-chain report uses —
deployer-rooted lineage (rule_11) + wallet cluster mapping + holder labels +
project multisig/reserve contracts.

v1.1.1 (UB 2026-06-27, the product spec caught): the buckets are measured as % of the
AUTHORITATIVE Alpha `circulating_supply`, NOT the on-chain top-holder sum. The
project-controlled supply that is NOT circulating (`total - circulating`) is an
OVERHANG, subtracted from the operator bucket. Without this, a token whose
project holds e.g. 8B across multisig Safes while only 3.75B is circulating reads
as "99.5% operator of a 10B base" instead of "62.5% overhang + ~47% operator of
the 3.75B float" (UB). `_compute_chip_3way`'s implied-circ denominator is exactly
the wrong base for these mirror tokens, so this helper computes the bucket token
sums directly from the operator union and anchors them to circulating_supply.

R6 (in-pipeline cross-chain run) — resolved
-------------------------------------------
The single-chain detectors are chain-portable: `chain_router.chain_lock(chain)`
flips `transfers_table()` for every downstream SQL. The cross-chain
`funding_attribution.multi_chain` block already proves `_discover_mint_authorities`
/ `discover_wallet_cluster_graph` (both via `_run_surf_with_retry`) run under
`chain_lock("ethereum")` in-pipeline (FOLKS ethereum mint_auth_n=3). 2026-06-27
verified `rule_11.run_backward_trace` ALSO runs cleanly under chain_lock(ethereum)
on CAP (deployer found, 8 receivers, ~10s, no hang) — the standalone "fast-path
all chunks errored" the handoff flagged was a harness artifact, not a chain-lock
defect. So this helper runs the FULL existing distribution mechanism on the
supply chain.

Pipeline (all under `chain_lock(supply_chain)`; restores the prior chain on exit)
  1. Holders — `surf token-holders` top-100 on the supply chain for reliable
     BALANCES. The `--include labels` field is flaky (CAP ethereum returned 0
     labels) so labels are resolved separately.
  2. Labels — `surf_labels_probe.resolve_labels` (R1 chunked + retry) gives
     reliable CEX / multisig / DEX classification for the top-K holders.
  3. R5 locked detection — a holder is LOCKED (excluded from the circulating
     denominator, reported as overhang) if it is a vesting/treasury/lock label,
     OR an UNLABELED CONTRACT whose balance alone exceeds the entire circulating
     supply (definitionally cannot all be circulating → genesis reserve). CAP:
     8.45B contract > 1.56B circulating → locked. Reuses `_is_contract`
     (eth_getCode, free public RPC). Bridge-lock holders are EXCLUDED as mirror
     backing (Phase 3 dedup), not counted as operator ammo.
  4. Operator set — rule_11 deployer-rooted lineage (`run_backward_trace`:
     deployer + pre_launch_receivers + dumper_destinations) ∪ a multi-hop
     genesis-funded BFS (catches post-launch distribution rule_11's pre-launch
     m6 misses) ∪ wallet cluster graph ∪ multisig-labelled holders.
  5. Relay — CEX-labelled holders (resolve_labels CEX classification).
  6. Buckets — build a supply-chain mini-skeleton (CEX holders in thc.cex; the
     rest non-locked in thc.unclassified; operator set as monitoring_wallets;
     clusters; mint authorities) and call `_compute_chip_3way`. Result:
     operator / relay(cex) / non-operator(retail) as % of CIRCULATING.

Cost: 1 token-holders call + 1 label batch + rule_11 (~5-8 SQL) + 1-3 cluster
SQL + a few multi-hop lineage SQL + free eth_getCode. Bounded by TOP_K.
Single-chain / BSC-native tokens never reach this helper
(detect_multichain_split → split=False → 0 cost). Solana is excluded
(HOLDER_SNAPSHOT, no agent.solana_* tables).
"""
from __future__ import annotations

import json
import re as _re
import subprocess
import sys
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

# tunables (kept conservative; accuracy-first, cost is bounded by TOP_K)
TOP_K = 40                    # classify the top-K holders by balance on supply chain
_LINEAGE_MAX_HOPS = 4         # multi-hop genesis distribution BFS depth
_RPC_TIMEOUT = 12

# public EVM RPCs by surf chain prefix (free, no key) — contract test only
_RPC_BY_PREFIX: dict[str, list[str]] = {
    "ethereum": ["https://eth.drpc.org", "https://ethereum.publicnode.com",
                 "https://rpc.ankr.com/eth"],
    "bsc": ["https://bsc-dataseed.binance.org", "https://bsc.publicnode.com"],
    "base": ["https://mainnet.base.org", "https://base.publicnode.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc", "https://arbitrum.publicnode.com"],
    "polygon": ["https://polygon-rpc.com", "https://polygon.publicnode.com"],
    "optimism": ["https://mainnet.optimism.io", "https://optimism.publicnode.com"],
}

# transfers table per surf prefix (the lineage SQL names the table explicitly so
# it is unambiguous which chain it queries).
_TRANSFERS_TABLE = {
    "ethereum": "agent.ethereum_transfers", "bsc": "agent.bsc_transfers",
    "base": "agent.base_transfers", "arbitrum": "agent.arbitrum_transfers",
    "polygon": "agent.polygon_transfers", "optimism": "agent.optimism_transfers",
}

# Multisig / project-custody labels → operator (a project Safe/treasury holding
# circulating supply is 项目方可控筹码). Bridge → EXCLUDED (mirror backing).
_MULTISIG_RE = _re.compile(
    r"gnosis\s*safe|safe\s*proxy|multisig|multi-?sig|timelock", _re.IGNORECASE)
# adversarial review MED#7: LOCKED-by-label must require TIME-LOCK evidence only. "treasury" /
# "reserve" alone is a live, sellable operator wallet (项目方弹药), NOT locked —
# excluding it as locked understates operator control. A genuine undistributed
# reserve is still caught by the contract-balance>circulating size test below.
_LOCK_LABEL_RE = _re.compile(
    r"vesting|timelock|time-?lock|lock-?up|cliff|unlock\s*schedule|"
    r"linear\s*release", _re.IGNORECASE)
_BRIDGE_RE = _re.compile(
    r"bridge|wormhole|layerzero|stargate|across|celer|cbridge|synapse|"
    r"multichain|anyswap|portal|hop\s*protocol|orbiter|axelar|hyperlane|"
    r"polygon\s*(?:pos\s*)?bridge|arbitrum\s*bridge|optimism\s*gateway",
    _re.IGNORECASE)
# Staking / vote-escrow lock contracts hold tokens deposited BY holders (the
# stakers own them, not the operator). They are circulating-but-locked, so they
# are NEITHER operator float NOR a project reserve — classify as non-operator and
# keep them OUT of the operator bucket even if the operator seeded the pool. UB:
# `veUnibase (VEBASE)` holds 1.945B staked — counting it as operator wrongly
# inflated control to 99.5%.
# adversarial review v4 CRITICAL: the generic words are case-insensitive, but the veToken
# heuristic (`ve` + Uppercase, e.g. veCRV / veUnibase) is CASE-SENSITIVE so it
# does NOT match the ordinary word "vesting" (ve+sting). Vesting is a project
# RESERVE (operator), not a staker lock — it must be checked separately (and
# BEFORE staking) so it is never mis-bucketed as non-operator.
_STAKING_GENERIC_RE = _re.compile(
    r"vote.?escrow|\bstaking\b|stak(?:ed|er)\b|\bgauge\b|reward\s*pool|"
    r"masterchef|liquid\s*stak", _re.IGNORECASE)
_VE_TOKEN_RE = _re.compile(r"\bve[A-Z][A-Za-z]")  # case-sensitive: veCRV / veUnibase


def _is_staking(label: str) -> bool:
    return bool(_STAKING_GENERIC_RE.search(label) or _VE_TOKEN_RE.search(label))


def _rpc(prefix: str, method: str, params: list) -> Any:
    """Single JSON-RPC call, trying the prefix's endpoints in order."""
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    )
    for url in _RPC_BY_PREFIX.get(prefix, []):
        try:
            proc = subprocess.run(
                ["curl", "-sS", "--max-time", str(_RPC_TIMEOUT),
                 "-H", "Content-Type: application/json",
                 "-H", "User-Agent: Mozilla/5.0",
                 "-X", "POST", "--data", payload, url],
                capture_output=True, text=True, check=False,
                timeout=_RPC_TIMEOUT + 4,
            )
            if proc.returncode != 0:
                continue
            doc = json.loads(proc.stdout)
            if "result" in doc:
                return doc["result"]
        except (subprocess.SubprocessError, json.JSONDecodeError, ValueError):
            continue
    return None


def _is_contract(prefix: str, addr: str, cache: dict[str, bool]) -> bool:
    """True if `addr` has bytecode (is a contract) on `prefix`. Cached.
    Fail-safe: on RPC failure returns False (treats as EOA — conservative,
    won't over-promote an unreachable address to the locked/operator bucket)."""
    if addr in cache:
        return cache[addr]
    code = _rpc(prefix, "eth_getCode", [addr, "latest"])
    is_c = bool(code and code != "0x" and len(code) > 4)
    cache[addr] = is_c
    return is_c


def _fetch_supply_holders(prefix: str, supply_ca: str, limit: int = 100):
    """surf token-holders for the supply chain → [(addr_lower, balance)] sorted
    desc. We take BALANCES here (reliable) and resolve labels separately because
    token-holders `--include labels` coverage is flaky on non-Alpha chains (CAP
    ethereum returned 0 labels for all 100 holders)."""
    try:
        from section_a_scope import _run_surf_with_retry
        cmd = ["surf", "token-holders", "--address", supply_ca, "--chain", prefix,
               "--limit", str(limit), "--include", "labels", "--json"]
        doc, _err = _run_surf_with_retry(cmd)
    except Exception as e:  # noqa: BLE001
        print(f"[supply_chain_overhang] holder fetch failed: {str(e)[:120]}",
              file=sys.stderr)
        return []
    rows: list[tuple[str, float]] = []
    burn = {"0x0000000000000000000000000000000000000000",
            "0x000000000000000000000000000000000000dead"}
    for r in (doc or {}).get("data") or []:
        a = (r.get("address") or "").lower()
        if not a or a in burn:
            continue
        try:
            b = float(r.get("balance") or 0)
        except (TypeError, ValueError):
            b = 0.0
        if b > 0:
            rows.append((a, b))
    rows.sort(key=lambda x: x[1], reverse=True)
    return rows


def _label_text(info: dict[str, Any]) -> str:
    """Combine resolve_labels fields into one text blob for regex matching."""
    parts = [info.get("entity_name"), info.get("label")]
    return " | ".join(p for p in parts if p)


def _funded_by_seed_one_hop(
    prefix: str, supply_ca: str, eoas: list[str], seed: set[str], date_floor: str,
) -> set[str]:
    """ONE batched onchain-sql query: which of `eoas` received the token FROM any
    address in `seed`? Bounded single query; fail-soft (empty on error)."""
    eoas = [a for a in eoas if a and a not in seed]
    if not eoas or not seed:
        return set()
    table = _TRANSFERS_TABLE.get(prefix)
    if not table:
        return set()
    eoa_list = ",".join(f"'{a}'" for a in eoas)
    seed_list = ",".join(f"'{a}'" for a in seed)
    sql = (
        f'SELECT DISTINCT lower("to") AS a FROM {table} '
        f"WHERE contract_address='{supply_ca.lower()}' "
        f'AND lower("to") IN ({eoa_list}) AND lower("from") IN ({seed_list}) '
        f"AND block_date >= '{date_floor}'"
    )
    try:
        from section_a_scope import _run_surf_with_retry
        doc, _err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": 500}),
            base_timeout=60, max_attempts=3,
        )
        if not doc:
            return set()
        return {(r.get("a") or "").lower() for r in (doc.get("data") or []) if r.get("a")}
    except Exception as e:  # noqa: BLE001
        print(f"[supply_chain_overhang] funded-by-seed query failed (non-fatal): "
              f"{str(e)[:120]}", file=sys.stderr)
        return set()


def _trace_operator_forward(
    prefix: str, supply_ca: str, initial_seed: set[str], top_holder_set: set[str],
    total_supply: float, date_floor: str, code_cache: dict[str, bool],
    do_not_expand: set[str], max_hops: int = _LINEAGE_MAX_HOPS,
) -> tuple[set[str], int]:
    """FORWARD expansion of the operator distribution tree from the seed,
    following ALL out-edges (including pass-through EOAs with ~0 current
    balance), then intersecting with the current top holders.

    Fixes the CAP 0xf440 miss: the operator routed `Safe → 0x5692 / 0xe7ae
    (pass-through EOAs, ~0 balance now) → 0xf440 (holds 104M)`. The
    candidate-restricted BFS below only walks among current top-100 holders, so
    the 0-balance feeders were never candidates and the chain broke — 0xf440 (an
    operator stash) was mis-bucketed as non-operator, understating operator%.

    Each hop queries every address that received >= min_edge from the current
    frontier (NOT restricted to top holders), adds them to the reachable set +
    frontier, and repeats. The result is `reachable ∩ top_holder_set`: only
    addresses that are BOTH reachable from the operator tree AND still hold a
    top-holder balance. This is also the contamination guard — a wallet the
    operator SOLD to that then dumped is reachable but no longer a top holder, so
    it is NOT marked operator; only wallets that received an operator allocation
    and STILL HOLD it (0xf440) are. `min_edge` keeps the walk on the
    distribution backbone (large allocations), not retail-sized dust.

    Bounded: <= max_hops surf calls; frontier capped per hop."""
    table = _TRANSFERS_TABLE.get(prefix)
    if not table or not initial_seed or not top_holder_set:
        return set(), 0
    min_edge = max(0.001 * (total_supply or 0), 1_000_000.0)
    operator_holders: set[str] = set()
    reachable: set[str] = set()
    frontier = {a for a in initial_seed if a}
    hops = 0
    from section_a_scope import _run_surf_with_retry
    from chain_router import decimals_factor_str
    df = decimals_factor_str()
    for _ in range(max_hops):
        if not frontier:
            break
        front = sorted(frontier)[:300]  # cap IN-list size
        from_list = ",".join(f"'{a}'" for a in front)
        # adversarial review MEDIUM: require at least ONE large transfer
        # (max(amt) >= min_edge), not just many small ones summing over — a
        # market-maker / exchange-deposit cluster receiving lots of dust must not
        # cross the operator-edge threshold by aggregation alone.
        sql = (
            f'SELECT lower("to") AS a, '
            f'sum(toFloat64(toDecimal256(amount_raw,0))/{df}) AS s, '
            f'max(toFloat64(toDecimal256(amount_raw,0))/{df}) AS mx '
            f"FROM {table} WHERE contract_address='{supply_ca.lower()}' "
            f'AND lower("from") IN ({from_list}) AND block_date >= \'{date_floor}\' '
            f"GROUP BY a HAVING s >= {min_edge} AND mx >= {min_edge} ORDER BY s DESC LIMIT 1000"
        )
        try:
            doc, _err = _run_surf_with_retry(
                ["surf", "onchain-sql"],
                stdin=json.dumps({"sql": sql, "max_rows": 1000}),
                base_timeout=60, max_attempts=3,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[supply_chain_overhang] forward-trace query failed (non-fatal): "
                  f"{str(e)[:120]}", file=sys.stderr)
            break
        hops += 1
        recips = {(r.get("a") or "").lower() for r in (doc or {}).get("data") or [] if r.get("a")}
        new = recips - reachable - initial_seed
        if not new:
            break
        reachable |= new
        # A reached top-holder is an operator STASH → mark it, but do NOT expand
        # through it (terminal; expanding would follow its own sells/buyers).
        operator_holders |= (new & top_holder_set)
        # adversarial review HIGH: only expand through genuine PASS-THROUGH EOAs
        # (not a current top holder → it forwarded what it received) that are NOT
        # DEX-pool/router/CEX/bridge/staking/neutral-infra. Crucially, never expand
        # through a NON-seed CONTRACT (a Uniswap/Pancake pool, router or CEX is a
        # contract) — that would fan out to genuine public buyers and mark them
        # operator. Only EOA pass-throughs propagate the operator tree.
        next_frontier: set[str] = set()
        for a in new:
            if a in top_holder_set or a in do_not_expand:
                continue
            if _is_contract(prefix, a, code_cache):  # non-seed contract (pool/router/CEX)
                continue
            next_frontier.add(a)
        frontier = next_frontier
        if len(reachable) > 2000:  # runaway guard
            break
    return operator_holders, hops


def _trace_operator_distribution(
    prefix: str, supply_ca: str, eoas: list[str], initial_seed: set[str],
    date_floor: str, code_cache: dict[str, bool], max_hops: int = _LINEAGE_MAX_HOPS,
) -> tuple[set[str], int]:
    """Multi-hop BFS over the operator distribution tree among the candidate
    holders. The operator rarely distributes the genesis supply directly to every
    wallet — it routes through a project multisig/treasury contract (CAP: genesis
    → Safe → operator wallets). A single hop catches only the Safe.

    adversarial review HIGH#4 (operator-sold-to-retail contamination): only propagate the seed
    through CONTRACT hubs (genesis/multisig/treasury/distributor contracts). A
    direct recipient of a hub is marked operator (it received an allocation, not a
    DEX buy — genuine retail buys are funded by the DEX pool, not a direct hub
    transfer), but a plain EOA recipient is NOT expanded, so the chain cannot
    cascade through `hub → operatorEOA → that EOA's own buyers`. Bounded: ≤
    max_hops surf calls + ≤ |new contracts| eth_getCode (cached, free)."""
    operator: set[str] = set()
    seed = set(initial_seed)
    remaining = [a for a in eoas if a not in seed]
    hops = 0
    for _ in range(max_hops):
        if not remaining:
            break
        found = _funded_by_seed_one_hop(prefix, supply_ca, remaining, seed, date_floor)
        hops += 1
        new = found - operator - seed
        if not new:
            break
        operator |= new
        remaining = [a for a in remaining if a not in new]
        # Expand the seed ONLY through contract hubs (no EOA cascade).
        new_hubs = {a for a in new if _is_contract(prefix, a, code_cache)}
        if not new_hubs:
            break  # all new recipients are leaf EOAs — nothing left to expand
        seed |= new_hubs
    return operator, hops


def compute_supply_chain_overhang(
    *,
    split: dict[str, Any],
    total_supply: float | None,
    circulating_supply: float | None,
    date_floor: str,
    alpha_listing_date: str | None = None,
    deployer_addr: str | None = None,
) -> dict[str, Any]:
    """Accurate 真实派发 3-bucket split for a multi-chain token's CANONICAL
    supply chain, reusing `_compute_chip_3way`.

    Call only when `detect_multichain_split` returned split=True. Manages
    `chain_lock(supply_chain)` + the secondary chain's token decimals internally
    (save/restore), so the caller's active chain is unchanged on return.

    Args:
        split: detect_multichain_split() output (supply_prefix / supply_ca /
            supply_chain_id_numeric / supply_chain_label / alpha_prefix / ...).
        total_supply / circulating_supply: from Alpha API.
        date_floor: 'YYYY-MM-DD' surf floor (helpers clamp to surf's 365d window).
        alpha_listing_date: 'YYYY-MM-DD' for rule_11's window anchoring.
        deployer_addr: primary-chain deployer (rule_11) if known — added to the
            operator seed.

    Returns the supply_chain_overhang dict. On failure returns
    {"split": True, "_error": "..."} so the caller falls back to the Alpha-chain
    chip without crashing.
    """
    prefix = (split or {}).get("supply_prefix") or ""
    supply_ca = ((split or {}).get("supply_ca") or "").lower()
    chain_id = (split or {}).get("supply_chain_id_numeric")
    if not prefix or not supply_ca:
        return {"split": True, "_error": "missing supply_prefix/supply_ca in split"}

    try:
        from chain_router import (
            chain_lock, get_token_decimals, set_token_decimals,
        )
    except Exception as e:  # noqa: BLE001
        return {"split": True, "_error": f"chain_router import failed: {str(e)[:120]}"}

    with chain_lock(prefix):
        _saved_dec = get_token_decimals()
        try:
            try:
                from section_a_scope import _fetch_evm_token_decimals
                _sec_dec = _fetch_evm_token_decimals(supply_ca, chain_id)
            except Exception:
                _sec_dec = None
            set_token_decimals(_sec_dec)  # None → fallback 18 internally
            return _compute_inner(
                prefix=prefix, supply_ca=supply_ca, split=split,
                total_supply=float(total_supply or 0),
                circulating_supply=float(circulating_supply or 0),
                date_floor=date_floor, alpha_listing_date=alpha_listing_date,
                deployer_addr=deployer_addr,
            )
        except Exception as e:  # noqa: BLE001 — fail-soft, never crash pipeline
            print(f"[supply_chain_overhang] failed (non-fatal): {str(e)[:200]}",
                  file=sys.stderr)
            return {"split": True, "_error": str(e)[:200]}
        finally:
            set_token_decimals(_saved_dec)  # restore primary chain, always


def _compute_inner(
    *, prefix: str, supply_ca: str, split: dict[str, Any], total_supply: float,
    circulating_supply: float, date_floor: str, alpha_listing_date: str | None,
    deployer_addr: str | None,
) -> dict[str, Any]:
    from funding_source_attribution import discover_mint_authorities
    from wallet_cluster_graph_detector import discover_wallet_cluster_graph
    from screen_summary import _is_neutral_infra_label
    from surf_labels_probe import resolve_labels

    # adversarial review MED#6: a valid circulating denominator is REQUIRED. Without it the
    # R5 locked-by-size test (bal > circulating) is disabled and a CAP-like 8.45B
    # genesis reserve would NOT be excluded → operator% computed on the wrong
    # denominator. Fail closed so the caller keeps the Alpha-chain chip rather
    # than overriding the headline with a broken number.
    if not circulating_supply or circulating_supply <= 0:
        return {"split": True,
                "_error": "missing/zero circulating_supply — cannot measure "
                          "supply-chain buckets safely"}

    # ---- 1. supply-chain top holders (reliable balances) ----
    holders = _fetch_supply_holders(prefix, supply_ca, limit=100)
    if not holders:
        return {"split": True, "_error": "no supply-chain holders fetched"}
    topk = holders[:TOP_K]            # lineage/cluster tracing is bounded to these
    addr_bal = {a: b for a, b in holders}

    # ---- 2. reliable labels (R1 chunked resolve) ----
    # adversarial review re-audit HIGH: resolve + classify (CEX / bridge / lock / multisig)
    # over ALL fetched holders, not just top-K. Since the circulating denominator
    # now includes holders ranked TOP_K+1..100 (adversarial review HIGH#3 fix), a CEX / bridge
    # / locked wallet down there must still be detected — otherwise it is silently
    # bucketed as non-operator retail (overstating "good" retail, understating
    # relay/exclusions). The expensive lineage/cluster tracing stays bounded to
    # top-K (those hold the operator control); label resolution is cheap+chunked.
    try:
        labels = resolve_labels([a for a, _ in holders]) or {}
    except Exception as e:  # noqa: BLE001
        print(f"[supply_chain_overhang] resolve_labels failed (non-fatal): {str(e)[:120]}",
              file=sys.stderr)
        labels = {}

    def _cls(addr: str) -> str:
        return ((labels.get(addr) or {}).get("classification") or "UNLABELED")

    def _lbl(addr: str) -> str:
        return _label_text(labels.get(addr) or {})

    circ = circulating_supply or None  # None → skip locked-by-size test
    code_cache: dict[str, bool] = {}

    # ---- 3. classify holders (bridge / staking / reserve / relay / multisig) ----
    # v1.1.1 (UB 2026-06-27): the circulating buckets are anchored to the Alpha
    # `circulating_supply`, and the project-controlled supply that is NOT
    # circulating (total - circulating) is reported as an OVERHANG, subtracted
    # from the operator bucket. So a project Safe / reserve contract is routed to
    # OPERATOR here (project-controlled) — the structural-overhang subtraction
    # below, not a per-address exclusion, separates its undistributed portion.
    # This fixes UB: 5 Gnosis Safes (8B) each < circulating (3.75B) escaped the
    # old single-contract `bal > circ` locked test and were counted as
    # circulating operator over a 10B holder-sum denominator → false 99.5%.
    excluded_addrs: set[str] = set()       # bridge backing — out of supply entirely
    staking_addrs: set[str] = set()        # ve / staking lock — non-operator (stakers)
    relay_addrs: set[str] = set()          # CEX — 中转
    multisig_addrs: set[str] = set()       # project multisig — operator reserve
    reserve_addrs: set[str] = set()        # vesting/treasury/big-contract — operator reserve
    rows_meta: list[dict[str, Any]] = []
    for addr, bal in holders:
        label = _lbl(addr)
        cls = _cls(addr)
        if _BRIDGE_RE.search(label):
            excluded_addrs.add(addr)
            rows_meta.append({"addr": addr, "balance": bal, "bucket": "bridge",
                              "reason": "bridge_backing_mirror", "label": label})
            continue
        if cls in ("CEX_HOT_WALLET", "CEX_DEPOSIT"):
            relay_addrs.add(addr)
            continue
        # vesting / timelock = project RESERVE (operator-side undistributed) —
        # checked BEFORE staking so "vesting" is never caught by the ve heuristic.
        if _LOCK_LABEL_RE.search(label):
            reserve_addrs.add(addr)
            rows_meta.append({"addr": addr, "balance": bal, "bucket": "reserve",
                              "reason": "vesting_lock_label", "label": label})
            continue
        # staking / ve-escrow = circulating-but-locked, held by stakers → non-operator.
        if _is_staking(label):
            staking_addrs.add(addr)
            rows_meta.append({"addr": addr, "balance": bal, "bucket": "staking",
                              "reason": "staking_lock_non_operator", "label": label})
            continue
        if _MULTISIG_RE.search(label):
            multisig_addrs.add(addr)
            continue
        # unlabeled CONTRACT whose balance alone exceeds circulating → reserve
        if (circ is not None and bal > circ
                and _is_contract(prefix, addr, code_cache)):
            pct_total = 100.0 * bal / total_supply if total_supply else 0.0
            reserve_addrs.add(addr)
            rows_meta.append({"addr": addr, "balance": bal, "bucket": "reserve",
                              "reason": f"reserve_contract_gt_circ_{pct_total:.1f}pct_of_total",
                              "label": label})
    # v1.0.5-parity: DEX router / aggregator / pool-manager / yield-vault are
    # neutral infra, never 项目方可控筹码 — even if they sit in the operator
    # distribution tree (e.g. the Uniswap V4 PoolManager receives LP from the
    # operator). Mirror the single-chain chip's _is_neutral_infra_label so the
    # supply-chain operator bucket uses the identical exclusion.
    neutral_infra: set[str] = {
        a for a, _b in holders if _is_neutral_infra_label(_lbl(a))
    }
    bridge_tokens = sum(r["balance"] for r in rows_meta if r["bucket"] == "bridge")
    staking_tokens = sum(r["balance"] for r in rows_meta if r["bucket"] == "staking")

    # candidate set for the EXPENSIVE lineage BFS + cluster = top-K project-side
    # candidate holders (exclude bridge / staking / relay / neutral-infra; the
    # classification above already covered all 100 holders).
    _non_candidate = excluded_addrs | staking_addrs | relay_addrs | neutral_infra
    # adversarial review v4 HIGH#2: the cheap seed-funded BFS runs over ALL fetched top-100
    # holders (an IN-list query, marginal cost) so operator shards ranked
    # TOP_K+1..100 are not silently dropped to retail. The EXPENSIVE cluster graph
    # stays bounded to top-K.
    bfs_candidates = [a for a, _b in holders if a not in _non_candidate]
    candidate_addrs = [a for a, _b in topk if a not in _non_candidate]

    # ---- 4a. operator seed: mint authorities + locked reserve contracts + deployer ----
    mint_auth = discover_mint_authorities(
        ca=supply_ca, date_floor=date_floor, top_n=10,
        min_pct_supply=0.001, total_supply=total_supply,
    )
    seed: set[str] = set(reserve_addrs)  # reserve contracts are operator distribution roots
    for a in (mint_auth.get("authorities") or []):
        ad = (a.get("addr") or "").lower()
        if ad:
            seed.add(ad)
    if deployer_addr:
        seed.add(deployer_addr.lower())

    # ---- 4b. rule_11 deployer-rooted lineage (the existing insider口径) ----
    rule11_ops: set[str] = set()
    rule11_summary: dict[str, Any] = {}
    if alpha_listing_date:
        try:
            from rule_11_backward_trace import run_backward_trace
            import tempfile
            import shutil
            _r11_workdir = tempfile.mkdtemp(prefix="r11_supply_")
            try:
                _r11 = run_backward_trace(
                    ca=supply_ca, alpha_listing_date=alpha_listing_date,
                    workdir=Path(_r11_workdir),
                )
            finally:
                # adversarial review LOW#8: rule_11 leaves its chunk query JSONs in workdir;
                # remove the temp dir so repeated pipeline runs don't leak.
                shutil.rmtree(_r11_workdir, ignore_errors=True)
            if not _r11.get("error"):
                _dep = (_r11.get("deployer") or "").lower()
                if _dep:
                    rule11_ops.add(_dep)
                    seed.add(_dep)
                for r in (_r11.get("pre_launch_receivers") or []):
                    a = (r.get("addr") or "").lower()
                    if a:
                        rule11_ops.add(a)
                for d in (_r11.get("dumper_destinations") or {}):
                    a = (d or "").lower()
                    if a:
                        rule11_ops.add(a)
                rule11_summary = {
                    "deployer": _dep or None,
                    "n_pre_launch_receivers": len(_r11.get("pre_launch_receivers") or []),
                    "n_dumper_destinations": len(_r11.get("dumper_destinations") or {}),
                }
            else:
                rule11_summary = {"_error": str(_r11.get("error"))[:160]}
        except Exception as e:  # noqa: BLE001
            print(f"[supply_chain_overhang] rule_11 failed (non-fatal): {str(e)[:120]}",
                  file=sys.stderr)
            rule11_summary = {"_error": str(e)[:160]}

    # ---- 4c. multi-hop genesis distribution BFS (post-launch lineage) ----
    op_funded, _hops_used = _trace_operator_distribution(
        prefix, supply_ca, bfs_candidates, seed, date_floor, code_cache
    )
    # ---- 4c-bis: FORWARD expansion through pass-through EOAs (CAP 0xf440 fix).
    # Follows the full operator out-tree (incl 0-balance feeders) and keeps the
    # top holders reachable from it — catches operator stashes the candidate BFS
    # misses when the operator routes via throwaway intermediaries. ----
    _top_holder_set = {a for a, _b in topk}
    _fwd_no_expand = excluded_addrs | staking_addrs | relay_addrs | neutral_infra
    # forward seed = the operator DISTRIBUTION HUBS (genesis/reserve/mint seed +
    # project multisig Safes). These are roots the trace must expand FROM even
    # when they are also top holders (the Safe holds 586M AND distributes); the
    # top-holder "don't expand" guard only filters DISCOVERED downstream nodes,
    # not these starting hubs.
    _fwd_seed = set(seed) | multisig_addrs | reserve_addrs
    op_forward, _fwd_hops = _trace_operator_forward(
        prefix, supply_ca, _fwd_seed, _top_holder_set, total_supply, date_floor,
        code_cache, _fwd_no_expand,
    )
    op_funded = op_funded | op_forward

    # ---- 4d. wallet cluster graph (wallet↔wallet operator groups) ----
    # adversarial review CRIT#2: never let bridge / staking / relay / neutral-infra addresses
    # into the cluster (their balance would re-enter the operator tail).
    _drop = excluded_addrs | staking_addrs | relay_addrs | neutral_infra
    _seed_circ = {a for a in seed if a not in _drop}
    try:
        cluster_res = discover_wallet_cluster_graph(
            ca=supply_ca, candidates=sorted(set(candidate_addrs) | _seed_circ),
            total_supply=total_supply, date_floor=date_floor,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[supply_chain_overhang] cluster failed (non-fatal): {str(e)[:120]}",
              file=sys.stderr)
        cluster_res = {"clusters": [], "summary": {}, "_error": str(e)[:120]}
    for _c in (cluster_res or {}).get("clusters") or []:
        if _drop:
            _c["addrs"] = [a for a in (_c.get("addrs") or []) if a.lower() not in _drop]
            _ab = _c.get("addr_balances") or {}
            for _k in list(_ab.keys()):
                if _k.lower() in _drop:
                    _ab.pop(_k, None)
            _c["addr_balances"] = _ab
            _c["cluster_balance_total_tokens"] = sum(_ab.values())
    cluster_addrs = {a.lower() for c in (cluster_res or {}).get("clusters") or []
                     for a in c.get("addrs") or []}

    # ---- 5. operator set = lineage ∪ genesis-funded ∪ cluster ∪ multisig ∪
    #         reserve contracts, minus staking / relay / bridge / neutral infra ----
    op_set = (rule11_ops | op_funded | cluster_addrs | multisig_addrs
              | reserve_addrs | set(seed))
    op_set = {a for a in op_set if a not in _drop}

    # ---- 6. buckets anchored to Alpha circulating_supply ----
    # v1.1.1 (UB): the buckets are % of the AUTHORITATIVE Alpha circulating float,
    # NOT the on-chain top-holder sum. Project-controlled supply that is not
    # circulating (total - circulating) is an OVERHANG, subtracted from the
    # operator bucket — so a project that holds 8B in Safes while only 3.75B is
    # circulating reads as "62.5% overhang + operator-of-circulating", not
    # "99.5% operator of a 10B base". Operator on-chain holdings (op_set, incl
    # reserve contracts) + cluster tail outside top-100; CEX = relay; everything
    # else circulating = non-operator. The undistributed reserve comes off the
    # operator side (project treasury holds it).
    op_onchain = sum(addr_bal[a] for a in op_set if a in addr_bal)
    cluster_tail = 0.0
    for _c in (cluster_res or {}).get("clusters") or []:
        for _a, _b in (_c.get("addr_balances") or {}).items():
            if _a.lower() not in addr_bal:  # cluster wallet outside top-100
                cluster_tail += float(_b or 0)
    op_onchain += cluster_tail
    cex_tokens = sum(addr_bal[a] for a in relay_addrs if a in addr_bal)

    # The undistributed reserve (overhang) is project-held. Subtract it from the
    # operator on-chain holdings, but never more than the operator actually holds
    # on-chain (`min(structural, op_onchain)`).
    #   - op_onchain >= structural  → operator holds the reserve + some circulating
    #     ammo; op_circ = the circulating remainder (CAP 1.20B, O 126M, UB 1.75B).
    #   - op_onchain <  structural  → the non-circulating supply is NOT fully
    #     visible in operator holdings (unminted / off-chain / unrecognized
    #     reserve); op_circ floors at 0 and `overhang_offchain_warning` flags that
    #     the operator% is a lower bound (adversarial review v4 HIGH#1).
    reserve_carrier = sum(addr_bal[a] for a in (reserve_addrs | multisig_addrs)
                          if a in addr_bal)
    structural_overhang = max(0.0, total_supply - circulating_supply)
    overhang_subtract = min(structural_overhang, op_onchain)
    overhang_offchain_warning = structural_overhang > op_onchain + 1.0
    op_circ = max(0.0, op_onchain - overhang_subtract)
    denom = circulating_supply

    # adversarial review v4 MEDIUM: CEX is an unambiguous labelled exchange holding → it gets
    # first claim on the 100% cap; operator takes the remainder up to its computed
    # value; non-operator is the residual. If operator+CEX raw share exceeds the
    # circulating float (project holdings can't be reconciled to circulating),
    # flag it rather than silently zeroing a real bucket.
    cex_raw_pct = (100.0 * cex_tokens / denom) if denom else 0.0
    op_raw_pct = (100.0 * op_circ / denom) if denom else 0.0
    cex_pct = min(100.0, cex_raw_pct)
    op_pct = min(max(0.0, 100.0 - cex_pct), op_raw_pct)
    retail_pct = max(0.0, 100.0 - op_pct - cex_pct)
    reconcile_warning = (op_raw_pct + cex_raw_pct) > 105.0
    implied_circ = denom
    locked_tokens = structural_overhang
    overhang_in_reserve = sum(addr_bal[a] for a in reserve_addrs if a in addr_bal)

    # ---- audit trail: per top-holder bucket ----
    _classified_already = {r["addr"] for r in rows_meta}
    classified_rows: list[dict[str, Any]] = list(rows_meta)
    for addr, bal in holders:
        if addr in _classified_already:
            continue  # bridge / staking / reserve already recorded
        if addr in relay_addrs:
            bucket, reason = "relay", "cex_label"
        elif addr in op_set:
            if addr in rule11_ops:
                reason = "rule11_lineage"
            elif addr in op_funded:
                reason = "genesis_lineage"
            elif addr in cluster_addrs:
                reason = "wallet_cluster"
            elif addr in multisig_addrs:
                reason = "multisig_label"
            else:
                reason = "operator_seed"
            bucket = "operator"
        else:
            bucket, reason = "non_operator", "unlinked"
        classified_rows.append({"addr": addr, "balance": bal, "bucket": bucket,
                                "reason": reason, "label": _lbl(addr)})

    locked_pct_of_total = (100.0 * structural_overhang / total_supply) if total_supply else 0.0
    staking_pct_of_total = (100.0 * staking_tokens / total_supply) if total_supply else 0.0

    return {
        "split": True,
        "supply_chain": prefix,
        "supply_chain_label": (split or {}).get("supply_chain_label") or prefix.upper(),
        "supply_ca": supply_ca,
        "alpha_chain": (split or {}).get("alpha_prefix"),
        "supply_pct_of_total": (split or {}).get("supply_pct_of_total"),
        # 流通三桶 (% of Alpha CIRCULATING supply; overhang/bridge NOT in denominator)
        "operator_pct": round(op_pct, 1),
        "relay_pct": round(cex_pct, 1),
        "non_operator_pct": round(retail_pct, 1),
        "circulating_supply": circulating_supply,
        "circulating_classified_tokens": implied_circ,
        "operator_circulating_tokens": round(op_circ, 0),
        "operator_onchain_tokens": round(op_onchain, 0),
        "reserve_carrier_tokens": round(reserve_carrier, 0),
        "overhang_reconcile_warning": reconcile_warning,
        "overhang_offchain_warning": overhang_offchain_warning,
        # 锁仓/未派发 overhang = total − circulating (% of TOTAL supply, 单独报)
        "locked_tokens": structural_overhang,
        "locked_pct_of_total": round(locked_pct_of_total, 1),
        "reserve_onchain_tokens": round(overhang_in_reserve, 0),  # 链上可见储备合约
        "staking_locked_tokens": staking_tokens,
        "staking_pct_of_total": round(staking_pct_of_total, 1),
        "bridge_tokens": bridge_tokens,
        # evidence / audit trail
        "n_holders_scanned": len(holders),
        "n_holders_traced": len(topk),
        "n_operator_wallets": len(op_set),
        "n_reserve_contracts": len(reserve_addrs),
        "n_staking_locks": len(staking_addrs),
        "n_rule11_lineage": len(rule11_ops),
        "n_genesis_funded": len(op_funded),
        "lineage_hops_used": _hops_used,
        "n_clusters": len((cluster_res or {}).get("clusters") or []),
        "n_relay_cex": len(relay_addrs),
        "n_mint_authorities": len((mint_auth.get("authorities") or [])),
        "rule11_summary": rule11_summary,
        "operator_seed": sorted(seed),
        "classified_rows": classified_rows,
        "_method": (
            "buckets anchored to Alpha circulating_supply; overhang = "
            "total − circulating (undistributed project reserve, subtracted from "
            "operator). operator = rule_11 lineage + multi-hop genesis BFS + "
            "wallet cluster + multisig/reserve contracts; relay = CEX "
            "(resolve_labels); staking/ve locks = non-operator; bridge excluded. "
            "All SQL under chain_lock(supply_chain)."
        ),
    }


__all__ = ["compute_supply_chain_overhang"]
