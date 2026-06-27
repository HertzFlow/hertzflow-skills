"""primary_sale_attribution.py — v1.2.0 (CAP 2026-06-27).

Identify a token's PRIMARY-SALE distribution pools (CCA / IDO / launchpad /
airdrop redemption) on-chain, and attribute how much of each pool was captured
by insider / operator-related wallets vs dispersed to genuine public.

Why this exists (CAP)
=====================
CAP ran a Uniswap "Continuous Clearing Auction" (CCA, 4.5% of supply) + a
PancakeSwap IDO. An independent analyst (@ShillSeals) flagged on-chain that
"~50-55% of the 4% CCA pool was taken by a small number of associated wallets".
The single-chain / chip-bucket report shows the AGGREGATE result (operator vs
non-operator) but never the EVENT-level attribution. This helper reconstructs it
purely on-chain so the report prints "CCA pool 166M (X% of circulating), top-5
wallets 52% — insider-concentrated" without a human digging through social.

Verified on CAP: the distribution contract 0x9999b7e3… (vanity, operator-funded
by the project Safe) spread 166M to 319 wallets with top-5 = 52.1% — exactly
reproducing the @ShillSeals finding.

Mechanism (on-chain core — 100% automatic, no user input)
=========================================================
1. DETECT distribution pools: addresses that SENT the token to >= MIN_RECIPIENTS
   distinct wallets in the listing window, are CONTRACTS, are operator-FUNDED
   (received from the operator/genesis/Safe seed), and are NOT a labelled DEX
   pool/router (those are secondary trading, not a primary sale).
2. ATTRIBUTE per pool: tokens distributed (% of circulating), recipient count,
   top-N concentration (a fair public sale is dispersed; high top-N% = insider /
   whitelist capture), and overlap with the operator set.

Social enrichment (best-effort — NAMES the pool, may be fuzzy)
=============================================================
`enrich_with_social` runs a surf social-post search for the token's public-sale
events ("{symbol} CCA / IDO / auction / launchpad") to LABEL a detected pool as
"Uniswap CCA" / "PancakeSwap IDO" etc. and surface any announced allocation %.
Naming can mis-fire on common tickers — it is advisory, flagged, and never
changes the on-chain numbers.

Cost: gated. The single DETECT query is cheap; per-pool analysis (1 recipient
query + 1-2 label chunks) only runs for the 1-3 pools found. Tokens with no
high-fan-out operator-funded contract → 1 query, ~0 added cost.
"""
from __future__ import annotations

import json
import re as _re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

# tunables (pre-registered)
MIN_RECIPIENTS = 20          # fan-out floor to count as a distribution pool
MIN_POOL_PCT_CIRC = 1.0      # ignore pools distributing < 1% of circulating
TOP_LABEL_K = 40             # resolve labels for the top-K recipients per pool
MAX_POOLS = 5                # analyse at most the top-N fan-out pools
# Product gate (product spec): primary-sale attribution is only meaningful for a
# FRESH listing — once the TGE is more than a month old the CCA/IDO chips have
# dispersed/been sold and the analysis adds no forensic value. Skip entirely for
# older listings. (Also keeps every query inside surf's lookback by construction.)
MAX_TGE_AGE_DAYS = 30
# Primary-sale TGE window: a CCA/IDO/launchpad distributes around listing. Scan
# [listing − PRE_DAYS, listing + POST_DAYS] so later staking/vesting/claim emissions
# (which fan out over months) are NOT mislabeled a primary sale. (adversarial review HIGH: the
# old `>= date_floor … present` scan caught ongoing emissions.)
WINDOW_PRE_DAYS = 30
WINDOW_POST_DAYS = 60

_TRANSFERS_TABLE = {
    "ethereum": "agent.ethereum_transfers", "bsc": "agent.bsc_transfers",
    "base": "agent.base_transfers", "arbitrum": "agent.arbitrum_transfers",
    "polygon": "agent.polygon_transfers", "optimism": "agent.optimism_transfers",
}
# Infra labels that are NOT a primary sale — DEX/router/bridge (secondary trading)
# PLUS staking/vesting/timelock/claim/rewards/distributor/custody/vault/treasury
# (ongoing emissions or custody, not a public sale). adversarial review HIGH: a treasury-funded
# vesting/staking-rewards contract with fan-out fit every other detector condition.
_NON_SALE_INFRA_RE = _re.compile(
    r"uniswap|pancake|pool\s*manager|poolmanager|\brouter\b|aggregator|\bv[234]\b|"
    r"\bamm\b|liquidity|bridge|layerzero|lz\s*multicall|settler|permit2|stargate|"
    r"multicall|1inch|paraswap|0x\s*protocol|cow\s*protocol|"
    r"stak|vest|timelock|time\s*lock|\bclaim\b|reward|distributor|custod|\bvault\b|"
    r"treasury|escrow|gauge|locker|merkle", _re.IGNORECASE)
# Sale-venue override (adversarial review MED): a label like "Uniswap CCA" / "PancakeSwap IDO" /
# "… auction" / "launchpad" is the EXACT pool we want — never let the infra regex
# (which matches "uniswap"/"pancake") drop it. A sale term in the label wins.
_SALE_VENUE_RE = _re.compile(
    r"\bcca\b|continuous\s+clearing|\bido\b|\bipo\b|public\s+sale|token\s+sale|"
    r"token\s+auction|\bauction\b|launchpad|launch\s*pad|fair\s+launch|\blbp\b|"
    r"bootstrap|\btge\b|presale|pre-sale", _re.IGNORECASE)

_ADDR_RE = _re.compile(r"^0x[0-9a-f]{40}$")
_DATE_RE = _re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[T ].*)?$")


def _safe_addr(a: str) -> str | None:
    """Return a lowercased EVM address only if it is a strict 0x+40-hex string,
    else None. Hardens every SQL interpolation against malformed/injected input
    (adversarial review MED — this helper is exported, no upstream guarantee)."""
    if not a:
        return None
    a = a.strip().lower()
    return a if _ADDR_RE.match(a) else None


def _safe_date(d: str | None) -> str | None:
    """Return the YYYY-MM-DD prefix of a date/ISO-datetime string, or None. Strict:
    rejects trailing garbage (adversarial review MED — old code truncated to 10 chars first, so
    "2026-01-01garbage" silently passed). Accepts "2026-01-01" and
    "2026-01-01T00:00:00Z"; rejects anything else."""
    if not d:
        return None
    m = _DATE_RE.match(str(d).strip())
    if not m:
        return None
    try:  # reject calendar-invalid dates (e.g. 2026-13-99) — shape alone is not enough
        datetime.strptime(m.group(1), "%Y-%m-%d")
    except ValueError:
        return None
    return m.group(1)


def _window_bounds(listing_date: str | None, date_floor: str) -> tuple[str, str | None]:
    """(lo, hi) date bounds for the primary-sale scan. With a listing date, clamp to
    [max(date_floor, listing−PRE), listing+POST]; without one, fall back to
    (date_floor, None) = `>= date_floor` (legacy, flagged in the result)."""
    df = _safe_date(date_floor) or "2020-01-01"
    ld = _safe_date(listing_date)
    if not ld:
        return df, None
    base = datetime.strptime(ld, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    lo = (base - timedelta(days=WINDOW_PRE_DAYS)).strftime("%Y-%m-%d")
    hi = (base + timedelta(days=WINDOW_POST_DAYS)).strftime("%Y-%m-%d")
    if df > lo:
        lo = df
    return lo, hi


# A KOL / ENS / social-named recipient is a HUMAN-identifiable wallet (ENS name,
# X/Polymarket handle, or a named person/entity) — NOT exchange/DEX infra. A large
# primary-sale allocation to such named wallets is the whitelist / associated-party
# signal the report must surface in full.
# surf_labels_probe classification enum: CEX_DEPOSIT / CEX_HOT_WALLET / DEX_POOL /
# BRIDGE / MARKET_MAKER / OTHER_NAMED / UNLABELED. Exclude all infra/entity classes
# from the KOL highlight — only a named human/KOL (ENS / handle / OTHER_NAMED) counts.
_KOL_INFRA_CLS = {"CEX_HOT_WALLET", "CEX_DEPOSIT", "DEX_POOL", "BRIDGE", "MARKET_MAKER"}
_KOL_INFRA_RE = _re.compile(
    r"uniswap|pancake|pool|router|exchange|deposit|hot\s*wallet|cold\s*wallet|"
    r"vault|bridge|binance|coinbase|okx|bybit|kucoin|gate|mexc|kraken|bitvavo|"
    r"layerzero|multicall|settler|safe\s*proxy|gnosis", _re.IGNORECASE)
_KOL_NAME_RE = _re.compile(r"\.eth\b|@\w|polymarket|\bon\s+x\b|farcaster|lens\b", _re.IGNORECASE)


def _named_kind(info: dict, label: str | None) -> str | None:
    """Classify a named recipient (adversarial review MED — don't call a foundation/protocol a
    "KOL"): returns 'kol' for an ENS / social-handle wallet (high-confidence human
    KOL), 'entity' for an OTHER_NAMED label without ENS/social (could be a
    foundation/protocol/custodian — a named entity, not necessarily a KOL), or None
    for exchange/DEX/MM/bridge infra and unlabeled wallets."""
    if not label:
        return None
    if (info or {}).get("classification") in _KOL_INFRA_CLS:
        return None
    if _KOL_INFRA_RE.search(label):
        return None
    # ENS / social handle / platform reference → high-confidence KOL.
    if _KOL_NAME_RE.search(label):
        return "kol"
    # OTHER_NAMED with a real entity_name but no ENS/social → a named entity.
    if (info or {}).get("classification") == "OTHER_NAMED" and (info or {}).get("entity_name"):
        return "entity"
    return None


def _run_sql(sql: str, max_rows: int = 1000):
    from section_a_scope import _run_surf_with_retry
    try:
        doc, _err = _run_surf_with_retry(
            ["surf", "onchain-sql"],
            stdin=json.dumps({"sql": sql, "max_rows": max_rows}),
            base_timeout=60, max_attempts=3,
        )
        return (doc or {}).get("data") or []
    except Exception as e:  # noqa: BLE001
        print(f"[primary_sale] sql failed (non-fatal): {str(e)[:120]}", file=sys.stderr)
        return []


def detect_primary_sale_pools(
    *, prefix: str, supply_ca: str, operator_seed: set[str], operator_set: set[str],
    total_supply: float, circulating_supply: float, date_floor: str,
    is_contract_fn, code_cache: dict[str, bool], listing_date: str | None = None,
) -> list[dict[str, Any]]:
    """On-chain detection + attribution of primary-sale distribution pools.

    Must be called inside `chain_lock(prefix)` (caller holds it). `operator_seed`
    = the treasury/genesis/Safe FUNDING sources (the funding gate uses ONLY this).
    `operator_set` = the full insider wallet set (used for recipient overlap only).
    `is_contract_fn(prefix, addr, cache)` = the shared eth_getCode contract test.
    `listing_date` (YYYY-MM-DD) constrains the scan to the TGE window.

    Returns a list of pool dicts (largest first), each:
      {pool_addr, label, tokens_distributed, pct_of_circulating, n_recipients,
       top5_pct, top10_pct, operator_overlap_pct, operator_funded, is_dex_infra,
       insider_concentration_pct, window_lo, window_hi, named_pct_is_lower_bound,
       rows[]}
    """
    table = _TRANSFERS_TABLE.get(prefix)
    supply_ca = _safe_addr(supply_ca)
    if not table or not supply_ca:
        return []
    circ = circulating_supply or 0
    if circ <= 0:
        return []
    operator_seed = operator_seed or set()   # tolerate None from external callers
    operator_set = operator_set or set()
    # FRESH-listing gate (FAIL CLOSED): require a valid listing date, and skip if
    # the TGE is more than MAX_TGE_AGE_DAYS old. Without a verifiable listing date we
    # cannot prove freshness — and the window would fall back to an unbounded
    # `>= date_floor` scan that catches later rewards/claims emissions — so we bail
    # rather than risk a stale false positive (adversarial review HIGH / product spec gate).
    _ld_gate = _safe_date(listing_date)
    if not _ld_gate:
        return []
    _age = (date.today() - datetime.strptime(_ld_gate, "%Y-%m-%d").date()).days
    if _age > MAX_TGE_AGE_DAYS:
        return []
    # v1.2.0: decimals factor from the ACTIVE chain (set by the caller's
    # chain_lock / set_token_decimals), never a hardcoded 1e18 — non-18-decimal
    # supply tokens (USDC=6, WBTC=8) would otherwise be off by orders of magnitude
    # (matches the codebase-wide v0.9.7 decimals_factor migration).
    try:
        from chain_router import decimals_factor_str
        _df = decimals_factor_str()
    except Exception:
        _df = "1e18"
    # TGE-window clause for DISTRIBUTION (outflows): don't catch later
    # staking/vesting emissions (adversarial review HIGH).
    _lo, _hi = _window_bounds(listing_date, date_floor)
    # FUNDING-provenance lower bound (inflows): wider than the TGE window (pre-sale
    # prefund) but capped at the TGE upper bound (adversarial review MED: funding arriving months
    # AFTER the TGE distribution is not prefund — don't promote it).
    _fund_lo = _safe_date(date_floor) or "2020-01-01"
    # CLAMP both lower bounds to surf's large-table lookback (~365d): querying
    # block_date earlier than this returns EMPTY on agent.{chain}_transfers, silently
    # dropping every pool. The full-pipeline date_floor (= listing−365d) sits right at
    # that edge — the cause of the "0 pools in full run" bug (standalone used a later
    # floor so never hit it).
    try:
        from surf_constraints import surf_earliest_date_floor
        _earliest = surf_earliest_date_floor()
    except Exception:
        _earliest = None
    # Cap the upper bound at today: there is no future on-chain data, and a fresh
    # listing's `listing+60d` is in the future — leaving it would make the funding
    # span (earliest .. listing+60d) exceed surf's ~364-day large-table window and
    # return EMPTY. Capping keeps span = [today−364, today] ≤ 364 (the real bug).
    _today = date.today().isoformat()
    if _hi and _hi > _today:
        _hi = _today
    if _earliest:
        if _lo < _earliest:
            _lo = _earliest
        if _fund_lo < _earliest:
            _fund_lo = _earliest
    # adversarial review HIGH: a token listed >~424d ago has its whole TGE window below surf's
    # lookback, so `_hi` (= listing+60d, in the past) ends up BEFORE the clamped
    # lower bound → an inverted BETWEEN that silently returns empty. Bail explicitly
    # rather than emit a misleading "no primary sale" — the sale predates queryable
    # surf data, so the section is honestly omitted.
    if _hi and (_hi < _lo or _hi < _fund_lo):
        print(f"[primary_sale] TGE window [{_lo}..{_hi}] is below surf lookback "
              f"({_earliest}); primary sale predates queryable data — skipping.",
              file=sys.stderr)
        return []
    _win = (f"AND block_date BETWEEN '{_lo}' AND '{_hi}' " if _hi
            else f"AND block_date >= '{_lo}' ")
    _fund_win = (f"AND block_date BETWEEN '{_fund_lo}' AND '{_hi}' " if _hi
                 else f"AND block_date >= '{_fund_lo}' ")

    # 1. DETECT high-fan-out senders (candidate distribution pools). Rank by
    #    tokens distributed (materiality), not recipient count — a smaller-fan-out
    #    but high-value sale pool must not be crowded out by tiny dust senders.
    sql = (
        'SELECT lower("from") AS src, count(DISTINCT lower("to")) AS n_recip, '
        f'sum(toFloat64(toDecimal256(amount_raw,0))/{_df}) AS amt, '
        'min(block_date) AS first_out '
        f"FROM {table} WHERE contract_address='{supply_ca}' {_win}"
        f"GROUP BY src HAVING n_recip >= {MIN_RECIPIENTS} "
        f"ORDER BY amt DESC LIMIT 40"
    )
    cands = _run_sql(sql, max_rows=50)
    if not cands:
        return []

    BURN = {"0x0000000000000000000000000000000000000000",
            "0x000000000000000000000000000000000000dead"}
    try:
        from surf_labels_probe import resolve_labels
    except Exception:
        resolve_labels = lambda a: {}  # noqa: E731

    # Pre-filter: contracts that are NOT infra (DEX/router/bridge/staking/vesting/
    # claim/rewards/custody/vault), distributing a material share of circulating.
    src_labels = resolve_labels([(c.get("src") or "").lower() for c in cands]) or {}
    pools_raw: list[dict[str, Any]] = []
    for c in cands:
        src = _safe_addr(c.get("src") or "")
        if not src or src in BURN:
            continue
        amt = float(c.get("amt") or 0)
        pct_circ = 100.0 * amt / circ
        if pct_circ < MIN_POOL_PCT_CIRC:
            continue
        info = src_labels.get(src) or {}
        label = " | ".join(x for x in [info.get("entity_name"), info.get("label")] if x)
        # infra unless the label itself names a sale venue (then it's the pool we want)
        is_dex = bool(_NON_SALE_INFRA_RE.search(label)) and not _SALE_VENUE_RE.search(label)
        is_c = is_contract_fn(prefix, src, code_cache)
        pools_raw.append({
            "pool_addr": src, "label": label or None, "tokens_distributed": amt,
            "pct_of_circulating": round(pct_circ, 1),
            "n_recipients": int(c.get("n_recip") or 0),
            "first_out": c.get("first_out"),   # earliest distribution date (ordering)
            "is_contract": is_c, "is_dex_infra": is_dex,
        })

    # OPERATOR-FUNDED check (true semantics): a primary-sale pool is FUNDED by the
    # operator TREASURY *before* it distributes. Verify with one batched query — who
    # funded each candidate and when — and require a material inflow (>= min_funding)
    # FROM operator_seed ONLY (genesis/reserve/multisig/deployer treasury) whose first
    # inflow is AT OR BEFORE the pool's first distribution outflow. adversarial review HIGH:
    # (a) operator_seed | operator_set wrongly promoted cluster-funded pools — now
    # seed-only; (b) accepting any same-window inflow let a contract fan out FIRST then
    # receive treasury funds LATER and still be called a sale — now ordering-gated.
    cand_pools = [p for p in pools_raw if p["is_contract"] and not p["is_dex_infra"]]
    # group inflow by (pool, funder, block_date) so the ordering gate can sum ONLY the
    # tranches that arrived AT OR BEFORE the pool's first distribution outflow. adversarial review
    # HIGH: a min(block_date) gate over the whole funder sum let dust-before + material-
    # after still pass — summing per-date and filtering by block_date closes that.
    funders_by_pool: dict[str, list[tuple[str, float, Any]]] = {}
    safe_in = [p["pool_addr"] for p in cand_pools if _safe_addr(p["pool_addr"])]
    seed = {a for a in (_safe_addr(x) for x in operator_seed) if a}
    # Push the operator-seed funder filter INTO the SQL (adversarial review MED): without it the
    # query returns every funder of every candidate, which can exceed max_rows and
    # truncate before the seed rows arrive — suppressing a real pool. Filtering to
    # seed funders keeps the result tiny and the ordering sum exact.
    if safe_in and seed:
        in_list = ",".join("'%s'" % a for a in safe_in)
        seed_list = ",".join("'%s'" % a for a in sorted(seed))
        frows = _run_sql(
            'SELECT lower("to") AS pool, lower("from") AS funder, block_date AS bd, '
            f'sum(toFloat64(toDecimal256(amount_raw,0))/{_df}) AS amt '
            f"FROM {table} WHERE contract_address='{supply_ca}' "
            f'AND lower("to") IN ({in_list}) AND lower("from") IN ({seed_list}) {_fund_win}'
            "GROUP BY pool, funder, bd",
            max_rows=4000,
        )
        for r in frows:
            funders_by_pool.setdefault((r.get("pool") or "").lower(), []).append(
                ((r.get("funder") or "").lower(), float(r.get("amt") or 0), r.get("bd")))
    min_funding = max(0.001 * (total_supply or 0), 1_000_000)  # material inflow floor
    sale_pools = []
    for p in cand_pools:
        funders = funders_by_pool.get(p["pool_addr"], [])
        _fout = p.get("first_out")
        # sum operator-seed inflow that landed at/before the first distribution outflow
        # (block_date granularity; same-day counts as before/at). A row dated after the
        # first outflow does NOT prove the pool was operator-funded *to* distribute.
        op_inflow = sum(v for f, v, bd in funders
                        if f in seed and (not _fout or (bd is not None and bd <= _fout)))
        p["operator_funded"] = bool(op_inflow >= min_funding)
        p["operator_inflow_tokens"] = round(op_inflow, 0)
        if p["operator_funded"]:
            sale_pools.append(p)
    # tokens DESC, then pool_addr ASC for a deterministic order on exact ties
    sale_pools.sort(key=lambda p: (-p["tokens_distributed"], p["pool_addr"]))
    sale_pools = sale_pools[:MAX_POOLS]

    # 2. ATTRIBUTE each pool: recipient concentration + operator overlap.
    for p in sale_pools:
        rows = _run_sql(
            'SELECT lower("to") AS r, '
            f'sum(toFloat64(toDecimal256(amount_raw,0))/{_df}) AS amt '
            f"FROM {table} WHERE contract_address='{supply_ca}' "
            f"AND lower(\"from\")='{p['pool_addr']}' {_win}"
            "GROUP BY r ORDER BY amt DESC LIMIT 1000",
            max_rows=1000,
        )
        recips = [((r.get("r") or "").lower(), float(r.get("amt") or 0))
                  for r in rows if r.get("r")]
        recips = [(a, v) for a, v in recips if a not in BURN and v > 0]
        recips.sort(key=lambda x: x[1], reverse=True)
        # adversarial review HIGH: denominator = the UNCAPPED pool outflow (tokens_distributed
        # from the detect aggregate), NOT sum(top-1000). Using the capped sum would
        # inflate concentration for a sale dispersed across >1000 wallets.
        pool_total = p["tokens_distributed"] or (sum(v for _a, v in recips) or 1.0)
        top5 = sum(v for _a, v in recips[:5])
        top10 = sum(v for _a, v in recips[:10])
        op_overlap = sum(v for a, v in recips if a in operator_set or a in operator_seed)
        # label the top-K recipients (cheap; the dispersed tail is genuine public)
        rlabels = resolve_labels([a for a, _v in recips[:TOP_LABEL_K]]) or {}
        rrows = []
        named_recips = []   # ENS / social / named recipients — surfaced in full
        named_tokens = 0.0
        for a, v in recips[:TOP_LABEL_K]:
            li = rlabels.get(a) or {}
            label = " | ".join(x for x in [li.get("entity_name"), li.get("label")] if x) or None
            is_op = (a in operator_set or a in operator_seed)
            kind = _named_kind(li, label)   # 'kol' | 'entity' | None
            rrows.append({
                "addr": a, "tokens": v, "pct_of_pool": round(100.0 * v / pool_total, 1),
                "label": label, "is_operator": is_op, "is_named": bool(kind),
            })
            if kind:
                named_recips.append({
                    "addr": a, "name": label, "tokens": v, "kind": kind,
                    "pct_of_pool": round(100.0 * v / pool_total, 1),
                })
                named_tokens += v
        p["n_recipients_resolved"] = len(recips)
        p["top5_pct"] = round(100.0 * top5 / pool_total, 1)
        p["top10_pct"] = round(100.0 * top10 / pool_total, 1)
        p["operator_overlap_pct"] = round(100.0 * op_overlap / pool_total, 1)
        # insider concentration headline = max(top-5 concentration, operator overlap).
        # A fair public sale is dispersed; >40% in the top 5 OR direct operator
        # overlap is the insider-capture signal.
        p["insider_concentration_pct"] = round(max(p["top5_pct"], p["operator_overlap_pct"]), 1)
        # Named (ENS/social/entity) recipients. adversarial review MED: named_pct is computed
        # over the labeled top-K only, so it is a LOWER BOUND when the pool has more
        # recipients than we resolved labels for — flag it so render can say "≥".
        named_recips.sort(key=lambda x: x["tokens"], reverse=True)
        p["named_recipients"] = named_recips
        p["n_named_recipients"] = len(named_recips)
        p["n_kol_recipients"] = sum(1 for r in named_recips if r["kind"] == "kol")
        p["named_pct_of_pool"] = round(100.0 * named_tokens / pool_total, 1)
        p["named_pct_is_lower_bound"] = bool(len(recips) > TOP_LABEL_K)
        p["window_lo"] = _lo
        p["window_hi"] = _hi
        p["rows"] = rrows
        # drop bulky internals
        for k in ("is_contract",):
            p.pop(k, None)
    return sale_pools


_SOCIAL_EVENT_RE = _re.compile(
    r"\b(cca|continuous\s+clearing\s+auction|ido|public\s+sale|token\s+auction|"
    r"launchpad|tge|fair\s+launch|lbp|liquidity\s+bootstrap)\b", _re.IGNORECASE)


def enrich_with_social(symbol: str, pools: list[dict[str, Any]]) -> dict[str, Any]:
    """Best-effort: surf social-post search to NAME the detected pools (CCA / IDO
    / auction) + surface any announced allocation %. Advisory only — fuzzy on
    common tickers; never alters the on-chain numbers. Returns
    {event_hits: [...], _note}. The caller attaches it under
    primary_sales.social (clearly flagged as best-effort)."""
    if not symbol or not pools:
        return {}
    import subprocess
    # cashtag form ($CAP) — the crypto convention that filters "capital" /
    # "market cap" noise that plagues short tickers in a plain keyword search.
    cashtag = "$" + symbol.lstrip("$")
    sym_re = _re.compile(r"(?:\$%s\b|@\w*%s\w*)" % (_re.escape(symbol), _re.escape(symbol)),
                         _re.IGNORECASE)
    hits: list[dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["surf", "search-social-posts", "--q",
             f'{cashtag} (CCA OR IDO OR auction OR launchpad OR "public sale")',
             "--limit", "15"],
            capture_output=True, text=True, check=False, timeout=40,
        )
        doc = json.loads(proc.stdout) if proc.returncode == 0 else {}
        for t in (doc.get("data") or [])[:15]:
            text = t.get("text") or ""
            # require the ticker as a cashtag or in a handle — not a bare substring
            if not sym_re.search(text):
                continue
            m = _SOCIAL_EVENT_RE.search(text)
            if not m:
                continue
            # pull an allocation % if mentioned near the event word
            pct = None
            pm = _re.search(r"(\d+(?:\.\d+)?)\s*%[^.]{0,40}(?:supply|allocation|pool|cca|ido)",
                            text, _re.IGNORECASE)
            if pm:
                pct = pm.group(1)
            hits.append({
                "event": m.group(0).lower(),
                "announced_pct": pct,
                "handle": (t.get("author") or {}).get("handle"),
                "likes": (t.get("stats") or {}).get("likes"),
                "excerpt": text[:220],
                "url": t.get("url"),
            })
    except Exception as e:  # noqa: BLE001
        print(f"[primary_sale] social enrich failed (non-fatal): {str(e)[:120]}",
              file=sys.stderr)
        return {"_error": str(e)[:120]}
    # rank by likes; keep the most-engaged few
    hits.sort(key=lambda h: (h.get("likes") or 0), reverse=True)
    return {
        "event_hits": hits[:5],
        "_note": ("best-effort surf social naming; fuzzy on common tickers, "
                  "advisory only — on-chain pool numbers are authoritative."),
    }


__all__ = ["detect_primary_sale_pools", "enrich_with_social"]
