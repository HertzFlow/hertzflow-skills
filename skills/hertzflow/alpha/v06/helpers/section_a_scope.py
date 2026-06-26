#!/usr/bin/env python3
"""section_a_scope.py — Section A: scope confirmation (Alpha listing + Spot graduation check).

Equivalent to v0.5.x SKILL.md Section A inline bash, now Python. Source-of-truth
methodology lives in SKILL_v06.md Rule 0 (Spot graduation terminal) — this file
implements the check.

## Behavior

Given a contract address:
1. Query Binance Alpha listing API. If CA not in Alpha list → return SPOT_OR_NEVER state.
2. If CA in Alpha list, ALSO probe Binance Spot exchangeInfo for the symbol.
   If symbol on Spot → return SPOT_GRADUATED (mutual-exclusion lag, refuse forensic).
3. Return Section A scope data: symbol, name, supply, listing time, chain, etc.

## Output schema (locked, populated into report_data.skeleton)

```python
{
    "symbol": "TOKEN",
    "name": "Block Street",
    "contract_address": "0x595deaad...",
    "chain_id": 56,
    "chain_label": "BSC",
    "total_supply": 1000000000,
    "circulating_supply": 207750000,
    "circ_ratio": 0.2078,
    "alpha_listing_ts": 1772618400000,
    "alpha_listing_date_utc": "2026-03-04",
    "alpha_vol_24h_usd": 24994801.45,
    "spot_status": "not_on_spot",  # or "spot_graduated"
    "scope_ok": True,  # False if SPOT_GRADUATED or NEVER_ALPHA
}
```

v0.6 (2026-05-24)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from contextlib import nullcontext as _nullcontext
from chain_router import transfers_table, dex_trades_table  # v0.7.20

sys.path.insert(0, str(Path(__file__).parent))
from i18n import t   # v0.6.2 i18n
try:
    from parallel_surf import run_parallel
except ImportError:
    run_parallel = None


_ALPHA_LIST_URL = (
    "https://www.binance.com/bapi/defi/v1/public/wallet-direct/buw/wallet/cex/alpha/all/token/list"
)
_SPOT_EXCHANGE_INFO = "https://api.binance.com/api/v3/exchangeInfo"

# v0.7.10: CoinGecko platform id → surf token-holders --chain shortname.
# surf token-holders supports: ethereum, polygon, bsc, solana, avalanche,
# arbitrum, optimism, base. We use this for **real-time** LP detection
# (DEX-labeled holders × current price), replacing v0.7.9's lagged
# ClickHouse aggregate path.
_SURF_HOLDER_CHAINS = {
    "binance-smart-chain": "bsc",
    "ethereum": "ethereum",
    "base": "base",
    "arbitrum-one": "arbitrum",
    "polygon-pos": "polygon",
    "optimistic-ethereum": "optimism",
    "solana": "solana",
    # NOTE: every short-name value here MUST be routable by
    # chain_router.set_active_chain (i.e. in chain_router._VALID_PREFIXES).
    # `derive_primary_chain` gates `alpha_chain_authoritative` on this dict,
    # so any chain present here but NOT in chain_router would make
    # primary_chain diverge from the SQL routing chain (adversarial review v1.0.1 HIGH:
    # 'avalanche'/43114 was listed here but unsupported by the router →
    # removed). test_surf_holder_chains_subset_of_router enforces this.
}

# v0.7.9 (kept for back-compat with any direct importers): EVM-only
# ClickHouse dex_trades tables. New code should not consume this; use the
# real-time token-holders path via _SURF_HOLDER_CHAINS instead.
_SURF_DEX_TRADES_TABLES = {
    "binance-smart-chain": "bsc_dex_trades",
    "ethereum": "ethereum_dex_trades",
    "base": "base_dex_trades",
    "arbitrum-one": "arbitrum_dex_trades",
}

# v0.7.9: CoinGecko 跨链 platforms 查询
_COINGECKO_COIN_LIST = "https://api.coingecko.com/api/v3/coins/list?include_platform=true"
_COINGECKO_CACHE_PATH = Path(
    os.environ.get("BINANCE_ALPHA_COINGECKO_CACHE")
    or os.path.expanduser("~/.binance-alpha-data/coingecko_platforms.json")
)
_COINGECKO_CACHE_TTL_SECS = 24 * 3600

_ADDR_RE_LOCAL = re.compile(r"0x[0-9a-f]{40}")


# v0.9.4: surf credit accumulator. Every successful onchain-sql / token-
# holders / wallet-labels-batch / project-detail call returns
# `meta.credits_used` in its response. We accumulate the total + per-call
# count + cumulative time so forensic_pipeline.py can snapshot a delta
# around each section and write `_credits_used` / `_surf_calls` /
# `_surf_seconds` into the skeleton. This was previously fake: only the
# 3 skipped sections (cross_sym / wash / flow_operators) had non-None
# entries, and they were zero.
import threading as _threading
_CREDIT_LOCK = _threading.Lock()
_CREDIT_STATE = {
    "credits": 0.0,
    "calls": 0,
    "seconds": 0.0,
    # Per-attempt counter — calls that failed + retried bill partial
    # scan credits even when they ultimately succeed. We separate
    # successful surface metric (`calls`) from billing metric (`attempts`)
    # so reports can show "X useful calls, Y attempts billed".
    "attempts": 0,
}


def _surf_credit_snapshot() -> dict[str, Any]:
    """Atomic read of cumulative surf usage. Pipeline calls this before
    and after each section to compute a per-section delta."""
    with _CREDIT_LOCK:
        return dict(_CREDIT_STATE)


def _surf_credit_add(credits: float, seconds: float, attempts: int = 1, success: bool = True) -> None:
    with _CREDIT_LOCK:
        _CREDIT_STATE["credits"] += float(credits or 0)
        _CREDIT_STATE["seconds"] += float(seconds or 0)
        _CREDIT_STATE["attempts"] += int(attempts or 0)
        if success:
            _CREDIT_STATE["calls"] += 1


def _run_surf_with_retry(
    cmd: list[str],
    stdin: str | None = None,
    max_attempts: int = 4,
    base_timeout: int = 30,
) -> tuple[dict[str, Any] | None, str | None]:
    """Run a surf CLI command with retry-on-transient-error.

    v0.7.10.2: surf token-holders / project-detail / search-project /
    onchain-sql calls all hit transient failures (subprocess timeout,
    network hiccup, surf-side rate limit, malformed stdout). Without
    retry, a single transient failure made the whole pipeline output
    wrong (e.g. BSC fetch fails once → primary_chain silently flips to
    Base). Now we retry up to `max_attempts` with exponential backoff.

    Returns:
        (doc, error)
        - doc: parsed JSON dict if any attempt succeeded
        - error: short reason string if all attempts failed
        Exactly one of them is None.

    Retried error classes (all transient):
      - subprocess.TimeoutExpired / OSError on subprocess.run
      - returncode != 0
      - stdout failed JSON decode
      - JSON parsed OK but contains top-level "error" field
    """
    last_err = "no_attempt"
    attempts_billed = 0
    seconds_total = 0.0
    for attempt in range(1, max_attempts + 1):
        attempts_billed += 1
        t0 = time.perf_counter()
        try:
            kwargs: dict[str, Any] = {
                "capture_output": True, "text": True,
                "encoding": "utf-8", "errors": "replace",
                "timeout": base_timeout * (1 + (attempt - 1) // 2),
                "check": False,
            }
            if stdin is not None:
                kwargs["input"] = stdin
            proc = subprocess.run(cmd, **kwargs)
        except (subprocess.TimeoutExpired, OSError) as e:
            last_err = f"subprocess_error: {str(e)[:120]}"
            seconds_total += time.perf_counter() - t0
        else:
            seconds_total += time.perf_counter() - t0
            if proc.returncode != 0:
                # v0.8.5.2: surf 返 INVALID_REQUEST 时 JSON 写 stdout 不写 stderr.
                # adversarial review CLO bug report (2026-06-12): max_rows=50000 撞 10K cap,
                # 真实错误在 stdout, 之前只读 stderr → 错误吞掉成 "exit_4:" 误导.
                # Fix: 优先 stderr (有则用), 否则 fall through stdout.
                _err_raw = (proc.stderr or "").strip() or (proc.stdout or "").strip()
                last_err = f"exit_{proc.returncode}: {_err_raw[:300]}"
            else:
                try:
                    doc = json.loads(proc.stdout)
                except json.JSONDecodeError as e:
                    last_err = f"json_decode: {str(e)[:120]}"
                else:
                    if isinstance(doc, dict) and doc.get("error"):
                        last_err = f"surf_error: {str(doc['error'])[:120]}"
                    else:
                        # v0.9.4 credit accounting: success path. credits_used
                        # lives at meta.credits_used per surf 2026-06 schema;
                        # absent = legacy endpoint → count as 0 credits but
                        # still bump call counter so wall-time totals stay
                        # honest.
                        credits = 0.0
                        try:
                            credits = float((doc.get("meta") or {}).get("credits_used") or 0)
                        except (TypeError, ValueError, AttributeError):
                            credits = 0.0
                        _surf_credit_add(
                            credits=credits, seconds=seconds_total,
                            attempts=attempts_billed, success=True,
                        )
                        return doc, None
        # transient — backoff and retry. 1s, 3s, 7s (cap)
        if attempt < max_attempts:
            time.sleep(min(2 ** attempt - 1, 7))
    # All attempts failed. Still record the attempt count + wall time
    # (credit=0 since surf timeouts on the platform side may or may not
    # bill, we conservatively log 0 — pipeline reports "attempts=N for 0
    # credits" so a timeout retry storm is visible).
    _surf_credit_add(credits=0, seconds=seconds_total,
                     attempts=attempts_billed, success=False)
    return None, last_err


_CHAIN_ID_TO_LABEL = {
    "1": "ETH",
    "56": "BSC",
    "137": "Polygon",
    "8453": "Base",
    "42161": "Arbitrum",
    "10": "Optimism",
    "43114": "Avalanche",
    # v0.7.21.7: Alpha API encodes Solana as the SLIP-44-derived sentinel
    # "CT_501". Map to a human label so the report header doesn't say
    # `chain_id_CT_501`.
    "CT_501": "Solana",
}

# v0.7.20: Alpha API chainId → CoinGecko platform id (= surf token-holders chain
# shortname domain in _SURF_HOLDER_CHAINS). Used as the primary_chain fallback
# when all surf-supported chains return 0 LP — instead of hardcoding BSC,
# honour the chain Alpha API actually declares for the token.
_CHAIN_ID_TO_CG_PLATFORM = {
    "1": "ethereum",
    "56": "binance-smart-chain",
    "137": "polygon-pos",
    "8453": "base",
    "42161": "arbitrum-one",
    "10": "optimistic-ethereum",
    # v1.0.1: 43114→avalanche removed — avalanche is NOT routable by
    # chain_router.set_active_chain, so mapping it here would let
    # derive_primary_chain return a chain the SQL path can't use.
    # v0.7.21.7: Solana mapping for derive_primary_chain so the primary-chain
    # derivation can honour Alpha's CT_501 instead of falling back to BSC.
    "CT_501": "solana",
}


def _curl_json(url: str, timeout_seconds: int = 8) -> dict[str, Any] | None:
    """Fetch a URL and parse JSON. Returns None on failure (caller decides)."""
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout_seconds), url],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False,
            timeout=timeout_seconds + 5,   # v0.9.9: subprocess ceiling > curl --max-time (deadlock guard)
        )
        if proc.returncode != 0:
            return None
        return json.loads(proc.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


# v1.0.6: prefix → CoinGecko platform (to pull the battlefield chain's per-chain
# CA out of coingecko_platforms). Inverse of the surf-supported subset of
# _SURF_HOLDER_CHAINS. Solana stays out of the reroute target set: it is
# HOLDER_SNAPSHOT-only (no `agent.solana_*` tables) so rerouting the SQL
# forensic there is pointless — Solana tokens keep the holder-snapshot path.
_PREFIX_TO_CG_PLATFORM: Final[dict[str, str]] = {
    "bsc": "binance-smart-chain", "ethereum": "ethereum", "base": "base",
    "arbitrum": "arbitrum-one", "polygon": "polygon-pos",
    "optimism": "optimistic-ethereum",
}
# prefix → numeric EIP-155 chain_id (keep meta.chain_id numeric after a reroute,
# consistent with the pre-reroute Alpha value).
_PREFIX_TO_CHAIN_ID: Final[dict[str, str]] = {
    "bsc": "56", "ethereum": "1", "base": "8453",
    "arbitrum": "42161", "polygon": "137", "optimism": "10",
}
_PREFIX_TO_CHAIN_LABEL: Final[dict[str, str]] = {
    "bsc": "BSC", "ethereum": "Ethereum", "base": "Base",
    "arbitrum": "Arbitrum", "polygon": "Polygon", "optimism": "Optimism",
}


def _chain_supply_presence(chain_entry: dict[str, Any]) -> float:
    """Sum of top-100 holder balances surf token-holders already returned for a
    chain (chain_lp_realtime[chain].top_holders_classified). Proxy for how much
    of the token's supply lives on that chain."""
    thc = (chain_entry or {}).get("top_holders_classified") or {}
    total = 0.0
    for bucket in thc.values():
        if not isinstance(bucket, dict):
            continue
        for h in bucket.get("top") or []:
            try:
                total += float(h.get("balance") or 0)
            except (TypeError, ValueError):
                continue
    return total


def detect_multichain_split(
    chain_lp_realtime: dict[str, Any],
    coingecko_platforms: dict[str, Any],
    alpha_chain_id: Any,
    min_supply_ratio: float = 2.0,
) -> dict[str, Any]:
    """Detect a cross-chain SUPPLY SPLIT — a surf-SQL-supported chain (other
    than the Alpha listing/trading chain) that holds the bulk of the token's
    supply — so the report can add a cost-bounded supply-overhang overlay
    instead of silently measuring only the Alpha-chain slice.

    Deliberately does NOT reroute the heavy SQL forensic. The Alpha listing
    trades on the Alpha chain by definition (Binance Alpha lists the BSC/Base/…
    token), so the dump / lineage / trade forensic belongs there. What the
    single-chain pipeline MISSED is the supply living elsewhere:
      - CAP (2026-06-26): trades on BSC (Alpha mirror, $20.3M/90d) BUT 99.6% of
        supply sits on Ethereum (84.5% in one lock-like 0x0000… contract +
        5.9% Gnosis Safe). The BSC chip (1.4% slice) hid a massive overhang.
      - O: trades mostly on BSC ($137M) but also has a real Base venue
        (973M supply + $10M/90d) — a genuine second deployment, not noise.
    The caller keeps the full forensic on the Alpha chain (no double surf-credit
    cost) and adds ONE compact overlay section for the supply chain, reusing the
    per-chain holders section_a already fetched (0 extra credits to detect).

    SURF-ONLY signal (no DexScreener — per `surf-endpoint-freshness-methodology`
    + the v0.1.6 "剔 DexScreener / Section D 改 surf" decision): per-chain SUPPLY
    PRESENCE = sum of the top-100 holder balances surf token-holders already
    returned. Supply (not LP) because surf/Arkham frequently does not label a
    fresh DEX pool — the LP-derivation path returned 0 for CAP's Ethereum
    Uniswap pool even though 99.6% of supply was visible in the raw balances.

    Returns a dict. `split` is True ONLY when ALL hold:
      - the supply-dominant surf-SQL chain != the Alpha listing chain
      - it holds >= min_supply_ratio × the Alpha chain's supply (materially more)
      - coingecko_platforms has that chain's CA (needed for the overlay queries)
    Otherwise `split` is False → no overlay, zero added cost. Every BSC-native /
    single-chain token is unaffected (its home chain dominates supply, so the
    top supply chain == the Alpha chain). Solana is excluded as a split target
    (HOLDER_SNAPSHOT-only, no agent.solana_* tables). Fail-OPEN: any error →
    split False.

    Keys: split, supply_prefix, supply_cg_platform, supply_ca,
          supply_chain_id_numeric, supply_chain_label, supply_amount,
          alpha_prefix, alpha_supply, supply_by_chain, supply_pct_of_total.
    """
    out: dict[str, Any] = {"split": False}
    try:
        alpha_plat = _CHAIN_ID_TO_CG_PLATFORM.get(str(alpha_chain_id or ""))
        alpha_prefix = _SURF_HOLDER_CHAINS.get(alpha_plat or "")
        out["alpha_prefix"] = alpha_prefix
        clr = chain_lp_realtime or {}
        # supply presence per surf-SQL-routable chain (exclude solana / non-surf)
        supply_by_prefix: dict[str, float] = {}
        for cg_plat, entry in clr.items():
            prefix = _SURF_HOLDER_CHAINS.get(cg_plat)
            if not prefix or prefix not in _PREFIX_TO_CG_PLATFORM:
                continue  # non-surf-SQL (solana) or unknown — never a target
            supply_by_prefix[prefix] = _chain_supply_presence(entry)
        out["supply_by_chain"] = supply_by_prefix
        if not supply_by_prefix:
            return out
        top_prefix = max(supply_by_prefix, key=lambda k: supply_by_prefix[k])
        top_supply = supply_by_prefix[top_prefix]
        alpha_supply = supply_by_prefix.get(alpha_prefix or "", 0.0)
        grand_total = sum(supply_by_prefix.values()) or 1.0
        out.update({
            "supply_prefix": top_prefix, "supply_amount": top_supply,
            "alpha_supply": alpha_supply,
            "supply_pct_of_total": round(100.0 * top_supply / grand_total, 1),
        })
        # ---- split gating (conservative; any fail → no overlay, 0 cost) ----
        # adversarial review HIGH#5: require a KNOWN Alpha chain with OBSERVED supply. If
        # alpha_chain_id is missing/unmapped, alpha_prefix is None and
        # alpha_supply is 0 — then `top_prefix != alpha_prefix` is trivially true
        # and `top_supply >= 2 × max(alpha_supply, 1)` passes for ANY token,
        # firing a false split overlay + an expensive canonical-chain scan on a
        # normal single-chain token. Gate on alpha_prefix being resolved and the
        # Alpha chain actually showing holders.
        if not alpha_prefix or alpha_supply <= 0:
            return out
        if not top_prefix or top_prefix == alpha_prefix:
            return out
        if top_supply <= 0:
            return out
        if top_supply < min_supply_ratio * max(alpha_supply, 1.0):
            return out
        cg_plat = _PREFIX_TO_CG_PLATFORM.get(top_prefix)
        bf_ca = (coingecko_platforms or {}).get(cg_plat or "")
        if not bf_ca:
            return out
        out.update({
            "split": True,
            "supply_cg_platform": cg_plat,
            "supply_ca": bf_ca,
            "supply_chain_id_numeric": _PREFIX_TO_CHAIN_ID.get(top_prefix, top_prefix),
            "supply_chain_label": _PREFIX_TO_CHAIN_LABEL.get(top_prefix, top_prefix.upper()),
        })
        return out
    except Exception as e:  # noqa: BLE001 — fail-open by contract
        out["_error"] = str(e)
        return out


# v0.7.21.9: Solana public RPC endpoint for SPL mint metadata. Free, no API
# key, no rate-limit issues for occasional one-shot getTokenSupply calls.
# Used by section_a_scope to read on-chain `decimals` + `uiAmount` so
# section_f_holders / section_alloc can normalise the raw lamport balances
# surf token-holders returns. Pre-v0.7.21.9, raw lamports were divided by
# Alpha API's already-normalised totalSupply, giving the FARTCOIN /
# JELLYJELLY "其他 (散户+未分类)  96,200,818% 占总供应" bug.
_SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"

# v0.9.7 fix #2: public EVM RPC endpoints keyed by chain_id. Used by
# `_fetch_evm_token_decimals` for the `decimals()` call (selector 0x313ce567).
# Tier 1 public RPCs picked for stability + no API key requirement; fall
# back chain-by-chain order = [primary, secondary] handled in fn.
_EVM_RPC_URLS = {
    "1":     ["https://ethereum.publicnode.com", "https://eth.llamarpc.com"],
    "56":    ["https://bsc-dataseed.binance.org", "https://bsc.publicnode.com"],
    "137":   ["https://polygon-rpc.com", "https://polygon.publicnode.com"],
    "8453":  ["https://mainnet.base.org", "https://base.publicnode.com"],
    "42161": ["https://arb1.arbitrum.io/rpc", "https://arbitrum.publicnode.com"],
    "10":    ["https://mainnet.optimism.io", "https://optimism.publicnode.com"],
    "43114": ["https://api.avax.network/ext/bc/C/rpc", "https://avalanche.publicnode.com"],
}


def _fetch_evm_token_decimals(ca: str, chain_id: str | int | None) -> int | None:
    """v0.9.7 fix #2: read ERC20 `decimals()` via public EVM RPC.

    Selector `0x313ce567` is `decimals()` in ABI. Result is a 32-byte
    big-endian uint that fits a uint8. Returns the int value, or None on
    any failure (RPC down / chain not in map / non-conforming contract /
    HTTP 4xx-5xx).

    Cost: 1 eth_call per CA, ~50-200ms. Cached by surf project-detail
    side TBD; for now we re-query per CA per pipeline invocation (cheap).

    Failure-safe: caller (section_a) reads None → chain_router fallback
    to 18 → v0.9.6 behavior preserved.
    """
    if not ca:
        return None
    chain_key = str(chain_id) if chain_id is not None else "56"
    rpc_urls = _EVM_RPC_URLS.get(chain_key)
    if not rpc_urls:
        return None
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": ca, "data": "0x313ce567"}, "latest"],
    })
    for rpc_url in rpc_urls:
        try:
            proc = subprocess.run(
                ["curl", "-sS", "--max-time", "5",
                 "-H", "Content-Type: application/json",
                 "-X", "POST", "-d", payload, rpc_url],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=7, check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if proc.returncode != 0:
            continue
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue
        result = (doc or {}).get("result")
        if not result or not isinstance(result, str) or not result.startswith("0x"):
            continue
        # 32-byte uint encoded hex string; trailing 2 hex chars = uint8
        # decimals value. e.g. "0x0000...0012" = 18, "0x0000...0006" = 6.
        try:
            return int(result, 16)
        except (TypeError, ValueError):
            continue
    return None


def fetch_solana_spl_supply(mint: str, timeout_seconds: int = 8) -> dict[str, Any] | None:
    """Return the on-chain SPL mint's `{decimals, raw_amount, ui_amount}`
    via Solana mainnet-beta RPC `getTokenSupply`. Returns None on any
    failure (transport / API / parse) — caller falls back to Alpha API
    totalSupply with no decimal adjustment.

    Cost: 1 free public-RPC call (~50ms). Decimals on SPL never change
    after mint, so callers can cache the result per CA if they want.
    """
    if not mint:
        return None
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenSupply",
        "params": [mint],
    })
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout_seconds),
             "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", body,
             _SOLANA_RPC_URL],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False,
            timeout=timeout_seconds + 5,   # v0.9.9: subprocess ceiling > curl --max-time (deadlock guard)
        )
        if proc.returncode != 0:
            return None
        doc = json.loads(proc.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None
    value = ((doc or {}).get("result") or {}).get("value") or {}
    if not value:
        return None
    try:
        decimals = int(value.get("decimals"))
    except (TypeError, ValueError):
        return None
    raw_amount = value.get("amount")
    ui_amount_str = value.get("uiAmountString") or value.get("uiAmount")
    try:
        ui_amount = float(ui_amount_str) if ui_amount_str is not None else None
    except (TypeError, ValueError):
        ui_amount = None
    return {
        "decimals": decimals,
        "raw_amount": raw_amount,
        "ui_amount": ui_amount,
    }


def fetch_alpha_listing(ca_lower: str) -> dict[str, Any] | None:
    """Return the Alpha listing entry for `ca_lower`, or None if not listed.

    For EVM: `ca_lower` is a lowercase 0x-prefixed 40-hex address; matched
    case-insensitively against `entry.contractAddress`.

    For Solana: `ca_lower` is the original base58 CA (case-preserved). v0.7.21.7:
    we additionally try a case-insensitive fallback because the Alpha API
    has been observed to round-trip Solana CAs with inconsistent case (e.g.
    `…pump` suffix sometimes lowercase, sometimes mixed). The exact match is
    preferred to avoid `1`/`l` style ambiguity that lower() can introduce.
    """
    doc = _curl_json(_ALPHA_LIST_URL)
    if doc is None or "data" not in doc:
        return None
    ca_l_ci = ca_lower.lower()
    exact_hit = None
    ci_hit = None
    for entry in doc["data"]:
        ca_alpha = entry.get("contractAddress") or ""
        if ca_alpha == ca_lower:
            exact_hit = entry
            break
        if ca_alpha.lower() == ca_l_ci and ci_hit is None:
            ci_hit = entry
    return exact_hit or ci_hit


def probe_spot_symbol(symbol: str) -> str | None:
    """Probe Binance Spot exchangeInfo. Returns the matching trading pair
    (e.g. 'BSBUSDT') if listed on Spot, else None.
    """
    url = f"{_SPOT_EXCHANGE_INFO}?symbol={symbol}USDT"
    doc = _curl_json(url)
    if doc is None or "symbols" not in doc:
        return None
    for s in doc.get("symbols", []):
        sym = s.get("symbol")
        if sym:
            return sym
    return None


# --------------- v0.7.9 cross-chain + freshness probes ----------------

def _load_coingecko_cache() -> list | None:
    """Return cached coin list if fresh, else None. Atomic file write."""
    try:
        st = _COINGECKO_CACHE_PATH.stat()
    except FileNotFoundError:
        return None
    if (time.time() - st.st_mtime) > _COINGECKO_CACHE_TTL_SECS:
        return None
    try:
        return json.loads(_COINGECKO_CACHE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _save_coingecko_cache(payload: list) -> None:
    try:
        _COINGECKO_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _COINGECKO_CACHE_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, _COINGECKO_CACHE_PATH)
    except OSError:
        pass


def fetch_coingecko_platforms(symbol: str | None, contract_address: str | None) -> dict[str, Any]:
    """根据 symbol 找 CoinGecko 跨链部署清单. Prefer exact-CA match
    on binance-smart-chain when multiple symbol-matched coins exist.
    """
    if not symbol:
        return {"platforms": {}, "match_id": None, "match_method": "no_symbol"}
    coins = _load_coingecko_cache()
    if coins is None:
        try:
            out = subprocess.run(
                ["curl", "-fsS", "--max-time", "10", _COINGECKO_COIN_LIST],
                # v0.8.4.9.10: explicit utf-8 encoding (Windows 11 + Python 3.13
                # default fallback to cp1252 → UnicodeDecodeError on UTF-8 JSON).
                # 用户 adversarial review feedback 2026-06-11 catch.
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=15, check=True,
            )
            coins = json.loads(out.stdout)
            _save_coingecko_cache(coins)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            return {"platforms": {}, "match_id": None, "match_method": "error", "error": str(e)[:120]}

    sym_lower = symbol.lower()
    matches = [c for c in coins if (c.get("symbol") or "").lower() == sym_lower]
    if not matches:
        return {"platforms": {}, "match_id": None, "match_method": "no_match"}
    ca_lower = (contract_address or "").lower()
    if ca_lower:
        for c in matches:
            bsc_ca = (c.get("platforms") or {}).get("binance-smart-chain", "")
            if bsc_ca and bsc_ca.lower() == ca_lower:
                return {
                    "platforms": c.get("platforms") or {},
                    "match_id": c.get("id"),
                    "match_method": "exact_ca",
                }
    c = matches[0]
    return {
        "platforms": c.get("platforms") or {},
        "match_id": c.get("id"),
        "match_method": "symbol_only_unverified" if len(matches) > 1 else "symbol_only",
    }


def _verify_project_match(
    project_id: str, ca_lower: str, symbol: str,
    search_candidate: dict[str, Any] | None = None,
) -> tuple[bool, dict[str, Any], str]:
    """Fetch surf project-detail; return (matches, project_data, match_reason).

    Verification logic (any one wins):
      (a) Exact CA match in project.contracts[].address → strongest.
      (b) Symbol match in project.tokens[].symbol AND symbol match in the
          search-result candidate's `.symbol`. surf's `contracts` list is
          frequently incomplete (e.g. Solstice's surf record lists only the
          EUSX child contract, not the SLX BSC mirror — but token_info IS
          the SLX-level data). Symbol-based match handles this gracefully.

    Returns (False, ...) only when neither (a) nor (b) holds — i.e. we'd
    bind to a totally unrelated project. Better to return fetch_ok=False
    than pollute price/vol downstream.
    """
    pd_doc, err = _run_surf_with_retry(
        ["surf", "project-detail", "--id", project_id, "--json"],
        base_timeout=15,
    )
    if pd_doc is None:
        return False, {}, err or "fetch_failed"
    data = pd_doc.get("data") or {}

    # (a) CA match in contracts list.
    contracts_blob = data.get("contracts")
    # surf wraps it inconsistently: sometimes [{"address":...}], sometimes
    # {"contracts":[{"address":...}]}. Normalize.
    contracts: list = []
    if isinstance(contracts_blob, list):
        contracts = contracts_blob
    elif isinstance(contracts_blob, dict):
        contracts = contracts_blob.get("contracts") or []
    for c in contracts:
        if isinstance(c, dict):
            if (c.get("address") or "").lower() == ca_lower:
                return True, data, "ca_in_contracts"

    # (b) Symbol-based match — only if the search candidate's symbol matched.
    # surf project-detail exposes the symbol at:
    #   data.overview.token_symbol  (canonical project ticker)
    #   data.token_info.symbol      (token-info block ticker)
    # search-project exposes it at the top-level `symbol` field.
    if symbol:
        sym_lower = symbol.lower()
        cand_sym = ((search_candidate or {}).get("symbol") or "").lower()
        if cand_sym == sym_lower:
            overview = data.get("overview") or {}
            token_info = data.get("token_info") or {}
            for slot in (
                overview.get("token_symbol"),
                token_info.get("symbol"),
            ):
                if (slot or "").lower() == sym_lower:
                    return True, data, "symbol_match"

    return False, data, "no_match"


def fetch_realtime_token_info_via_surf(
    symbol: str, contract_address: str, name: str | None = None,
) -> dict[str, Any]:
    """v0.7.10: surf-only **实时** aggregate vol / price / mcap.

    Replaces v0.7.9's `surf onchain-sql` against `bsc_dex_trades` (24h
    batch lag — broke on freshly-listed tokens where surf hadn't synced
    yet, e.g. Solstice 5/26 returning vol=0).

    Uses `surf project-detail.token_info` (real-time aggregate, CEX+DEX
    cross-chain). Verified on Solstice 2026-05-26: $105M 24h vol on
    listing day — matches CoinGecko/DexScreener.

    v0.7.10.3 rewrite: `surf project-detail --q <ticker>` resolves a ticker
    (or name or slug) directly to the project document in ONE call. The old
    approach (search-project then verify) failed for COLLECT because
    search-project only matches on `overview.name` — surf has COLLECT's
    project named "Fanable", while the Alpha API gives us name "Collect on
    Fanable" + ticker "COLLECT", neither of which search-project matched.
    project-detail --q accepts the ticker directly.

    Query order: [symbol, name, *name_tokens] — ticker first (canonical for
    Alpha tokens). Each candidate is CA-verified against project.contracts
    (symbol-match fallback) to guard same-ticker collisions.

    Returns:
        {
          "price_usd": float, "volume_24h_usd": float, "market_cap_usd": float,
          "fdv_usd": float, "price_change_24h_pct": float,
          "surf_project_id": str, "surf_chains": [str], "fetch_ok": bool,
        }
    Returns empty dict + fetch_ok=False on any failure.
    """
    fallback = {
        "price_usd": None, "volume_24h_usd": None,
        "market_cap_usd": None, "fdv_usd": None,
        "price_change_24h_pct": None,
        "surf_project_id": None, "surf_chains": [],
        "fetch_ok": False,
    }
    ca_lower = (contract_address or "").lower()
    if not ca_lower:
        return fallback

    _STOP = {"on", "of", "the", "a", "an", "and", "&", "by", "for", "in"}
    queries: list[str] = []
    if symbol:
        queries.append(symbol)             # ticker — canonical for Alpha
    if name and name not in queries:
        queries.append(name)               # full name fallback
    if name:
        for tok in name.split():
            t2 = tok.strip(".,()[]").strip()
            if len(t2) >= 3 and t2.lower() not in _STOP and t2 not in queries:
                queries.append(t2)         # name tokens (surf short-name case)
    if not queries:
        return fallback

    matched_data: dict[str, Any] | None = None
    matched_id: str | None = None
    matched_reason: str = ""
    for q in queries:
        pd_doc, _ = _run_surf_with_retry(
            ["surf", "project-detail", "--q", q, "--json"],
            base_timeout=15,
        )
        if pd_doc is None:
            continue
        data = pd_doc.get("data") or {}
        if not data:
            continue
        # CA-in-contracts hard verify (guards same-ticker collisions).
        contracts_blob = data.get("contracts")
        contracts: list = (
            contracts_blob if isinstance(contracts_blob, list)
            else (contracts_blob.get("contracts") if isinstance(contracts_blob, dict) else []) or []
        )
        ca_matched = any(
            isinstance(c, dict) and (c.get("address") or "").lower() == ca_lower
            for c in contracts
        )
        if ca_matched:
            matched_data, matched_reason = data, "ca_in_contracts"
            matched_id = (data.get("overview") or {}).get("id") or q
            break
        # Fallback: symbol equality (surf contracts list often incomplete —
        # e.g. Solstice surf record only lists the EUSX child contract).
        if symbol:
            sym_lower = symbol.lower()
            overview = data.get("overview") or {}
            token_info = data.get("token_info") or {}
            if (overview.get("token_symbol") or "").lower() == sym_lower or \
               (token_info.get("symbol") or "").lower() == sym_lower:
                matched_data, matched_reason = data, "symbol_match"
                matched_id = overview.get("id") or q
                break

    if not matched_data:
        return fallback

    ti = matched_data.get("token_info") or {}
    overview = matched_data.get("overview") or {}
    return {
        "price_usd": ti.get("price_usd"),
        "volume_24h_usd": ti.get("volume_24h"),
        "market_cap_usd": ti.get("market_cap_usd"),
        "fdv_usd": ti.get("fdv"),
        "price_change_24h_pct": ti.get("price_change_24h"),
        "surf_project_id": matched_id,
        "surf_chains": overview.get("chains") or [],
        "surf_match_reason": matched_reason,
        "fetch_ok": True,
    }


# v0.7.10: DEX entity_type / label matchers used to identify pool addresses
# from surf token-holders response. Arkham's structured `entity_type` is the
# strongest signal; fall back to label-text regex when entity_type is empty.
_DEX_ENTITY_TYPES = {"dex", "amm", "liquidity_pool", "decentralized_exchange"}
_DEX_LABEL_RE = re.compile(
    r"(pancakeswap|uniswap|sushiswap|curve|balancer|raydium|orca|meteora|"
    r"jupiter|trader\s*joe|quickswap|velodrome|aerodrome|cake\s*lp|"
    r"\bv[23]\s*pool\b|\bpool\b|\blp\b|liquidity\s*pool|amm)",
    re.IGNORECASE,
)


def _is_dex_holder(row: dict[str, Any]) -> bool:
    """Return True if holder row is a DEX pool (per Arkham label data)."""
    et = (row.get("entity_type") or "").lower()
    if not et and isinstance(row.get("label"), dict):
        et = (row["label"].get("entity_type") or "").lower()
    if et in _DEX_ENTITY_TYPES:
        return True
    # Fallback: label text matching. Pull from top-level entity_name and
    # nested label.labels[].label.
    candidates = []
    if row.get("entity_name"):
        candidates.append(str(row["entity_name"]))
    lbl = row.get("label")
    if isinstance(lbl, dict):
        if lbl.get("entity_name"):
            candidates.append(str(lbl["entity_name"]))
        for sub in lbl.get("labels") or []:
            if isinstance(sub, dict) and sub.get("label"):
                candidates.append(str(sub["label"]))
    return any(_DEX_LABEL_RE.search(c) for c in candidates)


def _fetch_one_chain_lp(
    plat: str, ca: str, chain_short: str, price_usd: float | None,
) -> dict[str, Any]:
    """One `surf token-holders` call → DEX-labeled subset → LP totals.

    v0.7.10.2: uses _run_surf_with_retry — transient subprocess /
    network / surf rate-limit errors are retried up to 4 attempts
    instead of silently propagating to derive_primary_chain.
    """
    cmd = [
        "surf", "token-holders",
        "--address", ca, "--chain", chain_short,
        "--limit", "100", "--include", "labels", "--json",
    ]
    doc, err = _run_surf_with_retry(cmd)
    if doc is None:
        return {
            "lp_tokens": None, "lp_usd": None, "n_dex_pools": 0,
            "top_pool_addr": None, "top_pool_balance": None,
            "surf_supported": True, "ca_on_chain": ca, "surf_chain": chain_short,
            "_error": err,
        }
    rows = doc.get("data") or []
    pools: list[tuple[str, float]] = []
    for row in rows:
        if not _is_dex_holder(row):
            continue
        addr = (row.get("address") or "").lower()
        try:
            bal = float(row.get("balance") or 0)
        except (TypeError, ValueError):
            bal = 0.0
        if bal > 0:
            pools.append((addr, bal))
    pools.sort(key=lambda x: x[1], reverse=True)

    # v0.8.4: classify ALL top-100 holders into 6 categories using
    # protocol_lockup_detector. Surface CEX / multisig / vesting / treasury
    # / airdrop_platform sums + unclassified large holders for
    # hidden_operator_enricher (suspected_operator_reserve detection).
    # Same surf call as the LP path — 0 extra credits / 0 extra time.
    try:
        from protocol_lockup_detector import classify_protocol_lockup
        classified: dict[str, dict] = {
            "cex": {"tokens": 0.0, "n_wallets": 0, "top": []},
            "lp": {"tokens": 0.0, "n_wallets": 0, "top": []},
            "multisig": {"tokens": 0.0, "n_wallets": 0, "top": []},
            "vesting": {"tokens": 0.0, "n_wallets": 0, "top": []},
            "treasury": {"tokens": 0.0, "n_wallets": 0, "top": []},
            "airdrop_platform": {"tokens": 0.0, "n_wallets": 0, "top": []},
            "burn": {"tokens": 0.0, "n_wallets": 0, "top": []},
            "unclassified": {"tokens": 0.0, "n_wallets": 0, "top": []},
        }
        # We don't know circulating supply at this fetch-time (section_a
        # phase, before alpha metadata is fully merged). Caller in
        # section_a will compute pct_circ post-fetch by passing
        # circulating_supply.
        for row in rows:
            try:
                bal = float(row.get("balance") or 0)
            except (TypeError, ValueError):
                bal = 0.0
            if bal <= 0:
                continue
            addr = (row.get("address") or "").lower()
            if addr in ("0x0000000000000000000000000000000000000000",
                        "0x000000000000000000000000000000000000dead"):
                classified["burn"]["tokens"] += bal
                classified["burn"]["n_wallets"] += 1
                continue
            # Parse surf label structure (surf returns
            # {address, balance, label: {entity_name, entity_type,
            # labels: [{label, confidence}]}}).
            lbl = row.get("label")
            text = ""
            ent_name = ""
            ent_type = ""
            if isinstance(lbl, dict):
                ent_name = str(lbl.get("entity_name") or "")
                ent_type = str(lbl.get("entity_type") or "")
                labels = lbl.get("labels") or []
                if isinstance(labels, list):
                    text = " | ".join(
                        str(x.get("label", "")) for x in labels
                        if isinstance(x, dict)
                    )
                if ent_name and text:
                    text = f"{ent_name} | {text}"
                elif ent_name:
                    text = ent_name
            elif isinstance(lbl, str):
                text = lbl
            cls = classify_protocol_lockup(
                arkham_label_text=text, entity_name=ent_name, entity_type=ent_type,
            )
            cat = None
            if cls["is_dex_infra"]:
                cat = "lp"
            elif cls["is_cex_custody"]:
                cat = "cex"
            elif cls["is_vesting"]:
                cat = "vesting"
            elif cls["is_multisig"]:
                cat = "multisig"
            elif cls["is_treasury"]:
                cat = "treasury"
            elif cls["is_airdrop_platform"]:
                cat = "airdrop_platform"
            else:
                cat = "unclassified"
            classified[cat]["tokens"] += bal
            classified[cat]["n_wallets"] += 1
            classified[cat]["top"].append({
                "addr": addr, "balance": bal, "label_text": text[:80],
            })
        # Sort each top list + cap at 10
        for cat_data in classified.values():
            cat_data["top"].sort(key=lambda x: -x["balance"])
            cat_data["top"] = cat_data["top"][:10]
    except Exception as _e:
        classified = {"_error": f"classify failed: {str(_e)[:120]}"}

    if not pools:
        return {
            "lp_tokens": None, "lp_usd": None, "n_dex_pools": 0,
            "top_pool_addr": None, "top_pool_balance": None,
            "surf_supported": True, "ca_on_chain": ca, "surf_chain": chain_short,
            "top_holders_classified": classified,
        }
    lp_tokens = sum(b for _, b in pools)
    lp_usd = (lp_tokens * price_usd) if price_usd else None
    top_addr, top_bal = pools[0]
    return {
        "lp_tokens": lp_tokens,
        "lp_usd": lp_usd,
        "n_dex_pools": len(pools),
        "top_pool_addr": top_addr,
        "top_pool_balance": top_bal,
        "surf_supported": True,
        "ca_on_chain": ca,
        "surf_chain": chain_short,
        "top_holders_classified": classified,
    }


def fetch_chain_lp_via_surf(
    platforms: dict[str, str], price_usd: float | None = None,
) -> dict[str, dict[str, Any]]:
    """v0.7.10: 实时 LP per chain via `surf token-holders --chain X --include labels`.

    For each CoinGecko-listed platform that surf token-holders supports
    (bsc / ethereum / base / arbitrum / polygon / optimism / avalanche /
    solana), call token-holders top-100 and sum the balance of holders
    whose Arkham label classifies them as a DEX pool / AMM. Multiply by
    the current real-time price (from project-detail.token_info.price_usd)
    to get LP USD value.

    This is the **real-time** path; v0.7.9 used `surf onchain-sql` against
    `bsc_dex_trades` which is a 24h+ batch and returned vol=0 for tokens
    listed in the last day (Solstice on 2026-05-26 was the trigger case).

    For platforms surf can't query (chain not in _SURF_HOLDER_CHAINS), the
    entry is marked `surf_supported: False` and `lp_usd: None`. Caller
    surfaces them as out-of-pipeline-scope.

    Returns:
      {
        chain_platform_id: {
          "lp_tokens": float | None,    # sum of DEX-labeled holder balances
          "lp_usd": float | None,       # × price_usd (None if no price)
          "n_dex_pools": int,           # how many holders were DEX-labeled
          "top_pool_addr": str | None,
          "top_pool_balance": float | None,
          "surf_supported": bool,
          "ca_on_chain": str,
          "surf_chain": str | None,
        }
      }
    """
    out: dict[str, dict[str, Any]] = {}
    queryable: list[tuple[str, str, str]] = []  # (platform_id, surf_chain, ca)
    for plat, ca in platforms.items():
        if not ca:
            continue
        chain_short = _SURF_HOLDER_CHAINS.get(plat)
        if not chain_short:
            out[plat] = {
                "lp_tokens": None, "lp_usd": None, "n_dex_pools": 0,
                "top_pool_addr": None, "top_pool_balance": None,
                "surf_supported": False, "ca_on_chain": ca, "surf_chain": None,
            }
            continue
        # EVM platforms expect 0x... CA, Solana expects base58 — let surf
        # validate. We only pre-reject obviously wrong (empty) CAs.
        queryable.append((plat, chain_short, ca))

    if not queryable:
        return out

    # Run all chains concurrently with a small thread pool. Each call is a
    # single CLI subprocess hitting a different chain → safe to parallelise.
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(8, len(queryable))) as ex:
        futures = {
            ex.submit(_fetch_one_chain_lp, plat, ca, chain_short, price_usd): plat
            for plat, chain_short, ca in queryable
        }
        for fut in futures:
            plat = futures[fut]
            try:
                out[plat] = fut.result()
            except Exception as e:
                out[plat] = {
                    "lp_tokens": None, "lp_usd": None, "n_dex_pools": 0,
                    "top_pool_addr": None, "top_pool_balance": None,
                    "surf_supported": True, "ca_on_chain": "",
                    "surf_chain": None, "_error": str(e)[:200],
                }
    return out


def _inject_alpha_chain_platform(
    platforms: dict[str, str] | None, chain_id: str | int | None, ca: str,
) -> dict[str, str]:
    """v1.0.2 (H 2026-06-20): guarantee the Alpha-API chain is in the platform
    map fed to `fetch_chain_lp_via_surf`, even when CoinGecko omits it.

    The pipeline pulls per-chain holders BEFORE picking primary_chain, and the
    pull is driven by CoinGecko's platform list — NOT by what surf supports nor
    by the authoritative Alpha chainId. `chain_lp_realtime` is keyed by those
    CoinGecko platforms, and the chip-structure 3-way classifier (screen_summary
    `_compute_chip_3way` + render 真实派发 section) reads
    `chain_lp_realtime[primary_chain].top_holders_classified`.

    H is an ETH token (chainId=1) whose CoinGecko platforms listed only
    hyperliquid/hyperevm (CG metadata gap) → fetch_chain_lp_via_surf never
    queried ethereum → no `chain_lp_realtime['ethereum']` → chip 3-way all 0%
    → 一屏「筹码结构」shows 数据缺失. surf FULLY supports ethereum (a live
    token-holders call returns 17 classified holders for H's ETH CA); the
    pipeline simply never asked, because CG didn't list it. The SQL detectors
    were unaffected — they route by the Alpha chainId, not CoinGecko.

    Injecting the Alpha chain (with the input CA as its address — the token's
    address on its own listing chain) forces the holder pull to include it.
    `setdefault` never overrides a genuine CoinGecko entry.
    """
    out = dict(platforms or {})
    alpha_plat = _CHAIN_ID_TO_CG_PLATFORM.get(str(chain_id or ""))
    if alpha_plat and alpha_plat in _SURF_HOLDER_CHAINS and ca:
        # adversarial review v1.0.2: inject when the key is MISSING **or blank/None** —
        # CoinGecko sometimes lists a platform with an empty address, and
        # `setdefault` would keep that blank → fetch_chain_lp_via_surf skips
        # empty CAs → the ETH pull is still missed. Only a truthy CoinGecko
        # address is preserved.
        if not out.get(alpha_plat):
            out[alpha_plat] = ca
    return out


def derive_primary_chain(
    chain_lp: dict[str, dict[str, Any]],
    alpha_chain_id: str | None = None,
) -> tuple[str | None, str]:
    """v0.7.20+: 用 surf 实时 LP (token-holders × price) 选主战场链.

    Decision tree (strictness order):
      1. **有任意 surf-supported 链 fetch 失败 (_error 字段存在)** AND
         能从剩余链选出一个 lp_usd_max → 标 `lp_usd_max_unreliable_<chain>`.
         (Banner 警告用户 fetch 失败.)
      2. surf-supported 链有 >0 LP USD → 选 lp_usd 最大的 (`lp_usd_max`).
      3. surf-supported 全 0 LP 时 (primary_chain 路由 holder/cluster/CEX
         的 token-holders 查询, skill 只能查 surf-supported 链, **绝不能落
         到 non-surf 链**):
         (3a) Alpha chainId 的 CoinGecko platform 在 chain_lp 里 → 选它,
              标 `lp_zero_fallback_alpha_chain`.
         (3b) **v1.0.1 (H): Alpha chainId 映射到 surf-supported 链 (即使不
              在 chain_lp dict 里) → 选它, 标 `alpha_chain_surf_supported`.**
         (3c) **v1.0.1: chain_lp 里有任意 surf-supported 链 → 选它 (哪怕 0
              LP), 标 `surf_supported_fallback`. 取代旧的 `non_surf_inferred`
              (那个会把 hyperliquid/celo 当 primary → holder SQL 路由到查不
              了的分区 → 筹码三桶 0%).**
         (3d) **v1.0.1: 完全没 surf-supported 链 → fallback BSC, 标
              `no_surf_chain_bsc_fallback`. 绝不返回 non-surf 链.**
      4. 完全无 platforms → `no_platforms` (Alpha chainId surf-supported
         时已在 3b 兜住).
    """
    # Detect fetch errors first — these change derivation confidence.
    failed_chains = sorted(
        p for p, v in chain_lp.items()
        if v.get("_error") and v.get("surf_supported")
    )

    # v1.0.1 (H 2026-06-18 + adversarial review HIGH): the Alpha-API chainId is the
    # AUTHORITATIVE routing key. SQL detectors already route by
    # `set_active_chain(chain_id)`; `primary_chain` routes the holder /
    # wallet-cluster / CEX-label token-holders queries. The two MUST agree
    # — so whenever the Alpha chainId maps to a surf-supported chain, that
    # chain wins OUTRIGHT, regardless of LP on other chains and regardless
    # of whether it's a key in the CoinGecko-derived chain_lp dict.
    #
    #   * H (zero-LP, non-surf CG platforms): ETH token, chainId=1, CG
    #     listed only hyperliquid + hyperevm. Old code fell to
    #     `non_surf_inferred` = hyperliquid → holder/cluster/CEX SQL hit an
    #     unqueryable partition → 筹码三桶 0%.
    #   * adversarial review HIGH (positive-LP split): a Base token (chainId=8453) with a
    #     bigger ETH wrapper LP — old `lp_usd_max` picked ethereum, so SQL
    #     ran on Base while holders ran on Ethereum = incoherent report.
    #
    # The skill can only query surf-supported chains (BSC / ETH / ARB / BASE
    # / Polygon / Optimism / Solana); a non-surf chain as primary_chain is
    # always a dead end. LP-max is now only a tiebreaker
    # for the rare case where the Alpha chainId is missing / unmapped.
    alpha_platform = _CHAIN_ID_TO_CG_PLATFORM.get(str(alpha_chain_id or ""))
    if alpha_platform and alpha_platform in _SURF_HOLDER_CHAINS:
        if alpha_platform in failed_chains:
            # Keep the "unreliable_fetch_failed" substring so render_report's
            # fetch-error banner (which greps for it) fires on this path too.
            return alpha_platform, f"alpha_chain_authoritative_unreliable_fetch_failed:{alpha_platform}"
        return alpha_platform, "alpha_chain_authoritative"

    # No usable Alpha chainId hint — fall back to liquidity discovery, but
    # NEVER to a non-surf chain (the skill can't query it).
    surf_supported = {
        p: v for p, v in chain_lp.items()
        if v.get("surf_supported") and (v.get("lp_usd") or 0) > 0
    }
    if surf_supported:
        primary = max(surf_supported.keys(), key=lambda p: surf_supported[p]["lp_usd"])
        if failed_chains:
            return primary, f"lp_usd_max_unreliable_fetch_failed:{','.join(failed_chains)}"
        return primary, "lp_usd_max"

    # All-zero LP and no Alpha hint: prefer ANY surf-supported chain present
    # (at least the holder query can run) over a non-surf pick.
    surf_present = sorted(
        p for p, v in chain_lp.items() if v.get("surf_supported")
    )
    if surf_present:
        return surf_present[0], "surf_supported_fallback"

    # No surf-supported chain anywhere — for an Alpha-listed token this is a
    # CoinGecko metadata gap (the token IS on a surf chain; CG just didn't
    # list it). Route to BSC (queryable) so the holder path returns
    # real-or-empty from a real partition, never a non-surf dead end. The
    # derivation flag discloses the uncertainty.
    if chain_lp:
        return "binance-smart-chain", "no_surf_chain_bsc_fallback"

    return None, "no_platforms"


def check_surf_data_freshness(ca: str, alpha_listing_date: str | None) -> dict[str, Any]:
    """探 surf bsc_transfers 的 max(block_time) 看数据滞后多久."""
    out = {
        "latest_surf_block_time": None,
        "latest_surf_date_utc": None,
        "lag_hours": None,
        "warning": None,
    }
    # v0.7.21.7: chain-aware CA validation. EVM 0x40-hex on EVM chains,
    # Solana base58 32-44 on Solana. SQL-injection guard: only embed the
    # CA after `is_valid_addr` accepts it for the active chain.
    from chain_router import is_valid_addr, get_active_chain
    if not is_valid_addr(ca or ""):
        return out
    # Solana CAs are case-sensitive; EVM CAs are case-insensitive but we
    # lower-case them for consistency with all other helpers.
    ca_for_sql = ca if get_active_chain() == "solana" else ca.lower()
    sql = (
        "SELECT max(block_time) AS latest_ts "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca_for_sql}' "
        f"AND block_date >= today() - 30"
    )
    body = json.dumps({"sql": sql, "max_rows": 1})
    doc, _ = _run_surf_with_retry(
        ["surf", "onchain-sql"], stdin=body,
    )
    if doc is None:
        return out
    rows = doc.get("data") or []
    if not rows:
        return out
    ts_raw = rows[0].get("latest_ts")
    if ts_raw is None:
        return out
    try:
        ts = int(ts_raw)
    except (TypeError, ValueError):
        return out
    out["latest_surf_block_time"] = ts
    out["latest_surf_date_utc"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    lag_secs = time.time() - ts
    lag_hours = lag_secs / 3600.0
    out["lag_hours"] = round(lag_hours, 1)
    if lag_hours > 24:
        # v0.7.9 中性表述: 不说"滞后", 说"底层数据可获得至 XXX". 让用户知道
        # 数据截止时间, 而不是带责备色彩的"晚了几天".
        out["warning"] = t(
            "sec1.scope.data_freshness_warning",
            latest_date=out['latest_surf_date_utc'],
            lag_hours=out['lag_hours'],
        )
    return out


def run(ca: str) -> dict[str, Any]:
    """Section A entrypoint. Pipeline calls this with the user-provided CA.

    Returns a dict with at minimum:
      - scope_ok: True/False
      - reason (if not ok): SPOT_GRADUATED | NEVER_ALPHA | INVALID_CA | API_DOWN
      - (if scope_ok) all Section A scope fields

    Caller (forensic_pipeline.py) should abort forensic and surface the reason
    to the user if scope_ok is False.
    """
    # v0.7.21.7: accept EVM 0x40-hex OR Solana base58 32-44 chars. Section A
    # runs BEFORE chain_router.set_active_chain (we don't know the chain
    # yet — Alpha API will tell us via chainId), so we accept both
    # formats here and let chain_router decide the active chain after
    # Section A returns.
    _evm_ok = (
        ca and ca.startswith("0x") and len(ca) == 42
        and all(c in "0123456789abcdefABCDEF" for c in ca[2:])
    )
    _solana_ok = (
        ca and 32 <= len(ca) <= 44
        and all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                for c in ca)
    )
    if not (_evm_ok or _solana_ok):
        return {
            "scope_ok": False,
            "reason": "INVALID_CA",
            "detail": (
                f"CA {ca!r} failed format check (expected EVM 0x + 40 hex "
                "chars OR Solana base58 32-44 chars)"
            ),
        }

    # EVM addresses are case-insensitive on the surf side; we normalise to
    # lower-case downstream. Solana base58 IS case-sensitive — preserve
    # original case.
    ca_lower = ca.lower() if _evm_ok else ca

    # Alpha listing fetch
    entry = fetch_alpha_listing(ca_lower)

    if entry is None:
        # Not in Alpha → probe Spot to differentiate SPOT_GRADUATED vs NEVER_ALPHA
        # We don't have a symbol from Alpha API; the caller may pass symbol_hint
        # but that's optional. Without symbol, we can only say NEVER_ALPHA.
        return {
            "scope_ok": False,
            "reason": "NEVER_ALPHA_OR_GRADUATED",
            "detail": (
                f"CA {ca_lower} not in Alpha listing. Could be: (a) never on Alpha, "
                "(b) graduated to Binance Spot. Pass symbol_hint to differentiate, "
                "or check https://www.binance.com/en/trade manually."
            ),
        }

    symbol = entry.get("symbol")
    name = entry.get("name")
    total_supply = entry.get("totalSupply")
    circ_supply = entry.get("circulatingSupply")
    listing_ts = entry.get("listingTime")  # ms
    vol_24h = entry.get("volume24h")
    chain_id = str(entry.get("chainId", ""))

    # Belt-and-braces: even if CA IS in Alpha, check if Spot has the symbol
    # (mutual-exclusion invariant lag where Binance added to Spot but not yet
    # removed from Alpha).
    if symbol:
        spot_hit = probe_spot_symbol(symbol)
        if spot_hit:
            return {
                "scope_ok": False,
                "reason": "SPOT_GRADUATED",
                "detail": (
                    f"{symbol} appears in BOTH Alpha listing AND Binance Spot as "
                    f"{spot_hit}. By design Alpha and Spot are mutually exclusive; "
                    "token is in graduation transition. Forensic does NOT apply."
                ),
                "spot_pair": spot_hit,
            }

    # Derive listing date
    try:
        listing_ts_int = int(listing_ts)
        listing_date_utc = (
            datetime.fromtimestamp(listing_ts_int / 1000, tz=timezone.utc)
            .strftime("%Y-%m-%d")
        )
    except (TypeError, ValueError):
        listing_date_utc = None

    # v0.6.1 fix: Alpha API returns circulatingSupply as decimal string
    # (e.g. "2568907563.02521"). int() on that throws ValueError → all 3
    # fields fall to None → downstream progress_bars get pct=None → bar
    # renders all-empty ░░░░ (visual bug user reported on a token report).
    # Fix: parse float first, then int. Handles both clean integer strings
    # ("5000000000") and decimal strings ("2568907563.02521").
    try:
        total = int(float(total_supply))
        circ = int(float(circ_supply))
        circ_ratio = circ / total if total > 0 else None
    except (TypeError, ValueError):
        total, circ, circ_ratio = None, None, None

    try:
        vol_24h_f = float(vol_24h)
    except (TypeError, ValueError):
        vol_24h_f = None

    # v0.7.16: Alpha API token-list returns price + marketCap + fdv + 24h
    # high/low alongside volume24h. Earlier the pipeline only grabbed
    # volume24h and relied on surf project-detail for price — but surf
    # NOT_FOUND on a real listed token (GUA 上线 3 个月 surf 没 index) silently
    # left price=None and the report's TGE / decision-stop-loss / liq tables
    # rendered every price cell as "—". Per the user's directive (memory
    # feedback_binance_alpha_vol_must_fetch.md): "Alpha-listed token 任何
    # 价格 / vol 必须用 Binance Alpha 官方 endpoint". Pull them all here so
    # the rest of the pipeline can use the Alpha price as a fallback when
    # surf project-detail is unavailable.
    def _safe_float(x):
        try: return float(x) if x is not None else None
        except (TypeError, ValueError): return None
    alpha_price_usd            = _safe_float(entry.get("price"))
    alpha_percent_change_24h   = _safe_float(entry.get("percentChange24h"))
    alpha_market_cap_usd       = _safe_float(entry.get("marketCap"))
    alpha_fdv_usd              = _safe_float(entry.get("fdv"))
    alpha_liquidity_usd        = _safe_float(entry.get("liquidity"))   # LP USD per Alpha API
    alpha_price_high_24h       = _safe_float(entry.get("priceHigh24h"))
    alpha_price_low_24h        = _safe_float(entry.get("priceLow24h"))
    alpha_count_24h            = _safe_float(entry.get("count24h"))    # 24h tx count
    alpha_holders              = _safe_float(entry.get("holders"))

    # v0.7.10: realtime 数据走两条 surf 实时路径 (不再走 24h 滞后 ClickHouse):
    #   1. `surf project-detail.token_info` → 跨链 aggregate 实时 vol/price/mcap
    #   2. `surf token-holders --chain X --include labels` per CoinGecko 平台 →
    #      DEX-labeled holders × price = 实时 LP USD per chain (主战场识别)
    cg = fetch_coingecko_platforms(symbol, ca_lower)
    # v1.0.2 (H 2026-06-20): ALWAYS fetch the Alpha-API chain's holders, even
    # when CoinGecko's platform list omits it. See _inject_alpha_chain_platform.
    cg["platforms"] = _inject_alpha_chain_platform(
        cg.get("platforms"), chain_id, ca_lower
    )
    realtime = fetch_realtime_token_info_via_surf(symbol or "", ca_lower, name=name)
    price_usd = realtime.get("price_usd")
    chain_lp = (
        fetch_chain_lp_via_surf(cg["platforms"], price_usd=price_usd)
        if cg["platforms"] else {}
    )
    primary_chain, derivation = (
        derive_primary_chain(chain_lp, alpha_chain_id=chain_id)
        if chain_lp else (None, "no_platforms")
    )
    # v0.7.9: surf BSC partition 数据新鲜度 (历史 SQL 维度) — 保留供 banner 用,
    # 不再用来决策 vol/LP/primary_chain (那些都走实时 endpoint 了).
    # v0.7.20 adversarial review MEDIUM #2: freshness probe runs INSIDE section_a, which
    # is invoked BEFORE forensic_pipeline calls set_active_chain. Without
    # this temporary route, the probe would query whatever chain the
    # module global is currently set to (default "bsc"), producing a
    # banner that mis-attributes data freshness when the actual primary
    # chain is e.g. Base. Route the probe to the Alpha-API chain so the
    # banner matches the pipeline's downstream SQL routing.
    try:
        from chain_router import chain_lock as _chain_lock
        with _chain_lock(chain_id) if chain_id else _nullcontext():
            freshness = check_surf_data_freshness(ca_lower, listing_date_utc)
    except Exception:
        # Unmapped/unknown chainId — fall back to whatever the module
        # global says (matches pre-v0.7.20 behavior). The banner will
        # still surface freshness in BSC partition, which is informative
        # diagnostic noise rather than a correctness issue.
        freshness = check_surf_data_freshness(ca_lower, listing_date_utc)

    # v0.7.21.9: SPL mint metadata for Solana CAs. Carries `decimals` so
    # downstream sections can normalise surf token-holders raw-lamport
    # balances, plus `chain_total_supply` (on-chain ground truth, often
    # off from Alpha API's snapshot for inflationary mints). EVM CAs use
    # contract decimals as-is via Alpha API's already-normalised supply.
    chain_decimals: int | None = None
    chain_total_supply_ui: float | None = None
    if _solana_ok:
        spl = fetch_solana_spl_supply(ca_lower)
        if spl:
            chain_decimals = spl.get("decimals")
            chain_total_supply_ui = spl.get("ui_amount")
    else:
        # v0.9.7 fix #2: EVM `decimals()` RPC lookup. Pre-v0.9.7 every SQL
        # hardcoded `/1e18` (the 18-decimal default). FOLKS empirical
        # (6 decimals) → all token amounts in skeleton were off by 1e12.
        # Failure-safe: any RPC error leaves chain_decimals=None → router
        # falls back to 18 → v0.9.6 behavior preserved.
        chain_decimals = _fetch_evm_token_decimals(ca_lower, chain_id)

    # v0.9.7: propagate to chain_router so every helper's SQL builder uses
    # the correct divisor instead of hardcoded `/1e18`.
    try:
        from chain_router import set_token_decimals
        set_token_decimals(chain_decimals)
    except Exception as _e:
        import sys as _sys
        print(f"[section_a] decimals propagate failed (non-fatal): {_e}",
              file=_sys.stderr)

    return {
        "scope_ok": True,
        "symbol": symbol,
        "name": name,
        "contract_address": ca_lower,
        "chain_id": chain_id,
        "chain_label": _CHAIN_ID_TO_LABEL.get(chain_id, f"chain_id_{chain_id}"),
        "total_supply": total,
        "circulating_supply": circ,
        "circ_ratio": circ_ratio,
        "alpha_listing_ts_ms": listing_ts,
        "alpha_listing_date_utc": listing_date_utc,
        "alpha_vol_24h_usd": vol_24h_f,
        # v0.7.16: Alpha API token-list price+liquidity fields. Fallback when
        # surf project-detail returns NOT_FOUND (e.g. GUA — listed 3 months,
        # still not indexed). Per memory feedback_binance_alpha_vol_must_fetch.
        # These also drive the top-of-report token-info header table that was
        # previously gated on `rti.fetch_ok` and invisible on surf-not-found tokens.
        "alpha_price_usd": alpha_price_usd,
        "alpha_percent_change_24h": alpha_percent_change_24h,
        "alpha_market_cap_usd": alpha_market_cap_usd,
        "alpha_fdv_usd": alpha_fdv_usd,
        "alpha_liquidity_usd": alpha_liquidity_usd,
        "alpha_price_high_24h": alpha_price_high_24h,
        "alpha_price_low_24h": alpha_price_low_24h,
        "alpha_count_24h": alpha_count_24h,
        "alpha_holders": alpha_holders,
        "spot_status": "not_on_spot",
        "token_type_initial": (
            "MEME_LIKELY" if (circ_ratio is not None and circ_ratio >= 0.99)
            else "VC_LIKELY" if circ_ratio is not None
            else "UNKNOWN"
        ),
        # v0.7.10: 跨链 + 主战场识别走实时 LP. primary_chain 是 surf token-holders
        # 实测 DEX-labeled LP USD 最大的链 (不再用 ClickHouse 滞后 vol). chain_lp
        # 是各链当前 LP 明细 (lp_tokens / lp_usd / n_dex_pools / top_pool_addr).
        "coingecko_platforms": cg["platforms"],
        "coingecko_match_id": cg.get("match_id"),
        "coingecko_match_method": cg.get("match_method"),
        "chain_lp_realtime": chain_lp,
        "primary_chain": primary_chain,
        "primary_chain_derivation": derivation,
        # v0.7.10: surf project-detail 实时 aggregate token_info (price/vol/mcap/
        # FDV/24h_change). 跨链 aggregate, 不分链 breakdown. CEX+DEX 合一.
        "realtime_token_info": realtime,
        # v0.7.9: surf BSC 数据滞后检测 (历史 SQL 维度), banner 仍触发, 但不再
        # 影响 primary_chain / vol / LP 决策.
        "data_freshness": freshness,
        # v0.7.21.9: on-chain SPL mint metadata (Solana only). decimals lets
        # section_f_holders / section_alloc normalise raw lamport balances
        # surf token-holders returns; chain_total_supply_ui is the on-chain
        # ground-truth supply (slightly different from Alpha API snapshot on
        # inflationary mints — JELLYJELLY shipped 999,966,701 on-chain vs
        # 999,999,099 Alpha). None on EVM and on Solana RPC fallback.
        "chain_decimals": chain_decimals,
        "chain_total_supply_ui": chain_total_supply_ui,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("ca", help="Contract address (0x... 40-hex)")
    args = ap.parse_args()
    result = run(args.ca)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result.get("scope_ok") else 1)
