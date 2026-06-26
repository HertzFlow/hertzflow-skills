"""chain_router.py — v0.7.20 cross-chain SQL table router.

Background
==========

forensic_pipeline.py and every helper (rule_11, dump_tracker, wash_infra,
section_a, section_anomaly_72h, section_liq, section_tge, role_classifier,
section_wash_infra) hardcoded `agent.bsc_transfers` and `agent.bsc_dex_trades`
in their SQL strings, dating to v0.6 when the skill was BSC-only. v0.7.20
adds a chain-routing layer so the same pipeline can run against any of
surf's 7 EVM-compatible chains plus Solana.

Surf's data coverage (re-verified 2026-06-02 after v0.7.21.7 FARTCOIN
ship surfaced a coverage gap I had previously documented wrong):

  ✅ BSC          agent.bsc_transfers       / agent.bsc_dex_trades
  ✅ Ethereum    agent.ethereum_transfers  / agent.ethereum_dex_trades
  ✅ Arbitrum    agent.arbitrum_transfers  / agent.arbitrum_dex_trades
  ✅ Base        agent.base_transfers      / agent.base_dex_trades
  ✅ Polygon     agent.polygon_transfers   / agent.polygon_dex_trades
  ✅ Optimism    agent.optimism_transfers  / agent.optimism_dex_trades
  ⚠️  Solana     **NOT covered** by surf's onchain-sql (no
                 `agent.solana_*` table exists; `surf onchain-schema`
                 lists `arbitrum/base/bsc/ethereum/tempo` as the
                 SQL-supported chains as of 2026-06-02).

For Solana tokens we can still hit:
  - `surf token-holders --chain solana --address <CA> --include labels`
    (REST endpoint, returns top-N holders with Arkham labels)
  - `surf project-detail` for realtime price / vol / mcap

…but the SQL-driven detectors (rule_11 mint trace, dump_tracker
top-seller table, wash_infra_detector closed-loop SQL, flow_operator
cross-Alpha SQL, section_anomaly_72h transfer SQL, section_liq pool
SQL, section_tge LP-first-trade SQL, section_l_distribution dumper-
destination SQL, cross_sym registry SQL) all require those missing
Solana tables.

v0.7.21.8 therefore routes Solana through a HOLDER_SNAPSHOT mode:
SQL-only sections short-circuit with a `_skip_reason="surf_no_sql_solana"`
status; section_f_holders (REST), section_alloc (Alpha API), and the
monitoring-paste export still run. Pre-v0.7.21.8 those SQL sections
silently returned empty rows and the report shipped looking like a
forensic clean bill of health, which is the misleading failure mode
the user caught when FARTCOIN's report showed 0 m6 / 0 cross-sym
whales / 0 wash setups despite being a $151M MC live token.

History note: v0.7.20's "surf supports Solana SQL" line came from me
misreading a `surf onchain-sql` error message — when a Solana table
identifier was passed in the SQL parser ran its missing-`block_date`
pre-check and echoed the table name back in the error string, which I
interpreted as "table exists". A subsequent probe with a real
block_date filter returned a UNKNOWN_TABLE error explicitly listing
the supported chains (no Solana). v0.7.21.7's pipeline ran end-to-end
on FARTCOIN but every SQL detector hit the same UNKNOWN_TABLE error
and degraded to empty rows, producing the misleading "looks ok"
skeleton. v0.7.21.8 fail-loud-but-graceful on that gap.

Usage pattern
=============

`forensic_pipeline.py` calls `set_active_chain(chain_id)` immediately
after `section_a_scope` returns the scope dict (which contains the
Alpha API's `chainId`). Every downstream helper module reads the active
chain via `transfers_table()` / `dex_trades_table()` instead of hard-
coding the BSC table name.

Defaults to `bsc` if `set_active_chain` was never called, preserving
behavior for any out-of-pipeline callers that import a helper directly
(e.g. CLI smoke tests).

Thread-safety
=============

`forensic_pipeline.py` is a single-shot CLI. The active chain is set
exactly once in the main thread immediately after Section A returns the
Alpha-API `chainId`, and is read by all downstream helpers — including
helpers that fan out via `ThreadPoolExecutor` inside `wash_infra_detector`
/ `dump_tracker` / `rule_11_backward_trace`.

We deliberately use a **plain module-level string** rather than
`ContextVar` or `threading.local`. Empirical test (verified during
v0.7.20 development): a `ContextVar` with a `default=` value is NOT
inherited by `ThreadPoolExecutor` workers — they see the default, not
the value set in the main thread. That would silently route SQL in
parallel sections to BSC even when the main thread set Base, exactly
the v0.7.19.x mis-routing bug we're fixing. `threading.local` has the
same problem (workers get a fresh local).

Module-level string works because Python's GIL gives every thread the
same view of module globals. The "global mutable adversarial review flag" cost is
worth paying here — the alternative is a silent cross-thread routing
bug.

Use the `chain_lock()` context manager (or `set_active_chain` + explicit
reset in tests) when you need to temporarily route SQL to a different
chain.
"""

from __future__ import annotations

import re
import warnings
from contextlib import contextmanager
from typing import Final, Iterator


# chain_id (int) → table prefix used by surf's `agent.{prefix}_transfers`
# and `agent.{prefix}_dex_trades`. Solana is non-EVM and Alpha API
# encodes it with a sentinel chain_id; we currently see -1 / None on
# some API responses, so we also accept the string token "solana" via
# `set_active_chain("solana")`.
#
# Sources for chain_id mapping (EIP-155):
#   1     = Ethereum mainnet
#   10    = Optimism
#   56    = BNB Smart Chain (BSC)
#   137   = Polygon PoS
#   8453  = Base
#   42161 = Arbitrum One
_CHAIN_ID_TO_PREFIX: Final[dict[int, str]] = {
    1: "ethereum",
    10: "optimism",
    56: "bsc",
    137: "polygon",
    8453: "base",
    42161: "arbitrum",
}

# v0.7.21.7: Alpha API uses non-numeric chain identifiers for non-EVM
# chains. Solana is reported as "CT_501" (the prefix "CT_" plus the
# SLIP-44 coin type 501 for Solana). Map those explicitly so
# `set_active_chain("CT_501")` from forensic_pipeline works without
# the caller having to translate first.
_NON_NUMERIC_CHAIN_ID_TO_PREFIX: Final[dict[str, str]] = {
    "CT_501": "solana",
}

# All chain prefixes the router accepts as direct strings (case-insensitive).
_VALID_PREFIXES: Final[frozenset[str]] = frozenset({
    "bsc", "ethereum", "optimism", "polygon", "base", "arbitrum", "solana",
})

# Default to BSC so any direct-import call site without a pipeline
# context (e.g. unit test importing rule_11_backward_trace.SQL_FIND_MINT)
# gets the v0.6 - v0.7.19.5 behavior. Plain module-level string — see
# Thread-safety section in module docstring for why this beats ContextVar.
_active_chain: str = "bsc"


class UnsupportedChainError(ValueError):
    """Raised when `set_active_chain` is called with an unmapped chain_id
    or an unrecognized chain name. We fail-loud rather than silently
    fall back to BSC because a silent fallback would re-create the
    PLAY-style mis-attribution bug (running a Base token against BSC
    tables and producing an empty-but-shipped forensic report)."""


def set_active_chain(chain: int | str) -> str:
    """Set the active chain for downstream SQL helpers.

    Args:
        chain: an EIP-155 `chain_id` int (e.g. 8453 for Base) OR a
               chain prefix string (e.g. "base", "ethereum", "solana").
               Case-insensitive on strings.

    Returns:
        The resolved chain prefix (lowercase, e.g. "base").

    Raises:
        UnsupportedChainError: if `chain` is unmapped. Fail-loud is
            intentional — a silent fallback would let a non-BSC token
            run against BSC tables and produce a misleading "empty
            forensic" report (the v0.7.19.x PLAY bug we're fixing).
    """
    global _active_chain  # v0.7.21.7: single declaration covers all branches
    if isinstance(chain, str):
        raw_original = chain.strip()
        raw = raw_original.lower()
        if not raw:
            raise UnsupportedChainError(
                "chain_router: empty chain identifier"
            )
        # v0.7.21.7: Alpha API non-numeric chain IDs (currently just
        # "CT_501" for Solana). Match case-insensitively against the
        # mapping keys.
        for key, value in _NON_NUMERIC_CHAIN_ID_TO_PREFIX.items():
            if raw == key.lower():
                _active_chain = value
                if value == "solana":
                    warnings.warn(
                        "chain_router: Solana routing enabled. Validators "
                        "(Section A CA regex, rule_11/dump_tracker/wash_infra/"
                        "flow_operators address checks) are chain-aware as of "
                        "v0.7.21.7. Surf DEX-trades coverage on Solana lags "
                        "BSC — expect fewer rows in trade-volume sections.",
                        stacklevel=2,
                    )
                return value
        # Accept numeric chain_id encoded as string ("8453") — Alpha API
        # responses arrive at the pipeline as `str(entry.get("chainId"))`
        # so by the time we reach the router the type has been lost.
        if raw.lstrip("-").isdigit():
            try:
                chain_id = int(raw)
            except ValueError as e:
                raise UnsupportedChainError(
                    f"chain_router: invalid numeric chain identifier {chain!r}"
                ) from e
            if chain_id not in _CHAIN_ID_TO_PREFIX:
                raise UnsupportedChainError(
                    f"chain_router: unmapped chain_id {chain_id}. "
                    f"Supported chain_ids: {sorted(_CHAIN_ID_TO_PREFIX)} "
                    f"(plus 'solana' via string). Add the mapping in "
                    f"chain_router._CHAIN_ID_TO_PREFIX to onboard a new chain."
                )
            prefix = _CHAIN_ID_TO_PREFIX[chain_id]
        else:
            if raw not in _VALID_PREFIXES:
                raise UnsupportedChainError(
                    f"chain_router: unrecognized chain prefix {chain!r}. "
                    f"Supported: {sorted(_VALID_PREFIXES)}"
                )
            prefix = raw
    else:
        try:
            chain_id = int(chain)
        except (TypeError, ValueError) as e:
            raise UnsupportedChainError(
                f"chain_router: invalid chain identifier {chain!r}"
            ) from e
        if chain_id not in _CHAIN_ID_TO_PREFIX:
            raise UnsupportedChainError(
                f"chain_router: unmapped chain_id {chain_id}. "
                f"Supported chain_ids: {sorted(_CHAIN_ID_TO_PREFIX)} "
                f"(plus 'solana' via string). Add the mapping in "
                f"chain_router._CHAIN_ID_TO_PREFIX to onboard a new chain."
            )
        prefix = _CHAIN_ID_TO_PREFIX[chain_id]
    if prefix == "solana":
        # v0.7.21.7: Solana validators are now chain-aware (Section A CA regex,
        # rule_11/dump_tracker/wash_infra/flow_operators/role_classifier all
        # delegate to chain_router.is_valid_addr). Warn instead about surf
        # DEX-trades coverage on Solana, which lags BSC and may yield fewer
        # rows in trade-volume sections.
        warnings.warn(
            "chain_router: Solana routing enabled. Validators are chain-aware "
            "as of v0.7.21.7; surf DEX-trades coverage on Solana lags BSC.",
            stacklevel=2,
        )
    _active_chain = prefix
    return prefix


def get_active_chain() -> str:
    """Return the active chain prefix (lowercase). Defaults to 'bsc'."""
    return _active_chain


def transfers_table() -> str:
    """Return the surf SQL `agent.{prefix}_transfers` for the active chain.

    Use this in every SQL string that previously hardcoded
    `agent.bsc_transfers`. The substitution is a pure rename — the table
    schema is identical across chains (block_date / block_time / from /
    to / amount_raw / contract_address / tx_hash / tx_from columns).
    """
    return f"agent.{_active_chain}_transfers"


def dex_trades_table() -> str:
    """Return the surf SQL `agent.{prefix}_dex_trades` for the active chain.

    Use this in every SQL string that previously hardcoded
    `agent.bsc_dex_trades`. Schema identical across chains
    (block_date / block_time / token_sold_address / token_sold_amount /
    amount_usd / tx_from columns).
    """
    return f"agent.{_active_chain}_dex_trades"


# v0.9.7 fix #2 (FOLKS 6-decimal 2026-06-16): module-level token decimals.
# Pre-v0.9.7 every SQL hardcoded `/1e18` assuming 18-decimal ERC20. FOLKS
# is 6-decimal (Folks Finance was originally an Algorand project, 6-decimal
# default carried to its multichain EVM mirrors). Every token-amount field
# computed by the skill (m6 received, dump_tracker tokens, insider holdings,
# anomaly amounts) was wrong by `10^(18-decimals)` factor — for FOLKS that
# is 10^12. Ratios (dumped_pct, % supply) cancelled the error so verdict
# logic survived, but raw token counts in the report were 1e12 too small.
#
# section_a sets this on every CA via the EVM `decimals()` RPC call; if
# the RPC fails or the chain is Solana (uses SPL mint metadata path), we
# fall back to the v0.9.6 default 18 so behavior never regresses.
_token_decimals: int = 18


def set_token_decimals(d: int | None) -> None:
    """Set the active token's `decimals` value. Called by section_a after
    successful RPC lookup. None / invalid input falls back to 18 (v0.9.6
    behavior — never regresses for the 99% case)."""
    global _token_decimals
    try:
        d_int = int(d) if d is not None else 18
    except (TypeError, ValueError):
        d_int = 18
    # Bound check: ERC20 spec allows 0-255 but realistic tokens use 6-18.
    # Reject obvious garbage so downstream SQL doesn't `/1e0` divide.
    if d_int < 0 or d_int > 30:
        d_int = 18
    _token_decimals = d_int


def get_token_decimals() -> int:
    """Return active token decimals (default 18)."""
    return _token_decimals


def decimals_factor() -> float:
    """Return the divisor for raw amounts. SQL builders should use
    `decimals_factor_str()` instead — this is for Python-side math."""
    return 10.0 ** _token_decimals


def decimals_factor_str() -> str:
    """Return SQL-safe scientific notation for the active decimals factor.
    Defaults to `1e18` (v0.9.6 baseline) — exact string match so SQL plans
    remain identical for 18-decimal tokens. For FOLKS (6 decimals) returns
    `1e6`. Used in every SQL template's `{decimals_factor}` placeholder
    via `.format(decimals_factor=decimals_factor_str())`."""
    return f"1e{_token_decimals}"


@contextmanager
def chain_lock(chain: int | str) -> Iterator[str]:
    """Temporarily set the active chain, then restore the prior value.

    Useful in tests / cross-chain ad-hoc scripts that want to flip the
    router for a single block without leaking state into other tests.
    """
    global _active_chain
    prior = _active_chain
    try:
        yield set_active_chain(chain)
    finally:
        _active_chain = prior


def supported_chains() -> list[str]:
    """List of chain prefixes the router accepts (for diagnostics)."""
    return sorted(_VALID_PREFIXES)


# v0.7.21.8: surf onchain-sql coverage. Solana is intentionally absent —
# surf has no `agent.solana_*` table (verified 2026-06-02 against
# `surf onchain-schema`; the error path also lists supported chains
# explicitly). Helpers that build SQL against `agent.{chain}_transfers`
# / `agent.{chain}_dex_trades` should gate on this set before issuing
# the query and short-circuit with `_skip_reason="surf_no_sql_solana"`
# (or similar) otherwise the surf call wastes a credit and returns an
# empty rowset that downstream code mis-reads as "0 hits".
_SQL_SUPPORTED_CHAINS: Final[frozenset[str]] = frozenset({
    "bsc", "ethereum", "arbitrum", "base", "polygon", "optimism",
})


def sql_supported() -> bool:
    """True when the active chain has `agent.{chain}_transfers/dex_trades`
    tables in surf's onchain-sql. False for chains where forensic helpers
    must skip SQL-based detection (currently: Solana).
    """
    return _active_chain in _SQL_SUPPORTED_CHAINS


def requires_holder_snapshot() -> bool:
    """True when the active chain has NO surf onchain-sql coverage and the
    forensic pipeline should run in HOLDER_SNAPSHOT mode (Alpha API
    realtime + surf token-holders REST + section_alloc only).
    Currently equivalent to `not sql_supported()`; kept as a separate
    name so callers can express intent ("am I in holder-snapshot mode?")
    rather than "is SQL available?".
    """
    return not sql_supported()


# v0.7.21.7: chain-aware address validation. Every helper that used to
# hardcode `^0x[0-9a-f]{40}$` (rule_11_backward_trace, dump_tracker,
# wash_infra_detector, flow_operator_detector, section_cross_sym, etc.)
# now delegates to `is_valid_addr` so the same code path produces correct
# checks on Solana base58 wallets too. Pre-v0.7.21.7 Solana CAs cleared
# Section A but every downstream SQL helper rejected every base58 address
# in their _valid_addr filters → m6/dump_tracker/wash/flow_operators all
# returned empty for Solana tokens.
_EVM_ADDR_RE: Final[re.Pattern] = re.compile(r"^0x[0-9a-f]{40}$")
# Solana base58 — alphanumeric minus 0/O/I/l, 32-44 chars. Length 44 is
# typical for pump.fun tokens / token mints; vanity-derived PDAs and some
# program-owned accounts can be slightly shorter.
_SOLANA_ADDR_RE: Final[re.Pattern] = re.compile(
    r"^[1-9A-HJ-NP-Za-km-z]{32,44}$"
)


def is_valid_addr(addr) -> bool:
    """Return True if `addr` is a syntactically valid wallet / contract
    address for the *currently active chain*.

    On EVM chains: matches `^0x[0-9a-f]{40}$` (case-insensitive — the
    helper lowercases before matching). On Solana: matches base58
    32-44 chars (excludes 0/O/I/l per the Bitcoin base58 alphabet).

    Use this in every helper that filters addresses out of a SQL `IN`
    list or guards against SQL injection. Direct callers that only
    want one chain's regex should grab `addr_re_pattern()` instead.
    """
    if not isinstance(addr, str):
        return False
    if _active_chain == "solana":
        return bool(_SOLANA_ADDR_RE.fullmatch(addr))
    return bool(_EVM_ADDR_RE.fullmatch(addr.lower()))


def addr_re_pattern() -> re.Pattern:
    """Return the compiled address-format regex for the active chain.

    Helpers that need to embed the pattern in a larger regex (e.g.
    multi-address tokenisers) should call this rather than maintain
    their own copy of the EVM/Solana split.
    """
    return _SOLANA_ADDR_RE if _active_chain == "solana" else _EVM_ADDR_RE


# Solana burn / system addresses that section_f_holders should treat as
# "not a holder" the way 0xdead / 0x0 are treated on EVM. Includes:
#   - 11111111111111111111111111111111  (System Program; common dust sink)
#   - 1nc1nerator11111111111111111111111111111111 (Solana Incinerator program)
_SOLANA_BURN_ADDRS: Final[frozenset[str]] = frozenset({
    "11111111111111111111111111111111",
    "1nc1nerator11111111111111111111111111111111",
})

_EVM_BURN_ADDRS: Final[frozenset[str]] = frozenset({
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
})


def burn_addrs() -> frozenset[str]:
    """Return the set of burn / dust-sink addresses for the active chain.

    section_f_holders subtracts these from top_holders into a dedicated
    burn bucket (v0.7.20.2). The active chain decides which set applies.
    """
    return _SOLANA_BURN_ADDRS if _active_chain == "solana" else _EVM_BURN_ADDRS


# v0.7.20.1: explorer URL templates per chain. Pre-v0.7.20.1 render_report.py
# hardcoded `bscscan.com/address/` in 6 places — a Base PLAY report rendered
# every wallet link to BSCScan (where the wallet does not exist or has
# unrelated activity), making the report useless for cross-checking
# anything off the primary chain. v0.7.20.1 routes the explorer URL by
# the active chain alongside the SQL routing fix.
_EXPLORER_URL_TEMPLATES: Final[dict[str, str]] = {
    "bsc":       "https://bscscan.com/address/{addr}",
    "ethereum":  "https://etherscan.io/address/{addr}",
    "base":      "https://basescan.org/address/{addr}",
    "arbitrum":  "https://arbiscan.io/address/{addr}",
    "polygon":   "https://polygonscan.com/address/{addr}",
    "optimism":  "https://optimistic.etherscan.io/address/{addr}",
    "solana":    "https://solscan.io/account/{addr}",
}

_EXPLORER_NAMES: Final[dict[str, str]] = {
    "bsc":      "BscScan",
    "ethereum": "Etherscan",
    "base":     "BaseScan",
    "arbitrum": "Arbiscan",
    "polygon":  "PolygonScan",
    "optimism": "Optimistic Etherscan",
    "solana":   "Solscan",
}


def explorer_url(addr: str) -> str:
    """Return the explorer URL for `addr` on the currently active chain.

    Use this in render_report.py templates instead of hardcoding
    `https://bscscan.com/address/...`. For Base / Arbitrum / Polygon /
    Optimism / Solana the returned URL points at the corresponding
    public block explorer.
    """
    tpl = _EXPLORER_URL_TEMPLATES.get(_active_chain) or _EXPLORER_URL_TEMPLATES["bsc"]
    return tpl.format(addr=addr)


def explorer_name() -> str:
    """Return the explorer display name for the active chain
    (e.g. 'BaseScan' on Base). Used by i18n strings that reference the
    explorer brand name (e.g. 'View on BaseScan')."""
    return _EXPLORER_NAMES.get(_active_chain) or _EXPLORER_NAMES["bsc"]
