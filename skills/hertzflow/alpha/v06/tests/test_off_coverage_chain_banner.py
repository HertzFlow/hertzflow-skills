"""test_off_coverage_chain_banner.py — regression for the v1.2.6 mirror-slice fix.

SLX/Solstice 2026-06-29 (3rd recurrence): the token is Solana-canonical with a BSC
Binance-Alpha mirror. v1.0.1's `alpha_chain_authoritative` pins primary_chain to BSC
(correct for SQL routing — Solana has no agent.solana_* tables), but that silently
suppressed the rule-#1 banner (methodology-chain-assumption-trap), which was gated on
`primary_chain != bsc`. So the report read as "BSC native" with no warning that it
only covers a mirror. Fix: detect off-coverage (non-EVM-surf) chains from CoinGecko
platforms INDEPENDENT of primary_chain, and fire a top banner. The verdict still
renders (option A) but is flagged mirror-only.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
from section_a_scope import detect_off_coverage_chains, _FULL_FORENSIC_CG_PLATFORMS  # noqa: E402


def test_solana_canonical_with_bsc_mirror_flags_solana():
    # the exact SLX case: deployed on Solana + BSC → Solana is off-coverage
    assert detect_off_coverage_chains(
        {"solana": "SLXdx", "binance-smart-chain": "0x02b"}) == ["solana"]


def test_all_evm_surf_chains_not_flagged():
    # a token on BSC + ETH (both full-forensic) must NOT trigger the banner
    assert detect_off_coverage_chains(
        {"binance-smart-chain": "0x", "ethereum": "0x"}) == []


def test_native_single_evm_not_flagged():
    assert detect_off_coverage_chains({"base": "0x"}) == []


def test_multiple_off_coverage_sorted():
    assert detect_off_coverage_chains({"solana": "x", "tron": "y"}) == ["solana", "tron"]


def test_empty_platform_key_ignored():
    assert detect_off_coverage_chains({"": "native", "binance-smart-chain": "0x"}) == []


def test_none_and_empty_safe():
    assert detect_off_coverage_chains(None) == []
    assert detect_off_coverage_chains({}) == []


def test_solana_is_not_full_forensic():
    # the whole point: Solana is holder-snapshot only, NOT in the full-forensic set
    assert "solana" not in _FULL_FORENSIC_CG_PLATFORMS
    assert "binance-smart-chain" in _FULL_FORENSIC_CG_PLATFORMS
    assert "ethereum" in _FULL_FORENSIC_CG_PLATFORMS
