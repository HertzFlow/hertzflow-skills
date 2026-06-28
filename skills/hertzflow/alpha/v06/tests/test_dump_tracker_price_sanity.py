"""test_dump_tracker_price_sanity.py — regression for the v1.2.5 non-18-decimal
USD overflow fix.

SLX (Solstice, 8 decimals) 2026-06-29: surf's dex_trades `amount` is decimal-
adjusted assuming 18 decimals, so for an 8-decimal token the token amount is
mis-scaled by 10^10 → the implied DEX TWAP exploded to $243B/token → the CEX
disposal estimate read $2.7e18. _sane_effective_price bounds the DEX price by the
reliable spot price and falls back to spot when it is decimals-broken.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
from dump_tracker import _sane_effective_price  # noqa: E402


def test_decimals_broken_twap_falls_back_to_spot():
    # SLX: twap $243B/token, spot $0.5715 → must use spot
    assert _sane_effective_price(243_327_828_848.0, 0.5715) == 0.5715


def test_cex_value_is_sane_after_bound():
    px = _sane_effective_price(243_327_828_848.0, 0.5715)
    cex_value = 11_404_965 * px
    assert 1e6 < cex_value < 1e8, cex_value   # ~$6.5M, not $2.7e18


def test_plausible_dex_price_kept():
    # within 100x band → keep the DEX price (legit volatility / clean token)
    assert _sane_effective_price(0.60, 0.5715) == 0.60
    assert _sane_effective_price(5.0, 0.5715) == 5.0     # 8.7x — kept


def test_too_low_dex_price_rejected():
    # <0.01x spot is also decimals-broken (over-scaled) → fall back to spot
    assert _sane_effective_price(1e-9, 0.5715) == 0.5715


def test_no_spot_keeps_dex_price_legacy():
    # no reliable spot → cannot sanity-check, return DEX price unchanged
    assert _sane_effective_price(0.60, None) == 0.60
    assert _sane_effective_price(0.60, 0) == 0.60


def test_no_dex_price_uses_spot():
    assert _sane_effective_price(None, 0.5715) == 0.5715
