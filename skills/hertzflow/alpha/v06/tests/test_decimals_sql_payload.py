"""test_decimals_sql_payload.py — v0.9.7 decimals SQL interpolation regression.

adversarial review R2 Category 10: the v0.9.7 batch sed (/1e18 → /{decimals_factor})
left literal placeholders in non-f-string fragments (dump_tracker 5 sites,
funding_source_attribution 2 sites). The existing 267 tests stubbed surf
calls WITHOUT asserting SQL payload content, so the literal-leak bug
passed CI. This file asserts the actual SQL string built by each detector
contains the correct `/1e{decimals}` divisor and NO literal placeholder.

Every detector that scales raw token amounts is covered for both the
18-decimal (default, must produce /1e18 → 0 regression) and 6-decimal
(FOLKS-class, must produce /1e6) cases.
"""
import sys
from pathlib import Path

_HELPERS = Path(__file__).resolve().parent.parent / "helpers"
sys.path.insert(0, str(_HELPERS))

import pytest  # noqa: E402
from chain_router import (  # noqa: E402
    set_token_decimals, set_active_chain, decimals_factor_str,
)


@pytest.fixture(autouse=True)
def _bsc_chain():
    set_active_chain("bsc")
    yield
    set_token_decimals(18)  # restore default after each test


# ----- chain_router primitive -----

def test_decimals_factor_str_18():
    set_token_decimals(18)
    assert decimals_factor_str() == "1e18"


def test_decimals_factor_str_6():
    set_token_decimals(6)
    assert decimals_factor_str() == "1e6"


def test_decimals_factor_str_8():
    set_token_decimals(8)
    assert decimals_factor_str() == "1e8"


def test_set_token_decimals_none_falls_back_18():
    set_token_decimals(None)
    assert decimals_factor_str() == "1e18"


def test_set_token_decimals_garbage_falls_back_18():
    set_token_decimals(999)  # out of 0-30 bound
    assert decimals_factor_str() == "1e18"


# ----- per-detector SQL payload assertions -----

_CA = "0xff7f8f301f7a706e3cfd3d2275f5dc0b9ee8009b"
_ADDR = "0x1111111111111111111111111111111111111111"


def _assert_clean(sql: str, expect_factor: str):
    """SQL must contain the right divisor + zero literal placeholders."""
    assert "{decimals_factor" not in sql, f"literal placeholder leaked: {sql[:200]}"
    assert f"/{expect_factor}" in sql, f"missing /{expect_factor}: {sql[:200]}"


@pytest.mark.parametrize("decimals,factor", [(18, "1e18"), (6, "1e6"), (8, "1e8")])
def test_funding_build_source_sql(decimals, factor):
    set_token_decimals(decimals)
    import funding_source_attribution as F
    sql = F._build_source_sql(
        ca=_CA, high_value_addrs=[_ADDR],
        dex_pair_addrs=[], cex_addrs=[], date_floor="2025-10-01",
    )
    _assert_clean(sql, factor)


@pytest.mark.parametrize("decimals,factor", [(18, "1e18"), (6, "1e6")])
def test_dump_tracker_current_balances_sql(decimals, factor, monkeypatch):
    set_token_decimals(decimals)
    import dump_tracker
    captured = {}

    def _spy(cmd, stdin=None, **kw):
        import json
        captured["sql"] = json.loads(stdin)["sql"]
        return None, "spy-abort"

    import section_a_scope
    monkeypatch.setattr(section_a_scope, "_run_surf_with_retry", _spy)
    dump_tracker.fetch_current_balances(_CA, [_ADDR], "2025-10-01")
    _assert_clean(captured["sql"], factor)


@pytest.mark.parametrize("decimals,factor", [(18, "1e18"), (6, "1e6")])
def test_dump_tracker_apparatus_to_cex_sql(decimals, factor, monkeypatch):
    set_token_decimals(decimals)
    import dump_tracker
    captured = {}

    def _spy(cmd, stdin=None, **kw):
        import json
        captured["sql"] = json.loads(stdin)["sql"]
        return None, "spy-abort"

    import section_a_scope
    monkeypatch.setattr(section_a_scope, "_run_surf_with_retry", _spy)
    # fetch_apparatus_to_cex builds the per-dest GROUP BY SQL (lines 363-372)
    dump_tracker.fetch_apparatus_to_cex(_CA, [_ADDR], "2025-10-01")
    _assert_clean(captured["sql"], factor)


@pytest.mark.parametrize("decimals,factor", [(18, "1e18"), (6, "1e6")])
def test_funding_high_throughput_template(decimals, factor):
    set_token_decimals(decimals)
    import funding_source_attribution as F
    from chain_router import transfers_table
    sql = F._SQL_HIGH_THROUGHPUT.format(
        transfers=transfers_table(), ca_lc=_CA, date_floor="2025-10-01",
        min_throughput=1e6, max_throughput=5e17, max_balance_frac=0.05,
        min_n_tx=1000, top_n=50, decimals_factor=decimals_factor_str(),
    )
    _assert_clean(sql, factor)


@pytest.mark.parametrize("decimals,factor", [(18, "1e18"), (6, "1e6")])
def test_funding_mint_authorities_template(decimals, factor):
    set_token_decimals(decimals)
    import funding_source_attribution as F
    from chain_router import transfers_table
    sql = F._SQL_FIND_MINT_AUTHORITIES.format(
        transfers=transfers_table(), ca_lc=_CA, date_floor="2025-10-01",
        top_n=10, decimals_factor=decimals_factor_str(),
    )
    _assert_clean(sql, factor)
