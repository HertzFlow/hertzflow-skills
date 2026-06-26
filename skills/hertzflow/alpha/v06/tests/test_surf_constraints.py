"""test_surf_constraints — v0.9.1 surf 365-day window guard tests.

Defensive: these tests pin down the two-layer protection against the
SIREN-class silent-data-loss bug (dump_tracker reports $0 sellout while
the chain shows $45.7M; root cause: surf rejects block_date queries
beyond 365 days; pipeline section silently consumes the INVALID_REQUEST).

Layer 1 (source clamp) — `surf_safe_date_floor()` returns a date string
guaranteed within surf's 364-day safe window.

Layer 2 (runtime guard) — `_check_surf_365_day_window()` in
parallel_surf scans every outgoing SQL payload for block_date violations
against large surf tables and refuses to dispatch the query.
"""
from __future__ import annotations

import json
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

_HELPERS = Path(__file__).parent.parent / "helpers"
sys.path.insert(0, str(_HELPERS))


# ---------- Layer 1: surf_safe_date_floor ----------

def test_surf_safe_date_floor_clamps_old_token():
    from surf_constraints import surf_safe_date_floor, surf_earliest_date_floor
    # SIREN-style 480-day-old listing.
    old_date = (date.today() - timedelta(days=480)).isoformat()
    clamped = surf_safe_date_floor(old_date)
    assert clamped == surf_earliest_date_floor()
    # Verify the clamped date is within surf's window.
    assert date.fromisoformat(clamped) >= date.today() - timedelta(days=364)


def test_surf_safe_date_floor_passes_recent_token():
    from surf_constraints import surf_safe_date_floor
    # JCT-style ~190-day-old listing — within window, return as-is.
    recent_date = (date.today() - timedelta(days=190)).isoformat()
    assert surf_safe_date_floor(recent_date) == recent_date


def test_surf_safe_date_floor_handles_none():
    from surf_constraints import surf_safe_date_floor, surf_earliest_date_floor
    # No listing_date — falls back to the safe floor (not the legacy
    # "2020-01-01" fallback, which would itself violate the limit).
    assert surf_safe_date_floor(None) == surf_earliest_date_floor()


def test_surf_safe_date_floor_handles_today():
    from surf_constraints import surf_safe_date_floor
    today_str = date.today().isoformat()
    assert surf_safe_date_floor(today_str) == today_str


# ---------- Layer 2: parallel_surf runtime guard ----------

def _make_payload(sql: str) -> str:
    return json.dumps({"sql": sql, "max_rows": 100})


def test_guard_rejects_old_block_date_against_large_table():
    from parallel_surf import _check_surf_365_day_window
    old = (date.today() - timedelta(days=400)).isoformat()
    sql = (
        f"SELECT * FROM agent.bsc_transfers WHERE block_date >= '{old}' LIMIT 1"
    )
    payload = _make_payload(sql)
    err = _check_surf_365_day_window(payload, "/tmp/test.sql")
    assert err is not None
    assert "365-day window guard" in err["error"]["message"]
    assert "surf_safe_date_floor" in err["error"]["message"]


def test_guard_rejects_old_block_date_against_bsc_dex_trades():
    from parallel_surf import _check_surf_365_day_window
    old = (date.today() - timedelta(days=500)).isoformat()
    sql = (
        f"SELECT * FROM agent.bsc_dex_trades WHERE block_date >= '{old}'"
    )
    err = _check_surf_365_day_window(_make_payload(sql), "/tmp/test.sql")
    assert err is not None


def test_guard_accepts_recent_block_date():
    from parallel_surf import _check_surf_365_day_window
    recent = (date.today() - timedelta(days=300)).isoformat()
    sql = (
        f"SELECT * FROM agent.bsc_transfers WHERE block_date >= '{recent}'"
    )
    err = _check_surf_365_day_window(_make_payload(sql), "/tmp/test.sql")
    assert err is None


def test_guard_accepts_today_minus_n_within_window():
    from parallel_surf import _check_surf_365_day_window
    sql = "SELECT * FROM agent.bsc_transfers WHERE block_date >= today() - 30"
    err = _check_surf_365_day_window(_make_payload(sql), "/tmp/test.sql")
    assert err is None


def test_guard_rejects_today_minus_n_exceeding_window():
    from parallel_surf import _check_surf_365_day_window
    sql = "SELECT * FROM agent.bsc_transfers WHERE block_date >= today() - 400"
    err = _check_surf_365_day_window(_make_payload(sql), "/tmp/test.sql")
    assert err is not None
    assert "exceeds the 364-day safe floor" in err["error"]["message"]


def test_guard_skips_when_no_large_table_in_sql():
    """Queries against small tables (e.g. wallet labels) aren't subject to
    the 365-day rule — guard must not false-positive."""
    from parallel_surf import _check_surf_365_day_window
    old = (date.today() - timedelta(days=800)).isoformat()
    sql = (
        f"SELECT * FROM agent.some_small_table WHERE block_date >= '{old}'"
    )
    err = _check_surf_365_day_window(_make_payload(sql), "/tmp/test.sql")
    assert err is None


def test_guard_handles_non_json_payload():
    """Older code may send raw SQL strings — guard must not blow up,
    just defer to the surf server's own validation."""
    from parallel_surf import _check_surf_365_day_window
    err = _check_surf_365_day_window("SELECT 1", "/tmp/test.sql")
    assert err is None  # Permissive fallback.


def test_guard_covers_all_supported_evm_chains():
    """All 6 surf-SQL-covered EVM chains (BSC + Ethereum + Arbitrum +
    Base + Polygon + Optimism) are subject to the 365-day rule."""
    from parallel_surf import _check_surf_365_day_window
    old = (date.today() - timedelta(days=500)).isoformat()
    for chain in ("bsc", "ethereum", "arbitrum", "base", "polygon", "optimism"):
        for table in (f"{chain}_transfers", f"{chain}_dex_trades"):
            sql = (
                f"SELECT * FROM agent.{table} WHERE block_date >= '{old}'"
            )
            err = _check_surf_365_day_window(_make_payload(sql), "/tmp/test.sql")
            assert err is not None, f"guard missed {table}"
