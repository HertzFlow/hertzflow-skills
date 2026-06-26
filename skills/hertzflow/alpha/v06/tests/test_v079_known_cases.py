#!/usr/bin/env python3
"""test_v079_known_cases.py — regression test for known-good v0.7.9 invariants.

Each known case (ESPORTS / Solstice) has a fixture under
`tests/fixtures/known_cases/<token>.json` capturing the locked forensic
invariants we expect the pipeline to surface:

- single_chain / primary_chain / primary_chain_derivation
- data_freshness_warning_set
- decision_summary (verdict_enum, entry_size_cap_usd, primary_chain, n_blindspots)
- m6_min_rows + expected_m6_addrs (Rule 11 recursive m6 expansion)
- cross_sym_whales_min + expected_cross_sym_addrs
- wash_infra_setups_min + expected_wash_setups

The fixtures are FROZEN snapshots. A developer manually re-runs the CA
+ confirms invariants after a non-trivial change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "known_cases"


def _load_fixtures():
    return sorted(FIXTURES_DIR.glob("*.json"))


def test_fixtures_exist():
    """Sanity: at least 2 known-case fixtures present."""
    fixtures = _load_fixtures()
    assert len(fixtures) >= 2, (
        f"Expected at least 2 known-case fixtures under {FIXTURES_DIR}, "
        f"found {len(fixtures)}"
    )


@pytest.mark.parametrize("fixture_path", _load_fixtures(), ids=lambda p: p.stem)
def test_fixture_structure(fixture_path):
    """Each fixture must have the v0.7.9 invariant schema."""
    fx = json.loads(fixture_path.read_text(encoding="utf-8"))
    required_keys = {
        "ca", "symbol", "_v079_schema", "_decision_summary",
        "m6_min_rows", "expected_m6_addrs",
        "cross_sym_whales_min", "expected_cross_sym_addrs",
        "wash_infra_setups_min", "expected_wash_setups",
    }
    missing = required_keys - set(fx.keys())
    assert not missing, f"{fixture_path.name} missing keys: {missing}"
    v079 = fx["_v079_schema"]
    assert "single_chain" in v079
    assert "primary_chain" in v079
    ds = fx["_decision_summary"]
    assert "verdict_enum" in ds
    assert "entry_size_cap_usd" in ds
