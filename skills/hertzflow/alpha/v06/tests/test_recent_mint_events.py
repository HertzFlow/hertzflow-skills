"""test_recent_mint_events.py — v1.2.14 (product spec 2026-07-01, TAC): recent MINT-event
detection (fresh supply from 0x0) + its 一屏结论 / 速读 dimension. Grounded in the TAC
case: a 164.2M-token mint on 2026-06-29 (317 tx) — the pump source — was invisible
because mint_authorities carries no timestamp."""
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
from recent_mint_events import detect_recent_mint_events, _to_iso_date  # noqa: E402
from screen_summary import _dim_recent_mint  # noqa: E402

_TODAY = date(2026, 7, 2)


def _run(rows):
    return detect_recent_mint_events(
        ca="0x" + "12" * 20, circ_supply=4_677_000_000.0,
        recent_window_days=14, min_pct_circ=1.0, today=_TODAY,
        run_sql=lambda _sql: {"data": rows})


def test_recent_significant_mint_flagged_with_timestamp():
    # TAC shape: 6/29 = 164M (3.5% circ, recent) + two older big mints outside window.
    r = _run([
        {"d": "2026-06-29", "minted": 164_248_660, "n_tx": 317},
        {"d": "2026-05-08", "minted": 392_975_686, "n_tx": 21},
        {"d": "2026-05-01", "minted": 122_470_191, "n_tx": 31},
        {"d": "2026-07-01", "minted": 6_038_562, "n_tx": 96},  # <1% circ → not significant
    ])
    assert r["has_recent_significant_mint"] is True
    top = r["top_recent_mint"]
    assert top["date"] == "2026-06-29"
    assert top["days_ago"] == 3
    assert round(top["pct_circ"], 2) == 3.51
    # 3 significant days total (6/29, 5/08, 5/01); the 7/01 6M is below 1% → excluded
    assert len(r["significant_mints"]) == 3


def test_headline_is_largest_RECENT_not_largest_overall():
    # 5/08 (392M) is bigger but 55d old (outside 14d window); the headline must be the
    # recent 6/29, not the older-but-larger 5/08.
    r = _run([
        {"d": "2026-06-29", "minted": 164_248_660, "n_tx": 317},
        {"d": "2026-05-08", "minted": 392_975_686, "n_tx": 21},
    ])
    assert r["top_recent_mint"]["date"] == "2026-06-29"


def test_no_recent_mint_when_all_old_or_small():
    # all significant mints are outside the recent window → no headline.
    r = _run([
        {"d": "2026-05-08", "minted": 392_975_686, "n_tx": 21},
        {"d": "2026-07-01", "minted": 100_000, "n_tx": 5},  # recent but tiny (<1%)
    ])
    assert r["has_recent_significant_mint"] is False
    assert _dim_recent_mint(r) is None


def test_dim_fires_and_reads_as_ammo_not_bare_pump_claim():
    r = _run([{"d": "2026-06-29", "minted": 164_248_660, "n_tx": 317}])
    dim = _dim_recent_mint(r)
    assert dim is not None and dim["_state"] == "RECENT_MINT"
    assert "2026-06-29" in dim["evidence"]
    assert "3.51" in dim["evidence"]
    # honest framing: not a bare causal claim — must ask to corroborate
    assert "核实" in dim["evidence"] or "corrob" in dim["evidence"].lower()


def test_dim_none_on_error_or_empty():
    assert _dim_recent_mint(None) is None
    assert _dim_recent_mint({"_error": "surf down"}) is None
    assert _dim_recent_mint({"has_recent_significant_mint": False}) is None


def test_zero_circ_supply_never_flags():
    # circ=0 → floor is +inf → nothing significant → no headline (no div-by-zero).
    r = detect_recent_mint_events(
        ca="0x" + "12" * 20, circ_supply=0.0, today=_TODAY,
        run_sql=lambda _sql: {"data": [{"d": "2026-06-29", "minted": 1e9, "n_tx": 5}]})
    assert r["has_recent_significant_mint"] is False


def test_surf_error_paths_are_soft():
    assert detect_recent_mint_events(
        ca="0xabc", circ_supply=1e9, today=_TODAY,
        run_sql=lambda _sql: None)["_error"] == "surf_no_doc"


def test_to_iso_date_handles_unix_and_string():
    # surf may return toDate() as unix-seconds int OR a YYYY-MM-DD string.
    assert _to_iso_date("2026-06-29") == "2026-06-29"
    assert _to_iso_date(1782691200) == "2026-06-29"  # unix seconds for that date
    assert _to_iso_date(None) is None
