"""test_recent_flow_actions.py — v1.2.9 (product spec 2026-06-29): near-72h fan-out /
consolidation detection + its 一屏结论 dimension. Grounded in the JCT/Janction case
(a mint-authority Gnosis Safe fanned out to 50 EOAs in 72h, invisible to cex_fanout)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
from recent_flow_actions import detect_recent_flow_actions  # noqa: E402
from screen_summary import _dim_recent_flow  # noqa: E402

_MINT = "0x" + "e0" * 20
_WASH = "0x" + "23" * 20
_CEX = "0x" + "73" * 20
_ROUTER = "0x" + "b3" * 20


def _mock(sql):
    if 'DISTINCT "to"' in sql:      # fan-out (from → many to)
        return {"data": [
            {"hub": _WASH, "n_cp": 239, "n_tx": 39592, "total": 1e9},   # wash bot (bidir)
            {"hub": _MINT, "n_cp": 50, "n_tx": 50, "total": 7e9},        # mint auth → 50 EOAs
            {"hub": _CEX, "n_cp": 22, "n_tx": 894, "total": 2e8},        # CEX withdrawals
            {"hub": _ROUTER, "n_cp": 21, "n_tx": 1527, "total": 3e8},    # DEX router
        ]}
    return {"data": [                # consolidation (to ← many from)
        {"hub": _WASH, "n_cp": 108, "n_tx": 39984, "total": 1e9},        # wash bot (bidir)
        {"hub": _CEX, "n_cp": 30, "n_tx": 300, "total": 2e8},            # CEX ← 30 EOAs
    ]}


def _run():
    return detect_recent_flow_actions(
        ca="0xca", operator_addrs={_MINT}, cex_addrs={_CEX}, infra_addrs={_ROUTER},
        run_sql=_mock)


def test_operator_fanout_detected():
    r = _run()
    assert r["has_operator_fanout"] is True
    assert r["top_operator_fanout"]["hub"] == _MINT
    assert r["top_operator_fanout"]["n_counterparties"] == 50


def test_cex_consolidation_detected_not_dropped_as_wash():
    # a CEX is bidirectional by nature — must NOT be excluded as wash-churn
    r = _run()
    assert r["has_cex_consolidation"] is True
    assert r["top_cex_consolidation"]["hub"] == _CEX


def test_bidirectional_unknown_is_wash_churn():
    r = _run()
    kinds = {a["hub"]: a["kind"] for a in r["fanout"] + r["consolidation"]}
    assert kinds[_WASH] == "wash_churn"       # only the pure-unknown bidir bot
    assert kinds[_ROUTER] == "infra_fanout"   # DEX router not a signal


def test_dim_fires_top_priority():
    dim = _dim_recent_flow(_run())
    assert dim is not None
    assert dim["_state"] == "FANOUT_AND_CONSOLIDATION"


def test_dim_none_when_no_signal():
    assert _dim_recent_flow({"has_operator_fanout": False, "has_cex_consolidation": False,
                             "has_unknown_fanout": False}) is None
    assert _dim_recent_flow({"_error": "x"}) is None
    assert _dim_recent_flow(None) is None


def test_unknown_only_does_not_fire_headline():
    # adversarial review HIGH: unknown-hub fan-out alone is too speculative for the top row
    assert _dim_recent_flow({"has_operator_fanout": False, "has_cex_consolidation": False,
                             "has_unknown_fanout": True,
                             "fanout": [{"kind": "unknown_hub_fanout", "n_counterparties": 30,
                                         "hub": "0x" + "9" * 40}]}) is None
