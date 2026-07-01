"""test_recent_flow_actions.py — v1.2.9 (product spec 2026-06-29): near-72h fan-out /
consolidation detection + its 一屏结论 dimension. Grounded in the JCT/Janction case
(a mint-authority Gnosis Safe fanned out to 50 EOAs in 72h, invisible to cex_fanout)."""
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
from recent_flow_actions import detect_recent_flow_actions  # noqa: E402
from screen_summary import _dim_recent_flow  # noqa: E402

_RENDER = (Path(__file__).parent.parent / "render_report.py").read_text(encoding="utf-8")


def test_tldr_bullet_surfaces_unknown_fanout_medium_tier():
    # v1.2.13 (product spec 2026-07-01, TAC): the 速读摘要 recent-flow bullet must also fire
    # for the 🟠 SUSPECTED_BATCH_DISTRIBUTION medium tier — not only confirmed
    # operator/CEX. Otherwise a reader who scans only the 速读摘要 misses the
    # unknown-hub batch distribution that IS in the 一屏结论 dim table.
    live = re.sub(r"\{#[\s\S]*?#\}", "", _RENDER)  # strip jinja comments
    assert "has_unknown_fanout" in live, (
        "速读摘要 recent-flow bullet no longer gates on has_unknown_fanout — the "
        "medium unknown-hub tier regressed to invisible in the 速读摘要")
    assert "SUSPECTED_BATCH_DISTRIBUTION" in live, (
        "速读摘要 bullet loop no longer includes the SUSPECTED_BATCH_DISTRIBUTION state")

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


def test_small_unknown_fanout_does_not_fire():
    # v1.2.12: a small unknown-hub fan-out (< _UNKNOWN_FANOUT_MEDIUM_MIN=20) stays
    # suppressed — too speculative to surface even as medium.
    assert _dim_recent_flow({"has_operator_fanout": False, "has_cex_consolidation": False,
                             "has_unknown_fanout": True,
                             "top_unknown_fanout": {"kind": "unknown_hub_fanout",
                                                    "n_counterparties": 15,
                                                    "hub": "0x" + "9" * 40,
                                                    "total_tokens": 1000.0}}) is None


def test_large_unknown_fanout_fires_medium_not_confirmed_operator():
    # v1.2.12 (product spec 2026-07-01, TAC): a LARGE unknown-hub batch distribution
    # (≥ 20 wallets) surfaces as a 🟠 疑似批量分发 medium row — NOT suppressed
    # (previously dropped entirely), and NOT presented as confirmed operator.
    dim = _dim_recent_flow({"has_operator_fanout": False, "has_cex_consolidation": False,
                            "has_unknown_fanout": True, "window_days": 3,
                            "top_unknown_fanout": {"kind": "unknown_hub_fanout",
                                                   "n_counterparties": 88,
                                                   "hub": "0xc2eff1f1" + "0" * 32,
                                                   "total_tokens": 807445.0}},
                           circ_supply=4_677_000_000.0)
    assert dim is not None
    assert dim["_state"] == "SUSPECTED_BATCH_DISTRIBUTION"
    # must read as 疑似/unverified, never a confirmed-operator 🔴 label
    assert "🔴" not in dim["label"]
    assert "88" in dim["evidence"]
    # % of circulating shown so a tiny batch (0.017%) is not read as large
    assert "0.017" in dim["evidence"]


def test_unknown_fanout_boundary_at_threshold():
    # exactly _UNKNOWN_FANOUT_MEDIUM_MIN (20) fires; one below (19) does not.
    def _mk(n):
        return {"has_operator_fanout": False, "has_cex_consolidation": False,
                "has_unknown_fanout": True, "window_days": 3,
                "top_unknown_fanout": {"kind": "unknown_hub_fanout", "n_counterparties": n,
                                       "hub": "0x" + "1" * 40, "total_tokens": 10.0}}
    assert _dim_recent_flow(_mk(20)) is not None
    assert _dim_recent_flow(_mk(19)) is None


def test_confirmed_operator_still_outranks_unknown():
    # when a confirmed operator fan-out AND an unknown hub both exist, the row is
    # the 🔴 confirmed-operator one, not the 🟠 unknown medium.
    dim = _dim_recent_flow({"has_operator_fanout": True, "has_cex_consolidation": False,
                            "has_unknown_fanout": True, "window_days": 3,
                            "top_operator_fanout": {"n_counterparties": 12, "hub": "0xop"},
                            "top_unknown_fanout": {"n_counterparties": 88, "hub": "0xunk",
                                                   "total_tokens": 5.0}})
    assert dim["_state"] == "OPERATOR_FANOUT"
