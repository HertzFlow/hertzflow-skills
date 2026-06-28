"""test_supply_chain_smoke.py — END-TO-END code-path smoke test for the
multi-chain 真实派发 (chip three-way) computation.

WHY THIS EXISTS
===============
v1.2.2 shipped a CRITICAL regression that NO unit test and NO adversarial review diff-review
caught: the supply_chain operator filter bound a local `_lbl = r.get("arkham_label")`
that shadowed the `_lbl(addr)` holder-label CLOSURE used later in the same function.
When a pre-launch receiver had no Arkham label (`_lbl = None`), the later
`_lbl(addr)` call raised `'NoneType' object is not callable` and the ENTIRE chip
three-way failed (operator/relay/non_op = None) on every multi-chain mirror token.

It only surfaced when a FULL pipeline was run against a real mirror token — exactly
the integration step that was skipped. This test runs `_compute_inner` end-to-end on
fixtures with every surf / RPC boundary mocked, so the whole classification +
bucketing code path executes deterministically, offline, with zero credits. Any
NameError / TypeError / shadowing bug in that path now fails CI instead of shipping.

The fixtures deliberately include:
  - a pre-launch receiver with `arkham_label=None`  → the exact crash trigger,
  - a CEX hot wallet (must land in relay),
  - a DEX liquidity pool (must land in relay, not non-operator — v1.2.3 decision),
  - unlabeled retail holders (non-operator).
"""
import sys
from pathlib import Path

import pytest

_HELPERS = Path(__file__).parent.parent / "helpers"
sys.path.insert(0, str(_HELPERS))

import supply_chain_overhang as sco  # noqa: E402

# 40-hex addresses (lowercase, as the pipeline normalises them)
_DEPLOYER = "0x" + "de" * 20
_OP = "0x" + "a1" * 20          # operator receiver — NO arkham label (crash trigger)
_CEX = "0x" + "b2" * 20         # CEX hot wallet → relay
_DEX = "0x" + "c3" * 20         # DEX liquidity pool → relay (v1.2.3)
_RETAIL1 = "0x" + "d4" * 20     # unlabeled retail → non-operator
_RETAIL2 = "0x" + "e5" * 20     # unlabeled retail → non-operator

_HOLDERS = [
    (_OP, 50_000_000.0),
    (_CEX, 20_000_000.0),
    (_DEX, 16_000_000.0),
    (_RETAIL1, 8_000_000.0),
    (_RETAIL2, 6_000_000.0),
]
_CIRC = 100_000_000.0

_LABELS = {
    _CEX: {"classification": "CEX_HOT_WALLET", "label": "Bitget | Hot Wallet",
           "entity_name": "Bitget"},
    _DEX: {"classification": "DEX_POOL", "label": "V3 Pool", "entity_name": None},
    # _OP / retail are intentionally UNLABELED (operator is found via rule_11)
}

# rule_11 result with a receiver that carries NO arkham label — the precise input
# that shadowed `_lbl` to None and crashed _compute_inner in v1.2.2.
_R11 = {
    "deployer": _DEPLOYER,
    "pre_launch_receivers": [
        {"addr": _OP, "arkham_label": None},                      # ← crash trigger
        {"addr": _CEX, "arkham_label": "Bitget | Hot Wallet", "is_cex_custody": True},
    ],
    "dumper_destinations": {},
}

_CONTRACTS = {_DEX}  # only the pool is a contract; EOAs are not

_SPLIT = {
    "split": True, "supply_prefix": "base", "supply_ca": "0x" + "f6" * 20,
    "supply_pct_of_total": 97.3, "alpha_prefix": "bsc", "supply_chain_label": "Base",
}


@pytest.fixture
def _mocked(monkeypatch):
    """Mock every surf / RPC boundary so _compute_inner runs offline on fixtures."""
    import surf_labels_probe
    import funding_source_attribution
    import wallet_cluster_graph_detector
    import rule_11_backward_trace
    import primary_sale_attribution

    monkeypatch.setattr(sco, "_fetch_supply_holders", lambda *a, **k: list(_HOLDERS))
    # primary-sale attribution runs its own surf sweep — mock it out (its own tests
    # cover it); here we only exercise the chip-three-way code path.
    monkeypatch.setattr(primary_sale_attribution, "detect_primary_sale_pools",
                        lambda *a, **k: [])
    monkeypatch.setattr(primary_sale_attribution, "enrich_with_social",
                        lambda *a, **k: {})
    monkeypatch.setattr(surf_labels_probe, "resolve_labels", lambda addrs: dict(_LABELS))
    monkeypatch.setattr(funding_source_attribution, "discover_mint_authorities",
                        lambda *a, **k: {"authorities": []})
    monkeypatch.setattr(wallet_cluster_graph_detector, "discover_wallet_cluster_graph",
                        lambda *a, **k: {"clusters": [], "summary": {}})
    monkeypatch.setattr(rule_11_backward_trace, "run_backward_trace",
                        lambda *a, **k: dict(_R11))
    # both genesis-distribution walks (BFS + forward) hit surf — stub them: the
    # operator set then comes purely from rule_11 + labels, which is all the
    # chip-three-way code path needs to exercise.
    monkeypatch.setattr(sco, "_trace_operator_distribution",
                        lambda *a, **k: (set(), 0))
    monkeypatch.setattr(sco, "_trace_operator_forward",
                        lambda prefix, ca, initial_seed, *a, **k: (set(initial_seed), 0))
    monkeypatch.setattr(sco, "_is_contract",
                        lambda prefix, addr, cache: addr.lower() in _CONTRACTS)


def _run():
    return sco._compute_inner(
        prefix="base", supply_ca=_SPLIT["supply_ca"], split=_SPLIT,
        total_supply=_CIRC, circulating_supply=_CIRC, date_floor="2025-06-26",
        alpha_listing_date="2026-06-17", deployer_addr=_DEPLOYER, symbol="TEST",
    )


def test_chip_three_way_does_not_crash(_mocked):
    """The regression guard: a None-label receiver must NOT crash the computation."""
    res = _run()
    assert "_error" not in res, res.get("_error")
    for k in ("operator_pct", "relay_pct", "non_operator_pct"):
        assert res.get(k) is not None, f"{k} is None — chip three-way failed"


def test_buckets_sum_to_100(_mocked):
    res = _run()
    total = res["operator_pct"] + res["relay_pct"] + res["non_operator_pct"]
    assert abs(total - 100.0) < 1.5, f"buckets sum to {total}, expected ~100"


def test_cex_and_dex_pool_land_in_relay(_mocked):
    """CEX hot wallet AND DEX liquidity pool are both neutral relay (v1.2.3),
    so neither is counted as verifiable non-operator sell-pressure."""
    res = _run()
    rows = {(r.get("addr") or "").lower(): r for r in res.get("classified_rows") or []}
    assert rows.get(_CEX, {}).get("bucket") == "relay", rows.get(_CEX)
    assert rows.get(_DEX, {}).get("bucket") == "relay", rows.get(_DEX)
    # the relay bucket must carry real weight (CEX 20% + DEX 16% of circulating)
    assert res["relay_pct"] >= 30.0, res["relay_pct"]


if __name__ == "__main__":
    import traceback

    class _MP:
        def setattr(self, o, n, v): setattr(o, n, v)
    mp = _MP()
    # minimal manual run (no pytest)
    import surf_labels_probe, funding_source_attribution
    import wallet_cluster_graph_detector, rule_11_backward_trace
    sco._fetch_supply_holders = lambda *a, **k: list(_HOLDERS)
    surf_labels_probe.resolve_labels = lambda addrs: dict(_LABELS)
    funding_source_attribution.discover_mint_authorities = lambda *a, **k: {"authorities": []}
    wallet_cluster_graph_detector.discover_wallet_cluster_graph = lambda *a, **k: {"clusters": [], "summary": {}}
    rule_11_backward_trace.run_backward_trace = lambda *a, **k: dict(_R11)
    sco._trace_operator_forward = lambda prefix, ca, initial_seed, *a, **k: (set(initial_seed), 0)
    sco._is_contract = lambda prefix, addr, cache: addr.lower() in _CONTRACTS
    try:
        r = _run()
        print("operator/relay/non_op =", r.get("operator_pct"), r.get("relay_pct"),
              r.get("non_operator_pct"), "| error:", r.get("_error"))
    except Exception:
        traceback.print_exc()
