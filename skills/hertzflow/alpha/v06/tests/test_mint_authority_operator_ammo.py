"""test_mint_authority_operator_ammo.py — 做死 (product spec 2026-07-01, TAC).

A mint-authority WALLET balance is already-minted, dumpable operator ammo — NOT
"unminted reserve". A wallet balance is by definition minted; unminted reserve =
mint-cap − minted and is never a wallet balance. Routing mint authorities into the
vest/skip bucket HID the operator's stash:

  TAC (2026-07-01): 8 mint authorities held 326.6M = 42% of BSC supply in
  ~38-45M near-equal chunks. The chip skipped them as "vesting/未释放" → reported
  "🟢 分散 / 100% 非庄家". The real picture is 🟣 高控盘 (91.6% operator).

This test FAILS CI if that concealment class reappears, so the process can't be
re-broken:
  1. a mint-authority held balance MUST count as operator (not vest-skip),
  2. an unlabelled top holder ≥ 1% of circulating is an operator-suspect whale
     (not verifiable dispersed retail); DEX/CEX neutral infra is never a whale,
  3. render_report.py must route mint authorities to the operator union, never to
     _vest_set_ns (parity with screen_summary._compute_chip_3way).
"""
import re
from pathlib import Path

import sys

_V06 = Path(__file__).parent.parent
sys.path.insert(0, str(_V06 / "helpers"))

from screen_summary import (  # noqa: E402
    _compute_chip_3way,
    _dim_chip_struct,
)


def _mint_auth_skel(mint_bal: float, retail_bal: float, circ: float) -> dict:
    """A token whose top holders are one mint authority + one small retail wallet.
    No m6 lineage, no monitoring roles — the mint authority is ONLY discoverable
    via funding_attribution.mint_authorities (the exact TAC shape)."""
    return {
        "meta": {
            "primary_chain": "binance-smart-chain",
            "circulating_supply": circ,
            "chain_lp_realtime": {
                "binance-smart-chain": {
                    "top_holders_classified": {
                        "unclassified": {"top": [
                            {"addr": "0xmint", "balance": mint_bal},
                            {"addr": "0xsmall", "balance": retail_bal},
                        ]},
                    }
                }
            },
        },
        "funding_attribution": {
            "mint_authorities": {"authorities": [
                {"addr": "0xmint", "total_minted": mint_bal, "is_excluded": False},
            ]},
        },
        "monitoring_wallets": [],
    }


def test_mint_authority_balance_is_operator_not_vest():
    # mint authority holds 900 of 1000 circ; small retail 10 (1% of circ, at floor)
    skel = _mint_auth_skel(mint_bal=900.0, retail_bal=10.0, circ=1000.0)
    out: dict = {}
    op, cex, retail, circ = _compute_chip_3way(skel, out=out)
    # the mint-authority 900 MUST be operator, NOT dropped as vesting
    assert op >= 90.0, f"mint-authority balance not counted as operator: op={op}"
    assert out["n_mint_op"] == 1
    assert out["mint_op_tokens"] == 900.0
    # and the headline must be HIGH (🟣 高控盘) — never DISPERSED
    dim = _dim_chip_struct(op, cex, retail, chip_extra=out)
    assert dim["_state"] == "HIGH", dim


def test_mint_authority_only_token_never_reports_dispersed():
    """The exact TAC regression: a token whose entire float is mint authorities +
    equal-chunk whales must not read as 分散/100% 非庄家."""
    skel = _mint_auth_skel(mint_bal=326.0, retail_bal=88.0, circ=4677.0)
    out: dict = {}
    op, cex, retail, _ = _compute_chip_3way(skel, out=out)
    # 88 ≥ 1% of 4677 (=46.77) → operator-suspect whale; both wallets are operator
    assert retail < 10.0, f"equal-chunk operator wallets leaked to retail: {retail}"
    assert _dim_chip_struct(op, cex, retail, chip_extra=out)["_state"] == "HIGH"


def test_whale_floor_uses_circulating_not_thin_snapshot():
    """An unlabelled holder below 1% of circulating stays retail (honest) — the
    guard keys on circulating supply, so a thin snapshot does not manufacture
    false whales."""
    # holder 30 of circ 10000 → 0.3% < 1% floor → retail, even though it is 75%
    # of the 2-wallet snapshot.
    skel = {
        "meta": {
            "primary_chain": "binance-smart-chain",
            "circulating_supply": 10000.0,
            "chain_lp_realtime": {"binance-smart-chain": {"top_holders_classified": {
                "unclassified": {"top": [
                    {"addr": "0xa", "balance": 30.0},
                    {"addr": "0xb", "balance": 10.0},
                ]},
            }}},
        },
        "monitoring_wallets": [],
    }
    out: dict = {}
    op, cex, retail, _ = _compute_chip_3way(skel, out=out)
    assert out["n_suspect_whales"] == 0, "sub-1%-circulating holder wrongly whaled"
    assert round(retail, 1) == 100.0


def test_neutral_infra_whale_is_never_operator_suspect():
    """A DEX/CEX vault holding ≥ 1% of circulating must NOT be pulled back into
    operator by the whale guard — it was deliberately excluded as neutral infra."""
    skel = {
        "meta": {
            "primary_chain": "binance-smart-chain",
            "circulating_supply": 1000.0,
            "chain_lp_realtime": {"binance-smart-chain": {"top_holders_classified": {
                "lp": {"top": [{"addr": "0xvault", "balance": 980.0,
                                "label_text": "PancakeSwap | Vault"}]},
                "unclassified": {"top": [{"addr": "0xr", "balance": 20.0}]},
            }}},
        },
        "monitoring_wallets": [{"addr_full": "0xVAULT", "monitor_role_enum": "deployer"}],
        "_neutral_infra_addrs": ["0xvault"],
    }
    out: dict = {}
    op, cex, retail, _ = _compute_chip_3way(skel, out=out)
    # the vault (980, ≥1% floor) must NOT be whaled into operator — it stays out
    # of the operator bucket (falls through to retail like any excluded infra).
    # Only 0xr (20 = 2% of circ, unlabelled) is the operator-suspect whale.
    assert out["n_suspect_whales"] == 1, "expected only 0xr to be whaled"
    assert out["suspect_tokens"] == 20.0, "vault balance leaked into the whale set"
    assert round(op, 1) == 2.0, "neutral-infra vault wrongly counted as operator"


# ── 做死: render_report.py must mirror the operator-ammo routing ──────────────

def _render_src() -> str:
    return (_V06 / "render_report.py").read_text(encoding="utf-8")


def _strip(src: str) -> str:
    src = re.sub(r"\{#[\s\S]*?#\}", "", src)  # jinja comments
    return src


def test_render_routes_mint_authorities_to_operator_union_not_vest():
    live = _strip(_render_src())
    # mint authorities must be added to the OPERATOR union
    assert "_op_union_ns.set + [(_auth.addr" in live, (
        "render_report.py no longer routes mint authorities into _op_union_ns — "
        "the operator-ammo fix regressed")
    # and must NOT be added back to the vest/skip set
    assert "_vest_set_ns.set + [(_auth.addr" not in live, (
        "render_report.py re-added mint authorities to _vest_set_ns (vest-skip) — "
        "this is the TAC '100% 非庄家' concealment bug; mint-authority held balance "
        "is operator ammo, not unminted reserve")


def test_render_whale_floor_keys_on_circulating_supply():
    live = _strip(_render_src())
    assert "circulating_supply') or 0) * 0.01" in live, (
        "render whale floor must key on circulating_supply (not a thin snapshot)")
