"""test_chip_structure_data_flow.py — v1.0.2 (H 2026-06-20) regression.

The 一屏「筹码结构」card showed 数据缺失 on an ETH-listed token (H) even though
ETH is fully surf-supported and the detailed sections had data. Root cause: the
chip 3-way classifier (screen_summary._compute_chip_3way) reads holders from
`meta.chain_lp_realtime[primary_chain].top_holders_classified`, a dict keyed by
CoinGecko platform. The pipeline's holder pull was driven by CoinGecko's list,
which (for H) omitted ethereum — so chain_lp_realtime had no 'ethereum' entry,
the classifier read empty, and all 3 buckets came back 0% → MISSING.

These tests pin the data flow: missing primary-chain entry → 0 (the bug), and a
populated primary-chain entry → real percentages (the fix, once _inject_alpha_
chain_platform guarantees the Alpha chain is always pulled).
"""
import sys
from pathlib import Path

_HELPERS = Path(__file__).resolve().parent.parent / "helpers"
sys.path.insert(0, str(_HELPERS))

from screen_summary import (  # noqa: E402
    _compute_chip_3way,
    _dim_chip_struct,
    _is_neutral_infra_label,
    compute_neutral_infra_addrs,
)


def test_neutral_infra_label_matcher():
    """v1.0.5 (ARX): DEX/CEX infra is excluded from operator, but genuine LP
    pools, project/team vaults, and VC arms are NOT (adversarial review R1/R2 precision)."""
    # excluded (neutral infra)
    for lab in ("PancakeSwap | Vault", "Binance Wallet | Proxy (EIP-1967)",
                "1inch Router", "Uniswap V4: PoolManager", "Permit2",
                "Bitfinex: Hot Wallet", "Beefy Vault", "Universal Router",
                "0x: Exchange Proxy", "LiFi Diamond", "Thena Vault",
                "Wombat Vault", "ApeSwap Vault", "Trader Joe Vault",
                "Stargate Router", "Across Protocol"):
        assert _is_neutral_infra_label(lab), lab
    # NOT excluded (real operator / project / LP / VC). The last row is the
    # adversarial review R3 false-positive guard: common project words must not match.
    for lab in ("Cake-LP", "PancakeSwap LPs", "V3 Pool", "Liquidity Pool",
                "Team Vault", "Treasury Vault", "Coinbase Ventures",
                "Binance Labs", "some random deployer", "",
                "Diamond Hands Treasury", "Diamond Capital",
                "Project Diamond Reserve", "AlphaRouter Team", "Socket Capital"):
        assert not _is_neutral_infra_label(lab), lab


def test_chip_excludes_infra_labeled_from_operator():
    """v1.0.5 (ARX 2026-06-22): a PancakeSwap Vault in the 'lp' category +
    flagged role=deployer must NOT count as 项目方可控. surf labelled it; the
    chip now drops it from the operator union. It becomes retail (verifiable
    non-operator), not operator."""
    skel = {
        "meta": {"primary_chain": "bsc", "chain_lp_realtime": {"bsc": {
            "top_holders_classified": {
                "lp": {"top": [{"addr": "0xvault", "balance": 982.0,
                                "label_text": "PancakeSwap | Vault"}]},
                "unclassified": {"top": [{"addr": "0xreal", "balance": 18.0}]},
            }}}},
        "monitoring_wallets": [
            {"addr_full": "0xVAULT", "monitor_role_enum": "deployer"},
        ],
    }
    skel["_neutral_infra_addrs"] = compute_neutral_infra_addrs(skel)
    assert "0xvault" in skel["_neutral_infra_addrs"]
    op, cex, retail, circ = _compute_chip_3way(skel)
    # 982 vault excluded from op despite role=deployer + 'lp' category → retail
    assert op == 0.0
    assert round(retail, 1) == 100.0


def test_chip_real_lp_still_operator():
    """A genuine LP pool ('Cake-LP', no infra-type keyword) still counts as
    project liquidity (operator) — the fix must not over-exclude."""
    skel = {
        "meta": {"primary_chain": "bsc", "chain_lp_realtime": {"bsc": {
            "top_holders_classified": {
                "lp": {"top": [{"addr": "0xlp", "balance": 700.0, "label_text": "Cake-LP"}]},
                "unclassified": {"top": [{"addr": "0xr", "balance": 300.0}]},
            }}}},
        "monitoring_wallets": [],
    }
    skel["_neutral_infra_addrs"] = compute_neutral_infra_addrs(skel)
    assert skel["_neutral_infra_addrs"] == []
    op, cex, retail, circ = _compute_chip_3way(skel)
    assert round(op, 1) == 70.0   # LP stays operator


def test_chip_missing_when_primary_chain_absent_from_chain_lp():
    """The H bug shape: primary_chain='ethereum' but chain_lp_realtime only has
    a (non-surf) hyperliquid key → classifier reads empty → all-zero → MISSING."""
    skel = {
        "meta": {
            "primary_chain": "ethereum",
            "chain_lp_realtime": {
                "hyperliquid": {"top_holders_classified": {}},
            },
        }
    }
    op, cex, retail, circ = _compute_chip_3way(skel)
    assert (op, cex, retail, circ) == (0.0, 0.0, 0.0, 0.0)
    dim = _dim_chip_struct(op, cex, retail)
    assert dim["_state"] == "MISSING"          # 数据缺失


def test_chip_populates_when_primary_chain_present():
    """After _inject_alpha_chain_platform guarantees chain_lp_realtime has the
    Alpha chain, the classifier reads real holders → non-zero buckets → not
    MISSING. Mirrors the live result: surf returns classified ETH holders."""
    skel = {
        "meta": {
            "primary_chain": "ethereum",
            "chain_lp_realtime": {
                "ethereum": {
                    "top_holders_classified": {
                        "cex": {"top": [{"addr": "0xbbb", "balance": 400.0}]},
                        "unclassified": {"top": [{"addr": "0xaaa", "balance": 600.0}]},
                    }
                },
            },
        }
    }
    op, cex, retail, circ = _compute_chip_3way(skel)
    assert circ == 1000.0
    assert cex == 40.0
    assert retail == 60.0
    dim = _dim_chip_struct(op, cex, retail)
    assert dim["_state"] != "MISSING"          # 有数据


def test_chip_reads_annotated_operator_roles():
    """v1.0.4 (O 2026-06-20): _compute_chip_3way's operator union keys on
    monitoring_wallets[].monitor_role_enum — which is only set by
    annotate_monitoring_wallets. If a big holder carries an operator role, it
    must land in the op bucket (高控盘), NOT retail. This is the data half of
    the ordering bug: the headline showed op 0.0% (假分散) only because
    screen_summary ran before the roles were assigned."""
    skel = {
        "meta": {
            "primary_chain": "binance-smart-chain",
            "chain_lp_realtime": {
                "binance-smart-chain": {
                    "top_holders_classified": {
                        "unclassified": {"top": [
                            {"addr": "0xbig", "balance": 8340.0},
                            {"addr": "0xretail", "balance": 1660.0},
                        ]},
                    }
                },
            },
        },
        "monitoring_wallets": [
            {"addr_full": "0xBIG", "monitor_role_enum": "deployer"},
        ],
    }
    op, cex, retail, circ = _compute_chip_3way(skel)
    assert round(op, 1) == 83.4
    assert _dim_chip_struct(op, cex, retail)["_state"] == "HIGH"
    # Same skeleton WITHOUT the role assigned (pre-annotation state) → the bug:
    skel_unannotated = {**skel, "monitoring_wallets": [{"addr_full": "0xBIG"}]}
    op2, _, _, _ = _compute_chip_3way(skel_unannotated)
    assert op2 == 0.0  # this is exactly the 假"分散" the ordering fix prevents


def test_screen_summary_built_after_annotate_in_pipeline():
    """v1.0.4 static guard: in forensic_pipeline.py the build_screen_summary
    call MUST come AFTER annotate_monitoring_wallets, else the chip op_union is
    computed on unannotated monitoring_wallets → headline 假分散 contradicting
    the render-side detailed section. Prevents silent re-ordering regression."""
    src = (_HELPERS.parent / "forensic_pipeline.py").read_text(encoding="utf-8")
    i_annotate = src.find("annotate_monitoring_wallets(skeleton)")
    i_build = src.find("build_screen_summary(skeleton)")
    assert i_annotate != -1 and i_build != -1
    assert i_build > i_annotate, (
        "build_screen_summary must run AFTER annotate_monitoring_wallets "
        "(monitor_role_enum drives the chip operator union)"
    )


def test_chip_degraded_to_missing_when_annotation_failed():
    """v1.0.4 (adversarial review finding 1): if annotate_monitoring_wallets failed
    (monitoring_summary._error set), monitor_role_enum is absent → op_union
    would be falsely empty → misleading 分散. Must degrade to MISSING instead."""
    skel = {
        "monitoring_summary": {"_error": "boom"},
        "meta": {
            "primary_chain": "bsc",
            "chain_lp_realtime": {"bsc": {"top_holders_classified": {
                "unclassified": {"top": [{"addr": "0xa", "balance": 1000.0}]},
            }}},
        },
    }
    assert _compute_chip_3way(skel) == (0.0, 0.0, 0.0, 0.0)
    assert _dim_chip_struct(0.0, 0.0, 0.0)["_state"] == "MISSING"


def test_chip_fanout_tail_overlap_not_double_counted():
    """v1.0.4 (adversarial review finding 2): a CEX-fanout recipient that ALSO appears in
    top-100 must not be counted twice. fanout_net is added only for the portion
    held OUTSIDE top-100 (net minus in-top-100 overlap), mirroring render."""
    skel = {
        "meta": {"primary_chain": "bsc", "chain_lp_realtime": {"bsc": {
            "top_holders_classified": {"unclassified": {"top": [
                {"addr": "0xf", "balance": 1000.0},  # fanout recipient, in top-100
            ]}},
        }}},
        "monitoring_wallets": [],
        "funding_attribution": {"cex_fanout_hubs": {
            "hubs": [{"_net_structured_recipient_addrs_raw": ["0xf"]}],
            "summary": {"net_structured_fanout_tokens_total": 1000.0},
        }},
    }
    op, cex, retail, circ = _compute_chip_3way(skel)
    # fanout_net 1000 fully overlaps the 1000 already in top-100 → tail 0 → no
    # double count. 0xf isn't in op_union so it's retail.
    assert circ == 1000.0 and retail == 100.0 and op == 0.0


def test_chip_cluster_tail_uses_correct_field():
    """v1.0.4 (adversarial review finding 3): cluster tail must read
    'cluster_balance_total_tokens' (the field the skeleton emits), not the
    stale 'total_balance'. An off-top-100 cluster balance counts as operator."""
    skel = {
        "meta": {"primary_chain": "bsc", "chain_lp_realtime": {"bsc": {
            "top_holders_classified": {"unclassified": {"top": [
                {"addr": "0xr", "balance": 400.0},
            ]}},
        }}},
        "monitoring_wallets": [],
        "wallet_cluster_graph": {"clusters": [
            {"addrs": ["0xc"], "cluster_balance_total_tokens": 600.0},  # off top-100
        ]},
    }
    op, cex, retail, circ = _compute_chip_3way(skel)
    assert circ == 1000.0 and round(op, 1) == 60.0 and round(retail, 1) == 40.0


def test_chip_operator_bucket_drives_high_state():
    """Operator-controlled holders (via op_union from monitoring_wallets) land
    in the op bucket and drive the HIGH 控盘 verdict."""
    skel = {
        "meta": {
            "primary_chain": "base",
            "chain_lp_realtime": {
                "base": {
                    "top_holders_classified": {
                        "unclassified": {
                            "top": [
                                {"addr": "0xop", "balance": 800.0},
                                {"addr": "0xretail", "balance": 200.0},
                            ]
                        },
                    }
                },
            },
        },
        "monitoring_wallets": [
            {"addr_full": "0xOP", "monitor_role_enum": "high_throughput_dumper"},
        ],
    }
    op, cex, retail, circ = _compute_chip_3way(skel)
    assert op == 80.0
    assert retail == 20.0
    assert _dim_chip_struct(op, cex, retail)["_state"] == "HIGH"
