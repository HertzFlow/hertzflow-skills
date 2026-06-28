"""test_label_classification.py — regression guard for the v1.2.2 infra-vs-operator
classification fix. A user found a CEX custody wallet ("Binance Wallet") and a DEX
pool ("V3 Pool") mislabeled as 项目方/内幕 in the monitoring list because:
  - classify_label only checked the `label`, ignoring `entity_name` (so a "Binance
    Wallet" entity with a generic "Proxy" label fell to OTHER_NAMED), and
  - a bare "V3 Pool" label (no protocol-name prefix) was not recognized as DEX.
These tests pin the corrected behavior so the same misclassification can't recur.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))

from surf_labels_probe import classify_label, neutral_infra_kind  # noqa: E402


# ---- classify_label: the two reported cases + their inverses ----------------
def test_binance_wallet_entity_is_cex():
    # entity carries the brand, label is a generic proxy → must still be CEX
    assert classify_label("Proxy (EIP-1967 Transparent)", "Binance Wallet", None) == "CEX_HOT_WALLET"


def test_bare_v3_pool_is_dex():
    # "V3 Pool" with no protocol-name prefix is unambiguously a DEX pool
    assert classify_label("V3 Pool", None, None) == "DEX_POOL"
    assert classify_label("V2 Pool", None, None) == "DEX_POOL"
    assert classify_label("Concentrated Liquidity", None, None) == "DEX_POOL"


def test_protocol_named_dex_still_works():
    assert classify_label("PancakeSwap V3 Pool", "PancakeSwap", None) == "DEX_POOL"


def test_bare_brand_not_hidden_as_cex():
    # a bare exchange brand with no custody/wallet/hot keyword must NOT be CEX —
    # otherwise a genuine insider whose label merely says "Binance" gets hidden
    assert classify_label("Binance", "Binance", None) == "OTHER_NAMED"


def test_staking_and_mining_pool_not_dex():
    # bare "Pool" without a DEX protocol must NOT sweep in staking/mining pools
    assert classify_label("Staking Pool", None, None) == "OTHER_NAMED"
    assert classify_label("Mining Pool", None, None) == "OTHER_NAMED"


def test_real_insider_label_kept():
    assert classify_label("Project Operator", "Project Operator", None) == "OTHER_NAMED"


# ---- neutral_infra_kind: CEX/DEX are neutral, lockup is NOT -----------------
def test_neutral_infra_cex_dex():
    assert neutral_infra_kind("Proxy", "Binance Wallet", None) == "cex"
    assert neutral_infra_kind("V3 Pool", None, None) == "dex"


def test_lockup_is_not_neutral_infra():
    # vesting / multisig / treasury are project-CONTROLLED (operator-side), so they
    # must NOT be treated as neutral infra (else a project Safe gets dropped)
    assert neutral_infra_kind("Vesting (Proxy)", None, None) is None
    assert neutral_infra_kind("Gnosis Safe", "Gnosis Safe", None) is None
    assert neutral_infra_kind("Treasury", None, None) is None


def test_plain_insider_not_neutral():
    assert neutral_infra_kind("Some Operator EOA", None, None) is None
    assert neutral_infra_kind(None, None, None) is None


# ---- _receiver_infra_kind: strict label governs, loose flag doesn't hide insiders --
def _rik(r):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from forensic_pipeline import _receiver_infra_kind
    return _receiver_infra_kind(r)


def test_receiver_infra_real_cex_dex():
    assert _rik({"is_cex_custody": True, "arkham_label": "Binance Wallet"}) == "cex"
    assert _rik({"arkham_label": "V3 Pool"}) == "dex"
    assert _rik({"is_dex_infra": True, "arkham_label": "V3 Pool"}) == "dex"


def test_receiver_infra_label_fallback():
    # a receiver whose enrich path left flags unset is judged from the Arkham label
    assert _rik({"arkham_label": "Binance Wallet"}) == "cex"
    assert _rik({"arkham_label": "Operator EOA"}) is None
    assert _rik({"arkham_label": None}) is None


# ---- SOURCE classifier: VC arms + operator vaults must NOT become neutral infra ---
def _cpl(label):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
    from protocol_lockup_detector import classify_protocol_lockup
    return classify_protocol_lockup(arkham_label_text=label, entity_name=label)


def test_source_vc_arm_not_cex():
    # "Binance Labs" / "Coinbase Ventures" carry an exchange brand but are operator-
    # side EARLY INVESTORS — must NOT be classified as neutral CEX custody
    for lbl in ("Binance Labs", "Coinbase Ventures", "OKX Ventures"):
        assert not _cpl(lbl)["is_cex_custody"], lbl


def test_source_real_cex_still_caught():
    for lbl in ("Binance Wallet", "Cold Wallet", "Binance 14", "Bitget Hot Wallet"):
        assert _cpl(lbl)["is_cex_custody"], lbl


def test_source_operator_vault_not_dex():
    # a bare "Vault" with no DeFi protocol is an operator treasury, not DEX/DeFi infra
    assert not _cpl("Team Vault")["is_dex_infra"]
    assert not _cpl("Operator Vault")["is_dex_infra"]


def test_source_defi_vault_is_dex():
    # a vault WITH a yield/DEX protocol name is neutral DeFi infra
    for lbl in ("Yearn Vault", "Beefy Vault", "Gamma Vault", "Arrakis Vault",
                "Pancake Vault"):
        assert _cpl(lbl)["is_dex_infra"], lbl


def test_source_exchange_fund_is_cex():
    # an exchange Insurance / Reserve / SAFU fund IS real CEX custody — the VC-arm
    # exclusion must NOT use a bare "fund" keyword (regression for adversarial review round 8)
    for lbl in ("Binance Insurance Fund", "Binance Reserve Fund",
                "OKX Insurance Fund", "Bybit Insurance Fund"):
        assert _cpl(lbl)["is_cex_custody"], lbl


if __name__ == "__main__":
    import traceback
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    p = 0
    for fn in fns:
        try:
            fn(); p += 1
        except Exception:
            print("FAIL", fn.__name__); traceback.print_exc()
    print(f"{p}/{len(fns)} passed")
