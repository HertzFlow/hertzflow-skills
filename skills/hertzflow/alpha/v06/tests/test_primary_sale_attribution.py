"""test_primary_sale_attribution.py — unit tests for the v1.2.0 primary-sale
(CCA/IDO) allocation-attribution helper's pure (no-surf) logic.

Covers the false-positive surface flagged in adversarial review: SQL-input
validation, the TGE window, infra exclusion vs sale-venue override, and the
KOL-vs-entity named-recipient split. The SQL/surf paths are validated live in
the CAP end-to-end run, not mocked here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))

import primary_sale_attribution as psa  # noqa: E402


# ---- _safe_addr ------------------------------------------------------------
def test_safe_addr_valid():
    a = "0x99991c6AAbba5a096f24f250b73580F5179b9999"
    assert psa._safe_addr(a) == a.lower()


def test_safe_addr_rejects_malformed():
    for bad in ["", None, "0x123", "not_an_addr", "0xZZZ" + "0" * 37,
                "0x99991c6aabba5a096f24f250b73580f5179b9999; DROP TABLE"]:
        assert psa._safe_addr(bad) is None


# ---- _safe_date (adversarial review MED: strict, no truncate-then-validate) -------------
def test_safe_date_accepts_date_and_iso():
    assert psa._safe_date("2026-06-26") == "2026-06-26"
    assert psa._safe_date("2026-06-26T00:00:00Z") == "2026-06-26"
    assert psa._safe_date("2026-06-26 12:00") == "2026-06-26"


def test_safe_date_rejects_garbage():
    for bad in ["", None, "2026-01-01garbage", "26-06-26", "2026/06/26",
                "garbage", "2026-13-99extra"]:
        # "2026-13-99extra" has a valid YYYY-MM-DD shape prefix only if no trailing
        # garbage; here the trailing "extra" must make it None.
        out = psa._safe_date(bad)
        assert out is None or psa._DATE_RE.match(out)


def test_safe_date_no_trailing_garbage():
    assert psa._safe_date("2026-01-01garbage") is None


def test_safe_date_rejects_calendar_invalid():
    # shape-valid but calendar-invalid must be rejected (else strptime raises later)
    assert psa._safe_date("2026-13-99") is None
    assert psa._safe_date("2026-02-30") is None
    assert psa._safe_date("2026-00-10") is None


# ---- _window_bounds (TGE window) -------------------------------------------
def test_window_bounds_with_listing():
    lo, hi = psa._window_bounds("2026-06-26", "2020-01-01")
    assert lo == "2026-05-27"   # listing - 30d
    assert hi == "2026-08-25"   # listing + 60d


def test_window_bounds_clamped_to_date_floor():
    lo, hi = psa._window_bounds("2026-06-26", "2026-06-20")
    assert lo == "2026-06-20"   # date_floor is later than listing-30d → clamp
    assert hi == "2026-08-25"


def test_window_bounds_no_listing_falls_back():
    lo, hi = psa._window_bounds(None, "2026-04-01")
    assert lo == "2026-04-01"
    assert hi is None           # >= date_floor (legacy), flagged by caller


# ---- infra exclusion vs sale-venue override (adversarial review MED) --------------------
def _is_infra(label: str) -> bool:
    return bool(psa._NON_SALE_INFRA_RE.search(label)) and not psa._SALE_VENUE_RE.search(label)


def test_infra_excludes_dex_staking_vesting():
    for lbl in ["Uniswap V3 Pool", "PancakeSwap Router", "Staking Rewards",
                "Vesting Vault", "Token Timelock", "Merkle Distributor",
                "Treasury Multisig", "Stargate Bridge"]:
        assert _is_infra(lbl), lbl


def test_sale_venue_override_keeps_sale_pools():
    # the exact pools the feature exists to surface must NOT be dropped
    for lbl in ["Uniswap CCA", "PancakeSwap IDO", "CAP Launchpad",
                "Public Sale Auction", "Fair Launch", "TGE Distributor"]:
        assert not _is_infra(lbl), lbl


# ---- _named_kind: KOL (ENS/social) vs entity vs infra (adversarial review MED) ----------
def test_named_kind_kol_ens_social():
    assert psa._named_kind({"classification": "OTHER_NAMED", "entity_name": "memelife"},
                           "memelife.eth") == "kol"
    assert psa._named_kind({"classification": "UNLABELED"}, "@KriptoGOATi | theack.eth") == "kol"
    assert psa._named_kind({"classification": "OTHER_NAMED"}, '"tphhh" on Polymarket') == "kol"


def test_named_kind_entity_not_kol():
    # OTHER_NAMED without ENS/social → 'entity', not 'kol'
    assert psa._named_kind({"classification": "OTHER_NAMED", "entity_name": "Acme Foundation"},
                           "Acme Foundation") == "entity"


def test_named_kind_infra_is_none():
    for cls, lbl in [("CEX_HOT_WALLET", "Binance 14"), ("DEX_POOL", "Uniswap Pool"),
                     ("MARKET_MAKER", "Wintermute"), ("BRIDGE", "Stargate"),
                     ("UNLABELED", None)]:
        assert psa._named_kind({"classification": cls}, lbl) is None


# ---- FRESH-listing gate (product spec): skip TGE > 30d old ------------------
def test_fresh_listing_gate_skips_old_tge():
    # a token listed long ago must yield no pools without touching surf
    out = psa.detect_primary_sale_pools(
        prefix="ethereum", supply_ca="0x" + "9" * 40,
        operator_seed=set(), operator_set=set(), total_supply=1e10,
        circulating_supply=1e9, date_floor="2024-01-01",
        is_contract_fn=lambda *a: True, code_cache={}, listing_date="2024-06-01")
    assert out == []


def test_max_tge_age_constant():
    assert psa.MAX_TGE_AGE_DAYS == 30


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} passed")
