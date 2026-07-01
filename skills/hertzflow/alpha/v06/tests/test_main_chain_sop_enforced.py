"""test_main_chain_sop_enforced.py — 做死 (product spec 2026-06-29, TAC).

THE MAIN-CHAIN (主战场) DETERMINATION IS A SINGLE, UN-BYPASSABLE SOURCE OF TRUTH:
`section_a_scope.derive_primary_chain` (surf real-time LP) + `alpha_chain_authoritative`.
An Alpha token IS the BSC market — "Alpha 就是 BSC 链".

NO code may decide the main chain, or fire a "mirror slice / wrong chain / main chain
elsewhere" banner, from CoinGecko `asset_platform` or the CoinGecko platform LIST —
that is issuance metadata, NOT the traded market. TAC 2026-06-29: a coingecko-platform
banner mislabelled BSC (~38× the DEX volume of the TON side: PancakeSwap $7.1M vs
STON.fi $189K) as a "mirror slice", contradicting the skill's own surf-LP SOP.

This test FAILS CI if that class of bypass reappears, so the process can't be
re-broken. If a "real market elsewhere" warning is ever wanted it MUST be volume-based
(compare actual per-chain LP/volume), never metadata-based.
(coingecko_platforms is still allowed for its legit uses: multi-chain SUPPLY discovery
on surf-supported chains + the D2 cross-chain-deployment detector — neither decides
the main chain.)
"""
import json
import re
from pathlib import Path

_V06 = Path(__file__).parent.parent
_CODE_FILES = [
    _V06 / "forensic_pipeline.py",
    _V06 / "render_report.py",
    _V06 / "helpers" / "section_a_scope.py",
    _V06 / "helpers" / "screen_summary.py",
]

# forbidden in LIVE code (comments/docstrings are stripped first): the removed
# coingecko-based main-chain / mirror-slice machinery must never come back.
_FORBIDDEN = ["detect_off_coverage", "off_coverage_chains", "banner_off_coverage",
              "asset_platform"]


def _strip_comments_and_strings(src: str) -> str:
    """Remove Python # comments, Jinja {# #} comments, and triple-quoted blocks so
    the removal-documentation prose (which legitimately names these tokens) does not
    trip the guard — only executable code is checked."""
    src = re.sub(r'"""[\s\S]*?"""', "", src)
    src = re.sub(r"'''[\s\S]*?'''", "", src)
    src = re.sub(r"\{#[\s\S]*?#\}", "", src)          # jinja comments
    out = []
    for line in src.splitlines():
        # drop everything after an unquoted '#' (naive but fine post string-strip)
        h = line.find("#")
        out.append(line if h == -1 else line[:h])
    return "\n".join(out)


def test_no_coingecko_based_main_chain_or_mirror_banner():
    offenders = []
    for f in _CODE_FILES:
        code = _strip_comments_and_strings(f.read_text(encoding="utf-8"))
        for tok in _FORBIDDEN:
            if tok in code:
                offenders.append(f"{f.name}: '{tok}' in live code")
    assert not offenders, (
        "主战场 (main chain) must be decided ONLY by derive_primary_chain (surf LP) + "
        "alpha_chain_authoritative — never from CoinGecko metadata. Forbidden token(s) "
        "reappeared in live code:\n  " + "\n  ".join(offenders))


def test_no_off_coverage_i18n_keys():
    for lang in ("zh.json", "en.json"):
        d = json.loads((_V06 / "lang" / lang).read_text(encoding="utf-8"))
        bad = [k for k in (d.get("report") or {}) if k.startswith("banner_off_coverage")]
        assert not bad, f"{lang}: removed mirror-slice banner i18n key(s) reappeared: {bad}"


def test_derive_primary_chain_is_the_sop():
    # the single sanctioned main-chain function must exist + be importable
    import sys
    sys.path.insert(0, str(_V06 / "helpers"))
    from section_a_scope import derive_primary_chain
    assert callable(derive_primary_chain)
    # and it must be LP-driven: alpha-chain-authoritative when the Alpha chain is
    # surf-routable, else the max-LP surf-supported chain — never a non-surf chain.
    p, why = derive_primary_chain(
        {"binance-smart-chain": {"lp_usd": 2815.0, "surf_supported": True}},
        alpha_chain_id="56")
    assert p == "binance-smart-chain" and why == "alpha_chain_authoritative"
