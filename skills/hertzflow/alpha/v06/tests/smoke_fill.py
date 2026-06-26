#!/usr/bin/env python3
"""smoke_fill.py — DEV/CI ONLY. Replace <LLM_NARRATIVE_PLACEHOLDER> in a
skeleton with min-length narrative so pipeline → render E2E paths can be
exercised without a real LLM.

⚠️ NOT FOR PRODUCTION. The output is tagged `_smoke_test_fixture: true`
at top-level and render_report.py REFUSES TO RENDER it (exit 3) unless
the test override env var BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1 is set.
The render also fingerprint-detects NATO suffix stubs even if the flag
is stripped, so manually deleting the flag does not bypass the gate.

Agents producing real forensic reports MUST author narrative directly
into the writable slots of skeleton.json; do not invoke this script as
a production fill step.

Usage (CI / E2E only):
    BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1 \\
        python3 tests/smoke_fill.py <skeleton.json> <out_filled.json>
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

PLACEHOLDER = "<LLM_NARRATIVE_PLACEHOLDER>"

# v0.6.2: smoke fill content sourced from i18n (lang/zh.json + en.json).
# set_lang() before calling main() to use a specific lang; default reads
# from BINANCE_ALPHA_LANG env var or "zh".
sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))
from i18n import t, set_lang  # noqa: E402


def _pick(path: str) -> str:
    norm = re.sub(r"\[\d+\]", "[]", path)
    if path.endswith(".one_liner"):
        return t("smoke_stub.verdict_one_liner")
    if path.endswith(".verdict_impact"):
        return t("smoke_stub.anomaly_verdict_impact")
    if path.endswith(".interpretation"):
        # v0.6.1: per-section variation so V_INTERPRETATION_DUPLICATION passes.
        # Section name kept in source language for grep-ability.
        section_name = path.rsplit(".", 1)[0].split(".")[-1] or "section"
        return f"[{section_name}] " + t("smoke_stub.interpretation")
    if norm.endswith(".monitoring_footer") or path.endswith("monitoring_footer"):
        return t("smoke_stub.monitoring_footer")
    if path.endswith(".hours_ago_text"):
        return t("smoke_stub.hours_ago")
    if path.endswith(".nature"):
        return t("smoke_stub.nature")
    if path.endswith(".status_text"):
        return t("smoke_stub.wave_status")
    if path.endswith(".detail") and "rhythm" in path:
        return t("smoke_stub.detector_detail_rhythm")
    if path.endswith(".detail"):
        return t("smoke_stub.detector_detail")
    if norm.endswith(".rhythm.title"):
        return t("smoke_stub.rhythm_title")
    if "key_takeaways[]" in norm:
        return t("smoke_stub.key_takeaway")
    if "m4_notes[]" in norm:
        return t("smoke_stub.m4_note")
    if path.endswith(".identity_narrative") or path.endswith(".status_narrative"):
        return t("smoke_stub.identity_narrative")
    if path.endswith(".alert"):
        return t("smoke_stub.alert")
    if path.endswith(".narrative") and "immediate_action" in path:
        return t("smoke_stub.immediate_action")
    if path.endswith(".rationale"):
        return t("smoke_stub.rationale")
    if path.endswith(".narrative") and "re_entry_conditions" in path:
        return t("smoke_stub.re_entry")
    # v0.7 cross_sym narrative slots
    if path.endswith(".summary_narrative") and "cross_sym" in path:
        return "cross-sym candidates above are observable cross-token operator footprint; review and monitor."
    if path.endswith(".identity_narrative") and "cross_sym" in path:
        return "cross_sym_count and pre_launch_insider_count locked evidence: cross-token operator pattern."
    if path.endswith(".risk_assessment_narrative"):
        return "risk read for traders: monitor for cross-token exit moves and concentration."
    return t("smoke_stub.generic")


_NATO = (
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
    "golf", "hotel", "india", "juliet", "kilo", "lima",
    "mike", "november", "oscar", "papa", "quebec", "romeo",
    "sierra", "tango", "uniform", "victor", "whiskey", "xray",
    "yankee", "zulu",
)


def walk(obj, path: str):
    if isinstance(obj, str):
        if obj == PLACEHOLDER:
            base = _pick(path)
            # v0.6.4: append a per-index distinct WORD (NATO alphabet) so
            # anti-dup validators see genuinely distinct strings even after
            # the v2 digit-normalization pass (which strips numeric suffixes
            # to catch boilerplate-with-fact-substitution evasion). Letters
            # survive normalization; numbers do not.
            idx_match = re.findall(r"\[(\d+)\]", path)
            if idx_match:
                idx = int(idx_match[-1])
                suffix = _NATO[idx % len(_NATO)]
                return f"{base} ({suffix} variant)"
            return base
        return obj
    if isinstance(obj, dict):
        return {k: walk(v, f"{path}.{k}") for k, v in obj.items()}
    if isinstance(obj, list):
        return [walk(v, f"{path}[{i}]") for i, v in enumerate(obj)]
    return obj


def main() -> int:
    # Beta.15: force UTF-8 stdout/stderr (Windows cp1252 console fix).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    # v0.6.2: lang from env BINANCE_ALPHA_LANG (default "zh"). smoke_fill is
    # called from tests so we don't add CLI flag — env is enough.
    set_lang(os.environ.get("BINANCE_ALPHA_LANG", "zh"))
    if len(sys.argv) != 3:
        print("Usage: smoke_fill.py <skeleton.json> <out_filled.json>", file=sys.stderr)
        return 1
    skel = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    filled = walk(skel, "$")
    # v0.7.2 hard gate: tag every smoke output with a top-level flag.
    # render_report.py reads this and refuses to render unless
    # BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1 is set. Removing the flag does
    # not bypass the gate — render also fingerprints NATO suffix stubs.
    filled["_smoke_test_fixture"] = True
    filled["_smoke_generator"] = "tests/smoke_fill.py"
    Path(sys.argv[2]).write_text(json.dumps(filled, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"OK: wrote {sys.argv[2]} (smoke fixture — tagged "
        f"_smoke_test_fixture=true; render will refuse unless "
        f"BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
