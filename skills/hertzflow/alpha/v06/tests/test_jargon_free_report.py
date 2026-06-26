#!/usr/bin/env python3
"""test_jargon_free_report.py — regression test for jargon translation.

adversarial review beta.7 ZEST test (2026-05-24) found 12 hits of internal jargon
('Rule 11' / 'OPERATOR_RELAY' / 'DUMPER_DEST' / 'RULE11_QUIET' / ...)
in rendered report.md. Beta.8 patched 4 sources; this test pins fix.

Beta.9 (cross-LLM audit fix): test now uses a checked-in skeleton
fixture (`tests/fixtures/zest_skeleton_fixture.json`) so the full
pipeline → fill → render path is exercised every run, regardless of
SURF availability. Previous network-dependent branching could
false-pass when SURF was missing.

Also: jargon detection broadened from exact-string list to case-
insensitive regex with variants ('quiet wallet', 'Quiet', 'rule\\s*11',
'operator\\s*relay', 'pre[- ]launch', 'full dumper', 'partial dumper').

Allowed locations for jargon (stripped before grep):
- machine_readable_json fenced block (designed for grep/automation)
- mermaid flowchart blocks (node IDs are alphanumeric, labels translated)

Run:
    cd v06/ && python3 tests/test_jargon_free_report.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

V06_DIR = Path(__file__).parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "zest_skeleton_fixture.json"


# Beta.9 — broadened regex patterns. Case-insensitive, allows spacing
# variants ('rule 11' / 'rule11' / 'Rule  11').
_FORBIDDEN_PATTERNS = [
    r"rule\s*11",                # Rule 11 / Rule11 / rule  11
    r"operator[\s_]*relay",      # Operator relay / operator_relay / OPERATOR_RELAY
    r"dumper[\s_]*dest",         # Dumper Dest / dumper_dest / DUMPER_DEST
    r"rule11_[a-z]+",            # RULE11_QUIET / RULE11_FULL / etc
    r"\bquiet\s*wallet",         # quiet wallet / Quiet Wallet (word boundary to avoid Chinese context)
    r"\bfull\s+dumper",          # Full Dumper / full dumper
    r"\bpartial\s+dumper",       # Partial Dumper
    r"\bdumper\b",               # bare "dumper" word (beta.9 retest: 主 dumper 派发 still leaked)
    r"\breceiver\b",             # "deployer 已向 receiver 派发" style
    r"\bdeployer\b",             # bare "deployer" word (already covered by 'deployer' in main grep)
    r"\bmint(ed)?\b",            # English "mint" / "minted"
    r"\bpre[- ]launch\b",        # Pre-launch / pre launch
    r"\bevt_ref\b",              # internal ID name
    r"\bm6_ref\b",
    r"\bdumped_pct\b",
    # Standalone English enum tokens that snuck into mermaid labels in
    # beta.7 but not user-facing (caught by role_to_cn now), still grep:
    r"\b(DEX_POOL|DEPLOYER|RULE11_QUIET|RULE11_PARTIAL|RULE11_FULL|OPERATOR_RELAY|DUMPER_DEST)\b",
    # v0.7.19.1 — block internal development self-deprecation that the
    # v0.7.16 "口径 大白话" rewrite leaked into the report. A retail trader
    # doesn't know what R2 is or what 1013% means; the dev backstory
    # belongs in CHANGELOG / memory, not in the user-facing decision brief.
    r"R2\s*token",                 # "R2 token" reference
    r"1013\s*%",                   # "1013% 派发" specific bug number
    r"踩过.*?笑话",                 # self-deprecating "踩过 ... 笑话" pattern
]


def _user_facing_surfaces(report_text: str) -> str:
    """Strip the machine_readable_json fenced block + mermaid blocks.
    Return only the prose + tables the user actually reads."""
    out = re.sub(
        r"##\s*机器可读\s*JSON.*?```json.*?```",
        "[MACHINE_READABLE_JSON_BLOCK_OMITTED]",
        report_text,
        flags=re.DOTALL,
    )
    out = re.sub(
        r"```mermaid.*?```",
        "[MERMAID_BLOCK_OMITTED]",
        out,
        flags=re.DOTALL,
    )
    return out


def _render_from_fixture(tmp_dir: Path) -> str:
    """Beta.9 deterministic test path: smoke_fill the checked-in
    skeleton fixture, then run render_report.py end-to-end. No SURF
    dependency. Test FAILS hard if any step fails — never false-passes."""
    if not FIXTURE.exists():
        raise RuntimeError(
            f"Missing checked-in skeleton fixture: {FIXTURE}. "
            f"This test cannot run without it. Re-add fixture from a "
            f"successful ZEST pipeline run."
        )
    # Copy fixture to tmp so we don't mutate
    skel_path = tmp_dir / "skeleton.json"
    filled_path = tmp_dir / "filled.json"
    report_path = tmp_dir / "report.md"
    skel_path.write_bytes(FIXTURE.read_bytes())

    # Beta.14: surface subprocess stderr on failure so test failures
    # report root cause (e.g., render_report.py REFUSED messages) instead
    # of opaque CalledProcessError. adversarial review Windows beta.13 run revealed
    # render_report.py exit 1 with no visible reason because we captured
    # and discarded stderr.
    r1 = subprocess.run(
        [sys.executable, str(V06_DIR / "tests" / "smoke_fill.py"),
         str(skel_path), str(filled_path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if r1.returncode != 0:
        raise RuntimeError(
            f"smoke_fill.py exit {r1.returncode}\n"
            f"--- stdout ---\n{r1.stdout}\n--- stderr ---\n{r1.stderr}"
        )
    # v0.7.2: render_report.py refuses smoke_fill output by default
    # (REFUSED exit 3). This jargon-grep test legitimately needs an E2E
    # render of the smoke fixture, so we set the override env var that
    # tells render this is an intentional CI test path.
    render_env = os.environ.copy()
    render_env["BINANCE_ALPHA_ALLOW_SMOKE_RENDER"] = "1"
    render_env["BINANCE_ALPHA_SMOKE_OVERRIDE_REASON"] = "test_jargon_free_report.py E2E"
    render_env["BINANCE_ALPHA_NO_UPDATE_CHECK"] = "1"
    # v0.7.19.5: smoke fixture has stale hardcoded numbers that no longer
    # match the locked pool of the smoke-filled skeleton. NUMERIC_HALLUCINATION
    # is now structural-by-default; this smoke E2E intentionally uses stale
    # data so the env-override soft-classifies it.
    render_env["BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS"] = "1"
    r2 = subprocess.run(
        [
            sys.executable, str(V06_DIR / "render_report.py"),
            "--skeleton", str(skel_path),
            "--filled", str(filled_path),
            "--out", str(report_path),
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=render_env,
    )
    # Exit 2 is acceptable (narrative-quality warnings on smoke stubs); the
    # report file is still produced. Exit 1/3 are fatal — surface stderr.
    if r2.returncode not in (0, 2):
        raise RuntimeError(
            f"render_report.py exit {r2.returncode}\n"
            f"--- stdout ---\n{r2.stdout}\n--- stderr ---\n{r2.stderr}"
        )
    return report_path.read_text(encoding="utf-8")


def test_no_jargon_in_user_facing_surfaces():
    """Real-render test: pipeline → smoke_fill → render full path,
    then grep user-facing surfaces for any forbidden jargon pattern.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        report_text = _render_from_fixture(tmp_dir)
        user_facing = _user_facing_surfaces(report_text)
        hits = []
        for pattern in _FORBIDDEN_PATTERNS:
            matches = re.findall(pattern, user_facing, flags=re.IGNORECASE)
            if matches:
                hits.append((pattern, matches[:3]))   # cap evidence at 3 per pattern
        assert not hits, (
            f"Jargon leak in user-facing surfaces:\n" +
            "\n".join(f"  pattern={p!r} matches={m}" for p, m in hits) +
            f"\nAll labels should be 中文大白话 (项目方钱包, 潜伏钱包, "
            f"庄家中转地, etc.) per SKILL_v06.md."
        )


def test_role_to_cn_unknown_enum_fails_closed():
    """adversarial review beta.8 10th-audit HIGH: unknown role enum must NOT leak.
    Verify role_to_cn returns 未知角色 (not raw enum) for unmapped values.
    """
    sys.path.insert(0, str(V06_DIR))
    from render_report import role_to_cn
    # Known: maps correctly
    assert role_to_cn("DEPLOYER") == "项目方"
    assert role_to_cn("OPERATOR_RELAY") == "庄家中转"
    # Unknown enum-looking: fails closed
    assert role_to_cn("CEX_ROUTER") == "未知角色", (
        f"Unknown enum should fail closed to 未知角色, "
        f"got {role_to_cn('CEX_ROUTER')!r}"
    )
    assert role_to_cn("FUTURE_ROLE_XYZ") == "未知角色"
    # 中文 / mixed text: pass through (no enum pattern match)
    assert role_to_cn("项目方钱包") == "项目方钱包"
    # None / empty: empty string
    assert role_to_cn(None) == ""
    assert role_to_cn("") == ""


if __name__ == "__main__":
    tests = [
        ("no jargon in user-facing surfaces", test_no_jargon_in_user_facing_surfaces),
        ("role_to_cn unknown enum fails closed", test_role_to_cn_unknown_enum_fails_closed),
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
            failed += 1
    if failed:
        print(f"\n{failed}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"\n{len(tests)}/{len(tests)} passed")
