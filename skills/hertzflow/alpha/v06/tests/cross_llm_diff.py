#!/usr/bin/env python3
"""cross_llm_diff.py — compare two LLM-filled report_data JSONs.

Outputs a structural diff focused on the cross-LLM convergence question:

1. Did both LLMs preserve identical locked + derived_locked values?
   (Should be IDENTICAL — both pipelines wrote them; if they differ,
   one LLM tampered with locked fields.)
2. Did both LLMs fill EVERY writable slot?
   (Should be 100% on both sides — placeholder survival = LLM didn't
   complete the fill.)
3. Where do narratives DIFFER, are they semantically aligned?
   (Acceptable: same verdict signal explained differently. Unacceptable:
   one LLM says "EXIT_IF_HOLDING because Quiet wallet 5M" and the
   other says "Quiet wallet healthy, ENTER".)

Usage:
    python3 cross_llm_diff.py <claude_filled.json> <model_b_filled.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _flatten(obj, path=""):
    """Yield (path, value) pairs for every leaf scalar in obj."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _flatten(v, f"{path}[{i}]")
    else:
        yield (path, obj)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: cross_llm_diff.py <claude_filled.json> <model_b_filled.json>", file=sys.stderr)
        return 1

    claude = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    model_b = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

    claude_leaves = dict(_flatten(claude))
    model_b_leaves = dict(_flatten(model_b))

    # Categorize differences
    only_claude = set(claude_leaves) - set(model_b_leaves)
    only_model_b = set(model_b_leaves) - set(claude_leaves)
    common = set(claude_leaves) & set(model_b_leaves)
    identical = [p for p in common if claude_leaves[p] == model_b_leaves[p]]
    differ = [p for p in common if claude_leaves[p] != model_b_leaves[p]]

    # Which differences are in writable narrative paths? (heuristic by name)
    NARRATIVE_SUFFIXES = (
        ".one_liner", ".verdict_impact", ".interpretation", ".nature",
        ".status_text", ".hours_ago_text", ".detail", ".title",
        ".alert", ".monitoring_footer", ".narrative", ".rationale",
        ".identity_narrative", ".status_narrative",
    )
    NARRATIVE_LIST_PATTERNS = ("key_takeaways[", "m4_notes[")
    NARRATIVE_EXACT = {"monitoring_footer"}   # top-level writable scalar

    def is_narrative(path):
        if path in NARRATIVE_EXACT:
            return True
        if any(path.endswith(s) for s in NARRATIVE_SUFFIXES):
            return True
        if any(p in path for p in NARRATIVE_LIST_PATTERNS):
            return True
        return False

    narrative_differ = [p for p in differ if is_narrative(p)]
    structural_differ = [p for p in differ if not is_narrative(p)]

    # Placeholder survival check
    PLACEHOLDER = "<LLM_NARRATIVE_PLACEHOLDER>"
    claude_placeholder_paths = [p for p, v in claude_leaves.items() if v == PLACEHOLDER]
    model_b_placeholder_paths = [p for p, v in model_b_leaves.items() if v == PLACEHOLDER]

    print("=" * 72)
    print(f"Cross-LLM diff: {sys.argv[1]} vs {sys.argv[2]}")
    print("=" * 72)
    print(f"Total leaves: claude={len(claude_leaves)} model_b={len(model_b_leaves)}")
    print(f"  identical:           {len(identical)}")
    print(f"  differ:              {len(differ)}")
    print(f"    narrative:         {len(narrative_differ)}  ← expected to differ")
    print(f"    STRUCTURAL:        {len(structural_differ)}  ← CONVERGENCE BUG if > 0")
    print(f"  only_claude:         {len(only_claude)}")
    print(f"  only_model_b:          {len(only_model_b)}")
    print()
    print(f"Placeholder survival:")
    print(f"  claude has:          {len(claude_placeholder_paths)}  ← LLM-fill incomplete if > 0")
    print(f"  model_b has:           {len(model_b_placeholder_paths)}  ← LLM-fill incomplete if > 0")
    print()

    if structural_differ:
        print("STRUCTURAL DIFFERENCES (convergence bug — these should match):")
        for p in structural_differ[:20]:
            cv = repr(claude_leaves[p])[:80]
            xv = repr(model_b_leaves[p])[:80]
            print(f"  {p}")
            print(f"    claude: {cv}")
            print(f"    model_b:  {xv}")
        if len(structural_differ) > 20:
            print(f"  ... and {len(structural_differ) - 20} more.")
        print()

    if only_claude or only_model_b:
        print("PATH PRESENCE MISMATCH (one LLM added/dropped a field):")
        for p in sorted(only_claude)[:10]:
            print(f"  only claude: {p}")
        for p in sorted(only_model_b)[:10]:
            print(f"  only model_b:  {p}")
        print()

    # Verdict alignment check
    cv_enum = claude.get("verdict", {}).get("enum")
    cx_enum = model_b.get("verdict", {}).get("enum")
    print(f"verdict.enum: claude={cv_enum!r} model_b={cx_enum!r} → "
          f"{'MATCH' if cv_enum == cx_enum else 'DIVERGE'}")

    cv_action = claude.get("decision_action_block", {}).get("immediate_action", {}).get("action_enum")
    cx_action = model_b.get("decision_action_block", {}).get("immediate_action", {}).get("action_enum")
    print(f"action_enum:  claude={cv_action!r} model_b={cx_action!r} → "
          f"{'MATCH' if cv_action == cx_action else 'DIVERGE'}")

    # Sample 3 narrative slots side-by-side for human review
    print()
    print("Sample narrative slots (human review):")
    for p in ["verdict.one_liner", "anomaly.verdict_impact", "liq.interpretation"]:
        cv = claude_leaves.get(p, "<absent>")
        xv = model_b_leaves.get(p, "<absent>")
        print(f"\n  {p}:")
        print(f"    claude: {str(cv)[:200]}{'...' if len(str(cv)) > 200 else ''}")
        print(f"    model_b:  {str(xv)[:200]}{'...' if len(str(xv)) > 200 else ''}")

    # Return 0 if no structural diff + no placeholders survived; else 1
    convergence_ok = (
        len(structural_differ) == 0
        and len(claude_placeholder_paths) == 0
        and len(model_b_placeholder_paths) == 0
        and cv_enum == cx_enum
        and cv_action == cx_action
    )
    print()
    print("=" * 72)
    print(f"CONVERGENCE: {'OK' if convergence_ok else 'NEEDS REVIEW'}")
    print("=" * 72)
    return 0 if convergence_ok else 1


if __name__ == "__main__":
    sys.exit(main())
