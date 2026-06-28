#!/usr/bin/env python3
"""validate_report_data.py — v0.6 content-level validator.

Verifies a LLM-filled report_data.json against:
1. Skeleton invariance: locked fields MUST equal pipeline output (no LLM tampering)
2. R1-R12 content cross-field consistency rules
3. Provenance: every narrative claim referencing evt_ref must be consistent
   with the underlying evidence_graph entry
4. Causal Rule 11: m6.rows ↔ anomaly.waves coupling
5. Semantic META check: writable fields must not match the blacklist
   embedding corpus (optional, falls back to substring match if embeddings
   not built)
6. Field authority enforcement: derived from field_authority.yaml registry

## Error categories (v0.7.1)

v0.7.1 splits errors into two classes so render_report.py can decide:

  STRUCTURAL — LLM tampered locked data / pipeline regression / security
                gate. NEVER produce a report (caller paid surf credits but
                output cannot be trusted).

  NARRATIVE_QUALITY — narrative content didn't meet quality bar (too short,
                duplicated, doesn't cite locked evidence, etc.). Render the
                report anyway with warning at top; let caller decide to
                re-fill narrative and re-render.

This stops the v0.7.0 architecture bug where a fresh LLM that didn't cite
enough evidence wasted user's Surf credits with no report.md emitted.

## Usage

```bash
python3 validate_report_data.py --skeleton skeleton.json --filled filled.json
# exits 0 if all pass
# exits 1 if any STRUCTURAL fail (hard abort)
# exits 2 if only NARRATIVE_QUALITY fails (caller may render anyway)
```

The skeleton is the pipeline output BEFORE LLM-fill (contains
<LLM_NARRATIVE_PLACEHOLDER>). The filled JSON is what the LLM produced. We
diff locked fields between the two AND apply content checks to writable fields.

v0.6 (2026-05-24, cross-LLM audit conditions)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent / "helpers"))
from evidence_graph import EvidenceGraph


# ============================================================
# Helpers — path resolution
# ============================================================

def _resolve_path(obj: Any, path: str) -> list[tuple[str, Any]]:
    """Resolve a dot-path with [] array notation. Returns list of (concrete_path, value)
    tuples. `meta.symbol` returns 1 tuple; `anomaly.waves[].events[].nature` returns
    one tuple per actual array index.

    Returns empty list if path doesn't resolve (field absent — caller decides
    if that's an error).
    """
    parts = re.split(r"\.", path)
    results: list[tuple[str, Any]] = [("", obj)]
    for part in parts:
        new_results: list[tuple[str, Any]] = []
        # Handle [] suffix
        if part.endswith("[]"):
            key = part[:-2]
            for cp, val in results:
                if isinstance(val, dict) and key in val:
                    arr = val[key]
                    if isinstance(arr, list):
                        for i, item in enumerate(arr):
                            new_results.append((f"{cp}.{key}[{i}]" if cp else f"{key}[{i}]", item))
                # If key missing, silently produce nothing — caller checks length
        else:
            for cp, val in results:
                if isinstance(val, dict) and part in val:
                    new_results.append((f"{cp}.{part}" if cp else part, val[part]))
        results = new_results
    return results


def _load_yaml_simple(path: Path) -> dict:
    """Minimal YAML loader — no external dep. Supports our specific format:
    - top-level keys (locked / derived_locked / writable / deferred)
    - lists under those keys (strings OR dicts)
    - dict values flat (path, min_length, etc.)
    For full YAML semantics we'd use PyYAML, but this avoids a runtime dep
    and is enough for our restricted schema.
    """
    text = path.read_text(encoding="utf-8")
    out: dict = {}
    current_key = None
    current_list: list = []
    current_dict: dict | None = None
    for raw_line in text.split("\n"):
        # Strip comments + trailing whitespace; keep leading whitespace for indent
        if "#" in raw_line:
            raw_line = raw_line.split("#", 1)[0]
        line = raw_line.rstrip()
        if not line.strip():
            continue
        # Top-level key (no leading whitespace, ends with ':')
        if not line.startswith((" ", "\t")) and ":" in line:
            if current_key:
                if current_dict:
                    current_list.append(current_dict)
                    current_dict = None
                out[current_key] = current_list
            k, v = line.split(":", 1)
            v = v.strip()
            if v and v not in ('"', "'"):
                # scalar top-level value (e.g. version: "0.6.0-alpha.1")
                out[k] = v.strip('"').strip("'")
                current_key = None
                current_list = []
            else:
                current_key = k
                current_list = []
                current_dict = None
            continue
        # List item under current key
        if line.lstrip().startswith("- "):
            # Flush prior dict if any
            if current_dict:
                current_list.append(current_dict)
                current_dict = None
            content = line.lstrip()[2:].strip()
            # v0.6.0-alpha.13 (cross-LLM audit MEDIUM): explicitly reject
            # nested-list / non-scalar list-item shapes. Previously `- - foo`
            # parsed as the string "- foo" because we only stripped one "- "
            # prefix, which let malformed YAML pass the constructor's
            # isinstance(str) check. Fail closed at load time.
            if content.startswith("-") or content.startswith("["):
                raise ValueError(
                    f"field_authority.yaml line {ln+1 if 'ln' in dir() else '?'}: "
                    f"malformed list item {line.rstrip()!r}. Nested lists / "
                    f"flow-style arrays are not supported by this loader."
                )
            if ":" in content and not content.startswith('"'):
                # Start of a dict item: `- path: foo`
                k, v = content.split(":", 1)
                current_dict = {k.strip(): v.strip().strip('"')}
            else:
                # Plain string item: `- "meta.symbol"` or `- meta.symbol`
                current_list.append(content.strip('"').strip("'"))
            continue
        # Continuation of dict item (indented `  key: value`)
        if current_dict is not None and ":" in line:
            stripped = line.strip()
            k, v = stripped.split(":", 1)
            current_dict[k.strip()] = v.strip().strip('"')
            continue
    # Flush final
    if current_dict:
        current_list.append(current_dict)
    if current_key:
        out[current_key] = current_list
    return out


# ============================================================
# Validator class
# ============================================================

class Validator:
    """v0.6 validator. Reads field_authority.yaml + meta_blacklist_corpus.txt.

    Calling convention:
        v = Validator(yaml_path=..., corpus_path=...)
        errors = v.validate(skeleton_dict, filled_dict)
    """

    def __init__(self, use_embeddings: bool = False):
        """v0.6.0-alpha.3: paths to field_authority.yaml + meta_blacklist_corpus.txt
        are HARDCODED to the schema/ directory adjacent to this validator.

        Previously these were constructor args, but cross-LLM tester v0.6.0-alpha.2
        audit demonstrated a bypass: moving the action_enum locked line out
        of a custom yaml made the same filled JSON pass. Hardcoding closes
        that surface — same class of fix as v0.5.x --bypass-validation removal.
        """
        self.errors: list[str] = []

        schema_dir = Path(__file__).parent / "schema"
        yaml_path = schema_dir / "field_authority.yaml"
        corpus_path = schema_dir / "meta_blacklist_corpus.txt"

        self.authority = _load_yaml_simple(yaml_path)

        # v0.6.0-alpha.11 (cross-LLM audit HIGH): reject unknown top-level
        # keys in field_authority.yaml. Previously, only locked / derived_locked
        # / writable were consumed; any other key (incl. typos like
        # `derived_lock`, or a future tier nobody plumbed in) was silently
        # ignored, downgrading enforcement to "what we happened to recognize".
        # Fail closed at construction time so config drift is a startup error,
        # not a runtime silent pass.
        _ALLOWED_TIERS = {
            "locked", "derived_locked", "writable",
            # Documentation-only keys (not iterated as tiers):
            "version", "updated", "deferred",
        }
        unknown_keys = set(self.authority.keys()) - _ALLOWED_TIERS
        if unknown_keys:
            raise ValueError(
                f"field_authority.yaml has unknown top-level keys: "
                f"{sorted(unknown_keys)}. Allowed: {sorted(_ALLOWED_TIERS)}. "
                f"Refusing to load — silent typos here downgrade enforcement."
            )

        # v0.6.0-alpha.12 (cross-LLM audit HIGH): strict grammar check
        # on locked + derived_locked entries. Previously _check_locked_invariance
        # had `if not isinstance(path, str): continue` which silently skipped
        # any malformed entry (e.g., a dict `{'path': 'meta.symbol'}` produced
        # by a YAML refactor). Now reject at construction.
        for tier in ("locked", "derived_locked"):
            entries = self.authority.get(tier, [])
            if not isinstance(entries, list):
                raise ValueError(
                    f"field_authority.yaml: {tier!r} must be a list of "
                    f"non-empty strings, got {type(entries).__name__}."
                )
            for i, entry in enumerate(entries):
                if not isinstance(entry, str) or not entry.strip():
                    raise ValueError(
                        f"field_authority.yaml: {tier}[{i}] is not a "
                        f"non-empty string (got {entry!r}). Locked-tier "
                        f"entries must be plain dot-path strings; structured "
                        f"entries with metadata belong in `writable`."
                    )

        # Load META corpus (substring fallback for now; embedding mode is
        # phase 4.2 polish)
        self.meta_corpus: list[str] = []
        if corpus_path.exists():
            for line in corpus_path.read_text(encoding="utf-8").split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    self.meta_corpus.append(line)

        self.use_embeddings = use_embeddings
        self._embeddings_cache = None  # lazy load only if used

        # Build the evidence_graph helper for narrative checks
        self._eg: EvidenceGraph | None = None  # set during validate()

    # ----- Core validation entry -----

    def validate(self, skeleton: dict, filled: dict) -> list[str]:
        """Run all checks. Returns list of error strings (empty = pass)."""
        self.errors = []

        # Reconstruct EvidenceGraph from filled["evidence_graph"] for lookups
        self._eg = self._reconstruct_eg(filled.get("evidence_graph", {}))

        # 1. Schema-version sanity (cheap)
        self._check_schema_version(skeleton, filled)

        # 2. Locked field invariance (the core anti-LLM-tampering check)
        self._check_locked_invariance(skeleton, filled)

        # 3. Writable field content quality (length, no remaining placeholders)
        self._check_writable_quality(filled)

        # 4. Provenance: every narrative referencing evt_ref must be consistent
        self._check_provenance(filled)

        # 5. Causal Rule 11: m6.rows ↔ waves coupling
        self._check_causal_rule_11(filled)

        # 6. R1-R12 cross-field rules
        self._check_R1_detector_counts(filled)
        self._check_R2_m6_implies_detector(filled)
        self._check_R4_rule11_implies_waves(filled)
        self._check_R7_rhythm_matches_waves(filled)
        self._check_R10_detector_categories(filled)
        self._check_R11_decision_action_complete(filled)
        self._check_R12_no_placeholders_remain(filled)

        # 7. Semantic META check on writable narrative fields
        self._check_meta_language(filled)

        # 8. v0.6.1: Anti-duplication checks. Prevents lazy LLM filling N items
        # with same narrative string (cross-LLM regression test exposed this — 12 m6 rows
        # all got identical "项目方派发的内幕派发方" filler).
        self._check_no_narrative_duplication(filled)

        # 9. v0.6.4: Narrative-vs-locked semantic consistency. Catches LLM
        # writing narrative that directly contradicts what the pipeline-locked
        # data says — e.g. cex_trace.interpretation saying "no perp catalyst"
        # when locked tier == "S2" + Binance perp listing row is present.
        # Two independent LLMs (an LLM + adversarial review) made this mistake on STAR
        # 2026-05-25 cross-LLM test; user caught it on read.
        self._check_narrative_vs_locked_semantic(filled)

        # 10. v0.7: cross_sym whale narrative validation. Pipeline-derived
        # identity classification is locked; LLM cannot freelance the
        # identity (e.g. claim KOL when classifier says ARB_DESK), and
        # identity narrative must cite ≥2 locked signature evidence fields.
        self._check_cross_sym_whales(skeleton, filled)

        # 10b. v0.7.7: wash_infrastructure section. Pipeline emits the X/P/Q
        # triplet + 5-step structural metrics as locked. LLM may only write
        # the investigation_narrative + summary_narrative.
        self._check_wash_infrastructure(skeleton, filled)

        # 11-13. v0.7.3: narrative quality validators — catch dud narrative
        # not caught above. All three are NARRATIVE_QUALITY (soft-fail) so
        # render still produces a report with warning header.
        self._check_narrative_generic_phrases(filled)
        self._check_narrative_template_reuse(filled)
        self._check_narrative_numeric_hallucination(filled)

        return list(self.errors)

    def _reconstruct_eg(self, eg_dict: dict) -> EvidenceGraph:
        """Rebuild an EvidenceGraph from a serialized dict (read-only use)."""
        eg = EvidenceGraph()
        eg._store = dict(eg_dict)  # raw dict, no add_event() because we want exact IDs preserved
        return eg

    # ----- Individual checks -----

    def _check_schema_version(self, skeleton: dict, filled: dict) -> None:
        s_ver = skeleton.get("_schema_version")
        f_ver = filled.get("_schema_version")
        if s_ver != f_ver:
            self.errors.append(
                f"V_SCHEMA_VERSION: skeleton={s_ver!r} != filled={f_ver!r}"
            )
        # v0.8.4.9.4: accept 0.6.x AND 0.7.x AND 0.8.x. v0.9.0 加: 跟
        # 0.8 schema 兼容 (没 breaking change), 只是 architecture rearch
        # (folder 重组 + 单 skill router). schema 字段未动.
        # v1.2.0: accept ALL 1.x via a "1." prefix — the per-minor enumeration meant
        # every _version.py bump (1.0→1.1→1.2…) silently broke the FIRST render with
        # a V_SCHEMA_VERSION hard-fail until someone re-listed it. The s_ver != f_ver
        # check above still catches a genuine skeleton/filled mismatch; within the 1.x
        # line the schema is forward-compatible, so a prefix accept is correct + stops
        # this recurring on every release.
        if s_ver and not (s_ver.startswith("0.6") or s_ver.startswith("0.7")
                          or s_ver.startswith("0.8") or s_ver.startswith("0.9")
                          or s_ver.startswith("1.")):
            self.errors.append(
                f"V_SCHEMA_VERSION: expected 0.6.x / 0.7.x / 0.8.x / 0.9.x / 1.x, "
                f"got {s_ver!r}"
            )

    def _check_array_segments_present(self, skeleton: dict, path: str) -> list[str]:
        """For an array-path like `foo[].bar[].baz`, verify every `[]`
        segment's parent is a list in skeleton. v0.6.0-alpha.13 fix for
        cross-LLM audit HIGH: previously only the FIRST `[]` parent
        was validated, leaving nested-array configs bypassable.

        Returns list of error strings. Empty lists at any level are
        legitimate (no further descent possible, but no missing-segment
        finding either — that's the count check's job).
        """
        if "[]" not in path:
            return []
        parts = path.split("[]")
        errors: list[str] = []
        current_targets: list = [skeleton]
        # Walk every `[]` segment except the post-final scalar tail (parts[-1]).
        for i in range(len(parts) - 1):
            segment = parts[i].lstrip(".")
            next_targets: list = []
            for t in current_targets:
                node = t
                if segment:
                    for k in segment.split("."):
                        if isinstance(node, dict) and k in node:
                            node = node[k]
                        else:
                            errors.append(
                                f"V_LOCKED_FIELD_ABSENT: path={path!r} "
                                f"missing key {k!r} at array segment "
                                f"index {i} ({segment!r})."
                            )
                            node = None
                            break
                if node is None:
                    continue
                if not isinstance(node, list):
                    errors.append(
                        f"V_LOCKED_FIELD_ABSENT: path={path!r} expected "
                        f"list at segment index {i} ({segment!r}), got "
                        f"{type(node).__name__}. Likely `[]` typo on a "
                        f"scalar field."
                    )
                    continue
                next_targets.extend(node)
            current_targets = next_targets
            if not current_targets:
                # All matched arrays are empty — legitimate (empty
                # monitoring_wallets[] on tokens with zero detected actors).
                # No further descent possible; stop without error.
                break
        return errors

    def _check_locked_invariance(self, skeleton: dict, filled: dict) -> None:
        """For every locked OR derived_locked path, skeleton value == filled value.

        v0.6.0-alpha.10 (cross-LLM re-audit): previously this only
        iterated `locked`, leaving `derived_locked` fields (verdict.enum,
        verdict.cn_label, verdict.next_tier_*, decision_action_block.
        immediate_action.action_enum) unenforced. An LLM could rewrite
        verdict.enum from EXIT_IF_HOLDING → ENTER with the validator
        passing. Same class of trust-boundary gap as v0.5 --bypass-validation
        and v0.6 alpha.2 --yaml flag; closes that surface.

        The two tier names remain distinct in the registry (locked = derived
        from raw data; derived_locked = derived from other locked fields)
        but ENFORCEMENT is identical: LLM cannot touch either tier.
        """
        locked_paths = list(self.authority.get("locked", []))
        derived_locked_paths = list(self.authority.get("derived_locked", []))
        all_paths = locked_paths + derived_locked_paths

        # v0.6.0-alpha.11 (cross-LLM audit HIGH): paths absent in BOTH
        # skeleton and filled previously passed silently (len(s_vals) == 0 ==
        # len(f_vals)). That weakens the trust boundary from "must be pipeline
        # controlled" to "only checked if present" — pipeline can regress and
        # silently stop emitting a locked field with no failure signal.
        #
        # Two classes of locked paths exist:
        #   1. Scalar leaves (e.g., meta.symbol) — MUST be present in skeleton.
        #   2. Array element paths (foo[].bar) — empty array is legitimate
        #      pre-population state (e.g., monitoring_wallets[] for tokens with
        #      zero detected actors). For these we only flag if filled adds
        #      elements that skeleton doesn't have (covered by count-mismatch).
        #
        # The simple heuristic: array paths contain `[]`, scalar paths don't.
        # v0.6.0-alpha.12 (cross-LLM audit HIGH): the `[]` heuristic
        # was bypassable — a scalar path declared with a typo `meta.symbol[]`
        # would be classified as array, skip V_LOCKED_FIELD_ABSENT, and
        # _resolve_path returning [] in both skeleton + filled would pass
        # count check. Closed by requiring array paths to have a structurally
        # existing PARENT in skeleton (the dict/list at the parent key must
        # exist, even if the array is empty). Empty array is legitimate
        # pipeline state; absent parent dict is a config / pipeline bug.
        for path in all_paths:
            if not isinstance(path, str):
                # Defensive: constructor already rejects non-string entries,
                # but if a future refactor adds runtime mutation paths this
                # remains a fail-closed gate, NOT a silent skip.
                self.errors.append(
                    f"V_AUTHORITY_GRAMMAR: non-string locked entry "
                    f"{type(path).__name__}({path!r}) — config bug"
                )
                continue
            s_vals = _resolve_path(skeleton, path)
            f_vals = _resolve_path(filled, path)

            is_array_path = "[]" in path

            # Scalar locked path absent in both skeleton AND filled:
            # fail closed. Locked means "pipeline must emit"; absence is a
            # regression, not a no-op.
            if not is_array_path and not s_vals and not f_vals:
                self.errors.append(
                    f"V_LOCKED_FIELD_ABSENT: path={path!r} (scalar, "
                    f"declared in field_authority {('derived_' if path in derived_locked_paths else '')}locked) "
                    f"missing from both skeleton and filled — pipeline regression."
                )
                continue

            # Array locked path with zero matches in BOTH: verify EVERY `[]`
            # segment's parent list exists. v0.6.0-alpha.12 only checked the
            # FIRST `[]` parent — cross-LLM audit HIGH caught that for
            # nested paths like `foo[].bar[].baz`, if `foo` exists but each
            # `foo[i].bar` is missing, both s_vals and f_vals stay empty and
            # no V_LOCKED_FIELD_ABSENT fires. Now we walk every `[]` segment.
            if is_array_path and not s_vals and not f_vals:
                nested_errors = self._check_array_segments_present(skeleton, path)
                if nested_errors:
                    self.errors.extend(nested_errors)
                # If all segments resolved to lists but the resulting array(s)
                # are empty, that's legitimate (empty monitoring_wallets[] on
                # a token with zero detected actors). Fall through; count
                # check below stays 0 == 0 as legitimate.

            if len(s_vals) != len(f_vals):
                self.errors.append(
                    f"V_LOCKED_FIELD_COUNT: path={path!r} skeleton has "
                    f"{len(s_vals)} matches, filled has {len(f_vals)}"
                )
                continue
            for (sp, sv), (fp, fv) in zip(s_vals, f_vals):
                if sv != fv:
                    self.errors.append(
                        f"V_LOCKED_FIELD_MODIFIED: path={fp} was locked. "
                        f"skeleton={_summary(sv)!r} but filled={_summary(fv)!r}"
                    )

    def _check_writable_quality(self, filled: dict) -> None:
        """Each writable spec has min_length / min_count / etc. Verify."""
        writable_specs = self.authority.get("writable", [])
        for spec in writable_specs:
            if not isinstance(spec, dict):
                continue
            path = spec.get("path")
            if not path:
                continue
            try:
                min_length = int(spec.get("min_length", 0))
            except (ValueError, TypeError):
                min_length = 0
            try:
                min_count = int(spec.get("min_count", 0))
            except (ValueError, TypeError):
                min_count = 0

            matches = _resolve_path(filled, path)

            if min_count and len(matches) < min_count:
                self.errors.append(
                    f"V_WRITABLE_COUNT: path={path!r} requires min_count={min_count} "
                    f"but only {len(matches)} present"
                )

            for cp, val in matches:
                if val is None:
                    self.errors.append(f"V_WRITABLE_NULL: {cp} is null")
                    continue
                if isinstance(val, str):
                    if "<LLM_NARRATIVE_PLACEHOLDER>" in val:
                        self.errors.append(
                            f"V_WRITABLE_PLACEHOLDER: {cp} still contains "
                            "<LLM_NARRATIVE_PLACEHOLDER> — LLM did not fill"
                        )
                        continue
                    if "<PIPELINE_PHASE" in val:
                        self.errors.append(
                            f"V_WRITABLE_STUB: {cp} contains pipeline stub marker"
                        )
                        continue
                    if min_length and len(val) < min_length:
                        self.errors.append(
                            f"V_WRITABLE_TOO_SHORT: {cp} length={len(val)} < "
                            f"min_length={min_length}"
                        )

    def _check_provenance(self, filled: dict) -> None:
        """For every anomaly.waves[].events[].nature, look up evt_ref and call
        EvidenceGraph.event_matches_narrative()."""
        if self._eg is None:
            return
        events = _resolve_path(filled, "anomaly.waves[].events[]")
        for cp, event in events:
            if not isinstance(event, dict):
                continue
            evt_ref = event.get("evt_ref")
            nature = event.get("nature", "")
            if not evt_ref:
                self.errors.append(f"V_PROVENANCE_MISSING_REF: {cp} has no evt_ref")
                continue
            if not nature or "<LLM_NARRATIVE_PLACEHOLDER>" in nature:
                # Already caught by writable check
                continue
            ok, why = self._eg.event_matches_narrative(evt_ref, nature)
            if not ok:
                self.errors.append(
                    f"V_PROVENANCE_MISMATCH: {cp}.nature inconsistent with "
                    f"evidence_graph[{evt_ref!r}]: {why}"
                )

    def _check_causal_rule_11(self, filled: dict) -> None:
        """v0.6 condition 3: m6.rows must align with waves events.

        Specifically:
        - Every m6.row has m6_ref pointing into evidence_graph
        - Every wave event has evt_ref pointing into evidence_graph
        - If lineage.m6 has rows AND anomaly.waves is empty, REJECT (R4 strict)
        - Time ordering: waves[0] ts_range MUST start before or equal to waves[1] start
        """
        m6_rows = _resolve_path(filled, "lineage.m6.rows[]")
        waves = _resolve_path(filled, "anomaly.waves[]")

        if m6_rows and not waves:
            self.errors.append(
                "V_CAUSAL_RULE11: lineage.m6.rows has "
                f"{len(m6_rows)} entries but anomaly.waves is empty. Rule 11 "
                "found insiders; pipeline must emit waves_proposal."
            )

        # Verify each m6.row.m6_ref exists in evidence_graph
        if self._eg is None:
            return
        for cp, row in m6_rows:
            if not isinstance(row, dict):
                continue
            m6_ref = row.get("m6_ref")
            if not m6_ref:
                self.errors.append(f"V_CAUSAL_RULE11_NO_M6_REF: {cp} missing m6_ref")
                continue
            if self._eg.lookup(m6_ref) is None:
                self.errors.append(
                    f"V_CAUSAL_RULE11_DANGLING: {cp}.m6_ref={m6_ref!r} not in evidence_graph"
                )

    def _check_R1_detector_counts(self, filled: dict) -> None:
        """Detector_summary[].count must be non-negative int."""
        for cp, d in _resolve_path(filled, "anomaly.detector_summary[]"):
            if not isinstance(d, dict):
                continue
            cnt = d.get("count")
            if cnt is None:
                self.errors.append(f"V_R1_DETECTOR_NO_COUNT: {cp} has no count field")
                continue
            try:
                if int(cnt) < 0:
                    self.errors.append(f"V_R1_DETECTOR_NEG: {cp}.count={cnt} negative")
            except (TypeError, ValueError):
                self.errors.append(f"V_R1_DETECTOR_NOT_INT: {cp}.count={cnt!r} not int")

    def _check_R2_m6_implies_detector(self, filled: dict) -> None:
        """If m6.rows.length > 0, detector_summary MUST include a row about
        Rule 11 / 内幕地址 / pre-launch with matching count."""
        m6_rows = _resolve_path(filled, "lineage.m6.rows[]")
        if not m6_rows:
            return
        n_m6 = len(m6_rows)
        # Check detector_summary has a label mentioning rule11 / 内幕 / pre-launch
        detectors = _resolve_path(filled, "anomaly.detector_summary[]")
        matching_keywords = ("Rule 11", "rule 11", "Rule11", "内幕", "pre-launch", "Pre-launch")
        for cp, d in detectors:
            if not isinstance(d, dict):
                continue
            label = d.get("label", "")
            if any(kw in label for kw in matching_keywords):
                # Check count is plausible (>= number of full+partial dumpers, or >= n_quiet, etc.)
                # Loose check: count > 0
                try:
                    if int(d.get("count", 0)) >= 1:
                        return  # Found at least one detector covering Rule 11
                except (TypeError, ValueError):
                    pass
        self.errors.append(
            f"V_R2_M6_NO_DETECTOR: lineage.m6.rows has {n_m6} entries but no "
            "detector_summary entry mentions Rule 11 / 内幕 / pre-launch with count >= 1"
        )

    def _check_R4_rule11_implies_waves(self, filled: dict) -> None:
        """If any m6.rows.length > 0, anomaly.waves.length must be >= 1
        (Rule 11 backward trace produces wave 1 at minimum)."""
        m6_rows = _resolve_path(filled, "lineage.m6.rows[]")
        waves = _resolve_path(filled, "anomaly.waves[]")
        if m6_rows and not waves:
            # already caught by causal check; duplicate is OK
            return
        if not m6_rows and waves:
            # waves without m6 is fine — could be 72h anomaly only
            return

    def _check_R7_rhythm_matches_waves(self, filled: dict) -> None:
        """anomaly.rhythm.waves count == anomaly.waves count."""
        rhythm_waves = _resolve_path(filled, "anomaly.rhythm.waves[]")
        waves = _resolve_path(filled, "anomaly.waves[]")
        if len(rhythm_waves) != len(waves):
            self.errors.append(
                f"V_R7_RHYTHM_MISMATCH: anomaly.waves has {len(waves)} but "
                f"anomaly.rhythm.waves has {len(rhythm_waves)}"
            )

    def _check_R10_detector_categories(self, filled: dict) -> None:
        """detector_summary should cover 7 mandatory categories. Soft check —
        at least 3 entries must exist (pipeline minimum)."""
        detectors = _resolve_path(filled, "anomaly.detector_summary[]")
        if len(detectors) < 3:
            self.errors.append(
                f"V_R10_DETECTOR_TOO_FEW: anomaly.detector_summary has only "
                f"{len(detectors)} entries; expect >= 3 mandatory categories"
            )

    def _check_R11_decision_action_complete(self, filled: dict) -> None:
        """decision_action_block.immediate_action.action_enum must be filled."""
        action_paths = _resolve_path(filled, "decision_action_block.immediate_action.action_enum")
        for cp, v in action_paths:
            if not v or (isinstance(v, str) and "<" in v):
                self.errors.append(
                    f"V_R11_DECISION_ACTION_NOT_DERIVED: {cp}={v!r} still a stub"
                )

    def _check_R12_no_placeholders_remain(self, filled: dict) -> None:
        """Recursively scan: no <LLM_NARRATIVE_PLACEHOLDER> or <PIPELINE_PHASE_*>
        markers can remain in the final filled JSON.

        v0.6.0-alpha.11 (cross-LLM audit MEDIUM): previously the docstring
        promised <PIPELINE_PHASE_*> rejection but only <LLM_NARRATIVE_PLACEHOLDER>
        was actually checked. A filled payload could ship with un-implemented
        pipeline stub markers and clear R12. Now BOTH classes are rejected.
        """
        def walk(node, path):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, f"{path}.{k}" if path else k)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, f"{path}[{i}]")
            elif isinstance(node, str):
                if "<LLM_NARRATIVE_PLACEHOLDER>" in node:
                    self.errors.append(
                        f"V_R12_PLACEHOLDER: {path} still has <LLM_NARRATIVE_PLACEHOLDER>"
                    )
                if "<PIPELINE_PHASE" in node:
                    self.errors.append(
                        f"V_R12_PLACEHOLDER: {path} still has pipeline stub marker "
                        f"({node[:50]!r}) — section not yet wired"
                    )
        walk(filled, "")

    def _check_meta_language(self, filled: dict) -> None:
        """For each writable spec with semantic_meta_check=true, check the
        filled value against the META blacklist corpus.

        Phase 4.1 implementation: substring + fuzzy ratio match. Phase 4.2
        upgrades to embedding cosine similarity.
        """
        writable_specs = self.authority.get("writable", [])
        for spec in writable_specs:
            if not isinstance(spec, dict):
                continue
            check_str = spec.get("semantic_meta_check", "").lower()
            if check_str not in ("true", "yes", "1"):
                continue
            path = spec.get("path")
            for cp, val in _resolve_path(filled, path):
                if not isinstance(val, str) or len(val) < 5:
                    continue
                hit = self._meta_corpus_check(val)
                if hit:
                    self.errors.append(
                        f"V_META_LANGUAGE: {cp} matches blacklist phrase: "
                        f"{hit[:80]!r}"
                    )

    def _meta_corpus_check(self, text: str) -> str | None:
        """Return the first matching blacklist phrase, or None.

        Phase 4.1: substring + token-overlap match. Phase 4.2 will replace
        with embedding cosine sim > 0.75.
        """
        text_norm = text.lower()
        for phrase in self.meta_corpus:
            p = phrase.lower()
            # Strong: substring of 15+ chars
            if len(p) >= 15 and p in text_norm:
                return phrase
            # Weaker: 75%+ token overlap (Chinese-aware: char-shingles)
            t_chars = set(text_norm)
            p_chars = set(p)
            if len(p_chars) >= 8:
                overlap = len(t_chars & p_chars) / len(p_chars)
                if overlap > 0.92 and len(p) > 20:
                    # Plus: a 6-char shingle from phrase appears in text
                    if any(p[i:i+6] in text_norm for i in range(0, len(p)-6, 3)):
                        return phrase
        return None

    # ============================================================
    # v0.6.1: Anti-narrative-duplication checks
    # ============================================================
    # Triggered by cross-LLM regression test: lazy adversarial review filled 12 m6 rows
    # with identical "项目方派发的内幕派发方" string, 5 section interpretations
    # all = "本节数据已落地, 详见证据图", 3 key_takeaways all identical.
    # These pass V_WRITABLE_TOO_SHORT (length > 20) but produce useless report.
    #
    # 3 specific anti-dup rules — calibrated to allow some natural overlap
    # but reject obvious copy-paste filling. Threshold 70% for arrays > 5
    # items, all-identical for arrays = 3 items.

    def _check_no_narrative_duplication(self, filled: dict) -> None:
        """Detect lazy LLM patterns where N narrative items are all same string."""
        # Rule 1: lineage.m6.rows[].identity_narrative + status_narrative
        # 12 rows is typical; > 70% identical meanslaziness.
        m6_rows = filled.get("lineage", {}).get("m6", {}).get("rows", [])
        if len(m6_rows) >= 5:
            self._check_array_field_uniqueness(
                items=[r.get("identity_narrative") for r in m6_rows],
                field_path="lineage.m6.rows[].identity_narrative",
                error_code="V_NARRATIVE_DUPLICATION",
                threshold_pct=70,
            )
            self._check_array_field_uniqueness(
                items=[r.get("status_narrative") for r in m6_rows],
                field_path="lineage.m6.rows[].status_narrative",
                error_code="V_NARRATIVE_DUPLICATION",
                threshold_pct=70,
            )

        # Rule 2: 5 section interpretations (multi_chain / tge / alloc /
        # cex_trace / liq). > 60% identical (3 of 5) meanslaziness.
        section_interps = []
        for sec in ("multi_chain", "tge", "alloc", "cex_trace", "liq"):
            v = filled.get(sec, {}).get("interpretation")
            if isinstance(v, str):
                section_interps.append((sec, v))
        if len(section_interps) >= 4:
            self._check_array_field_uniqueness(
                items=[v for _, v in section_interps],
                field_path="*.interpretation (multi_chain/tge/alloc/cex_trace/liq)",
                error_code="V_INTERPRETATION_DUPLICATION",
                threshold_pct=60,
            )

        # Rule 3: holdings_distribution.key_takeaways[] — typically 3 items;
        # all 3 identical = obviouslaziness. Threshold = 100% (all same).
        takeaways = filled.get("holdings_distribution", {}).get("key_takeaways", [])
        if len(takeaways) >= 2:
            unique = {t for t in takeaways if isinstance(t, str) and len(t) > 5}
            if len(takeaways) >= 3 and len(unique) == 1:
                self.errors.append(
                    f"V_KEY_TAKEAWAYS_DUPLICATION: holdings_distribution."
                    f"key_takeaways has {len(takeaways)} items, all identical: "
                    f"{takeaways[0][:60]!r}. LLM must write distinct insights."
                )

        # Rule 4: anomaly.detector_summary[].detail — typically 4 items;
        # all 4 identical = laziness.
        detectors = filled.get("anomaly", {}).get("detector_summary", [])
        if len(detectors) >= 3:
            self._check_array_field_uniqueness(
                items=[d.get("detail") for d in detectors],
                field_path="anomaly.detector_summary[].detail",
                error_code="V_DETECTOR_DUPLICATION",
                threshold_pct=70,
            )

    # ============================================================
    # v0.6.4: Narrative-vs-locked semantic consistency check
    # ============================================================
    # For each narrative slot strongly coupled to a locked field, define
    # phrase patterns that MUST NOT appear when the locked field has
    # certain values. Catches the "LLM dismisses a catalyst that the
    # pipeline clearly captured" failure mode (STAR 2026-05-25:
    # cex_trace.tier locked to "S2" + Binance perp listing 10d ago, but
    # narrative said "perp 未确认" — both an LLM and adversarial review did this).
    #
    # Design notes:
    # - Phrase patterns are conservative substrings (long enough to avoid
    #   incidental matches) anchored to specific contradictions.
    # - Only triggers when locked condition is met AND forbidden phrase
    #   appears AND narrative is non-trivial length (> 30 chars).
    # - Each pair documents the specific locked → forbidden mapping.

    # locked condition → list of forbidden phrases (lowercase substring match)
    _NARRATIVE_VS_LOCKED_RULES = [
        {
            "name": "cex_trace.tier S2/S3 must not deny CEX catalyst",
            "locked_path": "cex_trace.tier",
            "locked_predicate": lambda v: isinstance(v, str) and v in ("S2", "S3"),
            "narrative_paths": [
                "cex_trace.interpretation",
                "verdict.one_liner",
                "anomaly.verdict_impact",
            ],
            "forbidden_phrases": [
                # Chinese
                "perp 未上",
                "perp 未确认",
                "perp 未在 snapshot 中确认",
                "perp 等覆盖未在",
                "未确认是否上 perp",
                "未上 perp",
                "cex 催化未确认",
                "cex 催化不突出",
                "cex 催化线索不突出",
                "交易所催化线索目前不突出",
                "交易所催化线索不突出",
                "永续未上线",
                "永续未确认",
                "没有明确的近期 cex 催化",
                "没有明确的 cex 催化",
                "无 cex 催化",
                # English
                "no perp catalyst",
                "perp coverage unconfirmed",
                "no cex catalyst",
                "cex catalyst unclear",
            ],
        },
        {
            "name": "rule_11 empty must not claim active insider distribution",
            "locked_path": "lineage.m6.rows",
            "locked_predicate": lambda v: isinstance(v, list) and len(v) == 0,
            "narrative_paths": [
                "verdict.one_liner",
                "anomaly.verdict_impact",
                "lineage.m4_notes",  # list of strings
            ],
            "forbidden_phrases": [
                # v0.7.15: 派发 (sell-out) AND 分发 (transfer) versions both
                # forbidden — LLM must not claim either when the underlying
                # detector hasn't fired. Old "派发" entries kept so a regressed
                # LLM still gets caught even after the term split.
                "active insider distribution",
                "内幕已确认派发",
                "内幕已确认分发",
                "内幕正在派发",
                "内幕正在分发",
                "项目方派发链路已确认",
                "项目方分发链路已确认",
                "派发链路清晰",
                "分发链路清晰",
                "active rule 11 distribution",
            ],
        },
        {
            "name": "deployer balance 0 must not claim deployer still holding",
            "locked_path": "holdings_distribution.role_rows",
            "locked_predicate": lambda v: isinstance(v, list) and any(
                r.get("role") == "DEPLOYER" and (r.get("total_balance") or 0) < 1
                for r in v
            ),
            "narrative_paths": [
                "verdict.one_liner",
                "alloc.interpretation",
                "holdings_distribution.key_takeaways",  # list of strings
            ],
            "forbidden_phrases": [
                "项目方仍持有大量筹码",
                "项目方仍持有大量",
                "项目方钱包持有大量",
                "deployer still holds significant",
                "deployer wallet still holding",
                "项目方未派发",   # legacy 派发 wording (kept for old-LLM regression)
                "项目方未分发",   # v0.7.15 — correct 分发 wording
            ],
        },
        {
            "name": "tier S1 must not claim CEX perp listing",
            "locked_path": "cex_trace.tier",
            "locked_predicate": lambda v: v == "S1",
            "narrative_paths": [
                "cex_trace.interpretation",
                "verdict.one_liner",
            ],
            "forbidden_phrases": [
                "已上 binance 永续",
                "binance 永续已上线",
                "perp 已上",
                "binance perp listed",
            ],
        },
    ]

    # v0.6.4 P0-B: negation-context skip. If the forbidden phrase appears
    # AFTER a negation marker (within ~25 chars before it), it's likely
    # being refuted, not asserted. Skip the match.
    # Examples (should NOT trigger):
    #   "并非无 cex 催化, 实际上是有的"
    #   "并不像 perp 未确认 那样, 已经上线了"
    #   "没有 perp 未确认 的情况, 已经在 5/14 上"
    # audit 2026-05-25 raised this FP risk.
    _NEGATION_MARKERS_RE = re.compile(
        r"(并\s*[非不未没]|并\s*没有|并\s*不是|"
        r"不是|没有|并\s*未|实际上|事实上|与\s*[此其]\s*相反|"
        r"恰\s*恰\s*相反|相反\s*的|相反\s*地|"
        r"not\s+(?:like|the\s+case|the\s+situation|true|that)|"
        r"contrary\s+to|"
        r"opposite\s+of|"
        r"refute[sd]?|"
        r"is\s+not\s+(?:the\s+case|true))"
    )

    def _phrase_is_negated(self, text_lower: str, phrase_lower: str) -> bool:
        """Check if EVERY `phrase` occurrence in `text` is in a negation
        context. Returns True if all occurrences are refuted (skip-safe),
        False if at least one occurrence has no negation marker before it
        (real violation).

        Scans up to 10 chars BEFORE each phrase occurrence for a negation
        marker (immediate-context only — wider windows let earlier
        refutations leak into later phrases' lookback). audit
        2026-05-25 raised the FP risk this addresses.
        """
        start = 0
        saw_negated = False
        while True:
            idx = text_lower.find(phrase_lower, start)
            if idx == -1:
                # No more occurrences. If we skipped at least one as
                # negated AND never found a non-negated one, all
                # occurrences were refuted → safe to skip phrase.
                return saw_negated
            window_start = max(0, idx - 10)
            window = text_lower[window_start:idx]
            if self._NEGATION_MARKERS_RE.search(window):
                saw_negated = True
                start = idx + len(phrase_lower)
                continue
            return False   # at least one occurrence without negation

    def _check_narrative_vs_locked_semantic(self, filled: dict) -> None:
        """v0.6.4 — narrative MUST NOT contradict locked field semantics."""
        for rule in self._NARRATIVE_VS_LOCKED_RULES:
            locked_val = self._resolve_dot_path(filled, rule["locked_path"])
            if not rule["locked_predicate"](locked_val):
                continue   # locked condition not met → no constraint
            # Locked condition triggered: check each narrative slot
            for nar_path in rule["narrative_paths"]:
                nar_val = self._resolve_dot_path(filled, nar_path)
                # Narrative can be a string OR a list of strings (e.g. m4_notes)
                texts = []
                if isinstance(nar_val, str):
                    texts.append((nar_path, nar_val))
                elif isinstance(nar_val, list):
                    for i, item in enumerate(nar_val):
                        if isinstance(item, str):
                            texts.append((f"{nar_path}[{i}]", item))
                for sub_path, text in texts:
                    if len(text) < 30:
                        continue   # too short to meaningfully contradict
                    text_lower = text.lower()
                    for phrase in rule["forbidden_phrases"]:
                        phrase_lower = phrase.lower()
                        if phrase_lower not in text_lower:
                            continue
                        # P0-B: skip if this phrase occurrence is in a
                        # negation context (refuted, not asserted).
                        if self._phrase_is_negated(text_lower, phrase_lower):
                            continue
                        self.errors.append(
                            f"V_NARRATIVE_VS_LOCKED_SEMANTIC: {sub_path} "
                            f"contains forbidden phrase {phrase!r} but "
                            f"locked field {rule['locked_path']!r} = "
                            f"{locked_val!r} ({rule['name']}). "
                            f"Narrative: {text[:80]!r}"
                        )
                        break   # one error per (rule, path) is enough

    @staticmethod
    def _resolve_dot_path(obj: dict, path: str):
        """Walk a dotted path through a nested dict. Returns None on miss."""
        cur = obj
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
            if cur is None:
                return None
        return cur

    # ============================================================
    # v0.7: cross_sym whale validation
    # ============================================================
    # Pipeline locks every whale's identity_classification_enum (computed
    # by identity_classifier.classify deterministically from behavior
    # signature). LLM only writes 2 narrative slots:
    #   - identity_narrative: WHY this classification (must cite ≥2 of the
    #     locked evidence_required_fields by name)
    #   - risk_assessment_narrative: trader-actionable read
    #
    # 4 validators (each one a hard gate):

    _IDENTITY_ENUM_WORDS = {
        # enum → list of phrases that imply the LLM is asserting this identity
        "KOL_MANAGER": [
            "kol manager", "kol 经理", "kol 操盘", "kol 管钱",
            "市场制造商管理", "项目方代理人",
        ],
        "ACTIVE_MM": [
            "主动做市", "主动 mm", "主动mm", "做市商", "做市操作",
            "active market maker", "active mm",
        ],
        "ARB_DESK": [
            "套利", "套利桌", "arb desk", "arbitrage desk", "arb 桌",
            "套利商", "套利团队",
        ],
        "OTC_DESK": [
            "otc desk", "otc 桌", "otc 团队", "场外 desk", "场外交易桌",
        ],
        "UNKNOWN_WHALE_HIGH_CROSS_SYM": [
            "未知大户", "身份不明的大户",
        ],
        "INSUFFICIENT_SIGNAL": [
            "信号不足", "数据不足以分类",
        ],
    }

    def _check_cross_sym_whales(self, skeleton: dict, filled: dict) -> None:
        """v0.7 — cross_sym whales: lock + narrative + identity consistency."""
        skel_whales = (skeleton.get("cross_sym") or {}).get("whales") or []
        fill_whales = (filled.get("cross_sym") or {}).get("whales") or []

        # V_CROSS_SYM_WHALES_INVARIANCE — count + address list must match
        skel_addrs = [(w.get("address") or "").lower() for w in skel_whales]
        fill_addrs = [(w.get("address") or "").lower() for w in fill_whales]
        if skel_addrs != fill_addrs:
            self.errors.append(
                f"V_CROSS_SYM_WHALES_INVARIANCE: filled.cross_sym.whales addresses "
                f"({fill_addrs}) differ from skeleton's ({skel_addrs}). "
                f"LLM cannot add, remove, or reorder whale candidates."
            )
            return  # Subsequent checks meaningless if list changed

        # Pair up by index for per-whale checks
        for i, (skel_w, fill_w) in enumerate(zip(skel_whales, fill_whales)):
            self._check_one_whale(i, skel_w, fill_w)

    # All pipeline-emitted fields per whale that must match between skeleton
    # and filled. Pipeline writes these; LLM can ONLY write the 2 narrative
    # slots (identity_narrative, risk_assessment_narrative). adversarial review final
    # audit 2026-05-25 flagged the original 2-field check as too narrow.
    _WHALE_LOCKED_KEYS = (
        # locked tier (pipeline-derived raw data)
        "address",
        "this_token_pct",
        "this_token_balance",
        "cross_sym_count",
        "cross_sym_tokens",
        "top_cross_sym_token",
        "arkham_label",
        "pre_launch_insider_count",
        "pre_launch_insider_tokens",
        "behavior_signature",
        # derived_locked tier (pipeline applies decision tree)
        "identity_classification_enum",
        "confidence_score",
        "evidence_required_fields",
        # v0.7.7 whale role classifier output (6-step on-chain analysis)
        "role_classification",
    )

    def _check_one_whale(self, idx: int, skel: dict, fill: dict) -> None:
        path_base = f"cross_sym.whales[{idx}]"

        # V_CROSS_SYM_CLASSIFICATION_LOCKED — every pipeline-emitted field is
        # locked. adversarial review final audit 2026-05-25 REJECT fix: previously only
        # checked identity_classification_enum + confidence_score, leaving
        # ~11 other fields LLM-tamperable.
        for locked_key in self._WHALE_LOCKED_KEYS:
            skel_val = skel.get(locked_key)
            fill_val = fill.get(locked_key)
            if skel_val != fill_val:
                # Truncate displayed values for readability
                self.errors.append(
                    f"V_CROSS_SYM_CLASSIFICATION_LOCKED: {path_base}.{locked_key} "
                    f"modified by LLM: skeleton={_summary(skel_val)!r}, "
                    f"filled={_summary(fill_val)!r}. "
                    f"All pipeline-emitted whale fields are locked."
                )

        # V_CROSS_SYM_NARRATIVE_MUST_CITE_EVIDENCE
        evidence_required = skel.get("evidence_required_fields") or []
        narrative = fill.get("identity_narrative") or ""
        if not isinstance(narrative, str) or len(narrative.strip()) < 30:
            # Too-short narrative also fails (defense in depth)
            # If empty / placeholder still present, R12 catches it separately.
            return
        if evidence_required:
            # Count how many of the evidence_required field names appear in the
            # narrative text (substring match). LLM should cite them by name
            # OR include a number that matches the locked value.
            cited = 0
            for field in evidence_required:
                if field.lower() in narrative.lower():
                    cited += 1
                    continue
                # Also accept if narrative contains the locked numeric value
                # for that field (e.g. "9 个其他 Alpha 币" cites cross_sym_count=9)
                sig = skel.get("behavior_signature") or {}
                val_candidates = [
                    skel.get(field),
                    sig.get(field),
                ]
                for v in val_candidates:
                    if v is None or v == "":
                        continue
                    # numeric: search for the integer or rounded-percent rendering
                    try:
                        v_num = float(v)
                        # Try int + 1-2 decimal renderings
                        if str(int(v_num)) in narrative:
                            cited += 1
                            break
                        if v_num < 1 and f"{v_num*100:.0f}%" in narrative:
                            cited += 1
                            break
                        if f"{v_num:.2f}" in narrative or f"{v_num:.1f}" in narrative:
                            cited += 1
                            break
                    except (ValueError, TypeError):
                        if str(v) in narrative:
                            cited += 1
                            break
            if cited < 2:
                self.errors.append(
                    f"V_CROSS_SYM_NARRATIVE_MUST_CITE_EVIDENCE: {path_base}."
                    f"identity_narrative cites only {cited}/{len(evidence_required)} "
                    f"required evidence fields ({evidence_required!r}). Narrative "
                    f"must cite ≥2 (by field name OR locked numeric value). "
                    f"Got: {narrative[:120]!r}"
                )

        # V_CROSS_SYM_NARRATIVE_NO_FREELANCE_IDENTITY — narrative cannot
        # assert an identity different from the locked enum.
        locked_enum = skel.get("identity_classification_enum")
        if not locked_enum:
            return
        narrative_lower = narrative.lower()
        for other_enum, phrases in self._IDENTITY_ENUM_WORDS.items():
            if other_enum == locked_enum:
                continue   # same enum, OK to mention
            for phrase in phrases:
                if phrase.lower() in narrative_lower:
                    # Check for negation context to avoid FP — reuse Phase v0.6.4 helper
                    if self._phrase_is_negated(narrative_lower, phrase.lower()):
                        continue
                    self.errors.append(
                        f"V_CROSS_SYM_NARRATIVE_NO_FREELANCE_IDENTITY: {path_base}."
                        f"identity_narrative asserts identity {other_enum!r} via "
                        f"phrase {phrase!r}, but locked enum is {locked_enum!r}. "
                        f"LLM cannot override pipeline classification."
                    )
                    return  # one error per whale is enough

    # v0.7.7: wash_infrastructure section lock + narrative validation.
    _WASH_INFRA_LOCKED_KEYS = (
        "executor_X",
        "maker_buy_P",
        "maker_sell_Q",
        "atomic_pair_ratio",
        "p_drift_pct",
        "q_drift_pct",
        "p_tok_in",
        "q_tok_in",
        "tx_from_diversity",
        "classification",
    )

    _WASH_INFRA_CLASS_VALID = {
        "wash_infrastructure_routed",
        "wash_infrastructure_operator_controlled",
        "wash_infrastructure_ambiguous",
    }

    # v0.7.7: top-level wash section metadata is also pipeline-locked.
    # Cross-LLM security audit follow-up: previously these fields were not
    # locked by `_check_wash_infrastructure`, letting an LLM silently
    # alter `_credits_used` / `_n_candidates_scanned` / `_skip_reason`
    # / `_pipeline_source`.
    _WASH_INFRA_SECTION_LOCKED_KEYS = (
        "_pipeline_source",
        "_credits_used",
        "_n_candidates_scanned",
        "_skip_reason",
    )

    def _check_wash_infrastructure(self, skeleton: dict, filled: dict) -> None:
        """v0.7.7 — wash_infrastructure section locked + writable validation.

        Pipeline emits the X / P / Q triplet and 5-step structural metrics
        as derived_locked. LLM may only write investigation_narrative per
        setup + the section-level summary_narrative.
        """
        skel_wi = skeleton.get("wash_infrastructure") or {}
        fill_wi = filled.get("wash_infrastructure") or {}

        for k in self._WASH_INFRA_SECTION_LOCKED_KEYS:
            if skel_wi.get(k) != fill_wi.get(k):
                self.errors.append(
                    f"V_WASH_INFRA_SECTION_LOCKED: wash_infrastructure.{k} "
                    f"modified by LLM: skeleton={_summary(skel_wi.get(k))!r}, "
                    f"filled={_summary(fill_wi.get(k))!r}"
                )

        skel_setups = skel_wi.get("setups") or []
        fill_setups = fill_wi.get("setups") or []

        if len(skel_setups) != len(fill_setups):
            self.errors.append(
                f"V_WASH_INFRA_SETUPS_INVARIANCE: filled.wash_infrastructure.setups "
                f"length ({len(fill_setups)}) differs from skeleton "
                f"({len(skel_setups)}). LLM cannot add / remove setups."
            )
            return

        skel_executors = [(s.get("executor_X") or "").lower() for s in skel_setups]
        fill_executors = [(s.get("executor_X") or "").lower() for s in fill_setups]
        if skel_executors != fill_executors:
            self.errors.append(
                f"V_WASH_INFRA_SETUPS_INVARIANCE: filled.wash_infrastructure.setups "
                f"executor_X list ({fill_executors}) differs from skeleton "
                f"({skel_executors}). LLM cannot reorder setups."
            )
            return

        for idx, (skel_s, fill_s) in enumerate(zip(skel_setups, fill_setups)):
            path_base = f"wash_infrastructure.setups[{idx}]"
            for locked_key in self._WASH_INFRA_LOCKED_KEYS:
                if skel_s.get(locked_key) != fill_s.get(locked_key):
                    self.errors.append(
                        f"V_WASH_INFRA_LOCKED: {path_base}.{locked_key} modified "
                        f"by LLM: skeleton={_summary(skel_s.get(locked_key))!r}, "
                        f"filled={_summary(fill_s.get(locked_key))!r}"
                    )
            cls_val = skel_s.get("classification")
            if cls_val and cls_val not in self._WASH_INFRA_CLASS_VALID:
                self.errors.append(
                    f"V_WASH_INFRA_CLASS_ENUM: {path_base}.classification "
                    f"{cls_val!r} not in valid set {sorted(self._WASH_INFRA_CLASS_VALID)!r}"
                )
            narr = fill_s.get("investigation_narrative") or ""
            if narr == "<LLM_NARRATIVE_PLACEHOLDER>" or not narr.strip():
                self.errors.append(
                    f"V_WASH_INFRA_NARRATIVE_MISSING: {path_base}."
                    f"investigation_narrative is empty / placeholder"
                )

    def _check_array_field_uniqueness(
        self,
        items: list,
        field_path: str,
        error_code: str,
        threshold_pct: int,
    ) -> None:
        """Helper: if > threshold_pct% of items share the same string, fail.

        v0.6.4: normalizes per-item content before counting — strips digits,
        normalizes whitespace, lowercases — so that
        boilerplate-with-fact-substitution evasion (e.g. "上线前发现 2 个相关
        接收地址,..." vs "上线前发现 0 个相关接收地址,...", differing only
        in the count) collapses to the same normalized form and triggers
        the duplication check.

        Strips items that are None, empty, or stub strings.
        """
        import re
        valid = [i for i in items if isinstance(i, str) and len(i) > 5]
        if len(valid) < 3:
            return   # too few items to judge

        def _norm(s: str) -> str:
            # Strip digits (1 / 12 / 2.5 / 99.9% etc.) and dollar amounts
            s = re.sub(r"[\d,.]+%?", "N", s)
            s = re.sub(r"\$[\d,.kKmM]+", "$X", s)
            # Normalize whitespace + lowercase
            s = re.sub(r"\s+", " ", s.strip().lower())
            return s
        from collections import Counter
        # v0.6.4: dual check — exact match AND normalized match (the latter
        # catches boilerplate-with-fact-substitution evasion). P0-D fix
        # (adversarial review 2026-05-25 audit): normalized check uses a HIGHER threshold
        # (+15pp, capped at 95) AND requires the normalized form to be
        # substantive (≥30 chars) — short normalized strings often share
        # structure across genuinely-distinct narratives (FP risk adversarial review
        # raised for "本类检测器命中" vs "另一类检测器命中").
        norm_threshold = min(threshold_pct + 15, 95)
        for label, key_fn, eff_threshold, require_min_len in (
            ("identical", lambda s: s, threshold_pct, 0),
            ("near-identical", _norm, norm_threshold, 30),
        ):
            counts = Counter(key_fn(s) for s in valid)
            most_common_str, most_common_n = counts.most_common(1)[0]
            ratio = most_common_n / len(valid) * 100
            if ratio <= eff_threshold:
                continue
            # P0-D: skip if normalized form is too short to meaningfully
            # signal duplication (short boilerplate naturally collides).
            if require_min_len and len(most_common_str) < require_min_len:
                continue
            # Find a representative original (not normalized) string
            sample = next(s for s in valid if key_fn(s) == most_common_str)
            self.errors.append(
                f"{error_code}: {field_path} has {most_common_n}/{len(valid)} "
                f"items ({ratio:.0f}%) sharing {label} narrative: "
                f"{sample[:80]!r}. LLM must write distinct content "
                f"for each item (threshold: {eff_threshold}%)."
            )
            return  # one error per field is enough

    # ============================================================
    # v0.7.3 narrative quality validators
    # ============================================================
    # Three soft-fail checks that catch dud narrative not caught by earlier
    # validators. v0.7.2 acceptance testing found two distinct failure modes:
    #   1. adversarial review/an LLM default to invoking tests/smoke_fill.py → caught by
    #      render_report.py smoke gate (v0.7.2).
    #   2. another LLM did real LLM fill but with boilerplate evasion like
    #      "该字段已沿邻近锁定数据补充叙述" repeated across slots, or
    #      hallucinated numbers that don't match locked fields → caught
    #      by the validators below (v0.7.3).
    # All three categorize as NARRATIVE_QUALITY so render still produces a
    # report (with warning header), but the agent gets clear feedback.

    # Phrase blacklist — observed boilerplate from cross-LLM testing that
    # carries no analytical content. Each phrase is a substring match on
    # casefolded narrative (case-insensitive). Conservative list: only
    # phrases that have NO legitimate analytical use case. Expanded only
    # after observing the phrase in real lazy-LLM output.
    _GENERIC_BOILERPLATE_PHRASES = (
        # another LLM v0.7.1 boilerplate (observed 2026-05-25):
        "该字段已沿邻近锁定数据补充叙述",
        "本字段已沿邻近锁定数据补充叙述",
        "沿邻近锁定数据补充叙述",
        # adversarial review smoke_fill template (observed 2026-05-25):
        "本节数据已落地, 关键读数与结论推理一致",
        "本节数据已落地，关键读数与结论推理一致",
        "关键读数与结论推理一致",
        # Other lazy patterns we've seen in cross-LLM testing:
        "详见证据图中对应",
        "请参考相邻锁定字段",
        "请参考邻近锁定字段",
        "请参考相关字段",
        "数据见上方",
        "见上方表格",
        "见上文",
        "见相邻字段",
        # English equivalents (an LLM sometimes mixes EN in ZH reports):
        "see adjacent locked fields",
        "see above",
        "refer to the locked data",
        "data has been populated",
    )

    def _check_narrative_generic_phrases(self, filled: dict) -> None:
        """V_NARRATIVE_GENERIC_PHRASES — reject narrative slots that contain
        observed-in-the-wild boilerplate phrases adding no analytical content.

        A phrase appearing once in a long narrative is OK (might be quoting).
        We flag when:
          - The phrase is present AND
          - The narrative is short (< 60 chars) — i.e. the phrase IS most of
            the content, not an aside.
        This avoids false-positives on legitimate narratives that happen to
        reference these phrases (e.g. discussing what NOT to write).
        """
        for path, text in self._iter_narrative_strings(filled):
            if not isinstance(text, str) or len(text) < 5:
                continue
            text_cf = text.casefold()
            for phrase in self._GENERIC_BOILERPLATE_PHRASES:
                phrase_cf = phrase.casefold()
                if phrase_cf not in text_cf:
                    continue
                # Length-gate: if narrative is mostly boilerplate, fire.
                if len(text) < 60:
                    self.errors.append(
                        f"V_NARRATIVE_GENERIC_PHRASES: {path} contains "
                        f"boilerplate phrase {phrase!r} and is too short "
                        f"({len(text)} chars) to carry independent content. "
                        f"Write a real interpretation tied to the locked "
                        f"data adjacent to this slot. Got: {text[:120]!r}"
                    )
                    break

    def _check_narrative_template_reuse(self, filled: dict) -> None:
        """V_NARRATIVE_TEMPLATE_REUSE — global cross-slot template detection.

        _check_no_narrative_duplication already catches per-array duplication
        (e.g. all 12 m6.rows.narrative identical). This check catches the
        CROSS-section case: writer uses one template across many independent
        slots (e.g. anomaly.detector_summary[].detail + section.interpretation
        + key_takeaways[] all share the same "本节数据已落地" template).

        Strategy: collect every narrative string across the whole filled
        document, normalize via the same _norm() as v0.6.4, count occurrences,
        flag the largest cluster if it covers > 25% of the corpus (and corpus
        size ≥ 8). Threshold 25% chosen empirically — another llm v0.7.1 report had
        the "该字段已沿邻近..." template covering ~40% of slots.
        """
        import re
        from collections import Counter
        # Collect narrative strings from the filled document.
        strings = []
        for path, text in self._iter_narrative_strings(filled):
            if not isinstance(text, str) or len(text) < 20:
                continue
            strings.append((path, text))
        if len(strings) < 8:
            return   # corpus too small to meaningfully detect templates
        # Same normalization as _check_array_field_uniqueness (strips digits,
        # dollar amounts, whitespace, case) so factual substitution doesn't
        # disguise template reuse.
        def _norm(s: str) -> str:
            s = re.sub(r"[\d,.]+%?", "N", s)
            s = re.sub(r"\$[\d,.kKmM]+", "$X", s)
            s = re.sub(r"\s+", " ", s.strip().lower())
            return s
        norm_to_paths: dict[str, list[str]] = {}
        for path, text in strings:
            key = _norm(text)
            if len(key) < 25:
                continue   # short normalized form, naturally collides
            norm_to_paths.setdefault(key, []).append(path)
        if not norm_to_paths:
            return
        counts = Counter({k: len(v) for k, v in norm_to_paths.items()})
        top_key, top_n = counts.most_common(1)[0]
        ratio = top_n / len(strings) * 100
        if ratio < 25 or top_n < 3:
            return
        # Representative original string for the offender cluster
        sample_paths = norm_to_paths[top_key]
        sample_text = next(
            text for path, text in strings if _norm(text) == top_key
        )
        self.errors.append(
            f"V_NARRATIVE_TEMPLATE_REUSE: {top_n}/{len(strings)} narrative "
            f"slots ({ratio:.0f}%) share the same normalized template. "
            f"Write distinct content per slot. Offender (sample): "
            f"{sample_text[:120]!r}. Paths: {sample_paths[:5]}"
            f"{' ...' if len(sample_paths) > 5 else ''}"
        )

    def _check_narrative_numeric_hallucination(self, filled: dict) -> None:
        """V_NARRATIVE_NUMERIC_HALLUCINATION — every concrete number cited in
        a narrative slot must appear in some locked numeric field nearby,
        within ±5% relative tolerance (or ±0.5 absolute for small numbers).

        Catches LLMs that invent plausible-looking numbers in narrative:
        - "操盘者持有 0.5%" when locked.pct_of_total = 0.19%
        - "派发了约 $1.2M" when locked.usd_value = $244,000
        - "12 小时前" when actual timestamp is 36 hours ago

        Excluded number patterns (high false-positive risk):
        - Tx hash short forms (0x followed by hex)
        - Ratio-like phrasing ("3:1", "2/3")
        - Common ordinals ("第 1 个", "第二个")
        - Single digits in regulation-text contexts (Rule 11, S1, S2, etc.)

        Tolerance: a narrative number N matches locked L if either:
          |N - L| / max(|L|, 1) <= 0.05  (5% relative)
          |N - L| <= 0.5                  (absolute, for small N/L)
        """
        import re
        # Collect every numeric value from the locked side. We pool from the
        # whole filled document (not just adjacent fields) — narrative may
        # reference numbers computed elsewhere. Tolerance is the gate.
        locked_numbers = self._collect_all_numbers(filled)
        if not locked_numbers:
            return
        # Number regex: matches integers and floats with optional %, K, M, B
        # suffix or $ prefix. Captures the bare numeric value.
        # v0.7.3 P1 (E2E found): allow comma-thousands separator so
        # "$282,740" matches as one number, not "$282" + "740".
        num_re = re.compile(
            r"(?<![\w0-9])"                              # not preceded by letter/digit
            r"\$?([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)"    # 1 / 1,234 / 1,234.56
            r"\s?([%KkMmBb])?"                           # optional unit suffix
            r"(?![\w])"                                  # not followed by letter
        )
        # Skip patterns — narrative contexts where embedded numbers are
        # rules/identifiers/time-ago, not factual claims.
        skip_re = re.compile(
            r"(?:0x[0-9a-fA-F]{4,}"             # tx hash / address
            r"|rule\s*1?1"                       # Rule 11
            r"|s[123]\b"                         # S1/S2/S3 tier markers
            r"|m[3-9]\b"                         # M3-M9 detector codes
            r"|d[1-9]\b"                         # D1-D9 detector codes
            r"|第\s*[一二三四五六七八九十百]"      # Chinese ordinals
            # Time-ago / duration phrases — these numbers are derived from
            # now(), not stored in any locked field. Skip the whole window.
            r"|\d+\s*(?:小时|分钟|秒|天|周|月|年|hour|minute|second|day|week|month|year)s?\s*(?:前|ago)?"
            r"|约\s*\d+\s*(?:小时|分钟|天|周|月|h\b)"  # 约 12 小时
            r"|\d+\s*[-–]\s*\d+\s*(?:小时|h|天|day)"   # 12-24h ranges
            # Section / chapter markers
            r"|chapter\s*\d+"
            # Times: HH:MM, HH:MM:SS — narrative often quotes evt timestamps
            r"|\d{1,2}:\d{2}(?::\d{2})?"
            # Dates: YYYY-MM-DD (the year is already skipped, but day/month digits
            # remain — easier to skip the whole token).
            r"|\d{4}-\d{1,2}-\d{1,2}"
            # List size / rank: "Top-100 holder", "前 100 持币", "top 5"
            r"|top\s*-?\s*\d+"
            r"|前\s*\d+\s*(?:大|名|个|位)?"
            r")",
            re.IGNORECASE,
        )
        hits = []   # collect to emit one consolidated error
        for path, text in self._iter_narrative_strings(filled):
            if not isinstance(text, str) or len(text) < 30:
                continue
            # v0.7.14 (adversarial review HIGH #1): no path-based exemption here. An earlier
            # patch skipped `m4_notes[0]` because the pipeline-authored Rule 11
            # summary cited numbers (mint_amount etc.) that were not mirrored as
            # standalone locked numeric fields, so they tripped the hallucination
            # check. But `lineage.m4_notes[]` is WRITABLE — exempting index 0
            # would let an LLM smuggle a fabricated number through. The proper
            # fix is upstream: forensic_pipeline now exposes those numbers as
            # `lineage.summary_locked_numbers`, so they enter the locked-number
            # pool naturally and m4_notes[0] passes without an exemption.
            # Mask out skip patterns so their embedded digits don't surface.
            masked = skip_re.sub(" SKIP ", text)
            for m in num_re.finditer(masked):
                raw = m.group(1)
                suffix = (m.group(2) or "").lower()
                try:
                    # Strip comma-thousands separators before float parse.
                    val = float(raw.replace(",", ""))
                except ValueError:
                    continue
                # Apply unit suffix
                if suffix == "%":
                    # Percentages can be stored as 0.x ratio OR raw % — check both
                    candidates = (val, val / 100.0)
                elif suffix == "k":
                    candidates = (val * 1_000,)
                elif suffix == "m":
                    candidates = (val * 1_000_000,)
                elif suffix == "b":
                    candidates = (val * 1_000_000_000,)
                else:
                    candidates = (val,)
                # FP guard: ignore very small bare numbers (1-10 with no
                # unit) — often "3 weeks ago", "Top 5", "2 days", indices.
                if not suffix and val < 10:
                    continue
                # Ignore 4-digit years (2024-2027).
                if not suffix and 2020 <= val <= 2030:
                    continue
                if not any(self._number_matches(c, locked_numbers) for c in candidates):
                    hits.append((path, m.group(0), candidates))
        # Emit a max of 5 hits per validator run to keep error log readable.
        for path, snippet, candidates in hits[:5]:
            cand_str = ", ".join(f"{c:.4g}" for c in candidates)
            self.errors.append(
                f"V_NARRATIVE_NUMERIC_HALLUCINATION: {path} mentions number "
                f"{snippet!r} (parsed as {cand_str}) which does not match "
                f"any locked numeric field within ±5%. Either cite the "
                f"locked value verbatim or rephrase to avoid the number."
            )
        if len(hits) > 5:
            self.errors.append(
                f"V_NARRATIVE_NUMERIC_HALLUCINATION: ...and {len(hits)-5} "
                f"more unmatched numbers across narrative slots (showing "
                f"first 5)."
            )

    # --- helpers for the 3 v0.7.3 validators ---

    _NARRATIVE_LEAF_SUFFIXES = (
        ".one_liner", ".verdict_impact", ".interpretation", ".detail",
        ".nature", ".identity_narrative", ".risk_assessment_narrative",
        ".status_narrative", ".alert", ".rationale", ".narrative",
        ".summary_narrative", ".monitoring_footer", ".hours_ago_text",
        ".status_text",
    )

    def _iter_narrative_strings(self, filled):
        """Yield (path, string) pairs for every writable narrative slot.
        Path uses dotted notation with [i] for list indices. Skips
        non-narrative metadata (anything starting with `_`)."""
        stack = [("", filled)]
        while stack:
            path, node = stack.pop()
            if isinstance(node, str):
                # Only yield strings whose path looks like a narrative slot.
                if any(path.endswith(suf) for suf in self._NARRATIVE_LEAF_SUFFIXES):
                    yield path, node
                # Also yield list items of narrative arrays (key_takeaways[])
                elif "key_takeaways" in path or "m4_notes" in path:
                    yield path, node
            elif isinstance(node, dict):
                for k, v in node.items():
                    if k.startswith("_"):
                        continue
                    stack.append((f"{path}.{k}" if path else k, v))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    stack.append((f"{path}[{i}]", v))

    def _collect_all_numbers(self, filled):
        """Walk the whole filled doc and collect every numeric value
        from non-narrative fields. Used by numeric hallucination check."""
        numbers = set()
        stack = [("", filled)]
        while stack:
            path, node = stack.pop()
            if isinstance(node, (int, float)) and not isinstance(node, bool):
                numbers.add(float(node))
            elif isinstance(node, str):
                # Don't trust strings — narrative slots are filled with
                # strings too. But locked numeric fields are stored as
                # actual int/float in JSON, so the float-walk above is
                # sufficient.
                pass
            elif isinstance(node, dict):
                for k, v in node.items():
                    if k.startswith("_"):
                        continue
                    # Skip narrative leaves — they're what we're validating.
                    if any(k == suf.lstrip(".") for suf in self._NARRATIVE_LEAF_SUFFIXES):
                        continue
                    stack.append((f"{path}.{k}" if path else k, v))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    stack.append((f"{path}[{i}]", v))
        return numbers

    @staticmethod
    def _number_matches(val: float, locked_numbers: set) -> bool:
        """True if val is within ±5% relative or ±0.5 absolute of any
        number in locked_numbers.

        v0.9.6 Fix #4 (adversarial review Windows EVAA 2026-06-15 feedback): also
        match on MAGNITUDE (|val| vs |L|). The narrative regex extracts
        unsigned digits — e.g. "余额 -591" parses as 591. The locked
        field is signed (`balance_tokens: -590.5980...`). Pre-v0.9.6,
        591 vs -590.598 failed both relative (591 + 590.598 = 1181.6,
        ratio 2.0 ≫ 5%) and absolute (>0.5) checks, hard-failing the
        render with V_NARRATIVE_NUMERIC_HALLUCINATION even though the
        narrative was correctly referring to the locked quantity.
        Magnitude fallback closes this false positive.
        """
        val_abs = abs(val)
        for L in locked_numbers:
            denom = max(abs(L), 1.0)
            # Signed exact (or near) match: original behavior.
            if abs(val - L) / denom <= 0.05:
                return True
            if abs(val - L) <= 0.5:
                return True
            # Magnitude fallback: narrative may strip the sign.
            L_abs = abs(L)
            if abs(val_abs - L_abs) / denom <= 0.05:
                return True
            if abs(val_abs - L_abs) <= 0.5:
                return True
        return False


## v0.7.1: Error categorization for soft-fail vs hard-abort.

# Error code prefixes that indicate LLM tampered locked data, pipeline
# regression, or security boundary breach. These NEVER let the report
# render — render_report.py must abort with exit 1.
STRUCTURAL_ERROR_PREFIXES = (
    "V_LOCKED_FIELD_",            # locked field modified or absent
    "V_SCHEMA_VERSION",           # schema mismatch
    "V_CROSS_SYM_WHALES_INVARIANCE",       # LLM added/removed whales
    "V_CROSS_SYM_CLASSIFICATION_LOCKED",   # LLM tampered classification
    "V_R12_PLACEHOLDERS_REMAIN",  # placeholder leaked to output
    "V_PROVENANCE_",              # provenance chain broken
    "V_CAUSAL_RULE11",            # rule 11 pipeline regression
    "V_R2_M6_NO_DETECTOR",        # pipeline didn't emit detector
    "V_R10_DETECTOR_TOO_FEW",     # pipeline regression
    "V_NO_DATA_SOURCE_LEAK",      # security
    "V_WRITABLE_COUNT",           # array length mismatch
    "V_INVALID_AUTHORITY",        # YAML config corrupt
)

# Error code prefixes that are RECOVERABLE — narrative quality issues.
# Render the report anyway with warning. Caller (AI agent) may re-fill
# the specific narrative slot and re-render to clear.
NARRATIVE_QUALITY_ERROR_PREFIXES = (
    "V_WRITABLE_TOO_SHORT",
    "V_NARRATIVE_DUPLICATION",
    "V_INTERPRETATION_DUPLICATION",
    "V_KEY_TAKEAWAYS_DUPLICATION",
    "V_DETECTOR_DUPLICATION",
    "V_CROSS_SYM_NARRATIVE_MUST_CITE_EVIDENCE",
    "V_CROSS_SYM_NARRATIVE_NO_FREELANCE_IDENTITY",
    "V_NARRATIVE_VS_LOCKED_SEMANTIC",
    "V_META_LANGUAGE",
    "V_R7_RHYTHM_MATCHES_WAVES",
    # v0.7.3 narrative quality validators
    "V_NARRATIVE_GENERIC_PHRASES",
    "V_NARRATIVE_TEMPLATE_REUSE",
    "V_NARRATIVE_NUMERIC_HALLUCINATION",
)


def categorize_errors(errors: list[str]) -> tuple[list[str], list[str]]:
    """Split errors into (structural, narrative_quality) lists.

    An error is structural if its code starts with any prefix in
    STRUCTURAL_ERROR_PREFIXES. Otherwise it's classified as narrative
    quality.

    Unknown prefixes default to STRUCTURAL (fail-closed): if a new error
    code is added without updating this categorizer, it goes into the
    abort path until explicitly classified.

    v0.7.19.5: V_NARRATIVE_NUMERIC_HALLUCINATION is now classified as
    STRUCTURAL by default — a hardcoded number in narrative that does
    not match any locked field is a DATA CORRECTNESS bug (the report
    self-contradicts its own locked tables), not a style preference.
    The COLLECT v0.7.19.4 rerun (price had moved from $0.0578 to $0.0522,
    LP from $635K to None / $1.82M, entry_cap from $8K to $9,239) had
    4 such warnings — they were soft-passed by render, the report
    shipped with "$8K" while the locked decision-summary table said
    "$9,239" right next to it. Set
    BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS=1 (truthy) to keep the old
    soft-warning behavior for dev / CI flows that intentionally test
    against stale fixtures.
    """
    import os as _os
    allow_numeric_warn = _os.environ.get(
        "BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS", ""
    ).lower() in ("1", "true", "yes", "on")

    structural = []
    narrative = []
    for err in errors:
        # Error format: "V_CODE: details"
        code = err.split(":", 1)[0].strip()
        is_narrative = any(code.startswith(p) for p in NARRATIVE_QUALITY_ERROR_PREFIXES)
        is_structural = any(code.startswith(p) for p in STRUCTURAL_ERROR_PREFIXES)
        # v0.7.19.5: NUMERIC_HALLUCINATION is structural-by-default unless
        # the dev opted in via env. This keeps the COLLECT-class
        # narrative-vs-locked mismatch from ever shipping again.
        if (code == "V_NARRATIVE_NUMERIC_HALLUCINATION"
                and not allow_numeric_warn):
            structural.append(err)
            continue
        if is_narrative and not is_structural:
            narrative.append(err)
        else:
            structural.append(err)
    return structural, narrative


def _summary(v) -> str:
    """Truncate a value for error messages."""
    s = json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= 80 else s[:77] + "..."


def main() -> int:
    # Beta.15: force UTF-8 stdout/stderr (Windows cp1252 console fix).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--skeleton", required=True, help="Pipeline output (pre-LLM-fill)")
    ap.add_argument("--filled", required=True, help="LLM-filled JSON")
    ap.add_argument("--quiet", action="store_true")
    # v0.6.0-alpha.3 (adversarial review feedback): removed --yaml and --corpus CLI flags.
    # Allowing override created a validator bypass surface: adversarial review demonstrated
    # passing v0.6.0-alpha.2 by moving the locked line for action_enum out of
    # a custom yaml. Hardcoded to schema/ directory now; no opt-out.
    args = ap.parse_args()

    skel = json.loads(Path(args.skeleton).read_text(encoding="utf-8"))
    filled = json.loads(Path(args.filled).read_text(encoding="utf-8"))

    v = Validator()  # locked to schema/ defaults
    errors = v.validate(skel, filled)

    if errors:
        structural, narrative = categorize_errors(errors)
        if structural:
            print(f"V_SEMANTIC_VALIDATION STRUCTURAL FAIL: {len(structural)} blocking issue(s):", file=sys.stderr)
            for i, e in enumerate(structural, 1):
                print(f"  {i}. {e}", file=sys.stderr)
        if narrative:
            print(f"V_SEMANTIC_VALIDATION NARRATIVE_QUALITY: {len(narrative)} recoverable issue(s):", file=sys.stderr)
            for i, e in enumerate(narrative, 1):
                print(f"  {i}. {e}", file=sys.stderr)
        return 1 if structural else 2
    if not args.quiet:
        print(f"OK: validator pass ({len(filled.get('evidence_graph', {}))} evidence entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
