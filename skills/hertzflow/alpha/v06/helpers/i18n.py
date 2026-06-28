#!/usr/bin/env python3
"""i18n.py — single-source-of-truth language loader for v0.6.2.

v0.6.1 had ~221 hardcoded Chinese strings across 13 files. Users running
the skill in English contexts (adversarial review / other LLMs / English-speaking analysts)
got Chinese reports they couldn't read. v0.6.2 centralizes all user-facing
strings into lang/<lang>.yaml files.

Usage:
    from helpers.i18n import t, set_lang
    set_lang("en")
    print(t("verdict.cn_label.EXIT_IF_HOLDING"))  # → "Exit if holding"
    print(t("rule_11.wave_title.pre_launch_otc"))  # → "Wave 1 pre-launch OTC distribution"

Key paths use dots: `section.<name>.<label>`. Supports `.format()` interp
on values that contain `{placeholder}` patterns.

Lang files live at v06/lang/<lang>.yaml. Default lang = "zh". Set via
`set_lang("en")` or env var `BINANCE_ALPHA_LANG=en`.

Fail mode: if a key is missing in the requested lang, fall back to "zh"
(the original source). If missing in BOTH, return the key itself as
visible-fail (so devs notice the gap).
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any


_LANG_DIR = Path(__file__).parent.parent / "lang"
_CACHE: dict[str, dict[str, Any]] = {}
_CURRENT_LANG: str = os.environ.get("BINANCE_ALPHA_LANG", "zh")


def _load_lang(lang: str) -> dict[str, Any]:
    """Load lang/<lang>.json into a flat dotted-key dict. Cached after first load.

    v0.6.2 design choice: JSON (stdlib, zero-dep) over YAML (would require
    PyYAML pip-install). YAML's prettier syntax not worth the dep risk for
    static config files.
    """
    if lang in _CACHE:
        return _CACHE[lang]
    path = _LANG_DIR / f"{lang}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"i18n lang file missing: {path}. Available: "
            f"{sorted(p.stem for p in _LANG_DIR.glob('*.json'))}"
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    # Flatten nested dicts → dotted keys
    flat: dict[str, Any] = {}
    _flatten(raw, "", flat)
    _CACHE[lang] = flat
    return flat


def _flatten(d: Any, prefix: str, out: dict[str, Any]) -> None:
    """Recursively flatten {"a": {"b": "x"}} → {"a.b": "x"}."""
    if isinstance(d, dict):
        for k, v in d.items():
            full = f"{prefix}.{k}" if prefix else k
            _flatten(v, full, out)
    else:
        # Leaf (str, list, int, etc.)
        out[prefix] = d


def set_lang(lang: str) -> None:
    """Switch active language. Subsequent t() calls use this lang."""
    global _CURRENT_LANG
    if lang not in ("zh", "en"):
        raise ValueError(f"unsupported lang: {lang!r} (supported: zh, en)")
    _CURRENT_LANG = lang


def get_lang() -> str:
    """Return active language."""
    return _CURRENT_LANG


def t(key: str, **kwargs: Any) -> str:
    """Translate a key. If key not found in active lang, fall back to zh.
    If missing in both, return the key itself (visible-fail marker).

    Optional **kwargs: passed to .format() if the value contains
    `{placeholder}` patterns.

    v0.6.2 strict mode (audit MED #4): set
    BINANCE_ALPHA_I18N_STRICT=1 to make missing en keys raise instead of
    silently falling back to zh. Useful for CI to catch key gaps before
    they ship Chinese leaks in English reports.
    """
    val = _lookup(key, _CURRENT_LANG)
    if val is None and _CURRENT_LANG != "zh":
        strict = os.environ.get("BINANCE_ALPHA_I18N_STRICT", "").strip()
        if strict in ("1", "true", "yes"):
            raise KeyError(
                f"i18n strict mode: key {key!r} missing in {_CURRENT_LANG!r} "
                f"(BINANCE_ALPHA_I18N_STRICT=1). Add the key to "
                f"lang/{_CURRENT_LANG}.json or unset strict mode."
            )
        val = _lookup(key, "zh")
    if val is None:
        return f"[MISSING:{key}]"   # devs notice
    if isinstance(val, str) and kwargs:
        try:
            return val.format(**kwargs)
        except (KeyError, IndexError):
            # Unfilled placeholder — return raw template so dev can see what was missing
            return val
        except (TypeError, ValueError) as e:
            # v0.7.13 (issue #1 Bug 2 class): a kwarg is None (or wrong type)
            # while the template applies a numeric format spec, e.g.
            # "${trigger:.6f}".format(trigger=None) → TypeError. The real fix
            # is at the call site (render None → "—" before calling t); this is
            # a last-resort net so one stray None can never crash a whole render.
            # adversarial review LOW #2: warn so this masked-bug path stays observable.
            print(f"[i18n] format fallback for key {key!r}: {type(e).__name__}: {e}", file=sys.stderr)
            # Strip each None placeholder (incl. its format spec) to a dash so
            # the surviving kwargs still interpolate cleanly.
            dash = _lookup("common.none_dash", _CURRENT_LANG) or _lookup("common.none_dash", "zh") or "—"
            patched = val
            safe = dict(kwargs)
            for k, v in kwargs.items():
                if v is None:
                    patched = re.sub(r"\{" + re.escape(k) + r"(?::[^}]*)?\}", dash, patched)
                    safe.pop(k, None)
            try:
                return patched.format(**safe)
            except (KeyError, IndexError, TypeError, ValueError):
                return patched
    return val


def _lookup(key: str, lang: str) -> Any:
    """Return the raw value for key in lang, or None if missing."""
    try:
        d = _load_lang(lang)
    except FileNotFoundError:
        return None
    return d.get(key)
