#!/usr/bin/env python3
"""monitoring_export.py — emit monitoring_wallets for Binance Wallet +
OKX Wallet bulk import via paste.

beta.16 final shape (2026-05-24, user实测 CSV reject + Windows mojibake):
- Binance Wallet + OKX wallet BOTH accept paste of `[{address, name,
  emoji}]` JSON. PASTE ROUTE ONLY — file upload abandoned.
- Binance Wallet CSV file upload: tested, format rejected.
- OKX wallet: no file upload option at all (paste only).
- GMGN bulk import: all probe formats rejected (beta.13/14).

Windows encoding fix (beta.16): paste.json emitted with
ensure_ascii=True so the file is pure ASCII bytes. Avoids the cp1252
mojibake user reported in beta.15 (Windows viewer displays UTF-8 中文
+ emoji as garbage Latin-1 chars; Ctrl+A Ctrl+C copies the mojibake
into Binance/OKX → garbage names imported). Binance/OKX JSON parsers
un-escape `\\uXXXX` sequences automatically; end-user sees correct
中文 + emoji in their tracker UI.

## Output files (per pipeline run, 2 files)

For a CA → `out_dir/monitoring/`:

- `monitoring_wallets_full.json` — canonical full schema (含 label /
  role / severity / alert / source_sym 完整字段). For own scripts /
  analytics. Not for tracker import.

- `monitoring_paste.json` — `[{address, name, emoji}]` paste format for
  Binance Wallet + OKX wallet. Pure ASCII bytes (Windows-safe).

## Usage

ONLY route — paste (both Binance Wallet + OKX):
  1. Open `monitoring_paste.json` in any text viewer
     (file is pure ASCII, no encoding concerns)
  2. Ctrl+A select all, Ctrl+C copy
  3. Open Binance Wallet OR OKX wallet bulk import → paste in text area
  4. Confirm/save — platform un-escapes \\uXXXX → 中文 + emoji rendered

## Label format (cross-tracker safe)

`<SYM>-<ROLE>-<addr5>` (e.g. "ZEST-Deployer-3a6dc"). ≤25 chars to clear
all known tracker char limits without truncation. Grep-stable.

ROLE enum maps to short tokens:
- Rule 11 Deployer        → Deployer
- Rule 11 Full Dumper     → Dumper
- Rule 11 Partial Dumper  → PDumper
- Rule 11 Quiet wallet    → Quiet
- DEX main LP             → LP
- Recent 72h anomaly      → Anomaly

v0.6 (2026-05-24, Phase B.5 restoration.)
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
from io import StringIO
from pathlib import Path
from typing import Any

from i18n import t   # v0.6.2 i18n


# Role enum → short token for label assembly.
# Order matters: more specific match first.
# 中文 → 中文 short token (beta.9 — user request: 钱包标注跟报告语言一致).
# Pipeline now emits Chinese role strings; tokens stay Chinese for GMGN
# tag matching. Order: most-specific first.
# v0.6.2 i18n: the LEFT side is the matching needle against pipeline /
# render-emitted role strings (always carries Chinese/English regardless
# of active lang, so it stays a literal). The RIGHT side is now an i18n
# KEY — _role_token() resolves it via t() at lookup time so the emitted
# short token follows the active lang (e.g. 庄家 vs Operator), as the
# write_all() docstring documents.
_ROLE_TOKEN_MAP = [
    # 中文 role strings from forensic_pipeline._build_monitoring_wallets.
    # v0.7.15 (派发/分发 术语统一): rule_11 链上转账场景一律用 "分发" 系列;
    # 旧 lang/zh.json 输出的 "派发" 系列仍保留映射,让 monitoring 能识别由
    # 上版本 render 出来的报告 — 不破老报告的钱包标注。
    ("项目方部署钱包", "role.DEPLOYER.short"),
    ("项目方钱包", "role.DEPLOYER.short"),
    # NEW (v0.7.15 — 链上"分发"系列). adversarial review LOW: more-specific BEFORE
    # general so a "分发中内幕钱包" wallet name is tagged via its own entry,
    # not the looser "分发中钱包" prefix.
    ("已分完内幕钱包", "role.RULE11_FULL.short"),
    ("分发中内幕钱包", "role.RULE11_PARTIAL.short"),
    ("分发中钱包", "role.RULE11_PARTIAL.short"),
    # LEGACY (pre-v0.7.15 — 旧 "派发" 系列, 仅用于老报告匹配); same ordering.
    ("已派完内幕钱包", "mon.token_full_dumper_legacy"),
    ("派发中内幕钱包", "mon.token_partial_legacy"),
    ("派发中钱包", "mon.token_partial_legacy"),
    ("潜伏钱包", "role.RULE11_QUIET.short"),
    ("庄家中转地", "mon.token_operator"),
    ("庄家中转", "mon.token_operator"),
    ("跨币大户", "mon.token_cross_sym"),
    ("散户接收", "mon.token_retail"),
    ("近 72h 异常大单参与方", "role.ANOMALY.short"),
    ("异常大单参与方", "role.ANOMALY.short"),
    ("DEX 主池", "mon.token_lp"),
    # English legacy (in case some path emits English) — fallback. Resolve
    # to the SAME i18n keys so the emitted token follows active lang too.
    ("Cross-token whale", "mon.token_cross_sym"),
    ("Operator relay", "mon.token_operator"),
    ("operator relay", "mon.token_operator"),
    ("Deployer", "role.DEPLOYER.short"),
    ("Full Dumper", "mon.token_full_dumper_legacy"),
    ("Partial Dumper", "mon.token_partial_legacy"),
    ("Partial dumper", "mon.token_partial_legacy"),
    ("Quiet", "role.RULE11_QUIET.short"),
    ("DEX", "mon.token_lp"),
    ("LP", "mon.token_lp"),
    ("72h", "role.ANOMALY.short"),
    ("anomaly", "role.ANOMALY.short"),
    ("Anomaly", "role.ANOMALY.short"),
]


def _role_token(role_str: str) -> str:
    """Map a free-form role string to a short token for label assembly.

    v0.6.2 i18n: _ROLE_TOKEN_MAP right side is an i18n key; resolve it via
    t() so the emitted token follows the active lang.
    """
    for pattern, token_key in _ROLE_TOKEN_MAP:
        if pattern in role_str:
            return t(token_key)
    # Default: take first word, capitalize, truncate to 8 chars
    head = re.split(r"[\s\(]", role_str.strip(), maxsplit=1)[0]
    return (head or "Other")[:8]


def _build_label(symbol: str, role: str, address: str, max_len: int = 25) -> str:
    """Assemble <SYM>-<ROLE>-<addr5> label, clipped to max_len."""
    sym = (symbol or "UNKNOWN")[:6].upper()
    token = _role_token(role)
    addr5 = (address or "").lower().lstrip("0x")[:5]
    label = f"{sym}-{token}-{addr5}"
    return label[:max_len]


def _severity_from_status(status_emoji: str) -> str:
    """Map status emoji to severity tier."""
    if status_emoji == "🔴":
        return "critical"
    if status_emoji == "🟠":
        return "high"
    if status_emoji == "🟣":
        # v0.7.3 cross-token mega-wallet — high priority forward-tracking
        # target (holds significant supply AND multiple Alpha tokens).
        return "high"
    if status_emoji == "🟡":
        return "watch"
    if status_emoji == "🟢":
        return "resolved"
    return "watch"


_PLACEHOLDER = "<LLM_NARRATIVE_PLACEHOLDER>"

# CSV formula injection neutralizer (adversarial review beta.3 audit HIGH 2).
# Cells starting with these chars can execute formulas / exfiltration
# payloads when the CSV is opened in Excel / Google Sheets / OKX / Binance
# Web3 tracker importers (most of which use spreadsheet-style parsers).
# Per OWASP CSV injection guidance, prefix with single-quote to neutralize.
_CSV_DANGEROUS_PREFIX = ("=", "+", "-", "@", "\t", "\r", "\n")


def _sanitize_csv_cell(value: Any) -> str:
    """Neutralize formula injection + control chars. Idempotent on safe input.

    adversarial review beta.4 8th audit MED: prior version only checked s[0]. Payloads
    like '  =CMD(...)' or '\\t=CMD(...)' (whitespace-prefixed) bypassed
    because the first char was whitespace (not dangerous), even though
    downstream Excel/Sheets trim leading whitespace before formula eval.

    Now: also check the first non-whitespace char. If THAT is a formula
    sigil, neutralize by prepending `'`.
    """
    if value is None:
        return ""
    s = str(value)
    if not s:
        return s
    # Check first non-whitespace char for formula sigil.
    # str.lstrip() with no arg strips all Unicode whitespace, matching
    # how spreadsheets normalize.
    first_non_ws = s.lstrip()
    if first_non_ws and first_non_ws[0] in _CSV_DANGEROUS_PREFIX:
        s = "'" + s   # OWASP-recommended neutralizer
    # Also strip embedded CR/LF that would break the row even with
    # csv.writer quoting (some downstream parsers don't follow RFC 4180).
    return s.replace("\r", " ").replace("\n", " ")


def _is_windows_short_path(p: Path) -> bool:
    """Detect Windows 8.3 short filename (NTFS legacy alias).

    Strict 8.3 grammar (adversarial review beta.6 9th-audit HIGH): 1-6 chars + `~N` (N=1-9)
    + optional `.` + 0-3 chars, all chars excluding reserved set
    `\\/:*?"<>|`. Loose regex `^.+~[1-9]...` previously matched any
    filename ending in `~1.tar` (Linux backup convention) — converted
    cosmetic false-positive into security risk.

    v0.6.0-beta.6 fix: User's Windows %TEMP% resolves to `TESTUS~1` etc.
    Path.resolve() expands to long name → realpath-vs-absolute check
    triggered false-positive.

    Used ONLY as exception for realpath-mismatch comparison, NEVER as
    a fast path that skips symlink + ancestor + .. checks (adversarial review
    beta.6 9th-audit CRITICAL).
    """
    if os.name != "nt":
        return False
    # Strict 8.3: 1-6 valid filename chars, ~ , digit 1-9, optional
    # 0-3 char extension. Excludes NTFS reserved chars in any segment.
    pattern = re.compile(r"^[^\\/:*?\"<>|]{1,6}~[1-9](\.[^\\/:*?\"<>|]{0,3})?$")
    for part in p.absolute().parts:
        if pattern.match(part):
            return True
    return False


def _paths_equal_normalized(a: Path, b: Path) -> bool:
    """Compare two paths after platform-aware normalization.

    v0.7.19.2: was `str(real) != str(absolute)` raw-string comparison,
    which on Windows wrongly flagged perfectly-canonical paths as
    "realpath differs from absolute" because of drive-letter case
    (`C:\\` vs `c:\\`) or separator differences (`/` vs `\\`).
    `os.path.normcase` lower-cases + flips `/` → `\\` on Windows
    (no-op on POSIX); `os.path.normpath` collapses `..` / `.` / dup
    separators. With both, equivalent paths compare equal regardless
    of cosmetic spelling. POSIX behavior is unchanged because
    normcase is identity on POSIX and normpath is structural-only.

    Reported by adversarial review BSC postmortem (2026-05-29): COLLECT run on
    Windows tripped the realpath-vs-absolute guard 3× in a row, each
    time at the same step but with cosmetically-different path
    spellings of the same on-disk directory.
    """
    a_norm = os.path.normcase(os.path.normpath(str(a)))
    b_norm = os.path.normcase(os.path.normpath(str(b)))
    return a_norm == b_norm


def _is_macos_system_tmp_symlink(p: Path) -> bool:
    """macOS system symlinks: `/tmp` → `/private/tmp`, `/var` → `/private/var`,
    `/etc` → `/private/etc`. Recognize so we don't reject platform default
    temp locations (tempfile.TemporaryDirectory uses /var/folders on macOS).

    Beta.9 (cross-LLM audit fix): broadened from /tmp-only to all
    3 platform-system symlinks. Without /var, Python tempfile dirs got
    rejected by the ancestor walker (every macOS /var/folders/.../tmpXXX
    path has /var as a symlinked ancestor).
    """
    if os.name != "posix":
        return False
    abs_str = str(p.absolute()).rstrip("/")
    try:
        real_str = str(p.resolve(strict=False)).rstrip("/")
    except (OSError, RuntimeError):
        return False
    for sysdir in ("/tmp", "/var", "/etc"):
        private = f"/private{sysdir}"
        if abs_str == sysdir and real_str == private:
            return True
        if abs_str.startswith(f"{sysdir}/") and real_str.startswith(f"{private}/"):
            # Verify suffix matches (no other redirect happening)
            if abs_str[len(sysdir):] == real_str[len(private):]:
                return True
    return False


def _walk_ancestors_for_symlinks(p: Path) -> None:
    """Walk every existing ancestor of `p` from root down; raise ValueError
    if any ancestor is a user-controlled symlink.

    adversarial review beta.4 8th audit HIGH 1: a guard that only checks `p.is_symlink()`
    misses the case where `p` doesn't exist but an ancestor IS a symlink.
    mkdir(parents=True) on `/tmp/link_to_etc/newdir` happily creates
    `newdir` under whatever `link_to_etc` points to.

    macOS /tmp → /private/tmp is recognized as a system symlink (not
    user-controlled) and allowed.
    """
    # Walk parents from root downward (deepest ancestor last)
    abs_p = p.absolute()
    parts = abs_p.parts
    cursor = Path(parts[0])
    for part in parts[1:]:
        cursor = cursor / part
        if not cursor.exists():
            return   # rest of path doesn't exist; mkdir(parents=True) will create it from here
        if cursor.is_symlink():
            # macOS /tmp exception
            if _is_macos_system_tmp_symlink(cursor):
                continue
            raise ValueError(
                f"monitoring_export: refused out_dir={str(p)!r} — "
                f"ancestor {str(cursor)!r} is a symlink "
                f"(realpath {str(cursor.resolve(strict=False))!r}). "
                f"mkdir(parents=True) would follow the link, leaking writes outside lexical path."
            )


def _guard_output_dir(out_dir: Path) -> Path:
    """Path-traversal + symlink guard on the monitoring/ output directory.

    adversarial review beta.3 audit HIGH 1: render_report._guard_out_path only checks
    the report.md file path. monitoring_export was called with out_p.parent
    or args.out's parent — neither re-validated.

    adversarial review beta.4 8th audit HIGH 1: also walk every ancestor for symlinks
    (defeats the `/tmp/link/newdir` ancestor-redirect bypass where the
    target itself doesn't exist yet).

    Refuse:
      - ".." anywhere in the path string
      - NUL bytes
      - POSIX backslash (Windows backslash legitimate, gated by os.name)
      - `out_dir` itself a symlink (except macOS /tmp system symlink)
      - ANY existing ancestor a user-controlled symlink (beta.4 new check)
      - `out_dir` exists + realpath escapes lexical absolute path
    """
    raw = str(out_dir)
    refuse_backslash = (os.name != "nt") and ("\\" in raw)
    if ".." in raw or refuse_backslash or "\x00" in raw:
        raise ValueError(
            f"monitoring_export: refused out_dir={raw!r} — contains '..', "
            f"POSIX-illegal '\\\\', or NUL byte."
        )
    p = Path(out_dir)

    # macOS-system-symlink exception applies FIRST (covers /tmp itself + subdirs).
    # Still walks ancestors above /tmp to detect attacker symlinks higher.
    macos_system = _is_macos_system_tmp_symlink(p)

    # Windows 8.3 short path is an NTFS alias, NOT a symlink. The ONLY
    # check it interferes with is `realpath != absolute` (resolve expands
    # TESTUS~1 → Testuser). All other guards run unconditionally.
    # adversarial review beta.6 9th-audit CRITICAL: previous version had this as a
    # full fast-path bypass, skipping symlink + ancestor + .. checks.
    win_8_3 = _is_windows_short_path(p)

    # ALWAYS check: out_dir itself a symlink (except macOS /tmp).
    if not macos_system and p.is_symlink():
        raise ValueError(
            f"monitoring_export: refused out_dir={raw!r} — itself a symlink."
        )

    # ALWAYS walk ancestors for symlinks (catches attacker-planted symlinks
    # in /home/user/legitimate_dir → /etc style).
    _walk_ancestors_for_symlinks(p)

    # Realpath-vs-absolute check: skip on macOS /tmp + Windows 8.3
    # (false-positive sources), otherwise enforce. v0.7.19.2: compare
    # via _paths_equal_normalized to defuse Windows drive-letter case
    # / separator cosmetic differences that the raw `str(real) !=
    # str(absolute)` check flagged as symlinks.
    if not macos_system and not win_8_3 and p.exists() and p.is_dir():
        try:
            real = p.resolve(strict=True)
            if not _paths_equal_normalized(real, p.absolute()):
                raise ValueError(
                    f"monitoring_export: refused out_dir={raw!r} — "
                    f"realpath {real!r} differs from absolute, "
                    f"likely user-controlled symlink."
                )
        except FileNotFoundError:
            pass   # parent not yet created
    return p


def _is_wallet_active_for_monitoring(w: dict) -> bool:
    """beta.12 filter: drop wallets that are 'done' (post-distribution
    archaeology, not active monitoring targets).

    User feedback 2026-05-24: "已分完 + 0 balance" wallets are info-only,
    not monitoring targets. Monitoring should only emit wallets that
    are (a) still holding meaningful supply, or (b) recently active in
    high-value flows.

    KEEP rules (any one):
    - status_emoji=🔴 (critical: OPERATOR_RELAY / 潜伏钱包 with big balance)
    - status_emoji=🟠 (high: 分发中)
    - recent_activity_72h=True (近 72h 异常大单参与方)
    - balance_tokens > 0 (still holds something)

    DROP:
    - status_emoji=🟢 (resolved/已分完 with 0 balance)
    - 项目方部署钱包 with balance 0 + no recent_activity (分完空仓)
    """
    emoji = w.get("status_emoji", "")
    role = w.get("role", "")
    balance = w.get("balance_tokens")
    recent = bool(w.get("recent_activity_72h"))

    # KEEP critical / high / cross-sym regardless of balance
    if emoji in ("🔴", "🟠", "🟣"):
        return True
    # KEEP recent-activity wallets regardless
    if recent:
        return True
    # KEEP wallets with non-trivial balance (> 0)
    if balance is not None and balance > 0:
        return True
    # DROP everything else (resolved / 0-balance with no recent activity)
    return False


# v0.7.27 sort/filter constants for monitor_level — used by build_canonical
# + to_paste_json so paste output reflects monitoring_ranker priority.
_LEVEL_RANK = {"CRITICAL": 0, "HIGH": 1, "NORMAL": 2, "NOT_TRACKED": 3, "": 4}

# v0.7.27 monitor_level → paste emoji. Distinct from severity emoji to avoid
# overloading; both are kept on canonical entries (severity is legacy field
# from anomaly status), monitor_level is the new actionable priority.
_LEVEL_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH": "🔥",
    "NORMAL": "👀",
    "NOT_TRACKED": "💤",
}


def build_canonical(
    symbol: str,
    chain: str,
    contract_address: str,
    monitoring_wallets: list[dict],
) -> list[dict]:
    """Produce the canonical address list for export.

    Each entry: {address, chain, label, role, severity, alert,
                 source_sym, source_contract, addr_short}

    `alert` field falls back to empty string when still
    <LLM_NARRATIVE_PLACEHOLDER> (pipeline-time emit, before LLM fill).
    render_report.py re-emits after fill with real alert text.

    Beta.12: filters out 已分完 wallets with 0 balance (info-only,
    not actively dangerous). See _is_wallet_active_for_monitoring().
    """
    # v0.7.21.7: chain-aware address validation. Solana base58 (32-44 chars,
    # case-sensitive) bypasses the old EVM-only `startswith("0x") + len 42`
    # gate which silently dropped every Solana wallet from monitoring.
    from chain_router import is_valid_addr as _chain_is_valid_addr, get_active_chain as _chain_get_active
    _is_sol = _chain_get_active() == "solana"
    rows = []
    for w in monitoring_wallets or []:
        raw = w.get("addr_full") or ""
        addr = raw if _is_sol else raw.lower()
        if not addr or not _chain_is_valid_addr(addr):
            continue
        if not _is_wallet_active_for_monitoring(w):
            continue   # skip 已分完 + 0 balance wallets
        role = w.get("role") or "Other"
        alert = w.get("alert", "")
        if alert == _PLACEHOLDER:
            alert = ""   # mask placeholder; render_report re-emits post-fill
        rows.append({
            "address": addr,
            "chain": chain.lower(),
            "label": _build_label(symbol, role, addr),
            "role": role,
            "severity": _severity_from_status(w.get("status_emoji", "🟡")),
            "alert": alert,
            "source_sym": symbol,
            "source_contract": contract_address if _is_sol else contract_address.lower(),
            "addr_short": w.get("addr_short", addr[:10]),
            # v0.7.27 monitoring_ranker fields (deterministic Python).
            # Default to NORMAL if monitoring_ranker didn't annotate (legacy
            # skeleton without Round 10) so paste export still works.
            "monitor_level": w.get("monitor_level") or "NORMAL",
            "monitor_score": w.get("monitor_score"),
            "monitor_role_enum": w.get("monitor_role_enum") or "other",
            "monitor_reason": w.get("monitor_reason") or "",
            "source_behaviors": w.get("source_behaviors") or [],
            "trigger_summary": w.get("trigger_summary") or "",
        })
    # v0.7.27 sort by monitor_level (CRITICAL → HIGH → NORMAL → NOT_TRACKED).
    # Stable secondary sort by role + address for deterministic output.
    rows.sort(key=lambda r: (_LEVEL_RANK.get(r.get("monitor_level"), 4),
                              r.get("role") or "", r.get("address") or ""))
    return rows


_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "watch": "🟡",
    "resolved": "🟢",
}


def to_paste_json(canonical: list[dict]) -> str:
    """Paste-format `[{address, name, emoji}]` JSON for Binance Wallet +
    OKX wallet bulk import (paste route only — neither supports JSON
    file upload).

    Beta.16 fix (2026-05-24): use ensure_ascii=True so output is pure
    ASCII bytes (中文 → `\\u5e84\\u5bb6` escapes, emoji → surrogate pair
    escapes). User reported beta.15 paste.json display 乱码 on Windows
    viewer:
      "ZEST-庄家-e30a0" → "ZEST-åºå®¶-e30a0" (UTF-8 read as cp1252)
      "🔴" → "ð´"
    The bytes on disk WERE correct UTF-8 (we use write_bytes(... encode
    utf-8)), but Windows default cp1252 viewer mis-decoded → user's
    Ctrl+A Ctrl+C copied the mojibake → pasted garbage into Binance/OKX.
    Pure ASCII bytes are encoding-invariant — any Windows viewer shows
    the same bytes, clipboard preserves them, Binance/OKX JSON parser
    unescapes `\\u5e84\\u5bb6` → 庄家 on import. End-user sees correct
    中文 in the tracker.

    Empirical (pre-mojibake) confirmation:
    - Binance Wallet bulk import → paste → ✅ works
    - OKX wallet bulk import → paste → ✅ works (paste only, no upload)
    """
    # v0.7.27: skip NOT_TRACKED entries entirely (infra / public CEX hot
    # wallets — they generate constant noise that drowns out real signal
    # in retail's tracker UI). Output now sorted by monitor_level via
    # build_canonical, so the first entries are always CRITICAL → HIGH.
    # Per-entry emoji uses monitor_level (🚨/🔥/👀) when available,
    # otherwise falls back to severity emoji for legacy compat.
    out = []
    for r in canonical:
        level = r.get("monitor_level") or ""
        if level == "NOT_TRACKED":
            continue
        emoji = _LEVEL_EMOJI.get(level) or _SEVERITY_EMOJI.get(r.get("severity"), "🟡")
        out.append({
            "address": r["address"],
            "name": r["label"],
            "emoji": emoji,
            # v0.7.27 paste schema additions — Binance Wallet / OKX paste
            # parsers ignore unknown fields (verified empirically beta.16),
            # so adding these doesn't break import.
            "level": level or "NORMAL",
            "reason": r.get("monitor_reason") or "",
        })
    return json.dumps(out, ensure_ascii=True, indent=2)


# Beta.16: to_unified_csv() removed. User empirical 2026-05-24:
# - Binance Wallet file upload of monitoring.csv → "format wrong" rejected
# - OKX wallet has no file-upload option at all (paste only)
# CSV was a guess that didn't pan out. Both platforms only accept the
# paste route via monitoring_paste.json. _sanitize_csv_cell helper kept
# below for any future CSV emit needs (unused as of beta.16).


# NOTE: to_binance_web3_csv / to_okx_csv removed in beta.11 — these CSVs
# were based on incorrect assumption Binance Wallet + OKX wallet have no
# bulk import. Both DO support bulk import via paste of GMGN-style JSON
# (see to_paste_json above). User实测 confirmed paste works on both. The
# CSV files were never importable; they were "manual-entry reference
# lists" pretending to be useful but report.md monitoring table already
# served that role with bscscan links.
#
# _sanitize_csv_cell kept as standalone utility — currently unused inside
# this module but retained for any future CSV-emit needs (e.g., DeBank).


def write_all(
    *,
    symbol: str,
    chain: str,
    contract_address: str,
    monitoring_wallets: list[dict],
    out_dir: Path,
    lang: str = "zh",
) -> dict[str, Any]:
    """Write all 4 files to `out_dir/monitoring/`. Returns paths + counts.

    Path traversal + symlink guards applied (adversarial review beta.3 audit HIGH 1).
    Callers MUST NOT pass attacker-controlled out_dir; we re-validate here
    as defense in depth.

    v0.6.2: `lang` param ("zh" | "en") controls localization of wallet label
    short tokens (e.g. "庄家" vs "Operator"). Default zh for backward compat.
    """
    # v0.6.2: switch to caller's lang for any t() calls during build_canonical /
    # to_paste_json. Loader is cached so this is a free-cost dict assignment.
    try:
        from i18n import set_lang
        set_lang(lang)
    except ImportError:
        # i18n module absent — silently fall back to whatever default was loaded.
        pass
    out_dir_guarded = _guard_output_dir(Path(out_dir))
    monitoring_dir = out_dir_guarded / "monitoring"
    # Pre-mkdir: refuse if monitoring/ exists as a symlink.
    if monitoring_dir.exists() and monitoring_dir.is_symlink():
        raise ValueError(
            f"monitoring_export: refused — monitoring/ under "
            f"{out_dir!r} is itself a symlink."
        )
    monitoring_dir.mkdir(parents=True, exist_ok=True)

    # adversarial review beta.4 8th audit HIGH 2 (TOCTOU mitigation): immediately after
    # mkdir, re-resolve the path and verify it didn't end up somewhere
    # unexpected via a race during creation. Race window between resolve
    # and file write still exists in principle, but attacker would need to
    # swap paths within microseconds — much narrower than no check at all.
    #
    # Beta.14 fix: also exempt Windows 8.3 short path (parity with the
    # pre-mkdir guard at line 318). Symptom: adversarial review Windows env with tmp
    # under `C:\Users\TESTUS~1\...` triggered post-mkdir TOCTOU here
    # because resolve() expands `TESTUS~1` → `cross-LLM tester`. The 8.3 alias
    # is NTFS metadata, not a user-controlled symlink, so it must be
    # exempted from this realpath-vs-absolute check (just like pre-mkdir).
    if not _is_macos_system_tmp_symlink(monitoring_dir) and not _is_windows_short_path(monitoring_dir):
        post_real = monitoring_dir.resolve(strict=True)
        post_abs = monitoring_dir.absolute()
        # v0.7.19.2: normalize before comparison so a cosmetic Windows
        # path-case / separator difference cannot masquerade as a
        # mid-mkdir attacker-swap. The actual TOCTOU guard is the
        # `is_symlink()` check immediately below — that one stays
        # strict (a symlink is a symlink regardless of casing).
        if not _paths_equal_normalized(post_real, post_abs):
            raise ValueError(
                f"monitoring_export: post-mkdir TOCTOU detection — "
                f"resolved {post_real!r} differs from absolute "
                f"{post_abs!r}. Refusing all writes."
            )
        if monitoring_dir.is_symlink():
            raise ValueError(
                f"monitoring_export: post-mkdir TOCTOU detection — "
                f"monitoring/ became a symlink. Refusing."
            )

    canonical = build_canonical(symbol, chain, contract_address, monitoring_wallets)

    files = {
        # Canonical: own scripts / analytics. Beta.17: ensure_ascii=True
        # (was False) — user 2026-05-24 reported same Windows cp1252
        # mojibake here as on paste.json: viewer showed "ZEST-åºå®¶..."
        # for "ZEST-庄家...". Consistency with paste.json: both emit pure
        # ASCII bytes, encoding-invariant across Windows viewers.
        # json.loads transparently un-escapes \uXXXX for analytical
        # readers (Python / JS / jq) — no consumer behavior change.
        # Beta.18 (v0.6.1): renamed from monitoring_wallets.json →
        # monitoring_wallets_full.json. Pair with monitoring_paste.json
        # forms a clear paste-vs-full naming convention: paste = 粘贴版
        # (3 字段精简), full = 完整版 (含 role / severity / alert / etc).
        "monitoring_wallets_full.json": json.dumps(
            {
                "schema_version": "0.6.1",
                "source_symbol": symbol,
                "source_contract": contract_address.lower(),
                "source_chain": chain.lower(),
                "n_wallets": len(canonical),
                "addresses": canonical,
            },
            ensure_ascii=True, indent=2,
        ),
        # Paste route — Binance Wallet + OKX wallet text-paste bulk import.
        # Empirically verified working since beta.6 era. Beta.16 switches
        # to ensure_ascii=True (pure ASCII bytes) so Windows cp1252
        # viewers don't mojibake the 中文 + emoji content before user
        # Ctrl+A Ctrl+C copies it. JSON parsers on Binance/OKX un-escape
        # \uXXXX sequences automatically — end-user sees 中文 + emoji
        # correctly in the imported wallet list.
        #
        # CSV file-upload route dropped in beta.16: user empirical 2026-05-24
        # found Binance Wallet rejects unified CSV format, and OKX has no
        # file-upload option at all (paste-only platform).
        "monitoring_paste.json": to_paste_json(canonical),
    }

    written = {}
    for fname, content in files.items():
        path = monitoring_dir / fname
        # All emitted files are JSON, written as plain UTF-8 bytes.
        # paste.json uses ensure_ascii=True so the bytes are also pure
        # ASCII — clipboard / Windows viewer safe.
        path.write_bytes(content.encode("utf-8"))
        written[fname] = str(path)

    return {
        "dir": str(monitoring_dir),
        "n_wallets": len(canonical),
        "files": written,
    }
