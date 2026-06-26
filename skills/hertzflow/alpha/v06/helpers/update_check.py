#!/usr/bin/env python3
"""update_check.py — Self-check for newer skill versions on GitHub.

v0.9.5 — auto-update on detection. Newer commit detected → run
`npx skills update hertzflow` synchronously, then exit with "please
retry" so the user's command resumes on the up-to-date version. The
original notify-only behavior remains the fallback when the npx
subprocess fails (and via BINANCE_ALPHA_NO_AUTO_UPDATE opt-out).

v0.6.5 (original). On pipeline startup, optionally checks GitHub for
newer commits on main. If installed commit SHA differs from latest,
prints a single i18n-localized line to stderr suggesting `npx skills
update`.

Design constraints:
  - **Non-blocking probe**: 3-second curl timeout, silent failure
  - **24h cache**: writes ~/.binance-alpha-data/last_update_check to
    avoid hitting GitHub more than once per day
  - **No GitHub token required** (public API)
  - **i18n-localized notice**: respects current lang via i18n.t()
  - **Off-switches**:
      - BINANCE_ALPHA_NO_UPDATE_CHECK=1 — skip the GitHub probe entirely
      - BINANCE_ALPHA_NO_AUTO_UPDATE=1 — probe + notify only (no
        auto-run of `npx skills update`)
  - **Privacy**: only 1 HTTP GET to GitHub commits API, no user data
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Module constants
DEFAULT_DATA_DIR = Path.home() / ".binance-alpha-data"
DEFAULT_CHECK_CACHE = DEFAULT_DATA_DIR / "last_update_check.json"
DEFAULT_INSTALLED_FILE = DEFAULT_DATA_DIR / "installed_commit"
CHECK_TTL_SECS = 86400   # 24h
HTTP_TIMEOUT_SECS = 3
GITHUB_REPO = "HertzFlow/hertzflow-skills"
GITHUB_COMMITS_URL = f"https://api.github.com/repos/{GITHUB_REPO}/commits/main"
GITHUB_TAGS_URL = f"https://api.github.com/repos/{GITHUB_REPO}/tags?per_page=1"


def check_for_update(
    *,
    cache_path: Path = DEFAULT_CHECK_CACHE,
    installed_file: Path = DEFAULT_INSTALLED_FILE,
    ttl_secs: int = CHECK_TTL_SECS,
    quiet: bool = False,
) -> dict | None:
    """Run the self-update check. Returns:
        - None if check skipped (env opt-out, recent cache hit) or failed
        - {"installed": str, "latest": str, "is_newer": bool} otherwise

    Side effect: writes warning to stderr if is_newer is True.
    Idempotent: 24h cache prevents repeated GitHub API hits.
    """
    if os.environ.get("BINANCE_ALPHA_NO_UPDATE_CHECK", "").strip() in ("1", "true", "yes"):
        return None

    # Cache check — skip if we hit GitHub in the last 24h
    cache = _load_cache(cache_path)
    if cache:
        age = int(time.time()) - cache.get("checked_ts", 0)
        if age < ttl_secs:
            # Within TTL — still print warning if last check found newer.
            if cache.get("is_newer") and not quiet:
                _print_warning(cache.get("installed", ""), cache.get("latest", ""))
            return cache

    # v0.9.6 fix #2 (adversarial review Windows EVAA 2026-06-15 feedback): switch from
    # SHA-based comparison to **version-based**. SHA comparison required
    # external `record_install(sha)` to keep `installed_commit` file
    # in sync — but npx skills install/update doesn't always update that
    # marker, so users on the latest `_version.py == "0.9.5"` still saw
    # "🆕 新版本 (stale_sha → current_sha)" because installed_commit was
    # frozen from initial install. Version is the canonical truth.
    latest_tag, latest_sha = _fetch_latest_tag()
    if not latest_tag:
        return None   # network failure → silently skip
    # Normalize "v0.9.5" → "0.9.5" so we can semver-compare against
    # _version.__version__ (which has no `v` prefix).
    latest_version = latest_tag.lstrip("v")
    local_version = _read_disk_version()
    if local_version is None:
        return None   # can't compare — skip silently

    is_newer = _version_tuple(latest_version) > _version_tuple(local_version)
    result = {
        # `installed` / `latest` now hold version strings (not SHAs).
        # Same field names preserved for cache backward-compat.
        "installed": local_version,
        "latest": latest_version,
        "is_newer": is_newer,
        "checked_ts": int(time.time()),
        # Keep the SHA in cache for diagnostic / record_install hooks
        # that still write installed_commit. Not used for comparison.
        "latest_sha": latest_sha or "",
    }
    _save_cache(cache_path, result)

    if is_newer and not quiet:
        _print_warning(local_version, latest_version)

        # v0.9.5: auto-update on detection. Run `npx skills update hertzflow`
        # synchronously; on success, save new SHA to cache. Return a signal
        # field `auto_updated=True` so the CLI entry-point can `sys.exit(0)`
        # without killing imported library callers (e.g. Discord bot batches
        # that call build_skeleton in-process — audit Finding 1).
        # Opt-out via env so anyone debugging against a specific old version
        # can keep running.
        auto_update_off = os.environ.get(
            "BINANCE_ALPHA_NO_AUTO_UPDATE", ""
        ).strip().lower() in ("1", "true", "yes")
        if not auto_update_off:
            ok, reason = _run_auto_update(
                latest_sha or "", installed_file, cache_path,
            )
            if ok:
                _print_auto_update_success(local_version, latest_version)
                result["auto_updated"] = True
                # Refresh cache (version-based) so next probe sees current.
                _save_cache(cache_path, {
                    "installed": latest_version, "latest": latest_version,
                    "is_newer": False, "checked_ts": int(time.time()),
                    "latest_sha": latest_sha or "",
                })
                return result
            else:
                _print_auto_update_failed(reason)
                # audit v0.9.5 R1 Finding 3: failed auto-update must
                # NOT cache is_newer=True for 24h — user might fix npm in
                # 30s and rerun. Drop the cache so next probe re-attempts.
                try:
                    cache_path.unlink(missing_ok=True)
                except (OSError, TypeError):
                    pass

    return result


def _run_auto_update(
    latest_sha: str,
    installed_file: Path,
    cache_path: Path,
) -> tuple[bool, str]:
    """v0.9.5: run `skills update hertzflow` synchronously.

    adversarial review round-2 Finding 5: `npx --no-install` is NOT a reliable
    no-bootstrap guarantee on npm 10.x (adversarial review tested empirically — npx
    still hits the registry). Trust boundary moved: resolve `skills`
    binary via `shutil.which()` first (typical case for users who ran
    `npm install -g skills`). Fall back to `npx --yes` only when no
    local CLI is found, then rely on the F2 verification step to detect
    any wrong-directory update.

    adversarial review round-1 Finding 2 + round-2 Finding 2: capture `_version.py`
    BEFORE the subprocess call (not after). Direct CLI invocations of
    update_check don't import `_version` at module-load time, so the
    "in-memory version" comparison breaks. Storing the pre-update
    version locally sidesteps the import-order issue entirely.

    Returns (ok, reason). `reason` describes the failure mode for the
    failed-update message (timeout / npx_missing / no_skills_cli /
    no_change_on_disk / exit_N).
    """
    # F2: snapshot version BEFORE invoking any subprocess.
    pre_update_version = _read_disk_version()

    # F5: prefer locally resolved binary over npx — avoids the
    # `npx --no-install` cross-version-flag-semantics issue entirely.
    skills_cli = shutil.which("skills")
    if skills_cli:
        cmd = [skills_cli, "update", "hertzflow"]
    else:
        # Fallback: `npx --yes` will auto-install upstream `skills` CLI
        # if missing. Safe because F2 verification catches any update
        # that touched the wrong directory.
        cmd = ["npx", "--yes", "skills", "update", "hertzflow"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=180,   # npm/GitHub fetch = up to 3 min
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout_180s"
    except (OSError, FileNotFoundError):
        # `npx` (or `skills`) itself missing (no Node.js installed)
        return False, "npx_missing"

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-500:].strip()
        cli_missing_markers = ("could not determine executable",
                               "command not found",
                               "404 Not Found",
                               "Could not find",
                               "not found in registry")
        is_cli_missing = any(m.lower() in tail.lower() for m in cli_missing_markers)
        if tail:
            print(f"[auto-update] skills update failed (exit {proc.returncode}):\n{tail}",
                  file=sys.stderr)
        return False, "no_skills_cli" if is_cli_missing else f"exit_{proc.returncode}"

    # F2: verify the running checkout actually got updated.
    if not _verify_update_applied(pre_update_version):
        return False, "no_change_on_disk"

    # Persist new SHA so we don't loop. _save_cache + record_install
    # already swallow OSError silently.
    try:
        record_install(latest_sha, installed_file=installed_file)
    except Exception:
        pass
    return True, "ok"


def _read_disk_version() -> str | None:
    """Read `__version__` directly from `_version.py` on disk. Bypasses
    Python module cache so we see post-`skills update` state. Returns
    None on any IO / parse error."""
    try:
        version_path = Path(__file__).parent / "_version.py"
        content = version_path.read_text(encoding="utf-8")
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        return m.group(1) if m else None
    except Exception:
        return None


def _verify_update_applied(pre_update_version: str | None) -> bool:
    """v0.9.5 adversarial review round-2 Finding 2: confirm `skills update` touched
    THIS checkout. Compares post-update on-disk version against the
    pre-update version captured before the subprocess ran.

    If they differ, the file was updated (success). If they match, the
    update touched a different install root (manual git clone, custom
    install path, npx auto-bootstrap that picked wrong directory) and
    we MUST NOT mark installed_commit, lest we silently suppress
    re-update of a still-stale install.

    pre_update_version=None means we couldn't read the file before —
    treat as failure (cannot prove anything changed).
    """
    if pre_update_version is None:
        return False
    post = _read_disk_version()
    return post is not None and post != pre_update_version


def _print_auto_update_success(old: str, new: str) -> None:
    # Lazy import to avoid circular dependency if i18n calls back into us.
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from i18n import t
        print(
            f"\n{t('sec2.update_auto_success', old=old or '?', new=new)}\n",
            file=sys.stderr,
        )
    except Exception:
        # Fall back to English if i18n itself fails
        print(
            f"\n✅ Auto-update applied ({old or '?'} → {new}). Please re-run your last command.\n",
            file=sys.stderr,
        )


def _print_auto_update_failed(reason: str = "") -> None:
    # Reason-specific human message so the user knows whether to install
    # npm, install skills CLI, fix network, etc.
    # Lazy import to avoid circular dependency if i18n calls back into us.
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from i18n import t
        reason_text = t(f"sec2.update_reason_{reason}") if reason in (
            "timeout_180s", "npx_missing", "no_skills_cli", "no_change_on_disk"
        ) else ""
        print(
            f"\n{t('sec2.update_auto_failed', reason=reason_text)}\n",
            file=sys.stderr,
        )
    except Exception:
        # Fall back to English if i18n itself fails
        reason_en = {
            "timeout_180s": "(timed out at 180s — likely slow network/proxy, retry usually works)",
            "npx_missing": "(no Node.js installed locally — install from https://nodejs.org/)",
            "no_skills_cli": "(no `skills` CLI installed — run `npm install -g @vercel/skills`)",
            "no_change_on_disk": "(npx exited 0 but this checkout didn't change — likely manual git clone, run `git pull`)",
        }.get(reason, "")
        print(
            f"\n⚠️ Auto-update failed {reason_en}. Please update manually.\n",
            file=sys.stderr,
        )


def record_install(commit_sha: str, *, installed_file: Path = DEFAULT_INSTALLED_FILE) -> None:
    """Write installed commit SHA to disk. Called by skill installer hook.

    If the installer cannot reliably get the commit SHA, this can be a no-op;
    the update check will simply not have a baseline to compare against, and
    will silently print nothing.
    """
    installed_file.parent.mkdir(parents=True, exist_ok=True)
    installed_file.write_text(commit_sha.strip(), encoding="utf-8")


def _fetch_latest_tag() -> tuple[str | None, str | None]:
    """v0.9.6: hit GitHub tags API instead of commits API. Returns
    `(tag_name, short_sha)` of the most recent tag, or `(None, None)` on
    failure. Tag name includes the `v` prefix (e.g. "v0.9.5"); caller
    must strip if comparing to `__version__`.

    Version-based comparison sidesteps the v0.9.5 false-positive nag
    (adversarial review Windows 2026-06-15 feedback): the SHA-based check required
    `installed_commit` file to be kept in sync via record_install hook,
    but `npx skills update` doesn't reliably update it. Tags are the
    canonical release marker.
    """
    try:
        result = subprocess.run(
            ["curl", "-sS", "--max-time", str(HTTP_TIMEOUT_SECS),
             "-H", "User-Agent: binance-alpha-skill",
             GITHUB_TAGS_URL],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=HTTP_TIMEOUT_SECS + 2, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, None
    if result.returncode != 0:
        return None, None
    try:
        doc = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(doc, list) or not doc:
        return None, None
    first = doc[0] or {}
    tag = first.get("name") or ""
    sha = ((first.get("commit") or {}).get("sha") or "")[:7]
    return (tag if tag else None), (sha if sha else None)


def _version_tuple(s: str) -> tuple[int, ...]:
    """Parse '0.9.5' / '0.9.5.1' / '1.0' → (0,9,5) etc. for semver
    comparison. Returns (0,) on parse failure so unknown versions sort
    as oldest (do not trigger spurious update nag)."""
    try:
        # Split on dots; ignore non-numeric suffixes ('-rc1', '+meta')
        parts = re.split(r"[^0-9]", s)
        return tuple(int(p) for p in parts if p)
    except (ValueError, AttributeError, TypeError):
        return (0,)


def _read_installed(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()[:7]
    except (OSError, UnicodeDecodeError):
        return None


def _load_cache(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _save_cache(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def _print_warning(old: str, new: str) -> None:
    """Print i18n-localized warning to stderr. Lazy import to avoid
    circular dependency if i18n calls back into us."""
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from i18n import t
        title = t("section.update_check.title", old=old or "?", new=new)
        action = t("section.update_check.action")
        print(f"\n{title}", file=sys.stderr)
        print(f"   {action}\n", file=sys.stderr)
    except Exception:
        # Fall back to English if i18n itself fails
        print(f"\n🆕 New version available ({old or '?'} → {new})", file=sys.stderr)
        print(f"   Run `npx skills update hertzflow` to update\n", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="Run update check (default)")
    p_record = sub.add_parser("record-install", help="Record installed commit SHA")
    p_record.add_argument("sha")
    args = ap.parse_args()

    if args.cmd == "record-install":
        record_install(args.sha)
        print(f"Recorded installed commit: {args.sha[:7]}")
    else:
        result = check_for_update()
        if result:
            print(json.dumps(result, indent=2))
        else:
            print("(no result)")
