"""test_surf_timeout_deadlock.py — v0.9.9 deadlock regression.

User report 2026-06-17 (CA 0x5dbde81f...): forensic_pipeline hung 46+ min
at rule_11 mint backward trace, CPU 0%, futex_wait. Root cause:
parallel_surf._run_one's two subprocess.run("surf onchain-sql") calls had
NO timeout. When surf hangs on a stuck network connection, subprocess.run
blocks forever → ThreadPool worker never returns → run_parallel's
as_completed waits forever → whole pipeline deadlocks.

These tests assert:
  1. A hung surf (TimeoutExpired) returns a SURF_TIMEOUT error dict, never
     blocks — the position the user hit.
  2. Every subprocess.run in the surf helpers carries a hard timeout ceiling
     (or the **kwargs form that sets one), so the no-timeout bug can't
     silently regress in a future refactor.
"""
import ast
import subprocess
import sys
import tempfile
import json
from pathlib import Path

_HELPERS = Path(__file__).resolve().parent.parent / "helpers"
sys.path.insert(0, str(_HELPERS))

import parallel_surf  # noqa: E402


def test_hung_surf_returns_error_not_hang(monkeypatch):
    """The exact user deadlock: surf hangs → must return error, not block."""
    def _always_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd=a[0] if a else "surf", timeout=k.get("timeout", 90))

    monkeypatch.setattr(subprocess, "run", _always_timeout)
    monkeypatch.setattr(parallel_surf.time, "sleep", lambda s: None)  # no real backoff wait

    qf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    qf.write(json.dumps({"sql": "SELECT 1", "max_rows": 1}))
    qf.close()

    path, resp, elapsed = parallel_surf._run_one(qf.name, max_attempts=2)
    assert isinstance(resp, dict) and "error" in resp
    assert resp["error"]["code"] == "SURF_TIMEOUT"


def test_subprocess_timeout_passed_to_surf(monkeypatch):
    """Confirm the timeout kwarg actually reaches subprocess.run."""
    seen = []

    def _spy(*a, **k):
        seen.append(k.get("timeout"))
        raise subprocess.TimeoutExpired(cmd="surf", timeout=k.get("timeout", 90))

    monkeypatch.setattr(subprocess, "run", _spy)
    monkeypatch.setattr(parallel_surf.time, "sleep", lambda s: None)

    qf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    qf.write(json.dumps({"sql": "SELECT 1", "max_rows": 1}))
    qf.close()
    parallel_surf._run_one(qf.name, max_attempts=1)
    assert seen, "subprocess.run was never called"
    assert all(t is not None and t > 0 for t in seen), f"timeout missing: {seen}"


def test_no_surf_subprocess_without_timeout():
    """Static guard: every subprocess.run/Popen in the surf helpers must
    carry a hard timeout (literal kwarg) OR use the **kwargs form (which
    sets one). Prevents silent reintroduction of the no-timeout deadlock."""
    surf_helpers = [
        "parallel_surf.py", "section_a_scope.py", "section_liq.py",
        "section_cex_trace.py", "role_classifier.py",
    ]
    offenders = []
    for fname in surf_helpers:
        src = (_HELPERS / fname).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("run", "Popen", "check_output", "call")):
                obj = getattr(node.func, "value", None)
                if isinstance(obj, ast.Name) and obj.id == "subprocess":
                    has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                    has_kwargs = any(kw.arg is None for kw in node.keywords)  # **kwargs
                    if not has_timeout and not has_kwargs:
                        offenders.append(f"{fname}:{node.lineno}")
    assert not offenders, f"subprocess.run without timeout (deadlock risk): {offenders}"
