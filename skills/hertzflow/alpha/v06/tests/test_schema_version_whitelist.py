"""test_schema_version_whitelist.py — regression guard for the V_SCHEMA_VERSION
whitelist. The per-minor enumeration (1.0/1.1/...) silently hard-failed the FIRST
render on every _version.py bump until re-listed; v1.2.0 switched to a "1." prefix
so all 1.x is accepted. This test pins that so a future bump can't re-break it.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import validate_report_data as vrd  # noqa: E402


def _schema_errs(ver):
    v = vrd.Validator.__new__(vrd.Validator)
    v.errors = []
    v._check_schema_version({"_schema_version": ver}, {"_schema_version": ver})
    return [e for e in v.errors if "expected" in e]


def test_all_1x_accepted():
    for ver in ("1.0.0", "1.1.2", "1.2.0", "1.2.1", "1.3.0", "1.9.9"):
        assert not _schema_errs(ver), f"{ver} should be accepted"


def test_legacy_0x_accepted():
    for ver in ("0.6.0", "0.7.21", "0.8.6", "0.9.5"):
        assert not _schema_errs(ver)


def test_2x_rejected():
    # a 2.x schema is a breaking change and must still be rejected
    assert _schema_errs("2.0.0")


def test_skeleton_filled_mismatch_flagged():
    v = vrd.Validator.__new__(vrd.Validator)
    v.errors = []
    v._check_schema_version({"_schema_version": "1.2.1"}, {"_schema_version": "1.1.2"})
    assert any("skeleton=" in e for e in v.errors)


if __name__ == "__main__":
    import traceback
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    p = 0
    for fn in fns:
        try:
            fn(); p += 1
        except Exception:
            print("FAIL", fn.__name__); traceback.print_exc()
    print(f"{p}/{len(fns)} passed")
