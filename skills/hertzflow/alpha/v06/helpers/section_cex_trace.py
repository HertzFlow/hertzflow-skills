#!/usr/bin/env python3
"""section_cex_trace.py — refines tier_classification (S1/S2/S3) from Alpha-only
stub to real value by probing Binance perp + Aster + Bitget perp APIs.

## Tier semantics (per SKILL.md Rule 0):
- S1: Alpha only — no CEX perp anywhere
- S2: Alpha + Binance perpetual futures (Binance's own perp)
- S3: Alpha + at least one non-Binance CEX perp (Aster/Bitget/OPG/etc.)
- S3 does NOT imply S2 — a token can reach S3 via Aster without Binance perp first

## Output schema (locked, populated into report_data.skeleton)

```python
{
    "tier": "S1" | "S2" | "S3",
    "s1_date": "YYYY-MM-DD",      # Alpha listing date (always present)
    "s2_date": "YYYY-MM-DD" | None,
    "s3_date": "YYYY-MM-DD" | None,
    "has_binance_perp": True / False,
    "binance_perp_pair": "BSBUSDT" | None,
    "binance_perp_onboard_ts": int | None,
    "aster_perp_listed": True / False,
    "bitget_perp_listed": True / False,
    "cex_trace_rows": [
        {"exchange": "Binance", "status": "已上线" | "未上线", "ts": "YYYY-MM-DD" | "—", "since": "..."},
        ...
    ],
}
```

v0.6 (2026-05-24, Phase B.2)
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from i18n import t   # v0.6.2 i18n


_BINANCE_PERP_INFO = "https://fapi.binance.com/fapi/v1/exchangeInfo"


def _curl_json(url: str, timeout: int = 8) -> dict[str, Any] | None:
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout), url],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
            timeout=timeout + 5,   # v0.9.9: subprocess ceiling > curl --max-time (deadlock guard)
        )
        if proc.returncode != 0:
            return None
        return json.loads(proc.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _ts_to_date(ts_ms: int | None) -> str | None:
    if ts_ms is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def probe_binance_perp(symbol: str) -> dict[str, Any]:
    """Return {listed, pair, onboard_ts_ms, onboard_date}."""
    doc = _curl_json(_BINANCE_PERP_INFO)
    if doc is None:
        return {"listed": False, "pair": None, "onboard_ts_ms": None, "onboard_date": None, "_probe_status": "API_DOWN"}
    target = f"{symbol}USDT"
    for s in doc.get("symbols", []):
        if s.get("symbol") == target:
            onboard_ms = s.get("onboardDate")
            return {
                "listed": True,
                "pair": target,
                "onboard_ts_ms": onboard_ms,
                "onboard_date": _ts_to_date(onboard_ms),
                "_probe_status": "OK",
            }
    return {"listed": False, "pair": None, "onboard_ts_ms": None, "onboard_date": None, "_probe_status": "OK"}


def probe_aster_perp(symbol: str) -> dict[str, Any]:
    """Aster perp probe. Aster's API surface varies; for v0.6 phase B we mark
    as 'unverified' unless future spec confirms a stable endpoint.

    Returns {listed: bool | None, ...}. listed=None means probe not attempted.
    """
    return {
        "listed": None,
        "pair": None,
        "onboard_date": None,
        "_probe_status": "NOT_IMPLEMENTED",
    }


def probe_bitget_perp(symbol: str) -> dict[str, Any]:
    """Same as Aster: NOT_IMPLEMENTED in v0.6 phase B. Caller treats listed=None
    as 'unknown' not 'no'.
    """
    return {
        "listed": None,
        "pair": None,
        "onboard_date": None,
        "_probe_status": "NOT_IMPLEMENTED",
    }


def run(symbol: str, alpha_listing_date: str) -> dict[str, Any]:
    """Section CEX-TRACE entrypoint.

    Args:
        symbol: token symbol (uppercase, e.g. "TOKEN")
        alpha_listing_date: "YYYY-MM-DD"

    Returns full cex_trace + tier_classification update dict (see module docstring).
    """
    binance = probe_binance_perp(symbol)
    aster = probe_aster_perp(symbol)
    bitget = probe_bitget_perp(symbol)

    has_binance = binance.get("listed", False)
    has_non_binance = any(
        x.get("listed") is True
        for x in (aster, bitget)
    )

    # Tier derivation (per Rule 0)
    if has_non_binance:
        tier = "S3"
        s2_date = binance.get("onboard_date") if has_binance else None
        s3_date = (
            aster.get("onboard_date") if aster.get("listed")
            else bitget.get("onboard_date") if bitget.get("listed")
            else None
        )
    elif has_binance:
        tier = "S2"
        s2_date = binance.get("onboard_date")
        s3_date = None
    else:
        tier = "S1"
        s2_date = None
        s3_date = None

    # Build cex_trace_rows for report rendering (v0.6.2 i18n)
    dash = t("common.none_dash")
    def _row(exchange: str, probe: dict, label_if_listed: str) -> dict:
        if probe.get("listed") is True:
            return {
                "exchange": exchange,
                "status": t("section.cex_trace.status_listed"),
                "ts": probe.get("onboard_date") or dash,
                "since": t("section.cex_trace.since_prefix",
                           text=_days_ago_text(probe.get("onboard_ts_ms"))),
            }
        if probe.get("listed") is False:
            return {"exchange": exchange,
                    "status": t("section.cex_trace.status_not_listed"),
                    "ts": dash, "since": dash}
        # None = NOT_IMPLEMENTED
        return {"exchange": exchange,
                "status": t("section.cex_trace.status_unverified"),
                "ts": dash, "since": dash}

    cex_trace_rows = [
        _row("Binance", binance, t("sec1.cex_trace.perp_label", exchange="Binance")),
        _row("Aster", aster, t("sec1.cex_trace.perp_label", exchange="Aster")),
        _row("Bitget", bitget, t("sec1.cex_trace.perp_label", exchange="Bitget")),
    ]

    return {
        "tier": tier,
        "s1_date": alpha_listing_date,
        "s2_date": s2_date,
        "s3_date": s3_date,
        "has_binance_perp": has_binance,
        "binance_perp_pair": binance.get("pair"),
        "binance_perp_onboard_ts": binance.get("onboard_ts_ms"),
        "aster_perp_listed": aster.get("listed"),
        "bitget_perp_listed": bitget.get("listed"),
        "cex_trace_rows": cex_trace_rows,
        "_probes": {
            "binance": binance["_probe_status"],
            "aster": aster["_probe_status"],
            "bitget": bitget["_probe_status"],
        },
    }


def _days_ago_text(ts_ms: int | None) -> str:
    if ts_ms is None:
        return t("common.none_dash")
    try:
        seconds = int(ts_ms) / 1000
        now = datetime.now(tz=timezone.utc).timestamp()
        days = int((now - seconds) / 86400)
        if days < 60:
            return t("section.cex_trace.ago_days", days=days)
        return t("section.cex_trace.ago_months", months=days // 30)
    except (ValueError, TypeError):
        return t("common.none_dash")


if __name__ == "__main__":
    import argparse, sys
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("symbol")
    ap.add_argument("--alpha-listing-date", required=True)
    args = ap.parse_args()
    print(json.dumps(run(args.symbol, args.alpha_listing_date), ensure_ascii=False, indent=2))
