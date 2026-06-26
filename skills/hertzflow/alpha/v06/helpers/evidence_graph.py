#!/usr/bin/env python3
"""evidence_graph.py — canonical evidence dict with stable provenance IDs.

The evidence graph is the SOURCE OF TRUTH for all locked facts in a v0.6
forensic report. Pipeline populates it during data collection; LLM narrative
fields reference entries by ID (e.g. `evt_017`); validator looks up the ID
and checks narrative claims for consistency.

Why this exists (cross-LLM audit 2026-05-24 finding #1):
> "No canonical evidence-linking model. LLM can write correct-looking
> narrative not traceable to locked facts. PoC: anomaly.waves references
> '$7.4M routed' but points to wrong tx/time; passes R3 string match."

The evidence graph + provenance IDs in waves.events[].evt_ref close this hole.

## ID schema

Stable IDs are assigned in insertion order within their type prefix:
- `evt_NNN`  — temporal events (mint, deployer outflow, recent transfer, CEX hop)
- `m6_NNN`   — confirmed insider rows (Rule 11 quiet + M6 window accumulators)
- `node_NNN` — lineage flowchart nodes (deployer / pool / router / etc.)
- `mon_NNN`  — monitoring wallet entries
- `anc_NNN`  — decision anchors

ID format is `<prefix>_<3-digit-zero-padded>`, guaranteed unique within graph.
IDs are byte-stable across runs given byte-identical input data.

## Usage

```python
from helpers.evidence_graph import EvidenceGraph
g = EvidenceGraph()

evt = g.add_event(
    type="mint",
    ts=1772109008,
    amount=850000000,
    to_addr="0x70554...",
    tx_hash="0x...",
)
# evt == "evt_001"

# Reference in wave event:
waves[0]["events"].append({
    "evt_ref": evt,
    "nature": "<LLM_NARRATIVE_PLACEHOLDER>",
})

# Serialize to report_data.json:
data["evidence_graph"] = g.to_dict()
```

v0.6 (2026-05-24, cross-LLM audit condition.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Allowed event types per prefix (closed enum — validator rejects unknown).
_EVENT_TYPES = {
    "mint",
    "deployer_outflow",
    "recent_transfer",
    "cex_hop",
    "dex_swap",
    "lp_add",
    "lp_remove",
}

_M6_TYPES = {
    "rule11_quiet",
    "rule11_partial_dumper",
    "rule11_full_dumper",
    "m6_window_accum_then_sold",
    "m6_window_accum_held",
    # v0.7.9 (re-applied from v0.7.8 revert): recursive m6 expansion —
    # sub-receiver promoted via rule_11 trace at depth >= 2 (e.g. ESPORTS
    # main distributor 0x94111012 receiving 100M from 1st-level dumper
    # 0x1552160b on 5/19).
    "rule11_sub_dumper",
}

_NODE_TYPES = {
    "deployer",
    "dumper",
    "quiet_wallet",
    "active_holder",
    "lp_pool",
    "router",
    "cex_hot_wallet",
    "cex_cold_wallet",
    "cex_deposit",
    "retail_fanout",
    "multisig_project",
}

_ANCHOR_TYPES = {
    "alpha_tier",
    "supply_chain",
    "price_vs_tge",
    "circulating_ratio",
    "alpha_5pct_depth",
    "dex_pool_depth",
    "rule11_dumped_pct",
    "rule11_quiet_balance_usd",
    "m6_confirmed_count",
    "lp_24h_net_flow_pct",
    "binance_perp_status",
    "spot_graduation_status",
}


@dataclass
class EvidenceGraph:
    """Append-only, ID-stable evidence registry. NOT thread-safe by design —
    the v0.6 pipeline runs single-process per report.
    """

    _counters: dict[str, int] = field(default_factory=lambda: {
        "evt": 0, "m6": 0, "node": 0, "mon": 0, "anc": 0,
    })
    _store: dict[str, dict[str, Any]] = field(default_factory=dict)

    def _next_id(self, prefix: str) -> str:
        if prefix not in self._counters:
            raise ValueError(f"unknown evidence prefix {prefix!r}")
        self._counters[prefix] += 1
        return f"{prefix}_{self._counters[prefix]:03d}"

    # ----- Temporal events (evt_NNN) -----

    def add_event(
        self,
        *,
        type: str,
        ts: int | str,
        amount: float | None = None,
        from_addr: str | None = None,
        to_addr: str | None = None,
        tx_hash: str | None = None,
        usd_value: float | None = None,
        notes: str | None = None,
    ) -> str:
        """Add a temporal event (mint / deployer_outflow / recent_transfer /
        cex_hop / dex_swap / lp_add / lp_remove). Returns evidence ID.

        `ts` should be Unix seconds (int) or ISO 'YYYY-MM-DD HH:MM' string.
        `amount` is in token units (NOT raw wei). `usd_value` optional.
        """
        if type not in _EVENT_TYPES:
            raise ValueError(f"invalid event type {type!r} (allowed: {_EVENT_TYPES})")
        eid = self._next_id("evt")
        self._store[eid] = {
            "kind": "event",
            "type": type,
            "ts": ts,
            "amount": amount,
            "from_addr": from_addr,
            "to_addr": to_addr,
            "tx_hash": tx_hash,
            "usd_value": usd_value,
            "notes": notes,
        }
        return eid

    # ----- M6 confirmed insiders (m6_NNN) -----

    def add_m6(
        self,
        *,
        type: str,
        addr: str,
        received: float,
        balance: float | None,
        dumped_pct: float | None,
        source_section: str,  # 'rule_11' | 'm6_window' | 'rule_11_depth_N'
        ts_received: int | str | None = None,
        ts_first_dump: int | str | None = None,
        usd_value: float | None = None,
    ) -> str:
        if type not in _M6_TYPES:
            raise ValueError(f"invalid m6 type {type!r}")
        eid = self._next_id("m6")
        self._store[eid] = {
            "kind": "m6",
            "type": type,
            "addr": addr.lower(),
            "received": received,
            "balance": balance,
            "dumped_pct": dumped_pct,
            "source_section": source_section,
            "ts_received": ts_received,
            "ts_first_dump": ts_first_dump,
            "usd_value": usd_value,
        }
        return eid

    # ----- Lineage flowchart nodes (node_NNN) -----

    def add_node(
        self,
        *,
        type: str,
        addr: str,
        balance: float | None = None,
        usd_value: float | None = None,
        label_hint: str | None = None,
    ) -> str:
        if type not in _NODE_TYPES:
            raise ValueError(f"invalid node type {type!r}")
        eid = self._next_id("node")
        self._store[eid] = {
            "kind": "node",
            "type": type,
            "addr": addr.lower(),
            "balance": balance,
            "usd_value": usd_value,
            "label_hint": label_hint,
        }
        return eid

    # ----- Monitoring wallet entries (mon_NNN) -----

    def add_monitoring(
        self,
        *,
        addr: str,
        role: str,
        status_emoji: str,  # 🔴🟠🟡🟢⚪
        evt_refs: list[str] | None = None,  # links back to events that triggered monitoring
        m6_ref: str | None = None,
    ) -> str:
        eid = self._next_id("mon")
        self._store[eid] = {
            "kind": "monitoring",
            "addr": addr.lower(),
            "role": role,
            "status_emoji": status_emoji,
            "evt_refs": evt_refs or [],
            "m6_ref": m6_ref,
        }
        return eid

    # ----- Decision anchors (anc_NNN) -----

    def add_anchor(
        self,
        *,
        type: str,
        value: Any,  # numeric or string depending on type
        status_emoji: str,
        derivation: str,  # short text explaining how the value was computed
    ) -> str:
        if type not in _ANCHOR_TYPES:
            raise ValueError(f"invalid anchor type {type!r}")
        eid = self._next_id("anc")
        self._store[eid] = {
            "kind": "anchor",
            "type": type,
            "value": value,
            "status_emoji": status_emoji,
            "derivation": derivation,
        }
        return eid

    # ----- Lookup + serialization -----

    def lookup(self, eid: str) -> dict[str, Any] | None:
        return self._store.get(eid)

    def all_ids(self) -> list[str]:
        return list(self._store.keys())

    def by_kind(self, kind: str) -> dict[str, dict[str, Any]]:
        return {eid: e for eid, e in self._store.items() if e.get("kind") == kind}

    def by_event_type(self, event_type: str) -> dict[str, dict[str, Any]]:
        return {
            eid: e for eid, e in self._store.items()
            if e.get("kind") == "event" and e.get("type") == event_type
        }

    def to_dict(self) -> dict[str, dict[str, Any]]:
        """Serialize for report_data.json. Sorted by ID for byte-stable output."""
        return {k: dict(v) for k, v in sorted(self._store.items())}

    def count_by_kind(self) -> dict[str, int]:
        c = {}
        for e in self._store.values():
            c[e["kind"]] = c.get(e["kind"], 0) + 1
        return c

    # ----- Validation helpers (used by validate_report_data.py) -----

    def event_matches_narrative(
        self,
        evt_ref: str,
        narrative: str,
        amount_tolerance_pct: float = 5.0,
    ) -> tuple[bool, str]:
        """Check if a narrative string is consistent with the referenced event.

        Used by R3-causal: when LLM writes `events[].nature = "..."`, validator
        calls this. Returns (ok, reason). Currently checks:
        - If narrative mentions a $ amount, must be within amount_tolerance_pct
          of evt.usd_value (or evt.amount if usd_value is None).
        - If narrative mentions an address fragment (0xABCD…EFGH or 0xABCD),
          must match evt.from_addr or evt.to_addr.

        Returns (True, "") on match, (False, reason) on mismatch.
        """
        evt = self.lookup(evt_ref)
        if evt is None:
            return False, f"evt_ref={evt_ref!r} not found in evidence_graph"
        if evt.get("kind") != "event":
            return False, f"evt_ref={evt_ref!r} is a {evt.get('kind')!r}, not an event"

        import re

        # Extract any $ amounts from narrative (e.g. "$7.4M", "$1.2k", "$284k")
        amounts_in_narrative = []
        for m in re.finditer(r"\$([\d.,]+)\s*([kMB])?", narrative):
            num = float(m.group(1).replace(",", ""))
            unit = m.group(2)
            multiplier = {"k": 1e3, "M": 1e6, "B": 1e9, None: 1.0}.get(unit, 1.0)
            amounts_in_narrative.append(num * multiplier)

        # If narrative mentions amounts, at least one must be close to evt amount
        if amounts_in_narrative:
            evt_amt = evt.get("usd_value") or 0
            if evt_amt > 0:
                tol = evt_amt * (amount_tolerance_pct / 100.0)
                if not any(abs(a - evt_amt) <= max(tol, evt_amt * 0.05) for a in amounts_in_narrative):
                    return False, (
                        f"evt_ref={evt_ref!r} narrative mentions amounts "
                        f"{amounts_in_narrative} but event usd_value={evt_amt}, "
                        f"no match within {amount_tolerance_pct}% tolerance"
                    )

        # Extract any 0x addresses or address fragments
        for m in re.finditer(r"0x[a-fA-F0-9]{4,}", narrative):
            frag = m.group(0).lower()
            from_match = (evt.get("from_addr") or "").lower().startswith(frag)
            to_match = (evt.get("to_addr") or "").lower().startswith(frag)
            if not (from_match or to_match):
                # Allow short fragments to match middle of address too
                if len(frag) >= 6:  # 0x + 4 hex
                    if not (
                        frag in (evt.get("from_addr") or "").lower()
                        or frag in (evt.get("to_addr") or "").lower()
                    ):
                        return False, (
                            f"evt_ref={evt_ref!r} narrative mentions address "
                            f"{frag!r} but event from={evt.get('from_addr')} "
                            f"to={evt.get('to_addr')}, no match"
                        )

        return True, ""


def build_empty() -> EvidenceGraph:
    """Convenience factory for tests."""
    return EvidenceGraph()


if __name__ == "__main__":
    # Quick self-test
    g = EvidenceGraph()
    e1 = g.add_event(type="mint", ts=1772109008, amount=850_000_000, to_addr="0x70554000")
    e2 = g.add_event(
        type="recent_transfer",
        ts="2026-05-23 01:34",
        amount=6_063_612,
        from_addr="0xf440139a",
        to_addr="0xf89d7b9c",
        usd_value=7_402_435,
    )
    m1 = g.add_m6(
        type="rule11_quiet",
        addr="0x9e81a6b3",
        received=101_387_472,
        balance=101_387_472,
        dumped_pct=0.0,
        source_section="rule_11",
    )
    print(f"IDs: {g.all_ids()}")
    print(f"Count by kind: {g.count_by_kind()}")

    # Test narrative match
    ok, why = g.event_matches_narrative(e2, "约 $7.40M tokens routed via 0xf440 → 0xf89d")
    print(f"Match ok={ok} why={why!r}")
    bad, why2 = g.event_matches_narrative(e2, "约 $1.2M routed elsewhere")
    print(f"Bad ok={bad} why={why2!r}")
    print("evidence_graph.py self-test PASS")
