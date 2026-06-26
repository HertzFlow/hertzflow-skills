"""wallet_cluster_graph_detector.py — v0.8.6.5.0

Builds a wallet-to-wallet transfer graph from a candidate set, identifies
connected components (= operator clusters), filters false positives.

# Why this exists

BEAT case (2026-06-12): Bubblemaps Twitter shows BEAT has ~$8B FDV pump with
LAB/RIVER same insider rug pattern. Visible via wallet transfer graph
clustering — "looks-like-retail wallets actually transferring to each other".

Our prior detectors catch specific patterns:
- mint_authority: 0x0 → addr (mint power)
- mint_authority_dumps: mint_authority → cluster
- mining_fed: mining cluster → DEX
- high_throughput_dumpers: high-tx wallets
- cex_fanout: CEX → hub → recipients
- rule_11: deployer-rooted m6 lineage

But we miss **wallet ↔ wallet** edges that don't fit any of these — e.g.
operator A sends to operator B (no CEX involved, no mint involved, no m6
ancestry). Bubblemaps catches these.

# Algorithm

1. Take master cluster set (= funding_attribution._master_cluster_addrs)
   + cex_fanout recipients + top_holders ≥ 0.1% supply. dedup.
2. Query transfers WHERE from IN (cands) AND to IN (cands) AND
   amount >= min_edge_weight. GROUP BY (from, to). ORDER BY amount DESC.
3. Build graph in Python (union-find). Edges = (from, to, amount).
4. Apply 5-layer false-positive defense:
   - L1: Pre-filter via Arkham label (skip DEX router / CEX / MM)
   - L2: Edge weight threshold (skip wash bot small edges)
   - L3: Node degree filter (cluster-internal degree ≥ 2)
   - L4: Cluster size threshold (≥ 3 nodes)
   - L5: Time concentration (edges within time_window)
5. Output: list of clusters [{addrs, n_edges, total_weight, max_edge_weight}]

# Surf compliance

- 1 main SQL with bidirectional IN filter (or chunked if N > 300)
- max_rows = 9000 (< surf 10K cap)
- Sequential chunks (no concurrent SQL inflation)
- No worker increase
- Reuse cex_fanout's resolved Arkham labels (no new label calls if labels
  passed in)

# Threshold tunings (M35 pre-register)

- min_edge_weight_pct_supply: 0.5% (BEAT 1B → 5M tokens per edge)
- min_cluster_size: 3 nodes
- min_node_degree: 2 cluster-internal edges
- max_chunk_size: 200 addresses (3-chunk × 3-chunk = 9 SQL max)
- arkham_exclude_classifications: {DEX_ROUTER, CEX_DEPOSIT, CEX_HOT_WALLET,
                                   LIQUIDITY_PROVIDER}
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from chain_router import transfers_table  # noqa: E402
from chain_router import decimals_factor_str  # v0.9.7

_SURF_MAX_ROWS_CAP = 9000
_SURF_MAX_LOOKBACK_DAYS = 365

# Default thresholds (pre-registered M35).
DEFAULT_MIN_EDGE_WEIGHT_PCT_SUPPLY = 0.005  # 0.5%
DEFAULT_MIN_CLUSTER_SIZE = 3
DEFAULT_MIN_NODE_DEGREE = 2
DEFAULT_CHUNK_SIZE = 200
DEFAULT_ARKHAM_EXCLUDE = frozenset({
    "DEX_ROUTER", "CEX_DEPOSIT", "CEX_HOT_WALLET", "LIQUIDITY_PROVIDER",
})


def _chain_is_valid_addr(a: str) -> bool:
    return isinstance(a, str) and a.startswith("0x") and len(a) == 42


class UnionFind:
    """Simple union-find for connected components."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        if self.parent.get(x, x) == x:
            self.parent.setdefault(x, x)
            return x
        root = self.find(self.parent[x])
        self.parent[x] = root
        return root

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[rx] = ry


def discover_wallet_cluster_graph(
    *,
    ca: str,
    candidates: list[str],
    total_supply: float | None = None,
    date_floor: str = "2020-01-01",
    arkham_labels: dict[str, dict] | None = None,
    resolve_candidate_labels: bool = True,
    source_categorization: dict[str, str] | None = None,
    min_edge_weight_pct_supply: float = DEFAULT_MIN_EDGE_WEIGHT_PCT_SUPPLY,
    min_cluster_size: int = DEFAULT_MIN_CLUSTER_SIZE,
    min_node_degree: int = DEFAULT_MIN_NODE_DEGREE,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    arkham_exclude: frozenset[str] = DEFAULT_ARKHAM_EXCLUDE,
    skip: bool = False,
) -> dict[str, Any]:
    """Run wallet cluster graph detection.

    Args:
        ca: Token contract address (lowercase).
        candidates: List of candidate wallet addresses to consider as graph
            nodes. Typically from funding_attribution._master_cluster_addrs
            + top_holders ≥ 0.1% + cex_fanout recipients.
        total_supply: Token total supply, for min_edge_weight calculation.
        date_floor: 'YYYY-MM-DD', surf 365d window clamp applied.
        arkham_labels: dict of {addr: {classification, label, entity_name}}.
            Reused from cex_fanout's resolved labels (no new resolve calls).
            If None, no L1 filtering — all wallets considered.
        min_edge_weight_pct_supply: 0.5% — edges below this are noise/wash.
        min_cluster_size: 3 nodes minimum to count as cluster.
        min_node_degree: 2 — each node in cluster must have ≥2 cluster-
            internal edges. Drops single-edge bilateral noise.
        chunk_size: Address chunk size for SQL splitting (default 200).
        arkham_exclude: Classifications to filter out via L1.
        skip: If True, return empty result without surf calls.

    Returns:
        {
          "clusters": [
            {"addrs": [a, b, c, ...],  # sorted by total weight desc
             "n_edges": int,
             "total_weight_tokens": float,
             "max_edge_weight_tokens": float,
             "arkham_unlabeled_pct": float,  # how much we couldn't pre-filter
             }
          ],
          "summary": {
            "n_clusters": int,
            "n_cluster_addrs_total": int,
            "n_candidates_input": int,
            "n_candidates_post_l1": int,
            "n_edges_total": int,
            "n_chunks_run": int,
          },
          "_debug": {date_floor_clamped, thresholds, ...},
          "_error": only on hard failure.
        }
    """
    if skip:
        return {
            "clusters": [], "summary": _empty_summary(),
            "_debug": {"skipped": True},
        }
    ca = (ca or "").lower()
    if not ca or not _chain_is_valid_addr(ca):
        return {
            "clusters": [], "summary": _empty_summary(),
            "_error": f"invalid ca: {ca!r}",
        }
    if not candidates:
        return {
            "clusters": [], "summary": _empty_summary(),
            "_error": "empty candidates",
        }

    # Dedup + filter invalid candidates
    raw_set = {(c or "").lower() for c in candidates if _chain_is_valid_addr((c or "").lower())}

    # v0.8.6.5.2 adversarial review M1: resolve candidate Arkham labels (was thin — only
    # cex_fanout source labels passed in). One mega batch call ~3-5 credits.
    # Merge with passed arkham_labels (cex_fanout sources have priority).
    merged_labels: dict[str, dict] = dict(arkham_labels or {})
    if resolve_candidate_labels and raw_set:
        try:
            from surf_labels_probe import resolve_labels as _resolve_labels
            new_addrs = [a for a in sorted(raw_set) if a not in merged_labels]
            if new_addrs:
                got = _resolve_labels(new_addrs)
                for addr, info in (got or {}).items():
                    if addr.lower() not in merged_labels:
                        merged_labels[addr.lower()] = info
        except Exception as e:
            print(f"[wallet_cluster_graph] candidate label resolve failed (non-fatal): {str(e)[:120]}",
                  file=sys.stderr)

    # L1: Pre-filter via Arkham label (DEX router / CEX / MM)
    n_candidates_input = len(raw_set)
    if merged_labels:
        filtered = set()
        for addr in raw_set:
            cls = (merged_labels.get(addr) or {}).get("classification") or "UNLABELED"
            if cls in arkham_exclude:
                continue
            filtered.add(addr)
        candidates_set = filtered
    else:
        candidates_set = raw_set
    n_candidates_post_l1 = len(candidates_set)
    n_filtered_by_l1 = n_candidates_input - n_candidates_post_l1

    if len(candidates_set) < min_cluster_size:
        return {
            "clusters": [], "summary": {
                **_empty_summary(),
                "n_candidates_input": n_candidates_input,
                "n_candidates_post_l1": n_candidates_post_l1,
            },
            "_error": f"too few candidates: {len(candidates_set)} < min_cluster_size {min_cluster_size}",
        }

    # L2: Edge weight threshold
    min_edge_weight = (total_supply or 0) * min_edge_weight_pct_supply
    if min_edge_weight <= 0:
        min_edge_weight = 1_000_000  # 1M tokens fallback

    # Clamp date_floor to surf 365d window
    surf_window_floor = (date.today() - timedelta(days=_SURF_MAX_LOOKBACK_DAYS)).isoformat()
    date_floor_clamped = surf_window_floor if date_floor < surf_window_floor else date_floor

    # Chunk candidates if needed
    candidates_list = sorted(candidates_set)
    chunks = [candidates_list[i:i + chunk_size] for i in range(0, len(candidates_list), chunk_size)]
    n_chunks_run = 0
    all_edges: list[tuple[str, str, float]] = []

    from section_a_scope import _run_surf_with_retry

    for chunk_a in chunks:
        for chunk_b in chunks:
            sql = _build_chunk_sql(
                ca=ca,
                from_addrs=chunk_a,
                to_addrs=chunk_b,
                date_floor=date_floor_clamped,
                min_edge_weight=min_edge_weight,
            )
            try:
                doc, err = _run_surf_with_retry(
                    ["surf", "onchain-sql"],
                    stdin=json.dumps({"sql": sql, "max_rows": _SURF_MAX_ROWS_CAP}),
                    base_timeout=60, max_attempts=3,
                )
                n_chunks_run += 1
            except Exception as e:
                print(f"[wallet_cluster_graph] chunk SQL failed: {str(e)[:120]}", file=sys.stderr)
                continue
            if not doc:
                continue
            rows = (doc.get("data") or [])
            for r in rows:
                f_a = (r.get("from_addr") or "").lower()
                t_a = (r.get("to_addr") or "").lower()
                amt = float(r.get("amt") or 0)
                if not f_a or not t_a or f_a == t_a:
                    continue
                if amt < min_edge_weight:
                    continue
                all_edges.append((f_a, t_a, amt, r.get("min_block_time"), r.get("max_block_time")))

    # audit C1 fix: aggregate to UNDIRECTED edges. A→B and B→A are
    # different transfer directions but same connectivity. Sum weights for
    # evidence, but use unique undirected neighbors for L3 degree filter.
    undirected_edge_weights: dict[tuple[str, str], float] = {}
    # v0.8.6.5.2 adversarial review M2: edge time stats per undirected edge
    edge_time_stats: dict[tuple[str, str], dict] = {}
    for entry in all_edges:
        f_a, t_a, amt = entry[0], entry[1], entry[2]
        e_min_t = entry[3] if len(entry) > 3 else None
        e_max_t = entry[4] if len(entry) > 4 else None
        a, b = sorted([f_a, t_a])  # canonical undirected key
        key = (a, b)
        undirected_edge_weights[key] = undirected_edge_weights.get(key, 0.0) + amt
        ts = edge_time_stats.setdefault(key, {"min_t": None, "max_t": None})
        if e_min_t and (ts["min_t"] is None or e_min_t < ts["min_t"]):
            ts["min_t"] = e_min_t
        if e_max_t and (ts["max_t"] is None or e_max_t > ts["max_t"]):
            ts["max_t"] = e_max_t

    # Build undirected adjacency
    adjacency: dict[str, set[str]] = defaultdict(set)
    node_weight: dict[str, float] = defaultdict(float)
    for (a, b), w in undirected_edge_weights.items():
        adjacency[a].add(b)
        adjacency[b].add(a)
        node_weight[a] += w
        node_weight[b] += w

    # audit C1 fix: iterative 2-core pruning. Repeatedly drop nodes
    # with unique-neighbor degree < min_node_degree until stable.
    keep_nodes = set(adjacency.keys())
    changed = True
    while changed:
        changed = False
        to_drop = {n for n in keep_nodes
                   if len(adjacency[n] & keep_nodes) < min_node_degree}
        if to_drop:
            keep_nodes -= to_drop
            changed = True

    # Union-find over surviving (kept) nodes only
    uf = UnionFind()
    for a in keep_nodes:
        for b in adjacency[a] & keep_nodes:
            uf.union(a, b)

    # Group by connected component
    components: dict[str, set[str]] = defaultdict(set)
    for node in keep_nodes:
        root = uf.find(node)
        components[root].add(node)

    # L4: Cluster size threshold
    clusters: list[dict[str, Any]] = []
    for root, nodes in components.items():
        if len(nodes) < min_cluster_size:
            continue
        # Compute cluster-internal undirected edges
        cluster_edges = [(a, b, w) for (a, b), w in undirected_edge_weights.items()
                         if a in nodes and b in nodes]
        if not cluster_edges:
            continue
        total_weight = sum(w for _, _, w in cluster_edges)
        max_edge = max(w for _, _, w in cluster_edges)
        # Arkham unlabeled % (uses merged_labels for accurate count)
        n_unlabeled = sum(1 for n in nodes
                          if (merged_labels.get(n) or {}).get("classification") in (None, "UNLABELED"))
        unlabeled_pct = (n_unlabeled / len(nodes) * 100) if nodes else 0
        # Sort cluster addresses by node_weight desc
        addrs_sorted = sorted(nodes, key=lambda a: node_weight.get(a, 0), reverse=True)
        # v0.8.6.5.2 adversarial review M2: time concentration L5
        edge_min_t_list = [edge_time_stats[(a, b)]["min_t"]
                           for (a, b) in [tuple(sorted([e[0], e[1]])) for e in cluster_edges]
                           if edge_time_stats.get((a, b), {}).get("min_t")]
        edge_max_t_list = [edge_time_stats[(a, b)]["max_t"]
                           for (a, b) in [tuple(sorted([e[0], e[1]])) for e in cluster_edges]
                           if edge_time_stats.get((a, b), {}).get("max_t")]
        cluster_min_t = min(edge_min_t_list) if edge_min_t_list else None
        cluster_max_t = max(edge_max_t_list) if edge_max_t_list else None
        cluster_window_days: int | None = None
        if cluster_min_t and cluster_max_t:
            try:
                from datetime import datetime
                _min = datetime.fromisoformat(str(cluster_min_t).replace("Z", "").split(".")[0])
                _max = datetime.fromisoformat(str(cluster_max_t).replace("Z", "").split(".")[0])
                cluster_window_days = (_max - _min).days
            except Exception:
                pass
        # v0.8.6.5.2 adversarial review M5: per-cluster source overlap (n_new = wallets
        # not in source_categorization or marked 'top_holder_only').
        if source_categorization:
            src_counts: dict[str, int] = defaultdict(int)
            for a in nodes:
                src = source_categorization.get(a, "unknown")
                src_counts[src] += 1
            n_new_in_cluster = src_counts.get("top_holder_only", 0) + src_counts.get("unknown", 0)
        else:
            src_counts = {}
            n_new_in_cluster = 0
        clusters.append({
            "addrs": addrs_sorted,
            "n_edges": len(cluster_edges),
            "total_weight_tokens": total_weight,
            "max_edge_weight_tokens": max_edge,
            "arkham_unlabeled_pct": unlabeled_pct,
            "min_block_time": cluster_min_t,
            "max_block_time": cluster_max_t,
            "time_window_days": cluster_window_days,
            "source_overlap_counts": dict(src_counts),
            "n_new_in_op_union": n_new_in_cluster,
        })

    # Sort clusters by total weight desc
    clusters.sort(key=lambda c: c["total_weight_tokens"], reverse=True)

    n_cluster_addrs_total = sum(len(c["addrs"]) for c in clusters)
    # v0.8.6.5.2 adversarial review M5: aggregate n_new_in_op_union across all clusters
    n_new_in_op_union_total = sum(c.get("n_new_in_op_union", 0) for c in clusters)
    n_existing_in_master_total = n_cluster_addrs_total - n_new_in_op_union_total

    # audit C2 fix: query current balances for all cluster wallets.
    # cex_fanout_tail-style: render uses these to inject cluster wallets'
    # balances into operator_in_circ when they're not in top 100.
    all_cluster_addrs = sorted({a for c in clusters for a in c["addrs"]})
    cluster_balances: dict[str, float] = {}
    if all_cluster_addrs:
        sql_bal = _build_balance_sql(
            ca=ca, addrs=all_cluster_addrs, date_floor=date_floor_clamped,
        )
        try:
            doc_bal, _err = _run_surf_with_retry(
                ["surf", "onchain-sql"],
                stdin=json.dumps({"sql": sql_bal, "max_rows": _SURF_MAX_ROWS_CAP}),
                base_timeout=30, max_attempts=2,
            )
            if doc_bal:
                for r in (doc_bal.get("data") or []):
                    addr = (r.get("addr") or "").lower()
                    if addr:
                        cluster_balances[addr] = float(r.get("balance") or 0)
        except Exception as e:
            print(f"[wallet_cluster_graph] balance query failed (non-fatal): {str(e)[:120]}",
                  file=sys.stderr)
    # Annotate clusters with per-addr balance
    for c in clusters:
        c["addr_balances"] = {a: cluster_balances.get(a, 0.0) for a in c["addrs"]}
        c["cluster_balance_total_tokens"] = sum(c["addr_balances"].values())

    return {
        "clusters": clusters,
        "summary": {
            "n_clusters": len(clusters),
            "n_cluster_addrs_total": n_cluster_addrs_total,
            "n_candidates_input": n_candidates_input,
            "n_candidates_post_l1": n_candidates_post_l1,
            "n_filtered_by_l1": n_filtered_by_l1,
            "n_edges_total": len(undirected_edge_weights),
            "n_chunks_run": n_chunks_run,
            "n_new_in_op_union": n_new_in_op_union_total,
            "n_existing_in_master": n_existing_in_master_total,
        },
        "_debug": {
            "date_floor_clamped": date_floor_clamped,
            "min_edge_weight_tokens": min_edge_weight,
            "min_cluster_size": min_cluster_size,
            "min_node_degree": min_node_degree,
            "chunk_size": chunk_size,
            "n_chunks": len(chunks),
        },
    }


def _empty_summary() -> dict[str, Any]:
    return {
        "n_clusters": 0,
        "n_cluster_addrs_total": 0,
        "n_candidates_input": 0,
        "n_candidates_post_l1": 0,
        "n_edges_total": 0,
        "n_chunks_run": 0,
    }


def _build_balance_sql(*, ca: str, addrs: list[str], date_floor: str) -> str:
    """Compute current balance per address: sum(in) - sum(out) since date_floor."""
    addr_in = "(" + ",".join(f"'{a}'" for a in addrs) + ")"
    array_list = "[" + ",".join(f"'{a}'" for a in addrs) + "]"
    return (
        "WITH ins AS ("
        f'SELECT "to" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amt '
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' AND block_date >= '{date_floor}' "
        f'AND "to" IN {addr_in} GROUP BY a'
        "), outs AS ("
        f'SELECT "from" AS a, sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amt '
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' AND block_date >= '{date_floor}' "
        f'AND "from" IN {addr_in} GROUP BY a'
        ") "
        "SELECT r.a AS addr, COALESCE(ins.amt, 0) - COALESCE(outs.amt, 0) AS balance "
        f"FROM (SELECT arrayJoin({array_list}) AS a) r "
        "LEFT JOIN ins ON r.a = ins.a LEFT JOIN outs ON r.a = outs.a"
    )


def _build_chunk_sql(
    *,
    ca: str,
    from_addrs: list[str],
    to_addrs: list[str],
    date_floor: str,
    min_edge_weight: float,
) -> str:
    """Build SQL for one chunk pair (from_chunk × to_chunk)."""
    from_in = "(" + ",".join(f"'{a}'" for a in from_addrs) + ")"
    to_in = "(" + ",".join(f"'{a}'" for a in to_addrs) + ")"
    # v0.8.6.5.2 adversarial review M2: emit min/max block_time per edge for time
    # concentration L5 filter.
    return (
        f'SELECT "from" AS from_addr, "to" AS to_addr, '
        f"sum(toFloat64(toDecimal256(amount_raw,0))/{decimals_factor_str()}) AS amt, "
        f"count() AS n_tx, "
        f"min(block_time) AS min_block_time, "
        f"max(block_time) AS max_block_time "
        f"FROM {transfers_table()} "
        f"WHERE contract_address = '{ca}' "
        f'AND "from" IN {from_in} AND "to" IN {to_in} '
        f"AND block_date >= '{date_floor}' "
        f'AND "from" != "to" '
        f'AND "from" != \'0x0000000000000000000000000000000000000000\' '
        f'AND "to" != \'0x0000000000000000000000000000000000000000\' '
        f"GROUP BY from_addr, to_addr "
        f"HAVING amt >= {min_edge_weight} "
        f"ORDER BY amt DESC LIMIT {_SURF_MAX_ROWS_CAP}"
    )


__all__ = [
    "discover_wallet_cluster_graph",
    "DEFAULT_MIN_EDGE_WEIGHT_PCT_SUPPLY",
    "DEFAULT_MIN_CLUSTER_SIZE",
    "DEFAULT_MIN_NODE_DEGREE",
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_ARKHAM_EXCLUDE",
]
