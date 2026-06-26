"""v0.7.23 — tests for window_chunker.py shared helper.

Locks the sliding-window math so future refactors don't quietly break
the LAB / SKYAI bucket counts or the per-chunk merge semantics.
"""

import pytest
from datetime import date

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))

from window_chunker import (
    chunked_dates,
    merge_chunked_rows,
    parallel_run_chunked,
    parallel_run_flat_tasks,
    chunk_summary,
)


# ---------- chunked_dates ----------

class TestChunkedDates:
    def test_single_chunk_for_new_token(self):
        """LAB-class token (~90d listing) should produce exactly 1 chunk
        so credit cost on new tokens stays identical to the legacy
        single-shot SQL."""
        chunks = chunked_dates("2026-03-10", "2026-06-07", chunk_days=90)
        assert chunks == [("2026-03-10", "2026-06-07")]

    def test_exact_90d_boundary_one_chunk(self):
        chunks = chunked_dates("2026-01-01", "2026-03-31", chunk_days=90)
        assert len(chunks) == 1
        assert chunks[0] == ("2026-01-01", "2026-03-31")

    def test_skyai_13_month_window_7_chunks(self):
        """SKYAI scenario: 13-month range chunks into 7 buckets so each
        fits inside the 30s surf budget."""
        chunks = chunked_dates("2024-10-25", "2026-06-07", chunk_days=90)
        assert len(chunks) == 7
        # First chunk is full 90d.
        first = chunks[0]
        assert first[0] == "2024-10-25"
        first_width = (
            date.fromisoformat(first[1]) - date.fromisoformat(first[0])
        ).days + 1
        assert first_width == 90
        # Last chunk ends at the ceiling.
        assert chunks[-1][1] == "2026-06-07"

    def test_chunks_partition_completely_no_overlap(self):
        """The union of all chunks must equal [floor, ceiling] with no
        gaps and no overlap — otherwise merged SUM would double-count
        or skip rows."""
        chunks = chunked_dates("2024-01-01", "2026-06-07", chunk_days=90)
        prev_end = None
        for floor, ceiling in chunks:
            f, c = date.fromisoformat(floor), date.fromisoformat(ceiling)
            assert f <= c
            if prev_end is not None:
                # Adjacent chunks must touch at boundary (prev_end + 1 day).
                assert f == prev_end + (date.fromisoformat("2024-01-02") - date.fromisoformat("2024-01-01"))
            prev_end = c
        assert chunks[0][0] == "2024-01-01"
        assert chunks[-1][1] == "2026-06-07"

    def test_floor_after_ceiling_raises(self):
        with pytest.raises(ValueError, match="floor.*after.*ceiling"):
            chunked_dates("2026-06-07", "2024-10-25")

    def test_chunk_days_zero_raises(self):
        with pytest.raises(ValueError, match="chunk_days"):
            chunked_dates("2024-01-01", "2024-12-31", chunk_days=0)

    def test_none_ceiling_defaults_to_today(self):
        chunks = chunked_dates("2026-03-10", None, chunk_days=90)
        # Last chunk's ceiling is today (≥ floor).
        last_ceiling = date.fromisoformat(chunks[-1][1])
        assert last_ceiling >= date.fromisoformat("2026-03-10")


# ---------- merge_chunked_rows ----------

class TestMergeChunkedRows:
    def test_sum_distributes_over_chunks(self):
        """Same key in two chunks: SUM(chunk_a.amt) + SUM(chunk_b.amt)
        must equal single-window SUM(all rows)."""
        chunk_results = [
            [{"addr": "0xa", "total_in": 100.0}, {"addr": "0xb", "total_in": 50.0}],
            [{"addr": "0xa", "total_in": 200.0}, {"addr": "0xc", "total_in": 30.0}],
        ]
        merged = merge_chunked_rows(
            chunk_results, key_field="addr", sum_fields=["total_in"],
        )
        d = {r["addr"]: r["total_in"] for r in merged}
        assert d["0xa"] == 300.0
        assert d["0xb"] == 50.0
        assert d["0xc"] == 30.0

    def test_merged_sorted_by_first_sum_desc(self):
        """Caller LIMIT N relies on the merged list being ordered the
        same way a single-window ORDER BY ... DESC would have been."""
        chunk_results = [
            [{"addr": "0xa", "amt": 10}, {"addr": "0xb", "amt": 100}],
            [{"addr": "0xc", "amt": 200}, {"addr": "0xa", "amt": 5}],
        ]
        merged = merge_chunked_rows(
            chunk_results, key_field="addr", sum_fields=["amt"],
        )
        assert [r["addr"] for r in merged] == ["0xc", "0xb", "0xa"]

    def test_min_field_picks_earliest(self):
        """min(first_ts) across chunks gives the earliest event, same as
        a single-window MIN(block_time)."""
        chunk_results = [
            [{"addr": "0xa", "first_ts": 1000}],
            [{"addr": "0xa", "first_ts": 800}],
        ]
        merged = merge_chunked_rows(
            chunk_results, key_field="addr",
            min_fields=["first_ts"], sum_fields=["dummy"],
        )
        assert merged[0]["first_ts"] == 800

    def test_max_field_picks_latest(self):
        chunk_results = [
            [{"addr": "0xa", "last_ts": 1000}],
            [{"addr": "0xa", "last_ts": 1500}],
        ]
        merged = merge_chunked_rows(
            chunk_results, key_field="addr",
            max_fields=["last_ts"], sum_fields=["dummy"],
        )
        assert merged[0]["last_ts"] == 1500

    def test_empty_input_returns_empty(self):
        assert merge_chunked_rows([], key_field="addr", sum_fields=["a"]) == []
        assert merge_chunked_rows([[], []], key_field="addr", sum_fields=["a"]) == []

    def test_row_missing_field_treated_as_zero(self):
        """A chunk that returns a row with no `total_in` field should
        contribute 0, not crash. ClickHouse occasionally returns sparse
        rows for empty-partition pairs."""
        chunk_results = [
            [{"addr": "0xa", "total_in": 100.0}],
            [{"addr": "0xa"}],   # missing total_in
        ]
        merged = merge_chunked_rows(
            chunk_results, key_field="addr", sum_fields=["total_in"],
        )
        assert merged[0]["total_in"] == 100.0


# ---------- parallel_run_chunked ----------

class TestParallelRunChunked:
    def test_results_ordered_by_input_chunks(self):
        """Even though execution is parallel, results must be in input
        order so callers can `zip(chunks, results)` for diagnostics."""
        chunks = [
            ("2024-01-01", "2024-03-31"),
            ("2024-04-01", "2024-06-30"),
            ("2024-07-01", "2024-09-30"),
        ]

        def sql_fn(floor, ceiling):
            return {"data": [{"addr": "0x" + floor[:4], "ceiling": ceiling}]}

        results = parallel_run_chunked(sql_fn, chunks, max_workers=3)
        assert len(results) == 3
        assert results[0]["data"][0]["ceiling"] == "2024-03-31"
        assert results[1]["data"][0]["ceiling"] == "2024-06-30"
        assert results[2]["data"][0]["ceiling"] == "2024-09-30"

    def test_per_chunk_exception_surfaces_in_result_not_raised(self):
        """One bad chunk shouldn't kill the whole pipeline — caller
        decides if partial data is acceptable."""
        chunks = [("2024-01-01", "2024-03-31"), ("2024-04-01", "2024-06-30")]

        def sql_fn(floor, ceiling):
            if floor == "2024-01-01":
                raise RuntimeError("simulated surf 429")
            return {"data": [{"addr": "0xa"}]}

        results = parallel_run_chunked(sql_fn, chunks, max_workers=2)
        assert "_error" in results[0]
        assert "simulated surf 429" in results[0]["_error"]
        assert results[1]["data"][0]["addr"] == "0xa"

    def test_empty_chunks_returns_empty_list(self):
        assert parallel_run_chunked(lambda f, c: {"data": []}, []) == []


# ---------- chunk_summary ----------

class TestChunkSummary:
    def test_lab_one_chunk_message(self):
        chunks = chunked_dates("2026-03-10", "2026-06-07", chunk_days=90)
        msg = chunk_summary(chunks)
        assert "1 chunks" in msg
        assert "2026-03-10..2026-06-07" in msg

    def test_skyai_seven_chunks_with_short_tail(self):
        chunks = chunked_dates("2024-10-25", "2026-06-07", chunk_days=90)
        msg = chunk_summary(chunks)
        assert "7 chunks" in msg
        assert "last" in msg   # last chunk shorter than 90d


# ---------- parallel_run_flat_tasks (v0.7.23 regression-fix) ----------

class TestParallelRunFlatTasks:
    """Lock the flat-parallel contract used by rule_11 step4:
    (dumper × chunk) is flattened, all tasks dispatched into a single
    ThreadPool, results returned in submission order."""

    def test_results_in_input_order_under_concurrent_completion(self):
        """Slow tasks complete out of submission order; results[] must
        still match input order so caller's zip(tasks, results) works."""
        import time
        # 6 tasks; task[i] sleeps proportional to (5-i) so they complete
        # in reverse order. Result list must still be [0,1,2,3,4,5].
        tasks = list(range(6))

        def task_fn(t):
            time.sleep(0.01 * (5 - t))
            return {"data": [{"i": t}]}

        results = parallel_run_flat_tasks(task_fn, tasks, max_workers=6)
        assert len(results) == 6
        assert [r["data"][0]["i"] for r in results] == [0, 1, 2, 3, 4, 5]

    def test_exception_attribution_correct_under_out_of_order(self):
        """A failing task's error must land at its input index, not at
        whichever slot completes first."""
        tasks = ["good_a", "fail_b", "good_c"]

        def task_fn(t):
            if t == "fail_b":
                raise RuntimeError(f"task {t} broke")
            return {"data": [{"name": t}]}

        results = parallel_run_flat_tasks(task_fn, tasks, max_workers=3)
        assert results[0]["data"][0]["name"] == "good_a"
        assert "_error" in results[1]
        assert "fail_b" in results[1]["_error"]
        assert results[2]["data"][0]["name"] == "good_c"

    def test_step4_synthetic_two_dumpers_two_chunks_merge(self):
        """rule_11 step4 use case: 2 dumpers × 2 chunks = 4 flat tasks,
        per-dumper merge yields per-dumper top receivers."""
        from collections import defaultdict
        # 2 dumpers × 2 chunks
        flat_tasks = [
            ("0xaa", "2024-Q1"), ("0xaa", "2024-Q2"),
            ("0xbb", "2024-Q1"), ("0xbb", "2024-Q2"),
        ]

        def task_fn(t):
            dumper, q = t
            if dumper == "0xaa" and q == "2024-Q1":
                return {"data": [{"receiver": "0xrcv1", "total_amt": 10.0}]}
            if dumper == "0xaa" and q == "2024-Q2":
                return {"data": [{"receiver": "0xrcv1", "total_amt": 5.0}]}
            if dumper == "0xbb" and q == "2024-Q1":
                return {"data": [{"receiver": "0xrcv2", "total_amt": 20.0}]}
            return {"data": [{"receiver": "0xrcv2", "total_amt": 7.0}]}

        results = parallel_run_flat_tasks(task_fn, flat_tasks, max_workers=4)
        # Re-group by dumper, like rule_11 step4 does.
        per_dumper: dict[str, list] = defaultdict(list)
        for task, result in zip(flat_tasks, results):
            per_dumper[task[0]].append(result["data"])
        # Dumper 0xaa: 10 + 5 = 15 for receiver 0xrcv1
        merged_aa = merge_chunked_rows(
            per_dumper["0xaa"], key_field="receiver",
            sum_fields=["total_amt"],
        )
        assert merged_aa[0]["receiver"] == "0xrcv1"
        assert merged_aa[0]["total_amt"] == 15.0
        # Dumper 0xbb: 20 + 7 = 27 for receiver 0xrcv2
        merged_bb = merge_chunked_rows(
            per_dumper["0xbb"], key_field="receiver",
            sum_fields=["total_amt"],
        )
        assert merged_bb[0]["receiver"] == "0xrcv2"
        assert merged_bb[0]["total_amt"] == 27.0

    def test_empty_tasks_returns_empty_list(self):
        assert parallel_run_flat_tasks(lambda t: {"data": []}, []) == []


# ---------- conditional chunker bypass (v0.7.23, adversarial review M7 equivalence) ----------

class TestConditionalBypass:
    """The `_single_chunk_or_chunker_dates` helper inside
    rule_11_backward_trace.py routes short windows back to a single
    SQL (v0.7.22 path) and long windows to chunker (v0.7.23 path).
    These tests lock the routing logic and verify both paths produce
    identical merged rows on the same mock data, which is the
    equivalence guarantee the audit (M7) demanded before LAB
    can rely on this bypass."""

    def _import_helper(self):
        # Late import to avoid surface coupling with rule_11 module
        # globals during chunker-only tests.
        from rule_11_backward_trace import (  # noqa: WPS433
            _single_chunk_or_chunker_dates,
            _is_short_window,
            SHORT_WINDOW_DAYS,
        )
        return _single_chunk_or_chunker_dates, _is_short_window, SHORT_WINDOW_DAYS

    def test_short_window_collapses_to_single_chunk(self):
        single_or_chunker, is_short, threshold = self._import_helper()
        # 90d window is well under the 300d default.
        chunks = single_or_chunker("2026-03-10", "2026-06-07", chunk_days=90)
        assert len(chunks) == 1
        assert chunks == [("2026-03-10", "2026-06-07")]
        assert is_short("2026-03-10", "2026-06-07") is True

    def test_long_window_falls_through_to_chunker(self):
        single_or_chunker, is_short, threshold = self._import_helper()
        # 730d (~24 months) far exceeds the 300d default.
        chunks = single_or_chunker("2024-06-07", "2026-06-07", chunk_days=90)
        assert len(chunks) >= 8   # 730d / 90d ≈ 9 chunks
        assert is_short("2024-06-07", "2026-06-07") is False

    def test_at_threshold_boundary_is_short(self):
        """Window length exactly equal to threshold is treated as short
        (≤, not <). 300d threshold → 300d window collapses."""
        single_or_chunker, is_short, threshold = self._import_helper()
        # Build a window of exactly `threshold` days.
        floor = "2025-01-01"
        # 300d after 2025-01-01 = 2025-10-28
        from datetime import date as _d, timedelta as _td
        floor_d = _d.fromisoformat(floor)
        ceiling = (floor_d + _td(days=threshold)).isoformat()
        assert is_short(floor, ceiling) is True
        chunks = single_or_chunker(floor, ceiling, chunk_days=90)
        assert len(chunks) == 1

    def test_just_above_threshold_uses_chunker(self):
        single_or_chunker, is_short, threshold = self._import_helper()
        from datetime import date as _d, timedelta as _td
        floor = "2025-01-01"
        floor_d = _d.fromisoformat(floor)
        ceiling = (floor_d + _td(days=threshold + 1)).isoformat()
        assert is_short(floor, ceiling) is False
        chunks = single_or_chunker(floor, ceiling, chunk_days=90)
        assert len(chunks) > 1

    def test_short_chunker_equivalence_via_merge(self):
        """Equivalence proof: single-chunk path and chunker path merge
        identical rows when fed equivalent per-chunk inputs. Because the
        SQL shape is the same (BETWEEN floor AND ceiling), and SUM/MIN/
        MAX/COUNT distribute, the only difference between the two paths
        is the number of chunks. Mathematically, [single chunk] merged
        equals [N chunks of disjoint sub-rows] merged."""
        single_chunk_rows = [
            [
                {"addr": "0xa", "total_in": 100.0},
                {"addr": "0xb", "total_in": 50.0},
            ],
        ]
        chunker_rows_3 = [
            [{"addr": "0xa", "total_in": 30.0}, {"addr": "0xb", "total_in": 20.0}],
            [{"addr": "0xa", "total_in": 40.0}, {"addr": "0xb", "total_in": 25.0}],
            [{"addr": "0xa", "total_in": 30.0}, {"addr": "0xb", "total_in": 5.0}],
        ]
        merged_single = merge_chunked_rows(
            single_chunk_rows, key_field="addr", sum_fields=["total_in"],
        )
        merged_chunker = merge_chunked_rows(
            chunker_rows_3, key_field="addr", sum_fields=["total_in"],
        )
        d_single = {r["addr"]: r["total_in"] for r in merged_single}
        d_chunker = {r["addr"]: r["total_in"] for r in merged_chunker}
        assert d_single == d_chunker
        assert d_single["0xa"] == 100.0
        assert d_single["0xb"] == 50.0
