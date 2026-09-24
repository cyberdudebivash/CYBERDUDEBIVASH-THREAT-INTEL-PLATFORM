#!/usr/bin/env python3
"""
tests/test_r2_report_publisher_retirement_backlog.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- P0 retirement-backlog deadlock guard.

INCIDENT (sentinel-blogger runs 35910500527, 35919409972, 35955730472,
2026-09-23/24): runs #2333/#2334 failed before STAGE 3.5a, so ~16h of
report expirations accumulated. STAGE 3.5a then planned
    new: 61   expired: 320   DELETE: 623   (budget 500) -> BLOCKED
enforce_budget() correctly refused the over-budget plan, but because the
plan was all-or-nothing the 61 new-report PUTs were refused with it, and
because nothing was retired the backlog could only grow. STAGE 3.5.1 then
found every new report missing, purged the public report index to 0 and
hard-failed -- on every run from then on.

Contract pinned here:
  * retirement never plans more DELETEs than the per-run ceiling;
  * new-report PUTs are never held hostage to the retirement backlog;
  * the backlog drains across runs, oldest first, whole items only;
  * the ceiling, zero-LIST rule and fail-closed guard are unchanged.
"""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import r2_report_publisher as pub  # noqa: E402
from r2_cost_guard import R2Budgets, enforce_budget  # noqa: E402


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestRetirementBacklog(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 23, 21, 34, 47, tzinfo=timezone.utc)
        self._written: list[Path] = []

    def tearDown(self):
        for p in self._written:
            p.unlink(missing_ok=True)
            try:
                p.parent.rmdir()
                p.parent.parent.rmdir()
            except OSError:
                pass

    def _incident_state(self) -> dict:
        """320 expired ids -> 623 objects (303 html+pdf, 17 html-only),
        ages spread 25h..345h so ordering is observable."""
        items = {}
        for i in range(320):
            ts = self.now - timedelta(hours=25 + i)
            entry = {"canonical_ts": _iso(ts), "html_key": f"reports/2026/09/intel--old{i:04d}.html"}
            if i < 303:
                entry["pdf_key"] = f"reports/pdf/intel--old{i:04d}.pdf"
            items[f"intel--old{i:04d}"] = entry
        return {"schema_version": "1.0", "items": items}

    def _new_candidates(self, n: int) -> list[dict]:
        from generate_intel_reports import rel_report_path
        cands = []
        for i in range(n):
            ts = self.now - timedelta(hours=1)
            item = {"id": f"intel--testbacklognew{i:03d}", "timestamp": _iso(ts)}
            path = rel_report_path(item)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"<html>new report {i}</html>", encoding="utf-8")
            self._written.append(path)
            cands.append({"item": item, "id": item["id"], "canonical_ts": ts})
        return cands

    def test_incident_uncapped_plan_is_blocked_as_before(self):
        """Documents the pre-fix shape: without a cap the planner emits 623
        deletes and the (unchanged) guard blocks the whole plan."""
        plan, _puts, deletes = pub.build_plan([], self._incident_state(), 24, self.now)
        self.assertEqual(len(deletes), 623)
        with self.assertRaises(pub.R2BudgetExceeded):
            enforce_budget(plan, R2Budgets(), is_report_plan=True)

    def test_incident_capped_plan_publishes_new_reports_within_budget(self):
        state = self._incident_state()
        cands = self._new_candidates(3)
        budgets = R2Budgets()
        plan, puts, deletes = pub.build_plan(cands, state, 24, self.now,
                                             max_deletes=budgets.max_report_deletes_per_run)
        enforce_budget(plan, budgets, is_report_plan=True)  # must not raise
        self.assertEqual(len(puts), 3, "new-report PUTs must survive a retirement backlog")
        self.assertLessEqual(len(deletes), budgets.max_report_deletes_per_run)
        self.assertEqual(plan.delete, len(deletes))
        self.assertEqual(plan.list_calls, 0)

    def test_oldest_retired_first_and_items_never_split(self):
        state = self._incident_state()
        _plan, _puts, deletes = pub.build_plan([], state, 24, self.now, max_deletes=500)
        by_id: dict[str, set] = {}
        for op in deletes:
            by_id.setdefault(op["id"], set()).add(op["kind"])
        for intel_id, kinds in by_id.items():
            entry = state["items"][intel_id]
            expected = {k for k in ("html", "pdf") if entry.get(f"{k}_key")}
            self.assertEqual(kinds, expected, f"{intel_id} was split across runs")
        oldest = sorted(state["items"], key=lambda k: state["items"][k]["canonical_ts"])
        self.assertEqual(set(by_id), set(oldest[: len(by_id)]), "must retire the oldest items first")

    def test_backlog_drains_across_runs_without_losing_ids(self):
        state = self._incident_state()
        total_deleted: set[str] = set()
        for _run in range(5):
            _plan, _puts, deletes = pub.build_plan([], state, 24, self.now, max_deletes=500)
            self.assertLessEqual(len(deletes), 500)
            ids = {op["id"] for op in deletes}
            total_deleted |= ids
            for i in ids:  # what execute_plan() does on a successful delete
                state["items"].pop(i, None)
            if not deletes:
                break
        self.assertEqual(len(total_deleted), 320, "every expired id is eventually retired")
        self.assertEqual(state["items"], {})

    def test_deferred_ids_stay_tracked(self):
        state = self._incident_state()
        _plan, _puts, deletes = pub.build_plan([], state, 24, self.now, max_deletes=500)
        retired = {op["id"] for op in deletes}
        deferred = set(state["items"]) - retired
        self.assertTrue(deferred, "fixture must exercise deferral")
        for i in deferred:
            self.assertIn("html_key", state["items"][i], "deferred entries must be left intact")

    def test_zero_ceiling_retires_nothing_but_still_publishes(self):
        cands = self._new_candidates(1)
        plan, puts, deletes = pub.build_plan(cands, self._incident_state(), 24, self.now, max_deletes=0)
        self.assertEqual(deletes, [])
        self.assertEqual(len(puts), 1)
        enforce_budget(plan, R2Budgets(max_report_deletes_per_run=0), is_report_plan=True)

    def test_main_passes_the_env_ceiling_to_the_planner(self):
        src = (REPO_ROOT / "scripts" / "r2_report_publisher.py").read_text(encoding="utf-8")
        self.assertIn("max_deletes=budgets.max_report_deletes_per_run", src)


if __name__ == "__main__":
    unittest.main()
