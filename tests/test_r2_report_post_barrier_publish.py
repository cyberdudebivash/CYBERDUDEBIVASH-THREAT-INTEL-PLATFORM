"""
tests/test_r2_report_post_barrier_publish.py

P0 regression guard (2026-09-26, uncertified-fallback incident).

Production run: STAGE 3.5a (scripts/r2_report_publisher.py) published the
2 reports rendered at that point. The feed then grew to 21 in-window items,
and STAGE 5.4.0b (Report Continuity Final Barrier) rendered the other 19
with --upload-r2. That uploader reads CF_R2_ENDPOINT, which
sentinel-blogger.yml never sets, so it logged r2_uploaded=0 r2_failed=19
without trying a single PUT. /reports/YYYY/MM/<id>.html then served the
Worker's uncertified fallback (~8s) for 21 of 28 live reports.

Fix: the barrier no longer passes --upload-r2. The new STAGE 5.4.0c re-runs
r2_report_publisher.py, the single sentinel-apex-reports writer, after the
barrier and before STAGE 5.4.1.

TestWorkflowWiring locks the step order and wiring.
TestSecondPublishIsIncremental proves the second publisher run in a job
PUTs only the late renders, not the reports STAGE 3.5a already published.
"""
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import r2_report_publisher as pub  # noqa: E402


def _steps():
    wf = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    return wf["jobs"]["generate-and-sync"]["steps"]


def _index(steps, prefix):
    for i, step in enumerate(steps):
        if str(step.get("name", "")).startswith(prefix):
            return i
    raise AssertionError(f"step starting with {prefix!r} not found")


class TestWorkflowWiring(unittest.TestCase):
    def setUp(self):
        self.steps = _steps()
        self.barrier = _index(self.steps, "STAGE 5.4.0b")
        self.publish = _index(self.steps, "STAGE 5.4.0c")
        self.validator = _index(self.steps, "STAGE 5.4.1 ")

    def test_order_barrier_then_publish_then_validator(self):
        self.assertLess(self.barrier, self.publish)
        self.assertLess(self.publish, self.validator)

    def test_publish_runs_canonical_publisher_with_reports_token(self):
        step = self.steps[self.publish]
        self.assertIn("python3 scripts/r2_report_publisher.py", step["run"])
        env = step.get("env", {})
        self.assertIn("CF_R2_REPORTS_KEY_ID", env)
        self.assertIn("CF_R2_REPORTS_SECRET_KEY", env)

    def test_publish_never_blocks_the_hard_gate(self):
        step = self.steps[self.publish]
        self.assertTrue(step.get("continue-on-error"))
        self.assertIn("PIPELINE_LOCKED", str(step.get("if", "")))

    def test_publish_state_is_uploaded_after_publish(self):
        late_upload = _index(self.steps, "Upload Intel State to R2 (post-manifest-repair, final)")
        self.assertLess(self.publish, late_upload)

    def test_barrier_no_longer_uses_dead_uploader(self):
        run = self.steps[self.barrier]["run"]
        self.assertNotIn("--upload-r2", run)
        self.assertIn("--only-missing", run)
        self.assertIn("--since-hours", run)


class TestSecondPublishIsIncremental(unittest.TestCase):
    def test_only_late_renders_are_put(self):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        items = [{"id": f"intel--t{i}", "timestamp": ts, "processed_at": ts} for i in range(4)]

        with tempfile.TemporaryDirectory() as tmp:
            reports_root = Path(tmp) / "reports"

            def fake_rel(item):
                return reports_root / "2026" / "09" / f"{item['id']}.html"

            def render(item):
                p = fake_rel(item)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(f"<!DOCTYPE html>{item['id']}", encoding="utf-8")

            with mock.patch.object(pub, "rel_report_path", side_effect=fake_rel), \
                 mock.patch.object(pub, "REPO_ROOT", Path(tmp)), \
                 mock.patch.object(pub, "PDF_DIR", Path(tmp) / "pdf"):
                state = {"schema_version": "1.0", "items": {}}

                # STAGE 3.5a: only the first 2 are rendered.
                for it in items[:2]:
                    render(it)
                cands = pub.build_publish_candidates(items, 24, now)
                _plan, puts, deletes = pub.build_plan(cands, state, 24, now)
                self.assertEqual(sorted(o["id"] for o in puts), ["intel--t0", "intel--t1"])
                self.assertEqual(deletes, [])
                for op in puts:  # what execute_plan() records on a successful PUT
                    state["items"][op["id"]]["html_sha256"] = op["sha256"]

                # STAGE 5.4.0b renders the rest; STAGE 5.4.0c publishes.
                for it in items[2:]:
                    render(it)
                cands = pub.build_publish_candidates(items, 24, now)
                _plan, puts, deletes = pub.build_plan(cands, state, 24, now)
                self.assertEqual(sorted(o["id"] for o in puts), ["intel--t2", "intel--t3"])
                self.assertEqual(deletes, [])


if __name__ == "__main__":
    unittest.main()
