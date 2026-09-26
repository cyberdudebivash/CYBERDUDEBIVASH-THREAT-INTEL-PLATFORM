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

Follow-up (same day): the customer Reports catalog (api/reports/*.json) is
built at STAGE 3.3.7 and uploaded at STAGE 3.5, so it still listed 1 report
next to 28 advisories until the next run. STAGE 5.4.0d rebuilds it,
verifies it against R2 and re-uploads it with
`r2_upload.py --reports-index-only` (TestCatalogRefresh*).
"""
import json
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
import r2_upload  # noqa: E402


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


class TestCatalogRefreshWiring(unittest.TestCase):
    def setUp(self):
        self.steps = _steps()
        self.publish = _index(self.steps, "STAGE 5.4.0c")
        self.refresh = _index(self.steps, "STAGE 5.4.0d")
        self.validator = _index(self.steps, "STAGE 5.4.1 ")

    def test_refresh_runs_after_publish_before_validator_and_dist(self):
        self.assertLess(self.publish, self.refresh)
        self.assertLess(self.refresh, self.validator)
        self.assertLess(self.refresh, _index(self.steps, "STAGE 5.4.6 "))

    def test_refresh_reuses_existing_chain_in_order(self):
        run = self.steps[self.refresh]["run"]
        build = run.index("python3 scripts/build_reports_index.py")
        verify = run.index("python3 scripts/r2_reports_integrity.py")
        upload = run.index("python3 scripts/r2_upload.py --reports-index-only")
        self.assertLess(build, verify)
        self.assertLess(verify, upload)

    def test_refresh_never_blocks_the_pipeline(self):
        step = self.steps[self.refresh]
        self.assertTrue(step.get("continue-on-error"))
        self.assertIn("PIPELINE_LOCKED", str(step.get("if", "")))
        self.assertIn("CF_R2_REPORTS_KEY_ID", step.get("env", {}))


class TestCatalogRefreshUpload(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, rel, data):
        path = self.dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    def _run(self, s3_ok=True):
        uploaded = []

        def fake_cp(src, bucket, key, endpoint, **_kw):
            uploaded.append((bucket, key))
            return s3_ok

        with mock.patch.object(r2_upload, "REPO_ROOT", self.dir), \
             mock.patch.object(r2_upload, "get_credentials", return_value=("acct", "k", "s")), \
             mock.patch.object(r2_upload, "install_awscli"), \
             mock.patch.object(r2_upload, "emit_summary"), \
             mock.patch.object(r2_upload, "s3_cp", side_effect=fake_cp), \
             mock.patch.object(r2_upload.os, "chdir"):
            code = 0
            try:
                r2_upload.main_reports_index_only()
            except SystemExit as exc:
                code = exc.code
        return uploaded, code

    def test_uploads_exactly_the_three_catalog_keys_to_data_bucket(self):
        fresh = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for rel, _dst in r2_upload.REPORTS_INDEX_FILES:
            self._write(rel, {"generated_at": fresh, "reports": []})
        uploaded, code = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(
            sorted(uploaded),
            sorted((r2_upload.BUCKET_DATA, dst) for _src, dst in r2_upload.REPORTS_INDEX_FILES),
        )

    def test_stale_catalog_is_never_uploaded(self):
        fresh = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self._write("api/reports/index.json", {"generated_at": fresh, "reports": []})
        self._write("api/reports/latest.json", {"generated_at": "2026-08-26T09:55:27Z", "reports": []})
        uploaded, code = self._run()
        self.assertEqual(code, 0)
        keys = [k for _b, k in uploaded]
        self.assertIn("api/reports/index.json", keys)
        self.assertNotIn("api/reports/latest.json", keys)

    def test_failed_put_exits_nonzero(self):
        fresh = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self._write("api/reports/index.json", {"generated_at": fresh, "reports": []})
        _uploaded, code = self._run(s3_ok=False)
        self.assertEqual(code, 1)

    def test_stage_3_5_plan_still_carries_the_same_keys(self):
        fresh = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for rel, _dst in r2_upload.REPORTS_INDEX_FILES:
            self._write(rel, {"generated_at": fresh, "reports": []})
        with mock.patch.object(r2_upload, "REPO_ROOT", self.dir):
            keys = {dst for _src, dst in r2_upload.build_upload_plan()}
        for _src, dst in r2_upload.REPORTS_INDEX_FILES:
            self.assertIn(dst, keys)


if __name__ == "__main__":
    unittest.main()
