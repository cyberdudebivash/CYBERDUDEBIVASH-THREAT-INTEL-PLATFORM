"""
tests/test_r2_reports_verifier.py

RX-PUB-A0 Phase 9: scripts/r2_reports_verifier.py cannot be exercised against
real R2 in this environment (no CF_ACCOUNT_ID / aws CLI available -- see
docs/RX_PUB_A0_EXECUTION_PATH.md Section 5). These tests instead verify its
decision logic directly by mocking the R2 head/get primitives it reuses from
scripts/r2_upload_verifier.py, proving the classification behavior
(REMOTE_VERIFIED / STALE_OR_DIVERGENT / FAILED / UNKNOWN) is correct for
each case the mission's Section 12 case table requires.
"""
import concurrent.futures
import hashlib
import json
import os
import sys
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import r2_reports_verifier as rrv  # noqa: E402


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _recent_timestamp() -> str:
    """P0 R2 COST AUDIT FIX: r2_reports_verifier.py now filters manifest
    entries to REPORT_WINDOW_HOURS via their canonical timestamp (see
    scripts/r2_reports_verifier.py's _load_in_window_entries()), matching
    scripts/r2_report_publisher.py's own in-window contract. Fixtures below
    that exercise main()'s dispatch/deadline/concurrency logic need a
    genuinely in-window timestamp to reach verify_one() at all -- same
    "dynamically-computed recent timestamp, not a fixed historical date"
    fix already applied to tests/test_report_materialization_barrier.py
    earlier in this same PR."""
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")


class TestVerifyOne(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_test_"))
        self.report_path = self.tmp / "intel--testverify0000.html"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, content: str) -> bytes:
        data = content.encode("utf-8")
        self.report_path.write_bytes(data)
        return data

    def test_matching_content_is_remote_verified(self):
        data = self._write("<!DOCTYPE html><html>correct content</html>")

        with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 200, "content_length": len(data), "etag": "x"}), \
             patch.object(rrv, "_get_object_bytes", return_value=data):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--testverify0000.html", skip_public=True)

        self.assertEqual(result["publication_state"], "REMOTE_VERIFIED")
        self.assertEqual(result["artifact_sha256"], _sha256(data))
        self.assertEqual(result["remote_sha256"], _sha256(data))
        self.assertIsNotNone(result["remote_verified_at"])
        self.assertNotIn("error", result)

    def test_divergent_content_is_stale_or_divergent(self):
        local_data = self._write("<!DOCTYPE html><html>LOCAL fixed content</html>")
        remote_data = b"<!DOCTYPE html><html>REMOTE stale content, different bytes</html>"

        with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 200, "content_length": len(remote_data), "etag": "y"}), \
             patch.object(rrv, "_get_object_bytes", return_value=remote_data):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--testverify0000.html", skip_public=True)

        self.assertEqual(result["publication_state"], "STALE_OR_DIVERGENT")
        self.assertEqual(result["artifact_sha256"], _sha256(local_data))
        self.assertEqual(result["remote_sha256"], _sha256(remote_data))
        self.assertNotEqual(result["artifact_sha256"], result["remote_sha256"])
        self.assertIn("diverge", result["error"])

    def test_missing_remote_object_is_failed(self):
        self._write("<!DOCTYPE html><html>content</html>")

        with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 404, "content_length": 0, "etag": ""}), \
             patch.object(rrv._verifier, "_boto3_head_object", return_value=None):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--testverify0000.html", skip_public=True)

        self.assertEqual(result["publication_state"], "FAILED")
        self.assertIsNone(result["remote_sha256"])
        self.assertIn("does not exist", result["error"])

    def test_head_object_totally_unreachable_is_unknown(self):
        self._write("<!DOCTYPE html><html>content</html>")

        with patch.object(rrv._verifier, "_s3api_head_object", return_value=None), \
             patch.object(rrv._verifier, "_boto3_head_object", return_value=None):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--testverify0000.html", skip_public=True)

        self.assertEqual(result["publication_state"], "UNKNOWN")

    def test_get_object_failure_after_successful_head_is_unknown_not_verified(self):
        """A HEAD success with a failed GET must never be silently treated as
        verified -- that would be exactly the "successful aws s3 sync ==
        content-identity proof" fallacy the mission's Section 3 prohibits,
        just at a different layer."""
        self._write("<!DOCTYPE html><html>content</html>")

        with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 200, "content_length": 10, "etag": "z"}), \
             patch.object(rrv, "_get_object_bytes", return_value=None):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--testverify0000.html", skip_public=True)

        self.assertEqual(result["publication_state"], "UNKNOWN")
        self.assertIsNone(result["remote_sha256"])


class TestManifestSchema(unittest.TestCase):
    """Static check that the Phase 9 required JSON manifest fields are all
    present in verify_one()'s output shape, matching the mission's schema."""

    def test_result_shape_matches_phase9_schema_fields(self):
        REQUIRED_FIELDS = {
            "r2_key", "size_bytes", "generator", "artifact_sha256",
            "remote_sha256", "remote_verified_at", "publication_state",
            "public_sha256", "public_verified_at", "live_state",
            "public_response_headers",
            # RX-PUB-A0.6A
            "publication_gate_state", "customer_ready",
            "expected_live_behavior", "publication_gate_bypass",
        }
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="rrv_schema_"))
        try:
            p = tmp / "intel--schematest00000.html"
            data = p.write_bytes(b"<!DOCTYPE html><html>x</html>") and None
            with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 404, "content_length": 0, "etag": ""}), \
                 patch.object(rrv._verifier, "_boto3_head_object", return_value=None):
                result = rrv.verify_one(p, "reports/2026/08/intel--schematest00000.html", skip_public=True)
            missing = REQUIRED_FIELDS - set(result.keys())
            self.assertEqual(missing, set(), f"verify_one() result is missing required schema fields: {missing}")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestPublicHttpLayer(unittest.TestCase):
    """RX-PUB-A0.4 Phase 2: the public HTTP layer must run and classify
    independently of the R2 layer (it needs no R2 credentials at all), and
    must never treat a failed/missing fetch as verified -- the same
    "successful check != content-identity proof" principle already proven
    for the R2 layer, enforced here too."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_public_test_"))
        self.report_path = self.tmp / "intel--publictest00000.html"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, content: str) -> bytes:
        data = content.encode("utf-8")
        self.report_path.write_bytes(data)
        return data

    def _no_r2(self):
        return patch.object(rrv._verifier, "_s3api_head_object", return_value=None), \
               patch.object(rrv._verifier, "_boto3_head_object", return_value=None)

    def _gate_approved(self):
        """RX-PUB-A0.6A: publication-status mock for a report the gate says
        should be served -- expected_live_behavior == SERVE_CANONICAL_ARTIFACT."""
        return patch.object(
            rrv, "_fetch_publication_status",
            return_value={"customer_ready": True, "state": "CUSTOMER_READY", "reason_codes": [], "fetch_error": None},
        )

    def test_matching_public_bytes_is_live_verified(self):
        data = self._write("<!DOCTYPE html><html>correct content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": data, "status": 200, "headers": {"cf-ray": "abc", "content-type": "text/html; charset=utf-8"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--publictest00000.html")

        self.assertEqual(result["live_state"], "LIVE_VERIFIED")
        self.assertEqual(result["expected_live_behavior"], "SERVE_CANONICAL_ARTIFACT")
        self.assertEqual(result["public_sha256"], _sha256(data))
        self.assertIsNotNone(result["public_verified_at"])
        self.assertEqual(result["public_response_headers"]["cf-ray"], "abc")

    def test_divergent_public_bytes_is_live_stale_or_divergent(self):
        local_data = self._write("<!DOCTYPE html><html>LOCAL fixed content</html>")
        remote_data = b"<!DOCTYPE html><html>STALE customer-served content</html>"
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": remote_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--publictest00000.html")

        self.assertEqual(result["live_state"], "LIVE_STALE_OR_DIVERGENT")
        self.assertEqual(result["public_sha256"], _sha256(remote_data))
        self.assertNotEqual(result["artifact_sha256"], result["public_sha256"])
        self.assertIn("diverge", result["public_error"])

    def test_public_404_when_gate_expects_serving_is_live_missing_unexpected(self):
        """A gate-approved report that 404s at its public URL is a genuine,
        unexpected delivery defect -- distinct from a gate-driven denial."""
        self._write("<!DOCTYPE html><html>content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": None, "status": 404, "headers": {}, "error": "HTTP 404"}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--publictest00000.html")

        self.assertEqual(result["live_state"], "LIVE_MISSING_UNEXPECTED")
        self.assertIsNone(result["public_sha256"])

    def test_public_fetch_failure_is_live_fetch_failed_not_verified(self):
        """A network timeout or 5xx must never be silently treated as
        LIVE_VERIFIED -- the exact same "successful transfer != content
        identity" fallacy the R2 layer already guards against, at this
        layer too."""
        self._write("<!DOCTYPE html><html>content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, patch.object(rrv, "_fetch_public", return_value={"bytes": None, "status": 503, "headers": {}, "error": "HTTP 503"}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--publictest00000.html")

        self.assertEqual(result["live_state"], "LIVE_FETCH_FAILED")
        self.assertIsNone(result["public_sha256"])

    def test_skip_public_does_not_call_fetch_at_all(self):
        """--skip-public (cost-governance escape hatch) must genuinely skip
        the fetch, not just discard its result after paying for it."""
        self._write("<!DOCTYPE html><html>content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, patch.object(rrv, "_fetch_public") as mock_fetch:
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--publictest00000.html", skip_public=True)

        mock_fetch.assert_not_called()
        self.assertEqual(result["live_state"], "PENDING")

    def test_public_layer_runs_without_any_r2_credentials(self):
        """The public HTTP layer needs no R2 credentials -- proven by
        running it with the R2 helpers forced to their credential-absent
        return value (None), matching exactly what happens in this sandbox
        (no CF_ACCOUNT_ID) and confirming the two layers are independent."""
        data = self._write("<!DOCTYPE html><html>content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": data, "status": 200, "headers": {"content-type": "text/html"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--publictest00000.html")

        self.assertEqual(result["publication_state"], "UNKNOWN")  # R2 layer: no credentials
        self.assertEqual(result["live_state"], "LIVE_VERIFIED")   # Public layer: independent, still works


class TestPublicationGateAwareness(unittest.TestCase):
    """RX-PUB-A0.6A (mission Section 9/38): the public HTTP layer must
    distinguish a publication gate's intended denial from a genuine
    customer-delivery defect, and must hard-flag the one case that must
    never happen silently -- a gate-rejected report whose public route
    serves the protected body anyway."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_gate_test_"))
        self.report_path = self.tmp / "intel--gatetest000000.html"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, content: str) -> bytes:
        data = content.encode("utf-8")
        self.report_path.write_bytes(data)
        return data

    def _no_r2(self):
        return patch.object(rrv._verifier, "_s3api_head_object", return_value=None), \
               patch.object(rrv._verifier, "_boto3_head_object", return_value=None)

    def _gate_rejected(self, reason_codes=None):
        return patch.object(
            rrv, "_fetch_publication_status",
            return_value={
                "customer_ready": False, "state": "REJECTED",
                "reason_codes": reason_codes or ["P25_BELOW_THRESHOLD"], "fetch_error": None,
            },
        )

    def _gate_unresolvable(self):
        return patch.object(
            rrv, "_fetch_publication_status",
            return_value={"customer_ready": False, "state": "UNKNOWN", "reason_codes": ["ITEM_NOT_RESOLVABLE"], "fetch_error": None},
        )

    def test_gate_rejected_and_public_route_correctly_denies_is_expected_denial(self):
        """The common, correct case: a below-threshold report's public route
        returns its own non-HTML denial body (e.g. the gate's JSON 404).
        Must never be counted as a failure."""
        self._write("<!DOCTYPE html><html>full canonical content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_rejected(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": None, "status": 404, "headers": {}, "error": "HTTP 404"}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--gatetest000000.html")

        self.assertEqual(result["expected_live_behavior"], "DENY_PUBLICATION_GATE")
        self.assertEqual(result["live_state"], "LIVE_EXPECTED_DENIAL")
        self.assertFalse(result["publication_gate_bypass"])

    def test_gate_rejected_and_public_route_serves_json_denial_body_is_expected_denial(self):
        """A 200 status is also a correct denial as long as the body is not
        the protected HTML -- e.g. the gate's own JSON block response."""
        self._write("<!DOCTYPE html><html>full canonical content</html>")
        deny_body = json.dumps({"error": "Report unavailable", "status": "BLOCKED"}).encode("utf-8")
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_rejected(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": deny_body, "status": 200, "headers": {"content-type": "application/json; charset=utf-8"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--gatetest000000.html")

        self.assertEqual(result["live_state"], "LIVE_EXPECTED_DENIAL")
        self.assertFalse(result["publication_gate_bypass"])

    def test_gate_rejected_but_public_route_serves_html_body_is_publication_gate_bypass(self):
        """THE critical hard-defect test (mission Section 9/38, verbatim):
        customer_ready=false + public route serves an HTML body -> HARD
        DEFECT, regardless of whether the served bytes happen to match the
        canonical artifact. Never folded into LIVE_STALE_OR_DIVERGENT."""
        local_data = self._write("<!DOCTYPE html><html>full canonical content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_rejected(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": local_data, "status": 200, "headers": {"content-type": "text/html; charset=utf-8"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--gatetest000000.html")

        self.assertEqual(result["live_state"], "PUBLICATION_GATE_BYPASS")
        self.assertTrue(result["publication_gate_bypass"])
        self.assertIn("bypass", result["public_error"].lower())

    def test_gate_rejected_and_public_route_serves_different_html_body_is_still_bypass(self):
        """The bypass classification does not depend on hash equality --
        serving ANY HTML body when the gate says no is the defect."""
        self._write("<!DOCTYPE html><html>full canonical content</html>")
        different_html = b"<!DOCTYPE html><html>some other HTML entirely</html>"
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_rejected(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": different_html, "status": 200, "headers": {"content-type": "text/html"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--gatetest000000.html")

        self.assertEqual(result["live_state"], "PUBLICATION_GATE_BYPASS")
        self.assertTrue(result["publication_gate_bypass"])

    def test_resolver_miss_is_live_resolution_failed_not_a_hash_verdict(self):
        """ITEM_NOT_RESOLVABLE means the gate never evaluated this report --
        byte equality is not a meaningful question (mission Section 30,
        Question B unanswerable). Must not be counted as verified or as
        divergent either way, even when the served bytes exactly match the
        canonical artifact (RX-PUB-A0.6 Phase 0's confirmed live finding)."""
        local_data = self._write("<!DOCTYPE html><html>full canonical content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, self._gate_unresolvable(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": local_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--gatetest000000.html")

        self.assertEqual(result["expected_live_behavior"], "UNKNOWN_EXPECTATION")
        self.assertEqual(result["live_state"], "LIVE_RESOLUTION_FAILED")
        self.assertFalse(result["publication_gate_bypass"])

    def test_own_publication_status_fetch_failure_is_live_unknown_not_resolution_failed(self):
        """Distinct from a resolver miss: here OUR OWN call to
        publication-status failed (network/parse), which is a verifier-side
        transient, not evidence the platform's resolver has a gap."""
        local_data = self._write("<!DOCTYPE html><html>content</html>")
        p1, p2 = self._no_r2()
        with p1, p2, \
             patch.object(rrv, "_fetch_publication_status", return_value={"customer_ready": None, "state": None, "reason_codes": [], "fetch_error": "HTTP 503"}), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": local_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None}):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--gatetest000000.html")

        self.assertEqual(result["live_state"], "LIVE_UNKNOWN")
        self.assertFalse(result["publication_gate_bypass"])


class TestExpectedLiveBehavior(unittest.TestCase):
    """Unit-level coverage of the pure classification helpers, independent
    of the HTTP mocking in TestPublicationGateAwareness above."""

    def test_customer_ready_true_is_serve_canonical_artifact(self):
        self.assertEqual(
            rrv._expected_live_behavior({"customer_ready": True, "state": "CUSTOMER_READY", "reason_codes": [], "fetch_error": None}),
            "SERVE_CANONICAL_ARTIFACT",
        )

    def test_customer_ready_false_with_real_reason_is_deny_publication_gate(self):
        self.assertEqual(
            rrv._expected_live_behavior({"customer_ready": False, "state": "REJECTED", "reason_codes": ["P26_REJECTED"], "fetch_error": None}),
            "DENY_PUBLICATION_GATE",
        )

    def test_item_not_resolvable_is_unknown_expectation_even_though_customer_ready_is_false(self):
        """The distinguishing case this whole PR exists for: customer_ready
        being false does NOT always mean the gate made a real decision."""
        self.assertEqual(
            rrv._expected_live_behavior({"customer_ready": False, "state": "UNKNOWN", "reason_codes": ["ITEM_NOT_RESOLVABLE"], "fetch_error": None}),
            "UNKNOWN_EXPECTATION",
        )

    def test_fetch_error_is_unknown_expectation_regardless_of_other_fields(self):
        self.assertEqual(
            rrv._expected_live_behavior({"customer_ready": True, "state": "CUSTOMER_READY", "reason_codes": [], "fetch_error": "timeout"}),
            "UNKNOWN_EXPECTATION",
        )

    def test_missing_customer_ready_is_unknown_expectation(self):
        self.assertEqual(
            rrv._expected_live_behavior({"customer_ready": None, "state": None, "reason_codes": [], "fetch_error": None}),
            "UNKNOWN_EXPECTATION",
        )


class TestCachePurgeAndReverify(unittest.TestCase):
    """RX-PUB-A0.6B (mission Section 10-16): a gate-approved, R2-verified
    report served stale by a lagging edge POP must trigger a precise purge
    and one re-check -- but ONLY after R2 itself has confirmed the
    canonical object (Section 15), never before."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_purge_test_"))
        self.report_path = self.tmp / "intel--purgetest000000.html"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, content: str) -> bytes:
        data = content.encode("utf-8")
        self.report_path.write_bytes(data)
        return data

    def _r2_verified(self, data: bytes):
        """R2 layer reports REMOTE_VERIFIED -- the only state that may
        authorize a purge attempt."""
        return patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 200, "content_length": len(data), "etag": "x"}), \
               patch.object(rrv, "_get_object_bytes", return_value=data)

    def _r2_unverified(self):
        return patch.object(rrv._verifier, "_s3api_head_object", return_value=None), \
               patch.object(rrv._verifier, "_boto3_head_object", return_value=None)

    def _gate_approved(self):
        return patch.object(
            rrv, "_fetch_publication_status",
            return_value={"customer_ready": True, "state": "CUSTOMER_READY", "reason_codes": [], "fetch_error": None},
        )

    def test_purge_succeeds_and_reverify_converges_reclassifies_as_verified(self):
        local_data = self._write("<!DOCTYPE html><html>current canonical content</html>")
        stale_data = b"<!DOCTYPE html><html>OLD stale edge-cached content</html>"
        p1, p2 = self._r2_verified(local_data)
        fetch_calls = [
            {"bytes": stale_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None},  # first fetch: stale
            {"bytes": local_data, "status": 200, "headers": {"content-type": "text/html", "cf-ray": "post-purge"}, "error": None},  # re-fetch after purge: fresh
        ]
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", side_effect=fetch_calls), \
             patch.object(rrv, "_purge_public_url", return_value=True) as mock_purge:
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--purgetest000000.html")

        mock_purge.assert_called_once_with("https://intel.cyberdudebivash.com/reports/2026/08/intel--purgetest000000.html")
        self.assertEqual(result["publication_state"], "REMOTE_VERIFIED")
        self.assertEqual(result["live_state"], "LIVE_VERIFIED")
        self.assertTrue(result["cache_purge_attempted"])
        self.assertTrue(result["cache_purge_succeeded"])
        self.assertTrue(result["public_verified_after_invalidation"])
        self.assertFalse(result["public_still_stale"])
        self.assertEqual(result["public_sha256"], _sha256(local_data))
        self.assertNotIn("public_error", result)

    def test_purge_succeeds_but_reverify_still_stale_stays_divergent(self):
        local_data = self._write("<!DOCTYPE html><html>current canonical content</html>")
        stale_data = b"<!DOCTYPE html><html>OLD stale edge-cached content</html>"
        p1, p2 = self._r2_verified(local_data)
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": stale_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None}), \
             patch.object(rrv, "_purge_public_url", return_value=True):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--purgetest000000.html")

        self.assertEqual(result["live_state"], "LIVE_STALE_OR_DIVERGENT")
        self.assertTrue(result["cache_purge_attempted"])
        self.assertTrue(result["cache_purge_succeeded"])
        self.assertFalse(result["public_verified_after_invalidation"])
        self.assertTrue(result["public_still_stale"])

    def test_purge_fails_stays_divergent_without_a_second_fetch(self):
        """Purge failure (no credentials, API error) must not attempt the
        bounded re-fetch -- there is nothing to re-check yet."""
        local_data = self._write("<!DOCTYPE html><html>current canonical content</html>")
        stale_data = b"<!DOCTYPE html><html>OLD stale edge-cached content</html>"
        p1, p2 = self._r2_verified(local_data)
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": stale_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None}) as mock_fetch, \
             patch.object(rrv, "_purge_public_url", return_value=False):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--purgetest000000.html")

        self.assertEqual(result["live_state"], "LIVE_STALE_OR_DIVERGENT")
        self.assertTrue(result["cache_purge_attempted"])
        self.assertFalse(result["cache_purge_succeeded"])
        self.assertTrue(result["public_still_stale"])
        self.assertEqual(mock_fetch.call_count, 1, "a failed purge must not trigger a re-fetch")

    def test_purge_never_attempted_when_r2_layer_has_not_verified_the_object(self):
        """Mission Section 15, verbatim: never purge toward an unverified
        canonical object. If R2 itself could not confirm the object (no
        credentials, R2 outage), staleness at the edge is not this
        function's problem to fix yet."""
        local_data = self._write("<!DOCTYPE html><html>content</html>")
        stale_data = b"<!DOCTYPE html><html>different content</html>"
        p1, p2 = self._r2_unverified()
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": stale_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None}), \
             patch.object(rrv, "_purge_public_url") as mock_purge:
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--purgetest000000.html")

        self.assertNotEqual(result["publication_state"], "REMOTE_VERIFIED")
        mock_purge.assert_not_called()
        self.assertFalse(result["cache_purge_attempted"])
        self.assertEqual(result["live_state"], "LIVE_STALE_OR_DIVERGENT")

    def test_unexpected_404_also_eligible_for_purge_and_reverify(self):
        """A 404 for a gate-approved, R2-verified report could be a stale
        negative-cache entry -- the same purge-and-reverify path applies."""
        local_data = self._write("<!DOCTYPE html><html>current canonical content</html>")
        p1, p2 = self._r2_verified(local_data)
        fetch_calls = [
            {"bytes": None, "status": 404, "headers": {}, "error": "HTTP 404"},
            {"bytes": local_data, "status": 200, "headers": {"content-type": "text/html"}, "error": None},
        ]
        with p1, p2, self._gate_approved(), \
             patch.object(rrv, "_fetch_public", side_effect=fetch_calls), \
             patch.object(rrv, "_purge_public_url", return_value=True):
            result = rrv.verify_one(self.report_path, "reports/2026/08/intel--purgetest000000.html")

        self.assertEqual(result["live_state"], "LIVE_VERIFIED")
        self.assertTrue(result["public_verified_after_invalidation"])


class TestPurgePublicUrl(unittest.TestCase):
    """Unit coverage of _purge_public_url in isolation from verify_one()."""

    def test_no_credentials_configured_returns_false_without_network_call(self):
        with patch.object(rrv, "CF_ZONE_ID", ""), patch.object(rrv, "CF_CACHE_PURGE_TOKEN", ""), \
             patch("urllib.request.urlopen") as mock_urlopen:
            self.assertFalse(rrv._purge_public_url("https://intel.cyberdudebivash.com/reports/2026/08/x.html"))
        mock_urlopen.assert_not_called()

    def test_disallowed_host_returns_false_without_network_call(self):
        with patch.object(rrv, "CF_ZONE_ID", "zone123"), patch.object(rrv, "CF_CACHE_PURGE_TOKEN", "secrettoken"), \
             patch("urllib.request.urlopen") as mock_urlopen:
            self.assertFalse(rrv._purge_public_url("https://169.254.169.254/latest/meta-data/"))
        mock_urlopen.assert_not_called()

    def test_successful_cloudflare_response_returns_true(self):
        class _FakeResp:
            def read(self):
                return json.dumps({"success": True}).encode("utf-8")
            def __enter__(self): return self
            def __exit__(self, *a): return False

        with patch.object(rrv, "CF_ZONE_ID", "zone123"), patch.object(rrv, "CF_CACHE_PURGE_TOKEN", "secrettoken"), \
             patch("urllib.request.urlopen", return_value=_FakeResp()):
            self.assertTrue(rrv._purge_public_url("https://intel.cyberdudebivash.com/reports/2026/08/x.html"))

    def test_cloudflare_api_error_returns_false_not_raises(self):
        with patch.object(rrv, "CF_ZONE_ID", "zone123"), patch.object(rrv, "CF_CACHE_PURGE_TOKEN", "secrettoken"), \
             patch("urllib.request.urlopen", side_effect=Exception("connection reset")):
            self.assertFalse(rrv._purge_public_url("https://intel.cyberdudebivash.com/reports/2026/08/x.html"))

    def test_unsuccessful_cloudflare_response_returns_false(self):
        class _FakeResp:
            def read(self):
                return json.dumps({"success": False, "errors": [{"message": "invalid zone"}]}).encode("utf-8")
            def __enter__(self): return self
            def __exit__(self, *a): return False

        with patch.object(rrv, "CF_ZONE_ID", "zone123"), patch.object(rrv, "CF_CACHE_PURGE_TOKEN", "secrettoken"), \
             patch("urllib.request.urlopen", return_value=_FakeResp()):
            self.assertFalse(rrv._purge_public_url("https://intel.cyberdudebivash.com/reports/2026/08/x.html"))


class TestPublicUrlAllowlist(unittest.TestCase):
    """CodeRabbit finding (CWE-918 SSRF): RX_PUB_A0_PUBLIC_BASE_URL is
    CI-environment-controlled, not end-user input, but urlopen() with a
    request-influenced URL and no scheme/host restriction is still worth
    closing defensively."""

    def test_https_production_host_is_allowed(self):
        rrv._validate_public_url("https://intel.cyberdudebivash.com/reports/2026/08/x.html")  # must not raise

    def test_http_scheme_is_rejected(self):
        with self.assertRaises(rrv.PublicFetchConfigError):
            rrv._validate_public_url("http://intel.cyberdudebivash.com/reports/x.html")

    def test_arbitrary_host_is_rejected(self):
        with self.assertRaises(rrv.PublicFetchConfigError):
            rrv._validate_public_url("https://169.254.169.254/latest/meta-data/")

    def test_extra_allowed_host_env_var_is_honored(self):
        with patch.dict(os.environ, {"RX_PUB_A0_PUBLIC_ALLOWED_HOSTS": "test.example.com"}):
            rrv._validate_public_url("https://test.example.com/reports/x.html")  # must not raise

    def test_fetch_public_config_error_classifies_as_live_fetch_failed_not_verified(self):
        """A misconfigured/rejected target must surface as an explicit
        failure through verify_one(), never silently skip the public layer
        or (worse) read as verified."""
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="rrv_ssrf_test_"))
        try:
            p = tmp / "intel--ssrftest0000000.html"
            p.write_bytes(b"<!DOCTYPE html><html>x</html>")
            with patch.object(rrv, "PUBLIC_BASE_URL", "http://not-https.example.com"), \
                 patch.object(rrv._verifier, "_s3api_head_object", return_value=None), \
                 patch.object(rrv._verifier, "_boto3_head_object", return_value=None):
                result = rrv.verify_one(p, "reports/2026/08/intel--ssrftest0000000.html")
            self.assertEqual(result["live_state"], "LIVE_FETCH_FAILED")
            self.assertIsNone(result["public_sha256"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestFinalFailureHeaderPreservation(unittest.TestCase):
    """CodeRabbit finding: a final (retries-exhausted) non-404 HTTP error
    must not lose the cache/response evidence headers Section 15 requires
    capturing."""

    def test_headers_from_final_http_error_are_preserved(self):
        import email.message

        class _FakeHTTPError(Exception):
            pass

        call_count = {"n": 0}

        def _fake_urlopen(*args, **kwargs):
            call_count["n"] += 1
            headers = email.message.Message()
            headers["CF-Ray"] = "abc123-IAD"
            headers["Cache-Control"] = "no-cache"
            import urllib.error as ue
            raise ue.HTTPError(
                url="https://intel.cyberdudebivash.com/reports/x.html",
                code=503, msg="Service Unavailable", hdrs=headers, fp=None,
            )

        with patch.object(rrv, "PUBLIC_RETRY_DELAY", 0), \
             patch.object(rrv._PUBLIC_OPENER, "open", side_effect=_fake_urlopen):
            result = rrv._fetch_public("https://intel.cyberdudebivash.com/reports/x.html")

        self.assertEqual(call_count["n"], rrv.PUBLIC_MAX_RETRIES)
        self.assertEqual(result["status"], 503)
        self.assertEqual(result["headers"].get("cf-ray"), "abc123-IAD")
        self.assertEqual(result["headers"].get("cache-control"), "no-cache")


class TestPublicFetchThrottling(unittest.TestCase):
    """RX-PUB-A0.6D follow-up: real production evidence (sentinel-apex.yml
    run 31786632126, the first run with 6D's bounded concurrency) showed
    VERIFY_MAX_WORKERS=8 driving public-origin HTTP 429s from a 3.2%
    baseline (5/155, observed even at ~1-at-a-time sequential pacing) up to
    36% (184/507) -- an order-of-magnitude increase from bursting up to 16
    simultaneous requests at the shared public origin. These tests cover the
    fix: a dedicated semaphore around _fetch_public's network attempt,
    independent of the R2-layer's own (unaffected, still-8-way) concurrency,
    plus Retry-After-aware backoff on a 429."""

    def test_retry_after_seconds_parses_valid_numeric_header(self):
        self.assertEqual(rrv._retry_after_seconds({"retry-after": "5"}), 5.0)

    def test_retry_after_seconds_returns_none_when_absent(self):
        self.assertIsNone(rrv._retry_after_seconds({}))

    def test_retry_after_seconds_returns_none_for_unparseable_value(self):
        # The HTTP-date form of Retry-After exists but is deliberately not
        # supported (see _retry_after_seconds docstring) -- must degrade to
        # the fixed delay, never raise.
        self.assertIsNone(rrv._retry_after_seconds({"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}))

    def test_retry_after_seconds_returns_none_for_negative_value(self):
        # CodeRabbit finding: float("-1") parses fine, and the prior
        # max(0.0, ...) clamp turned it into an immediate retry -- worse
        # than the fixed delay it was meant to replace when an origin (or a
        # misbehaving proxy) sends a negative value.
        self.assertIsNone(rrv._retry_after_seconds({"retry-after": "-1"}))

    def test_retry_after_seconds_returns_none_for_non_finite_value(self):
        # CodeRabbit finding: float("inf") parses fine too, and would have
        # reached time.sleep() and hung that worker thread indefinitely.
        self.assertIsNone(rrv._retry_after_seconds({"retry-after": "inf"}))
        self.assertIsNone(rrv._retry_after_seconds({"retry-after": "nan"}))

    def test_retry_after_seconds_caps_large_value(self):
        # STAGE 3.6a timeout postmortem (sentinel-apex.yml run
        # 33630720481, 2026-09-02): main() finished and logged its full run
        # summary at exactly RUN_DEADLINE_SECONDS (600.00s), then the step
        # went silent for 309s until the external 15-minute timeout-minutes
        # kill -- consistent with a non-daemon worker thread sleeping on an
        # uncapped Retry-After value (e.g. 300s) from a 429 response, which
        # blocks OS-level process exit regardless of what main() already
        # returned. An origin can name any delay it wants; this verifier
        # must never honor one large enough to outlive its own deadline
        # budget.
        self.assertEqual(
            rrv._retry_after_seconds({"retry-after": "300"}),
            rrv.RETRY_AFTER_CAP_SECONDS,
        )
        self.assertLess(rrv.RETRY_AFTER_CAP_SECONDS, 300)

    def test_retry_after_seconds_leaves_small_value_uncapped(self):
        # A cooperative, reasonably-sized Retry-After must still be honored
        # verbatim -- the cap protects against pathological values, it must
        # not silently override normal backoff hints.
        self.assertEqual(rrv._retry_after_seconds({"retry-after": "5"}), 5.0)

    def test_429_response_waits_for_retry_after_instead_of_fixed_delay(self):
        import email.message

        def _fake_urlopen(*args, **kwargs):
            headers = email.message.Message()
            headers["Retry-After"] = "7"
            raise urllib.error.HTTPError(
                url="https://intel.cyberdudebivash.com/reports/x.html",
                code=429, msg="Too Many Requests", hdrs=headers, fp=None,
            )

        sleep_calls = []
        with patch.object(rrv, "PUBLIC_RETRY_DELAY", 3), \
             patch.object(rrv._PUBLIC_OPENER, "open", side_effect=_fake_urlopen), \
             patch.object(rrv.time, "sleep", side_effect=sleep_calls.append):
            result = rrv._fetch_public("https://intel.cyberdudebivash.com/reports/x.html")

        self.assertEqual(result["status"], 429)
        self.assertEqual(
            sleep_calls, [7.0, 7.0],
            "a 429 with a Retry-After header must back off for that long, not the fixed PUBLIC_RETRY_DELAY"
        )

    def test_429_response_with_large_retry_after_sleeps_capped_not_verbatim(self):
        import email.message

        def _fake_urlopen(*args, **kwargs):
            headers = email.message.Message()
            headers["Retry-After"] = "300"
            raise urllib.error.HTTPError(
                url="https://intel.cyberdudebivash.com/reports/x.html",
                code=429, msg="Too Many Requests", hdrs=headers, fp=None,
            )

        sleep_calls = []
        with patch.object(rrv, "PUBLIC_RETRY_DELAY", 3), \
             patch.object(rrv._PUBLIC_OPENER, "open", side_effect=_fake_urlopen), \
             patch.object(rrv.time, "sleep", side_effect=sleep_calls.append):
            result = rrv._fetch_public("https://intel.cyberdudebivash.com/reports/x.html")

        self.assertEqual(result["status"], 429)
        self.assertTrue(
            all(delay == rrv.RETRY_AFTER_CAP_SECONDS for delay in sleep_calls),
            f"a large Retry-After must be capped to RETRY_AFTER_CAP_SECONDS "
            f"({rrv.RETRY_AFTER_CAP_SECONDS}), not honored verbatim (300s) -- "
            f"got sleep_calls={sleep_calls}",
        )

    def test_429_response_without_retry_after_falls_back_to_fixed_delay(self):
        import email.message

        def _fake_urlopen(*args, **kwargs):
            headers = email.message.Message()  # no Retry-After
            raise urllib.error.HTTPError(
                url="https://intel.cyberdudebivash.com/reports/x.html",
                code=429, msg="Too Many Requests", hdrs=headers, fp=None,
            )

        sleep_calls = []
        with patch.object(rrv, "PUBLIC_RETRY_DELAY", 3), \
             patch.object(rrv._PUBLIC_OPENER, "open", side_effect=_fake_urlopen), \
             patch.object(rrv.time, "sleep", side_effect=sleep_calls.append):
            rrv._fetch_public("https://intel.cyberdudebivash.com/reports/x.html")

        self.assertEqual(sleep_calls, [3, 3])

    def test_public_fetch_concurrency_is_bounded_independently_of_worker_pool(self):
        import threading
        import time as _time

        lock = threading.Lock()
        state = {"current": 0, "max_seen": 0}

        def _tracked_urlopen(req, timeout=None):
            with lock:
                state["current"] += 1
                state["max_seen"] = max(state["max_seen"], state["current"])
            _time.sleep(0.05)
            with lock:
                state["current"] -= 1

            class _Resp:
                status = 200
                def getheaders(self_inner): return [("Content-Type", "text/html")]
                def read(self_inner): return b"<!DOCTYPE html><html>x</html>"
                def __enter__(self_inner): return self_inner
                def __exit__(self_inner, *a): return False
            return _Resp()

        with patch.object(rrv, "PUBLIC_FETCH_MAX_CONCURRENCY", 2), \
             patch.object(rrv, "_public_fetch_semaphore", threading.Semaphore(2)), \
             patch.object(rrv._PUBLIC_OPENER, "open", side_effect=_tracked_urlopen):
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(
                    lambda _: rrv._fetch_public("https://intel.cyberdudebivash.com/reports/x.html"),
                    range(10),
                ))

        self.assertLessEqual(
            state["max_seen"], 2,
            "public-origin fetch concurrency must stay bounded by PUBLIC_FETCH_MAX_CONCURRENCY "
            "even when 8 worker threads are all trying to fetch simultaneously"
        )


class TestFailOpenGuard(unittest.TestCase):
    """CodeRabbit finding: LIVE_FETCH_FAILED (and the equivalent R2-layer
    UNKNOWN state) must block a PASS/success claim exactly like a confirmed
    mismatch -- "could not verify" must never read as "verified"."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_failopen_test_"))
        self.manifest_path = self.tmp / "feed_manifest.json"
        self.reports_base = self.tmp / "reports"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_public_fetches_failing_blocks_enforce_pass(self):
        entry_id = "intel--failopentest00000"
        report_path = self.reports_base / "2026" / "08" / f"{entry_id}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("<!DOCTYPE html><html>content</html>", encoding="utf-8")
        self.manifest_path.write_text(json.dumps([
            {"id": entry_id, "internal_report_url": f"/reports/2026/08/{entry_id}.html",
             "timestamp": _recent_timestamp()}
        ]), encoding="utf-8")

        with patch.object(rrv, "MANIFEST_PATH", self.manifest_path), \
             patch.object(rrv, "REPO_ROOT", self.tmp), \
             patch.object(rrv._verifier, "CF_ACCOUNT_ID", "test"), \
             patch.object(rrv._verifier, "ACCESS_KEY", "test"), \
             patch.object(rrv._verifier, "SECRET_KEY", "test"), \
             patch.object(rrv._verifier, "_s3api_head_object", return_value=None), \
             patch.object(rrv._verifier, "_boto3_head_object", return_value=None), \
             patch.object(rrv, "_fetch_public", return_value={"bytes": None, "status": 503, "headers": {}, "error": "HTTP 503"}), \
             patch.object(rrv, "emit_summary", return_value={}), \
             patch.object(sys, "argv", ["r2_reports_verifier.py", "--enforce"]):
            exit_code = rrv.main()

        self.assertEqual(
            exit_code, 1,
            "a total public-HTTP outage (every report LIVE_FETCH_FAILED) must "
            "exit nonzero under --enforce, not silently PASS"
        )


class TestWorkflowStepHasReportsBucketCredentials(unittest.TestCase):
    """
    RX-PUB-A0.4 Phase 1 real-run finding: the first real STAGE 3.6a run
    (workflow run 31713054946) reported 314/314 in-window reports as
    "R2 object does not exist" -- 100% FAILED -- while STAGE 3.5.1 (a
    separate, already-proven gate that runs moments earlier in the same job)
    reported 500 objects "clean" in the same R2 bucket. Root cause: unlike
    STAGE 3.5 and STAGE 3.5.1 (both of which explicitly set
    CF_R2_REPORTS_KEY_ID/CF_R2_REPORTS_SECRET_KEY at the step level), the
    STAGE 3.6a step this mission added had no `env:` block at all, so
    r2_reports_verifier.py's optional reports-bucket-credential swap
    (scripts/r2_reports_verifier.py's "_reports_key_id and _reports_secret"
    check) silently found both empty and fell back to the job-level
    DATA-bucket-scoped credentials against the REPORTS bucket -- which
    r2_upload_verifier.py's reused _s3api_head_object() then misclassified
    as "object not found" (its returncode==254 check does not distinguish
    AccessDenied from NoSuchKey). Not a real production incident: it never
    reflected the actual state of the reports bucket.
    """

    def test_stage_3_6a_step_has_reports_bucket_credentials_wired(self):
        import yaml

        workflow_path = REPO_ROOT / ".github" / "workflows" / "sentinel-apex.yml"
        with open(workflow_path, encoding="utf-8") as f:
            workflow = yaml.safe_load(f)

        job = next(iter(workflow["jobs"].values()))
        steps = job["steps"]
        matches = [s for s in steps if "STAGE 3.6a" in s.get("name", "")]
        self.assertEqual(
            len(matches), 1,
            "expected exactly one STAGE 3.6a step in sentinel-apex.yml"
        )
        step = matches[0]
        env = step.get("env", {})
        self.assertIn(
            "CF_R2_REPORTS_KEY_ID", env,
            "STAGE 3.6a must set CF_R2_REPORTS_KEY_ID (same as STAGE 3.5 / "
            "STAGE 3.5.1) or r2_reports_verifier.py silently falls back to "
            "the wrong bucket's credentials and every report is misreported "
            "as missing from R2"
        )
        self.assertIn("CF_R2_REPORTS_SECRET_KEY", env)

    def test_stage_3_6a_step_has_continue_on_error(self):
        # STAGE 3.6a timeout postmortem (sentinel-apex.yml run
        # 33630720481, 2026-09-02): this step is documented as
        # observability-only/bake-in (--enforce deliberately not passed,
        # its own `run:` already guards the script call with `|| true`),
        # but lacked continue-on-error -- so a step-level timeout-minutes
        # kill (which bypasses that internal guard entirely) was recorded
        # as a step failure and, via this workflow's default if:
        # success(), cascaded to skip STAGE 5 - Deploy to GitHub Pages.
        # Every other observability-only stage in this file already sets
        # continue-on-error: true (STAGE 3.1.0b, 3.1.1, 3.1.2, 3.93.15d
        # through 3.93.15k, etc.) -- this asserts STAGE 3.6a matches that
        # same established, repo-wide convention.
        import yaml

        workflow_path = REPO_ROOT / ".github" / "workflows" / "sentinel-apex.yml"
        with open(workflow_path, encoding="utf-8") as f:
            workflow = yaml.safe_load(f)

        job = next(iter(workflow["jobs"].values()))
        steps = job["steps"]
        matches = [s for s in steps if "STAGE 3.6a" in s.get("name", "")]
        self.assertEqual(len(matches), 1)
        step = matches[0]
        self.assertIs(
            step.get("continue-on-error"), True,
            "STAGE 3.6a must set continue-on-error: true so an external "
            "timeout-minutes kill (which bypasses this step's own internal "
            "`|| true` guard) can never cascade into skipping STAGE 5 -- "
            "Deploy to GitHub Pages"
        )


class TestManifestR2Sync(unittest.TestCase):
    """
    GitHub issue #185: the manifest STAGE 3.6a writes locally must also be
    synced to R2 (BUCKET_DATA, intel/ prefix -- the same "Python writes JSON
    -> R2 -> Worker reads via env.INTEL_R2.get()" pattern P40 uses) so
    workers/intel-gateway/src/rx-pub-a0-handlers.js can actually serve it.
    Must use the DATA-bucket-scoped credentials directly from os.environ,
    NOT r2_upload.get_credentials() (which sys.exit(1)s on absence -- this
    stage must never crash over a missing/wrong credential).
    """

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_r2sync_test_"))
        self.manifest_path = self.tmp / "feed_manifest.json"
        self.manifest_path.write_text("[]", encoding="utf-8")
        self.reports_base = self.tmp / "reports"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_uploads_manifest_to_r2_when_data_credentials_present(self):
        env_patch = {
            "CF_ACCOUNT_ID": "test-account",
            "AWS_ACCESS_KEY_ID": "test-data-key",
            "AWS_SECRET_ACCESS_KEY": "test-data-secret",
        }
        with patch.object(rrv, "MANIFEST_PATH", self.manifest_path), \
             patch.object(rrv, "REPO_ROOT", self.tmp), \
             patch.object(rrv, "OUTPUT_PATH", self.tmp / "manifest_out.json"), \
             patch.dict(os.environ, env_patch), \
             patch.object(rrv._verifier, "CF_ACCOUNT_ID", "test"), \
             patch.object(rrv._verifier, "ACCESS_KEY", "test"), \
             patch.object(rrv._verifier, "SECRET_KEY", "test"), \
             patch.object(rrv._r2_upload, "s3_cp", return_value=True) as mock_cp, \
             patch.object(rrv, "emit_summary", return_value={}), \
             patch.object(sys, "argv", ["r2_reports_verifier.py", "--skip-public"]):
            rrv.main()

        self.assertEqual(mock_cp.call_count, 1)
        _src, dst_bucket, dst_key, _endpoint = mock_cp.call_args[0]
        self.assertEqual(dst_bucket, rrv._r2_upload.BUCKET_DATA)
        self.assertEqual(dst_key, "intel/rx_pub_a0_reports_artifact_manifest.json")

    def test_no_crash_and_no_upload_attempt_when_data_credentials_absent(self):
        env_clear = {k: "" for k in ("CF_ACCOUNT_ID", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
        with patch.object(rrv, "MANIFEST_PATH", self.manifest_path), \
             patch.object(rrv, "REPO_ROOT", self.tmp), \
             patch.object(rrv, "OUTPUT_PATH", self.tmp / "manifest_out.json"), \
             patch.dict(os.environ, env_clear), \
             patch.object(rrv._verifier, "CF_ACCOUNT_ID", "test"), \
             patch.object(rrv._verifier, "ACCESS_KEY", "test"), \
             patch.object(rrv._verifier, "SECRET_KEY", "test"), \
             patch.object(rrv._r2_upload, "s3_cp") as mock_cp, \
             patch.object(rrv, "emit_summary", return_value={}), \
             patch.object(sys, "argv", ["r2_reports_verifier.py", "--skip-public"]):
            # Must not raise (in particular, must not call the real
            # r2_upload.get_credentials(), which would sys.exit(1) here).
            exit_code = rrv.main()

        self.assertEqual(exit_code, 0)
        mock_cp.assert_not_called()

    def test_upload_failure_does_not_crash_or_change_exit_code(self):
        env_patch = {
            "CF_ACCOUNT_ID": "test-account",
            "AWS_ACCESS_KEY_ID": "test-data-key",
            "AWS_SECRET_ACCESS_KEY": "test-data-secret",
        }
        with patch.object(rrv, "MANIFEST_PATH", self.manifest_path), \
             patch.object(rrv, "REPO_ROOT", self.tmp), \
             patch.object(rrv, "OUTPUT_PATH", self.tmp / "manifest_out.json"), \
             patch.dict(os.environ, env_patch), \
             patch.object(rrv._verifier, "CF_ACCOUNT_ID", "test"), \
             patch.object(rrv._verifier, "ACCESS_KEY", "test"), \
             patch.object(rrv._verifier, "SECRET_KEY", "test"), \
             patch.object(rrv._r2_upload, "s3_cp", side_effect=RuntimeError("boom")), \
             patch.object(rrv, "emit_summary", return_value={}), \
             patch.object(sys, "argv", ["r2_reports_verifier.py", "--skip-public"]):
            exit_code = rrv.main()

        self.assertEqual(
            exit_code, 0,
            "an R2 upload failure must not change the run's own exit code -- "
            "local file + git history remain authoritative either way"
        )


class TestBoundedConcurrencyAndDeadline(unittest.TestCase):
    """RX-PUB-A0.6D: real production evidence (sentinel-apex.yml run
    31761997953) showed the pre-6D sequential loop covering only 170/518
    in-window reports before RUN_DEADLINE_SECONDS cut it off -- the normal
    case, not a tail case. These tests exercise the bounded-worker-pool
    replacement directly through rrv.main(), mocking verify_one() itself
    (rather than the deeper R2/public-HTTP primitives TestVerifyOne already
    covers) so timing is the only variable under test."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_concurrency_test_"))
        self.manifest_path = self.tmp / "feed_manifest.json"
        self.reports_base = self.tmp / "reports"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_entries(self, n: int) -> list[str]:
        ids = [f"intel--concurtest{i:08d}" for i in range(n)]
        entries = []
        for entry_id in ids:
            report_path = self.reports_base / "2026" / "08" / f"{entry_id}.html"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("<!DOCTYPE html><html>content</html>", encoding="utf-8")
            entries.append({"id": entry_id, "internal_report_url": f"/reports/2026/08/{entry_id}.html",
                             "timestamp": _recent_timestamp()})
        self.manifest_path.write_text(json.dumps(entries), encoding="utf-8")
        return ids

    def _enter_base_patches(self, stack):
        stack.enter_context(patch.object(rrv, "MANIFEST_PATH", self.manifest_path))
        stack.enter_context(patch.object(rrv, "REPO_ROOT", self.tmp))
        stack.enter_context(patch.object(rrv, "OUTPUT_PATH", self.tmp / "manifest_out.json"))
        stack.enter_context(patch.object(rrv._r2_upload, "s3_cp", return_value=True))
        # r2_creds_present gates whether main() even enters the per-report
        # loop -- must be truthy here even though verify_one() itself is
        # mocked below, since these tests are exercising main()'s dispatch/
        # deadline logic, not the real R2 primitives (already covered by
        # TestVerifyOne).
        stack.enter_context(patch.object(rrv._verifier, "CF_ACCOUNT_ID", "test"))
        stack.enter_context(patch.object(rrv._verifier, "ACCESS_KEY", "test"))
        stack.enter_context(patch.object(rrv._verifier, "SECRET_KEY", "test"))
        stack.enter_context(patch.object(sys, "argv", ["r2_reports_verifier.py", "--skip-public"]))
        # P0 R2 COST AUDIT FIX: main() now also emits an R2_COST_GUARD summary
        # via scripts/r2_cost_guard.py's emit_summary(), which writes to
        # data/quality/r2_cost_guard_report.json using THAT module's own
        # REPO_ROOT -- independent of the rrv.REPO_ROOT patch above, so an
        # unmocked call here would write to the real repo's file during a
        # test run. Mocked for hermeticity; MAX_VERIFY_ITEMS/head/get
        # accounting itself is covered by TestBoundedVerification below.
        stack.enter_context(patch.object(rrv, "emit_summary", return_value={}))

    def test_deadline_exceeded_before_any_report_finishes_marks_all_not_processed_deadline(self):
        import contextlib
        import time as _time

        def _slow_verify_one(local_path, r2_key, skip_public=False):
            _time.sleep(0.3)
            return {"publication_state": "REMOTE_VERIFIED", "live_state": "LIVE_VERIFIED"}

        ids = self._make_entries(3)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(rrv, "RUN_DEADLINE_SECONDS", 0))
            stack.enter_context(patch.object(rrv, "verify_one", side_effect=_slow_verify_one))
            self._enter_base_patches(stack)
            exit_code = rrv.main()

        self.assertEqual(exit_code, 0)  # --enforce not set
        manifest = json.loads((self.tmp / "manifest_out.json").read_text())
        self.assertTrue(manifest["summary"]["run_deadline_exceeded"])
        self.assertEqual(manifest["summary"]["live_not_processed_deadline"], 3)
        for entry_id in ids:
            report = manifest["reports"][entry_id]
            self.assertEqual(report["publication_state"], "NOT_PROCESSED_DEADLINE")
            self.assertEqual(report["live_state"], "LIVE_NOT_PROCESSED_DEADLINE")

    def test_deadline_exceeded_preserves_reports_that_already_finished(self):
        import contextlib
        import time as _time

        def _selective_verify_one(local_path, r2_key, skip_public=False):
            if "slowpoke" in str(local_path):
                _time.sleep(2.0)
            return {"publication_state": "REMOTE_VERIFIED", "live_state": "LIVE_VERIFIED"}

        fast_id = "intel--fastreport00000"
        slow_id = "intel--slowpoke00000000"
        for entry_id in (fast_id, slow_id):
            report_path = self.reports_base / "2026" / "08" / f"{entry_id}.html"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("<!DOCTYPE html><html>content</html>", encoding="utf-8")
        self.manifest_path.write_text(json.dumps([
            {"id": fast_id, "internal_report_url": f"/reports/2026/08/{fast_id}.html",
             "timestamp": _recent_timestamp()},
            {"id": slow_id, "internal_report_url": f"/reports/2026/08/{slow_id}.html",
             "timestamp": _recent_timestamp()},
        ]), encoding="utf-8")

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(rrv, "RUN_DEADLINE_SECONDS", 0.2))
            stack.enter_context(patch.object(rrv, "verify_one", side_effect=_selective_verify_one))
            self._enter_base_patches(stack)
            rrv.main()

        manifest = json.loads((self.tmp / "manifest_out.json").read_text())
        self.assertTrue(manifest["summary"]["run_deadline_exceeded"])
        self.assertEqual(
            manifest["reports"][fast_id]["publication_state"], "REMOTE_VERIFIED",
            "a report that finished well within the deadline must keep its real "
            "result, not be discarded just because a sibling report ran long"
        )
        self.assertEqual(
            manifest["reports"][slow_id]["publication_state"], "NOT_PROCESSED_DEADLINE",
        )

    def test_a_single_report_exception_does_not_abort_the_other_reports_in_the_batch(self):
        import contextlib

        good_id = "intel--goodreport000000"
        bad_id = "intel--crashreport000000"

        def _one_raises(local_path, r2_key, skip_public=False):
            if "crashreport" in str(local_path):
                raise RuntimeError("simulated verify_one crash")
            return {"publication_state": "REMOTE_VERIFIED", "live_state": "LIVE_VERIFIED"}

        for entry_id in (good_id, bad_id):
            report_path = self.reports_base / "2026" / "08" / f"{entry_id}.html"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("<!DOCTYPE html><html>content</html>", encoding="utf-8")
        self.manifest_path.write_text(json.dumps([
            {"id": good_id, "internal_report_url": f"/reports/2026/08/{good_id}.html",
             "timestamp": _recent_timestamp()},
            {"id": bad_id, "internal_report_url": f"/reports/2026/08/{bad_id}.html",
             "timestamp": _recent_timestamp()},
        ]), encoding="utf-8")

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(rrv, "verify_one", side_effect=_one_raises))
            self._enter_base_patches(stack)
            exit_code = rrv.main()

        self.assertEqual(exit_code, 0)
        manifest = json.loads((self.tmp / "manifest_out.json").read_text())
        self.assertEqual(manifest["reports"][good_id]["publication_state"], "REMOTE_VERIFIED")
        crashed = manifest["reports"][bad_id]
        self.assertEqual(crashed["publication_state"], "UNKNOWN")
        self.assertEqual(crashed["live_state"], "LIVE_UNKNOWN")
        self.assertIn("simulated verify_one crash", crashed["error"])

    def test_verify_max_workers_bounds_true_concurrency_without_serializing_it(self):
        import contextlib
        import threading
        import time as _time

        lock = threading.Lock()
        state = {"current": 0, "max_seen": 0}

        def _tracked_verify_one(local_path, r2_key, skip_public=False):
            with lock:
                state["current"] += 1
                state["max_seen"] = max(state["max_seen"], state["current"])
            _time.sleep(0.05)
            with lock:
                state["current"] -= 1
            return {"publication_state": "REMOTE_VERIFIED", "live_state": "LIVE_VERIFIED"}

        self._make_entries(20)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(rrv, "VERIFY_MAX_WORKERS", 4))
            stack.enter_context(patch.object(rrv, "verify_one", side_effect=_tracked_verify_one))
            self._enter_base_patches(stack)
            rrv.main()

        self.assertLessEqual(
            state["max_seen"], 4,
            "must never run more concurrent verify_one() calls than VERIFY_MAX_WORKERS -- "
            "an unbounded pool could overwhelm the public origin / R2 / Cloudflare API"
        )
        self.assertGreater(
            state["max_seen"], 1,
            "with 20 independent reports and 4 workers, genuine overlap is expected -- "
            "if this is 1, the pool silently degenerated back into sequential processing"
        )


class TestOperationCounting(unittest.TestCase):
    """P0 R2 COST AUDIT FIX: HEAD/GET calls are counted at their real call
    sites inside verify_one() and reported through scripts/r2_cost_guard.py's
    shared ledger -- previously entirely unaccounted for (this platform's
    cost accounting only ever showed Class A operations from other scripts)."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_opcount_test_"))
        self.report_path = self.tmp / "intel--opcounttest0000.html"
        self.report_path.write_bytes(b"<!DOCTYPE html><html>x</html>")
        rrv._head_call_count = 0
        rrv._get_call_count = 0

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)
        rrv._head_call_count = 0
        rrv._get_call_count = 0

    def test_successful_verification_counts_one_head_and_one_get(self):
        data = self.report_path.read_bytes()
        with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 200, "content_length": len(data), "etag": "x"}), \
             patch.object(rrv, "_get_object_bytes", return_value=data):
            rrv.verify_one(self.report_path, "reports/2026/08/intel--opcounttest0000.html", skip_public=True)

        self.assertEqual(rrv._head_call_count, 1)
        self.assertEqual(rrv._get_call_count, 1)

    def test_404_counts_head_but_not_get(self):
        with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 404, "content_length": 0, "etag": ""}), \
             patch.object(rrv._verifier, "_boto3_head_object", return_value=None):
            rrv.verify_one(self.report_path, "reports/2026/08/intel--opcounttest0000.html", skip_public=True)

        self.assertEqual(rrv._head_call_count, 1)
        self.assertEqual(rrv._get_call_count, 0, "a 404 must never trigger a GET -- nothing to fetch")

    def test_totally_unreachable_head_counts_both_the_awscli_and_boto3_fallback_attempts(self):
        with patch.object(rrv._verifier, "_s3api_head_object", return_value=None), \
             patch.object(rrv._verifier, "_boto3_head_object", return_value=None):
            rrv.verify_one(self.report_path, "reports/2026/08/intel--opcounttest0000.html", skip_public=True)

        self.assertEqual(rrv._head_call_count, 2, "one attempt via awscli, one boto3 fallback attempt")
        self.assertEqual(rrv._get_call_count, 0)

    def test_get_failure_after_head_success_counts_one_head_and_one_get(self):
        with patch.object(rrv._verifier, "_s3api_head_object", return_value={"status": 200, "content_length": 10, "etag": "z"}), \
             patch.object(rrv, "_get_object_bytes", return_value=None):
            rrv.verify_one(self.report_path, "reports/2026/08/intel--opcounttest0000.html", skip_public=True)

        self.assertEqual(rrv._head_call_count, 1)
        self.assertEqual(rrv._get_call_count, 1, "the GET was attempted even though it failed -- still a real R2 call")


class TestBoundedVerification(unittest.TestCase):
    """P0 R2 COST AUDIT FIX -- the core defect a post-merge forensic audit of
    this PR found: r2_reports_verifier.py's docstring and this platform's own
    cost-containment documentation claimed this script was "bounded, not the
    full historical corpus", but _load_in_window_entries() actually loaded
    and verified EVERY entry in feed_manifest.json unconditionally -- no time
    filter, no count cap. Since that manifest is the append-only, ever-
    growing core intelligence record (report retention removes entries from
    R2, never from the manifest), this script's real R2 HEAD+GET call volume
    scaled directly with total historical corpus size (150-1040 calls/run
    observed). These tests prove the fix actually bounds it, at manifest
    sizes far larger than any realistic 24h window."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="rrv_bounded_test_"))
        self.manifest_path = self.tmp / "feed_manifest.json"
        self.reports_base = self.tmp / "reports"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_manifest(self, n_in_window: int = 0, n_out_of_window: int = 0, n_unparseable: int = 0) -> None:
        now = datetime.now(timezone.utc)
        entries = []
        for i in range(n_in_window):
            entry_id = f"intel--boundedtest{i:06d}"
            report_path = self.reports_base / "2026" / "08" / f"{entry_id}.html"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("<!DOCTYPE html><html>x</html>", encoding="utf-8")
            entries.append({
                "id": entry_id,
                "internal_report_url": f"/reports/2026/08/{entry_id}.html",
                "timestamp": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            })
        for i in range(n_out_of_window):
            entry_id = f"intel--oldtest{i:06d}"
            report_path = self.reports_base / "2025" / "01" / f"{entry_id}.html"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("<!DOCTYPE html><html>old</html>", encoding="utf-8")
            entries.append({
                "id": entry_id,
                "internal_report_url": f"/reports/2025/01/{entry_id}.html",
                "timestamp": (now - timedelta(days=400)).isoformat().replace("+00:00", "Z"),
            })
        for i in range(n_unparseable):
            entry_id = f"intel--notstest{i:06d}"
            entries.append({"id": entry_id, "internal_report_url": f"/reports/2026/08/{entry_id}.html"})
        self.manifest_path.write_text(json.dumps(entries), encoding="utf-8")

    def test_window_filter_excludes_entries_older_than_report_window_hours(self):
        self._write_manifest(n_in_window=3, n_out_of_window=5)
        now = datetime.now(timezone.utc)
        with patch.object(rrv, "MANIFEST_PATH", self.manifest_path):
            entries = rrv._load_in_window_entries(24, now)
        self.assertEqual(len(entries), 3)

    def test_window_filter_excludes_entries_with_no_parseable_timestamp(self):
        """Fail-safe direction matches r2_report_publisher.py's own
        build_publish_candidates(): a timestamp we cannot prove is fresh is
        excluded, never assumed fresh."""
        self._write_manifest(n_in_window=2, n_unparseable=4)
        now = datetime.now(timezone.utc)
        with patch.object(rrv, "MANIFEST_PATH", self.manifest_path):
            entries = rrv._load_in_window_entries(24, now)
        self.assertEqual(len(entries), 2)

    def test_verify_item_count_never_exceeds_max_verify_items_regardless_of_manifest_size(self):
        """The core proof: a manifest with 50x MAX_VERIFY_ITEMS in-window
        entries must still only ever trigger MAX_VERIFY_ITEMS worth of real
        verification work."""
        import contextlib
        n_entries = rrv.MAX_VERIFY_ITEMS * 50
        self._write_manifest(n_in_window=n_entries)

        call_count = {"n": 0}

        def _fast_verify_one(local_path, r2_key, skip_public=False):
            call_count["n"] += 1
            return {"publication_state": "REMOTE_VERIFIED", "live_state": "PENDING"}

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(rrv, "MANIFEST_PATH", self.manifest_path))
            stack.enter_context(patch.object(rrv, "REPO_ROOT", self.tmp))
            stack.enter_context(patch.object(rrv, "OUTPUT_PATH", self.tmp / "manifest_out.json"))
            stack.enter_context(patch.object(rrv._verifier, "CF_ACCOUNT_ID", "test"))
            stack.enter_context(patch.object(rrv._verifier, "ACCESS_KEY", "test"))
            stack.enter_context(patch.object(rrv._verifier, "SECRET_KEY", "test"))
            stack.enter_context(patch.object(rrv, "verify_one", side_effect=_fast_verify_one))
            stack.enter_context(patch.object(rrv._r2_upload, "s3_cp", return_value=True))
            mock_emit = stack.enter_context(patch.object(rrv, "emit_summary", return_value={}))
            stack.enter_context(patch.object(sys, "argv", ["r2_reports_verifier.py", "--skip-public"]))
            rrv.main()

        self.assertLessEqual(
            call_count["n"], rrv.MAX_VERIFY_ITEMS,
            f"verify_one() was called {call_count['n']} times for a {n_entries}-entry in-window "
            f"manifest -- must never exceed MAX_VERIFY_ITEMS ({rrv.MAX_VERIFY_ITEMS}) regardless "
            f"of manifest size (this is the exact defect the P0 R2 cost audit found: 150-1040 "
            f"calls/run scaling directly with manifest size before this fix)"
        )
        manifest = json.loads((self.tmp / "manifest_out.json").read_text())
        self.assertEqual(len(manifest["reports"]), n_entries, "every entry accounted for -- verified or explicitly excluded, never silently dropped")
        self.assertEqual(manifest["summary"]["live_not_processed_budget"], n_entries - rrv.MAX_VERIFY_ITEMS)
        mock_emit.assert_called_once()
        plan = mock_emit.call_args[0][0]
        self.assertEqual(plan.label, "r2_reports_verifier")
        self.assertEqual(plan.bucket, rrv.BUCKET_REPORTS)

    def test_overflow_items_recorded_as_not_processed_budget_never_silently_dropped(self):
        import contextlib
        n_entries = rrv.MAX_VERIFY_ITEMS + 50
        self._write_manifest(n_in_window=n_entries)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(rrv, "MANIFEST_PATH", self.manifest_path))
            stack.enter_context(patch.object(rrv, "REPO_ROOT", self.tmp))
            stack.enter_context(patch.object(rrv, "OUTPUT_PATH", self.tmp / "manifest_out.json"))
            stack.enter_context(patch.object(rrv._verifier, "CF_ACCOUNT_ID", "test"))
            stack.enter_context(patch.object(rrv._verifier, "ACCESS_KEY", "test"))
            stack.enter_context(patch.object(rrv._verifier, "SECRET_KEY", "test"))
            stack.enter_context(patch.object(rrv, "verify_one", return_value={"publication_state": "REMOTE_VERIFIED", "live_state": "PENDING"}))
            stack.enter_context(patch.object(rrv._r2_upload, "s3_cp", return_value=True))
            stack.enter_context(patch.object(rrv, "emit_summary", return_value={}))
            stack.enter_context(patch.object(sys, "argv", ["r2_reports_verifier.py", "--skip-public"]))
            rrv.main()

        manifest = json.loads((self.tmp / "manifest_out.json").read_text())
        budget_excluded = [r for r in manifest["reports"].values() if r["publication_state"] == "NOT_PROCESSED_BUDGET"]
        self.assertEqual(len(budget_excluded), 50)
        for r in budget_excluded:
            self.assertEqual(r["live_state"], "LIVE_NOT_PROCESSED_BUDGET")
            self.assertIn("MAX_VERIFY_ITEMS", r["error"])

    def test_window_and_budget_bounds_are_independent_defenses(self):
        """Belt-and-suspenders: even if every in-window entry somehow passed
        the time filter, the count cap still applies on top of it -- the two
        are separate, composable defenses, not alternatives."""
        self._write_manifest(n_in_window=rrv.MAX_VERIFY_ITEMS * 2, n_out_of_window=rrv.MAX_VERIFY_ITEMS * 100)
        now = datetime.now(timezone.utc)
        with patch.object(rrv, "MANIFEST_PATH", self.manifest_path):
            entries = rrv._load_in_window_entries(rrv.REPORT_WINDOW_HOURS, now)
        # Window filter alone already excludes the out-of-window majority;
        # what's left still exceeds MAX_VERIFY_ITEMS, so the count cap in
        # main() (exercised in the tests above) is what ultimately bounds it.
        self.assertEqual(len(entries), rrv.MAX_VERIFY_ITEMS * 2)
        self.assertGreater(len(entries), rrv.MAX_VERIFY_ITEMS)


if __name__ == "__main__":
    unittest.main()
