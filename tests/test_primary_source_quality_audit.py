"""Hermetic regression tests for public-feed primary-source quality triage."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "primary_source_quality_audit.py"
spec = importlib.util.spec_from_file_location("primary_source_quality_audit", MODULE)
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


def evidence(**overrides):
    row = {"id": "case", "primary_source_url": "https://www.drupal.org/sa-contrib-2026-254",
           "primary_source_published_at": "2026-10-28", "feed_source_url": "https://example.org/advisory",
           "minimum_severity": "HIGH"}
    row.update(overrides)
    return {"schema_version": "1.0", "assertions": [row]}


def feed(**overrides):
    row = {"id": "intel--test", "source_url": "https://example.org/advisory", "severity": "MEDIUM",
           "cve_id": "CVE-2026-118539", "ioc_count": 0, "actor_display_name": "Unknown Threat Actor"}
    row.update(overrides)
    return {"generated_at": "2026-11-01T16:01:54Z", "items": [row]}


class PrimarySourceAuditTests(unittest.TestCase):
    def test_undertriage_is_blocking_without_modifying_feed(self):
        original = feed()
        before = json.dumps(original, sort_keys=True)
        result = audit_module.audit(original, evidence())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["findings"][0]["code"], "PRIMARY_SEVERITY_UNDERTRIAGE")
        self.assertEqual(json.dumps(original, sort_keys=True), before)

    def test_primary_iocs_and_attribution_are_review_only_for_public_feed(self):
        result = audit_module.audit(feed(severity="HIGH"), evidence(
            primary_indicators_published=True, primary_attribution_published=True))
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertEqual({f["code"] for f in result["findings"]},
                         {"PUBLIC_FEED_IOC_COVERAGE_GAP", "PUBLIC_FEED_ATTRIBUTION_GAP"})

    def test_cvss_provenance_review_does_not_claim_cvss_is_false(self):
        result = audit_module.audit(feed(severity="CRITICAL", cvss_score=6.5),
                                    evidence(primary_cvss_published=False))
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertEqual(result["findings"][0]["code"], "CVSS_PROVENANCE_REVIEW")

    def test_good_evidence_passes(self):
        result = audit_module.audit(feed(severity="CRITICAL", ioc_count=3,
                                         actor_display_name="TraderTraitor"),
                                    evidence(primary_indicators_published=True,
                                             primary_attribution_published=True))
        self.assertEqual(result["verdict"], "PASS")

    def test_missing_record_is_not_misreported_as_live_defect(self):
        result = audit_module.audit({"items": []}, evidence())
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["findings"][0]["level"], "info")

    def test_invalid_evidence_fails_closed(self):
        for bad in (evidence(primary_source_url="http://www.drupal.org/x"),
                    evidence(primary_indicators_published="yes"),
                    {"schema_version": "9", "assertions": []}):
            with self.assertRaises(audit_module.AuditInputError):
                audit_module.audit(feed(), bad)

    def test_cli_offline_exit_codes(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / "feed.json").write_text(json.dumps(feed()), encoding="utf-8")
            (p / "evidence.json").write_text(json.dumps(evidence()), encoding="utf-8")
            self.assertEqual(audit_module.main(["--feed", str(p / "feed.json"),
                                                "--evidence", str(p / "evidence.json")]), 2)
            (p / "feed.json").write_text(json.dumps(feed(severity="CRITICAL")), encoding="utf-8")
            self.assertEqual(audit_module.main(["--feed", str(p / "feed.json"),
                                                "--evidence", str(p / "evidence.json")]), 0)


if __name__ == "__main__":
    unittest.main()
