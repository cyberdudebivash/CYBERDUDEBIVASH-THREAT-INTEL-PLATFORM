"""Offline negative controls for public feed-manifest policy smoke."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from public_manifest_smoke_contract import classify_manifest_response  # noqa: E402


def encoded(value):
    return json.dumps(value).encode("utf-8")


class ManifestSmokePolicyTests(unittest.TestCase):
    def test_exact_tlp_policy_denial_is_explicitly_withheld(self):
        payload = {"tlp_boundary": {
            "withheld": True, "reason_code": "LEGACY_LABEL_UNMIGRATED",
            "policy": "config/tlp_publication_policy.json"}}
        self.assertEqual(classify_manifest_response(200, encoded(payload)), "POLICY_WITHHELD")

    def test_valid_migrated_public_summary(self):
        summary = {"platform": "SENTINEL APEX", "tlp": "TLP:CLEAR",
                   "api": {"endpoints": {"live_feed": "/api/feed"}}}
        self.assertEqual(classify_manifest_response(200, encoded(summary)), "PUBLIC_SUMMARY")

    def test_retired_tlp_white_not_accepted(self):
        summary = {"platform": "SENTINEL APEX", "tlp": "TLP:WHITE",
                   "api": {"endpoints": {"live_feed": "/api/feed"}}}
        self.assertEqual(classify_manifest_response(200, encoded(summary)), "INVALID")

    def test_denial_extra_payload_is_not_accepted(self):
        payload = {"tlp_boundary": {
            "withheld": True, "reason_code": "LEGACY_LABEL_UNMIGRATED",
            "policy": "config/tlp_publication_policy.json"}, "advisories": ["secret"]}
        self.assertEqual(classify_manifest_response(200, encoded(payload)), "INVALID")

    def test_wrong_policy_or_reason_not_accepted(self):
        for key, value in (("reason_code", "OTHER"), ("policy", "wrong"), ("withheld", False)):
            payload = {"tlp_boundary": {
                "withheld": True, "reason_code": "LEGACY_LABEL_UNMIGRATED",
                "policy": "config/tlp_publication_policy.json"}}
            payload["tlp_boundary"][key] = value
            with self.subTest(key=key):
                self.assertEqual(classify_manifest_response(200, encoded(payload)), "INVALID")

    def test_http_error_html_and_malformed_json_fail(self):
        valid = encoded({"tlp_boundary": {
            "withheld": True, "reason_code": "LEGACY_LABEL_UNMIGRATED",
            "policy": "config/tlp_publication_policy.json"}})
        self.assertEqual(classify_manifest_response(503, valid), "INVALID")
        self.assertEqual(classify_manifest_response(200, b"<html>200</html>"), "INVALID")
        self.assertEqual(classify_manifest_response(200, b"{"), "INVALID")
        self.assertEqual(classify_manifest_response(200, b""), "INVALID")
        self.assertEqual(classify_manifest_response(200, b"x" * (64 * 1024 + 1)), "INVALID")


if __name__ == "__main__":
    unittest.main()
