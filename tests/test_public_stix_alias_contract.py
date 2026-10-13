"""Public and PRO advisory STIX alias isolation regression."""
import unittest
from scripts.public_api_sanitizer import sanitize_for_public, sanitize_for_pro

VALID = "indicator--123e4567-e89b-42d3-a456-426614174000"

class PublicStixIdentityTests(unittest.TestCase):
    def test_legacy_internal_alias_not_stix(self):
        obj = {"id": "intel--abc123", "stix_id": "intel--abc123", "title": "Example"}
        for sanitizer in (sanitize_for_public, sanitize_for_pro):
            with self.subTest(sanitizer=sanitizer.__name__):
                result = sanitizer(obj)
                self.assertEqual(result["id"], obj["id"])
                self.assertNotIn("stix_id", result)
        self.assertEqual(obj["stix_id"], "intel--abc123")

    def test_structural_validity_preserved(self):
        obj = {"id": "intel--abc123", "stix_id": VALID, "title": "Example"}
        for sanitizer in (sanitize_for_public, sanitize_for_pro):
            self.assertEqual(sanitizer(obj)["stix_id"], VALID)

    def test_unknown_and_empty_stix_identity_removed(self):
        for sid in (None, "", "indicator--invalid", "foo--123e4567-e89b-42d3-a456-426614174000", 1234):
            for sanitizer in (sanitize_for_public, sanitize_for_pro):
                with self.subTest(sid=sid, sanitizer=sanitizer.__name__):
                    self.assertNotIn("stix_id", sanitizer({"id": "intel--1", "stix_id": sid}))

if __name__ == "__main__":
    unittest.main()
