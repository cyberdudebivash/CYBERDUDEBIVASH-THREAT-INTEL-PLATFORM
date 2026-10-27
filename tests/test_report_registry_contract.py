"""Zero-network regression tests for the same-run report-registry contract."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "report_registry_contract", Path(__file__).resolve().parents[1] / "scripts" / "report_registry_contract.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RegistryContractTests(unittest.TestCase):
    def fixture(self):
        reports = [{"id": "intel--a", "severity": "HIGH"},
                   {"id": "intel--b", "severity": "MEDIUM"}]
        common = {"schema_version": "1.0", "generated_at": "2026-10-27T00:00:00Z",
                  "total_reports": 2}
        return (
            {**common, "reports_listed": 2, "reports": reports},
            {**common, "reports_listed": 1, "reports": reports[:1]},
            {**common, "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1,
                                        "LOW": 0, "UNKNOWN": 0}},
        )

    def test_matching_artifacts_are_only_offline_precheck(self):
        result = module.audit_registry(*self.fixture())
        self.assertEqual(result["verdict"], "ARTIFACT_CONSISTENCY_ONLY")
        self.assertFalse(result["delivery_certified"])

    def test_legacy_live_stats_schema_is_rejected(self):
        index, latest, stats = self.fixture()
        stats = {"schema_version": "1.1.0", "generated_at": stats["generated_at"],
                 "total_reports": 1, "critical_reports": 1, "medium_reports": 3}
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")

    def test_mixed_generation_timestamps_are_rejected(self):
        index, latest, stats = self.fixture()
        latest["generated_at"] = "2026-10-26T00:00:00Z"
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")

    def test_severity_inflation_is_rejected(self):
        index, latest, stats = self.fixture()
        stats["by_severity"]["MEDIUM"] = 3
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")

    def test_latest_not_index_prefix_is_rejected(self):
        index, latest, stats = self.fixture()
        latest["reports"] = [index["reports"][1]]
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")

    def test_boolean_total_is_rejected(self):
        index, latest, stats = self.fixture()
        stats["total_reports"] = True
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")

    def test_customer_ready_catalog_is_not_confused_with_builder_index(self):
        index, latest, stats = self.fixture()
        index = {"schema_version": "2.0.0", "total_candidates": 38,
                 "customer_ready_count": 0, "reports": []}
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")


    def test_equal_total_but_swapped_severity_buckets_is_blocked(self):
        index, latest, stats = self.fixture()
        stats["by_severity"]["HIGH"] = 0
        stats["by_severity"]["MEDIUM"] = 2
        result = module.audit_registry(index, latest, stats)
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertIn("severity distribution", " ".join(result["defects"]))

    def test_unknown_report_severity_is_rejected(self):
        index, latest, stats = self.fixture()
        index["reports"][0]["severity"] = "UNVERIFIED"
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")

    def test_duplicate_report_id_is_rejected(self):
        index, latest, stats = self.fixture()
        index["reports"][1]["id"] = index["reports"][0]["id"]
        self.assertEqual(module.audit_registry(index, latest, stats)["verdict"], "BLOCKED")

    def test_valid_unknown_severity_bucket_is_accepted_as_precheck_only(self):
        index, latest, stats = self.fixture()
        index["reports"][1]["severity"] = "UNKNOWN"
        stats["by_severity"]["MEDIUM"] = 0
        stats["by_severity"]["UNKNOWN"] = 1
        result = module.audit_registry(index, latest, stats)
        self.assertEqual(result["verdict"], "ARTIFACT_CONSISTENCY_ONLY")
        self.assertFalse(result["delivery_certified"])


if __name__ == "__main__":
    unittest.main()
