"""Offline negative controls for the commercial evidence precheck."""
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "commercial_evidence_gate", Path(__file__).resolve().parents[1] / "scripts" / "commercial_evidence_gate.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CommercialGateTests(unittest.TestCase):
    def valid(self):
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return {"report_candidates": 1, "customer_ready": 1,
                **{key: {"passed": True, "reference": "artifact:verified", "verified_at": now}
                   for key in module.REQUIRED}}

    def test_missing_evidence_fails(self):
        self.assertEqual(module.evaluate({})["verdict"], "NO_GO")

    def test_no_customer_reports_fails(self):
        data = self.valid()
        data["customer_ready"] = 0
        self.assertEqual(module.evaluate(data)["verdict"], "NO_GO")

    def test_false_entitlement_fails(self):
        data = self.valid()
        data["entitlement"]["passed"] = False
        self.assertEqual(module.evaluate(data)["verdict"], "NO_GO")

    def test_missing_reference_fails(self):
        data = self.valid()
        data["security"]["reference"] = ""
        self.assertEqual(module.evaluate(data)["verdict"], "NO_GO")

    def test_future_timestamp_fails(self):
        data = self.valid()
        data["payment"]["verified_at"] = "2999-01-01T00:00:00Z"
        self.assertEqual(module.evaluate(data)["verdict"], "NO_GO")

    def test_partial_ready_catalog_is_precheck_only(self):
        data = self.valid()
        data["report_candidates"] = 39
        self.assertEqual(module.evaluate(data)["verdict"], "EVIDENCE_PRECHECK_ONLY")
        self.assertFalse(module.evaluate(data)["production_go"])

    def test_ready_count_exceeding_candidates_fails(self):
        data = self.valid()
        data["customer_ready"] = 2
        self.assertEqual(module.evaluate(data)["verdict"], "NO_GO")

    def test_non_object_evidence_always_denies_release(self):
        result = module.evaluate(None)
        self.assertEqual(result["verdict"], "NO_GO")
        self.assertIs(result["production_go"], False)

    def test_positive_remains_precheck_only(self):
        result = module.evaluate(self.valid())
        self.assertEqual(result["verdict"], "EVIDENCE_PRECHECK_ONLY")
        self.assertFalse(result["production_go"])


if __name__ == "__main__":
    unittest.main()
