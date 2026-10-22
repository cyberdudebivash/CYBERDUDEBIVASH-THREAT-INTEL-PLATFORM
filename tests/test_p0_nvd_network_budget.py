"""Offline NVD adapter P0 regression tests; no external requests or credentials."""
import unittest
from unittest.mock import patch
from urllib.error import URLError
from core.ingestion.sources.nvd_source import NVDSource
from core.ingestion.sources.base import FetchStatus, NetworkError

class NVDP0Tests(unittest.TestCase):
    def test_anonymous_request_budget(self):
        with patch.dict("os.environ", {"NVD_API_KEY": ""}):
            source = NVDSource({"enrich_epss": False})
        self.assertAlmostEqual(source._limiter._rate, 8 / 60)
        self.assertEqual(source._limiter._burst, 1)

    def test_authenticated_request_budget(self):
        source = NVDSource({"api_key": "test-key", "enrich_epss": False})
        self.assertAlmostEqual(source._limiter._rate, 90 / 60)
        self.assertEqual(source._limiter._burst, 10)

    def test_network_exception_type(self):
        source = NVDSource({"enrich_epss": False})
        with patch("core.ingestion.sources.nvd_source.urlopen", side_effect=URLError("offline")):
            with self.assertRaises(NetworkError):
                source._get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-109618")

    def test_targeted_fetch_reports_network_error(self):
        source = NVDSource({"enrich_epss": False})
        with patch("core.ingestion.sources.nvd_source.urlopen", side_effect=URLError("offline")):
            result = source.fetch(cve_id="CVE-2026-109618")
        self.assertEqual(result.status, FetchStatus.NETWORK_ERROR)
        self.assertEqual(result.items, [])

if __name__ == "__main__":
    unittest.main()
