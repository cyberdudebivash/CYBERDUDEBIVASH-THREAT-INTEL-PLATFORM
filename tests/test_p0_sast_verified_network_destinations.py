"""Offline P0 B310 regression: HTTPS origin and redirect enforcement."""
from __future__ import annotations
import sys
from pathlib import Path
from unittest import TestCase, mock
SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
import enrich_cvss_epss_batch as enr  # noqa: E402
import pages_deploy_freshness_gate as pages  # noqa: E402


class IntelSources(TestCase):
    def test_only_pinned_https_sources(self):
        for url in ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-12345",
                    "https://api.first.org/data/v1/epss?cve=CVE-2026-12345&limit=1"):
            self.assertTrue(enr._approved_intelligence_url(url), url)
        for url in ("http://services.nvd.nist.gov/rest/json/cves/2.0",
                    "https://attacker.example/rest/json/cves/2.0",
                    "https://services.nvd.nist.gov.attacker.test/rest/json/cves/2.0",
                    "https://evil.test@services.nvd.nist.gov/rest/json/cves/2.0",
                    "https://services.nvd.nist.gov:8443/rest/json/cves/2.0",
                    "https://api.first.org/another-path",
                    "https://api.first.org/data/v1/epss#fragment",
                    "file:///etc/passwd"):
            with self.subTest(url=url):
                self.assertFalse(enr._approved_intelligence_url(url))
        self.assertFalse(enr._approved_intelligence_url(None))

    def test_denied_source_not_opened(self):
        with mock.patch.object(enr.urllib.request, "build_opener",
                               side_effect=AssertionError("must not connect")):
            with self.assertRaisesRegex(ValueError, "UNAPPROVED_INTELLIGENCE"):
                enr._open_approved_intelligence(
                    enr.urllib.request.Request("https://attacker.example/"), 2)

    def test_redirect_handler_never_follows_nvd_api_key(self):
        self.assertIsNone(enr._NoApiRedirects().redirect_request(
            enr.urllib.request.Request(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers={"apiKey": "test-placeholder"}),
            None, 302, "Found", {}, "https://attacker.example/"))

    def test_approved_json_bounded_read(self):
        class Response:
            def __init__(self, data):
                self.data = data
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self, n):
                return self.data[:n]
        class Opener:
            def __init__(self, data):
                self.data = data
            def open(self, req, timeout=0):
                assert timeout == 2
                return Response(self.data)
        url = "https://api.first.org/data/v1/epss?cve=CVE-2026-12345"
        with mock.patch.object(enr.urllib.request, "build_opener",
                               return_value=Opener(b'{"data":[]}')):
            self.assertEqual(enr._http_get(url, timeout=2), {"data": []})
        with mock.patch.object(enr.urllib.request, "build_opener",
                               return_value=Opener(b"x" * (enr._MAX_REMOTE_JSON_BYTES+1))):
            self.assertIsNone(enr._http_get(url, timeout=2))


class FreshnessSource(TestCase):
    def test_only_canonical_production_origin(self):
        self.assertTrue(pages._approved_freshness_url(
            "https://intel.cyberdudebivash.com/?_freshness_check=1234"))
        for url in ("http://intel.cyberdudebivash.com/?_freshness_check=1234",
                    "https://intel.cyberdudebivash.com.attacker.test/?_freshness_check=1234",
                    "https://evil.test@intel.cyberdudebivash.com/?_freshness_check=1234",
                    "https://intel.cyberdudebivash.com:8443/?_freshness_check=1234",
                    "https://intel.cyberdudebivash.com/other?_freshness_check=1234",
                    "https://intel.cyberdudebivash.com/?_freshness_check=x",
                    "https://intel.cyberdudebivash.com/?_freshness_check=1#frag",
                    "file:///etc/passwd"):
            with self.subTest(url=url):
                self.assertFalse(pages._approved_freshness_url(url))

    def test_unapproved_base_is_rejected_before_open(self):
        with mock.patch.object(pages.request, "build_opener",
                               side_effect=AssertionError("must not connect")):
            with self.assertRaisesRegex(ValueError, "UNAPPROVED_FRESHNESS"):
                pages.fetch_last_modified("https://attacker.example")

    def test_redirects_are_not_followed(self):
        self.assertIsNone(pages._NoFreshnessRedirects().redirect_request(
            None, None, 301, "Moved", {}, "https://attacker.example/"))
