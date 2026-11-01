"""Hermetic negative controls for production byte-parity release gate."""
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'pages_deploy_byte_parity_gate.py'
spec = importlib.util.spec_from_file_location('pages_deploy_byte_parity_gate', MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class TestByteParity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'js').mkdir()
        self.js = b'console.log("certified asset");\n'
        (self.root / gate.ASSET).write_bytes(self.js)
        self.short = gate.sha256(self.js)[:12]
        self.html = (f'<html><div id="sync-val" role="status">SYNC: '
                     f'<span>VERIFYING</span></div><span id="m-feed-count">&mdash;</span> REGISTERED'
                     f'<script src="/{gate.ASSET}?v={self.short}"></script></html>').encode()
        (self.root / 'index.html').write_bytes(self.html)

    def fetcher(self, url, _max_bytes, _hostname):
        return self.js if '/js/' in url else self.html

    def test_verified_exact_bytes(self):
        result = gate.check_once(self.root, getter=self.fetcher)
        self.assertTrue(result['deployed_asset_identical'])

    def test_bad_candidate_asset_version_denied(self):
        (self.root / 'index.html').write_bytes(self.html.replace(self.short.encode(), b'badbadbadbad'))
        with self.assertRaises(gate.ReleaseParityError):
            gate.check_once(self.root, getter=self.fetcher)

    def test_old_live_html_denied_even_if_asset_matches(self):
        def stale(url, n, host):
            return self.js if '/js/' in url else self.html.replace(self.short.encode(), b'000000000000')
        with self.assertRaises(gate.ReleaseParityError):
            gate.check_once(self.root, getter=stale)

    def test_stale_live_js_denied(self):
        def stale(url, n, host):
            return b'console.log("tampered");' if '/js/' in url else self.html
        with self.assertRaises(gate.ReleaseParityError):
            gate.check_once(self.root, getter=stale)

    def test_fake_live_initial_status_denied(self):
        def old(url, n, host):
            return self.js if '/js/' in url else self.html.replace(b'VERIFYING', b'LIVE')
        with self.assertRaises(gate.ReleaseParityError):
            gate.check_once(self.root, getter=old)

    def test_fake_feed_initial_count_denied(self):
        def old(url, n, host):
            return self.js if '/js/' in url else self.html.replace(b'&mdash;</span> REGISTERED', b'74</span> ACTIVE')
        with self.assertRaises(gate.ReleaseParityError):
            gate.check_once(self.root, getter=old)

    def test_disallow_http_origin(self):
        with self.assertRaises(gate.ReleaseParityError):
            gate.check_once(self.root, 'http://intel.cyberdudebivash.com', self.fetcher)

    def test_unrecognised_script_version_denied(self):
        with self.assertRaises(gate.ReleaseParityError):
            gate.script_version(b'<script src="/js/homepage-dashboard-engine.js?v=human-version"></script>')

    def test_duplicate_script_tags_denied(self):
        with self.assertRaises(gate.ReleaseParityError):
            gate.script_version(self.html + self.html)


    def test_cross_origin_probe_rejected_before_transport(self):
        origin = "intel.cyberdudebivash.com"
        forbidden = (
            "http://" + origin + "/",
            "https://127.0.0.1/private",
            "https://other.example/reports",
            "https://user@" + origin + "/",
            "https://" + origin + ":8443/reports",
            "https://" + origin + "/reports#fragment",
        )
        with patch.object(gate, "build_opener") as opener:
            for url in forbidden:
                with self.subTest(url=url), self.assertRaises(gate.ReleaseParityError):
                    gate.public_get(url, 64, origin)
            opener.assert_not_called()

    def test_redirect_target_checked_before_following(self):
        origin = "intel.cyberdudebivash.com"
        handler = gate._OriginLockedRedirectHandler(origin)
        request = gate.Request("https://" + origin + "/")
        for target in (
            "http://" + origin + "/",
            "https://127.0.0.1/metadata",
            "https://evil.example/",
            "https://" + origin + ":8443/",
            "https://user@" + origin + "/",
        ):
            with self.subTest(target=target), self.assertRaises(gate.ReleaseParityError):
                handler.redirect_request(request, None, 302, "Found", {}, target)
        permitted = handler.redirect_request(
            request, None, 302, "Found", {}, "https://" + origin + "/reports/"
        )
        self.assertEqual(permitted.full_url, "https://" + origin + "/reports/")

    def test_final_response_origin_checked_before_body_read(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return "https://127.0.0.1/private"

            def read(self, _limit):
                raise AssertionError("Unsafe response body was read")

        class Opener:
            def open(self, _req, timeout):
                self_timeout = timeout
                if self_timeout != 12:
                    raise AssertionError("Timeout contract changed")
                return Response()

        with patch.object(gate, "build_opener", return_value=Opener()):
            with self.assertRaises(gate.ReleaseParityError):
                gate.public_get("https://intel.cyberdudebivash.com/", 64,
                                "intel.cyberdudebivash.com")

    def test_same_origin_fetch_remains_bounded_and_read_only(self):
        class Response:
            status = 200

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return "https://intel.cyberdudebivash.com/"

            def read(self, limit):
                return self.body[:limit]

        class Opener:
            def __init__(self, body):
                self.body = body

            def open(self, req, timeout):
                assert req.get_method() == "GET"
                assert timeout == 12
                return Response(self.body)

        for body, allowed in ((b"ok", True), (b"", False), (b"oversized", False)):
            with self.subTest(body=body), patch.object(
                gate, "build_opener", return_value=Opener(body)
            ):
                if allowed:
                    self.assertEqual(gate.public_get(
                        "https://intel.cyberdudebivash.com/", 2,
                        "intel.cyberdudebivash.com"), body)
                else:
                    with self.assertRaises(gate.ReleaseParityError):
                        gate.public_get("https://intel.cyberdudebivash.com/", 2,
                                        "intel.cyberdudebivash.com")

    def test_noncanonical_production_origin_rejected(self):
        for origin in (
            "https://intel.cyberdudebivash.com:443",
            "https://user@intel.cyberdudebivash.com",
            "https://intel.cyberdudebivash.com/?x=1",
            "https://intel.cyberdudebivash.com/#x",
        ):
            with self.subTest(origin=origin), self.assertRaises(gate.ReleaseParityError):
                gate.check_once(self.root, origin, self.fetcher)


if __name__ == '__main__':
    unittest.main()
