"""Hermetic negative controls for production byte-parity release gate."""
import importlib.util
import tempfile
import unittest
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


if __name__ == '__main__':
    unittest.main()
