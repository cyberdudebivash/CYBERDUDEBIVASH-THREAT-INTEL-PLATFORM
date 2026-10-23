"""Offline synthetic tests: never read R2, make cloud requests or mutate production."""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import p0_php2shell_bundle_preflight as audit  # noqa: E402

NEWS = audit._PHP2SHELL_NEWS_URL
VENDOR = audit._PHP2SHELL_VENDOR_URL


def fake_worker(*args, **kwargs):
    return subprocess.CompletedProcess(args[0], 0, json.dumps({
        'verdict': 'DELIVERABLE', 'freshness': 'FRESH',
        'worker_public_tlp_gate': 'PASS', 'worker_body_budget_exceeded': False,
    }), '')


class BundlePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.canonical = self.root / 'feed.json'
        self.out = self.root / 'intel'
        self.out.mkdir()
        self.when = datetime.now(timezone.utc)
        self.ts = self.when.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.record = {
            'title': 'PHP ships emergency patches', 'tlp': 'TLP:CLEAR',
            'source': 'BleepingComputer', 'source_url': NEWS,
            'cve_id': 'CVE-2026-109619',
            'cve_ids': ['CVE-2026-109618', 'CVE-2026-109619'],
        }
        self.public = {**self.record, 'references': [{
            'url': VENDOR, 'type': 'vendor_advisory',
            'publisher': 'PHP Security Team',
            'cve_ids': ['CVE-2026-109618', 'CVE-2026-109619'],
        }]}
        self.canonical_data = [copy.deepcopy(self.record)]
        self.latest_data = [copy.deepcopy(self.public)]
        self.generate()

    def dump(self, path, data, pretty=False):
        path.write_text(json.dumps(data, ensure_ascii=False,
            separators=None if pretty else (',', ':'),
            indent=2 if pretty else None), encoding='utf8')

    def generate(self):
        self.dump(self.canonical, self.canonical_data)
        self.expected = hashlib.sha256(self.canonical.read_bytes()).hexdigest()
        bundles = {}
        for name in audit.BUNDLES:
            rows = self.latest_data if name == 'latest' else [self.record]
            obj = {
                'schema_version': '1.0', 'generated_at': self.ts,
                'count': len(rows), 'items': rows,
                **({'tier':'PRO'} if name == 'latest_pro' else {}),
            }
            sha = audit.compact_digest(obj)
            obj['sha256'] = sha
            self.dump(self.out / (name + '.json'), obj)
            bundles[name] = {'path': f'api/v1/intel/{name}.json',
                'count': len(rows), 'sha256': sha, 'generated_at': self.ts}
        reg = {'schema_version': '1.0', 'generated_at': self.ts,
            'bundles': bundles, 'source': {'path': 'api/feed.json',
                'count': len(self.canonical_data),
                'sha256': audit.compact_digest(self.canonical_data)}}
        self.dump(self.out / 'manifest.json', reg)

    def verify(self):
        return audit.verify(self.canonical, self.out, self.expected,
                            now=self.when, worker_runner=fake_worker)

    def test_known_good_bundle_passes_but_never_authorizes_remote_release(self):
        result = self.verify()
        self.assertEqual(result['errors'], [])
        self.assertTrue(result['passed'])
        self.assertFalse(result['production_approved'])

    def test_canonical_hash_mismatch_fails(self):
        result = audit.verify(self.canonical, self.out, '0'*64,
                              now=self.when, worker_runner=fake_worker)
        self.assertIn('CANONICAL_SHA256_MISMATCH', result['errors'])

    def test_unrelated_source_not_permitted_to_impersonate_reviewed_article(self):
        self.canonical_data[0]['source_url'] = 'https://attacker.invalid/fake'
        self.generate()
        self.assertIn('CANONICAL_REVIEWED_SOURCE_NOT_UNIQUE', self.verify()['errors'])

    def test_source_with_restricted_upstream_evidence_fails(self):
        self.canonical_data[0]['sources'] = [{'tlp': 'TLP:AMBER'}]
        self.generate()
        self.assertIn('CANONICAL_SOURCE_RESTRICTED_UPSTREAM', self.verify()['errors'])

    def test_missing_cve_in_reviewed_article_fails(self):
        self.canonical_data[0]['cve_ids'] = ['CVE-2026-109619']
        self.generate()
        self.assertIn('CANONICAL_SOURCE_CVE_IDENTITY_INCOMPLETE', self.verify()['errors'])

    def test_restricted_canonical_source_fails_even_if_public_copy_clear(self):
        self.canonical_data[0]['tlp'] = 'TLP:AMBER'
        self.generate()
        self.assertIn('CANONICAL_SOURCE_NOT_EXPLICIT_CLEAR', self.verify()['errors'])

    def test_missing_public_vendor_reference_fails(self):
        self.latest_data[0].pop('references')
        self.generate()
        result = self.verify()
        self.assertIn('REVIEWED_PROVENANCE_RECORD_MISMATCH', result['errors'])
        self.assertIn('PHP2SHELL_COVERAGE_GATE_FAILED', result['errors'])

    def test_paid_url_in_public_item_is_rejected(self):
        self.latest_data[0]['report_url'] = 'https://paid.example/report'
        self.generate()
        self.assertIn('PUBLIC_FIELD_ALLOWLIST_OR_PREMIUM_VIOLATION', self.verify()['errors'])

    def test_unreviewed_reference_is_rejected(self):
        self.latest_data.append({'title': 'Unrelated', 'tlp': 'TLP:CLEAR',
                                 'references': [{'url': 'https://internal.invalid/secret'}]})
        self.generate()
        self.assertIn('UNREVIEWED_PUBLIC_REFERENCES_PRESENT', self.verify()['errors'])

    def test_old_manifest_timestamp_rejected_despite_same_source_records(self):
        self.ts = (self.when - timedelta(hours=7)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.generate()
        self.assertIn('PUBLIC_LATEST_FRESHNESS_INVALID', self.verify()['errors'])

    def test_tampered_manifest_sha_detected(self):
        p = self.out / 'manifest.json'
        manifest = json.loads(p.read_text())
        manifest['bundles']['latest']['sha256'] = 'bad'
        self.dump(p, manifest)
        self.assertIn('MANIFEST_LATEST_INTEGRITY_MISMATCH', self.verify()['errors'])

    def test_duplicate_canonical_source_fails(self):
        self.canonical_data.append(copy.deepcopy(self.record))
        self.generate()
        self.assertIn('CANONICAL_REVIEWED_SOURCE_NOT_UNIQUE', self.verify()['errors'])

    def test_missing_bundle_fails(self):
        (self.out / 'latest_pro.json').unlink()
        self.assertIn('BUNDLE_LATEST_PRO_UNREADABLE', self.verify()['errors'])

    def test_pro_enterprise_field_leak_is_rejected(self):
        pro = self.out / 'latest_pro.json'
        doc = json.loads(pro.read_text())
        doc['items'][0]['siem_rules'] = ['restricted']
        digestable = {k:v for k,v in doc.items() if k != 'sha256'}
        doc['sha256'] = audit.compact_digest(digestable)
        self.dump(pro, doc)
        registry = self.out / 'manifest.json'
        info = json.loads(registry.read_text())
        info['bundles']['latest_pro']['sha256'] = doc['sha256']
        self.dump(registry, info)
        self.assertIn('PRO_TIER_ISOLATION_VIOLATION', self.verify()['errors'])

    def test_worker_gate_failure_is_not_ignored(self):
        bad = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1,
            json.dumps({'verdict': 'BLOCKED'}), '')
        r = audit.verify(self.canonical, self.out, self.expected,
                         now=self.when, worker_runner=bad)
        self.assertIn('WORKER_BOUNDARY_REJECTED', r['errors'])

    def test_worker_environment_does_not_receive_cloudflare_tokens(self):
        orig = audit.os.environ.get('CLOUDFLARE_API_TOKEN')
        audit.os.environ['CLOUDFLARE_API_TOKEN'] = 'synthetic-not-a-real-token'
        try:
            def inspect(*args, **kwargs):
                self.assertNotIn('CLOUDFLARE_API_TOKEN', kwargs['env'])
                self.assertNotIn('AWS_SECRET_ACCESS_KEY', kwargs['env'])
                return fake_worker(*args, **kwargs)
            ok, why = audit._worker_diagnostic(self.out / 'latest.json', runner=inspect)
            self.assertTrue(ok)
            self.assertIsNone(why)
        finally:
            if orig is None:
                audit.os.environ.pop('CLOUDFLARE_API_TOKEN', None)
            else:
                audit.os.environ['CLOUDFLARE_API_TOKEN'] = orig

    def test_report_contains_no_record_title_or_original_source_url(self):
        r = self.verify()
        raw = json.dumps(r)
        self.assertNotIn('PHP ships', raw)
        self.assertNotIn('bleepingcomputer.com', raw)


if __name__ == '__main__':
    unittest.main()
