#!/usr/bin/env python3
"""Fail-closed, zero-cloud-write verification of a LOCAL PHP2Shell publication batch.

Read-only inputs: an already-reviewed, post-generator canonical api/feed.json
and the sibling api/v1/intel/{latest,latest_pro,top10,apex,manifest}.json files.
Run from a clean disposable checkout. This script NEVER regenerates or uploads.

A matching expected canonical digest detects unintended local changes; it does
NOT authenticate the origin of the snapshot. Record the actual R2 object
version/ETag and independent digest in the operator evidence before use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from php2shell_coverage_gate import check as check_coverage  # noqa: E402
from public_api_sanitizer import (  # noqa: E402
    PUBLIC_LATEST_FIELDS, PREMIUM_FIELDS, PRO_PREMIUM_FIELDS, _PHP2SHELL_CVES,
    _PHP2SHELL_NEWS_URL, _PHP2SHELL_VENDOR_URL,
)
from public_freshness_contract import classify_manifest_freshness, FRESH  # noqa: E402
from tlp_policy import publication_decision  # noqa: E402

MAX_CANONICAL_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_PUBLIC_BYTES = 1024 * 1024
BUNDLES = ('latest', 'latest_pro', 'top10', 'apex')
HEX64 = re.compile(r'^[a-f0-9]{64}$')


def compact_digest(data):
    return hashlib.sha256(json.dumps(
        data, ensure_ascii=False, separators=(',', ':'), allow_nan=False
    ).encode('utf-8')).hexdigest()


def bounded_json(path: Path, cap: int):
    # Avoid using a Windows junction, symlink, directory, or oversized artifact.
    if path.is_symlink() or not path.is_file():
        raise ValueError('INPUT_NOT_REGULAR_FILE')
    if path.stat().st_size < 2 or path.stat().st_size > cap:
        raise ValueError('INPUT_SIZE_INVALID')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError('INPUT_EXCEEDS_BOUND')
    return json.loads(raw), len(raw), hashlib.sha256(raw).hexdigest()


def structured_ids(record):
    result = set()
    if isinstance(record.get('cve_id'), str):
        result.add(record['cve_id'].upper())
    more = record.get('cve_ids')
    if isinstance(more, list) and len(more) <= 32:
        result.update(v.upper() for v in more if isinstance(v, str))
    return result


def inspected_candidate_records(items):
    return [item for item in items
            if isinstance(item, dict)
            and item.get('source_url') == _PHP2SHELL_NEWS_URL
            and _PHP2SHELL_CVES.issubset(structured_ids(item))]


def _worker_diagnostic(latest: Path, runner=subprocess.run):
    # Explicit argv, no shell, no Cloudflare credentials, no network operation.
    env = {k: v for k, v in os.environ.items()
           if k not in ('CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_API_KEY',
                        'CLOUDFLARE_EMAIL', 'CLOUDFLARE_ACCOUNT_ID')
           and not k.startswith(('CF_', 'AWS_', 'R2_', 'WRANGLER_'))}
    try:
        done = runner(
            ['node', str(SCRIPTS / 'p0_r2_public_feed_diagnostic.mjs'), str(latest)],
            cwd=REPO, env=env, capture_output=True, text=True,
            check=False, timeout=30,
        )
        report = json.loads(done.stdout)
        if (done.returncode != 0 or not isinstance(report, dict)
                or report.get('verdict') != 'DELIVERABLE'
                or report.get('worker_public_tlp_gate') != 'PASS'
                or report.get('freshness') != 'FRESH'
                or report.get('worker_body_budget_exceeded') is True):
            return False, 'WORKER_BOUNDARY_REJECTED'
        return True, None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False, 'WORKER_DIAGNOSTIC_UNAVAILABLE'


def verify(canonical: Path, bundle_dir: Path, expected_digest: str,
           *, now: datetime | None = None, worker_runner=subprocess.run):
    """No file mutations; safe report contains counts, hash evidence and codes only."""
    errors, evidence = [], {}
    def block(code):
        if code not in errors:
            errors.append(code)

    if not HEX64.fullmatch(expected_digest):
        return {'gate': 'php2shell_local_bundle_preflight', 'passed': False,
                'errors': ['EXPECTED_CANONICAL_SHA256_INVALID'], 'evidence': evidence,
                'production_approved': False}

    try:
        canonical_obj, size, byte_sha = bounded_json(canonical, MAX_CANONICAL_BYTES)
        evidence['canonical_bytes'] = size
        evidence['canonical_file_sha256'] = byte_sha
        if byte_sha != expected_digest:
            block('CANONICAL_SHA256_MISMATCH')
        if not isinstance(canonical_obj, list) or not canonical_obj:
            block('CANONICAL_FEED_NOT_NONEMPTY_ARRAY')
            canonical_obj = []
    except (OSError, ValueError, TypeError, UnicodeError):
        block('CANONICAL_INPUT_UNREADABLE')
        canonical_obj = []

    # Fail closed on source identity gaps, restricted classifications and
    # duplicate canonical source records. This is not a freshness claim.
    article_rows = [item for item in canonical_obj if isinstance(item, dict)
                    and item.get('source_url') == _PHP2SHELL_NEWS_URL]
    source_hits = inspected_candidate_records(canonical_obj)
    evidence['canonical_exact_source_matches'] = len(article_rows)
    if len(article_rows) != 1:
        block('CANONICAL_REVIEWED_SOURCE_NOT_UNIQUE')
    elif not _PHP2SHELL_CVES.issubset(structured_ids(article_rows[0])):
        block('CANONICAL_SOURCE_CVE_IDENTITY_INCOMPLETE')
    elif article_rows[0].get('tlp') != 'TLP:CLEAR':
        block('CANONICAL_SOURCE_NOT_EXPLICIT_CLEAR')
    elif not publication_decision(article_rows[0]).get('allowed'):
        block('CANONICAL_SOURCE_RESTRICTED_UPSTREAM')

    loaded = {}
    for name in (*BUNDLES, 'manifest'):
        try:
            obj, nbytes, raw_sha = bounded_json(
                bundle_dir / (name + '.json'),
                MAX_PUBLIC_BYTES if name == 'latest' else MAX_BUNDLE_BYTES,
            )
            loaded[name] = (obj, nbytes, raw_sha)
            evidence[name + '_bytes'] = nbytes
            evidence[name + '_file_sha256'] = raw_sha
        except (OSError, ValueError, TypeError, UnicodeError):
            block('BUNDLE_' + name.upper() + '_UNREADABLE')

    manifest = loaded.get('manifest', (None,))[0]
    latest = loaded.get('latest', (None,))[0]
    if isinstance(manifest, dict):
        registry = manifest.get('bundles')
        source_registry = manifest.get('source')
        if not isinstance(registry, dict):
            block('MANIFEST_BUNDLE_REGISTRY_MISSING')
            registry = {}
        if not isinstance(source_registry, dict):
            block('MANIFEST_SOURCE_REGISTRY_MISSING')
        elif canonical_obj and (
            source_registry.get('path') != 'api/feed.json'
            or source_registry.get('count') != len(canonical_obj)
            or source_registry.get('sha256') != compact_digest(canonical_obj)
        ):
            block('MANIFEST_CANONICAL_CONTENT_MISMATCH')

        for name in BUNDLES:
            obj = loaded.get(name, (None,))[0]
            entry = registry.get(name)
            if not isinstance(obj, dict) or not isinstance(entry, dict):
                block('MANIFEST_' + name.upper() + '_REGISTRY_INCOMPLETE')
                continue
            entries = obj.get('items')
            digestable = {k: v for k, v in obj.items() if k != 'sha256'}
            try:
                computed = compact_digest(digestable)
            except (TypeError, ValueError):
                computed = None
            if (computed is None or obj.get('sha256') != computed
                    or entry.get('sha256') != computed
                    or entry.get('path') != f'api/v1/intel/{name}.json'
                    or not isinstance(entries, list)
                    or not isinstance(obj.get('count'), int)
                    or obj['count'] != len(entries)
                    or entry.get('count') != len(entries)
                    or obj.get('generated_at') != manifest.get('generated_at')
                    or entry.get('generated_at') != obj.get('generated_at')
            ):
                block('MANIFEST_' + name.upper() + '_INTEGRITY_MISMATCH')
    else:
        block('MANIFEST_FORMAT_INVALID')

    paid = loaded.get('latest_pro', (None,))[0]
    if isinstance(paid, dict):
        paid_items = paid.get('items')
        if (paid.get('tier') != 'PRO' or not isinstance(paid_items, list)
                or any(not isinstance(it, dict) or set(it) & PRO_PREMIUM_FIELDS
                       for it in paid_items)):
            block('PRO_TIER_ISOLATION_VIOLATION')

    if isinstance(latest, dict):
        items = latest.get('items')
        if not isinstance(items, list) or not items or latest.get('count') != len(items):
            block('PUBLIC_LATEST_EMPTY_OR_COUNT_INVALID')
            items = []
        evidence['public_record_count'] = len(items)
        freshness = classify_manifest_freshness(latest.get('generated_at'), now=now)
        evidence['manifest_freshness_state'] = freshness['state']
        if freshness['state'] != FRESH:
            block('PUBLIC_LATEST_FRESHNESS_INVALID')
        coverage = check_coverage(latest, now=now)
        if coverage:
            block('PHP2SHELL_COVERAGE_GATE_FAILED')
        # The anonymous latest manifest is an exact projection. Newly added
        # fields may not leak merely because a generic upstream feed has them.
        allowed = PUBLIC_LATEST_FIELDS | {'references'}
        if any(not isinstance(item, dict) or set(item) - allowed
               or set(item) & PREMIUM_FIELDS for item in items):
            block('PUBLIC_FIELD_ALLOWLIST_OR_PREMIUM_VIOLATION')
        article_public_rows = [item for item in items if isinstance(item, dict)
                               and item.get('source_url') == _PHP2SHELL_NEWS_URL]
        hits = inspected_candidate_records(items)
        evidence['public_exact_source_matches'] = len(article_public_rows)
        expected_ref = [{
            'url': _PHP2SHELL_VENDOR_URL, 'type': 'vendor_advisory',
            'publisher': 'PHP Security Team', 'cve_ids': sorted(_PHP2SHELL_CVES),
        }]
        if (len(article_public_rows) != 1 or len(hits) != 1
                or hits[0].get('source') != 'BleepingComputer'
                or hits[0].get('tlp') != 'TLP:CLEAR'
                or hits[0].get('references') != expected_ref):
            block('REVIEWED_PROVENANCE_RECORD_MISMATCH')
        # The *only* arbitrary record with this special metadata is the
        # curated reviewed article. Reject a reference leak in all others.
        if any('references' in item and item.get('source_url') != _PHP2SHELL_NEWS_URL
               for item in items if isinstance(item, dict)):
            block('UNREVIEWED_PUBLIC_REFERENCES_PRESENT')
        if len(items) and len(source_hits) == 1 and len(article_rows) == 1 and len(hits) == 1:
            if hits[0].get('source_url') != source_hits[0].get('source_url'):
                block('SOURCE_ATTRIBUTION_DRIFT')
        ok, reason = _worker_diagnostic(bundle_dir / 'latest.json', runner=worker_runner)
        if not ok:
            block(reason)
    else:
        block('PUBLIC_LATEST_FORMAT_INVALID')

    return {
        'gate': 'php2shell_local_bundle_preflight',
        'passed': not errors,
        'production_approved': False,
        'errors': sorted(errors),
        'evidence': evidence,
        'scope': 'offline artifacts only; real R2 provenance, budget, auth, rollback and customer readback separately required',
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--canonical', type=Path, required=True,
                   help='Reviewed, post-generator local api/feed.json')
    p.add_argument('--bundle-dir', type=Path, required=True,
                   help='Local api/v1/intel directory containing all 5 files')
    p.add_argument('--expected-canonical-sha256', required=True,
                   help='SHA-256 captured separately from the canonical input')
    args = p.parse_args()
    try:
        report = verify(args.canonical, args.bundle_dir,
                        args.expected_canonical_sha256)
    except Exception:
        report = {'gate': 'php2shell_local_bundle_preflight', 'passed': False,
                  'errors': ['PREFLIGHT_UNEXPECTED_FAILURE'],
                  'production_approved': False, 'evidence': {}}
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get('passed') else 1


if __name__ == '__main__':
    sys.exit(main())
