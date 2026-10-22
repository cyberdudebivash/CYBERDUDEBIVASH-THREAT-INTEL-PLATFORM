# P0 PHP2Shell release evidence and deployment gate (2026-10-23)

**Status: NO-GO.** Draft PR #890 adds a *snapshot coverage verifier*, not a complete
CVE ingestion fix or customer release. Do not deploy based solely on this PR.

## Evidence established from repository
- `core/ingestion/sources/nvd_source.py` supports targeted `fetch_cve()`.
- `scripts/generate_api_manifests.py` publishes `api/v1/intel/latest.json` from
  `api/feed.json` after TLP publication policy and public API projection.
- `scripts/public_api_sanitizer.py` exposes `cve_id`, `cve_ids`,
  `source_url` and `source` in the public projection.
- `config/public_freshness_contract.json` sets the public maximum age to 6h.
- The public latest endpoint is a bounded snapshot, **not** a complete inventory.

## Required operator evidence, in order
1. Record the current main SHA, production Worker version, R2 object versions,
   current API health status and Cloudflare usage. Capture rollback identifiers.
2. On an isolated checkout, run:
   `python -m unittest discover -s tests -p 'test_php2shell_coverage_gate.py' -v`
   and the existing freshness, TLP, sanitizer, manifest and gateway tests.
3. Check authoritative source records and NVD `fetch_cve()` for
   CVE-2026-109618 and CVE-2026-109619. Save original references and
   source timestamps. Do not fabricate CVSS, KEV or exploitation claims.
4. Check canonical ingestion inventory independently of the public snapshot.
   If absent: diagnose collector scheduling, API errors, lookback boundaries,
   filters, parsing, and persistence. If present: trace feed generation,
   TLP withholding, public projection, manifest upload, R2 and gateway.
5. Check whether either CVE is **expected** in the bounded latest snapshot.
   An absent older CVE is not necessarily a pipeline defect. For permanent
   discoverability use an existing authenticated/authorized lookup route,
   or design a separate bounded CVE index with explicit retention.
6. Only after verifying a publication contract, run:
   `python scripts/php2shell_coverage_gate.py --url https://intel.cyberdudebivash.com/api/v1/intel/latest.json`
   A nonzero result blocks the **snapshot coverage requirement**, not all
   platform health. Preserve stderr/stdout and response evidence.
7. Verify no TLP or premium data leakage, published source provenance,
   accurate timestamps, and customer-visible dashboard/API parity.
8. Check Cloudflare Workers, R2, KV and D1 aggregate account usage before
   any deploy. Keep external calls bounded and cached; avoid new polling.
9. Deploy only through the approved manual operator procedure after all
   gates pass. Verify live health, feed, dashboard, negative controls and
   rollback readiness; do not enable GitHub Actions deployment.

## Known limitations of this PR
- A recognized source domain does not prove its page corroborates the CVE.
- A fresh manifest timestamp does not prove source records are recent.
- Snapshot absence does not prove missing canonical ingestion.
- Tests have not been independently executed in the deployment environment.
- No live customer coverage or production deployment is certified.

**Decision:** Keep PR draft and production unchanged pending evidence.
