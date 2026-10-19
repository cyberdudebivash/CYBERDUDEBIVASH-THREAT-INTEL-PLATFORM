# Sentinel APEX P0 report chronology audit (offline)

The current convergence validator's primary manifest route sorts `reports/YYYY/MM/intel--<hash>.html` alphabetically and labels its tail "latest". Hash ordering is not chronology (incident #819).

This **read-only precheck** selects latest and historical candidates only after checking explicit UTC ISO timestamps, canonical host/path/id parity, uniqueness, and deterministic timestamp ordering. It never claims an object was published, that a 404 is expected, or that a customer can retrieve the object.

Run from the repository root:

```bash
python3 -m unittest tests.test_report_chronology_integrity -v
python3 scripts/report_chronology_integrity.py --catalog api/reports/index.json
python3 scripts/report_chronology_integrity.py --catalog api/reports/index.json --max-age-hours 24
```

- Exit 0 means **CHRONOLOGY_PRECHECK_ONLY**, not production certification.
- Exit 2 means **BLOCKED**; no remote requests or changes are made.
- Existing historical catalogue timestamps may be naive (without `Z` or `+00:00`); these intentionally fail validation pending provenance-backed normalization. Do not guess timezone.
- This standalone audit is **not yet wired into the publisher**. Wire it only after validating the canonical timestamp feed and preserving current fail-closed publication-status checks.
- Live release still requires customer-ready status parity against successful R2/Pages writes, bounded route fetch-back, operator release approval, and budget headroom across all shared Cloudflare workloads.
