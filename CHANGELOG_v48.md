# CHANGELOG v48.0 — PIPELINE HARDENING

**Release Date:** 2026-03-14
**Codename:** PIPELINE HARDENING
**Module:** `agent/v48_pipeline_hardening/`

## Critical Security Fix

### SEC-01: Hardcoded JWT Secret Removed
- `agent/config.py` exposed `cdb-sentinel-apex-v30-secret-change-in-prod` as default JWT secret in public repository
- Any attacker could forge valid JWT tokens for all API tiers
- **Fix:** Default removed. Ephemeral random secret generated with WARNING log when env var not set

## P0 Bug Fixes

### BUG-01: Dashboard EMBEDDED_INTEL 18+ Days Stale (FIXED)
- **Root cause:** `sync-dashboard.yml` used emoji-prefixed workflow names that didn't match actual workflow names
- Workflow `workflow_run` trigger NEVER fired — sync only ran on 6-hour cron (which also had issues)
- **Fix:** Corrected all 4 workflow names to match exact `name:` field in each workflow file

### BUG-02: Manifest Sorted Ascending Instead of Descending (FIXED)
- Dashboard and API consumers assume `manifest[0]` = newest entry
- `export_stix.py` appends new entries at end → `[-50:]` trim keeps newest but in ascending order
- **Fix:** Post-pipeline sort pass ensures descending order (newest first)

## High Priority Fixes

### BUG-03: 70% EPSS/CVSS Scores Null (FIXED)
- Individual API calls to FIRST.org EPSS and NVD CVSS APIs timeout in GitHub Actions
- **Fix:** Batch EPSS enrichment (30 CVEs per API call) with persistent local cache (24h TTL)
- NVD CVSS calls rate-limited with API key support

### BUG-04: KEV Always False (0/50 Entries) (FIXED)
- `_enrich_cve_metadata()` in sentinel_blogger.py constructed KEV URL but never queried it
- **Fix:** Post-pipeline KEV enrichment using v46 VANGUARD kev_enricher module

## Architecture

All fixes follow the established additive-only, zero-regression pattern:
- New module: `agent/v48_pipeline_hardening/`
- No modification of existing v26-v47 modules
- Post-pipeline orchestration via `pipeline_hardener.py`
- Graceful degradation on all import failures
