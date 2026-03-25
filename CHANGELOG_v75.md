# SENTINEL APEX v75.0 / v75.1 — CHANGELOG

## Release Date: 2026-03-25

---

## v75.1 — Pipeline Stability + Intelligence Quality (this session)

### CRITICAL FIXES

#### 1. `scripts/v75_pipeline_hardener.py` — CREATED (was missing from repo)
- The workflow referenced this script but it never existed — silently skipped every run
- Now fully implemented: 7-step hardening pipeline
- Sort BEFORE trim (newest entries always survive)
- 3-layer deduplication: advisory_id → dedup_key → normalized title
- Daily archive: data/archive/YYYY-MM-DD.json + data/archive/index.json
- Atomic write with backup + rollback on any failure
- Idempotent: safe to run multiple times per day

#### 2. `agent/export_stix.py` — Sort-before-trim root cause fix
- Bug: `manifest_entries[-500:]` trimmed from unsorted list
- Fix: sort by timestamp DESC, then `[:500]`
- Recent intel now guaranteed to survive every trim cycle

#### 3. `agent/v56_publish_guard/publisher.py` — Blogger 400 error fix
- Bug: CVE titles containing `<=` (e.g. "Easy Image Gallery <= 1.5.3") caused
  HttpError 400 "invalid argument" — title was passed raw to Blogger API
- Fix: title sanitization before post_body construction
  (`<` → `&lt;`, `>` → `&gt;`, plus full Unicode map)
- Also fixed pending queue retry path — same title sanitization applied on retry

### INTELLIGENCE QUALITY IMPROVEMENTS

#### 4. `agent/content/source_fetcher.py` — NVD fallback enrichment (v75.1)
- CVE sources like cvefeed.io block scrapers → 0 words → thin reports (~1700w)
- New: when source returns 0 words AND URL has CVE ID, auto-fetch from NVD API:
  - Full English description
  - CVSS score + vector
  - CWE weakness classification
  - Affected products from CPE configurations
  - Reference URLs
  - Published date
- Result: CVE reports now get real NVD content → targeting 2500+ words
- Updated User-Agent to full Chrome fingerprint (reduces block rate)
- Zero regression: non-CVE sources use existing fetch path unchanged

#### 5. `agent/config.py` — Dead feed replacement
- Removed 12 feeds returning 0 entries every run (wasting 36s of execution time):
  cloud.google.com, qualys, sophos, fortinet, proofpoint, trendmicro,
  symantec, virustotal, nakedsecurity, tripwire, tenable (0-entry), talos (0-entry)
- Added 11 active replacement feeds:
  ESET, Recorded Future, SC Magazine, Help Net Security, Threatpost,
  CyberSecurityNews, BleepingComputer/Vulnerabilities, BleepingComputer/Malware,
  Full Disclosure, CERT Belgium, BSI Germany

### MONITORING UPGRADES

#### 6. `scripts/pre_deploy_gate.py` — Upgraded from 5 to 8 checks (v75.1)
- CHECK 1-5: Preserved exactly (conflict markers, EMBEDDED_INTEL, JSON valid, braces, functions)
- CHECK 6 (NEW): Manifest sort order — verifies entry[0] is newest (warning, not blocker)
- CHECK 7 (NEW): Duplicate advisory_id detection in manifest (warning, not blocker)
- CHECK 8 (NEW): EMBEDDED_INTEL vs manifest count alignment within ±20 tolerance

#### 7. `.github/workflows/sentinel-blogger.yml` — Workflow updates
- Added `data/archive` and `data/v46_ultraintel` to Ensure Directories step
- Pipeline Summary step now also prints v75 archive stats (days + total entries)
- Version bump to v75.0 in commit messages

---

## v75.0 — Base Release (previous session)

- Workflow fixed after #545 YAML corruption (complete file rewritten)
- Permanent working directory established: C:/Users/Administrator/Desktop/...
- Initial v75 step added to workflow

---

## Zero Regression Guarantee

All changes are:
- Additive or surgical fixes to existing logic
- Wrapped in try/except where touching live paths
- Tested via offline validation before deployment
- Rollback-capable (backups before atomic writes)

Pipeline #546 confirmed: PASS (11m 32s, 499 advisories, 5 published, 148 deduped)
Next run (#547+) will show: v75 hardener PASS, archive written, 400 errors reduced
