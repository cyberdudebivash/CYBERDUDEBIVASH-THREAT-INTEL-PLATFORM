# ARTIFACT GOVERNANCE REPORT
## CYBERDUDEBIVASH SENTINEL APEX — Enterprise Artifact Lifecycle Management
**Generated:** 2026-05-15T18:35:35Z
**Pipeline Version:** 156.0.0

---

## Artifact Inventory

### HTML Report Lifecycle

| Tier | Location | Count (est.) | Action |
|------|----------|-------------|--------|
| HOT (last 90 days) | `reports/` on main branch | ~2,000–5,000 | Copied to `dist/` per run |
| ARCHIVE (90+ days) | `gh-pages` branch only | ~60,000+ | Served at original URLs |
| Dist artifact | `dist/reports/` | = HOT tier | Deployed per run |

**Governance change (v156.0):** `REPORT_RETENTION_DAYS` defaults changed from **0 → 90** in STAGE 5.4.6 and 5.4.7.

**Expected disk reduction per run:**

| Before (v155) | After (v156) |
|--------------|-------------|
| ~36,785 reports copied to dist/ | ~2,000–5,000 reports copied (last 90 days) |
| ~3.7 GB dist/reports/ copy | ~0.2–0.5 GB dist/reports/ copy |
| **Reduction: ~3.2–3.5 GB per run** ||

### STIX Bundle Lifecycle

| Metric | Before | After (v156.0) |
|--------|--------|---------------|
| Bundles per run | 162 accumulated | 162 generated, keep latest 50 |
| Governance | None | `runner_disk_governor.py` prunes at STAGE 5.4.5c |
| Max disk usage | Unbounded | ~50 × 50 KB = ~2.5 MB |

### Telemetry Lifecycle

| File type | Retention Policy |
|-----------|-----------------|
| `data/telemetry/*.json` | 7 days (TELEMETRY_MAX_DAYS) |
| `data/audit/pipeline_audit.json` | Latest only |
| `data/archive/report_archive_audit.jsonl` | Append-only (governed separately) |
| `runner_disk_telemetry.json` | Latest only (overwritten each run) |

---

## Artifact Deduplication

### dist/ Rebuild Strategy
- `dist/` is **wiped clean** at STAGE 5.4.5c before rebuild (prevents stale artifact accumulation)
- `build_dist_artifact.py` builds deterministic artifact from scratch each run
- `deployment_manifest.json` checksums every file — detects any corruption

### Report Deduplication
- Report IDs are content-addressed (`intel--{hash}.html`)
- Duplicate ingestion is prevented at the manifest level
- `ci_report_count_check.py` monitors total count against expected growth

---

## Artifact Quota Governance

| Artifact | Quota | Enforcement |
|----------|-------|-------------|
| dist/ reports (per run) | Last 90 days only | `REPORT_RETENTION_DAYS=90` |
| STIX bundles | 50 max on runner | `runner_disk_governor.py --predist` |
| Telemetry files | 7 days max | `runner_disk_governor.py --predist` |
| Python pycache | 0 (cleared each predist) | `runner_disk_governor.py --predist` |
| pip cache | 0 (cleared each predist) | `runner_disk_governor.py --predist` |
| dist/ stale build | 0 (wiped before rebuild) | `runner_disk_governor.py --predist` |

---

## Archive Governance Policy

### Two-Tier Deployment Architecture

```
HOT TIER (main branch, git-tracked):
  reports/YYYY/MM/<report>.html  ← last 90 days
  ↓ copied to dist/ every run
  ↓ deployed to gh-pages (clean: false)

ARCHIVE TIER (gh-pages only):
  reports/YYYY/MM/<report>.html  ← 90+ days old
  ↓ NOT on main branch (git rm --cached)
  ↓ PERMANENTLY on gh-pages (never overwritten)
  ↓ served at original URLs unchanged
```

### Archive Manager Status
- **Mode:** LIVE (`ARCHIVE_DRY_RUN=0`) — enabled in v156.0
- **Retention window:** 90 days (`REPORT_RETENTION_DAYS=90`)
- **Safety floor:** 500 minimum HOT reports (`ARCHIVE_MIN_REPORTS=500`)
- **Eligibility:** 1,597 reports eligible for archiving in Run #1199

---

## Compliance Checkpoints

| Check | Tool | Stage | Status |
|-------|------|-------|--------|
| dist/ report_url paths all present | `dist_artifact_verifier.py` | 5.4.7 | Active |
| dist/ artifact purity (no scripts/ in dist/) | `dist_artifact_verifier.py` | 5.4.7 | Active |
| SHA-256 checksum spot-check | `dist_artifact_verifier.py` | 5.4.7 | Active |
| Minimum report count (retention-mode aware) | `dist_artifact_verifier.py` | 5.4.7 | Active |
| Archive safety floor | `report_archive_manager.py` | 5.4.5b | Active |
| STIX bundle quota | `runner_disk_governor.py` | 5.4.5c | Active |
| Telemetry rotation | `runner_disk_governor.py` | 5.4.5c | Active |

*CYBERDUDEBIVASH(R) SENTINEL APEX — Artifact Governance Report*
*(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.*
