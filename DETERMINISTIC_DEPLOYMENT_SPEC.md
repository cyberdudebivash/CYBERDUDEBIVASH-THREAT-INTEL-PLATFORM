# CYBERDUDEBIVASH® SENTINEL APEX v155.0
# DETERMINISTIC DEPLOYMENT SPECIFICATION
# Classification: ENTERPRISE DEPLOYMENT ARCHITECTURE

**Version:** v155.0
**Effective:** 2026-05-15
**Author:** Principal CI/CD Deterministic Deployment Engineer

---

## SPECIFICATION OVERVIEW

This document specifies the complete deterministic deployment architecture for
SENTINEL APEX. A deployment is **deterministic** if:

1. The same working tree state ALWAYS produces the same gh-pages artifact
2. The artifact can be fully verified against a manifest before publication
3. No runtime file pollution reaches the customer-facing CDN
4. All historical reports are preserved on every deployment
5. Post-deployment customer URL validity is confirmed via HTTP probing

---

## DEPLOYMENT PIPELINE SPECIFICATION

### Stage Architecture (v155.0)

```
STAGE 0:    Checkout (fetch-depth:0)
STAGE 1-3:  Intelligence Pipeline (STIX, AI, enrichment)
STAGE 3.2:  Report Generation (God Mode governed)
STAGE 4:    Git Sync (safe_git_commit.py with ORIG_HEAD recovery)
STAGE 5.4.1: Report Existence Validator (HARD FAIL gate)
STAGE 5.4.6: Build Dist Artifact      (HARD FAIL gate)  ← NEW v155.0
STAGE 5.4.7: Dist Artifact Verifier   (HARD FAIL gate)  ← NEW v155.0
STAGE 5:    GitHub Pages Deploy (folder: dist)          ← CHANGED v155.0
STAGE 5.8.1b: Report URL Canary       (HARD FAIL gate)  ← HARDENED v155.0
```

---

## CHECKOUT SPECIFICATION

```yaml
- name: "Checkout repository"
  uses: actions/checkout@v4.3.1
  with:
    fetch-depth: 0        # Full history — enables ORIG_HEAD recovery, rollback
    ref: main
    token: ${{ secrets.GITHUB_TOKEN }}
```

**Rationale for fetch-depth: 0:**
- ORIG_HEAD recovery in safe_git_commit.py requires the preceding commit
- Deployment lineage tracking requires commit history
- Rollback to prior deployment requires historical commits
- `fetch-depth: 1` silently breaks ORIG_HEAD restore (FIX-1 from v154.0)

---

## DIST ARTIFACT SPECIFICATION

### dist/ Directory Contract

The `dist/` directory is the SOLE deployment artifact. It MUST:

1. Be rebuilt from scratch on every pipeline run (`shutil.rmtree(dist/)` first)
2. Contain only customer-facing files (no internal pipeline files)
3. Include the complete `reports/` corpus from the working tree
4. Contain `deployment_manifest.json` with SHA-256 checksums for all files
5. Pass the 10-check battery in `dist_artifact_verifier.py` before deployment

### dist/ Include List

```
INCLUDED:
  reports/**/*.html           (threat intel reports — ALL of them)
  css/**                      (frontend styles)
  js/**                       (frontend scripts)
  api/**                      (public API endpoints)
  *.html                      (root-level pages — filtered, see below)
  feed.json                   (public STIX feed)
  feed_manifest.json          (public manifest)
  latest.json                 (latest intel endpoint)
  _headers                    (Cloudflare/GitHub Pages response headers)
  .nojekyll                   (disables Jekyll — CRITICAL for Pages)
  CNAME                       (custom domain — intel.cyberdudebivash.com)
  robots.txt, sitemap.xml     (SEO)
  favicon.ico, favicon.png    (brand assets)

EXCLUDED:
  .github/                    (internal CI — NOT for customers)
  scripts/                    (Python scripts — NOT for customers)
  data/                       (runtime data — NOT for customers)
  config/                     (internal config — NOT for customers)
  agent/                      (agent code — NOT for customers)
  workers/                    (Cloudflare worker source — NOT for customers)
  *.py, *.sh, *.log, *.pem   (internal files)
  *.bak, *.pre_*, *.tmp       (temporary files)
  __pycache__                 (Python cache)
  node_modules/, vendor/      (dependency trees)
  GODMODE-*.html              (internal audit pages)
  SENTINEL_APEX_*_AUDIT.html  (internal audit pages)
```

---

## DEPLOYMENT MANIFEST SPECIFICATION

**Path:** `dist/deployment_manifest.json`

**Schema:** `sentinel_apex_deployment_manifest_v1`

```json
{
  "schema": "sentinel_apex_deployment_manifest_v1",
  "version": "155.0.0",
  "pipeline_run_id": "25913787114",
  "generated_at": "2026-05-15T11:19:00Z",
  "total_files": 38127,
  "report_count": 36087,
  "files": {
    "reports/2026/05/intel--e3899b6cfbfb2035d8db9a5c.html": {
      "sha256": "a3f5c7...",
      "size": 101832
    },
    "index.html": {
      "sha256": "b8d2e1...",
      "size": 42816
    },
    "..."
  }
}
```

**Invariants enforced:**
- `report_count` equals the count of `files` entries starting with `reports/`
- Every entry in `files` has a non-empty `sha256` (64 hex chars)
- Every entry in `files` has `size > 0`
- `generated_at` is an ISO-8601 UTC timestamp

---

## GITHUB PAGES DEPLOYMENT SPECIFICATION

```yaml
- name: "STAGE 5 - Deploy to GitHub Pages"
  uses: JamesIves/github-pages-deploy-action@v4.7.4
  with:
    branch: gh-pages
    folder: dist          # Governed artifact only — was "."
    clean: true           # gh-pages mirrors dist/ exactly
    force: true           # Ensure push succeeds
```

**Change rationale:**

| Parameter | Old Value | New Value | Reason |
|---|---|---|---|
| `folder` | `.` | `dist` | Deploy governed artifact, not raw workspace |
| `clean` | `false` | `true` | `dist/` is complete; mirror exactly |

**Why `clean: true` is now safe:**
`dist/reports/` contains ALL 36,087+ historical reports. With `clean: true`, gh-pages
EXACTLY mirrors `dist/`. No historical reports are lost because they are ALL in `dist/`.
Previously, `clean: false` was needed as a workaround for missing reports — that
workaround is no longer needed because `dist/` is always complete.

---

## CANARY VALIDATION SPECIFICATION

```yaml
- name: "STAGE 5.8.1b - Report URL Canary"
  timeout-minutes: 10
  env:
    CANARY_WAIT_SECS: "120"    # Initial CDN propagation wait
    CANARY_RETRY_COUNT: "3"    # Retry rounds
    CANARY_RETRY_WAIT: "60"    # Seconds between retries
  run: python3 scripts/report_url_canary.py
```

**Canary timing:**

```
T+0:    gh-pages force-push completes
T+30s:  GitHub Pages begins artifact processing
T+60s:  GitHub Pages CDN update begins
T+120s: CANARY: First probe round (initial wait expires)
T+150s: (if failures) CANARY: Retry 1 (after 60s retry wait)
T+210s: (if failures) CANARY: Retry 2
T+270s: (if failures) CANARY: Retry 3
T+300s: CANARY: Final result — HARD FAIL or GREEN
```

**URL source priority:**
1. `dist/deployment_manifest.json` — authoritative, SHA-256 validated
2. `api/feed.json` — gitignored runtime feed
3. `feed.json` — public committed feed (null-byte corruption guard active)

---

## CONCURRENCY AND RACE CONDITION SPECIFICATION

### Concurrency Group
```yaml
concurrency:
  group: sentinel-data-writer
  cancel-in-progress: false
```

Ensures only one pipeline runs at a time. Eliminates the `git reset --hard` race
condition that was the primary root cause in v154.0.

### ORIG_HEAD Recovery (safe_git_commit.py)
With `fetch-depth: 0`:
1. Before stash recovery: snapshot `reports/` file set
2. Run `git stash push` + `git reset --hard origin/main` + `git stash pop`
3. After reset: compare current `reports/` to snapshot
4. If files were lost: `git checkout ORIG_HEAD -- reports/` (ORIG_HEAD resolvable with full history)
5. Stage 5.4.1 then hard-fails if reports are still missing

---

## DEPLOYMENT REPRODUCIBILITY CONTRACT

A deployment is REPRODUCIBLE if it produces the same `dist/` for the same working tree.

**Determinism guarantees:**
1. `build_dist_artifact.py` uses a fixed include list (no glob ordering issues)
2. `dist/` is always wiped and rebuilt from scratch
3. SHA-256 checksums are deterministic (same input → same hash)
4. `deployment_manifest.json` is generated after all files are in place
5. Report files are binary-identical (no timestamp injection in HTML)

**Reproducibility verification:**
```bash
# To verify two runs produced the same dist/:
diff <(cat run1/dist/deployment_manifest.json | jq '.files | keys') \
     <(cat run2/dist/deployment_manifest.json | jq '.files | keys')
# Should produce no output for identical report sets
```
