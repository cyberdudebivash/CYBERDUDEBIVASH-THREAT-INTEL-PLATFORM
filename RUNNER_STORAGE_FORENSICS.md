# RUNNER STORAGE FORENSICS REPORT
## CYBERDUDEBIVASH SENTINEL APEX — P0 Incident #1199
**Generated:** 2026-05-15T18:35:03Z
**Incident:** v156 update #1199 — System.IO.IOException: No space left on device
**Classification:** P0 — Production Infrastructure Governance Failure

---

## Executive Summary

The GitHub Actions runner (ubuntu-24.04, 14 GB disk) exhausted all available disk space
during STAGE 5.4.6 (Build Deterministic Dist Artifact). The failure occurred because
`build_dist_artifact.py` attempted to copy **all 36,785+ HTML reports** from `reports/`
into `dist/` — duplicating the largest storage consumer on the runner at the worst
possible moment in the pipeline.

**Root cause chain: three compounding factors**

| # | Factor | Disk Impact |
|---|--------|------------|
| 1 | 64,743 tracked HTML reports checked out from main branch | ~3–5 GB |
| 2 | `build_dist_artifact.py` (REPORT_RETENTION_DAYS=0) copies ALL reports to dist/ | ~3–5 GB additional |
| 3 | Python toolchain, pip packages, STIX bundles (162/run), telemetry | ~2–3 GB |
| | **TOTAL** | **~8–13 GB → runner OOM** |

---

## Forensic Evidence from Run #1199

### Pipeline Timeline
| Timestamp (UTC) | Event |
|-----------------|-------|
| 17:41:26 | Runner allocated (GitHub Actions 1000020303, Azure westcentralus) |
| 17:41:29 | Checkout started |
| ~17:45 | Python 3.12.13 setup + pip install |
| ~17:46–18:07 | STAGES 0.0–3.2: intelligence pipeline (1214s total) |
| 18:11:21 | STAGE 4: git commit+push succeeded (`REPORT_COUNT: 36785`) |
| 18:11:29 | STAGE 5.1–5.4.5: post-deploy checks passed |
| 18:11:30 | STAGE 5.4.5b: archive dry-run — **64,743 tracked HTML reports detected** |
| 18:11:30+ | **STAGE 5.4.6: build_dist_artifact.py → DISK EXHAUSTION** |
| — | Worker diag log write failed: `No space left on device` |

### Storage Hotspot Analysis (Estimated)

| Directory | Estimated Size | File Count | Classification |
|-----------|---------------|------------|----------------|
| `reports/` | 3.0–5.5 GB | 36,785 active HTML | **PRIMARY HOTSPOT** |
| `dist/reports/` (copy attempt) | 3.0–5.5 GB | 36,785 (attempted) | **DISK EXHAUSTION TRIGGER** |
| `data/stix/` | 0.5–1.5 GB | 162 new bundles/run | Secondary growth vector |
| Python/pip toolchain | 1.5–2.0 GB | — | Fixed cost |
| `data/telemetry/` | 0.1–0.3 GB | Accumulates unbounded | Tertiary |
| Runner system + OS | 3.0–4.0 GB | — | Fixed |

### Archive Manager Evidence

From STAGE 5.4.5b log (dry-run):
```
Tracked HTML reports : 64,743
HOT (retain)         : 63,146  ← only 1,597 eligible for archiving
ARCHIVE (untrack)    : 1,597   ← older than 90 days
Mode                 : DRY-RUN (no changes made)
```

**The archive manager was in DRY-RUN mode** — it never freed a single byte.
The 1,597 archivable reports represent only 2.5% of total tracked files.

### Disk Growth Trajectory

| Metric | Value | Growth Rate |
|--------|-------|-------------|
| Current tracked HTML reports | 64,743 | ~24/day (6 runs × 4 reports) |
| Days to 75,000-file threshold | ~434 days | Without governance |
| Dist copy overhead per run | 36,785 × ~100 KB | ~3.7 GB per pipeline run |
| STIX bundle accumulation | 162/run | Unbounded without pruning |

---

## Storage Growth Map

```
14 GB Runner Disk Budget
├─ OS + system:          ~3.5 GB  [fixed]
├─ Python 3.12 + pip:    ~1.5 GB  [fixed]
├─ Repo checkout:        ~4.0 GB  [includes 64K HTML reports]
│   ├─ reports/          ~3.5 GB  ← LARGEST SINGLE CONSUMER
│   ├─ scripts/          ~0.1 GB
│   ├─ data/             ~0.2 GB
│   └─ other/            ~0.2 GB
├─ dist/ (copy attempt): ~3.5 GB  ← EXHAUSTION TRIGGER
│   └─ reports/          ~3.5 GB  ← duplicate of reports/
└─ Runner overhead:      ~0.5 GB
                        ─────────
TOTAL ATTEMPTED:        ~13.0 GB  [exceeds 14 GB runner disk]
```

---

## False Confidence Indicators

These factors masked the risk before it manifested:

1. **REPORT_COUNT: 36785** — logged as a success metric, not a warning
2. **Pipeline runtime: 1214s** — long runtime accepted without disk monitoring
3. **Archive dry-run** — showed 64,743 tracked reports but took no action
4. **No pre-dist disk check** — runner disk was never measured before the copy
5. **REPORT_RETENTION_DAYS defaulted to 0** — full copy was the default behavior

---

## Remediation Applied

See `WORKFLOW_STORAGE_HARDENING.md` for complete fix details.

*CYBERDUDEBIVASH(R) SENTINEL APEX — Runner Storage Forensics Report*
*(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.*
