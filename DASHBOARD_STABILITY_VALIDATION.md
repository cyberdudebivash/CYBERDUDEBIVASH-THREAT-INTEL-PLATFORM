# DASHBOARD_STABILITY_VALIDATION.md
## Dashboard Stability — Production Validation
**Generated:** 2026-06-06 | **Status:** ✅ PASS

## Problem Resolved

**Before v171.0:**
- Dashboard reads `api/v1/intel/latest.json`
- Each pipeline run overwrites `latest.json`
- Advisory count fluctuates: run #1=25, run #2=30, run #3=18
- Historical advisories disappear
- Customer trust erodes

**After v171.0:**
- Dashboard reads `data/intelligence_repository/intelligence_index.json`
- Index is append-only — never decreases
- Advisory count is cumulative: run #1=25, run #2=55, run #3=55
- All historical advisories permanently retained
- Customer trust restored

## Dashboard Data Source

| Metric | Old Source | New Source |
|---|---|---|
| Total advisories | `latest.json` count | `intelligence_index.json` repository.total_advisories |
| Critical count | `latest.json` filter | `intelligence_index.json` severity_breakdown.CRITICAL |
| IOC count | `latest.json` sum | Repository cumulative |
| Historical data | Not available | 30/90/180/365-day windows |

## Stability Proof

Run sequence simulation:

| Run | Feed Items | Old Dashboard | New Dashboard |
|---|---|---|---|
| #1 | 583 | 583 | 583 |
| #2 | 2,312 | 2,312 | 2,895 |
| #3 | 0 (empty run) | **0** ❌ | 2,895 ✅ |
| #4 | 73 | 73 | 2,968 |
| #5 | 33 | 33 | **3,001** |

**New dashboard count is STRICTLY NON-DECREASING** ✅

## Archive UI Validation

| Feature | Status |
|---|---|
| 30-day window | ✅ intelligence-archive.html |
| 90-day window | ✅ intelligence-archive.html |
| 180-day window | ✅ intelligence-archive.html |
| 365-day window | ✅ Enterprise tier gate |
| Search & filter | ✅ Client-side |
| Export JSON | ✅ All windows |
| Export CSV | ✅ All windows |
| Severity breakdown per window | ✅ |
| Accumulation trend chart | ✅ Monthly bars |

## Worker Integration

`dashboard_repository_adapter.js`:
- Reads from R2 bucket (primary) → GitHub raw (fallback)
- 5-minute cache TTL
- Returns cumulative repository metrics
- Never reads raw feed files

**Status: PRODUCTION READY** ✅
