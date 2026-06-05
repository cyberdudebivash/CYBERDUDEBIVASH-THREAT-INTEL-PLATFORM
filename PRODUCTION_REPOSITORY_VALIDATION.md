# PRODUCTION_REPOSITORY_VALIDATION.md
## Intelligence Repository Architecture — Production Validation
**Generated:** 2026-06-06 | **Status:** ✅ PASS

## Repository Architecture

```
data/intelligence_repository/
  intelligence_index.json          — Master index + stable dashboard metrics
  advisory_registry.json           — All advisory metadata (3,001 entries)
  intel_retention_registry.json    — Per-item retention policy (3,001 entries)
  intel_lifecycle_registry.json    — Lifecycle state tracking (3,001 entries)
  historical_feed_registry.json    — Per-run pipeline history
  advisories/
    registry_202602.json           — February 2026 (51 advisories)
    registry_202603.json           — March 2026 (2,312 advisories)
    registry_202604.json           — April 2026 (638 advisories)
```

## Data Integrity Checks

| Check | Result |
|---|---|
| advisory_registry total matches intelligence_index | ✅ 3,001 |
| retention_registry entries == advisory_registry entries | ✅ 3,001 |
| lifecycle_registry entries == advisory_registry entries | ✅ 3,001 |
| Monthly chunk totals sum to total | ✅ 51+2312+638=3,001 |
| Zero duplicate intel_ids | ✅ Verified |
| Zero null titles | ✅ Verified |
| Retention policy applied to all items | ✅ 3,001/3,001 |

## Lifecycle Distribution

| State | Count | Meaning |
|---|---|---|
| ACTIVE | 0 | Items published within last 30 days |
| MONITORING | 2,705 | Items 31–90 days old |
| ARCHIVED | 296 | Items >90 days old (retained — never deleted) |

**Note:** ARCHIVED items are RETAINED. Archiving is a lifecycle state, not deletion.

## Severity Distribution

| Severity | Count | Retention |
|---|---|---|
| CRITICAL | 292 | 24 months |
| HIGH | 278 | 18 months |
| MEDIUM | 2,054 | 12 months |
| LOW | 377+ | 6 months |
| Permanent | 377 | FOREVER |

## Dashboard Metrics (from intelligence_index.json)

```json
{
  "data_source": "intelligence_repository",
  "total_advisories": 3001,
  "note": "Cumulative totals — never decreasing"
}
```

**Status: PRODUCTION READY** ✅
