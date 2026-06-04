# DATA FLOW TRACE
## KEV Attribution Lifecycle — Ingestion to Integrity Gate
### CYBERDUDEBIVASH SENTINEL APEX — Forensic Run 2026-06-04

---

## PIPELINE STAGE MAP

```
Stage 1-3    run_pipeline.py → agent.sentinel_blogger       (ingestion + enrichment)
Stage 3.1    enrich_feed_apex.py                             (apex_ai injection)
Stage 3.1.1b cve_id_backfill                                 (CVE ID extraction)
Stage 3.1.2  enrich_cvss_epss_batch.py                       (CVSS / EPSS / KEV)
Stage 3.1.3  kev_feed_marker.py                              (CISA KEV marking)
Stage 3.1.4  intelligence_quality_hardener.py                (quality hardening)
Stage 3.1.7  enterprise_scoring_engine.py                    (apex_score)
...
Stage 3.93.15 intelligence_integrity_gate.py --check         (P0 gate — FAILED)
```

---

## STAGE-BY-STAGE KEV FIELD LIFECYCLE

### Stage 1-3: agent/sentinel_blogger.py — First KEV Assignment (BUG ORIGIN)

For each ingested article, `process_entry()` runs:

```
STEP 7b: CVE enrichment
  cve_ids = extracted_iocs.get("cve", [])     ← ALL CVEs from article text
  _enrich_cve_metadata(cve_ids[0])            ← only primary CVE for EPSS/CVSS/KEV
  → kev_present correctly = False for CVE-2026-3102, CVE-2026-0826

STEP 7c: VANGUARD enhance()
  vanguard_engine.enhance(cve_ids=cve_ids, ...)
    → kev_enricher.lookup(cve_id) for cve_id in cve_ids[:5]   ← BUG
    → CVE-2021-22204 found in KEV → kev_present = True  (for CVE-2026-3102 advisory)
    → CVE-2026-20182 found in KEV → kev_present = True  (for CVE-2026-0826 advisories)

STEP 7d: Confidence floor (enricher.py)
  kev_present=True → confidence floor 70%  (compounded effect of false kev)

Output fields set on advisory:
  kev_present = True   (INCORRECT for CVE-2026-3102 and CVE-2026-0826)
  kev_present = True   (CORRECT for CVE-2026-0257 — legitimately in KEV)
```

Advisory serialized to `data/stix/CDB-APEX-*.json` with `kev_present=True`.

---

### Stage 3.1: enrich_feed_apex.py — apex_ai Injection

Reads `api/feed.json`, injects `apex_ai` blocks. Does **not** modify `kev_present`.
`kev_present=True` values from Stage 1-3 pass through unchanged.

Feed count: **130 items** | KEV in feed at this stage: **34 items** (all from Stage 1-3
enrichment, including 3 falsely contaminated: CVE-2026-0826 ×2, CVE-2026-3102 ×1)

---

### Stage 3.1.1b: CVE ID Backfill

Regex-extracts CVE IDs from item titles and populates `cve_id` field. Does not
modify `kev_present`. Confirms: `CVE-2026-0826`, `CVE-2026-0257`, `CVE-2026-3102`
now have proper `cve_id` values for downstream lookup.

```
[INFO] CVE-BACKFILL [feed.json] backfill cve_id=CVE-2026-0826
[INFO] CVE-BACKFILL [feed.json] backfill cve_id=CVE-2026-0257
[INFO] CVE-BACKFILL [feed.json] backfill cve_id=CVE-2026-3102
```

---

### Stage 3.1.2: CVSS/EPSS Batch Enrichment

Queries NVD for CVE-2026-0826, CVE-2026-0257, CVE-2026-3102.
All three return HTTP 404 (not yet in NVD — PRELIMINARY status applied).

```
[WARNING] HTTP 404 for CVE-2026-0257 → nvd_status=PRELIMINARY
[WARNING] HTTP 404 for CVE-2026-3102 → nvd_status=PRELIMINARY
[WARNING] HTTP 404 for CVE-2026-0826 → nvd_status=PRELIMINARY
```

`kev_present` is NOT touched here.

---

### Stage 3.1.3: kev_feed_marker.py — CISA KEV Marking

Fetches LIVE CISA catalog (1611 entries, version 2026.06.03).
Scans all 130 items for CVE matches.

```
KEV catalog loaded: 1611 entries
[KEV] Marked: CVE-2026-0257 — Rapid7 ... PAN-OS (2026-05-29)
KEV marking complete: 1 newly marked, 0 already KEV, 130 total items
Status=PASS | CatalogSize=1611 | NewlyMarked=1 | TotalKEVInFeed=1
```

**Note the discrepancy**: The marker reports `TotalKEVInFeed=1` because it only
counts items it newly marked. The 34 pre-existing `kev_present=True` items from
Stage 1-3 are already set in `api/feed.json`, but the marker's counter only tracks
its own marks.

After this stage: 35 items have `kev_present=True` in the feed.

---

### Stage 3.1.7: Enterprise Scoring Engine

Reads `feed_manifest.json` (130 items), computes `apex_score`. Reads existing
`kev_present` field but does **not** modify it.

```
SCORING COMPLETE: 130/130 scored | KEV=35 | 0.09s
```

Confirms 35 KEV items in manifest (34 from Stage 1-3 + 1 from Stage 3.1.3).

---

### Stage 3.93 build_apex_v2.py — api/feed.json Assembly

Assembles final `api/feed.json` from STIX bundles + manifest. Adds 30 additional
items from staged bundles. Final feed: **160 items** with **35 kev=True**.

---

### Stage 3.93.15: intelligence_integrity_gate.py — HARD_FAIL

Loads `api/feed.json` (160 items). Loads local KEV catalog
`data/correlation/kev_catalog.json` (version 2026.04.02, 1557 CVEs — **stale**).

Cross-validation:

```
For each item with kev=True:
  cves = {item's CVE IDs from cve_ids field + title regex}
  hit  = cves ∩ catalog_kev

  item: CVE-2026-3102  | kev=True | cves={CVE-2026-3102}  | hit={}          → INFLATED
  item: CVE-2026-0826  | kev=True | cves={CVE-2026-0826}  | hit={}          → INFLATED (×2)
  item: CVE-2026-0257  | kev=True | cves={CVE-2026-0257}  | hit={}          → INFLATED
  (stale catalog predates 2026-05-29 when CVE-2026-0257 was added)
```

Gate D HARD_FAIL — 4 inflation violations.

**Critical detail**: The integrity gate's `_cves()` function correctly uses only
`item.get("cve_ids")` + title regex — it does NOT iterate article content. So the
gate's cross-check is scoped correctly (primary CVE only). The problem is upstream:
the enricher already wrote `kev=True` onto the advisory due to secondary-CVE
contamination.

---

## FEED ITEM COUNTS ACROSS STAGES

| Stage | Feed Size | kev=True Count | Source of kev=True |
|---|---|---|---|
| After Stage 1-3 | 130 | 34 | sentinel_blogger enrichment (34 legitimate + 3 false) |
| After Stage 3.1.3 | 130 | 35 | +1 from live KEV marker (CVE-2026-0257) |
| After Stage 3.93 | 160 | 35 | 30 more items added, 0 new kev=True |
| Gate cross-check | 160 | 35 claimed / 31 verified | 4 inflation violations |

---

## POST-FIX EXPECTED FLOW

After Fix 1 (vanguard_engine.py primary-CVE-only check):
- CVE-2026-3102 advisory: kev=False (primary CVE not in KEV) ✓
- CVE-2026-0826 advisories: kev=False (primary CVE not in KEV) ✓
- CVE-2026-0257: kev=True (primary CVE IS in KEV) ✓

After Fix 2+3 (updated catalog + live-fetch fallback):
- Gate loads catalog version 2026.06.03 (1611 CVEs)
- CVE-2026-0257 is present in catalog ✓
- Zero inflation violations → Gate D PASS
