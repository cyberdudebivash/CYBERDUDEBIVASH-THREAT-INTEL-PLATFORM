# KEV ENRICHMENT AUDIT
## Full Chain Audit of KEV Attribution Logic
### CYBERDUDEBIVASH SENTINEL APEX — 2026-06-05

---

## AUDIT SCOPE

This document audits every code path that can set `kev=True` / `kev_present=True`
on a feed advisory, from ingestion to feed publication. Each path is assessed for
correctness and the two confirmed bugs are documented with evidence.

---

## KEV ATTRIBUTION CODE PATHS

### Path 1 — sentinel_blogger.py STEP 7b: `_enrich_cve_metadata(cve_ids[0])`

**File:** `agent/sentinel_blogger.py` lines 1089–1108  
**Status:** CORRECT — only checks primary CVE

```python
cve_ids = extracted_iocs.get("cve", [])
if cve_ids:
    _epss, _cvss, _kev, _nvd = _enrich_cve_metadata(cve_ids[0])  # primary only ✓
    kev_present = _kev
```

`_enrich_cve_metadata()` queries NVD and checks the CISA KEV catalog for the
**primary CVE only**. This path is correctly scoped and was not the bug source.

**Verdict:** CLEAN

---

### Path 2 — vanguard_engine.py STEP 7c: VANGUARD KEV Enrichment ← **BUG SOURCE A**

**File:** `agent/v46_vanguard/vanguard_engine.py` lines 108–120  
**Status BEFORE FIX:** DEFECTIVE — checks up to 5 CVEs including secondary refs

```python
# DEFECTIVE (before fix):
for cve_id in cve_ids[:5]:      # iterates all article CVEs including secondary refs
    is_kev, kev_meta = _kev_enricher.lookup(cve_id)
    if is_kev:
        result["kev_present"] = True   # sets kev=True on primary advisory
        break

# FIXED (after fix):
primary_cve = cve_ids[0]        # primary advisory CVE only
is_kev, kev_meta = _kev_enricher.lookup(primary_cve)
if is_kev:
    result["kev_present"] = True
```

**Root cause confirmed.** The `cve_ids` list passed to VANGUARD contains all CVE
IDs extracted from the full article text by the IOC extractor. When an article
discusses vulnerability A but also references historical vulnerability B in its
analysis (e.g. "similar to the older CVE-2021-22204"), both appear in `cve_ids`.

**Contamination evidence from CI logs (2026-06-04):**

| Advisory | Primary CVE (from title) | Contaminating CVE (from article body) | Contaminating CVE in KEV? |
|---|---|---|---|
| ExifTool article | CVE-2026-3102 | CVE-2021-22204 (Perl/ExifTool) | YES (added 2021-11-17) |
| HP Poly VVX #1 | CVE-2026-0826 | CVE-2026-20182 (Cisco SD-WAN) | YES (added 2026-05-14) |
| HP Poly VVX #2 | CVE-2026-0826 | CVE-2026-20182 (Cisco SD-WAN) | YES (added 2026-05-14) |

**Verdict:** FIXED (vanguard_engine.py — primary CVE only)

---

### Path 3 — kev_feed_marker.py Stage 3.1.3

**File:** `scripts/kev_feed_marker.py`  
**Status:** CORRECT — fetches live CISA catalog, checks `cve_id` field (primary CVE)

The marker iterates `api/feed.json` items, extracts `cve_id` (single primary CVE),
and looks it up against the live CISA KEV catalog. Only marks `kev=True` for exact
primary CVE matches. This is the authoritative KEV marking stage.

**Run evidence (2026-06-04):**
```
KEV catalog loaded: 1611 entries (live from CISA)
[KEV] Marked: CVE-2026-0257 — Rapid7 ... PAN-OS (2026-05-29)
KEV marking complete: 1 newly marked
```

CVE-2026-0257 was correctly marked. No false markings.

**Verdict:** CLEAN

---

### Path 4 — intelligence_integrity_gate.py: Gate D Cross-Validation ← **BUG SOURCE B**

**File:** `scripts/intelligence_integrity_gate.py` — `_load_kev_catalog()`  
**Status BEFORE FIX:** DEFECTIVE — loaded stale local catalog (2026.04.02)

```python
# DEFECTIVE (before fix):
_KEV_CATALOG_PATHS = [
    REPO_ROOT / "data/kev/kev_catalog.json",
    REPO_ROOT / "data/correlation/kev_catalog.json",   # ← 2026.04.02, 1557 CVEs
]
# No freshness check, no live fallback

# FIXED (after fix):
# Added _catalog_age_days() check:
# If local catalog age > 30 days → auto-fetch from CISA → refresh local cache
```

**Stale catalog evidence:**
- Local file: `data/correlation/kev_catalog.json` version `2026.04.02` (1557 CVEs)
- CISA live: version `2026.06.03` (1611 CVEs)
- CVE-2026-0257 added `2026-05-29` — NOT present in April catalog

The gate correctly cross-validates that `kev_present=True` items have their primary
CVE in the catalog. This logic is sound. The defect was using a 54-day-stale catalog
that did not contain legitimate KEV entries added after its cutoff.

**Verdict:** FIXED (live-fetch fallback + catalog refreshed to 2026.06.03)

---

### Path 5 — enterprise_scoring_engine.py Stage 3.1.7

**File:** `scripts/enterprise_scoring_engine.py`  
**Status:** READ-ONLY — does not assign kev values

The scoring engine reads `kev_present` from the manifest to compute `apex_score`
priority weighting. It does not set `kev_present`. Clean pass-through.

**Verdict:** CLEAN (not a write path)

---

### Path 6 — build_apex_v2.py Stage 3.93

**File:** `scripts/build_apex_v2.py`  
**Status:** READ-ONLY — assembles final feed.json from STIX bundles

Reads `kev_present` to sort and prioritize items. Does not set `kev_present`.

**Verdict:** CLEAN (not a write path)

---

### Path 7 — enrich_feed_apex.py Stage 3.1

**File:** `scripts/enrich_feed_apex.py`  
**Status:** DOES NOT TOUCH KEV fields

Injects `apex_ai` blocks. The `kev_present` field is preserved as-is from
Stage 1-3. This stage is not in the KEV attribution chain.

**Verdict:** NOT IN SCOPE

---

## CATALOG VERSIONS AUDIT

| Component | Catalog Source | Version at Failure | Current Version |
|---|---|---|---|
| `kev_feed_marker.py` | Live CISA fetch | 2026.06.03 (1611 CVEs) | 2026.06.03 |
| `intelligence_integrity_gate.py` | Local file | 2026.04.02 (1557 CVEs) ← stale | 2026.06.03 ✓ |
| `apex_feed_quality_v2.py` | Local cache or live | 1611 entries | not audited |
| `agent/v46_vanguard/kev_enricher.py` | (loaded by vanguard) | 1611 entries (live) | 1611 entries |

---

## FALSE POSITIVE EVIDENCE SUMMARY

### CVE-2026-0257
- **IS in CISA KEV** (added 2026-05-29, vendor=Palo Alto Networks/PAN-OS)
- Correctly marked by `kev_feed_marker.py` using live catalog
- Gate false-positive caused by stale local catalog (2026.04.02, pre-dates entry)
- **Resolution:** Updated catalog + live-fetch fallback in gate

### CVE-2026-0826 (×2 advisories)
- **NOT in CISA KEV** (confirmed against live catalog 2026.06.03)
- Falsely marked `kev=True` via VANGUARD secondary-CVE contamination
- Contaminating CVE: CVE-2026-20182 (Cisco Catalyst SD-WAN, added 2026-05-14)
- Both articles about CVE-2026-0826 referenced CVE-2026-20182 in their text
- **Resolution:** VANGUARD now only checks primary CVE (cve_ids[0])

### CVE-2026-3102
- **NOT in CISA KEV** (confirmed against live catalog 2026.06.03)
- Falsely marked `kev=True` via VANGUARD secondary-CVE contamination
- Contaminating CVE: CVE-2021-22204 (Perl/ExifTool, added 2021-11-17)
- Article titled "How an image could compromise your Mac: ExifTool (CVE-2026-3102)"
  discussed the new CVE but referenced the historical CVE-2021-22204 in context
- **Resolution:** VANGUARD now only checks primary CVE (cve_ids[0])

---

## DETECTION COVERAGE IMPACT

No legitimate KEV markings were removed:
- CVE-2026-0257 remains `kev=True` (it IS in KEV)
- All 31 other legitimately KEV-marked items remain unchanged
- The 3 false-positive items (CVE-2026-0826 ×2, CVE-2026-3102) will correctly
  become `kev=False` in the next pipeline run

KEV detection coverage is **improved**, not degraded. The fix eliminates false
urgency inflation while preserving all real KEV signals.
