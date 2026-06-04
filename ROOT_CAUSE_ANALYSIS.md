# ROOT CAUSE ANALYSIS
## SENTINEL APEX Intelligence Integrity Gate — KEV Health Gate HARD_FAIL
### Forensic Investigation Report — 2026-06-05

---

## EXECUTIVE SUMMARY

The SENTINEL APEX Intelligence Integrity Gate (Stage 3.93.15, v160.0) issued a
`HARD_FAIL` for Gate D (KEV Health Gate) with the following evidence:

```
KEV INFLATION HARD_FAIL: 4 item(s) flagged KEV-true with no CISA KEV match
(fabricated urgency): ['CVE-2026-0826', 'CVE-2026-0826', 'CVE-2026-0257', 'CVE-2026-3102']
```

**Two distinct root causes were identified and confirmed with code evidence.**
Both have been permanently fixed. No governance controls were removed or weakened.

---

## ROOT CAUSE A — Cross-CVE KEV Contamination in VANGUARD Engine

### Severity: P0 CRITICAL
### Classification: Logic Bug — Incorrect Scope of KEV Attribution
### Affects: CVE-2026-0826 (×2 advisories), CVE-2026-3102 (1 advisory)

### File
```
agent/v46_vanguard/vanguard_engine.py
```

### Vulnerable Code (lines 108–120 before fix)
```python
# -- 2. KEV Enrichment --
if _kev_enricher and cve_ids:
    try:
        for cve_id in cve_ids[:5]:  # Limit to first 5 CVEs   ← BUG
            is_kev, kev_meta = _kev_enricher.lookup(cve_id)
            if is_kev:
                result["kev_present"] = True
                ...
                break  # One KEV hit is sufficient to flag
```

### How `cve_ids` Is Populated
In `agent/sentinel_blogger.py` line 1089:
```python
cve_ids = extracted_iocs.get("cve", [])
```

`extracted_iocs["cve"]` contains **all CVE IDs extracted from the full article
text** — not just the primary CVE assigned to the advisory. When an intelligence
article about vulnerability X also references historical CVE Y in its content,
both X and Y appear in `cve_ids`.

### Contamination Mechanism

| Advisory | Primary CVE | Secondary CVE (found in article) | KEV Status of Secondary |
|---|---|---|---|
| ExifTool article | CVE-2026-3102 (NOT in KEV) | CVE-2021-22204 (Perl/ExifTool, added 2021-11-17) | **IN KEV** |
| HP Poly VVX article #1 | CVE-2026-0826 (NOT in KEV) | CVE-2026-20182 (Cisco Catalyst SD-WAN, added 2026-05-14) | **IN KEV** |
| HP Poly VVX article #2 | CVE-2026-0826 (NOT in KEV) | CVE-2026-20182 (Cisco Catalyst SD-WAN, added 2026-05-14) | **IN KEV** |

The VANGUARD loop iterates `cve_ids[:5]`. When it encounters a secondary CVE
that IS in KEV, it immediately sets `kev_present=True` on the advisory and
breaks. The advisory's primary CVE is thus falsely marked as KEV-confirmed.

### Log Evidence
```
[CDB-ENRICHER]   -> CVE enrichment: EPSS=0.21 CVSS=None KEV=False   ← primary CVE correctly NOT in KEV
[CDB-ENRICHER] ? KEV CONFIRMED: CVE-2026-20182 - Cisco/Catalyst SD-WAN (added: 2026-05-14)
[CDB-ENRICHER] VANGUARD KEV: CVE-2026-20182 CONFIRMED in CISA KEV catalog   ← secondary CVE contaminates
[CDB-ENRICHER] [v134.0] KEV floor applied: 50.0% -> 70.0%
[CDB-ENRICHER]   [HARD-GATE] PASS — words=4118 iocs=7 conf=70.0 cve=True kev=True   ← FALSE kev=True
[CDB-ENRICHER]   [RISK-REASON] KEV confirmed (CISA active exploitation)             ← fabricated urgency
```

---

## ROOT CAUSE B — Stale Bundled KEV Catalog in Intelligence Integrity Gate

### Severity: P0 HIGH
### Classification: Catalog Version Skew — Gate vs. Marker using different catalog versions
### Affects: CVE-2026-0257 (1 advisory)

### File
```
scripts/intelligence_integrity_gate.py
data/correlation/kev_catalog.json
```

### Mechanism

| Component | Catalog Source | Version | CVE Count | CVE-2026-0257 present? |
|---|---|---|---|---|
| `kev_feed_marker.py` (Stage 3.1.3) | Live CISA fetch | 2026.06.03 | 1611 | YES (added 2026-05-29) |
| `intelligence_integrity_gate.py` (Stage 3.93.15) | Bundled local file | 2026.04.02 | 1557 | NO (predates entry) |

CVE-2026-0257 (Palo Alto Networks PAN-OS, GlobalProtect Auth Bypass) was added to
the CISA KEV catalog on **2026-05-29**. The `kev_feed_marker.py` correctly fetches
the live catalog and marks this advisory `kev=True`. The integrity gate loads a
local bundled catalog last updated **2026-04-02** — 54 days stale — which does not
contain this entry. The gate then cross-validates and raises a false INFLATION
alert because it believes the feed is claiming KEV for a CVE not in "its" catalog.

### Log Evidence
```
18:22:01 [kev-marker] INFO: KEV catalog loaded: 1611 entries
18:22:01 [kev-marker] INFO: [KEV] Marked: CVE-2026-0257 — Rapid7 ... (2026-05-29)  ← CORRECT
18:22:01 [kev-marker] INFO: KEV marking complete: 1 newly marked

...later at Stage 3.93.15...

[intelligence_integrity_gate] INFO:   [D] KEV catalog: 2026.04.02 (1557 CVEs)      ← STALE
[intelligence_integrity_gate] ERROR:  [D] KEV INFLATION HARD_FAIL: 4 item(s)...    ← FALSE POSITIVE
```

---

## OTHER GATES: CONFIRMED PASSING

All other integrity gates passed correctly:

| Gate | Result | Notes |
|---|---|---|
| A — Synthetic CVE Detector | PASS | No sequential CVE flood patterns |
| B — Entropy Gate | PASS | Title entropy 7.297 bits, actor diversity 0.918 bits |
| C — Feed Diversity Validator | PASS | 19 domains, 2 actors |
| E — Runtime Integrity Baseline | PASS | |
| F — Advisory Authenticity Scoring | PASS | avg 47.6/100 |
| G — Manifest Mutation Validator | PASS | 160 unique IDs, no duplicates |
| H — Synthetic Flood Circuit Breaker | PASS | 0/160 synthetic ratio |

The HARD_FAIL was **exclusively caused by the two bugs identified above**, not by any
genuine intelligence quality problem.

---

## WHAT DID NOT CAUSE THE FAILURE

These were explicitly ruled out during the investigation:

- ❌ Scoring engine bug — the scoring engine reads existing `kev` fields; it does not set them
- ❌ Feed merge logic — feed.json and manifest are correctly assembled
- ❌ Cache corruption — no NUL bytes or JSON corruption found in feed.json
- ❌ Schema mapping bug — `kev` / `kev_present` / `kev_confirmed` fields are correctly mapped
- ❌ Serialization bug — no encoding or deserialization errors observed
- ❌ AI enrichment logic — APEX AI (`enrich_feed_apex.py`) does not touch KEV fields
- ❌ Genuine KEV inflation — CVE-2026-0826 and CVE-2026-3102 are genuinely NOT in CISA KEV

---

## PERMANENT FIXES APPLIED

### Fix 1 — vanguard_engine.py: Primary-CVE-Only KEV Attribution

Changed `for cve_id in cve_ids[:5]` to **check only `cve_ids[0]`** (the primary
advisory CVE). Secondary/referenced CVEs in the article must never trigger KEV
attribution on the advisory. The confidence floor already correctly uses `cve_ids[0]`
via `_enrich_cve_metadata(cve_ids[0])` in `sentinel_blogger.py` — the VANGUARD engine
was the only path that diverged.

### Fix 2 — intelligence_integrity_gate.py: Live-Fetch Fallback for Stale Catalog

Added `_catalog_age_days()` and `_fetch_live_kev_catalog()` helpers. If the local
catalog is older than `_KEV_CATALOG_MAX_AGE_DAYS = 30` days, the gate automatically
fetches the current catalog from CISA, caches it locally, and uses it for cross-
validation. This permanently prevents gate/marker version skew.

### Fix 3 — data/correlation/kev_catalog.json: Immediate Catalog Refresh

Updated the bundled catalog from `2026.04.02` (1557 CVEs) to `2026.06.03` (1611 CVEs)
so the current run passes without waiting for the live-fetch path to trigger.

---

## VERIFICATION

Post-fix simulation results:

| Advisory | kev=True before fix | kev=True after fix | Correct? |
|---|---|---|---|
| CVE-2026-0826 (advisory 1) | YES (contaminated) | NO | ✓ |
| CVE-2026-0826 (advisory 2) | YES (contaminated) | NO | ✓ |
| CVE-2026-0257 | YES (legitimate) | YES (legitimate) | ✓ |
| CVE-2026-3102 | YES (contaminated) | NO | ✓ |

Gate D (KEV Health Gate) inflation violations after fix: **0** → **PASS**

---

## NO GOVERNANCE REGRESSION

- All 8 integrity gates remain active and fully enforced
- KEV inflation detection threshold unchanged
- KEV enrichment gap detection unchanged
- No bypass switches introduced
- No gate thresholds relaxed
- KEV correctness enforcement is now more accurate, not less strict
