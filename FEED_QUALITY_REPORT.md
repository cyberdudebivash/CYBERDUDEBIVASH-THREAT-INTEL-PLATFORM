# Feed Quality Report — SENTINEL APEX
**Generated:** 2026-06-05 | **Version:** 1.0.0 | **Validator:** Quality Enforcement Engine v1.0

---

## Executive Summary

The SENTINEL APEX feed quality enforcement pipeline completed its first run against the current `feed.json` (44 items). The overall quality grade is **C (61/100)**. Two critical issues are identified that require immediate root-cause remediation before they can be published to enterprise customers as production-grade intelligence.

---

## Findings

### P0 — IOC Contamination (Critical)

**Severity:** P0  
**Component:** IOC Extraction Pipeline → feed.json `iocs_by_type.domain`  
**Impact:** 33/44 items (75%) contain `store.ts` as a domain IOC  
**Evidence:**
- `ioc_count` reported as 23–26 on CVE stub items with no real IOCs
- `ioc_confidence` reaching 89–100% on items where actual intelligence confidence is 15–30
- Root cause: IOC extraction regex matches filesystem paths from the codebase, pulling `store.ts` as a valid domain IOC

**Affected Items:** 33/44 (75.0%)  
**Contaminants Removed by Validator:** 47 values  
**Contamination Pattern:** Single filename `store.ts` appearing across virtually all items

**Remediation:**
1. Add `INVALID_IOC_EXTENSIONS` blocklist to IOC extraction layer (implemented in `ioc_integrity_validator.js`)
2. Add `INVALID_IOC_FILENAMES` set to reject known internal filenames
3. Add source-domain exclusion list to reject metadata URLs (vulners.com, nvd.nist.gov, etc.)
4. Implement extraction-time validation before writing to `iocs_by_type`
5. Re-run extraction on existing feed to generate clean `feed.json`

**Validation Test:** After fix, run `ioc_integrity_validator.js` — contamination rate must drop to 0%

---

### P1 — ioc_threat_level Inflation (High)

**Severity:** P1  
**Component:** Confidence Scoring → `ioc_threat_level` field  
**Impact:** 29/44 items (65.9%) assigned `CRITICAL` threat level without supporting evidence  
**Evidence:**
- Average confidence_score: 31.4 (LOW band)
- Items with CRITICAL threat level but: no CVSS score, no MITRE tactics, no KEV status
- CVE items with severity=LOW assigned ioc_threat_level=CRITICAL
- Evidence-based scoring for these items: 12–18 (NONE/LOW band)
- Inflation delta: 71–88 points above evidence-based score

**Corrected CRITICAL count (evidence-based):** 0/44 (none qualify with current data)  
**Corrected distribution:** LOW: 38, MEDIUM: 4, HIGH: 2, NONE: 0

**Remediation:**
1. Derive `ioc_threat_level` from `evidence_score` computed by `confidence_validation_engine.js` after IOC cleaning
2. Do NOT assign threat level before cleaning and enrichment are complete
3. CRITICAL requires: `evidence_score ≥ 75` (CVSS ≥ 9.0 + MITRE + KEV or similar)
4. Implement publish gate in `quality_enforcement_engine.js` (implemented)

**Validation Test:** After fix, ioc_threat_level distribution must match evidence_score distribution

---

### P2 — Missing CVSS on CVE Items (Medium)

**Severity:** P2  
**Component:** CVE Enrichment → `cvss_score` field  
**Impact:** 34/34 CVE items (100%) have `cvss_score: null`  
**Evidence:**
- All CVE items show `cvss_score: None` despite having NVD CVE IDs in titles
- EPSS scores also null
- KEV status not enriched

**Remediation:**
1. Invoke NVD API for CVE enrichment at ingestion time
2. Cache CVSS/EPSS/KEV results in item object
3. Block publication of CVE items with missing CVSS until enrichment completes

---

### P3 — Code File Artifacts in ioc_counts (Low)

**Severity:** P3  
**Component:** `ioc_counts` field  
**Impact:** `ioc_counts: {'cve': 0}` on most items regardless of content  
**Evidence:** ioc_counts dictionary does not reflect actual extracted IOC types

**Remediation:** Recompute `ioc_counts` from cleaned `iocs_by_type` after validation

---

## Quality Metrics Summary

| Metric | Value | Status |
|--------|-------|--------|
| Feed Items | 44 | — |
| IOC Contamination Rate | 75.0% | ❌ CRITICAL |
| CRITICAL Level Inflation Rate | 65.9% | ❌ HIGH |
| Missing CVSS (CVE items) | 100% | ⚠ MEDIUM |
| Attribution Degradations | 0 | ✅ OK |
| MITRE Coverage (items with 0 tactics) | 9.1% | ⚠ LOW |
| Overall Quality Score | 61/100 | ⚠ Grade C |

---

## Implemented Remediations (This Sprint)

| File | Purpose |
|------|---------|
| `ioc_integrity_validator.js` | IOC contamination detection and removal |
| `confidence_validation_engine.js` | Evidence-based confidence scoring, inflation detection |
| `attck_precision_validator.js` | ATT&CK tactic/technique ID validation |
| `actor_attribution_validator.js` | Evidence-gated actor attribution |
| `quality_enforcement_engine.js` | Pipeline orchestrator + publish gate |

---

## Deployment Readiness

**Feed publication status:** CONDITIONAL — feed can publish after running quality enforcement pipeline. Items with contaminated IOC data will have `ioc_count` zeroed and `ioc_threat_level` corrected before customer delivery.

**Root cause fix required in:** IOC extraction layer (Python agent pipeline) — not in this sprint's scope but documented and blocked.

---

## Rollback Plan

If quality enforcement introduces regressions:
1. Set `PUBLISH_GATE.MIN_CONFIDENCE_TO_PUBLISH = 0` to allow all items through
2. Set `PUBLISH_GATE.CRITICAL_MIN_EVIDENCE_SCORE = 0` to disable CRITICAL downgrade
3. Both are environment-variable overrideable without code change
4. Original `feed.json` is preserved unchanged; enforcement runs on copy

---

*Generated by SENTINEL APEX Quality Enforcement Engine v1.0.0*
