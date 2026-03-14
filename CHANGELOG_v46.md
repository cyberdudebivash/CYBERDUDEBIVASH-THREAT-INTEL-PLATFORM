# CHANGELOG v46.0 — VANGUARD

**Release:** SENTINEL APEX v46.0 "VANGUARD"
**Date:** 2026-03-14
**Codename:** VANGUARD — Zero-False-Positive Intelligence Enhancement Suite
**Architecture:** 100% Additive. Zero regression. Zero breaking changes.

---

## CRITICAL FIXES

### 1. IOC FALSE POSITIVE: Source Code Filenames as Domains
**Impact:** HIGH — Live production reports contained FP domain IOCs
**Root Cause:** `enricher.py` domain regex matched `filename.ext` patterns like
`stealer.py`, `hvnc.py`, `utils.cpp`. The `FALSE_POSITIVE_EXTENSIONS` list in
`config.py` only covered Java/Android extensions (.jar, .dex, .apk).
**Fix:** Extended `FALSE_POSITIVE_EXTENSIONS` with 50+ source code, config, and
data file extensions (.py, .cpp, .c, .go, .rs, .ts, .java, .yaml, etc.).
Additionally, the new `ioc_validator.py` module provides a second validation
layer that catches any pattern the enricher's FP list might miss.
**Files Changed:** `agent/config.py` (additive extension list)
**Files Added:** `agent/v46_vanguard/ioc_validator.py`

### 2. IOC FALSE POSITIVE: Hash Substring Deconfliction
**Impact:** MEDIUM — SHA1/MD5 counts inflated by SHA256 substrings
**Root Cause:** SHA1 regex `[a-fA-F0-9]{40}` matches characters 0-39 of any
SHA256 hash. MD5 regex `[a-fA-F0-9]{32}` matches substrings of both.
**Fix:** New `ioc_validator.py` performs hash deconfliction: any SHA1 value
that is a substring of a known SHA256 is removed, same for MD5 vs SHA256/SHA1.
**Files Added:** `agent/v46_vanguard/ioc_validator.py`

### 3. KEV Lookup Never Executed
**Impact:** HIGH — `kev_present` was always `False` in every report
**Root Cause:** `_enrich_cve_metadata()` in `sentinel_blogger.py` declared
`kev_present = False` but never queried the CISA KEV feed.
**Fix:** New `kev_enricher.py` module loads the full CISA KEV catalog,
caches it in-memory (6h TTL), and performs live lookup per CVE ID.
Integrated via `vanguard_engine.py` in pipeline Step 7c.
**Files Added:** `agent/v46_vanguard/kev_enricher.py`

### 4. EPSS Dead Code Branch
**Impact:** LOW — Unreachable scoring tiers in `risk_engine.py`
**Root Cause:** `elif epss_score >= 0.90` appeared after `elif epss_score >= 0.10`,
making it unreachable. Same for `elif epss_score >= 0.50`.
**Fix:** Removed dead branches, added `elif epss_score >= 0.01` for low-EPSS tier.
**Files Changed:** `agent/risk_engine.py`

### 5. Confidence Score Inflation
**Impact:** MEDIUM — Mid-quality intel rated as "HIGH" confidence
**Root Cause:** Additive bonuses (MITRE depth + actor + records + keywords)
stacked linearly, pushing scores to 100% before `min()` clamp.
**Fix:** New `confidence_engine.py` uses weighted-average across 6 independent
dimensions (IOC richness, source depth, MITRE coverage, actor attribution,
impact evidence, CVE verification). Naturally bounded, no artificial clamping.
**Files Added:** `agent/v46_vanguard/confidence_engine.py`

### 6. Pre-Existing Test Fixes
**Impact:** Test suite reliability
- `test_deduplication.py`: Fixed test that expected `is_duplicate()` to
  auto-register entries (API requires separate `mark_processed()` call)
- `test_risk_engine.py`: Fixed 4 tests hitting 10.0 ceiling before signal
  measurement by using minimal IOC fixtures for signal isolation tests

---

## NEW MODULES

| Module | Path | Lines | Purpose |
|--------|------|-------|---------|
| `ioc_validator.py` | `agent/v46_vanguard/` | 195 | Multi-layer IOC FP elimination |
| `kev_enricher.py` | `agent/v46_vanguard/` | 120 | CISA KEV live catalog lookup |
| `confidence_engine.py` | `agent/v46_vanguard/` | 245 | Bayesian confidence scoring |
| `vanguard_engine.py` | `agent/v46_vanguard/` | 140 | Pipeline orchestrator |

## MODIFIED FILES (Surgical Patches Only)

| File | Change Type | Description |
|------|-------------|-------------|
| `agent/config.py` | Extension | +50 FP extensions added to list |
| `agent/risk_engine.py` | Bugfix | EPSS dead branch removed |
| `agent/sentinel_blogger.py` | Integration | v46 import + Step 7c call |
| `VERSION` | Bump | 45.0.0 → 46.0.0 |
| `tests/test_deduplication.py` | Fix | Corrected API usage in test |
| `tests/test_risk_engine.py` | Fix | Ceiling-proof signal isolation |

## REGRESSION GUARANTEE

- All 304 previously-passing tests continue to pass
- All existing module interfaces unchanged
- All existing report paths unmodified
- v46 modules wrapped in try/except — pipeline degrades to v45 on any failure
- No existing import paths changed
- No existing function signatures modified
