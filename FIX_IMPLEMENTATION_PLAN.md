# FIX IMPLEMENTATION PLAN
## SENTINEL APEX KEV Integrity Gate — Permanent Fix
### CYBERDUDEBIVASH SENTINEL APEX — 2026-06-05

---

## SUMMARY OF CHANGES

Three targeted changes were made. No governance controls were weakened.
No thresholds were relaxed. No bypass mechanisms were introduced.

---

## FIX 1 — vanguard_engine.py: Primary-CVE-Only KEV Attribution

**File:** `agent/v46_vanguard/vanguard_engine.py`  
**Lines changed:** 108–120 (KEV Enrichment block)  
**Risk:** Minimal — reduces false-positive KEV attributions, does not affect real ones

### Change

```python
# BEFORE (defective):
if _kev_enricher and cve_ids:
    try:
        for cve_id in cve_ids[:5]:  # Limit to first 5 CVEs
            is_kev, kev_meta = _kev_enricher.lookup(cve_id)
            if is_kev:
                result["kev_present"] = True
                result["kev_metadata"] = kev_meta
                result["enhancements_applied"].append("kev_enrichment")
                logger.info(f"VANGUARD KEV: {cve_id} CONFIRMED in CISA KEV catalog")
                break  # One KEV hit is sufficient to flag
    except Exception as e:
        logger.warning(f"VANGUARD KEV enrichment failed (non-critical): {e}")

# AFTER (fixed):
# P0-FIX v175.0: KEV attribution MUST be scoped to the PRIMARY advisory CVE only.
# cve_ids contains ALL CVEs extracted from article text (primary + any referenced CVEs).
# Iterating beyond cve_ids[0] causes cross-CVE contamination...
if _kev_enricher and cve_ids:
    try:
        primary_cve = cve_ids[0]  # Primary advisory CVE only — never check secondary refs
        is_kev, kev_meta = _kev_enricher.lookup(primary_cve)
        if is_kev:
            result["kev_present"] = True
            result["kev_metadata"] = kev_meta
            result["enhancements_applied"].append("kev_enrichment")
            logger.info(f"? KEV CONFIRMED: {primary_cve} CONFIRMED in CISA KEV catalog")
    except Exception as e:
        logger.warning(f"VANGUARD KEV enrichment failed (non-critical): {e}")
```

### Rationale
KEV is an advisory-level attribute. An advisory's KEV status must reflect
whether **its assigned primary CVE** is in the CISA Known Exploited
Vulnerabilities catalog. Secondary CVEs appearing in article text are
contextual references — they may be related vulnerabilities mentioned for
comparison, historical context, or technical background, but they do not
confer KEV urgency on the advisory under analysis.

### Impact Analysis
- Articles that reference older KEV-listed CVEs for context will no longer
  inherit false KEV status
- Advisories whose primary CVE IS in KEV are unaffected (they pass the primary-
  only check just as before)
- No effect on EPSS, CVSS, or confidence scoring logic
- `_enrich_cve_metadata(cve_ids[0])` in sentinel_blogger.py already uses only
  the primary CVE — this fix makes VANGUARD consistent with that behavior

---

## FIX 2 — intelligence_integrity_gate.py: Live-Fetch Fallback for Stale Catalog

**File:** `scripts/intelligence_integrity_gate.py`  
**Lines changed:** `_KEV_CATALOG_PATHS` block and `_load_kev_catalog()` function  
**Risk:** Minimal — new code path only triggers on stale catalog; existing path preserved

### New constants added
```python
_KEV_LIVE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CATALOG_MAX_AGE_DAYS = 30   # If local catalog is older than this, fetch live
```

### New helpers added
```python
def _catalog_age_days(data: dict) -> float:
    """Return age of catalog in days from catalogVersion or fetched_at field."""
    # Parses YYYY.MM.DD version strings and ISO-8601 timestamps

def _fetch_live_kev_catalog() -> Tuple[Optional[set], str]:
    """Fetch CISA KEV catalog live, refresh local cache, return (ids, version)."""
    # Fetches from _KEV_LIVE_URL, writes result to first writable catalog path
```

### Modified function: `_load_kev_catalog()`
```python
def _load_kev_catalog() -> Tuple[Optional[set], str]:
    # 1. Try local catalog
    # 2. If found but age > 30 days → fetch live, update cache, use live result
    # 3. If not found → fetch live
    # 4. If live fetch fails and local exists (even stale) → use local as fallback
```

### Rationale
The `kev_feed_marker.py` always fetches the live CISA catalog. The integrity
gate must cross-validate against the same (or newer) catalog version to avoid
false INFLATION alerts. The 30-day threshold is conservative — CISA typically
adds new KEV entries weekly. A 30-day-stale catalog will miss at most one month
of KEV additions.

### Network access note
The live fetch uses a 15-second timeout with graceful fallback. If the CISA
endpoint is unreachable (CI runner network restriction), the gate falls back to
the local catalog and logs a warning. This preserves robustness — a network
failure does not block the integrity gate.

---

## FIX 3 — data/correlation/kev_catalog.json: Catalog Refresh

**File:** `data/correlation/kev_catalog.json`  
**Change:** Updated from version `2026.04.02` (1557 CVEs) to `2026.06.03` (1611 CVEs)

This ensures the current CI run passes without waiting for Fix 2's live-fetch
logic to activate. Fix 2 ensures all future runs automatically self-refresh.

```
Before: catalogVersion=2026.04.02, 1557 CVEs
After:  catalogVersion=2026.06.03, 1611 CVEs, fetched_at=2026-06-05T...Z
```

**Key CVEs now present in catalog:**
- CVE-2026-0257 (Palo Alto Networks PAN-OS, added 2026-05-29) ✓
- CVE-2026-20182 (Cisco Catalyst SD-WAN, added 2026-05-14) ✓

---

## FILES MODIFIED

| File | Type | Change |
|---|---|---|
| `agent/v46_vanguard/vanguard_engine.py` | Code | KEV check scoped to primary CVE only |
| `scripts/intelligence_integrity_gate.py` | Code | Live-fetch fallback + staleness check |
| `data/correlation/kev_catalog.json` | Data | Updated to 2026.06.03 (1611 CVEs) |

---

## DEPLOYMENT STRATEGY

These changes are safe to deploy immediately:

1. **Backward compatible** — no API or schema changes
2. **Idempotent** — can re-run any pipeline stage without side effects
3. **Non-breaking** — all three changes have fallback paths; no hard failures introduced
4. **Governance-preserving** — all 8 integrity gate checks remain active
5. **CI/CD safe** — no workflow YAML changes required; `.py` and `.json` only

### Recommended deployment sequence
```
git add agent/v46_vanguard/vanguard_engine.py
git add scripts/intelligence_integrity_gate.py
git add data/correlation/kev_catalog.json
git commit -m "fix(kev): P0 KEV inflation — primary-CVE scope + stale catalog live-fetch [v175.0]"
git push origin main
```

Then re-run the `sentinel-blogger` workflow. Gate D should pass.

---

## ROLLBACK PLAN

If regression is observed:

1. **vanguard_engine.py**: Revert to `cve_ids[:5]` loop. This restores the old
   behavior (including the false-positive KEV contamination) but is safe as a
   temporary rollback while root cause is re-investigated.

2. **intelligence_integrity_gate.py**: Remove the `_catalog_age_days` check and
   `_fetch_live_kev_catalog` call; revert `_load_kev_catalog()` to the simple
   local-file-only version.

3. **kev_catalog.json**: Restore from git history (`git checkout HEAD~1 -- data/correlation/kev_catalog.json`).

None of the rollbacks would re-introduce the HARD_FAIL immediately — the gate
would go back to using the stale catalog, which would still fail for CVE-2026-0257
until the contamination fix (fix 1) is also reverted. Rollback both simultaneously
if needed.

---

## LONG-TERM RECOMMENDATIONS

1. **Add a workflow step to refresh `data/correlation/kev_catalog.json` before the
   integrity gate runs.** This makes the catalog refresh explicit and visible in
   CI logs, rather than relying on the in-gate live-fetch logic.

2. **Normalize the `cve_ids` list at ingestion time** to separate `primary_cve`
   (the advisory's assigned CVE) from `referenced_cves` (CVEs mentioned in the
   article text). This would prevent the contamination class of bugs from
   recurring across any future logic that iterates `cve_ids`.

3. **Add a unit test** that verifies: given an advisory whose primary CVE is NOT
   in KEV but whose article references a KEV-listed CVE, `kev_present` is `False`.
   See REGRESSION_TEST_PLAN.md for the full test specification.
