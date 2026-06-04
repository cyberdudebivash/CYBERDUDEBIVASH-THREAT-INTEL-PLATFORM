# REGRESSION TEST PLAN
## KEV Attribution Integrity — SENTINEL APEX v175.0
### CYBERDUDEBIVASH SENTINEL APEX — 2026-06-05

---

## OBJECTIVES

1. Prove that CVE-2026-0826 (×2) and CVE-2026-3102 advisories will NOT get
   `kev=True` when their articles reference a KEV-listed secondary CVE
2. Prove that CVE-2026-0257 and all legitimate KEV-listed primary CVEs continue
   to get `kev=True`
3. Prove the integrity gate passes with zero inflation violations
4. Prove no reduction in KEV detection coverage
5. Prove no governance regression across all 8 integrity gates

---

## TEST SUITE 1 — VANGUARD ENGINE: Cross-CVE Contamination Prevention

### Test 1.1 — Primary CVE not in KEV, secondary CVE in KEV → kev=False

```python
# Setup: Simulate the exact contamination scenario
kev_catalog = {"CVE-2021-22204", "CVE-2026-20182"}   # secondary CVEs that ARE in KEV
primary_not_in_kev = ["CVE-2026-3102", "CVE-2021-22204"]  # article cve_ids list

# Execute: Call vanguard_engine.enhance()
result = vanguard_engine.enhance(
    iocs={},
    cve_ids=primary_not_in_kev,  # CVE-2026-3102 primary, CVE-2021-22204 referenced
    kev_present=False,
)

# Assert
assert result["kev_present"] == False, (
    "Cross-CVE contamination: kev=True set because secondary CVE is in KEV"
)
assert "kev_enrichment" not in result["enhancements_applied"]
```

### Test 1.2 — Primary CVE in KEV → kev=True (regression check)

```python
# Setup: Primary CVE is legitimately in KEV
kev_catalog = {"CVE-2026-0257"}
cve_ids = ["CVE-2026-0257"]  # primary CVE IS in KEV

result = vanguard_engine.enhance(iocs={}, cve_ids=cve_ids, kev_present=False)

assert result["kev_present"] == True, "Legitimate KEV CVE must still be marked kev=True"
assert "kev_enrichment" in result["enhancements_applied"]
```

### Test 1.3 — No CVEs in article → kev unchanged

```python
result = vanguard_engine.enhance(iocs={}, cve_ids=[], kev_present=False)
assert result["kev_present"] == False

# Pre-existing kev=True must be preserved
result = vanguard_engine.enhance(iocs={}, cve_ids=[], kev_present=True)
assert result["kev_present"] == True
```

### Test 1.4 — Single CVE article, CVE in KEV → kev=True

```python
# No secondary CVEs; primary CVE is in KEV
result = vanguard_engine.enhance(iocs={}, cve_ids=["CVE-2026-20182"], kev_present=False)
assert result["kev_present"] == True
```

---

## TEST SUITE 2 — INTEGRITY GATE: Catalog Freshness

### Test 2.1 — Stale catalog triggers live fetch

```python
import json
from pathlib import Path
from datetime import datetime, timezone

# Write a fake catalog with old date
stale_catalog = {
    "catalogVersion": "2024.01.01",
    "vulnerabilities": [{"cveID": "CVE-2024-0001"}]
}
with open("data/correlation/kev_catalog.json", "w") as f:
    json.dump(stale_catalog, f)

# Load catalog via gate's function
ids, ver = _load_kev_catalog()

# Assert: live catalog was fetched (version should be current)
assert ver != "2024.01.01", "Stale catalog should trigger live fetch"
assert len(ids) > 1000, "Live catalog should have >1000 CVEs"
```

### Test 2.2 — Fresh catalog uses local file (no network call)

```python
# Write a fake catalog with today's date
from datetime import datetime, timezone
fresh_catalog = {
    "catalogVersion": datetime.now(timezone.utc).strftime("%Y.%m.%d"),
    "fetched_at": datetime.now(timezone.utc).isoformat(),
    "vulnerabilities": [{"cveID": "CVE-2026-0257"}, {"cveID": "CVE-2021-22204"}]
}
with open("data/correlation/kev_catalog.json", "w") as f:
    json.dump(fresh_catalog, f)

ids, ver = _load_kev_catalog()

assert "CVE-2026-0257" in ids, "Fresh local catalog must be used"
```

### Test 2.3 — Network failure falls back to local catalog

```python
# Mock urllib to raise an exception
# Verify that _load_kev_catalog() still returns the local catalog as fallback
# Expected: warning log + local catalog ids returned
```

---

## TEST SUITE 3 — GATE D: KEV Health Gate End-to-End

### Test 3.1 — Zero inflation violations for the 4 failing CVEs (post-fix)

```python
# Construct minimal feed items representing the 4 previously failing cases
items = [
    {"id": "a1", "cve_ids": ["CVE-2026-0826"], "kev": False},    # no longer kev=True
    {"id": "a2", "cve_ids": ["CVE-2026-0826"], "kev": False},    # no longer kev=True
    {"id": "a3", "cve_ids": ["CVE-2026-0257"], "kev": True},     # legitimately kev=True
    {"id": "a4", "cve_ids": ["CVE-2026-3102"], "kev": False},    # no longer kev=True
]

gate = KEVHealthGate()
hard_fail, findings = gate.check(items)

assert hard_fail == False, f"Gate D should PASS after fix. Findings: {findings}"
assert not any("INFLATION" in f for f in findings)
```

### Test 3.2 — Genuine inflation still detected (gate not weakened)

```python
# An advisory with a fabricated KEV=true for a CVE that truly is not in KEV
items = [
    {"id": "x1", "cve_ids": ["CVE-9999-99999"], "kev": True},  # fake CVE, not in KEV
]

gate = KEVHealthGate()
hard_fail, findings = gate.check(items)

assert hard_fail == True, "Real inflation must still HARD_FAIL"
assert any("INFLATION" in f for f in findings)
```

### Test 3.3 — Missed KEV entry still detected (gate not weakened)

```python
# Advisory whose primary CVE IS in KEV but kev=False (enrichment missed it)
items = [
    {"id": "x1", "cve_ids": ["CVE-2026-0257"], "kev": False},  # in KEV, but not marked
]

gate = KEVHealthGate()
hard_fail, findings = gate.check(items)

assert hard_fail == True, "Missed KEV entry must still HARD_FAIL"
assert any("GAP" in f or "missed" in f.lower() for f in findings)
```

---

## TEST SUITE 4 — FULL PIPELINE INTEGRATION

### Test 4.1 — sentinel-blogger workflow: Gate D PASS

**Manual validation steps:**

1. Push fixes to `main`
2. Trigger `sentinel-blogger` workflow manually
3. Confirm Stage 3.93.15 exits with PASS not HARD_FAIL
4. Confirm `data/quality/integrity_gate_report.json` shows:
   ```json
   {
     "gate_d_result": "PASS",
     "inflated": [],
     "missed": [],
     "catalog_version": "2026.06.03"
   }
   ```

### Test 4.2 — KEV detection coverage not reduced

After the fix run:
- Count `kev=True` items in `api/feed.json`
- Must be ≥ 32 (31 legitimate pre-existing + CVE-2026-0257 = 32 minimum)
- The 3 false-positive items (CVE-2026-0826 ×2, CVE-2026-3102) should now be
  `kev=False`, reducing the count from 35 to 32

### Test 4.3 — All 8 integrity gates pass

Confirm in CI logs that all gates A through H show PASS.

---

## TEST SUITE 5 — GOVERNANCE NON-REGRESSION

### Test 5.1 — Synthetic CVE detector unchanged

No changes to Gate A logic. Verify PASS in logs.

### Test 5.2 — Entropy gate unchanged

No changes to Gate B. Verify PASS.

### Test 5.3 — Feed diversity unchanged

No changes to Gate C. Verify PASS.

### Test 5.4 — Authenticity scoring unchanged

No changes to Gate F. Verify PASS with avg score unchanged.

### Test 5.5 — Manifest mutation validator unchanged

No changes to Gate G. Verify PASS.

### Test 5.6 — Synthetic flood circuit breaker unchanged

No changes to Gate H. Verify PASS.

---

## EXPECTED PASS/FAIL MATRIX (Post-Fix)

| Test | Expected | Validates |
|---|---|---|
| 1.1 Cross-CVE contamination | kev=False | Fix 1 eliminates false positives |
| 1.2 Legitimate KEV primary CVE | kev=True | Fix 1 preserves real positives |
| 1.3 No CVEs → kev unchanged | pass-through | Fix 1 non-destructive |
| 2.1 Stale catalog → live fetch | live version used | Fix 2 freshness |
| 2.2 Fresh catalog → local used | local version used | Fix 2 efficiency |
| 2.3 Network fail → local fallback | no crash | Fix 2 resilience |
| 3.1 Zero inflation for 4 CVEs | PASS | Combined fix correctness |
| 3.2 Genuine inflation detected | HARD_FAIL | Gate not weakened |
| 3.3 Missed KEV detected | HARD_FAIL | Gate not weakened |
| 4.1 Full workflow | Gate D PASS | End-to-end regression |
| 4.2 Coverage not reduced | ≥32 KEV items | No coverage loss |
| 4.3 All 8 gates pass | All PASS | Full governance |

---

## AUTOMATED TEST EXECUTION

```bash
# Run vanguard engine unit tests
cd CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
python3 -m pytest tests/test_vanguard_kev.py -v

# Run integrity gate unit tests
python3 -m pytest tests/test_integrity_gate_kev.py -v

# Run integration check against local feed
python3 scripts/intelligence_integrity_gate.py --check

# Expected output:
#   ✓  D — KEV Health Gate    PASS
#   INTELLIGENCE INTEGRITY GATE RESULT: PASS
```
