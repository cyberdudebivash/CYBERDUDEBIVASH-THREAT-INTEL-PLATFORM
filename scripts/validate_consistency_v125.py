#!/usr/bin/env python3
"""
scripts/validate_consistency_v125.py
CYBERDUDEBIVASH(R) SENTINEL APEX v125.0 — Cross-Layer Consistency Validator
=============================================================================
Validates ALL 7 architectural guarantees introduced in v125.0:

  V1. IOC engine: ioc_count == len(flat_iocs) (invariant)
  V2. IOC engine: ioc_confidence > 0 when IOCs exist
  V3. IOC engine: threat_level != NONE when confidence > 0
  V4. IOC engine: false positives (RFC1918/loopback) are excluded
  V5. Dedup engine: 3-layer dedup removes all duplicates
  V6. Source fetcher: thin content (< 80 words) is rejected
  V7. Risk scoring: CRITICAL only when KEV/CVSS≥9/EPSS≥0.7/high-IOC-density

Exits 0 on full pass. Exits 1 on any failure.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

# Ensure project root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

PASS = 0
FAIL = 0
ERRORS: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        msg = f"  [FAIL] {name}" + (f" — {detail}" if detail else "")
        print(msg)
        ERRORS.append(msg)


# =============================================================================
# V1–V4: IOC Engine Tests
# =============================================================================
print("\n══════════════════════════════════════════════════")
print("V1-V4: IOC EXTRACTION ENGINE")
print("══════════════════════════════════════════════════")

try:
    from agent.ioc_engine import (
        extract_iocs,
        enforce_ioc_integrity,
        normalize_risk_score,
        IOCResult,
    )

    # V1: invariant ioc_count == len(flat_iocs)
    test_text = (
        "SHA256: a77f3c6f8c8b4f2e9d1234567890abcdef1234567890abcdef1234567890abcd01 "
        "IP: 185.220.101.45 Domain: evil-c2-domain.ru "
        "URL: http://malicious-payload.com/stage2/download "
        "CVE-2024-12345 exploited. MD5: d41d8cd98f00b204e9800998ecf8427e"
    )
    result = extract_iocs(test_text)
    check("V1a: ioc_count == len(flat_iocs)",
          result.ioc_count == len(result.flat_iocs),
          f"ioc_count={result.ioc_count} len(flat_iocs)={len(result.flat_iocs)}")

    # V1b: Empty input gives empty result with correct invariant
    empty_result = extract_iocs("")
    check("V1b: Empty input → ioc_count=0 == len(flat_iocs)=0",
          empty_result.ioc_count == 0 and len(empty_result.flat_iocs) == 0)

    # V2: ioc_confidence > 0 when IOCs exist
    check("V2: ioc_confidence > 0 when IOCs exist",
          result.ioc_count > 0 and result.ioc_confidence > 0.0,
          f"ioc_count={result.ioc_count} confidence={result.ioc_confidence}")

    # V3: threat_level != NONE when confidence > 0
    check("V3: threat_level != NONE when confidence > 0",
          result.ioc_confidence > 0 and result.threat_level != "NONE",
          f"confidence={result.ioc_confidence} level={result.threat_level}")

    # V4a: RFC1918 addresses excluded
    fp_text = "Internal host at 192.168.1.100 and loopback 127.0.0.1 should not appear"
    fp_result = extract_iocs(fp_text)
    fp_ips = fp_result.iocs_by_type.get("ipv4", [])
    check("V4a: RFC1918 192.168.x.x excluded from IOCs",
          "192.168.1.100" not in fp_ips,
          f"Found in IOCs: {fp_ips}")
    check("V4b: Loopback 127.0.0.1 excluded from IOCs",
          "127.0.0.1" not in fp_ips,
          f"Found in IOCs: {fp_ips}")

    # V4c: Benign domains excluded
    benign_text = "See nvd.nist.gov and cisa.gov for details. Threat domain: evil-apt.ru"
    benign_result = extract_iocs(benign_text)
    benign_domains = benign_result.iocs_by_type.get("domain", [])
    check("V4c: nvd.nist.gov excluded (benign reference site)",
          "nvd.nist.gov" not in benign_domains,
          f"Domains found: {benign_domains}")

    # enforce_ioc_integrity: P0 fix — ioc_count > 0 but iocs empty
    broken_entry = {
        "title": "APT29 Campaign with 185.220.101.45 and CVE-2024-99999",
        "description": "Malicious IP 185.220.101.45 used in spearphishing campaign",
        "ioc_count": 5,   # claimed count
        "iocs": [],        # P0: empty list despite count > 0
        "ioc_confidence": 0.0,
        "ioc_threat_level": "NONE",
    }
    fixed = enforce_ioc_integrity(broken_entry)
    check("V1c: enforce_ioc_integrity fixes ioc_count > 0 with iocs=[]",
          fixed["ioc_count"] == len(fixed["iocs"]),
          f"ioc_count={fixed['ioc_count']} len(iocs)={len(fixed['iocs'])}")
    check("V2c: enforce_ioc_integrity fixes zero confidence",
          fixed.get("ioc_confidence", 0.0) > 0.0,
          f"confidence={fixed.get('ioc_confidence')}")
    check("V3c: enforce_ioc_integrity fixes NONE threat_level",
          fixed.get("ioc_threat_level") != "NONE",
          f"threat_level={fixed.get('ioc_threat_level')}")

    print(f"\n  IOC types found: {list(result.iocs_by_type.keys())}")
    print(f"  IOC count: {result.ioc_count}")
    print(f"  Confidence: {result.ioc_confidence}")
    print(f"  Threat level: {result.threat_level}")

except ImportError as e:
    check("IOC engine importable", False, str(e))
except Exception as e:
    check("IOC engine no exceptions", False, str(e))


# =============================================================================
# V5: Dedup Engine Tests
# =============================================================================
print("\n══════════════════════════════════════════════════")
print("V5: GLOBAL DEDUP ENGINE")
print("══════════════════════════════════════════════════")

try:
    from scripts.safe_io import dedup_items

    # Exact duplicate (same title + source + same-day timestamps → same date key)
    # Two entries from the same source on the same date should collapse to 1 via L1
    items = [
        {"title": "Russian APT29 targets diplomatic institutions via spearphishing",
         "source": "BleepingComputer", "timestamp": "2026-04-20T12:00:00Z"},
        {"title": "Russian APT29 targets diplomatic institutions via spearphishing",
         "source": "BleepingComputer", "timestamp": "2026-04-20T14:00:00Z"},  # same source+date → L1 dup
    ]
    deduped, removed = dedup_items(items)
    check("V5a: Layer-1 exact dedup (same title+source+date, same-day timestamps)",
          len(deduped) == 1 and removed == 1,
          f"deduped={len(deduped)} removed={removed}")

    # Cross-feed dedup (same title, different sources)
    items2 = [
        {"title": "Critical Zero-Day in Windows Kernel Exploited Actively", "source": "SecurityWeek",
         "timestamp": "2026-04-21"},
        {"title": "Critical Zero-Day in Windows Kernel Exploited Actively", "source": "BleepingComputer",
         "timestamp": "2026-04-21"},
    ]
    deduped2, removed2 = dedup_items(items2)
    check("V5b: Layer-2 cross-feed dedup (same title, different source)",
          len(deduped2) == 1,
          f"deduped={len(deduped2)} removed={removed2}")

    # Generic title should NOT be L2-deduped (different content, same template)
    items3 = [
        {"title": "CISA Adds One Known Exploited Vulnerability to Catalog",
         "source": "CISA", "timestamp": "2026-04-10"},
        {"title": "CISA Adds One Known Exploited Vulnerability to Catalog",
         "source": "CISA", "timestamp": "2026-04-21"},
    ]
    deduped3, removed3 = dedup_items(items3)
    check("V5c: Generic titles (CISA KEV) NOT cross-feed deduped when dates differ",
          len(deduped3) == 2,
          f"deduped={len(deduped3)} removed={removed3}")

    # Bundle ID dedup
    items4 = [
        {"title": "Threat A", "source": "src", "timestamp": "2026-04-21",
         "bundle_id": "bundle--deadbeef-1234-5678-abcd-000000000001"},
        {"title": "Threat A Modified Title", "source": "src2", "timestamp": "2026-04-22",
         "bundle_id": "bundle--deadbeef-1234-5678-abcd-000000000001"},
    ]
    deduped4, removed4 = dedup_items(items4)
    check("V5d: Layer-3 bundle_id dedup (same STIX bundle)",
          len(deduped4) == 1,
          f"deduped={len(deduped4)} removed={removed4}")

    print(f"\n  All dedup checks complete.")

except ImportError as e:
    check("Dedup engine importable", False, str(e))
except Exception as e:
    check("Dedup engine no exceptions", False, str(e))


# =============================================================================
# V6: Source Fetcher Quality Gate Tests
# =============================================================================
print("\n══════════════════════════════════════════════════")
print("V6: SOURCE FETCHER CONTENT QUALITY GATE")
print("══════════════════════════════════════════════════")

try:
    from agent.content.source_fetcher import SourceFetcher
    sf = SourceFetcher()
    check("V6a: SourceFetcher.CONTENT_MIN_WORDS >= 300",
          sf.CONTENT_MIN_WORDS >= 300,
          f"CONTENT_MIN_WORDS={sf.CONTENT_MIN_WORDS}")
    check("V6b: SourceFetcher.CONTENT_SOFT_REJECT_WORDS >= 80",
          sf.CONTENT_SOFT_REJECT_WORDS >= 80,
          f"CONTENT_SOFT_REJECT_WORDS={sf.CONTENT_SOFT_REJECT_WORDS}")
    check("V6c: SourceFetcher.CONTENT_RETRY_ATTEMPTS >= 2",
          sf.CONTENT_RETRY_ATTEMPTS >= 2,
          f"CONTENT_RETRY_ATTEMPTS={sf.CONTENT_RETRY_ATTEMPTS}")

    # Test invalid URL returns failed (no exception)
    r = sf.fetch_article("not-a-url")
    check("V6d: Invalid URL returns failed result (no exception)",
          r["fetch_status"] == "failed" and r["word_count"] == 0)

    print(f"\n  Content thresholds: min={sf.CONTENT_MIN_WORDS} "
          f"soft_reject={sf.CONTENT_SOFT_REJECT_WORDS} "
          f"retries={sf.CONTENT_RETRY_ATTEMPTS}")

except ImportError as e:
    check("SourceFetcher importable", False, str(e))
except Exception as e:
    check("SourceFetcher no exceptions", False, str(e))


# =============================================================================
# V7: Risk Scoring Normalization Tests
# =============================================================================
print("\n══════════════════════════════════════════════════")
print("V7: RISK SCORING NORMALIZATION")
print("══════════════════════════════════════════════════")

try:
    from agent.ioc_engine import normalize_risk_score

    # KEV → always CRITICAL
    r1 = normalize_risk_score(5.0, kev_present=True, cvss_score=5.0, ioc_count=0)
    check("V7a: KEV present → CRITICAL",
          r1["severity"] == "CRITICAL",
          f"got severity={r1['severity']}")

    # High CVSS without KEV → CRITICAL only if IOCs or high EPSS
    r2 = normalize_risk_score(9.5, kev_present=False, cvss_score=9.5, ioc_count=3)
    check("V7b: CVSS=9.5 + ioc_count=3 → CRITICAL",
          r2["severity"] == "CRITICAL",
          f"got severity={r2['severity']}")

    # High CVSS but no IOCs and no EPSS → NOT CRITICAL (prevent false inflation)
    r3 = normalize_risk_score(9.0, kev_present=False, cvss_score=9.0,
                               epss_score=0.2, ioc_count=0)
    check("V7c: CVSS=9.0 but no IOCs/KEV/EPSS → NOT CRITICAL (HIGH)",
          r3["severity"] in ("HIGH",),
          f"got severity={r3['severity']} (expected HIGH, not CRITICAL)")

    # EPSS ≥ 0.7 → CRITICAL
    r4 = normalize_risk_score(6.0, kev_present=False, cvss_score=6.0, epss_score=0.75)
    check("V7d: EPSS=0.75 → CRITICAL",
          r4["severity"] == "CRITICAL",
          f"got severity={r4['severity']}")

    # Low signals → LOW or MEDIUM (not CRITICAL/HIGH without justification)
    r5 = normalize_risk_score(3.0, kev_present=False, cvss_score=3.0, epss_score=0.05, ioc_count=0)
    check("V7e: Low CVSS, no IOCs, no KEV → MEDIUM or LOW (not CRITICAL)",
          r5["severity"] not in ("CRITICAL", "HIGH"),
          f"got severity={r5['severity']}")

    # risk_score clamped to [0, 10]
    r6 = normalize_risk_score(15.0, kev_present=False)
    check("V7f: risk_score clamped to ≤ 10.0",
          r6["risk_score"] <= 10.0,
          f"got risk_score={r6['risk_score']}")

    print(f"\n  Scoring results: KEV→{r1}, cvss+ioc→{r2}, epss→{r4}")

except ImportError as e:
    check("normalize_risk_score importable", False, str(e))
except Exception as e:
    check("normalize_risk_score no exceptions", False, str(e))


# =============================================================================
# V8: Export STIX stix_bundle_url linkage verification
# =============================================================================
print("\n══════════════════════════════════════════════════")
print("V8: STIX BUNDLE URL LINKAGE (manifest schema)")
print("══════════════════════════════════════════════════")

try:
    from agent.export_stix import STIXExporter

    # Verify STIXExporter._update_manifest signature accepts new v125 params
    import inspect
    sig = inspect.signature(STIXExporter._update_manifest)
    params = sig.parameters
    check("V8a: _update_manifest accepts iocs_flat parameter",
          "iocs_flat" in params, f"Params: {list(params.keys())}")
    check("V8b: _update_manifest accepts iocs_by_type parameter",
          "iocs_by_type" in params, f"Params: {list(params.keys())}")
    check("V8c: _update_manifest accepts stix_bundle_url parameter",
          "stix_bundle_url" in params, f"Params: {list(params.keys())}")

except ImportError as e:
    check("STIXExporter importable", False, str(e))
except Exception as e:
    check("STIXExporter inspection", False, str(e))


# =============================================================================
# FINAL REPORT
# =============================================================================
print("\n══════════════════════════════════════════════════")
total = PASS + FAIL
print(f"VALIDATION COMPLETE: {PASS}/{total} passed | {FAIL} failed")
print("══════════════════════════════════════════════════")
if ERRORS:
    print("\nFAILURES:")
    for e in ERRORS:
        print(e)
    sys.exit(1)
else:
    print("\n✓ ALL CHECKS PASSED — Platform integrity verified.")
    sys.exit(0)
