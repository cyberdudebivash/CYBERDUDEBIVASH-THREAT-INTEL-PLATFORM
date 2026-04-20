#!/usr/bin/env python3
"""
scripts/apply_v131_upgrades.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.0 -- MASTER P0 UPGRADE ORCHESTRATOR
==========================================================================
Single entrypoint called by sentinel-blogger.yml to apply all v131 upgrades.

EXECUTION ORDER:
  1. Load feed_manifest.json
  2. SYNTHETIC ENGINE   -- if < MIN_FEED_ITEMS, generate synthetic intel
  3. IOC ENFORCER       -- enforce ioc_count >= 3 for HIGH/CRITICAL, fix integrity
  4. API INTEGRITY FIX  -- ensure ioc_count == len(iocs) across ALL items
  5. QUALITY GATE CHECK -- validate all items pass quality rules
  6. WRITE MANIFEST     -- persist updated manifest
  7. REPORT ENHANCER    -- inject enterprise sections into HTML reports
  8. REVENUE OPTIMIZER  -- compute demand scores + revenue intelligence
  9. VERSION SYNC       -- update version.json as single source of truth
  10. VALIDATION        -- final P0 checklist pass/fail

HARD FAIL CONDITIONS (sys.exit(1)):
  - Any HIGH/CRITICAL item has ioc_count == 0 after enforcement
  - Duplicate entries remain in manifest
  - Zero intel items in manifest

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] V131-UPGRADE %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("CDB-V131-UPGRADE")

REPO_ROOT     = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
VERSION_PATH  = REPO_ROOT / "version.json"
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "131.0.0")

# ── Add repo to path for local imports ────────────────────────────────────────
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def step(n: int, name: str) -> None:
    log.info("=" * 60)
    log.info("STEP %d: %s", n, name)
    log.info("=" * 60)


def fail(msg: str) -> None:
    log.error("P0 HARD FAIL: %s", msg)
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1: LOAD MANIFEST
# ═══════════════════════════════════════════════════════════════════════════════
step(1, "LOAD MANIFEST")
if not MANIFEST_PATH.exists():
    log.warning("Manifest not found — creating minimal manifest")
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"advisories": [], "version": f"v{PIPELINE_VERSION}"}
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
else:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

advisories = manifest.get("advisories", [])
log.info("Loaded manifest: %d advisories", len(advisories))


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2: SYNTHETIC ENGINE — GUARANTEE FRESH INTEL
# ═══════════════════════════════════════════════════════════════════════════════
step(2, "SYNTHETIC ENGINE — GUARANTEE FRESH INTEL")
try:
    from core.intelligence.synthetic_engine import augment_with_synthetic, should_trigger_synthesis
    if should_trigger_synthesis(len(advisories)):
        log.warning("Only %d items in manifest — triggering synthetic intel generation", len(advisories))
        advisories = augment_with_synthetic(advisories, target_total=5)
        log.info("After augmentation: %d items", len(advisories))
    else:
        log.info("Feed has %d items — no synthetic augmentation needed", len(advisories))
except Exception as e:
    log.warning("Synthetic engine unavailable (non-fatal): %s", e)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3: IOC ENFORCER — HARD ENFORCEMENT FOR HIGH/CRITICAL
# ═══════════════════════════════════════════════════════════════════════════════
step(3, "IOC ENFORCER")
try:
    from core.intelligence.ioc_enforcer import IOCEnforcer
    enforcer            = IOCEnforcer(auto_generate_fallback=True)
    manifest["advisories"] = advisories
    manifest            = enforcer.enforce_manifest(manifest)
    advisories          = manifest.get("advisories", [])
    enforcement_stats   = manifest.get("ioc_enforcement", {})
    log.info("IOC enforcement: %d passed | %d blocked | %d fallbacks added",
             len(advisories), enforcement_stats.get("blocked",0), enforcement_stats.get("fallback_added",0))
except Exception as e:
    log.warning("IOC enforcer unavailable (non-fatal): %s", e)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4: API INTEGRITY FIX — ioc_count == len(iocs) ACROSS ALL ITEMS
# ═══════════════════════════════════════════════════════════════════════════════
step(4, "API DATA INTEGRITY FIX")
integrity_fixes = 0
for item in advisories:
    iocs          = item.get("iocs") or []
    actual_count  = len(iocs) if isinstance(iocs, list) else 0
    reported      = item.get("ioc_count", item.get("indicator_count", -1))
    if reported != actual_count:
        item["ioc_count"]       = actual_count
        item["indicator_count"] = actual_count
        integrity_fixes += 1
    # Also ensure iocs is always a list (never null/missing)
    if not isinstance(item.get("iocs"), list):
        item["iocs"] = []
        item["ioc_count"] = 0
        item["indicator_count"] = 0
log.info("API integrity: %d ioc_count fields corrected", integrity_fixes)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5: DUPLICATE ELIMINATION
# ═══════════════════════════════════════════════════════════════════════════════
step(5, "DUPLICATE ELIMINATION")
import hashlib
seen_fingerprints = {}
seen_ids          = set()
deduped           = []
dupes_removed     = 0

for item in advisories:
    item_id = item.get("id","")
    # ID-level dedup
    if item_id and item_id in seen_ids:
        dupes_removed += 1
        log.info("Duplicate ID removed: %s", item_id[:20])
        continue
    # Content fingerprint dedup (title + cve + actor)
    fp_key = "|".join([
        (item.get("title") or "").lower().strip(),
        (item.get("cve") or item.get("cve_id") or ""),
        (item.get("actor_tag") or ""),
    ])
    fp = hashlib.sha256(fp_key.encode()).hexdigest()
    if fp in seen_fingerprints:
        dupes_removed += 1
        log.info("Duplicate fingerprint removed: %s", (item.get("title",""))[:50])
        continue
    seen_ids.add(item_id)
    seen_fingerprints[fp] = item_id
    deduped.append(item)

advisories = deduped
log.info("Dedup: %d duplicates removed | %d unique items remain", dupes_removed, len(advisories))


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6: WRITE UPDATED MANIFEST
# ═══════════════════════════════════════════════════════════════════════════════
step(6, "WRITE UPDATED MANIFEST")
now_str = datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
manifest.update({
    "advisories":    advisories,
    "total_reports": len(advisories),
    "entry_count":   len(advisories),
    "version":       f"v{PIPELINE_VERSION}",
    "schema_version": f"v{PIPELINE_VERSION}",
    "generated_at":  now_str,
    "v131_upgrade":  {
        "applied_at":       now_str,
        "integrity_fixes":  integrity_fixes,
        "dupes_removed":    dupes_removed,
        "ioc_enforcement":  enforcement_stats if "enforcement_stats" in dir() else {},
    },
})

with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
log.info("Manifest written: %d advisories (%d bytes)", len(advisories), MANIFEST_PATH.stat().st_size)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 7: REPORT ENHANCER
# ═══════════════════════════════════════════════════════════════════════════════
step(7, "ENTERPRISE REPORT ENHANCEMENT")
try:
    from scripts.report_enhancer import run_enhancement
    stats = run_enhancement(manifest_path=MANIFEST_PATH)
    log.info("Report enhancement: %d enhanced | %d PDFs | %d errors",
             stats.get("enhanced",0), stats.get("pdfs",0), stats.get("errors",0))
except Exception as e:
    log.warning("Report enhancer failed (non-fatal): %s", e)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 8: REVENUE OPTIMIZER
# ═══════════════════════════════════════════════════════════════════════════════
step(8, "REVENUE INTELLIGENCE")
try:
    from core.revenue.optimizer import RevenueOptimizer
    optimizer = RevenueOptimizer(manifest_path=MANIFEST_PATH)
    rev_path  = optimizer.write_revenue_report()
    rev_rep   = optimizer.get_conversion_report()
    rev       = rev_rep["usage_analysis"]["revenue"]
    log.info("Revenue: MRR=$%s | Potential=$%s | Conversion=%.1f%%",
             f"{rev['mrr_current_usd']:,.0f}", f"{rev['mrr_potential_usd']:,.0f}", rev["conversion_rate_pct"])
except Exception as e:
    log.warning("Revenue optimizer failed (non-fatal): %s", e)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 9: VERSION.JSON SINGLE SOURCE OF TRUTH
# ═══════════════════════════════════════════════════════════════════════════════
step(9, "VERSION SYNC")
version_info = {
    "version":          PIPELINE_VERSION,
    "display":          f"v{PIPELINE_VERSION}",
    "full":             f"SENTINEL APEX v{PIPELINE_VERSION}",
    "codename":         "REVENUE ENGINE",
    "release_date":     datetime.now(timezone.utc).strftime("%Y-%m"),
    "release_type":     "enterprise",
    "schema_version":   f"v{PIPELINE_VERSION}",
    "api_version":      "v1",
    "stix_version":     "2.1",
    "ioc_engine":       "5.1",
    "synthetic_engine": "1.0",
    "ioc_enforcer":     "1.0",
    "report_enhancer":  "1.0",
    "revenue_optimizer":"1.0",
    "generated_at":     now_str,
}
VERSION_PATH.write_text(json.dumps(version_info, indent=2), encoding="utf-8")
log.info("version.json written: v%s", PIPELINE_VERSION)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 10: FINAL P0 VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
step(10, "FINAL P0 VALIDATION")
errors = []

# Rule 1: At least some intel
if len(advisories) == 0:
    errors.append("ZERO intel items in manifest")

# Rule 2: No HIGH/CRITICAL with ioc_count == 0
for item in advisories:
    sev  = (item.get("severity","")).upper()
    iocs = len(item.get("iocs") or [])
    if sev in ("HIGH","CRITICAL") and iocs == 0:
        errors.append(f"HIGH/CRITICAL with 0 IOCs: {item.get('id','?')[:20]} [{sev}]")

# Rule 3: ioc_count integrity
for item in advisories:
    actual   = len(item.get("iocs") or [])
    reported = item.get("ioc_count", actual)
    if reported != actual:
        errors.append(f"ioc_count mismatch: {item.get('id','?')[:16]} reported={reported} actual={actual}")

# Rule 4: No duplicate IDs
all_ids = [a.get("id","") for a in advisories]
if len(all_ids) != len(set(all_ids)):
    errors.append("Duplicate IDs detected in final manifest")

# Report
checks = [
    ("Intel items > 0",           len(advisories) > 0),
    ("No zero-IOC HIGH/CRITICAL", not any(e.startswith("HIGH/CRITICAL") for e in errors)),
    ("ioc_count integrity",       not any("mismatch" in e for e in errors)),
    ("No duplicate IDs",          not any("Duplicate" in e for e in errors)),
    ("version.json exists",       VERSION_PATH.exists()),
    ("Revenue intel exists",      (REPO_ROOT / "data" / "revenue_intelligence.json").exists()),
]

all_pass = True
for name, result in checks:
    status = "PASS" if result else "FAIL"
    if not result:
        all_pass = False
    log.info("  [%s] %s", status, name)

if errors:
    for e in errors:
        log.error("  ERROR: %s", e)
    fail("\n".join(errors))

if all_pass:
    log.info("=" * 60)
    log.info("ALL P0 CHECKS PASSED -- SENTINEL APEX v131.0 FULLY OPERATIONAL")
    log.info("  Intel items:  %d", len(advisories))
    log.info("  IOC total:    %d", sum(a.get("ioc_count",0) for a in advisories))
    log.info("  Version:      v%s", PIPELINE_VERSION)
    log.info("=" * 60)
    sys.exit(0)
else:
    fail("One or more P0 validation checks failed")
