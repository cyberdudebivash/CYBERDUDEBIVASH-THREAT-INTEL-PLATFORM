#!/usr/bin/env python3
"""
scripts/kev_feed_marker.py
CYBERDUDEBIVASH(R) SENTINEL APEX v160.0 — CISA KEV Feed Marker
================================================================
Fetches the live CISA Known Exploited Vulnerabilities (KEV) catalog
and marks all matching CVEs in api/feed.json with:
  kev          = true
  kev_date     = "YYYY-MM-DD"   (CISA dateAdded)
  kev_product  = "Vendor Product"
  severity     = "CRITICAL"     (KEV entries are always CRITICAL risk)
  risk_score   = max(existing, 9.0)  (KEV = minimum CRITICAL threshold)

Run:
  python3 scripts/kev_feed_marker.py
  FEED_PATH=api/feed.json python3 scripts/kev_feed_marker.py

T12 compliant: zero inline Python in YAML.
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [kev-marker] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("kev_marker")

REPO          = Path(__file__).resolve().parent.parent
FEED_PATH     = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
REPORT_PATH   = REPO / "data" / "health" / "kev_marker_report.json"
KEV_URL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DRY_RUN       = os.environ.get("DRY_RUN", "false").lower() == "true"
TIMEOUT       = int(os.environ.get("KEV_TIMEOUT", "20"))
_CVE_RE       = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# ---------------------------------------------------------------------------
def _fetch_kev_catalog() -> dict[str, dict]:
    """
    Fetch CISA KEV catalog. Returns {cve_id_upper: {dateAdded, vendorProject, product, ...}}.
    """
    log.info("Fetching CISA KEV catalog from %s", KEV_URL)
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "SentinelApex/160.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
        data = json.loads(raw)
    except urllib.error.URLError as e:
        log.error("KEV fetch failed (network): %s", e)
        return {}
    except Exception as e:
        log.error("KEV fetch failed: %s", e)
        return {}

    vulns = data.get("vulnerabilities") or []
    catalog: dict[str, dict] = {}
    for v in vulns:
        cid = (v.get("cveID") or "").upper().strip()
        if cid:
            catalog[cid] = {
                "date_added":     v.get("dateAdded", ""),
                "vendor_project": v.get("vendorProject", ""),
                "product":        v.get("product", ""),
                "vulnerability_name": v.get("vulnerabilityName", ""),
                "required_action": v.get("requiredAction", ""),
                "due_date":       v.get("dueDate", ""),
                "short_description": v.get("shortDescription", ""),
            }
    log.info("KEV catalog loaded: %d entries", len(catalog))
    return catalog


def _extract_cve(item: dict) -> list[str]:
    """Extract all CVE IDs from item fields."""
    cves: list[str] = []
    for field in ("title", "id", "source_url", "description"):
        val = item.get(field) or ""
        for m in _CVE_RE.finditer(str(val)):
            c = m.group(0).upper()
            if c not in cves:
                cves.append(c)
    # Also check cve list field
    cve_list = item.get("cve") or []
    if isinstance(cve_list, list):
        for c in cve_list:
            cid = str(c).upper().strip()
            if _CVE_RE.match(cid) and cid not in cves:
                cves.append(cid)
    return cves


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX — CISA KEV Feed Marker v160.0")
    log.info("Feed : %s | DryRun: %s", FEED_PATH, DRY_RUN)
    log.info("=" * 60)

    if not FEED_PATH.exists():
        log.error("Feed not found: %s", FEED_PATH)
        return 1

    # Load feed
    try:
        raw = FEED_PATH.read_text(encoding="utf-8")
        feed_data = json.loads(raw)
    except Exception as e:
        log.error("Feed parse error: %s", e)
        return 1

    items: list[dict] = feed_data if isinstance(feed_data, list) else (feed_data.get("items") or [])
    if not items:
        log.warning("Feed empty — nothing to mark")
        return 0

    # Fetch KEV catalog
    catalog = _fetch_kev_catalog()
    if not catalog:
        log.warning("KEV catalog unavailable — skipping marking (non-fatal)")
        # Write empty report so CI can still read it
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "kev_catalog_size": 0,
            "items_marked": 0,
            "status": "CATALOG_UNAVAILABLE",
        }, indent=2), encoding="utf-8")
        return 0

    # Mark matching items
    marked        = 0
    already_kev   = 0
    kev_items     = []

    for item in items:
        cves = _extract_cve(item)
        if not cves:
            continue

        matched_entry: dict | None = None
        matched_cve: str = ""
        for cve in cves:
            if cve in catalog:
                matched_entry = catalog[cve]
                matched_cve   = cve
                break

        if not matched_entry:
            continue

        if item.get("kev"):
            already_kev += 1
            continue

        # Mark as KEV
        item["kev"]           = True
        item["kev_confirmed"] = True
        item["kev_date"]      = matched_entry["date_added"]
        item["kev_product"]   = f"{matched_entry['vendor_project']} {matched_entry['product']}".strip()
        item["kev_name"]      = matched_entry.get("vulnerability_name", "")
        item["kev_action"]    = matched_entry.get("required_action", "")
        item["kev_due"]       = matched_entry.get("due_date", "")

        # KEV entries are always CRITICAL — enforce scoring
        existing_risk = float(item.get("risk_score") or 0)
        item["risk_score"]  = max(existing_risk, 9.0)
        item["severity"]    = "CRITICAL"
        item["confidence"]  = max(int(item.get("confidence") or 0), 90)
        item["_kev_marked_at"] = datetime.now(timezone.utc).isoformat()
        item["_kev_source"]    = "CISA-KEV-v2"

        marked += 1
        kev_items.append({
            "cve": matched_cve,
            "title": item.get("title", ""),
            "kev_date": matched_entry["date_added"],
            "kev_product": item["kev_product"],
        })
        log.info("[KEV] Marked: %s — %s (%s)", matched_cve, item.get("title", "")[:60], matched_entry["date_added"])

    log.info("─" * 60)
    log.info("KEV marking complete: %d newly marked, %d already KEV, %d total items",
             marked, already_kev, len(items))

    # Write report
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "kev_catalog_size":  len(catalog),
        "feed_items":        len(items),
        "items_marked":      marked,
        "already_kev":       already_kev,
        "total_kev_in_feed": marked + already_kev,
        "kev_items":         kev_items,
        "status":            "PASS" if marked >= 0 else "ERROR",
        "dry_run":           DRY_RUN,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Report written: %s", REPORT_PATH)

    if DRY_RUN:
        log.info("[DRY RUN] Would write %d marked items — skipping feed write", marked)
        return 0

    if marked == 0:
        log.info("No new KEV matches found — feed unchanged")
        return 0

    # Write back feed
    tmp = FEED_PATH.with_suffix(".kev_tmp")
    try:
        out = items if isinstance(feed_data, list) else {**feed_data, "items": items}
        tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(FEED_PATH)
        log.info("Feed updated: %s (%d items, %d KEV-marked)", FEED_PATH, len(items), marked)
    except Exception as e:
        log.error("Feed write failed: %s", e)
        tmp.unlink(missing_ok=True)
        return 1

    log.info("=" * 60)
    log.info("KEV Feed Marker complete — %d items marked CRITICAL", marked)
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
