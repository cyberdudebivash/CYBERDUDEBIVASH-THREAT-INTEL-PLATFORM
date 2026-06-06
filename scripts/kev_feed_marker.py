#!/usr/bin/env python3
"""
scripts/kev_feed_marker.py  — SENTINEL APEX v175.1 CISA KEV Feed Marker
P0-FIX v175.1:
  - _extract_cve() now checks cve_id/cve_ids/cves fields (was only 'cve')
  - _is_kev_true() replaces bare `if item.get('kev'):`  — handles kev="NO"
  - De-inflation pass: kev=True items whose CVE is NOT in catalog get cleared
  - write-back triggers on deflated>0 as well as marked>0
"""
from __future__ import annotations
import json, logging, os, re, sys, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [kev-marker] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S", stream=sys.stdout)
log = logging.getLogger("kev_marker")

REPO        = Path(__file__).resolve().parent.parent
FEED_PATH   = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
REPORT_PATH = REPO / "data" / "health" / "kev_marker_report.json"
KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DRY_RUN     = os.environ.get("DRY_RUN", "false").lower() == "true"
TIMEOUT     = int(os.environ.get("KEV_TIMEOUT", "20"))
_CVE_RE     = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _fetch_kev_catalog() -> dict:
    log.info("Fetching CISA KEV catalog from %s", KEV_URL)
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "SentinelApex/175.1"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        log.error("KEV fetch failed: %s", e)
        return {}
    catalog = {}
    for v in (data.get("vulnerabilities") or []):
        cid = (v.get("cveID") or "").upper().strip()
        if cid:
            catalog[cid] = {
                "date_added":         v.get("dateAdded", ""),
                "vendor_project":     v.get("vendorProject", ""),
                "product":            v.get("product", ""),
                "vulnerability_name": v.get("vulnerabilityName", ""),
                "required_action":    v.get("requiredAction", ""),
                "due_date":           v.get("dueDate", ""),
            }
    log.info("KEV catalog loaded: %d entries", len(catalog))
    return catalog


def _is_kev_true(val) -> bool:
    """Only True for genuinely-truthy KEV values; kev='NO' returns False."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "yes", "1", "confirmed")
    return bool(val)


def _extract_cve(item: dict) -> list:
    """Extract CVE IDs from all canonical fields + text fallback.
    P0-FIX: Added cve_id/cve_ids/cves — prior code only checked 'cve'.
    """
    cves = []
    # Structured fields first (most reliable)
    for field in ("cve_id", "cve_ids", "cves", "cve"):
        val = item.get(field)
        if val is None:
            continue
        if isinstance(val, str):
            cid = val.upper().strip()
            if _CVE_RE.match(cid) and cid not in cves:
                cves.append(cid)
        elif isinstance(val, list):
            for c in val:
                cid = str(c).upper().strip()
                if _CVE_RE.match(cid) and cid not in cves:
                    cves.append(cid)
    # Text fallback
    # P1-FIX (audit finding F1, run #1551 / STAGE 3.93.15 false HARD_FAIL):
    # Added 'headline' and 'name' for parity with intelligence_integrity_gate
    # ._title(), which falls back through title -> headline -> name. Without
    # this, items whose CVE text lives in `headline`/`name` (a real, populated
    # field pattern elsewhere in this codebase — see manifest_repair.py,
    # ocios_campaign_correlation_engine.py, auto_blog_publisher.py, etc.) were
    # returned as cves=[], fell through `if not cves: continue` below, and their
    # kev flag was never re-validated against the live catalog — surviving as an
    # unverified true/false positive that the Integrity Gate then (correctly,
    # from its own wider view) flagged as "inflated". This made the gate look
    # wrong when it was actually catching what THIS function missed.
    for field in ("title", "headline", "name", "id", "source_url", "description"):
        val = item.get(field) or ""
        for m in _CVE_RE.finditer(str(val)):
            c = m.group(0).upper()
            if c not in cves:
                cves.append(c)
    return cves


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX — CISA KEV Feed Marker v175.1")
    log.info("Feed : %s | DryRun: %s", FEED_PATH, DRY_RUN)
    log.info("=" * 60)

    if not FEED_PATH.exists():
        log.error("Feed not found: %s", FEED_PATH)
        return 1

    try:
        feed_data = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Feed parse error: %s", e)
        return 1

    items = feed_data if isinstance(feed_data, list) else (feed_data.get("items") or [])
    if not items:
        log.warning("Feed empty — nothing to mark")
        return 0

    catalog = _fetch_kev_catalog()
    if not catalog:
        log.warning("KEV catalog unavailable — skipping (non-fatal)")
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "kev_catalog_size": 0, "items_marked": 0, "items_deflated": 0,
            "status": "CATALOG_UNAVAILABLE"}, indent=2), encoding="utf-8")
        return 0

    marked = already_kev = deflated = 0
    kev_items = []

    for item in items:
        cves = _extract_cve(item)
        currently_kev = _is_kev_true(
            item.get("kev") or item.get("kev_confirmed") or item.get("kev_present"))

        if not cves:
            if currently_kev:
                already_kev += 1
            continue

        matched_cve = matched_entry = None
        for cve in cves:
            if cve in catalog:
                matched_cve   = cve
                matched_entry = catalog[cve]
                break

        if matched_entry:
            # CVE IS in KEV catalog
            if currently_kev:
                already_kev += 1
                continue
            # Mark it
            vp = matched_entry["vendor_project"]
            pr = matched_entry["product"]
            item["kev"]            = True
            item["kev_confirmed"]  = True
            item["kev_present"]    = True
            item["kev_date"]       = matched_entry["date_added"]
            item["kev_product"]    = (vp + " " + pr).strip()
            item["kev_name"]       = matched_entry.get("vulnerability_name", "")
            item["kev_action"]     = matched_entry.get("required_action", "")
            item["kev_due"]        = matched_entry.get("due_date", "")
            item["risk_score"]     = max(float(item.get("risk_score") or 0), 9.0)
            item["severity"]       = "CRITICAL"
            item["confidence"]     = max(int(item.get("confidence") or 0), 90)
            item["_kev_marked_at"] = datetime.now(timezone.utc).isoformat()
            item["_kev_source"]    = "CISA-KEV-v2"
            marked += 1
            kev_items.append({"cve": matched_cve, "title": item.get("title", "")[:80],
                               "kev_date": matched_entry["date_added"],
                               "kev_product": item["kev_product"]})
            log.info("[KEV] Marked: %s — %s (%s)",
                     matched_cve, item.get("title", "")[:60], matched_entry["date_added"])
        else:
            # CVE present but NOT in KEV catalog — de-inflate false positives
            if currently_kev:
                item["kev"] = item["kev_confirmed"] = item["kev_present"] = False
                for kf in ("kev_date","kev_product","kev_name","kev_action",
                           "kev_due","_kev_marked_at","_kev_source"):
                    item.pop(kf, None)
                deflated += 1
                log.info("[KEV-DEFLATE] Cleared false kev=True: %s — %s",
                         sorted(cves)[:3], item.get("title", "")[:60])

    log.info("─" * 60)
    log.info("KEV marking complete: %d newly marked, %d already KEV, %d deflated, %d total",
             marked, already_kev, deflated, len(items))

    total_kev = marked + already_kev
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps({
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "kev_catalog_size":  len(catalog),
        "feed_items":        len(items),
        "items_marked":      marked,
        "items_deflated":    deflated,
        "already_kev":       already_kev,
        "total_kev_in_feed": total_kev,
        "kev_items":         kev_items,
        "status":            "PASS",
        "dry_run":           DRY_RUN,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Report written: %s", REPORT_PATH)

    if DRY_RUN:
        log.info("[DRY RUN] Would write %d marked, %d def