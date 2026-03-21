#!/usr/bin/env python3
"""
SENTINEL APEX v70.3 — Enhanced Data Bridge
=============================================
Reads REAL data sources, converts to v70 format, AND builds
CVE enrichment index for the scoring engine.

Enhancements over v70.2:
- Extracts CVSS/EPSS/KEV from STIX items → cve_index.json
- Passes enrichment data through to advisories
- Sanitizes HTML entities that break Blogger API (fixes 400 errors)
- Performance logging
"""

import html
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
STIX_MANIFEST = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
INDEX_HTML = REPO_ROOT / "index.html"
OUTPUT_MANIFEST = REPO_ROOT / "data" / "feed_manifest.json"
CVE_INDEX_PATH = REPO_ROOT / "data" / "cve_index.json"
PENDING_PUBLISH = REPO_ROOT / "data" / "pending_publish.json"


def extract_cve_from_title(title: str) -> list:
    if not title:
        return []
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", title, re.IGNORECASE)))


def sanitize_blogger_html(text: str) -> str:
    """Fix characters that cause Blogger API 400 errors."""
    if not text:
        return text
    # Replace problematic chars
    text = text.replace("\uff5c", "|")  # fullwidth vertical bar
    text = text.replace("\u2013", "-")  # en dash
    text = text.replace("\u2014", "--")  # em dash
    text = text.replace("\u2018", "'").replace("\u2019", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2122", "(TM)")
    text = text.replace("\u00ae", "(R)")
    text = text.replace("\u00a9", "(C)")
    # Strip null bytes
    text = text.replace("\x00", "")
    return text


def convert_stix_item(item: dict) -> dict:
    title = sanitize_blogger_html(item.get("title", ""))
    cves = extract_cve_from_title(title)

    mitre_raw = item.get("mitre_tactics", "")
    mitre_techniques = []
    if isinstance(mitre_raw, str) and mitre_raw:
        mitre_techniques = [t.strip() for t in mitre_raw.split(",") if t.strip()]
    elif isinstance(mitre_raw, list):
        mitre_techniques = mitre_raw

    sev = (item.get("severity", "") or "").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "info"

    actors = []
    actor_tag = item.get("actor_tag", "")
    if actor_tag and isinstance(actor_tag, str) and actor_tag.lower() not in ("", "none", "unknown", "n/a"):
        actors = [actor_tag]

    source_name = item.get("feed_source", "")
    source_url = item.get("source_url", "")
    if not source_name and source_url:
        try:
            from urllib.parse import urlparse
            source_name = urlparse(source_url).netloc
        except Exception:
            source_name = "Unknown"

    ioc_counts = item.get("ioc_counts", {})
    total_iocs = item.get("indicator_count", 0) or 0
    if not total_iocs and ioc_counts:
        total_iocs = sum(v for v in ioc_counts.values() if isinstance(v, (int, float)))

    cvss = float(item.get("cvss_score", 0) or 0)
    epss = float(item.get("epss_score", 0) or 0)
    kev = bool(item.get("kev_present", False))

    return {
        "title": title,
        "description": title,
        "source": source_name,
        "source_url": source_url,
        "link": source_url,
        "published": item.get("timestamp", ""),
        "published_date": item.get("timestamp", ""),
        "severity": sev,
        "confidence": float(item.get("confidence_score", 0) or item.get("confidence", 0) or 0),
        "threat_score": float(item.get("risk_score", 0) or 0),
        "cves": cves,
        "iocs": [],
        "ioc_count": total_iocs,
        "actors": actors,
        "mitre_techniques": mitre_techniques,
        "tags": [],
        "stix_id": item.get("stix_id", ""),
        "bundle_id": item.get("bundle_id", ""),
        "blog_post_url": item.get("blog_url", ""),
        "blog_url": item.get("blog_url", ""),
        "cvss_score": cvss,
        "epss_score": epss,
        "kev_present": kev,
        "tlp_label": item.get("tlp_label", ""),
        "nvd_url": item.get("nvd_url", ""),
        "feed_source": source_name,
        "indicator_count": total_iocs,
    }


def build_cve_index(items: list) -> dict:
    """Build CVE enrichment index from STIX manifest items.
    This feeds the v70 ThreatScoringEngine with real CVSS/EPSS/KEV data."""
    cve_index = {}
    for item in items:
        cves = extract_cve_from_title(item.get("title", ""))
        if not cves:
            continue
        cvss = float(item.get("cvss_score", 0) or 0)
        epss = float(item.get("epss_score", 0) or 0)
        kev = bool(item.get("kev_present", False))
        for cve_id in cves:
            cve_upper = cve_id.upper()
            existing = cve_index.get(cve_upper)
            if existing:
                # Keep highest scores
                cve_index[cve_upper] = {
                    "cve_id": cve_upper,
                    "cvss_score": max(cvss, existing.get("cvss_score", 0)),
                    "epss_score": max(epss, existing.get("epss_score", 0)),
                    "kev_status": kev or existing.get("kev_status", False),
                    "exploit_available": kev or existing.get("exploit_available", False),
                }
            else:
                cve_index[cve_upper] = {
                    "cve_id": cve_upper,
                    "cvss_score": cvss,
                    "epss_score": epss,
                    "kev_status": kev,
                    "exploit_available": kev,
                }
    return cve_index


def sanitize_pending_publish():
    """Fix pending_publish.json entries that have Blogger-breaking characters."""
    if not PENDING_PUBLISH.exists():
        return
    try:
        with open(PENDING_PUBLISH, "r", encoding="utf-8") as f:
            items = json.load(f)
        if not isinstance(items, list):
            return
        changed = False
        for item in items:
            if not isinstance(item, dict):
                continue
            for key in ("title", "post_body"):
                val = item.get(key, "")
                if isinstance(val, str):
                    new_val = sanitize_blogger_html(val)
                    if new_val != val:
                        item[key] = new_val
                        changed = True
        if changed:
            with open(PENDING_PUBLISH, "w", encoding="utf-8") as f:
                json.dump(items, f, indent=2, ensure_ascii=True)
            print(f"[BRIDGE] Sanitized {len(items)} pending publish items")
    except Exception as e:
        print(f"[BRIDGE] WARN: Could not sanitize pending_publish: {e}")


def load_stix_manifest() -> list:
    if not STIX_MANIFEST.exists():
        print(f"[BRIDGE] WARN: {STIX_MANIFEST} not found")
        return []
    with open(STIX_MANIFEST, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        print(f"[BRIDGE] Loaded {len(data)} items from {STIX_MANIFEST}")
        return data
    items = data.get("items", data.get("entries", data.get("advisories", [])))
    print(f"[BRIDGE] Loaded {len(items)} items from {STIX_MANIFEST}")
    return items


def load_embedded_intel() -> list:
    if not INDEX_HTML.exists():
        return []
    with open(INDEX_HTML, encoding="utf-8") as f:
        h = f.read()
    match = re.search(r"const\s+EMBEDDED_INTEL\s*=\s*(\[[\s\S]*?\]);", h)
    if not match:
        return []
    try:
        items = json.loads(match.group(1))
        print(f"[BRIDGE] Loaded {len(items)} from EMBEDDED_INTEL fallback")
        return items
    except json.JSONDecodeError:
        return []


def main():
    t0 = time.time()
    print("=" * 60)
    print("SENTINEL APEX v71.0 — Enhanced Data Bridge")
    print("=" * 60)

    raw_items = load_stix_manifest()
    if not raw_items:
        raw_items = load_embedded_intel()
    if not raw_items:
        print("[BRIDGE] CRITICAL: No data found!")
        sys.exit(1)

    converted = []
    for item in raw_items:
        try:
            converted.append(convert_stix_item(item))
        except Exception as e:
            print(f"[BRIDGE] WARN: Conversion error: {e}")
    if not converted:
        print("[BRIDGE] CRITICAL: All items failed conversion!")
        sys.exit(1)

    if len(converted) < 5:
        print(f"[BRIDGE] BLOCKED: Only {len(converted)} items — preventing manifest corruption (min: 5)")
        sys.exit(1)

    # Build CVE enrichment index
    cve_index = build_cve_index(raw_items)

    # Count stats
    all_cves = set()
    total_iocs = 0
    for adv in converted:
        all_cves.update(adv.get("cves", []))
        total_iocs += adv.get("ioc_count", 0)

    manifest = {
        "version": "70.3",
        "schema_version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "SENTINEL_APEX_DATA_BRIDGE_v2",
        "total_advisories": len(converted),
        "total_cves": len(all_cves),
        "total_iocs": total_iocs,
        "advisories": converted,
        "cve_index": cve_index,
        "metadata": {
            "source": "data_bridge_v2",
            "bridge_version": "2.0",
            "cve_enrichments": len(cve_index),
            "kev_count": sum(1 for c in cve_index.values() if c.get("kev_status")),
        },
    }

    os.makedirs(OUTPUT_MANIFEST.parent, exist_ok=True)
    with open(OUTPUT_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str, ensure_ascii=True)

    # Write CVE index separately for scoring engine
    with open(CVE_INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(cve_index, f, indent=2)

    # Sanitize pending publish queue
    sanitize_pending_publish()

    elapsed = round(time.time() - t0, 3)
    print(f"[BRIDGE] Advisories: {len(converted)}")
    print(f"[BRIDGE] CVEs: {len(all_cves)} | CVE index: {len(cve_index)} entries")
    print(f"[BRIDGE] KEV: {sum(1 for c in cve_index.values() if c.get('kev_status'))}")
    print(f"[BRIDGE] IOCs: {total_iocs}")
    print(f"[BRIDGE] Pending publish sanitized")
    print(f"[BRIDGE] Duration: {elapsed}s")
    print(f"[BRIDGE] SUCCESS")
    print("=" * 60)


if __name__ == "__main__":
    main()
