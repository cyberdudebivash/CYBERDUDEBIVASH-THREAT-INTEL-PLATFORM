#!/usr/bin/env python3
"""
SENTINEL APEX v70 — Data Bridge (CRITICAL)
============================================
Reads the REAL data sources in this repo and produces
data/feed_manifest.json in the format the v70 orchestrator expects.

Actual data locations:
  - data/stix/feed_manifest.json  (401+ advisories, plain JSON array)
  - EMBEDDED_INTEL in index.html  (backup source)

Output:
  - data/feed_manifest.json       ({"version":..., "advisories":[...]})

This script MUST run BEFORE the v70 orchestrator.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
STIX_MANIFEST = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
INDEX_HTML = REPO_ROOT / "index.html"
OUTPUT_MANIFEST = REPO_ROOT / "data" / "feed_manifest.json"


def extract_cve_from_title(title: str) -> list:
    """Extract CVE IDs from advisory title."""
    if not title:
        return []
    return re.findall(r"CVE-\d{4}-\d{4,}", title, re.IGNORECASE)


def convert_stix_item(item: dict) -> dict:
    """
    Convert a real STIX manifest item into the format
    the v70 orchestrator expects.
    """
    title = item.get("title", "")
    cves = extract_cve_from_title(title)

    # Build IOC list from ioc_counts
    ioc_counts = item.get("ioc_counts", {})
    iocs = []
    # We don't have the actual IOC values from the manifest,
    # but we track the count for scoring purposes

    # MITRE techniques
    mitre_raw = item.get("mitre_tactics", "")
    mitre_techniques = []
    if isinstance(mitre_raw, str) and mitre_raw:
        # Could be comma-separated or JSON
        mitre_techniques = [t.strip() for t in mitre_raw.split(",") if t.strip()]
    elif isinstance(mitre_raw, list):
        mitre_techniques = mitre_raw

    # Severity normalization
    sev = (item.get("severity", "") or "").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "info"

    # Actor from actor_tag
    actors = []
    actor_tag = item.get("actor_tag", "")
    if actor_tag and isinstance(actor_tag, str) and actor_tag.lower() not in ("", "none", "unknown", "n/a"):
        actors = [actor_tag]

    # Source name from feed_source or source_url
    source_name = item.get("feed_source", "")
    source_url = item.get("source_url", "")
    if not source_name and source_url:
        # Extract domain as source name
        try:
            from urllib.parse import urlparse
            source_name = urlparse(source_url).netloc
        except Exception:
            source_name = "Unknown"

    # IOC count for scoring
    total_iocs = item.get("indicator_count", 0) or 0
    if not total_iocs and ioc_counts:
        total_iocs = sum(v for v in ioc_counts.values() if isinstance(v, (int, float)))

    # Build normalized advisory
    return {
        "title": title,
        "description": title,  # Use title as description (actual desc not in manifest)
        "source": source_name,
        "source_url": source_url,
        "link": source_url,
        "published": item.get("timestamp", ""),
        "published_date": item.get("timestamp", ""),
        "severity": sev,
        "confidence": float(item.get("confidence_score", 0) or item.get("confidence", 0) or 0),
        "threat_score": float(item.get("risk_score", 0) or 0),
        "cves": cves,
        "iocs": [],  # Actual IOC values not in manifest; count used for scoring
        "ioc_count": total_iocs,
        "actors": actors,
        "mitre_techniques": mitre_techniques,
        "tags": [],
        # Preserve original fields
        "stix_id": item.get("stix_id", ""),
        "bundle_id": item.get("bundle_id", ""),
        "blog_post_url": item.get("blog_url", ""),
        "blog_url": item.get("blog_url", ""),
        "cvss_score": float(item.get("cvss_score", 0) or 0),
        "epss_score": float(item.get("epss_score", 0) or 0),
        "kev_present": bool(item.get("kev_present", False)),
        "tlp_label": item.get("tlp_label", ""),
        "nvd_url": item.get("nvd_url", ""),
        "feed_source": source_name,
        "indicator_count": total_iocs,
    }


def load_stix_manifest() -> list:
    """Load advisories from data/stix/feed_manifest.json."""
    if not STIX_MANIFEST.exists():
        print(f"[BRIDGE] WARN: {STIX_MANIFEST} not found")
        return []

    with open(STIX_MANIFEST, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        print(f"[BRIDGE] Loaded {len(data)} items from {STIX_MANIFEST}")
        return data
    elif isinstance(data, dict):
        items = data.get("items", data.get("entries", data.get("advisories", [])))
        print(f"[BRIDGE] Loaded {len(items)} items from {STIX_MANIFEST} (dict format)")
        return items

    return []


def load_embedded_intel() -> list:
    """Fallback: extract EMBEDDED_INTEL from index.html."""
    if not INDEX_HTML.exists():
        return []

    with open(INDEX_HTML, encoding="utf-8") as f:
        html = f.read()

    match = re.search(r"const\s+EMBEDDED_INTEL\s*=\s*(\[[\s\S]*?\]);", html)
    if not match:
        return []

    try:
        items = json.loads(match.group(1))
        print(f"[BRIDGE] Loaded {len(items)} items from EMBEDDED_INTEL fallback")
        return items
    except json.JSONDecodeError:
        return []


def build_manifest(advisories: list) -> dict:
    """Build the v70-compatible manifest dict."""
    all_cves = set()
    total_iocs = 0
    for adv in advisories:
        all_cves.update(adv.get("cves", []))
        total_iocs += adv.get("ioc_count", 0) or len(adv.get("iocs", []))

    return {
        "version": "70.0",
        "schema_version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "SENTINEL_APEX_DATA_BRIDGE",
        "total_advisories": len(advisories),
        "total_cves": len(all_cves),
        "total_iocs": total_iocs,
        "advisories": advisories,
        "metadata": {
            "source": "data_bridge",
            "stix_manifest": str(STIX_MANIFEST),
            "bridge_version": "1.0",
        },
    }


def main():
    print("=" * 60)
    print("SENTINEL APEX v70 — Data Bridge")
    print("=" * 60)

    # Phase 1: Load from STIX manifest (primary source)
    raw_items = load_stix_manifest()

    # Phase 2: Fallback to EMBEDDED_INTEL if STIX manifest empty
    if not raw_items:
        print("[BRIDGE] STIX manifest empty — trying EMBEDDED_INTEL fallback")
        raw_items = load_embedded_intel()

    # Phase 3: HARD FAIL if no data at all
    if not raw_items:
        print("[BRIDGE] CRITICAL: No data found in ANY source!")
        print(f"  Checked: {STIX_MANIFEST}")
        print(f"  Checked: {INDEX_HTML} (EMBEDDED_INTEL)")
        sys.exit(1)

    # Phase 4: Convert to orchestrator format
    converted = []
    for item in raw_items:
        try:
            converted.append(convert_stix_item(item))
        except Exception as e:
            print(f"[BRIDGE] WARN: Failed to convert item: {e}")
            continue

    if not converted:
        print("[BRIDGE] CRITICAL: All items failed conversion!")
        sys.exit(1)

    print(f"[BRIDGE] Converted {len(converted)} / {len(raw_items)} items")

    # Phase 5: Build and write manifest
    manifest = build_manifest(converted)

    os.makedirs(OUTPUT_MANIFEST.parent, exist_ok=True)
    with open(OUTPUT_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    # Verify
    with open(OUTPUT_MANIFEST, "r") as f:
        verify = json.load(f)

    adv_count = len(verify.get("advisories", []))
    print(f"[BRIDGE] Written: {OUTPUT_MANIFEST}")
    print(f"[BRIDGE] Advisories: {adv_count}")
    print(f"[BRIDGE] CVEs: {verify.get('total_cves', 0)}")
    print(f"[BRIDGE] IOCs: {verify.get('total_iocs', 0)}")

    if adv_count == 0:
        print("[BRIDGE] CRITICAL: Written manifest has 0 advisories!")
        sys.exit(1)

    print(f"[BRIDGE] SUCCESS — {adv_count} advisories ready for v70 orchestrator")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
