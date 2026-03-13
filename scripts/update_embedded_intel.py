#!/usr/bin/env python3
"""
SENTINEL APEX — Auto-update EMBEDDED_INTEL in index.html
Runs post-pipeline to keep dashboard fallback cache always current.
Merges feed_manifest.json + enriched_manifest.json → patches index.html

Usage: python3 scripts/update_embedded_intel.py
CI:    Add as final step in any workflow that updates feed_manifest.json
"""
import json
import os
import sys
import re
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent.parent
INDEX_HTML = REPO_ROOT / "index.html"
FEED_MANIFEST = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
ENRICHED_MANIFEST = REPO_ROOT / "data" / "v46_ultraintel" / "enriched_manifest.json"

ENRICHMENT_KEYS = [
    "actor_profile", "sector_tags", "exploit_status",
    "cwe_classification", "intel_quality"
]


def load_manifest(path: Path) -> list:
    """Load and normalise manifest into a flat list."""
    if not path.exists():
        print(f"[WARN] Manifest not found: {path}")
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return data.get("items", data.get("entries", []))


def merge_intelligence(feed: list, enriched: list) -> list:
    """Merge enriched v46 fields onto feed_manifest items."""
    enriched_lookup = {item.get("stix_id", ""): item for item in enriched}
    merged = []
    for item in feed:
        sid = item.get("stix_id", "")
        merged_item = dict(item)
        if sid in enriched_lookup:
            enc = enriched_lookup[sid]
            for key in ENRICHMENT_KEYS:
                if key in enc:
                    merged_item[key] = enc[key]
        merged.append(merged_item)
    return merged


def patch_index_html(merged: list) -> bool:
    """Surgically replace EMBEDDED_INTEL in index.html."""
    if not INDEX_HTML.exists():
        print(f"[ERROR] index.html not found at {INDEX_HTML}")
        return False

    with open(INDEX_HTML, encoding="utf-8") as f:
        html = f.read()

    # Build new EMBEDDED_INTEL block
    compact_json = json.dumps(merged, separators=(",", ":"), ensure_ascii=False)
    new_block = f"        const EMBEDDED_INTEL = {compact_json};"

    # Match existing EMBEDDED_INTEL assignment (handles any existing data shape)
    pattern = r"        const EMBEDDED_INTEL = \[[\s\S]*?\];"
    if not re.search(pattern, html):
        print("[ERROR] EMBEDDED_INTEL pattern not found in index.html")
        return False

    patched = re.sub(pattern, new_block, html, count=1)

    if patched == html:
        print("[INFO] EMBEDDED_INTEL unchanged — possibly already current")
        return True  # Not a failure

    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(patched)

    return True


def compute_kpis(merged: list) -> dict:
    """Compute summary KPIs for CI log output."""
    critical = sum(1 for i in merged if (i.get("risk_score") or 0) >= 9)
    high = sum(1 for i in merged if 7 <= (i.get("risk_score") or 0) < 9)
    kev = sum(1 for i in merged if i.get("kev_present"))
    enriched = sum(1 for i in merged if any(k in i for k in ENRICHMENT_KEYS))
    latest = max((i.get("timestamp", "") for i in merged), default="—")
    return {
        "total": len(merged), "critical": critical, "high": high,
        "kev": kev, "enriched": enriched, "latest": latest
    }


def main():
    print("=" * 60)
    print("SENTINEL APEX — EMBEDDED_INTEL AUTO-UPDATER")
    print(f"Run: {datetime.utcnow().isoformat()}Z")
    print("=" * 60)

    feed = load_manifest(FEED_MANIFEST)
    enriched = load_manifest(ENRICHED_MANIFEST)

    if not feed:
        print("[ERROR] feed_manifest.json is empty or missing — aborting")
        sys.exit(1)

    print(f"[INFO] feed_manifest: {len(feed)} items")
    print(f"[INFO] enriched_manifest: {len(enriched)} items")

    merged = merge_intelligence(feed, enriched)
    kpis = compute_kpis(merged)

    print(
        f"[INFO] Merged: {kpis['total']} items | "
        f"CRITICAL:{kpis['critical']} HIGH:{kpis['high']} "
        f"KEV:{kpis['kev']} | Enriched:{kpis['enriched']} | "
        f"Latest: {kpis['latest']}"
    )

    success = patch_index_html(merged)
    if success:
        print("[SUCCESS] index.html EMBEDDED_INTEL patched ✓")
    else:
        print("[ERROR] Patch failed")
        sys.exit(1)

    print("=" * 60)


if __name__ == "__main__":
    main()
