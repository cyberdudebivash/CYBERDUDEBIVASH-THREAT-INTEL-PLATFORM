#!/usr/bin/env python3
"""
clean_feed_manifest.py — v110.1
Removes brand/identity entries and deduplicates feed_manifest.json.
Run once to clean existing data; future entries blocked by export_stix.py filter.
"""
import json, sys, os
from pathlib import Path

MANIFEST_PATH = Path("data/stix/feed_manifest.json")
BRAND_KEYWORDS = [
    "CYBERDUDEBIVASH® PRIVATE LIMITED",
    "OFFICIAL WORKPLACE",
    "GST & PAN VERIFIED",
    "GLOBAL CYBERSECURITY AUTHORITY",
]

def clean_manifest():
    if not MANIFEST_PATH.exists():
        print(f"[SKIP] {MANIFEST_PATH} not found")
        return

    with open(MANIFEST_PATH) as f:
        data = json.load(f)

    is_dict = isinstance(data, dict)
    items = data.get("advisories", data.get("reports", data if isinstance(data, list) else []))

    original_count = len(items)
    brand_removed  = 0
    dedup_removed  = 0
    seen_titles    = set()
    clean_items    = []

    for item in items:
        title = (item.get("title") or item.get("name") or "").strip()
        if not title:
            continue

        # Filter brand entries
        if any(kw in title for kw in BRAND_KEYWORDS):
            brand_removed += 1
            continue

        # Deduplicate by title (case-insensitive)
        title_lc = title.lower()
        if title_lc in seen_titles:
            dedup_removed += 1
            continue
        seen_titles.add(title_lc)

        # Fix "Tactical cluster: " prefix in description
        desc = item.get("description", "")
        if desc.startswith("Tactical cluster: "):
            item["description"] = desc[len("Tactical cluster: "):]

        clean_items.append(item)

    final_count = len(clean_items)
    print(f"[MANIFEST CLEAN] Original: {original_count} | Brand removed: {brand_removed} | Dedup removed: {dedup_removed} | Final: {final_count}")

    if is_dict:
        key = "advisories" if "advisories" in data else "reports"
        data[key] = clean_items
        data["total_reports"] = final_count
        data["cleaned_at"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        output = data
    else:
        output = clean_items

    with open(MANIFEST_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[OK] Cleaned manifest written to {MANIFEST_PATH}")
    return final_count

if __name__ == "__main__":
    os.chdir(Path(__file__).parent.parent)
    clean_manifest()
