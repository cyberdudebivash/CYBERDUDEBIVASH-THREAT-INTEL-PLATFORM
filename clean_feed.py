#!/usr/bin/env python3
"""
clean_feed.py — P0 Feed Decontamination Script
CYBERDUDEBIVASH® SENTINEL APEX
==============================================
Re-extracts IOCs for every item in the live feed using the fixed
ioc_engine.py.  Removes false positives introduced before the P0 fix.

Usage:  python3 clean_feed.py [--dry-run]
"""
from __future__ import annotations
import json, os, sys, copy, shutil
from datetime import datetime, timezone

sys.path.insert(0, ".")

from agent.ioc_engine import (
    extract_iocs_from_manifest_entry,
    enforce_ioc_integrity,
    _is_valid_extracted_domain,
    _DOMAIN_BLOCKLIST,
)
from urllib.parse import urlparse

DRY_RUN = "--dry-run" in sys.argv

FEED_FILES = [
    "feed.json",
    "api/v1/intel/latest.json",
    "api/v1/intel/apex.json",
]

def _is_valid_ioc_url(url: str) -> bool:
    """Reject source/reference URLs — only keep genuine C2/malware URLs."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        base = ".".join(hostname.split(".")[-2:]) if hostname else ""
        return hostname not in _DOMAIN_BLOCKLIST and base not in _DOMAIN_BLOCKLIST
    except Exception:
        return False


def clean_item(entry: dict) -> dict:
    """Fresh-extract IOCs for one feed item using the fixed engine."""
    entry = dict(entry)

    # Fresh extraction from text fields
    result = extract_iocs_from_manifest_entry(entry)

    # Also scrub any existing IOCs stored in the entry
    entry.update(result.to_manifest_fields())

    # URL scrub — remove any vulners.com / nvd / reference source URLs
    urls = entry.get("iocs_by_type", {}).get("url", [])
    if urls:
        clean_urls = [u for u in urls if _is_valid_ioc_url(u)]
        if len(clean_urls) != len(urls):
            entry["iocs_by_type"]["url"] = clean_urls
            # Rebuild flat list
            flat = entry.get("iocs", [])
            flat = [x for x in flat if not any(u in x for u in urls if u not in clean_urls)]
            entry["iocs"] = flat
            entry["ioc_count"] = len(flat)

    # Run enforce_ioc_integrity for Case 4 domain scrub + invariant
    entry = enforce_ioc_integrity(entry)

    return entry


def process_file(path: str) -> dict:
    """Process one feed file. Returns stats dict."""
    if not os.path.exists(path):
        return {"path": path, "status": "NOT_FOUND"}

    raw = json.load(open(path, encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("items", raw.get("feed", raw.get("data", [])))

    if not isinstance(items, list):
        return {"path": path, "status": "SKIP_NON_LIST", "size": os.path.getsize(path)}

    # Count contamination before
    before_store_ts  = sum(1 for i in items if isinstance(i, dict) and "store.ts" in i.get("iocs", []))
    before_vulners   = sum(1 for i in items if isinstance(i, dict) and
                          any("vulners.com" in u for u in i.get("iocs_by_type", {}).get("url", [])))
    before_critical  = sum(1 for i in items if isinstance(i, dict) and i.get("ioc_threat_level") == "CRITICAL")

    cleaned_items = [clean_item(dict(i)) if isinstance(i, dict) else i for i in items]

    # Count contamination after
    after_store_ts   = sum(1 for i in cleaned_items if "store.ts" in i.get("iocs", []))
    after_vulners    = sum(1 for i in cleaned_items if
                          any("vulners.com" in u for u in i.get("iocs_by_type", {}).get("url", [])))
    after_critical   = sum(1 for i in cleaned_items if i.get("ioc_threat_level") == "CRITICAL")

    stats = {
        "path": path,
        "items": len(items),
        "before": {"store_ts": before_store_ts, "vulners_urls": before_vulners, "critical": before_critical},
        "after":  {"store_ts": after_store_ts,  "vulners_urls": after_vulners,  "critical": after_critical},
        "p0_cleared": after_store_ts == 0 and after_vulners == 0,
    }

    if not DRY_RUN:
        # Backup original
        backup = path + f".pre_p0_fix_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(path, backup)

        # Write cleaned version
        if isinstance(raw, list):
            out = cleaned_items
        else:
            out = dict(raw)
            # Find the right key
            for k in ("items", "feed", "data"):
                if k in raw:
                    out[k] = cleaned_items
                    break
            else:
                out = cleaned_items

        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False, default=str)
        stats["status"] = "CLEANED"
        stats["backup"] = backup
    else:
        stats["status"] = "DRY_RUN"

    return stats


print("=" * 60)
print("  SENTINEL APEX — P0 Feed Decontamination")
print("  Mode:", "DRY RUN" if DRY_RUN else "LIVE WRITE")
print("=" * 60)

all_ok = True
for fp in FEED_FILES:
    s = process_file(fp)
    print(f"\n{s['path']} [{s['status']}]")
    if s.get("items"):
        print(f"  Items: {s['items']}")
        print(f"  BEFORE → store.ts={s['before']['store_ts']}  vulners_url={s['before']['vulners_urls']}  CRITICAL={s['before']['critical']}")
        print(f"  AFTER  → store.ts={s['after']['store_ts']}   vulners_url={s['after']['vulners_urls']}   CRITICAL={s['after']['critical']}")
        print(f"  P0 CLEARED: {'YES ✅' if s['p0_cleared'] else 'NO ❌'}")
        if not s["p0_cleared"]:
            all_ok = False
    else:
        print(f"  {s}")

print("\n" + "=" * 60)
if all_ok:
    print("✅  ALL FEEDS DECONTAMINATED — P0 RESOLVED")
else:
    print("❌  WARNING: Some feeds still have contamination")
print("=" * 60)
sys.exit(0 if all_ok else 1)
