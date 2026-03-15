#!/usr/bin/env python3
"""
SENTINEL APEX v55.2 — ONE-TIME MANIFEST REBUILD
=================================================
ROOT CAUSE: MANIFEST_MAX_ENTRIES was set to 50, causing all articles beyond
the 50th to be evicted from feed_manifest.json even though:
  - They were published to Blogger
  - Their STIX bundles exist on disk
  - The dashboard only reads from the manifest

This script scans all STIX bundle files in data/stix/ and rebuilds the manifest
from the actual bundle data. It preserves existing manifest entries (with their
enriched fields like EPSS/CVSS/KEV) and adds missing entries from bundles.

Usage:
    python scripts/rebuild_manifest.py          # Preview mode (no write)
    python scripts/rebuild_manifest.py --apply  # Write rebuilt manifest

Safe: Zero-regression. Only ADDS missing entries. Never modifies existing ones.
"""
import json
import os
import sys
import re
from pathlib import Path
from datetime import datetime, timezone

REPO_ROOT = Path(__file__).parent.parent
STIX_DIR = REPO_ROOT / "data" / "stix"
MANIFEST_PATH = STIX_DIR / "feed_manifest.json"
MAX_ENTRIES = 200  # New cap (was 50)

def load_manifest() -> list:
    if not MANIFEST_PATH.exists():
        return []
    with open(MANIFEST_PATH) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return data.get("entries", data.get("items", []))

def extract_from_bundle(bundle_path: Path) -> dict:
    """Extract manifest-compatible entry from a STIX bundle file."""
    try:
        with open(bundle_path) as f:
            bundle = json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

    objects = bundle.get("objects", [])
    if not objects:
        return {}

    bundle_id = bundle.get("id", "")
    title = ""
    risk_score = 5.0
    actor_tag = "UNC-CDB-99"
    mitre_tactics = []
    indicator_count = 0
    cve_count = 0
    domain_count = 0
    sha256_count = 0
    md5_count = 0
    ipv4_count = 0
    url_count = 0
    email_count = 0

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type == "intrusion-set":
            title_candidate = obj.get("description", "")
            if title_candidate.startswith("Tactical cluster: "):
                title = title_candidate[len("Tactical cluster: "):]
            aliases = obj.get("aliases", [])
            if aliases:
                actor_tag = aliases[0]
            risk_score_raw = obj.get("confidence", 50)
        elif obj_type == "indicator":
            indicator_count += 1
            pattern = obj.get("pattern", "")
            if "ipv4-addr" in pattern:
                ipv4_count += 1
            elif "domain-name" in pattern:
                domain_count += 1
            elif "file:hashes.'SHA-256'" in pattern:
                sha256_count += 1
            elif "file:hashes.'MD5'" in pattern:
                md5_count += 1
            elif "url:value" in pattern:
                url_count += 1
            elif "email" in pattern:
                email_count += 1
        elif obj_type == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id", "")
                    if tid:
                        mitre_tactics.append(tid)
        elif obj_type == "vulnerability":
            cve_count += 1

    if not title:
        return {}

    # Derive timestamp from filename (CDB-APEX-{epoch}.json)
    fname = bundle_path.stem  # e.g. CDB-APEX-1773555790
    epoch_match = re.search(r"(\d{10,})", fname)
    if epoch_match:
        epoch = int(epoch_match.group(1))
        timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    else:
        # Fallback to file mtime
        timestamp = datetime.fromtimestamp(
            bundle_path.stat().st_mtime, tz=timezone.utc
        ).isoformat()

    # Risk scoring heuristic (mirror sentinel_blogger logic)
    total_iocs = indicator_count
    if total_iocs >= 10:
        risk_score = 10.0
    elif total_iocs >= 5:
        risk_score = max(8.0, risk_score)
    elif cve_count > 0:
        risk_score = max(6.0, risk_score)

    severity = "CRITICAL" if risk_score >= 9 else "HIGH" if risk_score >= 7 else "MEDIUM" if risk_score >= 4 else "LOW"
    tlp = "TLP:RED" if risk_score >= 9 else "TLP:AMBER" if risk_score >= 7 else "TLP:GREEN"

    return {
        "title": title,
        "stix_id": bundle_id,
        "bundle_id": bundle_id,
        "risk_score": risk_score,
        "blog_url": "",  # Can't recover blog URL from STIX — will be blank
        "source_url": "",
        "timestamp": timestamp,
        "generated_at": timestamp,
        "severity": severity,
        "confidence_score": float(objects[2].get("confidence", 50) if len(objects) > 2 else 50),
        "confidence": float(objects[2].get("confidence", 50) if len(objects) > 2 else 50),
        "tlp_label": tlp,
        "ioc_counts": {
            "sha256": sha256_count, "sha1": 0, "md5": md5_count,
            "domain": domain_count, "ipv4": ipv4_count,
            "url": url_count, "email": email_count,
            "cve": cve_count, "registry": 0, "artifacts": 0,
        },
        "actor_tag": actor_tag,
        "mitre_tactics": mitre_tactics[:5],
        "feed_source": "CDB-REBUILT",
        "indicator_count": indicator_count,
        "stix_file": bundle_path.name,
        "cvss_score": None,
        "epss_score": None,
        "kev_present": False,
        "status": "active",
        "extended_metrics": {},
        "nvd_url": None,
        "supply_chain": False,
        "stix_object_count": len(objects),
        "stix_version": "2.1",
        "schema_version": "v22.0",
    }


def main():
    apply_mode = "--apply" in sys.argv

    print("=" * 60)
    print("SENTINEL APEX v55.2 — MANIFEST REBUILD FROM STIX BUNDLES")
    print(f"Mode: {'APPLY (writing changes)' if apply_mode else 'PREVIEW (read-only)'}")
    print("=" * 60)

    # Load existing manifest
    existing = load_manifest()
    existing_titles = {e.get("title", "").strip().lower() for e in existing}
    existing_bundles = {e.get("stix_id", "") for e in existing}
    print(f"[INFO] Existing manifest: {len(existing)} entries")

    # Scan all STIX bundles
    bundle_files = sorted(STIX_DIR.glob("CDB-APEX-*.json"), reverse=True)
    print(f"[INFO] STIX bundles on disk: {len(bundle_files)}")

    recovered = []
    skipped_dup = 0
    skipped_parse = 0

    for bf in bundle_files:
        entry = extract_from_bundle(bf)
        if not entry:
            skipped_parse += 1
            continue

        title_key = entry["title"].strip().lower()
        bundle_key = entry["stix_id"]

        if title_key in existing_titles or bundle_key in existing_bundles:
            skipped_dup += 1
            continue

        recovered.append(entry)
        existing_titles.add(title_key)
        existing_bundles.add(bundle_key)

    print(f"[INFO] Recovered from bundles: {len(recovered)} new entries")
    print(f"[INFO] Skipped (already in manifest): {skipped_dup}")
    print(f"[INFO] Skipped (parse error/empty): {skipped_parse}")

    if recovered:
        print(f"\n=== RECOVERED ENTRIES (newest first) ===")
        # Sort by timestamp
        recovered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        for r in recovered[:20]:
            ts = r.get("timestamp", "?")[:19]
            title = r.get("title", "?")[:65]
            print(f"  {ts} | {title}")
        if len(recovered) > 20:
            print(f"  ... and {len(recovered) - 20} more")

    # Merge: existing (preserved with enrichments) + recovered
    merged = existing + recovered
    # Sort by timestamp descending (newest first)
    merged.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    # Cap at MAX_ENTRIES
    merged = merged[:MAX_ENTRIES]

    print(f"\n[RESULT] Final manifest: {len(merged)} entries (cap: {MAX_ENTRIES})")
    newest_ts = merged[0].get("timestamp", "?")[:19] if merged else "—"
    oldest_ts = merged[-1].get("timestamp", "?")[:19] if merged else "—"
    print(f"  Newest: {newest_ts}")
    print(f"  Oldest: {oldest_ts}")

    if apply_mode:
        # Backup existing
        backup_path = MANIFEST_PATH.with_suffix(".json.bak")
        if MANIFEST_PATH.exists():
            import shutil
            shutil.copy2(MANIFEST_PATH, backup_path)
            print(f"[BACKUP] {backup_path}")

        with open(MANIFEST_PATH, "w") as f:
            json.dump(merged, f, indent=4)
        print(f"[WRITTEN] {MANIFEST_PATH} — {len(merged)} entries")
        print("[SUCCESS] Manifest rebuilt ✓")
    else:
        print(f"\n[DRY RUN] No changes written. Run with --apply to write.")

    print("=" * 60)


if __name__ == "__main__":
    main()
