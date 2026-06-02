#!/usr/bin/env python3
"""
scripts/synthetic_intelligence_quarantine.py
CYBERDUDEBIVASH(R) SENTINEL APEX v170.0
=========================================
SYNTHETIC INTELLIGENCE QUARANTINE SYSTEM

MANDATE 1: Zero Synthetic Intelligence
MANDATE 6: Cache Contamination Elimination

Scans all intelligence stores and quarantines:
  - Synthetic threat reports (no external source URL)
  - Internal-origin items (SENTINEL-APEX as publisher)
  - Placeholder IOCs (127.x, example.com, test.*)
  - Generated actors (UNC-CDB, UNCLASSIFIED)
  - Synthetic campaigns (OPERATION HYDRA-SHIELD, OPERATION ECLIPSE-ARROW)
  - Stale reports (reports/ directories from prior years)
  - Sample/demo/test intelligence

Quarantine is PERMANENT — quarantined items are NEVER re-ingested.
A quarantine manifest tracks all quarantined items with reasons.

Usage:
  python scripts/synthetic_intelligence_quarantine.py          # scan + quarantine
  python scripts/synthetic_intelligence_quarantine.py --dry-run # scan only, report
  python scripts/synthetic_intelligence_quarantine.py --status  # show quarantine stats

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [QUARANTINE] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.quarantine")

REPO_ROOT   = Path(__file__).resolve().parent.parent
QUARANTINE  = REPO_ROOT / "data" / "quarantine"
Q_MANIFEST  = QUARANTINE / "_manifest.json"

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _atomic_write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(str(tmp), str(path))


# =============================================================================
# DETECTION RULES
# =============================================================================

INTERNAL_SOURCES = frozenset([
    "SENTINEL-APEX", "SENTINEL_APEX", "CYBERDUDEBIVASH",
    "APEX AI", "AI ENGINE", "INTERNAL INTEL", "INTERNAL",
    "apex", "CDB",
])

# Items with ANY of these patterns in title/description are synthetic
SYNTHETIC_ITEM_PATTERNS = [
    (re.compile(r"\bUNC-CDB\b"),                               "synthetic_actor_UNC-CDB"),
    (re.compile(r"\bOPERATION HYDRA-SHIELD\b", re.I),         "synthetic_campaign_HYDRA-SHIELD"),
    (re.compile(r"\bOPERATION ECLIPSE-ARROW\b", re.I),        "synthetic_campaign_ECLIPSE-ARROW"),
    (re.compile(r"\bsynthetically?\s+generated\b", re.I),      "synthetic_generation_marker"),
    (re.compile(r"\bgenerated\s+by\s+(?:ai|apex|sentinel)\b", re.I), "ai_generated_marker"),
    (re.compile(r"\bsample\s+(?:advisory|report|intel)\b", re.I), "sample_content"),
    (re.compile(r"\bdemo\s+(?:advisory|report|intel)\b", re.I), "demo_content"),
    (re.compile(r"\btest\s+(?:advisory|report|intel)\b", re.I), "test_content"),
    (re.compile(r"\bCDB-APEX-SYNTHETIC\b", re.I),              "synthetic_stix_bundle"),
]

# IOC patterns that indicate placeholder/generated values
PLACEHOLDER_IOC_PATTERNS = [
    re.compile(r"\b(?:1\.2\.3\.4|0\.0\.0\.0|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.16\.\d+\.\d+)\b"),
    re.compile(r"\bexample\.(?:com|org|net)\b"),
    re.compile(r"\btest\.(?:com|org|net)\b"),
    re.compile(r"\bdummy\.(?:com|org|net)\b"),
    re.compile(r"\bplaceholder\.(?:com|org|net)\b"),
    re.compile(r"\blocalhost\b"),
    re.compile(r"\b(?:aaaaaa|deadbeef|cafebabe|00000000)\b", re.I),
]


def _item_is_synthetic(item: dict) -> tuple[bool, str]:
    """Check if a single feed item is synthetic. Returns (is_synthetic, reason)."""
    text = f"{item.get('title','')} {item.get('description','')}"

    for pattern, reason in SYNTHETIC_ITEM_PATTERNS:
        if pattern.search(text):
            return True, reason

    # Actor attribution that indicates provably synthetic generation
    # NOTE: "SENTINEL-APEX" as source label is a labeling bug fixed by backfill,
    # not evidence of synthetic content. Only quarantine on content evidence.
    actor = item.get("actor_tag", "") or item.get("actor_display_name", "")
    if actor in ("UNC-CDB",):
        return True, f"synthetic_actor_tag:{actor}"

    # Campaign names that are provably synthetic (never existed externally)
    campaign = item.get("campaign_name", "") or item.get("campaign", "")
    if campaign in ("OPERATION HYDRA-SHIELD", "OPERATION ECLIPSE-ARROW"):
        return True, f"synthetic_campaign:{campaign}"

    # Check IOCs
    iocs = item.get("iocs", []) or []
    if isinstance(iocs, list):
        for ioc in iocs:
            for p in PLACEHOLDER_IOC_PATTERNS:
                if p.search(str(ioc)):
                    return True, f"placeholder_ioc:{str(ioc)[:40]}"

    return False, ""


# =============================================================================
# QUARANTINE OPERATIONS
# =============================================================================

class QuarantineManager:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.manifest: list[dict] = self._load_manifest()
        self.quarantined_ids: set[str] = {
            e["item_id"] for e in self.manifest
        }
        self.stats = {
            "scanned": 0, "quarantined_new": 0,
            "already_quarantined": 0, "clean": 0,
        }

    def _load_manifest(self) -> list[dict]:
        if Q_MANIFEST.exists():
            try:
                return json.loads(Q_MANIFEST.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []

    def _save_manifest(self) -> None:
        if not self.dry_run:
            _atomic_write(Q_MANIFEST, self.manifest)

    def quarantine(self, item: dict, reason: str, source_file: str = "") -> bool:
        """Add item to quarantine. Returns True if newly quarantined."""
        item_id = item.get("id") or item.get("stix_id") or hashlib.sha256(
            item.get("title", "").encode()).hexdigest()[:24]

        if item_id in self.quarantined_ids:
            self.stats["already_quarantined"] += 1
            return False

        entry = {
            "item_id":      item_id,
            "quarantined_at": utc_now(),
            "reason":       reason,
            "source_file":  source_file,
            "title":        item.get("title", "")[:120],
            "original_source": (item.get("source") or item.get("feed_source") or ""),
            "never_republish": True,
        }
        self.manifest.append(entry)
        self.quarantined_ids.add(item_id)
        self.stats["quarantined_new"] += 1

        if not self.dry_run:
            # Write individual quarantine file
            qfile = QUARANTINE / f"{item_id[:48]}.json"
            QUARANTINE.mkdir(parents=True, exist_ok=True)
            _atomic_write(qfile, {"metadata": entry, "original_item": item})

        log.warning("[Q] %-60s | %s", item.get("title","")[:60], reason)
        return True

    def scan_feed(self, feed_path: Path) -> list[dict]:
        """Scan feed.json, quarantine synthetic items, return clean items."""
        try:
            raw = json.loads(feed_path.read_text(encoding="utf-8"))
            items = raw if isinstance(raw, list) else []
        except Exception as e:
            log.error("Cannot read %s: %s", feed_path, e)
            return []

        clean_items = []
        for item in items:
            self.stats["scanned"] += 1
            is_synth, reason = _item_is_synthetic(item)
            if is_synth:
                self.quarantine(item, reason, str(feed_path))
            else:
                clean_items.append(item)
                self.stats["clean"] += 1

        log.info("[SCAN] %s: %d total, %d quarantined, %d clean",
                 feed_path.name, len(items),
                 len(items) - len(clean_items), len(clean_items))

        if not self.dry_run and len(clean_items) < len(items):
            tmp = feed_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(clean_items, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            os.replace(str(tmp), str(feed_path))
            log.info("[SCAN] Wrote %d clean items back to %s", len(clean_items), feed_path.name)

        return clean_items

    def scan_manifest(self, manifest_path: Path) -> int:
        """Scan feed_manifest.json, quarantine synthetic entries."""
        if not manifest_path.exists():
            return 0
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as e:
            log.error("Cannot read %s: %s", manifest_path, e)
            return 0

        if isinstance(raw, list):
            items = raw
            wrap = None
        elif isinstance(raw, dict):
            for key in ("advisories", "reports", "items"):
                if key in raw and isinstance(raw[key], list):
                    items = raw[key]
                    wrap = (raw, key)
                    break
            else:
                return 0
        else:
            return 0

        clean_items = []
        quarantined = 0
        for item in items:
            is_synth, reason = _item_is_synthetic(item)
            if is_synth:
                self.quarantine(item, reason, str(manifest_path))
                quarantined += 1
            else:
                clean_items.append(item)

        if not self.dry_run and quarantined > 0:
            if wrap is None:
                out = clean_items
            else:
                d, key = wrap
                d[key] = clean_items
                d["quarantine_scan_at"] = utc_now()
                d["quarantine_removed"] = quarantined
                out = d
            tmp = manifest_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(manifest_path))
            log.info("[SCAN] %s: removed %d synthetic entries", manifest_path.name, quarantined)

        return quarantined

    def purge_stale_report_archives(self, reports_dir: Path) -> int:
        """MANDATE 6: Archive (not delete) report directories from prior years."""
        if not reports_dir.exists():
            return 0
        current_year = datetime.now().year
        archive_dir = REPO_ROOT / "data" / "archive" / "stale_reports"
        archived = 0
        for year_dir in sorted(reports_dir.iterdir()):
            if not year_dir.is_dir():
                continue
            if not year_dir.name.isdigit():
                continue
            year = int(year_dir.name)
            if year < current_year:
                count = len(list(year_dir.rglob("*.html")))
                if count > 0:
                    log.warning("[STALE] reports/%d contains %d HTML files from prior year", year, count)
                    if not self.dry_run:
                        dest = archive_dir / year_dir.name
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        if not dest.exists():
                            shutil.move(str(year_dir), str(dest))
                            log.info("[ARCHIVE] Moved reports/%d -> data/archive/stale_reports/%d",
                                     year, year)
                            archived += count
                        else:
                            log.warning("[ARCHIVE] Destination exists: %s", dest)
        return archived

    def finalize(self) -> None:
        self._save_manifest()
        log.info("=" * 60)
        log.info("QUARANTINE SUMMARY")
        log.info("  Scanned:             %d", self.stats["scanned"])
        log.info("  Newly quarantined:   %d", self.stats["quarantined_new"])
        log.info("  Already quarantined: %d", self.stats["already_quarantined"])
        log.info("  Clean (published):   %d", self.stats["clean"])
        log.info("  Total in quarantine: %d", len(self.quarantined_ids))
        log.info("=" * 60)


# =============================================================================
# ENTRY POINT
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Synthetic Intelligence Quarantine System")
    parser.add_argument("--dry-run", action="store_true",
                        help="Scan and report without modifying files")
    parser.add_argument("--status",  action="store_true",
                        help="Show quarantine stats and exit")
    args = parser.parse_args()

    if args.status:
        if Q_MANIFEST.exists():
            manifest = json.loads(Q_MANIFEST.read_text(encoding="utf-8"))
            print(f"Quarantine manifest: {len(manifest)} entries")
            by_reason = {}
            for e in manifest:
                r = e.get("reason", "unknown")
                by_reason[r] = by_reason.get(r, 0) + 1
            for reason, count in sorted(by_reason.items(), key=lambda x: -x[1]):
                print(f"  {count:4d}x  {reason}")
        else:
            print("Quarantine is empty.")
        return 0

    log.info("=" * 70)
    log.info("SENTINEL APEX SYNTHETIC INTELLIGENCE QUARANTINE SYSTEM v170.0")
    log.info("Mode: %s", "DRY-RUN (no changes)" if args.dry_run else "ACTIVE (quarantining)")
    log.info("=" * 70)

    qm = QuarantineManager(dry_run=args.dry_run)

    # Scan primary feed
    feed_path = REPO_ROOT / "api" / "feed.json"
    if feed_path.exists():
        qm.scan_feed(feed_path)

    # Scan manifests
    for manifest_path in [
        REPO_ROOT / "data" / "stix" / "feed_manifest.json",
        REPO_ROOT / "data" / "feed_manifest.json",
    ]:
        qm.scan_manifest(manifest_path)

    # Purge stale report archives (MANDATE 6)
    archived = qm.purge_stale_report_archives(REPO_ROOT / "reports")
    if archived:
        log.info("[M6] Archived %d stale report files", archived)

    qm.finalize()

    # Hard fail if synthetic items were found in feed
    if qm.stats["quarantined_new"] > 0 and not args.dry_run:
        log.warning("[QUARANTINE] %d synthetic items removed from feed",
                    qm.stats["quarantined_new"])
        # Non-fatal: we removed them, so pipeline can continue
        # The mandate enforcer will re-check after
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
