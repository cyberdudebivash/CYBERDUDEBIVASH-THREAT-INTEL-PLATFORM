#!/usr/bin/env python3
"""
=============================================================================
CYBERDUDEBIVASH® SENTINEL APEX v101 — CRITICAL FILE BOOTSTRAP
=============================================================================
Purpose : Self-healing bootstrap that ensures ALL pipeline-critical files
          exist before any workflow proceeds. If files are missing (e.g. after
          fresh checkout, git reset, or partial failure), this script either:
          a) Regenerates from existing STIX bundles
          b) Creates a valid skeleton so downstream steps never abort on FileNotFoundError
=============================================================================
Run     : python3 scripts/bootstrap_critical_files.py
Exit    : 0 always (self-healing — never blocks the pipeline)
=============================================================================
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STIX_DIR = ROOT / "data" / "stix"
API_DIR  = ROOT / "api"
DATA_DIR = ROOT / "data"
PLATFORM = "CYBERDUDEBIVASH SENTINEL APEX"
VERSION  = "101.0.0"

# Minimum number of advisories a manifest must have to be considered valid.
# If the file exists but has fewer entries than this, the bootstrap FORCES a
# full rebuild from STIX bundles. This prevents sentinel_blogger.py from
# overwriting the full manifest with only the per-run 1-entry slice.
MIN_MANIFEST_ENTRIES = 50


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs():
    dirs = [
        STIX_DIR,
        API_DIR,
        DATA_DIR / "status",
        DATA_DIR / "health",
        DATA_DIR / "ai_predictions",
        DATA_DIR / "bughunter",
        DATA_DIR / "genesis",
        DATA_DIR / "analyst",
        DATA_DIR / "arsenal",
        DATA_DIR / "convergence",
        DATA_DIR / "intelligence" / "detection_rules",
        DATA_DIR / "enrichment",
        DATA_DIR / "stix",
        DATA_DIR / "logs",
        DATA_DIR / "status",
        DATA_DIR / "sync_marker" if False else DATA_DIR,  # noqa (keep single data dir)
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def load_stix_entries() -> list:
    """Reconstruct advisory entries from individual STIX bundle files."""
    stix_files = sorted(f for f in STIX_DIR.iterdir()
                        if f.name.startswith("CDB-APEX-") and f.name.endswith(".json"))
    if not stix_files:
        return []

    entries = []
    seen_titles: set = set()

    for fpath in stix_files:
        try:
            bundle = json.loads(fpath.read_text(encoding="utf-8"))
            objs = bundle.get("objects", [])

            primary = (
                next((o for o in objs if o.get("type") == "intrusion-set"), None)
                or next((o for o in objs if o.get("type") == "report"), None)
            )
            if not primary:
                continue

            description = primary.get("description", "")
            m = re.search(r"Tactical cluster: (.+)", description)
            title = m.group(1).strip() if m else primary.get("name", description[:120])
            title = title[:200]

            if title in seen_titles:
                continue
            seen_titles.add(title)

            created  = primary.get("created", primary.get("first_seen", now_iso()))
            confidence = int(primary.get("confidence", 70))
            risk_score = round(confidence / 10.0, 1)

            tl = (title + description).lower()
            if any(k in tl for k in ["critical", "zero-day", "zero day", "ransomware", "rce", "remote code"]):
                severity = "CRITICAL"
            elif any(k in tl for k in ["high", "exploit", "backdoor", "malware", "trojan", "infostealer"]):
                severity = "HIGH"
            elif any(k in tl for k in ["low", "minor"]):
                severity = "LOW"
            else:
                severity = "MEDIUM"

            indicators = [o for o in objs if o.get("type") == "indicator"]
            iocs = []
            for ind in indicators[:5]:
                im = re.search(r"= '([^']+)'", ind.get("pattern", ""))
                if im and im.group(1) not in iocs:
                    iocs.append(im.group(1))

            attack_patterns = list(dict.fromkeys(
                o.get("name", "") for o in objs
                if o.get("type") == "attack-pattern" and o.get("name")
            ))[:5]

            entries.append({
                "id": primary.get("id", f"intel--{fpath.stem}"),
                "title": title,
                "description": description[:300],
                "severity": severity,
                "risk_score": risk_score,
                "confidence": confidence,
                "timestamp": created,
                "source": PLATFORM,
                "stix_bundle": fpath.name,
                "iocs": iocs,
                "ttps": attack_patterns,
                "tags": primary.get("labels", []),
            })
        except Exception as exc:  # noqa: BLE001
            print(f"  [bootstrap] WARN: could not parse {fpath.name}: {exc}")

    entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return entries


def write_json(path: Path, data: dict, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if compact:
        path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    else:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _count_manifest_entries(path: Path) -> int:
    """Return the number of advisories in a manifest file; 0 on any error."""
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(existing, list):
            return len(existing)
        for key in ("advisories", "entries", "items"):
            val = existing.get(key)
            if isinstance(val, list):
                return len(val)
        return 0
    except Exception:
        return 0


def _best_existing_manifest() -> tuple:
    """
    Scan all known manifest locations and return (path, entry_count) for the
    one with the most advisories.  Returns (None, 0) if none found.

    Priority order (tried in order, winner = most entries):
      1. data/feed_manifest.json          — v70 orchestrator writes here (richest)
      2. data/stix/feed_manifest.json     — bootstrap / sentinel_blogger
    """
    candidates = [
        DATA_DIR / "feed_manifest.json",
        STIX_DIR / "feed_manifest.json",
    ]
    best_path, best_count = None, 0
    for p in candidates:
        if p.exists() and p.stat().st_size > 100:
            n = _count_manifest_entries(p)
            if n > best_count:
                best_count = n
                best_path = p
    return best_path, best_count


def _write_manifest(entries: list, path: Path) -> None:
    """Serialise entries into the canonical manifest schema and write to path."""
    critical = sum(1 for e in entries if e["severity"] == "CRITICAL")
    high     = sum(1 for e in entries if e["severity"] == "HIGH")
    avg_risk = round(sum(e["risk_score"] for e in entries) / len(entries), 2)
    manifest = {
        "version": VERSION, "platform": PLATFORM,
        "generated_at": now_iso(),
        "entry_count": len(entries),
        "summary": {
            "critical": critical, "high": high,
            "medium": sum(1 for e in entries if e["severity"] == "MEDIUM"),
            "low": sum(1 for e in entries if e["severity"] == "LOW"),
            "avg_risk_score": avg_risk,
        },
        "advisories": entries,
    }
    write_json(path, manifest, compact=True)


def bootstrap_feed_manifest(entries: list) -> None:
    """
    Ensure data/stix/feed_manifest.json AND data/feed_manifest.json both
    contain a full advisory set (>= MIN_MANIFEST_ENTRIES).

    Decision logic:
      1. Find the existing manifest with the most entries.
      2. If it has >= MIN_MANIFEST_ENTRIES → copy it to both canonical paths
         (no STIX rebuild needed).
      3. If no manifest meets the threshold → rebuild from STIX bundles and
         write to both paths.
    """
    stix_path = STIX_DIR / "feed_manifest.json"
    root_path = DATA_DIR / "feed_manifest.json"  # v70 orchestrator path

    best_path, best_count = _best_existing_manifest()

    if best_path and best_count >= MIN_MANIFEST_ENTRIES:
        print(f"  [bootstrap] feed_manifest.json OK ({best_count} entries @ {best_path.name}) — skipping rebuild")
        # Sync whichever canonical path is missing or stale
        for target in (stix_path, root_path):
            if target != best_path:
                target_count = _count_manifest_entries(target) if target.exists() else 0
                if target_count < MIN_MANIFEST_ENTRIES:
                    import shutil
                    shutil.copy2(best_path, target)
                    print(f"  [bootstrap] Synced {best_path.name} → {target.relative_to(ROOT)} ({best_count} entries)")
        return

    # ── Rebuild required ──────────────────────────────────────────────────
    if best_path and best_count > 0:
        print(f"  [bootstrap] feed_manifest.json STALE ({best_count} entries < {MIN_MANIFEST_ENTRIES} min) — forcing rebuild")
    else:
        print("  [bootstrap] feed_manifest.json MISSING — building from STIX bundles")

    if not entries:
        skeleton = {
            "version": VERSION, "platform": PLATFORM,
            "generated_at": now_iso(),
            "entry_count": 0, "advisories": [],
            "note": "Skeleton — will be populated on next intelligence cycle",
        }
        write_json(stix_path, skeleton, compact=True)
        write_json(root_path, skeleton, compact=True)
        print("  [bootstrap] feed_manifest.json: skeleton created (no STIX bundles found)")
        return

    _write_manifest(entries, stix_path)
    _write_manifest(entries, root_path)
    size_kb = stix_path.stat().st_size / 1024
    print(f"  [bootstrap] feed_manifest.json rebuilt: {len(entries)} entries, {size_kb:.1f} KB (synced to both paths)")


def bootstrap_api_files(entries: list) -> None:
    """
    Ensure api/feed.json, api/latest.json, api/status.json exist AND contain
    a full dataset.  If the existing API files have fewer than MIN_MANIFEST_ENTRIES
    items, they are regenerated from `entries` (which comes from the best available
    manifest, not the per-run 1-entry sentinel_blogger slice).
    """
    total = len(entries)
    critical = sum(1 for e in entries if e["severity"] == "CRITICAL")
    high     = sum(1 for e in entries if e["severity"] == "HIGH")
    avg_risk = round(sum(e["risk_score"] for e in entries) / max(total, 1), 2)

    def _api_entry_count(path: Path) -> int:
        """Return the number of items in an API file; 0 on error."""
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            for key in ("items", "latest", "advisories"):
                val = d.get(key)
                if isinstance(val, list):
                    return len(val)
            return 0
        except Exception:
            return 0

    # ── api/feed.json ───────────────────────────────────────────────────
    feed_path = API_DIR / "feed.json"
    existing_count = _api_entry_count(feed_path) if feed_path.exists() else 0
    if existing_count < MIN_MANIFEST_ENTRIES:
        feed_data = {
            "version": VERSION, "platform": PLATFORM,
            "generated_at": now_iso(),
            "total_count": total, "page": 1, "page_size": 100,
            "items": entries[:100],
        }
        write_json(feed_path, feed_data)
        print(f"  [bootstrap] api/feed.json {'created' if existing_count == 0 else 'refreshed'}: {min(total, 100)} items")
    else:
        print(f"  [bootstrap] api/feed.json OK ({existing_count} items)")

    # ── api/latest.json ─────────────────────────────────────────────────
    latest_path = API_DIR / "latest.json"
    existing_latest = _api_entry_count(latest_path) if latest_path.exists() else 0
    if existing_latest < MIN_MANIFEST_ENTRIES:
        latest_data = {
            "version": VERSION, "platform": PLATFORM,
            "generated_at": now_iso(),
            "summary": {
                "total_advisories": total, "critical": critical, "high": high,
                "medium": sum(1 for e in entries if e["severity"] == "MEDIUM"),
                "low": sum(1 for e in entries if e["severity"] == "LOW"),
                "avg_risk_score": avg_risk,
                "last_updated": entries[0]["timestamp"] if entries else None,
                "pipeline_status": "OPERATIONAL",
            },
            "latest": entries[:20],
        }
        write_json(latest_path, latest_data)
        print(f"  [bootstrap] api/latest.json {'created' if existing_latest == 0 else 'refreshed'}")
    else:
        print(f"  [bootstrap] api/latest.json OK")

    # api/status.json
    status_path = API_DIR / "status.json"
    status_data = {
        "version": VERSION, "platform": PLATFORM,
        "status": "OPERATIONAL",
        "generated_at": now_iso(),
        "metrics": {
            "total_advisories": total, "critical_threats": critical,
            "high_threats": high, "pipeline_status": "ACTIVE",
            "avg_risk_score": avg_risk,
            "data_freshness": entries[0]["timestamp"][:10] if entries else "N/A",
        },
    }
    write_json(status_path, status_data)
    print("  [bootstrap] api/status.json refreshed")


def bootstrap_sentinel_files() -> None:
    """Ensure other sentinel-required files exist with valid skeletons."""
    sentinels = {
        DATA_DIR / "sync_marker.json": {
            "version": VERSION, "last_sync": now_iso(),
            "updated_by": "bootstrap", "status": "INITIALIZED"
        },
        DATA_DIR / "status" / "status.json": {
            "version": VERSION, "platform": PLATFORM,
            "status": "MONITORING", "generated_at": now_iso(),
        },
        DATA_DIR / "health" / "guardian_report.json": {
            "version": VERSION, "platform": PLATFORM,
            "status": "INITIALIZING", "generated_at": now_iso(),
            "cycles": [], "failures_detected": 0, "fixes_applied": 0,
        },
    }

    for path, skeleton in sentinels.items():
        if not path.exists():
            write_json(path, skeleton)
            print(f"  [bootstrap] {path.relative_to(ROOT)} skeleton created")
        else:
            print(f"  [bootstrap] {path.relative_to(ROOT)} OK")


def main() -> int:
    print("=" * 70)
    print(f"SENTINEL APEX v{VERSION} — CRITICAL FILE BOOTSTRAP")
    print(f"Timestamp: {now_iso()}")
    print("=" * 70)

    ensure_dirs()

    # Load STIX entries (needed for manifest + api rebuild)
    stix_files = list(STIX_DIR.glob("CDB-APEX-*.json"))
    if stix_files:
        print(f"\nLoading intelligence from {len(stix_files)} STIX bundles...")
        entries = load_stix_entries()
        print(f"  Resolved {len(entries)} unique advisories")
    else:
        print("\nNo STIX bundle files found — using empty state")
        entries = []

    print("\nBootstrapping pipeline-critical files:")
    bootstrap_feed_manifest(entries)
    bootstrap_api_files(entries)
    bootstrap_sentinel_files()

    print("\n[bootstrap] COMPLETE — all critical files verified/created")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())