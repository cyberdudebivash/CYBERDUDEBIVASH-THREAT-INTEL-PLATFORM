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


def bootstrap_feed_manifest(entries: list) -> None:
    path = STIX_DIR / "feed_manifest.json"

    if path.exists() and path.stat().st_size > 1000:
        # Validate it's readable
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            e = existing if isinstance(existing, list) else existing.get("advisories", existing.get("entries", []))
            if len(e) > 0:
                print(f"  [bootstrap] feed_manifest.json OK ({len(e)} entries) — skipping rebuild")
                return
        except Exception:
            pass

    if not entries:
        skeleton = {
            "version": VERSION, "platform": PLATFORM,
            "generated_at": now_iso(),
            "entry_count": 0, "advisories": [],
            "note": "Skeleton — will be populated on next intelligence cycle",
        }
        write_json(path, skeleton, compact=True)
        print("  [bootstrap] feed_manifest.json: skeleton created (no STIX bundles found)")
        return

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
    size_kb = path.stat().st_size / 1024
    print(f"  [bootstrap] feed_manifest.json rebuilt: {len(entries)} entries, {size_kb:.1f} KB")


def bootstrap_api_files(entries: list) -> None:
    """Ensure api/feed.json, api/latest.json, api/status.json are present."""
    total = len(entries)
    critical = sum(1 for e in entries if e["severity"] == "CRITICAL")
    high     = sum(1 for e in entries if e["severity"] == "HIGH")
    avg_risk = round(sum(e["risk_score"] for e in entries) / max(total, 1), 2)

    # api/feed.json
    feed_path = API_DIR / "feed.json"
    if not feed_path.exists() or feed_path.stat().st_size < 100:
        feed_data = {
            "version": VERSION, "platform": PLATFORM,
            "generated_at": now_iso(),
            "total_count": total, "page": 1, "page_size": 100,
            "items": entries[:100],
        }
        write_json(feed_path, feed_data)
        print(f"  [bootstrap] api/feed.json created: {min(total, 100)} items")
    else:
        print("  [bootstrap] api/feed.json OK")

    # api/latest.json
    latest_path = API_DIR / "latest.json"
    if not latest_path.exists() or latest_path.stat().st_size < 100:
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
        print("  [bootstrap] api/latest.json created")
    else:
        print("  [bootstrap] api/latest.json OK")

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
