#!/usr/bin/env python3
"""
SENTINEL APEX v101.1 — Safe API Layer Generator
════════════════════════════════════════════════
ARCHITECTURE: ADDITIVE ONLY. Does NOT touch existing manifest or dashboard logic.
Reads the authoritative feed_manifest.json → writes static API files to /api/.

Outputs:
  /api/feed.json      — full manifest with API envelope (v74 enricher format)
  /api/latest.json    — last 20 items (newest first)
  /api/status.json    — platform health + metrics snapshot
  /api/stats.json     — aggregate telemetry for enterprise consumers
  /api/feed.csv       — CSV export (Phase 5 export endpoint)
  /api/feed.stix.json — STIX 2.1 bundle export (Phase 5)
  /api/feed.misp.json — MISP event export (Phase 5)

Feature flags loaded from config/feature_flags.json.
All writes are atomic (write-tmp → rename) to prevent partial reads.
"""

import json
import os
import sys
import csv
import io
import hashlib
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Repo root resolution ────────────────────────────────────────────────────
_THIS  = Path(__file__).resolve()
REPO   = _THIS.parent.parent

# ── Paths ────────────────────────────────────────────────────────────────────
MANIFEST_CANDIDATES = [
    REPO / "data" / "stix" / "feed_manifest.json",
    REPO / "data" / "v101_manifest.json",
    REPO / "data" / "enriched_manifest.json",
]
FEATURE_FLAGS_PATH = REPO / "config" / "feature_flags.json"
API_DIR            = REPO / "api"
EXPORTS_DIR        = API_DIR / "exports"

# ── Logging ──────────────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [API-v101] [{level}] {msg}", flush=True)

# ── Feature flags ─────────────────────────────────────────────────────────────
def load_flags() -> Dict[str, Any]:
    defaults = {
        "ENABLE_API_V101": True,
        "ENABLE_API_PAGINATION": True,
        "ENABLE_EXPORT_ENDPOINTS": True,
        "EXPORT_FORMATS": ["json", "csv", "stix", "misp"],
        "ENABLE_ROLLING_WINDOW": True,
        "ROLLING_WINDOW_SIZE": 2000,
    }
    try:
        raw = json.loads(FEATURE_FLAGS_PATH.read_text(encoding="utf-8"))
        defaults.update(raw)
    except Exception as e:
        log(f"Feature flags load failed ({e}) — using defaults", "WARN")
    return defaults

FLAGS = load_flags()

# ── Manifest loader ───────────────────────────────────────────────────────────
def load_manifest() -> List[Dict]:
    for path in MANIFEST_CANDIDATES:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                entries = raw
            else:
                entries = []
                for key in ("advisories", "entries", "items", "data"):
                    v = raw.get(key)
                    if isinstance(v, list) and v:
                        entries = v
                        break
            if entries:
                log(f"Manifest loaded: {len(entries)} entries from {path.name}")
                return entries
        except Exception as e:
            log(f"Manifest parse error ({path.name}): {e}", "WARN")
    log("No manifest found — returning empty list", "WARN")
    return []

# ── Atomic write helper ───────────────────────────────────────────────────────
def atomic_write(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write to temp file then rename — prevents partial reads under concurrent access."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".tmp")
    try:
        tmp.write_text(content, encoding=encoding)
        shutil.move(str(tmp), str(path))
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise

def atomic_write_json(path: Path, obj: Any, compact: bool = False) -> int:
    sep = (",", ":") if compact else (",", ": ")
    content = json.dumps(obj, ensure_ascii=False, separators=sep,
                         indent=None if compact else 2)
    atomic_write(path, content)
    return path.stat().st_size

# ── Severity helpers ──────────────────────────────────────────────────────────
def get_severity(item: Dict) -> str:
    sev = item.get("severity", "")
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev
    rs = float(item.get("risk_score", 0) or 0)
    if rs >= 8.5: return "CRITICAL"
    if rs >= 6.5: return "HIGH"
    if rs >= 4.0: return "MEDIUM"
    return "LOW"

# ── Phase 1: /api/feed.json ───────────────────────────────────────────────────
def build_feed_json(entries: List[Dict], flags: Dict) -> Path:
    """Full manifest with API envelope. All entries, sorted newest-first."""
    # Rolling window guard (Phase 4)
    if flags.get("ENABLE_ROLLING_WINDOW"):
        window = int(flags.get("ROLLING_WINDOW_SIZE", 2000))
        if len(entries) > window:
            entries = entries[:window]
            log(f"Rolling window applied: {window} entries")

    # ── v102.0 SCHEMA NORMALIZATION ───────────────────────────────────────────────
    # v74 manifest enricher writes items with STIX object 'id' instead of 'stix_id'.
    # Normalize here so ALL api/feed.json consumers receive 'stix_id' unconditionally.
    for entry in entries:
        # Map STIX object id → stix_id (primary AI key for threatRegistry + ANALYZE btn)
        if not entry.get("stix_id") and entry.get("id"):
            entry["stix_id"] = entry["id"]
        # Map v74 ttps → mitre_techniques
        if not entry.get("mitre_techniques") and entry.get("ttps"):
            entry["mitre_techniques"] = entry["ttps"]
        # Map v74 confidence (0-100 int) → confidence_score (0.0-1.0 float)
        if entry.get("confidence_score") is None and entry.get("confidence") is not None:
            try:
                cv = float(entry["confidence"])
                entry["confidence_score"] = round(cv / 100 if cv > 1 else cv, 4)
            except (ValueError, TypeError):
                pass
        # Ensure risk_score is numeric
        if entry.get("risk_score") is not None:
            try:
                entry["risk_score"] = float(entry["risk_score"])
            except (ValueError, TypeError):
                pass

    sorted_entries = sorted(
        entries,
        key=lambda x: str(x.get("timestamp", x.get("published", x.get("created", "")))),
        reverse=True
    )

    # Aggregate metrics
    total    = len(sorted_entries)
    critical = sum(1 for e in sorted_entries if get_severity(e) == "CRITICAL")
    high     = sum(1 for e in sorted_entries if get_severity(e) == "HIGH")
    kev_ct   = sum(1 for e in sorted_entries if e.get("kev_present"))
    feed_srcs = len({e.get("feed_source", "") for e in sorted_entries if e.get("feed_source")})
    ioc_total = sum(int(e.get("ioc_count", 0) or 0) for e in sorted_entries)

    ts = datetime.now(timezone.utc).isoformat()

    envelope = {
        "version":      "101.1",
        "platform":     "CYBERDUDEBIVASH SENTINEL APEX",
        "generated_at": ts,
        "count":        total,
        "total_count":  total,
        "metrics": {
            "critical":      critical,
            "high":          high,
            "kev_flagged":   kev_ct,
            "active_feeds":  feed_srcs,
            "total_iocs":    ioc_total,
        },
        "pagination": {
            "page":      1,
            "page_size": total,
            "total":     total,
            "pages":     1,
        },
        "data":  sorted_entries,
        "items": sorted_entries,       # backward-compat alias
    }

    out_path = API_DIR / "feed.json"
    sz = atomic_write_json(out_path, envelope, compact=True)
    log(f"feed.json: {total} items | {sz:,} bytes | critical={critical} kev={kev_ct}")
    return out_path

# ── Phase 1: /api/latest.json ─────────────────────────────────────────────────
def build_latest_json(entries: List[Dict]) -> Path:
    """Last 20 items (newest-first). Lightweight endpoint for widgets/tickers."""
    recent = sorted(
        entries,
        key=lambda x: str(x.get("timestamp", "")),
        reverse=True
    )[:20]

    obj = {
        "version":      "101.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count":        len(recent),
        "data":         recent,
    }
    out_path = API_DIR / "latest.json"
    sz = atomic_write_json(out_path, obj, compact=True)
    log(f"latest.json: {len(recent)} items | {sz:,} bytes")
    return out_path

# ── Phase 1: /api/status.json ─────────────────────────────────────────────────
def build_status_json(entries: List[Dict]) -> Path:
    """Platform health + full metrics snapshot."""
    total    = len(entries)
    critical = sum(1 for e in entries if get_severity(e) == "CRITICAL")
    high     = sum(1 for e in entries if get_severity(e) == "HIGH")
    medium   = sum(1 for e in entries if get_severity(e) == "MEDIUM")
    low      = sum(1 for e in entries if get_severity(e) == "LOW")
    kev_ct   = sum(1 for e in entries if e.get("kev_present"))
    feed_srcs = sorted({e.get("feed_source", "") for e in entries if e.get("feed_source")})
    ioc_total = sum(int(e.get("ioc_count", 0) or 0) for e in entries)
    avg_risk  = (sum(float(e.get("risk_score", 0) or 0) for e in entries) / total) if total else 0

    ts_vals = [e.get("timestamp", "") for e in entries if e.get("timestamp")]
    newest  = max(ts_vals) if ts_vals else ""
    oldest  = min(ts_vals) if ts_vals else ""

    obj = {
        "version":            "101.1",
        "platform":           "CYBERDUDEBIVASH SENTINEL APEX",
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "status":             "OPERATIONAL",
        "total_advisories":   total,
        "severity_breakdown": {
            "CRITICAL": critical,
            "HIGH":     high,
            "MEDIUM":   medium,
            "LOW":      low,
        },
        "kev_flagged":        kev_ct,
        "active_feeds":       len(feed_srcs),
        "feed_sources":       feed_srcs[:50],
        "total_iocs":         ioc_total,
        "avg_risk_score":     round(avg_risk, 2),
        "newest_advisory":    newest,
        "oldest_advisory":    oldest,
        "api_endpoints": {
            "feed":    "/api/feed.json",
            "latest":  "/api/latest.json",
            "status":  "/api/status.json",
            "stats":   "/api/stats.json",
            "exports": {
                "csv":  "/api/exports/feed.csv",
                "stix": "/api/exports/feed.stix.json",
                "misp": "/api/exports/feed.misp.json",
            }
        }
    }
    out_path = API_DIR / "status.json"
    sz = atomic_write_json(out_path, obj)
    log(f"status.json: total={total} critical={critical} kev={kev_ct} feeds={len(feed_srcs)}")
    return out_path

# ── Phase 1: /api/stats.json ──────────────────────────────────────────────────
def build_stats_json(entries: List[Dict]) -> Path:
    """Enterprise telemetry: top CVEs, top actors, feed weight, severity trend."""
    from collections import Counter

    sev_counter = Counter(get_severity(e) for e in entries)
    feed_counter = Counter(
        e.get("feed_source", "Unknown") for e in entries if e.get("feed_source")
    )

    # CVE extraction
    import re
    cve_pat = re.compile(r"CVE-\d{4}-\d+", re.I)
    all_cves: List[str] = []
    for e in entries:
        all_cves.extend(cve_pat.findall(e.get("title", "") + " " + str(e.get("description", ""))))
    top_cves = Counter(c.upper() for c in all_cves).most_common(20)

    obj = {
        "version":      "101.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "severity_distribution": dict(sev_counter),
        "top_feed_sources":      [{"source": k, "count": v} for k, v in feed_counter.most_common(20)],
        "top_cves":              [{"cve": k, "count": v} for k, v in top_cves],
        "total_advisories":      len(entries),
        "kev_total":             sum(1 for e in entries if e.get("kev_present")),
        "ioc_total":             sum(int(e.get("ioc_count", 0) or 0) for e in entries),
    }
    out_path = API_DIR / "stats.json"
    sz = atomic_write_json(out_path, obj)
    log(f"stats.json: {sz:,} bytes")
    return out_path

# ── Phase 5: /api/exports/feed.csv ───────────────────────────────────────────
def build_csv_export(entries: List[Dict]) -> Path:
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    fields = [
        "stix_id", "title", "severity", "risk_score", "timestamp",
        "source", "feed_source", "blog_url", "source_url",
        "kev_present", "ioc_count", "cve_ids", "description",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for e in entries:
        row = {f: e.get(f, "") for f in fields}
        row["severity"]    = get_severity(e)
        row["cve_ids"]     = "|".join(e.get("cve_ids", []) or [])
        row["kev_present"] = "true" if e.get("kev_present") else "false"
        row["description"] = str(e.get("description", "") or "")[:500]
        writer.writerow(row)

    out_path = EXPORTS_DIR / "feed.csv"
    atomic_write(out_path, buf.getvalue())
    log(f"exports/feed.csv: {len(entries)} rows | {out_path.stat().st_size:,} bytes")
    return out_path

# ── Phase 5: /api/exports/feed.stix.json ────────────────────────────────────
def build_stix_export(entries: List[Dict]) -> Path:
    """STIX 2.1 bundle export — indicator objects from advisory entries."""
    import uuid
    ts_now = datetime.now(timezone.utc).isoformat()

    objects = []
    for e in entries:
        sid = e.get("stix_id") or f"indicator--{uuid.uuid4()}"
        sev = get_severity(e)
        risk = float(e.get("risk_score", 0) or 0)
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": sid,
            "name": e.get("title", "Unknown Advisory")[:256],
            "description": str(e.get("description", "") or "")[:1000],
            "created": e.get("timestamp", ts_now),
            "modified": e.get("timestamp", ts_now),
            "labels": [sev.lower(), "threat-intelligence"],
            "pattern_type": "stix",
            "pattern": f"[url:value = '{e.get('source_url', '')}']",
            "valid_from": e.get("timestamp", ts_now),
            "extensions": {
                "extension-definition--sentinel-apex": {
                    "extension_type": "property-extension",
                    "risk_score":  risk,
                    "severity":    sev,
                    "kev_present": bool(e.get("kev_present")),
                    "feed_source": e.get("feed_source", ""),
                    "blog_url":    e.get("blog_url", ""),
                    "cve_ids":     e.get("cve_ids", []),
                }
            }
        }
        objects.append(obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": ts_now,
        "objects": objects,
        "_meta": {
            "generated_by": "CYBERDUDEBIVASH SENTINEL APEX v101.1",
            "count": len(objects),
        }
    }
    out_path = EXPORTS_DIR / "feed.stix.json"
    sz = atomic_write_json(out_path, bundle, compact=True)
    log(f"exports/feed.stix.json: {len(objects)} indicators | {sz:,} bytes")
    return out_path

# ── Phase 5: /api/exports/feed.misp.json ────────────────────────────────────
def build_misp_export(entries: List[Dict]) -> Path:
    """MISP event format export — compatible with MISP 2.4+ import."""
    import uuid
    ts_now = datetime.now(timezone.utc).isoformat()
    ts_epoch = int(datetime.now(timezone.utc).timestamp())

    events = []
    for i, e in enumerate(entries[:500]):   # MISP cap: 500 events per export
        sev = get_severity(e)
        threat_level = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "3", "LOW": "4"}.get(sev, "2")
        attrs = []
        if e.get("source_url"):
            attrs.append({"type": "url", "category": "External analysis",
                          "value": e["source_url"], "to_ids": False})
        if e.get("blog_url"):
            attrs.append({"type": "url", "category": "External analysis",
                          "value": e["blog_url"], "to_ids": False, "comment": "Tactical Dossier"})
        for cve in (e.get("cve_ids") or []):
            attrs.append({"type": "vulnerability", "category": "External analysis",
                          "value": cve, "to_ids": False})
        for ioc in (e.get("iocs") or [])[:10]:
            if isinstance(ioc, str):
                attrs.append({"type": "text", "category": "External analysis",
                              "value": ioc, "to_ids": True})

        events.append({
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": e.get("title", "Unknown")[:255],
                "threat_level_id": threat_level,
                "distribution": "0",
                "analysis": "2",
                "timestamp": str(ts_epoch),
                "Attribute": attrs,
                "Tag": [
                    {"name": f"sentinel-apex:severity={sev}"},
                    {"name": f"sentinel-apex:feed={e.get('feed_source','unknown')}"},
                ],
            }
        })

    out_path = EXPORTS_DIR / "feed.misp.json"
    sz = atomic_write_json(out_path, {"response": events}, compact=True)
    log(f"exports/feed.misp.json: {len(events)} events | {sz:,} bytes")
    return out_path

# ── Main entrypoint ───────────────────────────────────────────────────────────
def main() -> int:
    log("═" * 60)
    log("SENTINEL APEX v101.1 — Safe API Layer Generator")
    log("═" * 60)

    flags = load_flags()
    if not flags.get("ENABLE_API_V101", True):
        log("ENABLE_API_V101=false — skipping (feature flag disabled)")
        return 0

    entries = load_manifest()
    if not entries:
        log("No entries to process — aborting API layer build", "ERROR")
        return 1

    API_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    results = {}

    # Phase 1: Core API files
    try:
        build_feed_json(list(entries), flags)
        results["feed.json"] = "OK"
    except Exception as e:
        log(f"feed.json FAILED: {e}", "ERROR"); results["feed.json"] = f"FAIL: {e}"

    try:
        build_latest_json(list(entries))
        results["latest.json"] = "OK"
    except Exception as e:
        log(f"latest.json FAILED: {e}", "ERROR"); results["latest.json"] = f"FAIL: {e}"

    try:
        build_status_json(list(entries))
        results["status.json"] = "OK"
    except Exception as e:
        log(f"status.json FAILED: {e}", "ERROR"); results["status.json"] = f"FAIL: {e}"

    try:
        build_stats_json(list(entries))
        results["stats.json"] = "OK"
    except Exception as e:
        log(f"stats.json FAILED: {e}", "ERROR"); results["stats.json"] = f"FAIL: {e}"

    # Phase 5: Export endpoints
    if flags.get("ENABLE_EXPORT_ENDPOINTS", True):
        export_formats = flags.get("EXPORT_FORMATS", ["csv", "stix", "misp"])

        if "csv" in export_formats:
            try:
                build_csv_export(list(entries))
                results["exports/feed.csv"] = "OK"
            except Exception as e:
                log(f"CSV export FAILED: {e}", "ERROR")
                results["exports/feed.csv"] = f"FAIL: {e}"

        if "stix" in export_formats:
            try:
                build_stix_export(list(entries))
                results["exports/feed.stix.json"] = "OK"
            except Exception as e:
                log(f"STIX export FAILED: {e}", "ERROR")
                results["exports/feed.stix.json"] = f"FAIL: {e}"

        if "misp" in export_formats:
            try:
                build_misp_export(list(entries))
                results["exports/feed.misp.json"] = "OK"
            except Exception as e:
                log(f"MISP export FAILED: {e}", "ERROR")
                results["exports/feed.misp.json"] = f"FAIL: {e}"

    # Summary
    log("─" * 60)
    ok = sum(1 for v in results.values() if v == "OK")
    fail = sum(1 for v in results.values() if v.startswith("FAIL"))
    log(f"API Layer complete: {ok} OK | {fail} FAILED")
    for k, v in results.items():
        status_icon = "✅" if v == "OK" else "❌"
        log(f"  {status_icon} {k}: {v}")
    log("═" * 60)

    return 0 if fail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
