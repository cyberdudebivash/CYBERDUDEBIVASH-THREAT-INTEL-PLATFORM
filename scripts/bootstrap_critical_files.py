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
            # v112.2 P0 FIX: Since export_stix.py v110.1, description IS the plain threat
            # title (no "Tactical cluster:" prefix). primary.get("name") is "{actor_tag} Campaign"
            # — NOT the threat title. Old regex never matched → all 52 bundles collapsed to ~8
            # generic actor-tag duplicates. Fix: try legacy regex for backward compat, then use
            # description directly, fall back to name only if description is empty.
            m = re.search(r"Tactical cluster: (.+)", description)
            if m:
                title = m.group(1).strip()
            elif description.strip():
                title = description.strip()[:200]
            else:
                title = primary.get("name", "")
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

            # Extract blog_url from external_references on report/intrusion-set objects.
            # The sentinel_blogger writes the published post URL into the STIX bundle
            # external_references so we can reconstruct the Tactical Dossier link.
            blog_url = ""
            for obj in objs:
                for ref in obj.get("external_references", []):
                    url = ref.get("url", "")
                    if url and any(k in url for k in ["cyberdudebivash", "cyberbivash.blogspot"]):
                        blog_url = url
                        break
                if blog_url:
                    break

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
                "blog_url": blog_url,
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
      3. data/validated_manifest.json     — COMMITTED to git (historical snapshot)
      4. data/apex_enriched_manifest.json — APEX enrichment output (committed)
      5. data/apex_v2_manifest.json       — APEX v2 output (committed)
    P0 FIX v111.1: validated_manifest.json is committed to git and contains the full
    historical advisory set. This ensures bootstrap always finds a rich base to merge
    from even on fresh checkout with empty data/stix/.
    """
    candidates = [
        DATA_DIR / "feed_manifest.json",
        STIX_DIR / "feed_manifest.json",
        DATA_DIR / "validated_manifest.json",      # COMMITTED — primary historical source
        DATA_DIR / "apex_enriched_manifest.json",  # COMMITTED — APEX enrichment
        DATA_DIR / "apex_v2_manifest.json",        # COMMITTED — APEX v2
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
    # v112.1 P0 FIX: Sort manifest entries by timestamp DESC → risk_score DESC before writing.
    # This ensures Worker preview slice(0,10) always surfaces the newest high-risk items,
    # not stale bootstrap entries that happen to sort first in merge order.
    def _sort_key(e):
        ts = e.get("timestamp") or e.get("created") or ""
        rs = float(e.get("risk_score") or e.get("cvss_score") or 0)
        return (ts, rs)
    entries = sorted(entries, key=_sort_key, reverse=True)
    # v112.2 P0 FIX: Use .get() with fallback for all field accesses — UNION merge brings
    # entries from old manifests that may use cvss_score, different severity labels, or
    # have missing fields entirely. Bracket notation caused KeyError: 'risk_score' crash.
    def _get_rs(e):
        return float(e.get("risk_score") or e.get("cvss_score") or 0)
    def _get_sev(e):
        return (e.get("severity") or e.get("risk_level") or "MEDIUM").upper()
    critical = sum(1 for e in entries if _get_sev(e) == "CRITICAL")
    high     = sum(1 for e in entries if _get_sev(e) == "HIGH")
    avg_risk = round(sum(_get_rs(e) for e in entries) / max(len(entries), 1), 2)
    manifest = {
        "version": VERSION, "platform": PLATFORM,
        "generated_at": now_iso(),
        "entry_count": len(entries),
        "total_reports": len(entries),
        "summary": {
            "critical": critical, "high": high,
            "medium": sum(1 for e in entries if _get_sev(e) == "MEDIUM"),
            "low": sum(1 for e in entries if _get_sev(e) == "LOW"),
            "avg_risk_score": avg_risk,
        },
        "advisories": entries,
    }
    write_json(path, manifest, compact=True)


def _load_existing_manifest_entries(stix_path: "Path", root_path: "Path") -> list:
    """
    Load entries from the best available pre-run manifest snapshot.
    Priority (searched in order; winner = most entries):
      1. /tmp/pre_run_manifest.json — saved at run start BEFORE v70 overwrites
      2. data/stix/feed_manifest.json
      3. data/feed_manifest.json
      4. data/validated_manifest.json     — COMMITTED to git (2463+ entries on fresh checkout)
      5. data/apex_enriched_manifest.json — COMMITTED (APEX enrichment)
      6. data/apex_v2_manifest.json       — COMMITTED (APEX v2)
    P0 FIX v111.1: validated_manifest.json is committed and contains the full historical
    advisory set. This ensures the force-rebuild MERGE always starts from a non-empty
    base, so the schema validation gate (min 100) is never triggered by an empty manifest.
    Used by force-rebuild MERGE so entries from previous runs survive v70.
    """
    snapshot = Path("/tmp/pre_run_manifest.json")
    # P0 FIX: Include committed manifests as fallback sources
    validated_path = DATA_DIR / "validated_manifest.json"
    apex_enriched  = DATA_DIR / "apex_enriched_manifest.json"
    apex_v2        = DATA_DIR / "apex_v2_manifest.json"

    # v112.2 P0 FIX: Changed from winner-takes-all to UNION-ALL merge.
    # Problem: /tmp snapshot (2463 entries) always outscored v70 enriched manifest
    # (497 entries with Risk=10.0 CRITICAL items), so enriched intel was silently
    # discarded. Fix: collect entries from ALL candidates and deduplicate by title,
    # with newer / higher risk_score winning. This guarantees enriched entries from
    # sentinel_blogger's v70 run are never lost to the historical snapshot.
    union_by_title: dict = {}  # title_lc → entry (best-score-wins)

    def _absorb(candidate: Path) -> int:
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                items = raw
            else:
                items = []
                for k in ("advisories", "entries", "items", "reports"):
                    v = raw.get(k)
                    if isinstance(v, list):
                        items = v
                        break
            absorbed = 0
            for item in items:
                t = (item.get("title") or item.get("name") or "").strip().lower()
                if not t:
                    continue
                if t not in union_by_title:
                    union_by_title[t] = item
                    absorbed += 1
                else:
                    # Best risk_score wins (enriched sentinel_blogger entry beats bootstrap)
                    existing_rs = float(union_by_title[t].get("risk_score") or
                                        union_by_title[t].get("cvss_score") or 0)
                    new_rs = float(item.get("risk_score") or item.get("cvss_score") or 0)
                    if new_rs > existing_rs:
                        union_by_title[t] = item
                        absorbed += 1
            if absorbed:
                print(f"  [bootstrap] MERGE source: {candidate.name} (+{absorbed} entries, union total={len(union_by_title)})")
            return absorbed
        except Exception:
            return 0

    for candidate in (snapshot, stix_path, root_path, validated_path, apex_enriched, apex_v2):
        if candidate.exists():
            _absorb(candidate)

    existing = list(union_by_title.values())
    print(f"  [bootstrap] UNION MERGE complete: {len(existing)} unique entries across all sources")
    return existing


def bootstrap_feed_manifest(entries: list, force_rebuild: bool = False) -> None:
    """
    Ensure data/stix/feed_manifest.json AND data/feed_manifest.json both
    contain a full advisory set (>= MIN_MANIFEST_ENTRIES).

    v111.0 P0 FIX:
      ALWAYS merge new STIX-bundle entries with the existing committed manifest.
      The old "skip if >= MIN_MANIFEST_ENTRIES" logic is REMOVED — it caused
      fresh intel to never reach R2 (existing manifest recycled indefinitely).

    Decision logic (revised):
      force_rebuild=True  → MERGE: new STIX bundles + existing committed entries
      force_rebuild=False → If new STIX bundles exist, merge them in.
                            If no new STIX bundles, preserve existing manifest.
                            If manifest below MIN threshold, rebuild from scratch.
    """
    stix_path = STIX_DIR / "feed_manifest.json"
    root_path = DATA_DIR / "feed_manifest.json"  # v70 orchestrator path

    if force_rebuild:
        # ── MERGE: existing committed manifest + new STIX-bundle entries ──
        # Load the existing committed manifest (may have entries from previous
        # runs whose STIX bundles were NOT committed and are therefore absent
        # from the `entries` list derived from scanning disk bundles).
        existing_entries = _load_existing_manifest_entries(stix_path, root_path)

        # Build dedup index from STIX-bundle entries (highest priority: current run)
        seen_keys: set = set()
        merged: list = []
        for e in entries:
            key = (e.get("stix_id") or e.get("id") or "")[:120] or e.get("title", "")[:120]
            if key and key not in seen_keys:
                seen_keys.add(key)
                merged.append(e)

        # Append existing manifest entries not already present
        appended = 0
        for e in existing_entries:
            key = (e.get("stix_id") or e.get("id") or "")[:120] or e.get("title", "")[:120]
            if key and key not in seen_keys:
                seen_keys.add(key)
                merged.append(e)
                appended += 1

        print(f"  [bootstrap] FORCE REBUILD+MERGE: {len(entries)} STIX-bundle entries "
              f"+ {appended} preserved from committed manifest "
              f"= {len(merged)} total (was {len(existing_entries)} committed)")
        entries = merged
    else:
        # v111.0 FIX: If new STIX-bundle entries exist, ALWAYS merge them in.
        # This replaces the old "skip if >= MIN_MANIFEST_ENTRIES" guard that
        # caused the pipeline to recycle stale manifests indefinitely.
        if entries:
            print(f"  [bootstrap] {len(entries)} new STIX entries found — merging into manifest")
            existing_entries = _load_existing_manifest_entries(stix_path, root_path)
            seen_keys: set = set()
            merged: list = []
            for e in entries:
                key = (e.get("stix_id") or e.get("id") or "")[:120] or e.get("title", "")[:120]
                if key and key not in seen_keys:
                    seen_keys.add(key)
                    merged.append(e)
            appended = 0
            for e in existing_entries:
                key = (e.get("stix_id") or e.get("id") or "")[:120] or e.get("title", "")[:120]
                if key and key not in seen_keys:
                    seen_keys.add(key)
                    merged.append(e)
                    appended += 1
            print(f"  [bootstrap] MERGE: {len(entries)} new + {appended} preserved = {len(merged)} total")
            entries = merged
            # Fall through to write merged manifest below
        else:
            # No new STIX bundles — preserve existing manifest if healthy
            best_path, best_count = _best_existing_manifest()
            if best_path and best_count >= MIN_MANIFEST_ENTRIES:
                print(f"  [bootstrap] feed_manifest.json preserved ({best_count} entries) — no new STIX bundles this run")
                for target in (stix_path, root_path):
                    if target != best_path:
                        target_count = _count_manifest_entries(target) if target.exists() else 0
                        if target_count < best_count:
                            import shutil
                            shutil.copy2(best_path, target)
                            print(f"  [bootstrap] Synced {best_path.name} → {target.relative_to(ROOT)}")
                return

    # ── Rebuild required ──────────────────────────────────────────────────
    if not force_rebuild:
        best_path, best_count = _best_existing_manifest()
    if not force_rebuild and best_path and best_count > 0:
        print(f"  [bootstrap] feed_manifest.json STALE ({best_count} entries < {MIN_MANIFEST_ENTRIES} min) — forcing rebuild")
    elif not force_rebuild:
        print("  [bootstrap] feed_manifest.json MISSING — building from STIX bundles")

    if not entries:
        # No STIX bundles on disk. Before creating an empty skeleton, check if
        # an existing manifest has valid entries — if so, preserve it rather
        # than destroying accumulated historical data.
        if not force_rebuild:
            best_path, best_count = _best_existing_manifest()
        if not force_rebuild and best_path and best_count > 0:
            import shutil as _shutil_pres
            for target in (stix_path, root_path):
                if not target.exists() or _count_manifest_entries(target) < best_count:
                    _shutil_pres.copy2(best_path, target)
            print(f"  [bootstrap] feed_manifest.json PRESERVED ({best_count} entries — no STIX bundles, keeping existing)")
            return
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
    # ── CLI flags ──────────────────────────────────────────────────────────
    force_rebuild = "--force-rebuild" in sys.argv

    print("=" * 70)
    print(f"SENTINEL APEX v{VERSION} — CRITICAL FILE BOOTSTRAP")
    print(f"Timestamp: {now_iso()}")
    if force_rebuild:
        print("Mode: FORCE REBUILD (--force-rebuild specified)")
    print("=" * 70)

    ensure_dirs()

    # ── SNAPSHOT: Save committed manifest BEFORE any step can overwrite it ──
    # This snapshot is used by force-rebuild MERGE so that entries from the
    # previous run's manifest (committed in git) survive v70's overwrite.
    # P0 FIX v111.1: Include validated_manifest.json (COMMITTED) as snapshot source.
    # On fresh checkout, data/stix/feed_manifest.json does NOT exist (R2-only).
    # validated_manifest.json IS committed with 2463+ historical entries — use it.
    import shutil as _shutil_snap
    _snapshot = Path("/tmp/pre_run_manifest.json")
    if not _snapshot.exists():  # only save once per runner lifetime
        _snap_candidates = [
            STIX_DIR / "feed_manifest.json",
            DATA_DIR / "feed_manifest.json",
            DATA_DIR / "validated_manifest.json",      # COMMITTED — primary P0 fix
            DATA_DIR / "apex_enriched_manifest.json",  # COMMITTED — fallback
            DATA_DIR / "apex_v2_manifest.json",        # COMMITTED — fallback
        ]
        _best_snap_count = 0
        _best_snap_path  = None
        for _cand in _snap_candidates:
            if _cand.exists():
                n = _count_manifest_entries(_cand)
                if n > _best_snap_count:
                    _best_snap_count = n
                    _best_snap_path  = _cand
        if _best_snap_path:
            _shutil_snap.copy2(_best_snap_path, _snapshot)
            print(f"  [bootstrap] Snapshot saved: {_best_snap_count} entries from {_best_snap_path.name} → /tmp/pre_run_manifest.json")
        else:
            print("  [bootstrap] WARN: No committed manifest found for snapshot — starting from empty")

    # Load STIX entries (needed for manifest + api rebuild)
    stix_files = list(STIX_DIR.glob("CDB-APEX-*.json"))
    if stix_files:
        print(f"\nLoading intelligence from {len(stix_files)} STIX bundles...")
        entries = load_stix_entries()
        print(f"  Resolved {len(entries)} unique advisories")
    else:
        print("\nNo STIX bundle files found — using existing manifest state")
        entries = []

    print("\nBootstrapping pipeline-critical files:")
    bootstrap_feed_manifest(entries, force_rebuild=force_rebuild)

    # FIX-5: Load the now-correct full manifest for API file metrics.
    # bootstrap_api_files() was receiving only the sparse STIX-bundle slice
    # (9 items, risk_score ~7.0, all LOW/MEDIUM) — giving zeros in status.json.
    best_path, best_count = _best_existing_manifest()
    if best_path and best_count > len(entries):
        try:
            import json as _j
            _raw = _j.loads(best_path.read_text(encoding="utf-8"))
            if isinstance(_raw, list):
                full_entries = _raw
            else:
                full_entries = entries
                for _k in ("advisories", "entries", "items"):
                    _v = _raw.get(_k)
                    if isinstance(_v, list):
                        full_entries = _v
                        break
            print(f"  [bootstrap] API metrics: {best_path.name} ({len(full_entries)} entries)")
        except Exception as _e:
            print(f"  [bootstrap] WARN: Full manifest load failed: {_e}")
            full_entries = entries
    else:
        full_entries = entries

    bootstrap_api_files(full_entries)
    bootstrap_sentinel_files()

    print("\n[bootstrap] COMPLETE — all critical files verified/created")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())