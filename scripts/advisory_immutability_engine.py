#!/usr/bin/env python3
"""
SENTINEL APEX v159.0 — Advisory Immutability Engine (AIE)
==========================================================
Deterministic advisory fingerprinting, stale-reuse detection, and
deduplication enforcement for the live feed.

ROOT CAUSE ADDRESSED:
  - Advisories were given non-deterministic IDs (pipeline clock-based)
    causing the same CVE to appear multiple times across pipeline runs.
  - Stale advisories (CVE-1999-x, CVE-2019-x) reappeared because there
    was no fingerprint-based dedup gate.
  - Synthetic re-generated advisories bypassed immutability: a CVE that
    had already been ingested would be regenerated as a new advisory with
    a new synthetic ID on every run.

WHAT THIS ENGINE DOES:
  1. Fingerprint generation — deterministic SHA-256 from (source_url + CVE IDs)
     or (title slug + published_at) for non-CVE items.
  2. Manifest registry — maintains data/health/advisory_registry.json as a
     persistent fingerprint→first_seen map.
  3. Stale reuse detection — warns when a fingerprint is seen for the Nth time
     (configurable REUSE_WARN_COUNT).
  4. Dedup enforcement — removes duplicate fingerprints from the feed (keeps
     the newest item, discards re-runs of the same advisory).
  5. Age gate — marks items with stale CVE years for downstream filtering.

USAGE:
  # Validate + dedup the live feed (non-destructive report):
  python3 scripts/advisory_immutability_engine.py --report

  # Hard-fail on immutability violations:
  python3 scripts/advisory_immutability_engine.py --check

  # Dedup the feed in-place (atomic write):
  python3 scripts/advisory_immutability_engine.py --dedup --feed api/feed.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Config ─────────────────────────────────────────────────────────────────────
REPO            = Path(__file__).resolve().parent.parent
DEFAULT_FEED    = REPO / "api" / "feed.json"
REGISTRY_PATH   = REPO / "data" / "health" / "advisory_registry.json"
REPORT_PATH     = REPO / "data" / "health" / "advisory_immutability.json"

REUSE_WARN_COUNT    = 3    # warn when same fingerprint seen >= this many times
STALE_CVE_YEAR      = 2024 # CVEs with year < this are flagged as potentially stale
SYNTHETIC_MARKERS   = {    # actor tags that signal synthetic fallback with no real data
    "CDB-UNATTR-CVE", "CDB-REBUILT", "CDB-SYNTHETIC", "CDB-FABRICATED",
}

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("advisory_immutability")

# ── Regex helpers ──────────────────────────────────────────────────────────────
_CVE_RE   = re.compile(r"\bCVE-(\d{4})-\d{4,}\b", re.IGNORECASE)
_SLUG_RE  = re.compile(r"[^a-z0-9]+")

def _extract_cves(item: Dict) -> List[str]:
    """Return all CVE IDs from an advisory item (multiple fields)."""
    cves: List[str] = []
    for field in ("title", "id", "stix_id", "source_url", "blog_url"):
        val = str(item.get(field) or "")
        cves.extend(m.group(0).upper() for m in _CVE_RE.finditer(val))
    cve_list = item.get("cve") or []
    if isinstance(cve_list, list):
        for v in cve_list:
            cves.extend(m.group(0).upper() for m in _CVE_RE.finditer(str(v)))
    # Deduplicate while preserving order
    seen: set = set()
    result: List[str] = []
    for c in cves:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result

def _title_slug(title: str) -> str:
    return _SLUG_RE.sub("-", title.lower().strip())[:80]

# ── Fingerprint ────────────────────────────────────────────────────────────────

def make_fingerprint(item: Dict) -> str:
    """
    Generate a deterministic SHA-256 fingerprint for an advisory.

    Priority:
      1. source_url + sorted CVE IDs  (most stable: ties to upstream source)
      2. sorted CVE IDs only           (no source URL, but CVE IDs known)
      3. title slug + published_at     (non-CVE advisory — content-addressed)
    """
    cves = _extract_cves(item)
    source_url = (item.get("source_url") or "").strip()

    if source_url and cves:
        key = f"src:{source_url}|cves:{','.join(sorted(cves))}"
    elif cves:
        key = f"cves:{','.join(sorted(cves))}"
    else:
        title_slug = _title_slug(str(item.get("title") or ""))
        pub_at = str(item.get("published_at") or item.get("timestamp") or "")[:10]
        # v166.14: include stix_id/id as tiebreaker to prevent collision when two
        # non-CVE items share the same title slug and publication date (e.g. two
        # BleepingComputer articles published same day with similar short titles).
        item_id = str(item.get("stix_id") or item.get("id") or "")
        key = f"title:{title_slug}|date:{pub_at}|id:{item_id}"

    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
    return f"aie-{digest}"

# ── Stale age check ────────────────────────────────────────────────────────────

def is_stale_cve(item: Dict) -> Tuple[bool, Optional[int]]:
    """Return (is_stale, cve_year) — stale = CVE year < STALE_CVE_YEAR."""
    cves = _extract_cves(item)
    for cve in cves:
        m = _CVE_RE.match(cve)
        if m:
            yr = int(m.group(1))
            if yr < STALE_CVE_YEAR:
                return True, yr
    return False, None

# ── Registry ───────────────────────────────────────────────────────────────────

def load_registry() -> Dict[str, Dict]:
    """Load persistent fingerprint registry from disk."""
    if REGISTRY_PATH.exists():
        try:
            return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Could not load registry (using empty): %s", exc)
    return {}

def save_registry(registry: Dict[str, Dict]) -> None:
    """Persist registry to disk (atomic write)."""
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = REGISTRY_PATH.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(registry, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(REGISTRY_PATH)
    except Exception as exc:
        log.warning("Could not save registry: %s", exc)
        tmp.unlink(missing_ok=True)

# ── Main Analysis Engine ───────────────────────────────────────────────────────

def analyze_feed(
    items: List[Dict],
    registry: Dict[str, Dict],
    update_registry: bool = False,
) -> Dict[str, Any]:
    """
    Analyze items for fingerprint collisions, stale reuse, and synthetic markers.
    Optionally updates the persistent registry with new fingerprints.
    Returns an analysis report dict.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    fp_to_items: Dict[str, List[int]] = defaultdict(list)   # fp -> list of item indices
    new_fps: List[str] = []
    stale_items: List[Dict] = []
    synthetic_items: List[Dict] = []
    reuse_violations: List[Dict] = []

    for idx, item in enumerate(items):
        fp = make_fingerprint(item)
        # Inject fingerprint into item (non-destructive — adds field)
        item["_aie_fingerprint"] = fp
        fp_to_items[fp].append(idx)

        # Registry lookup
        if fp in registry:
            entry = registry[fp]
            seen_count = entry.get("seen_count", 1) + 1
            if update_registry:
                entry["seen_count"] = seen_count
                entry["last_seen"]  = now_iso
        else:
            seen_count = 1
            if update_registry:
                registry[fp] = {
                    "first_seen":   now_iso,
                    "last_seen":    now_iso,
                    "seen_count":   1,
                    "item_id":      item.get("id", ""),
                    "title_slug":   _title_slug(str(item.get("title") or ""))[:60],
                }
                new_fps.append(fp)

        if seen_count >= REUSE_WARN_COUNT:
            reuse_violations.append({
                "fingerprint": fp,
                "item_id":     item.get("id"),
                "title":       str(item.get("title") or "")[:80],
                "seen_count":  seen_count,
            })

        # Stale CVE check
        stale, cve_yr = is_stale_cve(item)
        if stale:
            item["_aie_stale"] = True
            item["_aie_cve_year"] = cve_yr
            stale_items.append({"id": item.get("id"), "cve_year": cve_yr,
                                 "title": str(item.get("title") or "")[:80]})

        # Synthetic marker check
        actor = str(item.get("actor_tag") or "")
        if actor in SYNTHETIC_MARKERS and not item.get("cvss_score") and not item.get("epss_score"):
            synthetic_items.append({"id": item.get("id"), "actor": actor,
                                    "title": str(item.get("title") or "")[:80]})

    # Intra-feed dedup collisions (same fingerprint on multiple items in this run)
    intra_collisions = {
        fp: indices for fp, indices in fp_to_items.items() if len(indices) > 1
    }

    return {
        "total_items":          len(items),
        "unique_fingerprints":  len(fp_to_items),
        "new_fingerprints":     len(new_fps),
        "intra_collisions":     len(intra_collisions),
        "intra_collision_fps":  list(intra_collisions.keys())[:20],
        "stale_cve_count":      len(stale_items),
        "stale_cve_ratio":      round(len(stale_items) / max(len(items), 1), 4),
        "stale_items":          stale_items[:20],
        "synthetic_count":      len(synthetic_items),
        "synthetic_ratio":      round(len(synthetic_items) / max(len(items), 1), 4),
        "synthetic_items":      synthetic_items[:20],
        "reuse_violations":     reuse_violations[:20],
        "reuse_violation_count": len(reuse_violations),
    }


def dedup_feed(items: List[Dict]) -> Tuple[List[Dict], int]:
    """
    Remove intra-feed fingerprint duplicates, keeping the first occurrence
    (which is typically the newest after sorting by published_at DESC).
    Returns (deduped_items, removed_count).
    """
    seen_fps: set = set()
    deduped: List[Dict] = []
    removed = 0
    for item in items:
        fp = item.get("_aie_fingerprint") or make_fingerprint(item)
        if fp in seen_fps:
            removed += 1
            log.debug("Dedup: removed duplicate fingerprint %s (id=%s)", fp, item.get("id"))
        else:
            seen_fps.add(fp)
            deduped.append(item)
    return deduped, removed


# ── CLI ─────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Advisory Immutability Engine v159.0"
    )
    parser.add_argument("--feed",   default=str(DEFAULT_FEED), help="Path to feed JSON")
    parser.add_argument("--check",  action="store_true",
                        help="Hard-fail (exit 1) on HARD violations")
    parser.add_argument("--report", action="store_true",
                        help="Report-only mode — always exit 0")
    parser.add_argument("--dedup",  action="store_true",
                        help="Write deduped feed back in-place (atomic)")
    parser.add_argument("--update-registry", action="store_true",
                        help="Update persistent registry with fingerprints from this run")
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        log.error("Feed not found: %s", feed_path)
        return 0 if args.report else 1

    try:
        raw = json.loads(feed_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Failed to parse feed: %s", exc)
        return 0 if args.report else 1

    items: List[Dict] = raw if isinstance(raw, list) else (raw.get("items") or [])
    log.info("Loaded %d items from %s", len(items), feed_path)

    registry = load_registry()
    log.info("Registry: %d known fingerprints", len(registry))

    analysis = analyze_feed(items, registry, update_registry=args.update_registry)

    # Dedup in-place
    removed = 0
    if args.dedup:
        items, removed = dedup_feed(items)
        analysis["dedup_removed"] = removed
        if removed > 0:
            log.info("Dedup: removed %d duplicate items", removed)
            try:
                out = items if isinstance(raw, list) else {**raw, "items": items}
                tmp = feed_path.with_suffix(".tmp_aie")
                tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(feed_path)
                log.info("Feed written (deduped): %s (%d items)", feed_path, len(items))
            except Exception as exc:
                log.error("Failed to write deduped feed: %s", exc)

    if args.update_registry:
        save_registry(registry)
        log.info("Registry saved: %d fingerprints", len(registry))

    # Build final report
    now_iso = datetime.now(timezone.utc).isoformat()
    report = {
        "generated_at":       now_iso,
        "feed":               str(feed_path),
        "registry_size":      len(registry),
        "dedup_removed":      removed,
        **analysis,
        "thresholds": {
            "reuse_warn_count":  REUSE_WARN_COUNT,
            "stale_cve_year":    STALE_CVE_YEAR,
            "synthetic_markers": list(SYNTHETIC_MARKERS),
        },
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        log.warning("Could not write report: %s", exc)

    # Determine status
    hard_violations = []
    if analysis["intra_collisions"] > 0:
        hard_violations.append(f"{analysis['intra_collisions']} intra-feed fingerprint collision(s)")
    if analysis["reuse_violation_count"] > 0:
        hard_violations.append(
            f"{analysis['reuse_violation_count']} advisory reuse violation(s) (seen >= {REUSE_WARN_COUNT}x)"
        )

    status = "FAIL" if hard_violations else "PASS"

    log.info("=" * 60)
    log.info("ADVISORY IMMUTABILITY ENGINE — %s", status)
    log.info("  Total items      : %d", analysis["total_items"])
    log.info("  Unique fingerprints: %d", analysis["unique_fingerprints"])
    log.info("  Intra-collisions : %d", analysis["intra_collisions"])
    log.info("  Stale CVEs       : %d (%.1f%%)", analysis["stale_cve_count"],
             analysis["stale_cve_ratio"] * 100)
    log.info("  Synthetic items  : %d (%.1f%%)", analysis["synthetic_count"],
             analysis["synthetic_ratio"] * 100)
    log.info("  Reuse violations : %d", analysis["reuse_violation_count"])
    lo