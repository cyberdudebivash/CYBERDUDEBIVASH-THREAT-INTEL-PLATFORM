#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH SENTINEL APEX v134.0 — SOVEREIGN BOOTSTRAP
===============================================================================
Single-source-of-truth bootstrap. Rebuilds data/stix/feed_manifest.json from
ONE source only: the live STIX bundles in data/stix/CDB-APEX-*.json produced
by the intel engine in the current workflow run.

NO multi-source UNION merge.
NO reading from apex_enriched_manifest, apex_v2_manifest, validated_manifest.
NO reading from pre_run_manifest snapshots.
NO carry-over of stale entries lacking `id` or `report_url`.

Every entry emitted by this bootstrap SATISFIES THE SCHEMA CONTRACT:
    id           : str (auto-generated if missing)
    title        : str (non-empty, non-brand)
    timestamp    : ISO-8601 UTC (tz-aware)
    risk_score   : float
    severity     : {CRITICAL, HIGH, MEDIUM, LOW, INFO}
    report_url   : relative path /reports/YYYY/MM/<id>.html (populated post-gen)
    source_url   : canonical upstream URL
    tlp          : TLP marking
    tags         : list[str]

v134.0 changes vs v134.x:
  * Removed stale manifest UNION (root cause of 2-day-old intel regression)
  * Removed pre_run snapshot loader
  * Removed apex_enriched / apex_v2 / validated_manifest ingress
  * Enforced schema contract - entries missing required fields are DROPPED,
    not merged with placeholders
  * Auto-generate deterministic `id` = "intel--" + sha1(title + timestamp)[:24]
  * Blog URLs (blogspot.com) always stripped
  * Sort: timestamp DESC -> risk_score DESC (canonical)
  * Atomic write via os.replace
  * Writes canonical manifest ONLY to data/stix/feed_manifest.json
===============================================================================
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT       = Path(__file__).resolve().parent.parent
STIX_DIR        = REPO_ROOT / "data" / "stix"
MANIFEST_PATH   = STIX_DIR / "feed_manifest.json"
REPORTS_ROOT    = REPO_ROOT / "reports"
PLATFORM_VERSION= "v134.0"
MAX_MANIFEST_ENTRIES = 500

BRAND_KEYWORDS = (
    "CYBERDUDEBIVASH\u00ae PRIVATE LIMITED",
    "OFFICIAL WORKPLACE",
    "GST & PAN VERIFIED",
    "GLOBAL CYBERSECURITY AUTHORITY",
)

BANNED_URL_HOSTS = (
    "blogspot.com",
    "cyberbivash.blogspot.com",
    "cyberdudebivash-news.blogspot.com",
    "blogger.googleusercontent.com",
)

# NOTE: "INFO" excluded — validate_repo.py V5 rejects it as a threat severity.
SEVERITY_VALID = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{ts}] [BOOTSTRAP {PLATFORM_VERSION}] {msg}", flush=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha1_short(text: str, n: int = 24) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace"), usedforsecurity=False).hexdigest()[:n]


def gen_intel_id(title: str, timestamp: str) -> str:
    """Deterministic intel id. Same title+timestamp -> same id across runs."""
    return "intel--" + sha1_short(f"{title}::{timestamp}")


def strip_blog_url(url: str | None) -> str:
    if not url or not isinstance(url, str):
        return ""
    lower = url.lower()
    for host in BANNED_URL_HOSTS:
        if host in lower:
            return ""
    return url.strip()


def iso_month_path(timestamp: str) -> tuple[str, str]:
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    return f"{dt.year:04d}", f"{dt.month:02d}"


def build_report_url(intel_id: str, timestamp: str) -> str:
    yyyy, mm = iso_month_path(timestamp)
    return f"/reports/{yyyy}/{mm}/{intel_id}.html"


def is_brand(title: str) -> bool:
    return any(kw in title for kw in BRAND_KEYWORDS)


def stix_bundle_to_entry(bundle_path: Path) -> dict | None:
    try:
        with open(bundle_path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except Exception as e:
        log(f"  skip {bundle_path.name}: parse error {e!r}")
        return None

    if not isinstance(bundle, dict):
        return None
    objects = bundle.get("objects") or []
    if not isinstance(objects, list) or not objects:
        return None

    primary = None
    for obj in objects:
        t = obj.get("type")
        if t in ("report", "intrusion-set", "indicator"):
            primary = obj
            break
    if primary is None:
        primary = objects[0]

    # v160.1 P0 FIX: For intrusion-set objects the advisory headline lives in
    # 'description', NOT 'name'. The 'name' field is the campaign codename
    # (e.g. "CDB-UNATTR-CVE Campaign") which is shared across many bundles.
    # Using 'name' as title caused dedup-by-title to collapse all bundles of the
    # same campaign type into a single manifest entry (61 bundles → 8 entries),
    # triggering STAGE 2.5 FATAL (minimum 10). Fix: use 'description' for
    # intrusion-set primary objects; use 'name' for report/indicator as before.
    primary_type = primary.get("type") if primary else ""
    if primary_type == "intrusion-set":
        title = (
            primary.get("description")
            or primary.get("name")
            or bundle.get("name")
            or bundle_path.stem
        ).strip()
    else:
        title = (
            primary.get("name")
            or primary.get("title")
            or bundle.get("name")
            or bundle_path.stem
        ).strip()
    if not title or is_brand(title):
        return None

    timestamp = (
        primary.get("modified")
        or primary.get("created")
        or bundle.get("created")
        or utc_now_iso()
    )

    stix_id = primary.get("id") or bundle.get("id") or ""
    intel_id = stix_id if (stix_id and stix_id.startswith("intel--")) else gen_intel_id(title, timestamp)

    risk_score = bundle.get("x_risk_score")
    if risk_score is None:
        conf = primary.get("confidence")
        risk_score = (conf / 10.0) if conf else 5.0
    try:
        risk_score = float(risk_score)
    except Exception:
        risk_score = 5.0

    severity = (bundle.get("x_severity") or primary.get("x_severity") or "").upper().strip()
    if severity not in SEVERITY_VALID:
        if   risk_score >= 9.0: severity = "CRITICAL"
        elif risk_score >= 7.0: severity = "HIGH"
        elif risk_score >= 4.5: severity = "MEDIUM"
        elif risk_score >= 1.5: severity = "LOW"
        else:                   severity = "LOW"   # FIX v161.4: INFO rejected by validate_repo V5

    source_url = ""
    refs = primary.get("external_references") or []
    if isinstance(refs, list):
        for ref in refs:
            u = ref.get("url") or ""
            u_clean = strip_blog_url(u)
            if u_clean:
                source_url = u_clean
                break
    if not source_url:
        source_url = strip_blog_url(bundle.get("x_source_url", ""))

    description = primary.get("description") or bundle.get("description") or title
    if isinstance(description, str) and description.startswith("Tactical cluster: "):
        description = description[len("Tactical cluster: "):]

    tags = primary.get("labels") or bundle.get("x_tags") or []
    if not isinstance(tags, list):
        tags = [str(tags)]

    tlp = (bundle.get("x_tlp") or primary.get("x_tlp") or "TLP:CLEAR").upper()

    ttps = [t for t in tags if isinstance(t, str) and t.startswith("T1")]

    iocs = bundle.get("x_iocs") or []
    if not isinstance(iocs, list):
        iocs = []

    entry = {
        "id":              intel_id,
        "stix_id":         intel_id,
        "title":           title,
        "timestamp":       timestamp,
        "risk_score":      round(risk_score, 2),
        "severity":        severity,
        "report_url":      build_report_url(intel_id, timestamp),
        "source_url":      source_url,
        "tlp":             tlp,
        "tags":            tags,
        "description":     description,
        "ttps":            ttps,
        "mitre_tactics":   ttps,
        "iocs":            iocs,
        "indicator_count": len(iocs),
        "confidence":        float(primary.get("confidence") or 0),
        "confidence_score":  float(primary.get("confidence") or 0),
        "cvss_score":        bundle.get("x_cvss_score"),
        "epss_score":        bundle.get("x_epss_score"),
        "kev_present":       bool(bundle.get("x_kev_present", False)),
        "threat_type":       bundle.get("x_threat_type") or primary.get("x_threat_type") or "General",
        "feed_source":       bundle.get("x_feed_source") or "SENTINEL-APEX",
        "source":            bundle.get("x_source") or "SENTINEL-APEX",
        # v143.5 FIX: derive actor_tag from x_actor_tag field first, then extract
        # CDB campaign ID from the bundle title (e.g. "CDB-APT-41 Campaign" → "CDB-APT-41"),
        # then fall back to category-keyword match, then "UNC-CDB" as last resort.
        "actor_tag":         (primary.get("x_actor_tag")
                              or re.match(r"(CDB-[A-Z0-9]+-[A-Z0-9]+)", title or "")
                                  and re.match(r"(CDB-[A-Z0-9]+-[A-Z0-9]+)", title or "").group(1)
                              or "UNC-CDB"),
        "stix_file":         f"data/stix/{bundle_path.name}",
        "stix_object_count": len(objects),
        "stix_version":      "2.1",
        "schema_version":    PLATFORM_VERSION,
        "status":            "active",
        "published":         timestamp,  # FIX v161.4: ISO-8601 string (validate_repo V1 — must NOT be bool)
        "generated_at":      utc_now_iso(),
    }
    return entry


def ensure_dirs() -> None:
    for rel in (
        "data/stix", "data/status", "data/logs", "data/health",
        "data/ai_intelligence", "api", "api/ai", "reports",
        "secrets",
    ):
        (REPO_ROOT / rel).mkdir(parents=True, exist_ok=True)


def _load_previous_manifest() -> list[dict]:
    """
    Load the existing manifest from disk (if it exists and is valid).
    Used as a fallback when the current pipeline produces zero new STIX bundles
    so historical intelligence is not silently discarded.
    Returns a list of valid manifest entries, empty list if none found.
    """
    if not MANIFEST_PATH.exists():
        return []
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = (
                raw.get("advisories")
                or raw.get("items")
                or raw.get("reports")
                or []
            )
        else:
            items = []
        # Only keep valid dicts with required fields
        valid = [
            e for e in items
            if isinstance(e, dict)
            and e.get("id")
            and e.get("title")
            and not is_brand(e.get("title", ""))
        ]
        log(f"[PRESERVATION] Loaded {len(valid)} valid entries from existing manifest")
        return valid
    except Exception as ex:
        log(f"[PRESERVATION] Could not load previous manifest (non-fatal): {ex!r}")
        return []


def rebuild_manifest(force: bool) -> int:
    """
    Rebuild feed_manifest.json from live STIX bundles.

    v134.1 PRESERVATION POLICY (CRIT-01 FIX):
    When the current pipeline produces zero new STIX bundles (e.g. all sources
    blocked by anti-bot, all entries failed quality gate), the previous manifest
    is preserved INTACT rather than being replaced with an empty one.
    This prevents the catastrophic 2845→0 shrink that loses all historical intel.

    Preservation rule:
      - If STIX bundles produce >= 1 entry  → write fresh manifest (normal path)
      - If STIX bundles produce 0 entries   → preserve previous manifest unchanged
    """
    bundles = sorted(STIX_DIR.glob("CDB-APEX-*.json"))
    log(f"Found {len(bundles)} STIX bundles under {STIX_DIR}")

    entries: list[dict] = []
    seen_ids: set[str] = set()
    seen_titles: dict[str, int] = {}

    for bp in bundles:
        entry = stix_bundle_to_entry(bp)
        if entry is None:
            continue

        if entry["id"] in seen_ids:
            continue
        title_lc = entry["title"].strip().lower()
        if title_lc in seen_titles:
            idx = seen_titles[title_lc]
            existing = entries[idx]
            if entry["risk_score"] > existing["risk_score"]:
                entries[idx] = entry
                seen_ids.discard(existing["id"])
                seen_ids.add(entry["id"])
            continue

        seen_titles[title_lc] = len(entries)
        seen_ids.add(entry["id"])
        entries.append(entry)

    # v134.1 CRIT-01 FIX: Zero-bundle preservation guard
    # If the current pipeline produced NO entries, preserve the previous manifest
    # intact. Writing an empty manifest here would discard all historical intel.
    if len(entries) == 0:
        previous = _load_previous_manifest()
        if previous:
            log(
                f"[PRESERVATION] STIX bundles produced 0 entries this run. "
                f"Preserving {len(previous)} entries from previous manifest "
                f"(pipeline-generated-zero guard). Previous manifest NOT overwritten."
            )
            # Do not call _write_manifest() -- leave existing file unchanged.
            return 0
        else:
            log(
                "[PRESERVATION] STIX bundles produced 0 entries AND no previous "
                "manifest exists. Writing empty manifest (cold start)."
            )
            _write_manifest([])
            return 0

    def _sort_key(e: dict) -> tuple:
        return (e.get("timestamp") or "", float(e.get("risk_score") or 0))

    entries.sort(key=_sort_key, reverse=True)

    if len(entries) > MAX_MANIFEST_ENTRIES:
        entries = entries[:MAX_MANIFEST_ENTRIES]

    _write_manifest(entries)
    log(f"Manifest rebuilt: {len(entries)} entries (force={force})")
    return len(entries)


def _write_manifest(entries: list) -> None:
    payload = {
        "version":          PLATFORM_VERSION,
        "platform":         "SENTINEL-APEX",
        "generated_at":     utc_now_iso(),
        "total_reports":    len(entries),
        "entry_count":      len(entries),
        "schema_version":   PLATFORM_VERSION,
        "sort_order":       "timestamp DESC, risk_score DESC",
        "source_of_truth":  "data/stix/CDB-APEX-*.json",
        "advisories":       entries,
    }
    STIX_DIR.mkdir(parents=True, exist_ok=True)
    tmp = MANIFEST_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, MANIFEST_PATH)
    log(f"Wrote {MANIFEST_PATH} ({len(entries)} entries, atomic)")


def ensure_minimum_manifest() -> None:
    if MANIFEST_PATH.exists():
        return
    _write_manifest([])
    log(f"Initialised empty manifest at {MANIFEST_PATH}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=f"SENTINEL APEX bootstrap {PLATFORM_VERSION}")
    parser.add_argument("--force-rebuild", action="store_true",
                        help="Force full rebuild of feed_manifest.json from live STIX bundles.")
    args = parser.parse_args(argv)

    try:
        ensure_dirs()
        log("Directories ensured.")

        if args.force_rebuild:
            count = rebuild_manifest(force=True)
            if count == 0:
                log("WARNING: rebuild produced zero entries - manifest preserved or empty.")
        else:
            ensure_minimum_manifest()

        log("Bootstrap OK.")
        return 0
    except Exception as e:
        log(f"ERROR (non-fatal, exit 0 per self-healing contract): {e!r}")
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
