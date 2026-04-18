#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH SENTINEL APEX v114.0 — CANONICAL MANIFEST SHAPER
===============================================================================
Final-stage manifest cleaner. Runs AFTER bootstrap --force-rebuild and BEFORE
Pipeline Hardener + R2 upload.

CONTRACT (BLOCKING — exits non-zero on violation):
  Every advisory MUST have:
    - id           : non-empty string (auto-gen if missing)
    - title        : non-empty, non-brand
    - timestamp    : ISO-8601 UTC
    - risk_score   : float
    - severity     : CRITICAL|HIGH|MEDIUM|LOW|INFO
    - report_url   : /reports/YYYY/MM/<id>.html (relative)
    - source_url   : non-blogspot URL (may be empty)
    - tlp          : TLP marking
    - tags         : list

OPERATIONS:
  1. Strip brand entries
  2. Strip legacy `blog_url` field completely
  3. Strip blogspot.com / cyberbivash.blogspot.com URLs everywhere
  4. Auto-generate `id` for entries missing it (deterministic: sha1 of title+ts)
  5. Auto-derive `severity` from risk_score when invalid
  6. Compute `report_url` when missing
  7. Best-score-wins dedup by title (keeps enriched entry over bootstrap stub)
  8. Sort timestamp DESC -> risk_score DESC
  9. BLOCKING schema validation (exit 1 on any required-field violation)
 10. Atomic write via os.replace
===============================================================================
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT      = Path(__file__).resolve().parent.parent
MANIFEST_PATH  = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
PLATFORM_VERSION = "v114.0"

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
SEVERITY_VALID = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
REQUIRED_FIELDS = ("id", "title", "timestamp", "risk_score", "severity",
                   "report_url", "source_url", "tlp", "tags")


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{ts}] [CLEAN {PLATFORM_VERSION}] {msg}", flush=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha1_id(title: str, timestamp: str) -> str:
    return "intel--" + hashlib.sha1(f"{title}::{timestamp}".encode("utf-8")).hexdigest()[:24]


def strip_blog(url: str | None) -> str:
    if not url or not isinstance(url, str):
        return ""
    lower = url.lower()
    for host in BANNED_URL_HOSTS:
        if host in lower:
            return ""
    return url.strip()


def derive_report_url(intel_id: str, timestamp: str) -> str:
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    return f"/reports/{dt.year:04d}/{dt.month:02d}/{intel_id}.html"


def derive_severity(risk_score: float) -> str:
    if   risk_score >= 9.0: return "CRITICAL"
    elif risk_score >= 7.0: return "HIGH"
    elif risk_score >= 4.5: return "MEDIUM"
    elif risk_score >= 1.5: return "LOW"
    else:                   return "INFO"


def normalise_entry(item: dict) -> dict | None:
    """Return a canonical, schema-complete entry, or None if un-repairable."""
    out = dict(item)

    # -- title --
    title = (out.get("title") or out.get("name") or "").strip()
    if not title:
        return None
    if any(kw in title for kw in BRAND_KEYWORDS):
        return None
    out["title"] = title

    # -- timestamp --
    timestamp = (
        out.get("timestamp")
        or out.get("published")
        or out.get("generated_at")
        or out.get("created")
        or utc_now_iso()
    )
    out["timestamp"] = timestamp

    # -- risk_score (numeric float) --
    try:
        rs = float(out.get("risk_score") or out.get("cvss_score") or 0)
    except Exception:
        rs = 0.0
    out["risk_score"] = round(rs, 2)

    # -- severity (valid enum) --
    sev = str(out.get("severity") or "").upper().strip()
    if sev not in SEVERITY_VALID:
        sev = derive_severity(rs)
    out["severity"] = sev

    # -- id (auto-gen if missing) --
    intel_id = out.get("id") or out.get("stix_id") or ""
    if not intel_id or not isinstance(intel_id, str):
        intel_id = sha1_id(title, timestamp)
    out["id"]      = intel_id
    out["stix_id"] = intel_id

    # -- source_url (strip blog hosts) --
    out["source_url"] = strip_blog(out.get("source_url") or out.get("url") or "")

    # -- report_url (required; derive if missing) --
    rep = out.get("report_url") or ""
    if not isinstance(rep, str):
        rep = ""
    # v116.3.0: Rewrite dead reports.cyberdudebivash.com (DNS NXDOMAIN) → intel domain
    if "reports.cyberdudebivash.com" in rep:
        rep = rep.replace("https://reports.cyberdudebivash.com", "https://intel.cyberdudebivash.com")
    if not rep or "blogspot" in rep.lower():
        rep = derive_report_url(intel_id, timestamp)
    out["report_url"] = rep

    # -- validation_status: preserve if set, default to 'pending' --
    if not out.get("validation_status"):
        out["validation_status"] = "pending"

    # -- blog_url: HARD REMOVE (legacy field) --
    out.pop("blog_url", None)

    # -- tlp --
    tlp = (out.get("tlp") or out.get("tlp_label") or "TLP:CLEAR").upper()
    out["tlp"] = tlp

    # -- tags (list) --
    tags = out.get("tags") or out.get("categories") or []
    if not isinstance(tags, list):
        tags = [str(tags)]
    out["tags"] = tags

    # -- description: strip "Tactical cluster: " prefix --
    desc = out.get("description") or title
    if isinstance(desc, str) and desc.startswith("Tactical cluster: "):
        desc = desc[len("Tactical cluster: "):]
    out["description"] = desc

    out["schema_version"] = PLATFORM_VERSION
    return out


def validate_entry(entry: dict) -> list[str]:
    """Return list of missing/invalid required fields."""
    errors: list[str] = []
    for f in REQUIRED_FIELDS:
        v = entry.get(f)
        if v is None:
            errors.append(f"missing:{f}")
        elif f in ("id", "title", "timestamp", "report_url", "tlp") and not isinstance(v, str):
            errors.append(f"wrong-type:{f}")
        elif f == "risk_score" and not isinstance(v, (int, float)):
            errors.append(f"wrong-type:{f}")
        elif f == "severity" and v not in SEVERITY_VALID:
            errors.append(f"enum:{f}={v}")
        elif f == "tags" and not isinstance(v, list):
            errors.append(f"wrong-type:{f}")
    # report_url must be /reports/YYYY/MM/<id>.html OR non-empty absolute (NOT reports.cyberdudebivash.com)
    rep = entry.get("report_url") or ""
    if not rep:
        errors.append("empty:report_url")
    if "blogspot" in rep.lower():
        errors.append("banned-host:report_url")
    if "reports.cyberdudebivash.com" in rep:
        errors.append("stale-domain:report_url")
    return errors


def main() -> int:
    if not MANIFEST_PATH.exists():
        log(f"FATAL: {MANIFEST_PATH} does not exist.")
        return 1

    with open(MANIFEST_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    is_dict = isinstance(data, dict)
    items = data.get("advisories", data.get("reports", data if isinstance(data, list) else []))
    if not isinstance(items, list):
        log(f"FATAL: manifest advisories is not a list (type={type(items).__name__})")
        return 1

    original_count = len(items)
    log(f"Loaded {original_count} raw entries from {MANIFEST_PATH}")

    # --- Normalise every entry ---
    normalised: list[dict] = []
    dropped_brand  = 0
    dropped_empty  = 0
    for item in items:
        if not isinstance(item, dict):
            dropped_empty += 1
            continue
        norm = normalise_entry(item)
        if norm is None:
            if any(kw in (item.get("title") or "") for kw in BRAND_KEYWORDS):
                dropped_brand += 1
            else:
                dropped_empty += 1
            continue
        normalised.append(norm)

    # --- Best-score-wins dedup by title ---
    seen_by_title: dict[str, int] = {}
    deduped: list[dict] = []
    dedup_removed = 0
    for item in normalised:
        key = item["title"].strip().lower()
        if key in seen_by_title:
            dedup_removed += 1
            idx = seen_by_title[key]
            if item["risk_score"] > deduped[idx]["risk_score"]:
                deduped[idx] = item
            continue
        seen_by_title[key] = len(deduped)
        deduped.append(item)

    # --- Sort: timestamp DESC -> risk_score DESC ---
    def _sort_key(e: dict) -> tuple[str, float]:
        return (e.get("timestamp") or "", float(e.get("risk_score") or 0))
    deduped.sort(key=_sort_key, reverse=True)

    # --- BLOCKING validation ---
    invalid = []
    for i, entry in enumerate(deduped):
        errs = validate_entry(entry)
        if errs:
            invalid.append((i, entry.get("id", "?"), entry.get("title", "?")[:50], errs))

    if invalid:
        log(f"FATAL: schema validation FAILED for {len(invalid)} entries:")
        for idx, eid, etitle, errs in invalid[:20]:
            log(f"  [{idx}] id={eid} title={etitle!r} -> {errs}")
        log("This is a P0 BLOCKING failure. Manifest will NOT be rewritten.")
        return 1

    final_count = len(deduped)
    log(f"Cleanup complete: original={original_count} brand={dropped_brand} "
        f"empty={dropped_empty} dedup={dedup_removed} final={final_count}")

    # --- Write canonical manifest ---
    payload = {
        "version":         PLATFORM_VERSION,
        "platform":        "SENTINEL-APEX",
        "generated_at":    utc_now_iso(),
        "cleaned_at":      utc_now_iso(),
        "total_reports":   final_count,
        "entry_count":     final_count,
        "schema_version":  PLATFORM_VERSION,
        "sort_order":      "timestamp DESC, risk_score DESC",
        "source_of_truth": "data/stix/CDB-APEX-*.json",
        "advisories":      deduped,
    }
    tmp = MANIFEST_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, MANIFEST_PATH)
    log(f"OK: clean manifest written ({final_count} entries, atomic)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
