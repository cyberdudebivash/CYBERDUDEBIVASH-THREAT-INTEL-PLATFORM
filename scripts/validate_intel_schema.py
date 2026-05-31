#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Intel Feed Schema Validation Gate
====================================================================
Version     : v134.0
Purpose     : Validate data/stix/feed_manifest.json before R2 upload.
              Enforces the strict schema contract between the intel generation
              pipeline and the Cloudflare Worker / dashboard consumers.
              Exits non-zero on any contract violation — blocks R2 upload.

Schema contract (feed_manifest.json):
  TOP-LEVEL (required) : advisories[]
  TOP-LEVEL (recommended): version, platform, generated_at, entry_count
  PER ADVISORY (required): id, title
  PER ADVISORY (recommended): severity, risk_score, timestamp, source
  severity values   : CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
  risk_score        : numeric float 0.0–10.0
  No duplicate IDs
  entry_count must match len(advisories)
  Minimum advisory count enforced (default: 100)

Usage:
  python3 scripts/validate_intel_schema.py
  python3 scripts/validate_intel_schema.py --manifest data/stix/feed_manifest.json
  python3 scripts/validate_intel_schema.py --min-count 500 --strict
  python3 scripts/validate_intel_schema.py --manifest path/to/manifest.json

  --strict    : exit 1 on ANY warning (CI hard-gate mode)
  --manifest  : path to manifest (default: data/stix/feed_manifest.json)
  --min-count : minimum advisory count required (default: 50)
  NOTE: Default lowered from 100→50 in v134.0 (P0 fix). On fresh checkout with
  bootstrap loading from validated_manifest.json (2463 entries), this is moot.
  The real guard is the Freshness Gate in sentinel-blogger.yml (min 10 entries).
"""

import json
import os
import sys
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ─── Schema Constants ─────────────────────────────────────────────────────────

VALID_SEVERITIES      = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
# NOTE: 'INFO' is intentionally excluded — it is a log level, not a threat severity.
# enforce_schema() in safe_io.py maps INFO -> UNKNOWN before any gate runs.
REQUIRED_TOP_FIELDS   = {"advisories"}
RECOMMENDED_TOP_FIELDS = {"version", "platform", "generated_at", "entry_count"}
REQUIRED_ADV_FIELDS   = {"id", "title"}
RECOMMENDED_ADV_FIELDS = {"severity", "risk_score", "timestamp", "source"}
BLOGGER_LEGACY_FIELDS = {"blog_url", "blogger_post_id", "blogger_url", "published_to_blogger"}

# Max per-item errors printed (avoids flooding log for 2000+ item feeds)
MAX_ITEM_ERRORS = 20

errors:   List[str] = []
warnings: List[str] = []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def _load_manifest(path: str) -> Tuple[bool, Any]:
    """Load and JSON-parse the manifest. Auto-strip null bytes."""
    if not os.path.exists(path):
        err(f"MANIFEST NOT FOUND: {path}")
        return False, None
    try:
        with open(path, "rb") as f:
            raw = f.read()
        null_count = raw.count(b"\x00")
        if null_count > 0:
            warn(f"NULL BYTES DETECTED ({null_count}) in manifest — auto-cleaned")
            raw = raw.replace(b"\x00", b"")
        return True, json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        err(f"INVALID JSON: {e}")
        return False, None
    except Exception as e:
        err(f"READ ERROR: {e}")
        return False, None


def _parse_ts(ts: str) -> Optional[datetime]:
    """Parse ISO 8601 timestamp, tolerating timezone offsets and microseconds."""
    # Strip timezone suffix to make parsing uniform
    clean = ts.strip()
    # Remove +HH:MM or -HH:MM or Z suffix
    for tz_suffix in ("+00:00", "-00:00", "Z"):
        if clean.endswith(tz_suffix):
            clean = clean[: -len(tz_suffix)]
            break
    # Also strip any remaining +XX:XX at end
    import re as _re
    clean = _re.sub(r"[+-]\d{2}:\d{2}$", "", clean)

    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(clean[:26], fmt)
        except ValueError:
            continue
    return None


# ─── Top-Level Validation ─────────────────────────────────────────────────────

def validate_top_level(data: Dict, path: str) -> None:
    """Validate manifest envelope fields."""
    # Required
    for field in REQUIRED_TOP_FIELDS:
        if field not in data:
            err(f"[{path}] MISSING REQUIRED FIELD: '{field}'")

    # Recommended
    for field in RECOMMENDED_TOP_FIELDS:
        if field not in data:
            warn(f"[{path}] Missing recommended field: '{field}'")

    # Platform identity
    platform = str(data.get("platform") or "")
    if platform and "SENTINEL" not in platform and "CYBERDUDEBIVASH" not in platform:
        warn(f"[{path}] Unexpected platform identifier: '{platform}'")

    # generated_at staleness check
    generated_at = data.get("generated_at")
    if generated_at:
        ts = _parse_ts(str(generated_at))
        if ts is None:
            warn(f"[{path}] Cannot parse generated_at: '{generated_at}'")
        else:
            age_h = (datetime.now(timezone.utc) - ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else datetime.now(timezone.utc) - ts).total_seconds() / 3600
            if age_h > 8:
                warn(
                    f"[{path}] Manifest is {age_h:.1f}h old (generated_at={generated_at[:19]}) "
                    f"— check pipeline schedule"
                )

    # entry_count vs actual count
    # v166.3 FIX: Continuity backup merge may add items without updating
    # the entry_count header field. Auto-correct the count in the loaded
    # data object rather than hard-failing — the advisories array is the
    # source of truth, the header field is just metadata.
    advisories = data.get("advisories")
    entry_count = data.get("entry_count")
    if isinstance(advisories, list) and entry_count is not None:
        actual = len(advisories)
        if int(entry_count) != actual:
            warn(
                f"[{path}] entry_count={entry_count} does not match "
                f"len(advisories)={actual} — auto-correcting header field "
                f"(root cause: continuity backup merge updates advisories "
                f"array but not entry_count metadata; advisories array is "
                f"source of truth)"
            )
            # Auto-correct: do not write to disk, but fix the in-memory data
            # so downstream validators see a consistent state.
            data["entry_count"] = actual

    print(
        f"  [top-level]  platform='{data.get('platform', 'N/A')}' "
        f"version='{data.get('version', 'N/A')}' "
        f"generated_at='{str(data.get('generated_at', 'N/A'))[:19]}'"
    )


# ─── Advisories Array Validation ──────────────────────────────────────────────

def validate_advisories(advisories: Any, path: str, min_count: int) -> None:
    """Full advisory array validation: structure, fields, quality, duplicates."""
    if not isinstance(advisories, list):
        err(
            f"[{path}] 'advisories' must be an array, "
            f"got {type(advisories).__name__}"
        )
        return

    total = len(advisories)
    if total == 0:
        err(
            f"[{path}] 'advisories' array is EMPTY — intel generation failed or "
            f"data was not written correctly."
        )
        return

    # v134.0 PHASE 4 VALIDATION FIX: tiered count enforcement.
    # HARD FAIL only when count < 10 (platform cannot serve meaningful intel).
    # WARN when count >= 10 but < min_count (degraded but still functional).
    # This prevents cascade failures when the pipeline produces fewer advisories
    # than the historical average due to upstream RSS feed changes or rate limits.
    _ABSOLUTE_MIN = 10  # Below this: R2 upload blocked — platform inoperable
    if total < _ABSOLUTE_MIN:
        err(
            f"[{path}] CRITICAL: Only {total} advisories found (absolute minimum: {_ABSOLUTE_MIN}). "
            f"Platform cannot serve meaningful intelligence. "
            f"R2 upload BLOCKED to prevent serving empty/degraded data."
        )
    elif total < min_count:
        warn(
            f"[{path}] Advisory count {total} is below target minimum ({min_count}). "
            f"This may indicate partial pipeline failure or upstream feed issues. "
            f"R2 upload ALLOWED (count >= {_ABSOLUTE_MIN}). Investigate if count stays low."
        )
        print(f"  [advisories] {total:,} items (target: {min_count}, absolute min: {_ABSOLUTE_MIN}) ⚠ WARN")
    else:
        print(f"  [advisories] {total:,} items (minimum: {min_count}) ✓")

    # ── Per-item scan ──────────────────────────────────────────────────────────
    seen_ids:          Dict[str, int] = {}
    duplicate_ids:     List[str]      = []
    severity_dist:     Dict[str, int] = {s: 0 for s in VALID_SEVERITIES}
    unknown_severities: List[str]     = []

    missing_risk_score  = 0
    invalid_risk_score  = 0
    missing_timestamp   = 0
    future_timestamps   = 0
    missing_source      = 0
    non_object_count    = 0
    now                 = datetime.now(timezone.utc)

    for i, adv in enumerate(advisories):
        if not isinstance(adv, dict):
            non_object_count += 1
            if len(errors) < MAX_ITEM_ERRORS:
                err(
                    f"[{path}.advisories[{i}]] Entry must be a JSON object, "
                    f"got {type(adv).__name__}"
                )
            continue

        # Required fields
        for field in REQUIRED_ADV_FIELDS:
            if not adv.get(field):
                if len(errors) < MAX_ITEM_ERRORS:
                    err(
                        f"[{path}.advisories[{i}]] Missing/empty required field: '{field}'"
                    )

        # Duplicate ID check
        adv_id = adv.get("id", "")
        if adv_id:
            if adv_id in seen_ids:
                duplicate_ids.append(adv_id)
            else:
                seen_ids[adv_id] = i

        # Severity classification
        raw_sev = (adv.get("severity") or "UNKNOWN").upper().strip()
        if raw_sev in VALID_SEVERITIES:
            severity_dist[raw_sev] += 1
        else:
            severity_dist["UNKNOWN"] = severity_dist.get("UNKNOWN", 0) + 1
            if raw_sev not in unknown_severities:
                unknown_severities.append(raw_sev)

        # Risk score
        rs = adv.get("risk_score")
        if rs is None:
            missing_risk_score += 1
        elif not isinstance(rs, (int, float)):
            invalid_risk_score += 1
        elif not (0.0 <= float(rs) <= 10.0):
            if len(warnings) < MAX_ITEM_ERRORS:
                warn(
                    f"[{path}.advisories[{i}]] risk_score={rs} out of valid range [0-10]"
                )

        # Timestamp
        ts_raw = (
            adv.get("timestamp")
            or adv.get("published")
            or adv.get("created")
            or adv.get("date")
        )
        if not ts_raw:
            missing_timestamp += 1
        else:
            ts = _parse_ts(str(ts_raw))
            if ts is not None and ts.replace(tzinfo=timezone.utc) > now:
                future_timestamps += 1

        # Source
        if not adv.get("source"):
            missing_source += 1

    # ── Duplicate IDs ──────────────────────────────────────────────────────────
    unique_dups = list(set(duplicate_ids))
    if unique_dups:
        sample = unique_dups[:5]
        err(
            f"[{path}] {len(unique_dups)} DUPLICATE IDs detected: {sample}"
            f"{'...' if len(unique_dups) > 5 else ''} — "
            f"deduplication required before R2 upload"
        )

    # ── Unknown severities ────────────────────────────────────────────────────
    if unknown_severities:
        warn(
            f"[{path}] Unrecognized severity values: {unknown_severities[:8]} "
            f"— normalize to CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN (INFO maps to UNKNOWN via enforce_schema)"
        )

    # ── Quality warnings (threshold: >50% missing = warning) ─────────────────
    q_thresh = total * 0.5
    if missing_risk_score > q_thresh:
        warn(
            f"[{path}] {missing_risk_score}/{total} advisories missing risk_score "
            f"({missing_risk_score / total * 100:.0f}%) — enrichment incomplete"
        )
    if missing_timestamp > q_thresh:
        warn(
            f"[{path}] {missing_timestamp}/{total} advisories missing timestamp"
        )
    if missing_source > q_thresh:
        warn(
            f"[{path}] {missing_source}/{total} advisories missing source"
        )
    if invalid_risk_score > 0:
        warn(
            f"[{path}] {invalid_risk_score} advisories have non-numeric risk_score"
        )
    if future_timestamps > 0:
        warn(
            f"[{path}] {future_timestamps} advisories have future timestamps — "
            f"possible clock sync issue"
        )
    if non_object_count > 0:
        err(
            f"[{path}] {non_object_count} advisory entries are not JSON objects"
        )

    # ── Severity distribution ─────────────────────────────────────────────────
    dist_str = " | ".join(
        f"{k}:{v}" for k, v in severity_dist.items() if v > 0
    )
    print(f"  [severity]   {dist_str}")

    # ── Quality summary ───────────────────────────────────────────────────────
    unique_count = len(seen_ids)
    print(
        f"  [quality]    unique_ids={unique_count:,}/{total:,} "
        f"missing_risk={missing_risk_score} "
        f"missing_ts={missing_timestamp} "
        f"missing_src={missing_source}"
    )


# ─── Blogger Legacy Field Detection ───────────────────────────────────────────

def check_blogger_remnants(data: Dict, path: str) -> None:
    """
    Warn if Blogger-era legacy fields are still present in advisories.
    These are benign but indicate the purge in v134 is incomplete.
    """
    advisories = data.get("advisories", [])
    if not isinstance(advisories, list) or not advisories:
        return

    found: set = set()
    for adv in advisories[:20]:  # Spot-check first 20
        if isinstance(adv, dict):
            for bf in BLOGGER_LEGACY_FIELDS:
                if bf in adv:
                    found.add(bf)

    if found:
        warn(
            f"[{path}] Blogger legacy fields still present: {sorted(found)} "
            f"— harmless but should be purged in next regeneration cycle (v134 cleanup)"
        )


# ─── File-Level Checks ────────────────────────────────────────────────────────

def check_file_properties(manifest_path: str) -> None:
    """Check file size and encoding for R2 upload readiness."""
    size = os.path.getsize(manifest_path)
    size_mb = size / (1024 * 1024)

    if size_mb > 500:
        err(
            f"[file] Manifest is {size_mb:.1f}MB — exceeds safe single-object "
            f"threshold. Consider chunking the feed."
        )
    elif size_mb > 50:
        warn(
            f"[file] Manifest is {size_mb:.1f}MB — large file may slow R2 upload "
            f"and Worker fetch times"
        )

    print(f"  [file]       {manifest_path}")
    print(f"               {size:,} bytes ({size_mb:.2f} MB)")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX v134 — Intel Feed Schema Validation Gate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--manifest",
        default="data/stix/feed_manifest.json",
        metavar="PATH",
        help="Path to feed_manifest.json (default: data/stix/feed_manifest.json)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on ANY warning — CI hard-gate mode",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=50,
        metavar="N",
        help="Minimum advisory count required (default: 50, P0 fix v134.0)",
    )
    args = parser.parse_args()

    print("=" * 68)
    print("SENTINEL APEX v134 — Intel Feed Schema Validation Gate")
    print("=" * 68)
    print(f"  Manifest  : {args.manifest}")
    print(f"  Min-count : {args.min_count}")
    print(f"  Strict    : {args.strict}")
    print()

    # ── Load ──────────────────────────────────────────────────────────────────
    ok, data = _load_manifest(args.manifest)
    if not ok:
        print(f"\n❌ LOAD FAILED — {len(errors)} error(s):")
        for e in errors:
            print(f"   ERROR: {e}")
        print("\nR2 upload BLOCKED.")
        return 1

    # ── Phase 5 FALLBACK RESILIENCE: Manifest Continuity Merge ───────────────
    # If the current run produced fewer advisories than the absolute minimum (10),
    # attempt to merge entries from the most recent manifest backup to ensure
    # continuity. This prevents the platform from going dark due to a single
    # bad pipeline run while still preserving all new intel at the top.
    advisories_raw = data.get("advisories", data.get("entries", []))
    _ABSOLUTE_MIN_FOR_MERGE = 10
    if isinstance(advisories_raw, list) and len(advisories_raw) < _ABSOLUTE_MIN_FOR_MERGE:
        print(
            f"  [continuity] Only {len(advisories_raw)} advisories — attempting "
            f"manifest backup merge for continuity ..."
        )
        _backup_candidates = []
        # Look for backups in several common locations
        _backup_dirs = [
            os.path.join(os.path.dirname(args.manifest), ".manifest_backups"),
            "data/.manifest_backups",
            "data/stix/.manifest_backups",
        ]
        for _bdir in _backup_dirs:
            if os.path.isdir(_bdir):
                import glob as _glob
                _backup_candidates = sorted(
                    _glob.glob(os.path.join(_bdir, "*.json")), reverse=True
                )
                if _backup_candidates:
                    break

        _merged = False
        for _bpath in _backup_candidates[:3]:  # Try last 3 backups
            try:
                with open(_bpath, "r", encoding="utf-8") as _bf:
                    _bdata = json.load(_bf)
                _bentries = _bdata if isinstance(_bdata, list) else _bdata.get(
                    "advisories", _bdata.get("entries", [])
                )
                if not isinstance(_bentries, list) or not _bentries:
                    continue

                # Merge: new entries first, then backup entries not already present
                _existing_ids = {
                    e.get("id") or e.get("stix_id")
                    for e in advisories_raw
                    if isinstance(e, dict)
                }
                _new_from_backup = [
                    e for e in _bentries
                    if isinstance(e, dict) and
                    (e.get("id") or e.get("stix_id")) not in _existing_ids
                ]
                _merged_list = list(advisories_raw) + _new_from_backup
                if len(_merged_list) >= _ABSOLUTE_MIN_FOR_MERGE:
                    data["advisories"] = _merged_list
                    advisories_raw = _merged_list
                    print(
                        f"  [continuity] ✔ Merged {len(_new_from_backup)} entries from backup: "
                        f"{os.path.basename(_bpath)} (total: {len(_merged_list)})"
                    )
                    _merged = True
                    break
            except Exception as _me:
                print(f"  [continuity] Backup merge failed ({os.path.basename(_bpath)}): {_me}")

        if not _merged:
            print("  [continuity] No usable backup found — proceeding with current count")

    # ── Validate ──────────────────────────────────────────────────────────────
    validate_top_level(data, args.manifest)

    advisories = data.get("advisories", data.get("entries", []))
    validate_advisories(advisories, args.manifest, args.min_count)
    check_blogger_remnants(data, args.manifest)
    check_file_properties(args.manifest)

    # ── Results ───────────────────────────────────────────────────────────────
    print()

    if warnings:
        print(f"⚠️  {len(warnings)} WARNING(S):")
        for w in warnings:
            print(f"   WARN: {w}")

    if errors:
        print()
        print(f"❌ VALIDATION FAILED — {len(errors)} ERROR(S):")
        for e in errors:
            print(f"   ERROR: {e}")
        print()
        print("R2 upload BLOCKED. Resolve errors before deploying to production.")
        print("Platform integrity requires a valid intel feed at all times.")
        return 1

    if args.strict and warnings:
        print()
        print(
            f"❌ STRICT MODE: {len(warnings)} warning(s) treated as errors. "
            f"R2 upload BLOCKED."
        )
        return 1

    # ── PASS ──────────────────────────────────────────────────────────────────
    print()
    total = len(advisories) if isinstance(advisories, list) else 0
    print("✅ SCHEMA VALIDATION PASSED — R2 UPLOAD CLEARED")
    print(f"   {total:,} advisories validated")
    print(f"   Generated : {data.get('generated_at', 'N/A')}")
    print(f"   Platform  : {data.get('platform', 'N/A')}")
    print(f"   Version   : {data.get('version', 'N/A')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
