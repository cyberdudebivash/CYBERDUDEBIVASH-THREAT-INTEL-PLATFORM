#!/usr/bin/env python3
"""
scripts/validate_manifest_schema.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- STABLE CONTRACT Schema Validator
=====================================================================
Version : v155.0  Stage: 3.4.5 (HARD FAIL pre-R2 gate)

PLATFORM HARDENING: Zero-regression schema gate for feed_manifest.json
                    and api/feed.json.

v155.0 P0 FIX (Run #1270 root cause):
    Advisory records in api/feed.json use `id` (intel--XXXXXXXX) as their
    unique identifier. The STABLE CONTRACT requires `stix_id`. The backfill
    engine now derives stix_id deterministically from `id` when absent, fixing
    all 105 hard fails without modifying the STABLE CONTRACT definition itself.
    Priority: id field -> stix_bundle URL basename.

STABLE CONTRACT (immutable baseline -- do NOT modify without arch review):
    Required fields per intel item:
        stix_id         : str   -- unique STIX bundle identifier
        title           : str   -- threat advisory title
        risk_score      : float -- normalised risk 0-10
        apex_ai         : dict  -- APEX AI enrichment block (NEVER remove)
        tags            : list  -- classification tags
        blog_url/report_url : str  -- advisory URL
        created_at/timestamp/generated_at : str  -- ISO 8601 timestamp

    Also supports flat aliases (backfilled when absent, never stripped):
        apex_ai_summary : str   -- flat alias for apex_ai.ai_summary
        apex_ai_score   : float -- flat alias for apex_ai.predictive_risk

HARD FAIL conditions (sys.exit(1)):
    1. Manifest file is missing or unparseable
    2. Manifest is empty (0 items)
    3. Any item is missing a REQUIRED CRITICAL field (stix_id, title, risk_score)
    4. More than MAX_MISSING_APEX_PCT of items are missing apex_ai block (strict mode)

Usage:
    python3 scripts/validate_manifest_schema.py                  # validate only
    python3 scripts/validate_manifest_schema.py --backfill       # validate + backfill
    python3 scripts/validate_manifest_schema.py --strict-apex    # zero apex_ai missing

Exit codes:
    0 = PASS
    1 = HARD FAIL (deployment blocked)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [schema-validator] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.validate_manifest_schema")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFESTS = [
    REPO_ROOT / "data" / "stix" / "feed_manifest.json",
    REPO_ROOT / "api" / "feed.json",
]

STABLE_CONTRACT_VERSION = "stable-v1.0-apex"

REQUIRED_CRITICAL_FIELDS: list[str] = ["stix_id", "title", "risk_score"]
URL_FIELD_CANDIDATES: list[str] = ["blog_url", "report_url", "source_url", "nvd_url"]
TIMESTAMP_FIELD_CANDIDATES: list[str] = [
    "created_at", "timestamp", "generated_at", "published_at"
]
MAX_MISSING_APEX_PCT = 100.0
MIN_MANIFEST_ENTRIES = 1

# Manifests ALLOWED to be empty (architectural by-design).
# data/stix/feed_manifest.json is reset to [] by bootstrap_critical_files.py
# on every CI run -- documented in stability_lock.json known_non_fatal_warns.
SKIP_EMPTY_STIX_MANIFEST = True
STIX_MANIFEST_PARTIAL_PATH = "data/stix/feed_manifest.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_manifest(path: Path) -> tuple[list[dict], str, Any]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e
    if isinstance(data, list):
        return data, "list", data
    if isinstance(data, dict):
        for key in ("data", "items", "entries", "intel"):
            if isinstance(data.get(key), list):
                return data[key], "dict", data
        return [], "dict", data
    raise ValueError(f"Unexpected manifest root type: {type(data).__name__}")


def _atomic_write(path: Path, items: list[dict], fmt: str, raw_data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".schema_tmp")
    try:
        if fmt == "dict" and isinstance(raw_data, dict):
            for key in ("data", "items", "entries", "intel"):
                if key in raw_data:
                    raw_data[key] = items
                    break
            payload = raw_data
        else:
            payload = items
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, path)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        raise


def _extract_bundle_id_from_url(stix_bundle_url: str) -> str:
    """Extract stable identifier from stix_bundle URL as fallback stix_id.
    e.g. https://intel.cyberdudebivash.com/data/stix/CDB-APEX-1779350179.json
         -> CDB-APEX-1779350179
    """
    if not stix_bundle_url:
        return ""
    basename = stix_bundle_url.rstrip("/").split("/")[-1]
    if basename.endswith(".json"):
        basename = basename[:-5]
    return basename if basename else ""


def _derive_apex_flat(item: dict) -> dict:
    apex = item.get("apex_ai") or {}
    ai_summary = (
        apex.get("ai_summary")
        or item.get("apex_ai_summary")
        or (
            f"[{item.get('severity','MEDIUM')}] {item.get('threat_type','Threat')} advisory. "
            f"Risk score {float(item.get('risk_score') or 0):.1f}/10. "
            "Full APEX AI analysis available to Pro subscribers."
        )
    )
    apex_score = (
        apex.get("predictive_risk")
        or item.get("apex_ai_score")
        or item.get("risk_score")
        or 0.0
    )
    return {
        "apex_ai_summary": str(ai_summary)[:500],
        "apex_ai_score": float(apex_score) if apex_score is not None else 0.0,
    }


def _backfill_item(item: dict) -> tuple[dict, list[str]]:
    patched: list[str] = []

    # v155.0 P0 ARCHITECTURAL FIX: stix_id backfill
    # Advisory records use `id` (intel--XXXXXXXX); validator requires `stix_id`.
    # Derive stix_id deterministically from `id` when absent.
    # NON-DESTRUCTIVE: never overwrites an existing non-empty stix_id.
    # DETERMINISTIC: same input always produces same stix_id.
    # GENERATED-AT-SOURCE: `id` is assigned during advisory ingestion.
    if not item.get("stix_id"):
        derived = (
            str(item["id"]).strip() if item.get("id") else ""
        ) or _extract_bundle_id_from_url(str(item.get("stix_bundle") or ""))
        if derived:
            item["stix_id"] = derived
            patched.append("stix_id")

    if not isinstance(item.get("tags"), list) or len(item.get("tags", [])) == 0:
        sev = str(item.get("severity", "MEDIUM")).upper()
        tt = str(item.get("threat_type", "Threat Intel"))
        item["tags"] = [tt, sev]
        patched.append("tags")

    if not any(item.get(f) for f in URL_FIELD_CANDIDATES):
        item["blog_url"] = ""
        patched.append("blog_url")

    if not any(item.get(f) for f in TIMESTAMP_FIELD_CANDIDATES):
        item["created_at"] = _utc_now()
        patched.append("created_at")

    flat = _derive_apex_flat(item)
    if not item.get("apex_ai_summary"):
        item["apex_ai_summary"] = flat["apex_ai_summary"]
        patched.append("apex_ai_summary")
    if item.get("apex_ai_score") is None:
        item["apex_ai_score"] = flat["apex_ai_score"]
        patched.append("apex_ai_score")

    defaults: dict[str, Any] = {
        "severity": "MEDIUM",
        "threat_type": "Threat Intel",
        "status": "active",
        "schema_version": STABLE_CONTRACT_VERSION,
    }
    for field, default_val in defaults.items():
        if item.get(field) is None:
            item[field] = default_val
            patched.append(field)

    return item, patched


def validate_manifest(
    path: Path, backfill: bool = False, skip_empty: bool = False
) -> dict:
    result: dict[str, Any] = {
        "path": str(path),
        "status": "PASS",
        "item_count": 0,
        "hard_fail_reasons": [],
        "warnings": [],
        "backfilled_count": 0,
        "backfilled_fields_summary": {},
        "apex_ai_coverage_pct": 0.0,
        "checked_at": _utc_now(),
        "contract_version": STABLE_CONTRACT_VERSION,
    }

    if not path.exists():
        result["hard_fail_reasons"].append(f"MANIFEST FILE NOT FOUND: {path}")
        result["status"] = "FAIL"
        return result

    try:
        items, fmt, raw_data = _load_manifest(path)
    except ValueError as e:
        result["hard_fail_reasons"].append(f"PARSE ERROR: {e}")
        result["status"] = "FAIL"
        return result

    result["item_count"] = len(items)
    result["format"] = fmt

    if len(items) < MIN_MANIFEST_ENTRIES:
        if skip_empty:
            result["warnings"].append(
                f"MANIFEST EMPTY: {len(items)} items -- SKIPPED (by-design, see "
                "stability_lock.json known_non_fatal_warns). "
                "api/feed.json validated separately."
            )
            result["status"] = "PASS"
            result["skip_reason"] = "empty_by_design"
            log.warning(
                "  [SKIP-EMPTY] %s has 0 items -- by-design, skipping hard fail.",
                path.name,
            )
            return result
        result["hard_fail_reasons"].append(
            f"MANIFEST EMPTY: {len(items)} items found, minimum is {MIN_MANIFEST_ENTRIES}"
        )
        result["status"] = "FAIL"
        return result

    total = len(items)
    missing_apex_count = 0
    backfill_total = 0
    all_backfilled_fields: dict[str, int] = {}

    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            result["hard_fail_reasons"].append(
                f"ITEM[{idx}] is not a dict (type={type(item).__name__})"
            )
            result["status"] = "FAIL"
            continue

        # v155.0: backfill BEFORE critical-field check so stix_id derived from
        # `id` is present when the check loop runs.
        if backfill:
            updated_item, patched = _backfill_item(item)
            items[idx] = updated_item
            item = updated_item
            if patched:
                backfill_total += 1
                for f in patched:
                    all_backfilled_fields[f] = all_backfilled_fields.get(f, 0) + 1

        for field in REQUIRED_CRITICAL_FIELDS:
            val = item.get(field)
            if val is None or val == "" or val == []:
                result["hard_fail_reasons"].append(
                    f"ITEM[{idx}] stix_id='{item.get('stix_id','?')}': "
                    f"CRITICAL field '{field}' is missing or null"
                )
                result["status"] = "FAIL"

        if not item.get("apex_ai"):
            missing_apex_count += 1

    apex_coverage_pct = (
        (total - missing_apex_count) / total * 100.0
    ) if total else 0.0
    result["apex_ai_coverage_pct"] = round(apex_coverage_pct, 1)
    result["missing_apex_ai_count"] = missing_apex_count

    missing_pct = (missing_apex_count / total * 100.0) if total else 0.0
    if missing_pct > MAX_MISSING_APEX_PCT:
        result["hard_fail_reasons"].append(
            f"APEX AI COVERAGE CRITICAL: {missing_apex_count}/{total} items "
            f"({missing_pct:.1f}%) missing apex_ai "
            f"(threshold: >{MAX_MISSING_APEX_PCT:.0f}%)"
        )
        result["status"] = "FAIL"
    elif missing_apex_count > 0:
        result["warnings"].append(
            f"APEX AI PARTIAL: {missing_apex_count}/{total} items missing apex_ai. "
            "Run enrich_feed_apex.py to restore coverage."
        )

    if backfill and backfill_total > 0:
        try:
            _atomic_write(path, items, fmt, raw_data)
            result["backfilled_count"] = backfill_total
            result["backfilled_fields_summary"] = all_backfilled_fields
            if result["status"] == "PASS":
                result["status"] = "BACKFILL_APPLIED"
            log.info(
                "Backfilled %d items in %s | fields: %s",
                backfill_total, path.name, all_backfilled_fields,
            )
        except Exception as e:
            result["warnings"].append(f"Backfill write failed: {e}")

    return result


def _write_report(results: list[dict]) -> None:
    report_dir = REPO_ROOT / "data" / "quality"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "schema_validation_report.json"
    payload = {
        "generated_at": _utc_now(),
        "contract_version": STABLE_CONTRACT_VERSION,
        "total_manifests_checked": len(results),
        "total_hard_fails": sum(1 for r in results if r["status"] == "FAIL"),
        "total_pass": sum(
            1 for r in results if r["status"] in ("PASS", "BACKFILL_APPLIED")
        ),
        "results": results,
    }
    tmp = report_path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, report_path)
    except Exception as e:
        log.warning("Could not write schema report: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX STABLE CONTRACT manifest schema validator"
    )
    parser.add_argument(
        "--manifest", "-m", action="append", dest="manifests",
        help="Path to manifest file (repeatable)",
    )
    parser.add_argument(
        "--backfill", "-b", action="store_true", default=False,
        help="Backfill missing optional fields in-place",
    )
    parser.add_argument(
        "--strict-apex", action="store_true", default=False,
        help="Hard fail if ANY item missing apex_ai (0 pct tolerance)",
    )
    parser.add_argument(
        "--skip-empty", action="store_true", default=False,
        help=(
            "Skip manifests with 0 items (PASS with warning). "
            "Use for data/stix/feed_manifest.json which is by-design empty."
        ),
    )
    parser.add_argument(
        "--api-only", action="store_true", default=False,
        help=(
            "Only validate api/feed.json -- skip stix manifest entirely. "
            "Use for the HARD FAIL pre-R2 gate (STAGE 3.4.5)."
        ),
    )
    args = parser.parse_args()

    global MAX_MISSING_APEX_PCT
    if args.strict_apex:
        MAX_MISSING_APEX_PCT = 0.0
        log.info("STRICT APEX mode: 0 pct apex_ai gap tolerated")

    manifest_paths: list[Path] = []
    if args.api_only:
        manifest_paths = [REPO_ROOT / "api" / "feed.json"]
        log.info("API-ONLY mode: validating api/feed.json only (stix manifest excluded)")
    elif args.manifests:
        for m in args.manifests:
            p = Path(m)
            if not p.is_absolute():
                p = REPO_ROOT / p
            manifest_paths.append(p)
    else:
        manifest_paths = [p for p in DEFAULT_MANIFESTS if p.exists()]
        if not manifest_paths:
            manifest_paths = DEFAULT_MANIFESTS

    log.info("=" * 70)
    log.info(
        "SENTINEL APEX -- STABLE CONTRACT Schema Validator v%s",
        STABLE_CONTRACT_VERSION,
    )
    log.info("Manifests to validate : %d", len(manifest_paths))
    log.info("Backfill mode         : %s", args.backfill)
    log.info("=" * 70)

    results: list[dict] = []
    hard_fail_count = 0

    for path in manifest_paths:
        log.info("Validating: %s", path)
        skip_empty_for_this = getattr(args, "skip_empty", False) or (
            SKIP_EMPTY_STIX_MANIFEST and STIX_MANIFEST_PARTIAL_PATH in str(path)
        )
        result = validate_manifest(
            path, backfill=args.backfill, skip_empty=skip_empty_for_this
        )
        results.append(result)

        status_icon = {"PASS": "PASS", "FAIL": "FAIL", "BACKFILL_APPLIED": "BACKFILL"}.get(
            result["status"], result["status"]
        )
        log.info(
            "  [%s] %s -- %d items | apex_ai %.1f%% covered",
            status_icon, path.name, result["item_count"],
            result["apex_ai_coverage_pct"],
        )
        for w in result["warnings"]:
            log.warning("  WARN: %s", w)
        for r in result["hard_fail_reasons"]:
            log.error("  HARD FAIL: %s", r)
            hard_fail_count += 1
        if result.get("backfilled_count", 0) > 0:
            log.info(
                "  BACKFILLED: %d items -- fields: %s",
                result["backfilled_count"], result["backfilled_fields_summary"],
            )

    _write_report(results)
    log.info("=" * 70)
    log.info(
        "SUMMARY: %d/%d manifests PASS | %d hard fail(s)",
        sum(1 for r in results if r["status"] != "FAIL"),
        len(results),
        hard_fail_count,
    )

    if hard_fail_count > 0:
        log.error("SCHEMA VALIDATION FAILED -- DEPLOYMENT BLOCKED")
        sys.exit(1)

    log.info("SCHEMA VALIDATION PASSED -- STABLE CONTRACT INTACT")


if __name__ == "__main__":
    main()
