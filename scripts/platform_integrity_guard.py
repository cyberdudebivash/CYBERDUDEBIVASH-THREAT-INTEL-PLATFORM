#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX — PLATFORM INTEGRITY GUARD
================================================================================
Version    : v134.0.0
Author     : CYBERDUDEBIVASH Pvt. Ltd.
Purpose    : Permanent safety layer — protects the platform from:
               • Accidental corruption of index.html / EMBEDDED_INTEL
               • Manifest regression (entry count drops)
               • Missing critical JS functions / UI features
               • Broken field normalisation (stix_id, apex, tags)
               • Dashboard desync (EMBEDDED_INTEL count vs manifest count)
               • Conflict markers leaking into production
               • Script structural regressions in update_embedded_intel.py

Usage:
    python3 scripts/platform_integrity_guard.py               # full check
    python3 scripts/platform_integrity_guard.py --mode=pre-deploy
    python3 scripts/platform_integrity_guard.py --mode=sync
    python3 scripts/platform_integrity_guard.py --mode=pre-commit
    python3 scripts/platform_integrity_guard.py --strict      # exit 1 on WARNING

Exit codes:
    0  — All checks passed (or only WARNINGs in non-strict mode)
    1  — At least one WARNING in strict mode, or CRITICAL in any mode
    2  — CRITICAL failure — do NOT deploy

Install as pre-commit hook:
    ln -sf ../../scripts/platform_integrity_guard.py .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
================================================================================
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Constants ─────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML      = ROOT / "index.html"
STIX_MANIFEST   = ROOT / "data" / "stix" / "feed_manifest.json"
FEED_MANIFEST   = ROOT / "data" / "feed_manifest.json"
UPDATE_SCRIPT   = ROOT / "scripts" / "update_embedded_intel.py"
BOOTSTRAP_SCRIPT = ROOT / "scripts" / "bootstrap_critical_files.py"

PLATFORM_VERSION = "v134.0"

# Minimum acceptable advisory count — below this is a regression
MIN_MANIFEST_ENTRIES = 50
# EMBEDDED_INTEL must be within this % of manifest count
EMBEDDED_SYNC_TOLERANCE_PCT = 10

# Critical JS functions / identifiers that must be present in index.html
REQUIRED_JS_FUNCTIONS = [
    "cdbOpenAgent",
    "injectAnalyzeButtons",
    "EMBEDDED_INTEL",
    "js-open-modal",
    "cdb-agent-btn",
    "MutationObserver",
    "renderCards",
    "filterCards",     # primary filter function (previously mis-named applyFilters)
]

# Fields every normalised EMBEDDED_INTEL item must have
REQUIRED_ITEM_FIELDS = [
    "id",
    "stix_id",
    "title",
    "severity",
    "apex",
    "tags",
    "mitre_tactics",
    "kill_chain_phases",
    "executive_summary",
    "exploit_tier",
    "ai_risk_score",
]

# apex sub-object required keys
REQUIRED_APEX_KEYS = [
    "priority",
    "threat_level",
    "threat_category",
    "predictive_score",
    "ai_summary",
    "recommended_action",
]

# Regex patterns for git conflict markers (exact 7-char markers, line-anchored)
# Using regex instead of substring match to avoid false positives from:
#   • CSS/JS comment separators:  // ==================================
#   • Base64/encoded data:        <<<<< (fewer than 7)
#   • Arrow comparisons:          x >>>>> y
CONFLICT_MARKER_PATTERNS = [
    (re.compile(r'(?:^|\n)<{7}[^<]', re.MULTILINE), "<<<<<<< HEAD"),
    (re.compile(r'(?:^|\n)={7}(?:\n|$)', re.MULTILINE), "======= (conflict separator)"),
    (re.compile(r'(?:^|\n)>{7}[^>]', re.MULTILINE), ">>>>>>> branch"),
]

# Critical Python symbols that must exist in update_embedded_intel.py
REQUIRED_SCRIPT_SYMBOLS = [
    "def normalise_item",
    "def _build_apex",
    "def merge_intelligence",
    "EMBEDDED_INTEL",
    "stix_id",
    "tempfile",
]


# ── Severity levels ────────────────────────────────────────────────────────────

class Sev:
    OK       = "OK"
    WARN     = "WARN"
    CRITICAL = "CRITICAL"


# ── Result container ───────────────────────────────────────────────────────────

class CheckResult:
    def __init__(self, name: str, severity: str, detail: str, data: dict | None = None):
        self.name     = name
        self.severity = severity
        self.detail   = detail
        self.data     = data or {}

    def is_ok(self)       -> bool: return self.severity == Sev.OK
    def is_warn(self)     -> bool: return self.severity == Sev.WARN
    def is_critical(self) -> bool: return self.severity == Sev.CRITICAL

    def __repr__(self):
        icon = {"OK": "✅", "WARN": "⚠️ ", "CRITICAL": "❌"}.get(self.severity, "?")
        return f"{icon} [{self.severity:8s}] {self.name}: {self.detail}"


# ── Individual checks ─────────────────────────────────────────────────────────

def check_files_exist() -> list[CheckResult]:
    """Verify all critical platform files are present."""
    results = []
    files = {
        "index.html":                    (INDEX_HTML,       Sev.CRITICAL),
        "data/stix/feed_manifest.json":  (STIX_MANIFEST,   Sev.CRITICAL),
        "update_embedded_intel.py":      (UPDATE_SCRIPT,    Sev.CRITICAL),
        "bootstrap_critical_files.py":   (BOOTSTRAP_SCRIPT, Sev.WARN),
        "data/feed_manifest.json":       (FEED_MANIFEST,    Sev.WARN),
    }
    for label, (path, sev_if_missing) in files.items():
        if path.exists():
            size = path.stat().st_size
            results.append(CheckResult(
                f"file:{label}", Sev.OK,
                f"present ({size:,} bytes)"
            ))
        else:
            results.append(CheckResult(
                f"file:{label}", sev_if_missing,
                f"MISSING — {path}"
            ))
    return results


def check_manifest_count() -> list[CheckResult]:
    """Verify manifest has a healthy advisory count (no regression)."""
    results = []
    for label, path in [("stix", STIX_MANIFEST), ("feed", FEED_MANIFEST)]:
        if not path.exists():
            results.append(CheckResult(
                f"manifest_count:{label}", Sev.WARN, "file not found — skipping"
            ))
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            items = raw if isinstance(raw, list) else raw.get(
                "advisories", raw.get("entries", raw.get("items", []))
            )
            n = len(items)
            if n < MIN_MANIFEST_ENTRIES:
                results.append(CheckResult(
                    f"manifest_count:{label}", Sev.CRITICAL,
                    f"{n} entries — below minimum {MIN_MANIFEST_ENTRIES} (regression!)",
                    {"count": n}
                ))
            else:
                results.append(CheckResult(
                    f"manifest_count:{label}", Sev.OK,
                    f"{n} entries", {"count": n}
                ))
        except Exception as exc:
            results.append(CheckResult(
                f"manifest_count:{label}", Sev.CRITICAL,
                f"JSON parse error: {exc}"
            ))
    return results


def _extract_embedded_intel(html: str) -> tuple[list | None, str]:
    """
    Parse EMBEDDED_INTEL array from index.html.
    Returns (items_list, error_message).
    """
    pos = html.find("const EMBEDDED_INTEL = [")
    if pos == -1:
        return None, "const EMBEDDED_INTEL declaration not found"
    start = pos + len("const EMBEDDED_INTEL = ")
    depth = 0
    i = start
    in_str = False
    esc = False
    while i < len(html):
        c = html[i]
        if esc:
            esc = False; i += 1; continue
        if c == '\\' and in_str:
            esc = True; i += 1; continue
        if c == '"' and not esc:
            in_str = not in_str; i += 1; continue
        if not in_str:
            if c == '[':
                depth += 1
            elif c == ']':
                depth -= 1
                if depth == 0:
                    try:
                        items = json.loads(html[start:i + 1])
                        return items, ""
                    except Exception as exc:
                        return None, f"JSON parse failed: {exc}"
        i += 1
    return None, "EMBEDDED_INTEL array never closed"


def check_embedded_intel_sync() -> list[CheckResult]:
    """Verify EMBEDDED_INTEL count is in sync with manifest."""
    results = []
    if not INDEX_HTML.exists() or not STIX_MANIFEST.exists():
        results.append(CheckResult(
            "embedded_sync", Sev.WARN, "skipped — index.html or manifest missing"
        ))
        return results

    html = INDEX_HTML.read_text(encoding="utf-8")
    items, err = _extract_embedded_intel(html)
    if err:
        results.append(CheckResult("embedded_sync", Sev.CRITICAL, err))
        return results

    embedded_count = len(items)

    # Get manifest count
    raw = json.loads(STIX_MANIFEST.read_text(encoding="utf-8"))
    manifest_items = raw if isinstance(raw, list) else raw.get(
        "advisories", raw.get("entries", raw.get("items", []))
    )
    manifest_count = len(manifest_items)

    tolerance = manifest_count * EMBEDDED_SYNC_TOLERANCE_PCT // 100
    diff = abs(embedded_count - manifest_count)

    if manifest_count == 0:
        results.append(CheckResult(
            "embedded_sync", Sev.CRITICAL,
            "manifest has 0 entries — cannot validate sync"
        ))
    elif diff <= tolerance:
        results.append(CheckResult(
            "embedded_sync", Sev.OK,
            f"EMBEDDED_INTEL={embedded_count} | manifest={manifest_count} | diff={diff} (within {EMBEDDED_SYNC_TOLERANCE_PCT}% tolerance)",
            {"embedded": embedded_count, "manifest": manifest_count}
        ))
    else:
        results.append(CheckResult(
            "embedded_sync", Sev.CRITICAL,
            f"STALE — EMBEDDED_INTEL={embedded_count} vs manifest={manifest_count} (diff={diff} > tolerance={tolerance})",
            {"embedded": embedded_count, "manifest": manifest_count, "diff": diff}
        ))

    return results


def check_embedded_item_fields(sample_size: int = 20) -> list[CheckResult]:
    """
    Spot-check normalised fields on a sample of EMBEDDED_INTEL items.
    Checks: stix_id present, apex is dict with required keys, tags is list.
    """
    results = []
    if not INDEX_HTML.exists():
        results.append(CheckResult(
            "item_fields", Sev.WARN, "index.html missing — skipped"
        ))
        return results

    html = INDEX_HTML.read_text(encoding="utf-8")
    items, err = _extract_embedded_intel(html)
    if err:
        results.append(CheckResult("item_fields", Sev.CRITICAL, f"parse error: {err}"))
        return results

    if not items:
        results.append(CheckResult("item_fields", Sev.CRITICAL, "EMBEDDED_INTEL is empty"))
        return results

    # Sample first, middle, last items
    indices = list(dict.fromkeys([
        0, len(items) // 4, len(items) // 2,
        3 * len(items) // 4, len(items) - 1
    ]))
    sample = [items[i] for i in indices if i < len(items)]

    missing_stix_id  = 0
    missing_apex     = 0
    broken_apex      = []
    null_tags        = 0
    missing_fields   = {}

    for item in sample:
        # stix_id check
        if not item.get("stix_id"):
            missing_stix_id += 1

        # apex check
        apex = item.get("apex")
        if not isinstance(apex, dict):
            missing_apex += 1
        else:
            bad_keys = [k for k in REQUIRED_APEX_KEYS if not apex.get(k)]
            if bad_keys:
                broken_apex.append({"id": item.get("id", "?"), "missing": bad_keys})

        # tags check — must be list, not None
        if item.get("tags") is None:
            null_tags += 1

        # other required fields
        for field in REQUIRED_ITEM_FIELDS:
            if field not in item:
                missing_fields[field] = missing_fields.get(field, 0) + 1

    issues = []
    sev = Sev.OK

    if missing_stix_id:
        issues.append(f"stix_id missing in {missing_stix_id}/{len(sample)} sampled items (ANALYZE button will break)")
        sev = Sev.CRITICAL
    if missing_apex:
        issues.append(f"apex dict missing in {missing_apex}/{len(sample)} sampled items (AI panel will not render)")
        sev = Sev.CRITICAL
    if broken_apex:
        issues.append(f"apex incomplete in {len(broken_apex)} items: {broken_apex}")
        if sev == Sev.OK: sev = Sev.WARN
    if null_tags:
        issues.append(f"tags=null in {null_tags}/{len(sample)} items (JS iteration will crash)")
        if sev == Sev.OK: sev = Sev.WARN
    if missing_fields:
        issues.append(f"missing fields: {missing_fields}")
        if sev == Sev.OK: sev = Sev.WARN

    detail = "; ".join(issues) if issues else f"all {len(sample)} sampled items pass field checks"
    results.append(CheckResult("item_fields", sev, detail, {
        "sample_size": len(sample),
        "missing_stix_id": missing_stix_id,
        "missing_apex": missing_apex,
        "null_tags": null_tags,
    }))
    return results


def check_required_js_functions() -> list[CheckResult]:
    """Verify all critical JS functions/elements exist in index.html."""
    results = []
    if not INDEX_HTML.exists():
        results.append(CheckResult(
            "js_functions", Sev.WARN, "index.html missing — skipped"
        ))
        return results

    html = INDEX_HTML.read_text(encoding="utf-8")
    missing = [fn for fn in REQUIRED_JS_FUNCTIONS if fn not in html]

    if missing:
        results.append(CheckResult(
            "js_functions", Sev.CRITICAL,
            f"MISSING critical identifiers: {missing}"
        ))
    else:
        results.append(CheckResult(
            "js_functions", Sev.OK,
            f"all {len(REQUIRED_JS_FUNCTIONS)} required identifiers present"
        ))
    return results


def check_conflict_markers() -> list[CheckResult]:
    """
    Detect git conflict markers in index.html (never allowed in production).
    Uses line-anchored regex to avoid false positives from:
      • CSS/JS separators:   // ==================================  (>7 chars)
      • Comparison operators: x <<< y   (fewer than 7 chars)
    """
    results = []
    if not INDEX_HTML.exists():
        results.append(CheckResult(
            "conflict_markers", Sev.WARN, "index.html missing — skipped"
        ))
        return results

    html = INDEX_HTML.read_text(encoding="utf-8", errors="replace")
    found = []
    for pattern, label in CONFLICT_MARKER_PATTERNS:
        if pattern.search(html):
            found.append(label)

    if found:
        results.append(CheckResult(
            "conflict_markers", Sev.CRITICAL,
            f"git conflict markers found in index.html: {found} — NEVER deploy"
        ))
    else:
        results.append(CheckResult(
            "conflict_markers", Sev.OK,
            "no conflict markers (regex-verified)"
        ))
    return results


def check_update_script_integrity() -> list[CheckResult]:
    """Verify update_embedded_intel.py contains all required symbols."""
    results = []
    if not UPDATE_SCRIPT.exists():
        results.append(CheckResult(
            "script_integrity", Sev.CRITICAL,
            "update_embedded_intel.py missing — EMBEDDED_INTEL can never be patched"
        ))
        return results

    src = UPDATE_SCRIPT.read_text(encoding="utf-8")
    missing = [sym for sym in REQUIRED_SCRIPT_SYMBOLS if sym not in src]

    if missing:
        results.append(CheckResult(
            "script_integrity", Sev.CRITICAL,
            f"update_embedded_intel.py missing required symbols: {missing}"
        ))
    else:
        results.append(CheckResult(
            "script_integrity", Sev.OK,
            f"all {len(REQUIRED_SCRIPT_SYMBOLS)} required symbols present"
        ))
    return results


def check_version_string() -> list[CheckResult]:
    """Verify the dashboard shows the correct platform version."""
    results = []
    if not INDEX_HTML.exists():
        results.append(CheckResult(
            "version_string", Sev.WARN, "index.html missing — skipped"
        ))
        return results

    html = INDEX_HTML.read_text(encoding="utf-8")
    if PLATFORM_VERSION in html:
        results.append(CheckResult(
            "version_string", Sev.OK, f"version {PLATFORM_VERSION} confirmed in index.html"
        ))
    else:
        results.append(CheckResult(
            "version_string", Sev.WARN,
            f"platform version {PLATFORM_VERSION} not found in index.html — may be stale"
        ))
    return results


def check_single_embedded_intel_declaration() -> list[CheckResult]:
    """Exactly one EMBEDDED_INTEL declaration must exist (no duplicates from bad patch)."""
    results = []
    if not INDEX_HTML.exists():
        results.append(CheckResult(
            "embedded_unique", Sev.WARN, "index.html missing — skipped"
        ))
        return results

    html = INDEX_HTML.read_text(encoding="utf-8")
    count = html.count("const EMBEDDED_INTEL = ")

    if count == 0:
        results.append(CheckResult(
            "embedded_unique", Sev.CRITICAL,
            "const EMBEDDED_INTEL declaration not found — dashboard will show no data"
        ))
    elif count == 1:
        results.append(CheckResult(
            "embedded_unique", Sev.OK, "exactly 1 EMBEDDED_INTEL declaration"
        ))
    else:
        results.append(CheckResult(
            "embedded_unique", Sev.CRITICAL,
            f"{count} EMBEDDED_INTEL declarations found — patch duplication detected"
        ))
    return results


def check_manifest_json_valid() -> list[CheckResult]:
    """Both manifests must be valid JSON, not empty, not skeleton-only."""
    results = []
    for label, path in [("stix", STIX_MANIFEST), ("feed", FEED_MANIFEST)]:
        if not path.exists():
            results.append(CheckResult(
                f"manifest_json:{label}", Sev.WARN, "not found — skipped"
            ))
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                items = raw.get("advisories", raw.get("entries", raw.get("items", [])))
            elif isinstance(raw, list):
                items = raw
            else:
                items = []

            if len(items) == 0:
                results.append(CheckResult(
                    f"manifest_json:{label}", Sev.CRITICAL,
                    "manifest is valid JSON but contains 0 items"
                ))
            elif len(items) < MIN_MANIFEST_ENTRIES:
                results.append(CheckResult(
                    f"manifest_json:{label}", Sev.WARN,
                    f"only {len(items)} items — possible partial write"
                ))
            else:
                results.append(CheckResult(
                    f"manifest_json:{label}", Sev.OK,
                    f"valid JSON, {len(items)} items"
                ))
        except json.JSONDecodeError as exc:
            results.append(CheckResult(
                f"manifest_json:{label}", Sev.CRITICAL,
                f"INVALID JSON: {exc} — manifest is corrupted"
            ))
    return results


# ── Check registry ────────────────────────────────────────────────────────────



# ═══════════════════════════════════════════════════════════════════════════════
# v134.0 ENHANCED CHECKS — API Consistency + Queue Health + Feature Flags
# ADDITIVE ONLY — existing checks unchanged.
# ═══════════════════════════════════════════════════════════════════════════════

def check_api_consistency() -> list[CheckResult]:
    """
    Verify /api/feed.json exists, is valid JSON, and its count is within
    5% of the manifest count. Ensures API layer is not serving stale or
    truncated data relative to the source manifest.
    """
    results: list[CheckResult] = []
    api_path = ROOT / "api" / "feed.json"

    # Load manifest count
    manifest_count = 0
    for candidate in [
        ROOT / "data" / "stix" / "feed_manifest.json",
        ROOT / "data" / "v101_manifest.json",
        ROOT / "data" / "enriched_manifest.json",
    ]:
        if candidate.exists():
            try:
                raw = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    manifest_count = len(raw)
                else:
                    for k in ("advisories", "entries", "items", "data"):
                        v = raw.get(k)
                        if isinstance(v, list):
                            manifest_count = len(v)
                            break
                if manifest_count:
                    break
            except Exception:
                pass

    # Check api/feed.json
    if not api_path.exists():
        results.append(CheckResult("check_api_consistency", Sev.WARN,
            "api/feed.json not found — run scripts/api_layer_v101.py to generate"))
        return results

    try:
        api_raw  = json.loads(api_path.read_text(encoding="utf-8"))
        api_count = api_raw.get("count") or api_raw.get("total_count") or 0
        api_items = api_raw.get("data") or api_raw.get("items") or []
        api_actual = len(api_items) if isinstance(api_items, list) else api_count

        results.append(CheckResult("check_api_consistency", Sev.OK,
            f"api/feed.json valid | count={api_count} | items={api_actual}",
            {"api_count": api_count, "api_items": api_actual}))

        if manifest_count and api_count:
            drift_pct = abs(api_count - manifest_count) / max(manifest_count, 1) * 100
            if drift_pct > 10:
                results.append(CheckResult("check_api_consistency", Sev.WARN,
                    f"API count ({api_count}) vs manifest ({manifest_count}) drift={drift_pct:.1f}% — re-run api_layer_v101.py",
                    {"drift_pct": round(drift_pct, 1)}))
            else:
                results.append(CheckResult("check_api_consistency", Sev.OK,
                    f"API/manifest count drift acceptable: {drift_pct:.1f}% ({api_count} vs {manifest_count})",
                    {"drift_pct": round(drift_pct, 1)}))
        elif not manifest_count:
            results.append(CheckResult("check_api_consistency", Sev.WARN,
                "Could not load manifest for count comparison"))

    except json.JSONDecodeError as e:
        results.append(CheckResult("check_api_consistency", Sev.CRITICAL,
            f"api/feed.json is corrupt JSON: {e}"))
    except Exception as e:
        results.append(CheckResult("check_api_consistency", Sev.WARN,
            f"api/feed.json check error: {e}"))

    return results


def check_queue_health() -> list[CheckResult]:
    """
    Validate blog_queue health:
      - pending_posts.json parseable
      - pending queue not excessively large (>100 = problem)
      - dead_letter queue not growing uncontrolled (>50 = alert)
    """
    results: list[CheckResult] = []
    queue_file   = ROOT / "data" / "blog_queue" / "pending_posts.json"
    dead_letter  = ROOT / "data" / "blog_queue" / "dead_letter.json"

    # Check pending queue
    if not queue_file.exists():
        results.append(CheckResult("check_queue_health", Sev.OK,
            "Blog queue not initialized — no pending posts"))
    else:
        try:
            q = json.loads(queue_file.read_text(encoding="utf-8"))
            pending_count     = len(q.get("queue", []))
            total_published   = q.get("stats", {}).get("total_published", 0)
            total_dead        = q.get("stats", {}).get("total_dead_lettered", 0)

            if pending_count == 0:
                results.append(CheckResult("check_queue_health", Sev.OK,
                    f"Blog queue clear | published={total_published} | dead_lettered={total_dead}",
                    {"pending": pending_count, "published": total_published, "dead": total_dead}))
            elif pending_count <= 20:
                results.append(CheckResult("check_queue_health", Sev.OK,
                    f"Blog queue: {pending_count} pending (normal) | published={total_published}",
                    {"pending": pending_count}))
            elif pending_count <= 100:
                results.append(CheckResult("check_queue_health", Sev.WARN,
                    f"Blog queue backlog: {pending_count} pending — check retry runner",
                    {"pending": pending_count}))
            else:
                results.append(CheckResult("check_queue_health", Sev.CRITICAL,
                    f"Blog queue critically backed up: {pending_count} pending — intervention required",
                    {"pending": pending_count}))

        except Exception as e:
            results.append(CheckResult("check_queue_health", Sev.WARN,
                f"Blog queue parse error: {e}"))

    # Check dead letter queue
    if dead_letter.exists():
        try:
            dead = json.loads(dead_letter.read_text(encoding="utf-8"))
            dead_count = len(dead) if isinstance(dead, list) else 0
            if dead_count == 0:
                results.append(CheckResult("check_queue_health", Sev.OK,
                    "Dead letter queue empty"))
            elif dead_count <= 10:
                results.append(CheckResult("check_queue_health", Sev.WARN,
                    f"Dead letter queue: {dead_count} posts — review and re-enqueue if needed",
                    {"dead_count": dead_count}))
            else:
                results.append(CheckResult("check_queue_health", Sev.CRITICAL,
                    f"Dead letter queue critical: {dead_count} posts — data loss risk",
                    {"dead_count": dead_count}))
        except Exception as e:
            results.append(CheckResult("check_queue_health", Sev.WARN,
                f"Dead letter parse error: {e}"))

    return results


def check_feature_flags() -> list[CheckResult]:
    """
    Validate config/feature_flags.json exists and is valid JSON with
    expected schema keys. Ensures feature flags system is operational.
    """
    results: list[CheckResult] = []
    flags_path = ROOT / "config" / "feature_flags.json"

    if not flags_path.exists():
        results.append(CheckResult("check_feature_flags", Sev.WARN,
            "config/feature_flags.json not found — defaults will be used"))
        return results

    try:
        flags = json.loads(flags_path.read_text(encoding="utf-8"))
        required_keys = ["ENABLE_API_V101", "ENABLE_BLOG_QUEUE", "ENABLE_EXPORT_ENDPOINTS"]
        missing = [k for k in required_keys if k not in flags]

        if missing:
            results.append(CheckResult("check_feature_flags", Sev.WARN,
                f"Feature flags missing keys: {missing}",
                {"missing_keys": missing}))
        else:
            api_enabled   = flags.get("ENABLE_API_V101", False)
            queue_enabled = flags.get("ENABLE_BLOG_QUEUE", False)
            export_enabled = flags.get("ENABLE_EXPORT_ENDPOINTS", False)
            results.append(CheckResult("check_feature_flags", Sev.OK,
                f"Feature flags valid | API={api_enabled} | queue={queue_enabled} | exports={export_enabled}",
                {"api": api_enabled, "queue": queue_enabled, "exports": export_enabled}))

    except json.JSONDecodeError as e:
        results.append(CheckResult("check_feature_flags", Sev.CRITICAL,
            f"config/feature_flags.json corrupt: {e}"))
    except Exception as e:
        results.append(CheckResult("check_feature_flags", Sev.WARN,
            f"Feature flags check error: {e}"))

    return results

ALL_CHECKS = [
    check_files_exist,
    check_manifest_json_valid,
    check_manifest_count,
    check_single_embedded_intel_declaration,
    check_conflict_markers,
    check_required_js_functions,
    check_update_script_integrity,
    check_version_string,
    check_embedded_intel_sync,
    check_embedded_item_fields,
    # v134.0 enhanced checks
    check_api_consistency,
    check_queue_health,
    check_feature_flags,
]

# Lightweight checks safe to run in pre-commit (skip heavy HTML parse)
PRECOMMIT_CHECKS = [
    check_files_exist,
    check_manifest_json_valid,
    check_manifest_count,
    check_conflict_markers,
    check_update_script_integrity,
    check_single_embedded_intel_declaration,
]

# Checks run in sync-dashboard workflow
SYNC_CHECKS = [
    check_files_exist,
    check_manifest_json_valid,
    check_manifest_count,
    check_single_embedded_intel_declaration,
    check_conflict_markers,
    check_embedded_intel_sync,
]

MODE_CHECKS = {
    "full":       ALL_CHECKS,
    "pre-deploy": ALL_CHECKS,
    "sync":       SYNC_CHECKS,
    "pre-commit": PRECOMMIT_CHECKS,
}


# ── Runner ────────────────────────────────────────────────────────────────────

def run_guard(mode: str = "full", strict: bool = False) -> int:
    """
    Run all checks for the given mode.
    Returns exit code: 0=OK, 1=WARN(strict), 2=CRITICAL.
    """
    checks = MODE_CHECKS.get(mode, ALL_CHECKS)

    banner = textwrap.dedent(f"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║  CYBERDUDEBIVASH® SENTINEL APEX — PLATFORM INTEGRITY GUARD       ║
    ║  Mode: {mode:<10s}  |  Strict: {str(strict):<5s}  |  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """).strip()
    print(banner)
    print()

    all_results: list[CheckResult] = []
    for check_fn in checks:
        try:
            results = check_fn()
            for r in results:
                all_results.append(r)
                print(repr(r))
        except Exception as exc:
            err = CheckResult(check_fn.__name__, Sev.CRITICAL, f"check raised exception: {exc}")
            all_results.append(err)
            print(repr(err))

    # Tally
    ok_count       = sum(1 for r in all_results if r.is_ok())
    warn_count     = sum(1 for r in all_results if r.is_warn())
    critical_count = sum(1 for r in all_results if r.is_critical())
    total          = len(all_results)

    print()
    print("─" * 70)
    print(f"RESULTS  ✅ OK: {ok_count}  ⚠️  WARN: {warn_count}  ❌ CRITICAL: {critical_count}  (total: {total})")
    print("─" * 70)

    # Write JSON report for CI consumption
    report = {
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "mode":           mode,
        "strict":         strict,
        "ok":             ok_count,
        "warnings":       warn_count,
        "criticals":      critical_count,
        "total":          total,
        "passed":         critical_count == 0 and (warn_count == 0 or not strict),
        "checks": [
            {"name": r.name, "severity": r.severity, "detail": r.detail, **r.data}
            for r in all_results
        ],
    }

    report_dir = ROOT / "data" / "health"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "guardian_report.json"
    try:
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"📄 Report saved → {report_path.relative_to(ROOT)}")
    except Exception as exc:
        print(f"⚠️  Could not write report: {exc}")

    if critical_count > 0:
        print()
        print("❌ GUARD FAILED — CRITICAL issues detected. Do NOT deploy until resolved.")
        return 2

    if warn_count > 0 and strict:
        print()
        print("⚠️  GUARD STRICT FAIL — warnings present in strict mode.")
        return 1

    print()
    print("✅ GUARD PASSED — platform integrity confirmed.")
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH® Platform Integrity Guard v134.0"
    )
    parser.add_argument(
        "--mode",
        choices=["full", "pre-deploy", "sync", "pre-commit"],
        default="full",
        help="Check set to run (default: full)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Exit 1 on warnings (default: only exit non-zero on CRITICAL)",
    )
    args = parser.parse_args()

    # Change working directory to repo root so relative path resolution works
    os.chdir(ROOT)

    exit_code = run_guard(mode=args.mode, strict=args.strict)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
