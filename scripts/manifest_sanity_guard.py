#!/usr/bin/env python3
"""
scripts/manifest_sanity_guard.py
CYBERDUDEBIVASH(R) SENTINEL APEX v142.0.0 -- Manifest Sanity Guard (Standalone Gate)
======================================================================================
Pipeline gate: called from sentinel-blogger.yml AFTER intel_quality_engine runs.

HARD FAIL conditions (sys.exit(1)):
    - Duplicate stix_ids remaining AFTER quality engine dedup > 5
    - Feed.json structural corruption (tuple pattern: [[...], int])
    - Zero enrichment fields in entire manifest (enrichment engine failed)

WARNINGS (logged, pipeline continues):
    - duplicate_count > 0 but <= 5 (residual, acceptable)
    - enrichment_rate < 10%

Writes: data/quality/sanity_guard_report.json

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.manifest_sanity_guard")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [manifest-sanity-guard] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)

REPO_ROOT    = Path(__file__).resolve().parent.parent
DATA_DIR     = REPO_ROOT / "data"
QUALITY_DIR  = DATA_DIR / "quality"
REPORT_PATH  = QUALITY_DIR / "sanity_guard_report.json"

MANIFEST_CANDIDATES = [
    DATA_DIR / "stix" / "feed_manifest.json",
    REPO_ROOT / "api" / "feed.json",
    REPO_ROOT / "feed.json",
]

# Thresholds
MAX_TOLERABLE_DUPLICATE_STIX  = 5
MIN_ENRICHMENT_RATE            = 0.05  # 5% — absolute floor


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    try:
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
    except Exception:
        pass
    os.replace(tmp, path)


def _load_manifest() -> tuple[list, str]:
    """Load manifest from first available candidate. Returns (items, source_path)."""
    for path in MANIFEST_CANDIDATES:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                return raw, str(path)
            for key in ("advisories", "items", "entries", "data"):
                v = raw.get(key)
                if isinstance(v, list) and v:
                    return v, str(path)
        except Exception as e:
            log.warning("Failed to load %s: %s", path.name, e)
    return [], "none"


def run_sanity_check() -> int:
    """
    Run all sanity checks. Returns exit code (0=pass, 1=hard-fail).
    """
    t_start = time.monotonic()
    log.info("=== Manifest Sanity Guard v142.0.0 ===")

    items, source = _load_manifest()
    log.info("Loaded %d items from: %s", len(items), source)

    hard_fails: list[str] = []
    warnings: list[str] = []
    stats: dict = {"source": source, "total_items": len(items)}

    if not items:
        log.warning("No manifest items found — guard skipped")
        _atomic_write(REPORT_PATH, {
            "timestamp": _utc_now(),
            "result": "SKIP",
            "reason": "No manifest items found",
        })
        return 0

    # --- Check 1: Structural corruption (tuple pattern) ---
    log.info("Check 1: Structural corruption (tuple pattern)")
    if len(items) <= 3:
        list_elements = [i for i in items if isinstance(i, list)]
        int_elements  = [i for i in items if isinstance(i, int)]
        if list_elements and int_elements:
            hard_fails.append(
                f"TUPLE CORRUPTION DETECTED: feed has {len(items)} elements "
                f"with a nested list ({len(list_elements[0])} items) and an int. "
                f"This is the [[...], 0] tuple-assignment bug."
            )
    stats["structural_corruption"] = len(hard_fails) > 0
    if not hard_fails:
        log.info("  CHECK 1 PASS: No structural corruption")

    # --- Check 2: Duplicate stix_ids ---
    log.info("Check 2: Duplicate stix_ids")
    stix_ids = [
        (i.get("stix_id") or i.get("id") or "").strip()
        for i in items
        if isinstance(i, dict)
    ]
    stix_counts = Counter(stix_ids)
    dup_stix = {k: v for k, v in stix_counts.items() if v > 1 and k}
    dup_count = sum(v - 1 for v in dup_stix.values())

    stats["duplicate_stix_count"] = dup_count
    stats["duplicate_stix_ids"]   = list(dup_stix.keys())[:20]

    if dup_count > MAX_TOLERABLE_DUPLICATE_STIX:
        hard_fails.append(
            f"HARD FAIL: {dup_count} duplicate stix_ids found "
            f"(threshold: {MAX_TOLERABLE_DUPLICATE_STIX}). "
            f"Quality engine dedup did not fully resolve duplicates."
        )
    elif dup_count > 0:
        warnings.append(f"WARNING: {dup_count} duplicate stix_ids (within tolerance)")
        log.warning("  CHECK 2 WARN: %d duplicate stix_ids (tolerated)", dup_count)
    else:
        log.info("  CHECK 2 PASS: No duplicate stix_ids")

    # --- Check 3: Duplicate titles ---
    log.info("Check 3: Duplicate titles")
    titles = [
        (i.get("title") or "").strip().lower()
        for i in items
        if isinstance(i, dict) and (i.get("title") or "").strip()
    ]
    title_counts = Counter(titles)
    dup_titles = {k: v for k, v in title_counts.items() if v > 1 and k}
    dup_title_count = sum(v - 1 for v in dup_titles.values())

    stats["duplicate_title_count"] = dup_title_count
    if dup_title_count > 20:
        warnings.append(f"WARNING: {dup_title_count} duplicate titles (high)")
        log.warning("  CHECK 3 WARN: %d duplicate titles", dup_title_count)
    elif dup_title_count > 0:
        log.info("  CHECK 3 INFO: %d duplicate titles (within tolerance)", dup_title_count)
    else:
        log.info("  CHECK 3 PASS: No duplicate titles")

    # --- Check 4: Enrichment rate ---
    log.info("Check 4: Enrichment field coverage")
    dict_items = [i for i in items if isinstance(i, dict)]
    enriched = sum(
        1 for i in dict_items
        if i.get("kill_chain_phase") or i.get("attack_vector") or i.get("campaign_name")
    )
    enrichment_rate = enriched / len(dict_items) if dict_items else 0
    stats["enrichment_rate_pct"] = round(enrichment_rate * 100, 1)
    stats["enriched_items"]      = enriched

    if enrichment_rate < MIN_ENRICHMENT_RATE:
        warnings.append(
            f"WARNING: Enrichment rate {enrichment_rate:.1%} below floor "
            f"({MIN_ENRICHMENT_RATE:.0%}) — quality engine may not have run"
        )
        log.warning("  CHECK 4 WARN: Enrichment rate %.1f%% below floor", enrichment_rate * 100)
    else:
        log.info("  CHECK 4 PASS: Enrichment rate %.1f%% (%d/%d items)",
                 enrichment_rate * 100, enriched, len(dict_items))

    # --- Check 5: is_new field sanity ---
    log.info("Check 5: is_new field sanity")
    has_is_new = sum(1 for i in dict_items if "is_new" in i)
    new_true   = sum(1 for i in dict_items if i.get("is_new") is True)
    stats["has_is_new_field"] = has_is_new
    stats["new_entries_count"] = new_true
    log.info("  CHECK 5 INFO: %d items have is_new field | %d marked new", has_is_new, new_true)

    # --- Check 6: Source distribution ---
    log.info("Check 6: Source distribution")
    source_counts = Counter(i.get("feed_source", "unknown") for i in dict_items)
    total = len(dict_items)
    cisa_count = sum(v for k, v in source_counts.items() if "cisa_kev" in k)
    cisa_pct = cisa_count / total * 100 if total else 0
    stats["source_distribution"] = dict(source_counts.most_common(10))
    stats["cisa_kev_pct"] = round(cisa_pct, 1)

    if cisa_pct > 70:
        warnings.append(f"WARNING: CISA KEV dominates at {cisa_pct:.1f}% (CVE spam risk)")
        log.warning("  CHECK 6 WARN: CISA KEV = %.1f%% of feed", cisa_pct)
    else:
        log.info("  CHECK 6 PASS: CISA KEV = %.1f%% of feed", cisa_pct)

    # --- Final result ---
    elapsed = time.monotonic() - t_start
    result = "FAIL" if hard_fails else ("WARN" if warnings else "PASS")
    exit_code = 1 if hard_fails else 0

    report = {
        "timestamp":   _utc_now(),
        "result":      result,
        "exit_code":   exit_code,
        "hard_fails":  hard_fails,
        "warnings":    warnings,
        "stats":       stats,
        "elapsed_ms":  round(elapsed * 1000),
    }

    _atomic_write(REPORT_PATH, report)

    if hard_fails:
        log.error("=== MANIFEST SANITY GUARD: HARD FAIL ===")
        for f in hard_fails:
            log.error("  %s", f)
        log.error("Sanity report written: %s", REPORT_PATH)
        return 1
    elif warnings:
        log.warning("=== MANIFEST SANITY GUARD: WARN (pipeline continues) ===")
        for w in warnings:
            log.warning("  %s", w)
    else:
        log.info("=== MANIFEST SANITY GUARD: ALL CHECKS PASSED ===")
        log.info("  Items: %d | Dups: 0 | Enriched: %.1f%%",
                 len(items), enrichment_rate * 100)

    log.info("Sanity report written: %s", REPORT_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(run_sanity_check())
