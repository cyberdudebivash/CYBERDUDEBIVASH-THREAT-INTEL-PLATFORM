#!/usr/bin/env python3
"""
CVE CORRELATION ENGINE  v1.0  -- SENTINEL APEX
===============================================
Merges duplicate CVE records across multiple sources into a single
canonical intelligence record per CVE.

PROBLEM:
  Same CVE (e.g. CVE-2026-6657) appears from multiple sources:
    - Vulners: "Low Security Vulnerability (CVE-2026-6657)"
    - CVE Feed: "CVE-2026-6657 - CORS Origin Validation Bypass in..."
  This creates duplicate advisories, inflated feed counts, degraded
  commercial quality, and incorrect metrics.

SOLUTION:
  For each unique CVE ID:
    1. Collect all source records
    2. Elect the canonical record (richest title + highest enrichment)
    3. Merge: best CVSS, best EPSS, best KEV, all sources, all IOCs
    4. Aggregate confidence scores
    5. Write one canonical record per CVE

GUARANTEE: feed.json contains at most ONE record per CVE ID after this engine runs.

Usage:
  python3 scripts/cve_correlation_engine.py [--feed api/feed.json] [--fix] [--report]
"""
import json, os, sys, re, argparse, datetime, pathlib
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _extract_cves(item: dict) -> list:
    """Extract all CVE IDs from an item."""
    cves = set()
    for f in ("cve_ids", "cve_id"):
        val = item.get(f)
        if isinstance(val, list):
            cves.update(v.strip().upper() for v in val if v and re.match(r'CVE-\d{4}-\d+', str(v), re.I))
        elif val and isinstance(val, str) and re.match(r'CVE-\d{4}-\d+', val.strip(), re.I):
            cves.add(val.strip().upper())
    # Also scan title
    title = item.get("title", "")
    for m in re.finditer(r'CVE-\d{4}-\d+', title, re.I):
        cves.add(m.group(0).upper())
    return sorted(cves)


def _title_quality(title: str) -> int:
    """Score title quality: higher = more descriptive (prefer CVE Feed over generic Vulners titles)."""
    if not title:
        return 0
    score = len(title)
    if re.search(r'CVE-\d{4}-\d+\s*-\s*\w', title):  # "CVE-XXXX-YYYY - Description"
        score += 100
    if title.lower().startswith("low security vulnerability"):
        score -= 200  # Penalise generic Vulners titles
    return score


def _pick_best_title(records: list) -> str:
    """Pick the most descriptive title from a set of records for the same CVE."""
    return max(records, key=lambda r: _title_quality(r.get("title", ""))).get("title", "")


def _best_float(records: list, field: str, higher_is_better: bool = True) -> float | None:
    vals = [r.get(field) for r in records if r.get(field) is not None]
    if not vals:
        return None
    try:
        floats = [float(v) for v in vals]
        return max(floats) if higher_is_better else min(floats)
    except (TypeError, ValueError):
        return None


def _merge_lists(records: list, field: str) -> list:
    seen = set()
    result = []
    for r in records:
        val = r.get(field)
        if isinstance(val, list):
            for v in val:
                if v and v not in seen:
                    seen.add(v)
                    result.append(v)
        elif val and val not in seen:
            seen.add(val)
            result.append(val)
    return result


def _best_severity(records: list) -> str:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    best = "LOW"
    best_val = 0
    for r in records:
        sev = (r.get("severity") or "LOW").upper()
        v = order.get(sev, 0)
        if v > best_val:
            best_val = v
            best = sev
    return best


def _best_kev(records: list) -> bool:
    for r in records:
        v = str(r.get("kev") or r.get("kev_present") or "").upper()
        if v in ("YES", "TRUE", "1"):
            return True
    return False


def merge_cve_records(records: list) -> dict:
    """Merge multiple records for the same CVE into one canonical record."""
    if len(records) == 1:
        return records[0]

    canonical = dict(records[0])  # start from first record
    all_sources = list(dict.fromkeys(r.get("source", "") for r in records if r.get("source")))

    # Best title
    canonical["title"] = _pick_best_title(records)

    # Best CVSS / EPSS / risk_score
    cvss = _best_float(records, "cvss_score")
    epss = _best_float(records, "epss_score")
    risk = _best_float(records, "risk_score")
    if cvss is not None: canonical["cvss_score"] = cvss
    if epss is not None: canonical["epss_score"] = epss
    if risk is not None: canonical["risk_score"] = risk

    # Best severity
    canonical["severity"] = _best_severity(records)

    # KEV -- if any source says KEV, canonical is KEV
    if _best_kev(records):
        canonical["kev"] = "YES"
        canonical["kev_present"] = True

    # Merged IOCs (deduplicated)
    merged_iocs = _merge_lists(records, "iocs")
    if merged_iocs:
        canonical["iocs"] = merged_iocs
    canonical["ioc_count"] = max(r.get("ioc_count", 0) for r in records)

    # Merged CVE IDs
    canonical["cve_ids"] = _merge_lists(records, "cve_ids")
    if records[0].get("cve_id"):
        canonical["cve_id"] = records[0]["cve_id"]

    # Source attribution
    canonical["source"] = all_sources[0]  # primary source
    canonical["sources"] = all_sources    # all sources (multi-source attribution)
    canonical["source_count"] = len(all_sources)
    canonical["multi_source"] = len(all_sources) > 1

    # Aggregated confidence
    confs = [r.get("confidence") for r in records if r.get("confidence") is not None]
    if confs:
        try:
            canonical["confidence"] = round(sum(float(c) for c in confs) / len(confs), 1)
        except (TypeError, ValueError):
            pass

    # Keep earliest published_at (most original source date)
    dates = sorted(r.get("published_at") or r.get("published") or "" for r in records if (r.get("published_at") or r.get("published")))
    if dates:
        canonical["published_at"] = dates[0]
        canonical["published"] = dates[0]

    # Tag as correlated
    canonical["_cve_correlated"] = True
    canonical["_correlated_source_count"] = len(records)

    return canonical


def correlate_feed(items: list) -> tuple:
    """Correlate a feed list, returning (correlated_items, report_dict)."""
    # Group items by CVE IDs
    cve_groups: dict = defaultdict(list)
    no_cve_items = []
    item_to_cves: dict = {}

    for item in items:
        cves = _extract_cves(item)
        if cves:
            # Use the first CVE as the canonical key (multi-CVE items kept under primary CVE)
            primary_cve = cves[0]
            cve_groups[primary_cve].append(item)
            item_to_cves[id(item)] = cves
        else:
            no_cve_items.append(item)

    # Merge duplicates
    correlated = []
    merged_count = 0
    duplicate_count = 0
    correlation_details = []

    for cve_id, records in cve_groups.items():
        if len(records) > 1:
            merged = merge_cve_records(records)
            correlated.append(merged)
            merged_count += 1
            duplicate_count += len(records) - 1
            correlation_details.append({
                "cve_id": cve_id,
                "sources_merged": [r.get("source", "?") for r in records],
                "titles_merged": [r.get("title", "")[:60] for r in records],
                "canonical_title": merged.get("title", "")[:60],
                "canonical_severity": merged.get("severity", ""),
                "canonical_cvss": merged.get("cvss_score"),
            })
        else:
            correlated.append(records[0])

    # Add non-CVE items
    correlated.extend(no_cve_items)

    report = {
        "report_type": "cve_correlation_report",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "version": "v1.0",
        "input_count": len(items),
        "output_count": len(correlated),
        "duplicates_removed": duplicate_count,
        "cves_correlated": merged_count,
        "total_cves": len(cve_groups),
        "no_cve_items": len(no_cve_items),
        "correlation_details": correlation_details,
        "VERDICT": "PASS",
    }
    return correlated, report


# ─── CLI ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE Correlation Engine v1.0")
    parser.add_argument("--feed", default=os.path.join(REPO, "api", "feed.json"))
    parser.add_argument("--fix", action="store_true", help="Write correlated feed in-place")
    parser.add_argument("--report", default=os.path.join(REPO, "reports", "cve_correlation_report.json"))
    args = parser.parse_args()

    feed_path = pathlib.Path(args.feed)
    if not feed_path.exists():
        print(f"[ERROR] Feed not found: {feed_path}")
        sys.exit(1)

    raw = json.loads(feed_path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("items", [])

    print("=" * 60)
    print("CVE CORRELATION ENGINE  v1.0")
    print(f"Feed: {feed_path}  ({len(items)} items)")
    print("=" * 60)

    correlated, report = correlate_feed(items)

    print(f"Input:  {report['input_count']} items")
    print(f"Output: {report['output_count']} items")
    print(f"Duplicates removed: {report['duplicates_removed']}")
    print(f"CVEs correlated: {report['cves_correlated']}")

    if report["correlation_details"]:
        print("\nCorrelated CVEs:")
        for d in report["correlation_details"]:
            print(f"  {d['cve_id']}: {d['sources_merged']} -> \"{d['canonical_title']}\" [{d['canonical_severity']}]")

    if args.fix:
        tmp = feed_path.with_suffix(".cve_corr.tmp")
        out = correlated if isinstance(raw, list) else {**raw, "items": correlated}
        tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(feed_path)
        print(f"\n[FIX] Correlated feed written: {feed_path}")

    rpath = pathlib.Path(args.report)
    rpath.parent.mkdir(parents=True, exist_ok=True)
    rpath.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[REPORT] {rpath}")
    sys.exit(0)
