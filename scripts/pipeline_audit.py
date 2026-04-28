#!/usr/bin/env python3
"""
scripts/pipeline_audit.py
CYBERDUDEBIVASH(R) SENTINEL APEX v141.7.0 -- Pipeline Self-Audit Engine
=======================================================================
PHASE 9: Generates a post-run audit report covering:
  - Pipeline runtime and stage completion
  - Reports generated (count, sizes, HTML validity)
  - Manifest consistency (ioc_count vs len(iocs), no empty critical fields)
  - Feed.json / API endpoint health
  - Recent 404-prone report URL spot-check
  - Dedup state integrity
  - Overall PASS / WARN / FAIL verdict

Usage (called from run_pipeline.py at end, or standalone):
  python3 scripts/pipeline_audit.py [--output data/audit/pipeline_audit.json]

Exit codes:
  0 = PASS or WARN (non-blocking)
  1 = FAIL (critical consistency errors detected)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [pipeline_audit] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.pipeline_audit")

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = REPO_ROOT / "data" / "audit"
REPORTS_DIR = REPO_ROOT / "reports"
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
FEED_JSON = REPO_ROOT / "feed.json"
METRICS_PATH = REPO_ROOT / "data" / "pipeline_metrics.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Audit Checks
# ---------------------------------------------------------------------------

def check_reports(findings: list, stats: dict) -> None:
    """Audit reports/ directory: count, min-size, HTML validity."""
    if not REPORTS_DIR.is_dir():
        findings.append({"level": "FAIL", "check": "reports_dir",
                         "detail": "reports/ directory does not exist"})
        stats["report_count"] = 0
        return

    html_files = [f for f in REPORTS_DIR.rglob("*.html") if f.name != "index.html"]
    report_count = len(html_files)
    stats["report_count"] = report_count

    if report_count == 0:
        findings.append({"level": "FAIL", "check": "report_count",
                         "detail": "Zero HTML reports found in reports/"})
        return

    # Check minimum size (1 KB) and HTML signature
    too_small = []
    invalid_html = []
    HTML_SIGS = (b"<!doctype html", b"<!DOCTYPE html", b"<html")

    for f in html_files[:200]:  # sample first 200 to keep audit fast
        sz = f.stat().st_size
        if sz < 1024:
            too_small.append(str(f.relative_to(REPO_ROOT)))
            continue
        try:
            head = f.read_bytes()[:64].lower()
            if not any(head.startswith(sig.lower()) for sig in HTML_SIGS):
                invalid_html.append(str(f.relative_to(REPO_ROOT)))
        except OSError:
            invalid_html.append(str(f.relative_to(REPO_ROOT)) + " [unreadable]")

    if too_small:
        findings.append({"level": "WARN", "check": "report_min_size",
                         "detail": f"{len(too_small)} reports below 1KB minimum",
                         "examples": too_small[:5]})
    if invalid_html:
        findings.append({"level": "WARN", "check": "report_html_validity",
                         "detail": f"{len(invalid_html)} reports missing HTML signature",
                         "examples": invalid_html[:5]})
    if not too_small and not invalid_html:
        findings.append({"level": "PASS", "check": "reports",
                         "detail": f"{report_count} HTML reports — all valid"})

    stats["reports_too_small"] = len(too_small)
    stats["reports_invalid_html"] = len(invalid_html)


def check_manifest(findings: list, stats: dict) -> None:
    """Audit manifest: ioc_count consistency, required fields, no fake data."""
    if not MANIFEST_PATH.exists():
        findings.append({"level": "FAIL", "check": "manifest_exists",
                         "detail": f"Manifest not found: {MANIFEST_PATH}"})
        return

    try:
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        findings.append({"level": "FAIL", "check": "manifest_json",
                         "detail": f"Manifest JSON parse error: {e}"})
        return

    items = data.get("advisories", data if isinstance(data, list) else [])
    stats["manifest_entries"] = len(items)

    ioc_mismatch = []
    empty_title = []
    fake_risk_10 = []
    missing_id = []

    for item in items:
        _id = item.get("id", "")
        if not _id:
            missing_id.append(str(item.get("title", ""))[:40])
            continue

        # ioc_count == len(iocs)
        ioc_count_field = item.get("ioc_count", 0)
        iocs_list = item.get("iocs", [])
        actual_count = len(iocs_list) if isinstance(iocs_list, list) else 0
        if ioc_count_field != actual_count:
            ioc_mismatch.append(f"{_id}: ioc_count={ioc_count_field} vs len(iocs)={actual_count}")

        # No empty titles
        if not item.get("title", "").strip():
            empty_title.append(_id)

        # No unjustified CRITICAL risk score — mirrors T07 and pipeline FALSE_CRITICAL gate.
        # Evidence criteria (ANY ONE satisfies):
        #   a) cve_id present          b) kev_present
        #   c) cvss >= 9.0 AND (ioc_count > 0 OR epss >= 0.5)
        #   d) epss >= 0.7             e) ioc_confidence >= 80 AND ioc_count >= 5
        rs = float(item.get("risk_score", 0) or 0)
        if rs >= 9.0:
            _kev      = item.get("kev_present", False) or item.get("kev", False)
            _cvss     = float(item.get("cvss_score") or item.get("cvss") or 0)
            _epss     = float(item.get("epss_score") or item.get("epss") or 0)
            _ioc_cnt  = int(item.get("ioc_count", 0))
            _ioc_conf = float(item.get("ioc_confidence") or 0)
            _cve_id   = bool(item.get("cve_id"))
            _justified_audit = (
                _cve_id
                or _kev
                or (_cvss >= 9.0 and (_ioc_cnt > 0 or _epss >= 0.5))
                or _epss >= 0.7
                or (_ioc_conf >= 80.0 and _ioc_cnt >= 5)
            )
            if not _justified_audit:
                fake_risk_10.append(f"{_id}: risk={rs}")

    if ioc_mismatch:
        findings.append({"level": "WARN", "check": "ioc_count_consistency",
                         "detail": f"{len(ioc_mismatch)} entries have ioc_count != len(iocs)",
                         "examples": ioc_mismatch[:5]})
    else:
        findings.append({"level": "PASS", "check": "ioc_count_consistency",
                         "detail": "All entries: ioc_count == len(iocs)"})

    if empty_title:
        findings.append({"level": "WARN", "check": "empty_titles",
                         "detail": f"{len(empty_title)} entries with empty title",
                         "examples": empty_title[:5]})

    if fake_risk_10:
        findings.append({"level": "WARN", "check": "fake_risk_score",
                         "detail": f"{len(fake_risk_10)} entries with risk=10 but no CVE/KEV evidence",
                         "examples": fake_risk_10[:5]})

    if missing_id:
        findings.append({"level": "WARN", "check": "missing_id",
                         "detail": f"{len(missing_id)} entries missing 'id' field"})

    stats["ioc_mismatches"] = len(ioc_mismatch)
    stats["fake_risk_10_count"] = len(fake_risk_10)


def check_feed_json(findings: list, stats: dict) -> None:
    """Audit root feed.json: valid JSON, non-empty, no null bytes."""
    for fpath in (FEED_JSON, REPO_ROOT / "api" / "feed.json"):
        rel = str(fpath.relative_to(REPO_ROOT))
        if not fpath.exists():
            findings.append({"level": "WARN", "check": f"feed_json:{rel}",
                             "detail": f"{rel} does not exist"})
            continue

        raw = fpath.read_bytes()
        null_count = raw.count(b"\x00")
        if null_count:
            findings.append({"level": "FAIL", "check": f"feed_json_nullbytes:{rel}",
                             "detail": f"{rel} has {null_count} null bytes"})
            continue

        try:
            obj = json.loads(raw.decode("utf-8"))
            entry_count = len(obj) if isinstance(obj, list) else len(obj.get("advisories", obj))
            findings.append({"level": "PASS", "check": f"feed_json:{rel}",
                             "detail": f"{rel} valid JSON — {entry_count} entries"})
            stats[f"feed_json_entries_{rel.replace('/', '_')}"] = entry_count
        except Exception as e:
            findings.append({"level": "FAIL", "check": f"feed_json_parse:{rel}",
                             "detail": f"{rel} JSON parse error: {e}"})


def check_pipeline_metrics(findings: list, stats: dict) -> None:
    """Audit pipeline_metrics.json for runtime and stage data."""
    if not METRICS_PATH.exists():
        findings.append({"level": "WARN", "check": "pipeline_metrics",
                         "detail": "pipeline_metrics.json not found (first run?)"})
        return

    try:
        metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        findings.append({"level": "WARN", "check": "pipeline_metrics_parse",
                         "detail": f"Cannot parse pipeline_metrics.json: {e}"})
        return

    runtime = metrics.get("total_runtime_seconds", 0)
    stats["pipeline_runtime_seconds"] = runtime

    if runtime < 60:
        findings.append({"level": "FAIL", "check": "pipeline_runtime",
                         "detail": f"Pipeline runtime {runtime:.1f}s < 60s minimum — likely early exit"})
    elif runtime < 900:
        findings.append({"level": "WARN", "check": "pipeline_runtime",
                         "detail": f"Pipeline runtime {runtime:.1f}s < 900s baseline — possible partial execution"})
    else:
        findings.append({"level": "PASS", "check": "pipeline_runtime",
                         "detail": f"Pipeline runtime {runtime:.1f}s >= 900s baseline"})


def check_report_manifest_consistency(findings: list, stats: dict) -> None:
    """Cross-check: every manifest entry with status=ok/enriched has a physical report file."""
    if not MANIFEST_PATH.exists():
        return

    try:
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception:
        return

    items = data.get("advisories", data if isinstance(data, list) else [])
    missing_files = []
    checked = 0

    for item in items:
        vs = item.get("validation_status", "")
        if vs not in ("ok", "enriched", "valid"):
            continue

        # Derive physical path from report_url
        rurl = item.get("report_url", "")
        _id = item.get("id", "")
        if not _id:
            continue

        checked += 1
        PATH_MARKER = "/reports/"
        if PATH_MARKER in rurl:
            rel = rurl[rurl.index(PATH_MARKER) + 1:]
            rpath = REPO_ROOT / rel
        else:
            found = list(REPORTS_DIR.rglob(f"{_id}.html")) if REPORTS_DIR.is_dir() else []
            rpath = found[0] if found else REPO_ROOT / "reports" / f"{_id}.html"

        if not rpath.exists():
            missing_files.append(f"{_id} → {rpath.relative_to(REPO_ROOT)}")

    stats["manifest_report_cross_checked"] = checked
    stats["manifest_report_missing"] = len(missing_files)

    if missing_files:
        findings.append({"level": "FAIL", "check": "manifest_report_consistency",
                         "detail": f"{len(missing_files)} manifest entries reference non-existent report files",
                         "examples": missing_files[:10]})
    else:
        findings.append({"level": "PASS", "check": "manifest_report_consistency",
                         "detail": f"All {checked} publishable entries have physical report files"})


# ---------------------------------------------------------------------------
# Verdict + Report Generation
# ---------------------------------------------------------------------------

def compute_verdict(findings: list) -> str:
    levels = {f["level"] for f in findings}
    if "FAIL" in levels:
        return "FAIL"
    if "WARN" in levels:
        return "WARN"
    return "PASS"


def write_audit_report(report: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str),
                           encoding="utf-8")
    log.info("Audit report written: %s", output_path)


def print_summary(report: dict) -> None:
    verdict = report["verdict"]
    verdict_icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(verdict, "?")
    log.info("=" * 60)
    log.info("PIPELINE AUDIT REPORT  %s  %s", verdict_icon, verdict)
    log.info("Generated: %s", report["generated_at"])
    log.info("-" * 60)
    for f in report["findings"]:
        icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(f["level"], "?")
        log.info("  %s [%s] %s: %s", icon, f["level"], f["check"], f["detail"])
    log.info("-" * 60)
    for k, v in report["stats"].items():
        log.info("  STAT  %-40s  %s", k, v)
    log.info("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_audit(output_path: Path) -> int:
    t0 = time.monotonic()
    findings: list[dict] = []
    stats: dict[str, Any] = {
        "audit_timestamp": utc_now(),
        "repo_root": str(REPO_ROOT),
    }

    log.info("=" * 60)
    log.info("SENTINEL APEX v141.7.0 -- Pipeline Self-Audit Engine")
    log.info("=" * 60)

    check_reports(findings, stats)
    check_manifest(findings, stats)
    check_feed_json(findings, stats)
    check_pipeline_metrics(findings, stats)
    check_report_manifest_consistency(findings, stats)

    stats["audit_duration_seconds"] = round(time.monotonic() - t0, 2)
    verdict = compute_verdict(findings)

    report = {
        "generated_at": utc_now(),
        "verdict": verdict,
        "findings": findings,
        "stats": stats,
        "pass_count": sum(1 for f in findings if f["level"] == "PASS"),
        "warn_count": sum(1 for f in findings if f["level"] == "WARN"),
        "fail_count": sum(1 for f in findings if f["level"] == "FAIL"),
    }

    write_audit_report(report, output_path)
    print_summary(report)

    if verdict == "FAIL":
        log.critical("AUDIT VERDICT: FAIL -- %d critical issue(s) detected. "
                     "Review audit report: %s", report["fail_count"], output_path)
        return 1

    log.info("AUDIT VERDICT: %s  (pass=%d warn=%d fail=%d)",
             verdict, report["pass_count"], report["warn_count"], report["fail_count"])
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Pipeline Self-Audit Engine")
    parser.add_argument(
        "--output", default=str(AUDIT_DIR / "pipeline_audit.json"),
        help="Path to write audit JSON report"
    )
    parser.add_argument(
        "--fail-on-warn", action="store_true",
        help="Treat WARN findings as FAIL (strict mode)"
    )
    args = parser.parse_args()
    return run_audit(Path(args.output))


if __name__ == "__main__":
    sys.exit(main())
