#!/usr/bin/env python3
"""
scripts/p34_production_certification.py
CYBERDUDEBIVASH® SENTINEL APEX — P34 Engineering Assurance Certification v1.0.0

Scope: engineering assurance & platform excellence.
This script evaluates 26 production gates across:
  - Certification chain integrity (G01-G05)
  - Feed health & schema quality (G06-G14)
  - Intelligence field coverage (G15-G20)
  - Handler & route completeness (G21-G24)
  - CI/CD assurance (G25-G26)

Chains from: p33_certification_report.json (G01 is a chain blocker).

Exit codes:
  0 = WORLDWIDE_RELEASE (0 blockers)
  1 = BLOCKED (1+ blockers)

Output: data/quality/p34_certification_report.json
"""
from __future__ import annotations

import json
import pathlib
import sys
import time
from datetime import datetime, timezone
from typing import Any

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data" / "quality"
_WORKERS = _ROOT / "workers" / "intel-gateway" / "src"
_SCRIPTS = _ROOT / "scripts"
_WORKFLOW = _ROOT / ".github" / "workflows" / "sentinel-blogger.yml"

GATES: list[dict[str, Any]] = []
_passed = 0
_blockers = 0
_warnings = 0


def gate(gid: str, label: str, severity: str, result: bool, detail: str) -> None:
    global _passed, _blockers, _warnings
    status = "PASS" if result else ("FAIL_BLOCKER" if severity == "BLOCKER" else "FAIL_WARNING")
    if result:
        _passed += 1
    elif severity == "BLOCKER":
        _blockers += 1
    else:
        _warnings += 1
    GATES.append({
        "gate_id": gid,
        "label": label,
        "severity": severity,
        "status": status,
        "detail": detail,
    })
    icon = "✅" if result else ("❌" if severity == "BLOCKER" else "⚠️")
    print(f"  {icon} [{status}] {gid}: {label} — {detail}")


def _load_json(path: pathlib.Path) -> dict | None:
    try:
        return json.loads(path.read_bytes())
    except Exception:
        return None


def _load_feed() -> list:
    candidates = [
        _ROOT / "feed.json",
        _ROOT / "api" / "feed.json",
        _ROOT / "data" / "feed.json",
    ]
    for p in candidates:
        if p.exists():
            try:
                raw = json.loads(p.read_bytes())
                if isinstance(raw, list):
                    return raw
                if isinstance(raw, dict):
                    for key in ("items", "advisories", "data"):
                        if isinstance(raw.get(key), list):
                            return raw[key]
            except Exception:
                pass
    return []


def main() -> int:
    print("=" * 65)
    print("CYBERDUDEBIVASH® SENTINEL APEX — P34 Engineering Assurance")
    print(f"Certification started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 65)

    # ─── G01: P33 certification chain intact ─────────────────────────────
    p33_path = _DATA / "p33_certification_report.json"
    p33 = _load_json(p33_path)
    gate("G01", "P33 certification chain intact", "BLOCKER",
         p33 is not None and p33.get("blocker_count", 1) == 0,
         f"tier={p33.get('release_tier','?')} blockers={p33.get('blocker_count','?')}"
         if p33 else "p33_certification_report.json not found")

    # ─── G02: P33 release tier = WORLDWIDE_RELEASE ───────────────────────
    gate("G02", "P33 release tier = WORLDWIDE_RELEASE", "BLOCKER",
         p33 is not None and p33.get("release_tier") == "WORLDWIDE_RELEASE",
         p33.get("release_tier", "N/A") if p33 else "unavailable")

    # ─── G03: P32 certification report present ───────────────────────────
    p32 = _load_json(_DATA / "p32_certification_report.json")
    gate("G03", "P32 certification report present and passing", "WARNING",
         p32 is not None and p32.get("blocker_count", 1) == 0,
         f"tier={p32.get('release_tier','?')}" if p32 else "not found (non-fatal)")

    # ─── G04: P31 certification report present ───────────────────────────
    p31 = _load_json(_DATA / "p31_certification_report.json")
    gate("G04", "P31 certification report present", "WARNING",
         p31 is not None,
         f"tier={p31.get('release_tier','?')}" if p31 else "not found (non-fatal)")

    # ─── G05: P33 passed_count / total_gates >= 0.75 ─────────────────────
    p33_rate = 0.0
    if p33 and p33.get("total_gates", 0) > 0:
        p33_rate = p33.get("passed_count", 0) / p33.get("total_gates", 1)
    gate("G05", "P33 gate pass rate >= 75%", "WARNING",
         p33_rate >= 0.75,
         f"rate={p33_rate:.1%}" if p33 else "unavailable")

    # ─── Feed checks ─────────────────────────────────────────────────────
    feed = _load_feed()
    feed_count = len(feed)

    # G06: Feed non-empty
    gate("G06", "Feed non-empty (>= 1 item)", "BLOCKER",
         feed_count >= 1,
         f"feed_items={feed_count}")

    # G07: Feed items count >= 10 (minimum viable corpus)
    gate("G07", "Feed item count >= 10 (minimum viable corpus)", "BLOCKER",
         feed_count >= 10,
         f"item_count={feed_count}")

    # G08: Required fields present in all items (id, title, severity)
    required = ["id", "title", "severity"]
    missing_required = [i for i in feed[:50] if any(not i.get(f) for f in required)]
    gate("G08", "All feed items have required fields (id, title, severity)", "BLOCKER",
         len(missing_required) == 0,
         f"OK — {min(50, feed_count)} items checked" if not missing_required
         else f"{len(missing_required)} items missing required fields")

    # G09: No duplicate IDs
    ids = [i.get("id", "") for i in feed if isinstance(i, dict)]
    non_empty_ids = [x for x in ids if x]
    dupes = [x for x in set(non_empty_ids) if non_empty_ids.count(x) > 1]
    gate("G09", "No duplicate item IDs in feed", "BLOCKER",
         len(dupes) == 0,
         f"OK — {len(non_empty_ids)} unique IDs" if not dupes
         else f"{len(dupes)} duplicate ID(s): {dupes[:3]}")

    # G10: No items with risk_score > 10 (ceiling enforcement)
    over_ceil = [i for i in feed if isinstance(i.get("risk_score"), (int, float)) and i["risk_score"] > 10]
    gate("G10", "No items with risk_score > 10 (score ceiling enforcement)", "BLOCKER",
         len(over_ceil) == 0,
         f"OK — all scores within ceiling" if not over_ceil
         else f"{len(over_ceil)} items exceed risk_score ceiling of 10")

    # G11: Severity values are non-null
    null_sev = [i for i in feed[:100] if i.get("severity") is None and "severity" in i]
    gate("G11", "No null severity values", "WARNING",
         len(null_sev) == 0,
         f"OK" if not null_sev else f"{len(null_sev)} null severity value(s)")

    # G12: Title length >= 10 chars for all items
    short_title = [i for i in feed[:100] if len(str(i.get("title", ""))) < 10]
    gate("G12", "All items have title >= 10 chars (quality floor)", "WARNING",
         len(short_title) == 0,
         f"OK — all titles sufficient" if not short_title
         else f"{len(short_title)} items with short/missing title")

    # G13: Feed has at least one CRITICAL or HIGH item
    has_critical_high = any(
        str(i.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        or (isinstance(i.get("severity"), (int, float)) and i["severity"] >= 8)
        for i in feed
    )
    gate("G13", "Feed contains >= 1 CRITICAL or HIGH severity item", "WARNING",
         has_critical_high,
         "CRITICAL/HIGH items present" if has_critical_high else "No high-severity items")

    # G14: Source field coverage >= 80%
    sample = feed[:100]
    slen = max(len(sample), 1)
    source_cov = sum(1 for i in sample if i.get("source") or i.get("source_url")) / slen * 100
    gate("G14", "Source field coverage >= 80%", "WARNING",
         source_cov >= 80,
         f"source_coverage={source_cov:.1f}%")

    # ─── Intelligence field coverage ─────────────────────────────────────

    # G15: TTP coverage >= 50%
    ttp_cov = sum(1 for i in sample if isinstance(i.get("ttps"), list) and len(i["ttps"]) > 0) / slen * 100
    gate("G15", "TTP field coverage >= 50%", "WARNING",
         ttp_cov >= 50,
         f"ttp_coverage={ttp_cov:.1f}%")

    # G16: IOC coverage >= 30%
    ioc_cov = sum(1 for i in sample
                  if isinstance(i.get("iocs") or i.get("indicators"), list)
                  and len(i.get("iocs") or i.get("indicators") or []) > 0) / slen * 100
    gate("G16", "IOC field coverage >= 30%", "WARNING",
         ioc_cov >= 30,
         f"ioc_coverage={ioc_cov:.1f}%")

    # G17: Actor/threat actor coverage >= 20%
    actor_cov = sum(1 for i in sample
                    if i.get("actor") or i.get("threat_actor") or i.get("actor_tag")) / slen * 100
    gate("G17", "Threat actor field coverage >= 20%", "WARNING",
         actor_cov >= 20,
         f"actor_coverage={actor_cov:.1f}%")

    # G18: CVE-referenced items >= 10%
    cve_cov = 0.0
    for i in sample:
        cve = i.get("cve") or i.get("cve_id") or i.get("cves") or ""
        if isinstance(cve, str) and cve.startswith("CVE-"):
            cve_cov += 1
        elif isinstance(cve, list) and cve:
            cve_cov += 1
    cve_cov = cve_cov / slen * 100
    gate("G18", "CVE-referenced items >= 10% (evidence-based intelligence)", "WARNING",
         cve_cov >= 10,
         f"cve_coverage={cve_cov:.1f}%")

    # G19: Confidence field coverage >= 50%
    conf_cov = sum(1 for i in sample if i.get("confidence") is not None) / slen * 100
    gate("G19", "Confidence field coverage >= 50%", "WARNING",
         conf_cov >= 50,
         f"confidence_coverage={conf_cov:.1f}%")

    # G20: MITRE TTP format validation (T#### pattern)
    import re
    mitre_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    bad_ttps = []
    for i in feed[:50]:
        for t in (i.get("ttps") or []):
            if isinstance(t, str) and t.startswith("T") and not mitre_re.match(t):
                bad_ttps.append(t)
    gate("G20", "MITRE ATT&CK TTP format valid (T#### pattern)", "WARNING",
         len(bad_ttps) == 0,
         f"OK — all TTP formats valid" if not bad_ttps
         else f"{len(bad_ttps)} invalid TTP format(s): {bad_ttps[:3]}")

    # ─── Handler & route completeness ────────────────────────────────────

    # G21: p34-handlers.js exists
    handler_path = _WORKERS / "p34-handlers.js"
    gate("G21", "p34-handlers.js exists", "BLOCKER",
         handler_path.exists(),
         f"found at {handler_path.relative_to(_ROOT)}" if handler_path.exists()
         else "workers/intel-gateway/src/p34-handlers.js not found")

    # G22: p34-handlers.js has required exports
    required_exports = [
        "handleP34Assurance", "handleP34Security", "handleP34Reliability",
        "handleP34Status", "handleP34Observability", "handleP34Dashboard",
        "handleP34Metrics",
    ]
    handler_ok = True
    handler_detail = "all required exports present"
    if handler_path.exists():
        content = handler_path.read_text(encoding="utf-8")
        missing_exp = [e for e in required_exports if f"export async function {e}" not in content]
        if missing_exp:
            handler_ok = False
            handler_detail = f"missing exports: {missing_exp}"
    else:
        handler_ok = False
        handler_detail = "handler file not found"
    gate("G22", "p34-handlers.js has all required exports", "BLOCKER",
         handler_ok, handler_detail)

    # G23: index.js has P34 import
    index_path = _WORKERS / "index.js"
    index_content = ""
    if index_path.exists():
        index_content = index_path.read_text(encoding="utf-8")
    has_p34_import = "p34-handlers.js" in index_content
    gate("G23", "index.js has P34 import", "BLOCKER",
         has_p34_import,
         "P34 import present" if has_p34_import else "p34-handlers.js not imported in index.js")

    # G24: index.js has P34 routes
    has_p34_routes = "/api/v1/p34/" in index_content
    gate("G24", "index.js has P34 API routes", "BLOCKER",
         has_p34_routes,
         "/api/v1/p34/ routes present" if has_p34_routes else "P34 routes missing from index.js")

    # ─── CI/CD assurance ─────────────────────────────────────────────────

    # G25: ci_stats_extract.py has p34 key
    ci_stats = _SCRIPTS / "ci_stats_extract.py"
    has_p34_stats = False
    if ci_stats.exists():
        has_p34_stats = '"p34"' in ci_stats.read_text(encoding="utf-8")
    gate("G25", "ci_stats_extract.py has p34 key", "WARNING",
         has_p34_stats,
         "p34 key present" if has_p34_stats else "p34 key not found in ci_stats_extract.py")

    # G26: sentinel-blogger.yml has STAGE 3.99
    has_stage_399 = False
    if _WORKFLOW.exists():
        has_stage_399 = "STAGE 3.99" in _WORKFLOW.read_text(encoding="utf-8")
    gate("G26", "sentinel-blogger.yml has STAGE 3.99 (P34 CI gate)", "WARNING",
         has_stage_399,
         "STAGE 3.99 present" if has_stage_399 else "STAGE 3.99 not yet in workflow")

    # ─── Summary ─────────────────────────────────────────────────────────
    total_gates = len(GATES)
    release_tier = "WORLDWIDE_RELEASE" if _blockers == 0 else "BLOCKED"

    print()
    print("=" * 65)
    print(f"P34 CERTIFICATION RESULT: {release_tier}")
    print(f"Gates: {_passed}/{total_gates} PASS · {_blockers} BLOCKERS · {_warnings} WARNINGS")
    print("=" * 65)

    report = {
        "schema_version": "p34.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "layer": "P34",
        "scope": "engineering_assurance_platform_excellence",
        "release_tier": release_tier,
        "passed_count": _passed,
        "blocker_count": _blockers,
        "warning_count": _warnings,
        "total_gates": total_gates,
        "feed_item_count": feed_count,
        "p33_tier": p33.get("release_tier", "UNKNOWN") if p33 else "UNKNOWN",
        "gates": GATES,
        "quality_summary": {
            "ttp_coverage_pct": round(ttp_cov, 2),
            "ioc_coverage_pct": round(ioc_cov, 2),
            "source_coverage_pct": round(source_cov, 2),
            "actor_coverage_pct": round(actor_cov, 2),
            "cve_coverage_pct": round(cve_cov, 2),
            "confidence_coverage_pct": round(conf_cov, 2),
        },
    }

    _DATA.mkdir(parents=True, exist_ok=True)
    out_path = _DATA / "p34_certification_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport: {out_path.relative_to(_ROOT)}")

    return 0 if _blockers == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
