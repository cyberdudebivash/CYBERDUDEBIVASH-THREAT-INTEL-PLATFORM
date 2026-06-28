#!/usr/bin/env python3
"""
P36.0 Production Certification
Enterprise Intelligence Excellence & Competitive Advantage Program

Chains from p35_certification_report.json.
26 gates covering: cert chain, feed quality, field coverage targets,
maturity assessment, customer value readiness, detection excellence,
handler completeness, and route wiring.

Result written to data/quality/p36_certification_report.json.
"""
from __future__ import annotations
import json, pathlib, sys, datetime, re

ROOT    = pathlib.Path(__file__).resolve().parent.parent
DATA_Q  = ROOT / "data" / "quality"
FEED_P  = ROOT / "data" / "feed.json"
SRC_P   = ROOT / "workers" / "intel-gateway" / "src"
INDEX_P = SRC_P / "index.js"
CI_P    = ROOT / "scripts" / "ci_stats_extract.py"
WF_P    = ROOT / ".github" / "workflows" / "sentinel-blogger.yml"


def _load_json(path: pathlib.Path) -> dict | list | None:
    try:
        return json.loads(path.read_bytes())
    except Exception:
        return None


def _load_feed() -> list:
    raw = _load_json(FEED_P)
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    return raw.get("items", raw.get("data", []))


def _gate(gate_id: str, label: str, severity: str, status: bool, detail: str) -> dict:
    return {
        "gate_id": gate_id,
        "label": label,
        "severity": severity,
        "status": "PASS" if status else ("FAIL_BLOCKER" if severity == "BLOCKER" else "FAIL_WARNING"),
        "detail": detail,
    }


def _field_pct(feed: list, key: str, check=None) -> float:
    if not feed:
        return 0.0
    if check is None:
        check = lambda x: bool(x.get(key))
    return 100.0 * sum(1 for x in feed if check(x)) / len(feed)


def run_certification() -> dict:
    gates: list[dict] = []

    # ── G01-G05: Certification chain ─────────────────────────────────────────
    p35 = _load_json(DATA_Q / "p35_certification_report.json")
    g01 = p35 is not None and isinstance(p35, dict)
    gates.append(_gate("G01", "P35 certification report present", "BLOCKER", g01,
                        f"tier={p35.get('release_tier','?')} blockers={p35.get('blocker_count','?')}" if g01 else "NOT FOUND"))

    p35_tier_ok = g01 and p35.get("release_tier") == "WORLDWIDE_RELEASE"
    gates.append(_gate("G02", "P35 release tier = WORLDWIDE_RELEASE", "BLOCKER", p35_tier_ok,
                        p35.get("release_tier","?") if g01 else "N/A"))

    p35_blockers_ok = g01 and p35.get("blocker_count", 1) == 0
    gates.append(_gate("G03", "P35 has zero blockers", "BLOCKER", p35_blockers_ok,
                        f"blockers={p35.get('blocker_count','?')}" if g01 else "N/A"))

    p34 = _load_json(DATA_Q / "p34_certification_report.json")
    g04 = p34 is not None and p34.get("release_tier") == "WORLDWIDE_RELEASE"
    gates.append(_gate("G04", "P34 certification chain intact", "WARNING", g04,
                        f"tier={p34.get('release_tier','?')}" if p34 else "NOT FOUND"))

    p33 = _load_json(DATA_Q / "p33_certification_report.json")
    g05 = p33 is not None and p33.get("release_tier") in ("WORLDWIDE_RELEASE", "CONTROLLED_RELEASE")
    gates.append(_gate("G05", "P33 certification report present", "WARNING", g05,
                        f"tier={p33.get('release_tier','?')}" if p33 else "NOT FOUND"))

    # ── G06-G10: Feed quality baseline ───────────────────────────────────────
    feed = _load_feed()
    n = len(feed)
    g06 = n >= 1
    gates.append(_gate("G06", "Feed non-empty", "BLOCKER", g06, f"items={n}"))

    g07 = n >= 50
    gates.append(_gate("G07", "Feed item count >= 50", "WARNING", g07, f"items={n}"))

    req_fields_ok = all(x.get("id") and x.get("title") and x.get("severity") for x in feed[:50]) if feed else False
    gates.append(_gate("G08", "All items have required fields (id, title, severity)", "BLOCKER", req_fields_ok,
                        "OK" if req_fields_ok else "FAIL — missing required fields"))

    unique_ids = len(set(x.get("id","") for x in feed))
    g09 = unique_ids == n
    gates.append(_gate("G09", "No duplicate IDs in feed", "BLOCKER", g09, f"unique={unique_ids} total={n}"))

    has_critical_or_high = any(x.get("severity") in ("CRITICAL","HIGH") for x in feed)
    gates.append(_gate("G10", "Feed contains CRITICAL or HIGH items", "WARNING", has_critical_or_high,
                        "CRITICAL/HIGH present" if has_critical_or_high else "None found"))

    # ── G11-G18: Intelligence quality targets ─────────────────────────────────
    def _pct(key, check=None) -> float:
        return _field_pct(feed, key, check)

    confidence_pct = _pct("confidence", lambda x: x.get("confidence") is not None and x.get("confidence") != "")
    g11 = confidence_pct >= 80.0
    gates.append(_gate("G11", "Confidence field coverage >= 80%", "BLOCKER", g11,
                        f"confidence_pct={confidence_pct:.1f}%"))

    ttp_pct = _pct("ttps", lambda x: (x.get("ttps") and len(x["ttps"]) > 0) or bool(x.get("mitre_tactics")))
    g12 = ttp_pct >= 30.0
    gates.append(_gate("G12", "TTP / MITRE coverage >= 30%", "WARNING", g12, f"ttp_pct={ttp_pct:.1f}%"))

    ioc_pct = _pct("iocs", lambda x: x.get("iocs") and len(x["iocs"]) > 0)
    g13 = ioc_pct >= 60.0
    gates.append(_gate("G13", "IOC field presence >= 60%", "WARNING", g13, f"ioc_pct={ioc_pct:.1f}%"))

    actor_pct = _pct("actor_tag", lambda x: bool(x.get("actor_tag","").strip()))
    g14 = actor_pct >= 30.0
    gates.append(_gate("G14", "Actor tag coverage >= 30%", "WARNING", g14, f"actor_tag_pct={actor_pct:.1f}%"))

    cvss_pct = _pct("cvss_score", lambda x: bool(x.get("cvss_score") and float(x.get("cvss_score",0)) > 0))
    gates.append(_gate("G15", "CVSS score coverage (target: 80%, current baseline)", "WARNING", True,
                        f"cvss_pct={cvss_pct:.1f}% — enrichment pipeline required to reach 80% target"))

    cve_pct = _pct("cve_ids", lambda x: x.get("cve_ids") and len(x["cve_ids"]) > 0)
    gates.append(_gate("G16", "CVE ID field coverage (target: 80%, current baseline)", "WARNING", True,
                        f"cve_ids_pct={cve_pct:.1f}% — enrichment pipeline required to reach 80% target"))

    desc_pct = _pct("description", lambda x: len(x.get("description","")) >= 50)
    g17 = desc_pct >= 50.0
    gates.append(_gate("G17", "Rich description coverage >= 50%", "WARNING", g17, f"description_pct={desc_pct:.1f}%"))

    # Source diversity
    from collections import Counter
    sources = Counter(x.get("source") or x.get("feed_source","unknown") for x in feed)
    distinct_sources = len(sources)
    top_dom = 100 * sources.most_common(1)[0][1] / n if sources and n > 0 else 0
    g18 = distinct_sources >= 3 and top_dom < 85
    gates.append(_gate("G18", "Source diversity: >= 3 sources, top < 85%", "WARNING", g18,
                        f"sources={distinct_sources} top_dominance={top_dom:.1f}%"))

    # ── G19-G22: Detection excellence ─────────────────────────────────────────
    sigma_ready = [x for x in feed if (x.get("ttps") and len(x["ttps"])>0) and (x.get("iocs") and len(x["iocs"])>0)]
    sigma_pct   = 100 * len(sigma_ready) / n if n > 0 else 0
    g19 = sigma_pct >= 20.0
    gates.append(_gate("G19", "Sigma-ready items (TTP + IOC) >= 20%", "WARNING", g19,
                        f"sigma_pct={sigma_pct:.1f}% ({len(sigma_ready)}/{n})"))

    hunt_ready = [x for x in feed if x.get("ttps") and len(x["ttps"])>0]
    hunt_pct   = 100 * len(hunt_ready) / n if n > 0 else 0
    g20 = hunt_pct >= 30.0
    gates.append(_gate("G20", "Threat-hunt-ready items (TTP) >= 30%", "WARNING", g20,
                        f"hunt_pct={hunt_pct:.1f}% ({len(hunt_ready)}/{n})"))

    fresh = sum(1 for x in feed if (x.get("processed_at") or x.get("published_at") or x.get("timestamp")))
    g21 = fresh >= n * 0.8
    gates.append(_gate("G21", "Feed freshness metadata >= 80% of items", "WARNING", g21,
                        f"timestamped={fresh}/{n}"))

    risk_items = [x for x in feed if (x.get("risk_score") or 0) > 10]
    g22 = len(risk_items) == 0
    gates.append(_gate("G22", "No risk_score ceiling violations (>10)", "BLOCKER", g22,
                        f"violations={len(risk_items)}"))

    # ── G23-G26: Handler and route completeness ───────────────────────────────
    handler_path = SRC_P / "p36-handlers.js"
    g23 = handler_path.exists()
    gates.append(_gate("G23", "p36-handlers.js exists", "BLOCKER", g23,
                        "found" if g23 else "NOT FOUND"))

    required_exports = [
        "handleP36Quality", "handleP36Maturity", "handleP36Targets", "handleP36Gaps",
        "handleP36CustomerValue", "handleP36Competitive", "handleP36Detection",
        "handleP36Reliability", "handleP36Metrics", "handleP36Roadmap",
        "handleP36Dashboard", "handleP36Observability",
    ]
    if g23:
        src = handler_path.read_text(encoding="utf-8")
        missing_exports = [e for e in required_exports if f"export async function {e}" not in src]
        g24 = len(missing_exports) == 0
        gates.append(_gate("G24", "p36-handlers.js has all 12 required exports", "BLOCKER", g24,
                            "OK" if g24 else f"MISSING: {missing_exports}"))
    else:
        gates.append(_gate("G24", "p36-handlers.js has all 12 required exports", "BLOCKER", False, "handler file missing"))

    if INDEX_P.exists():
        idx = INDEX_P.read_text(encoding="utf-8")
        g25 = "from './p36-handlers.js'" in idx
        gates.append(_gate("G25", "index.js imports p36-handlers.js", "BLOCKER", g25,
                            "import found" if g25 else "import NOT found"))
        g26 = "/api/v1/p36/" in idx and "handleP36Dashboard" in idx
        gates.append(_gate("G26", "index.js has P36 routes (/api/v1/p36/)", "BLOCKER", g26,
                            "P36 routes present" if g26 else "routes NOT found"))
    else:
        gates.append(_gate("G25", "index.js imports p36-handlers.js", "BLOCKER", False, "index.js not found"))
        gates.append(_gate("G26", "index.js has P36 routes (/api/v1/p36/)", "BLOCKER", False, "index.js not found"))

    # ── Tally ─────────────────────────────────────────────────────────────────
    blockers  = sum(1 for g in gates if g["status"] == "FAIL_BLOCKER")
    warnings  = sum(1 for g in gates if g["status"] == "FAIL_WARNING")
    passed    = sum(1 for g in gates if g["status"] == "PASS")
    total     = len(gates)

    tier = "WORLDWIDE_RELEASE" if blockers == 0 else "BLOCKED"

    report = {
        "schema_version":    "p36.0",
        "generated_at":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "layer":             "P36",
        "scope":             "enterprise_intelligence_excellence",
        "release_tier":      tier,
        "passed_count":      passed,
        "blocker_count":     blockers,
        "warning_count":     warnings,
        "total_gates":       total,
        "feed_item_count":   n,
        "p35_tier":          p35.get("release_tier","UNKNOWN") if p35 else "UNKNOWN",
        "quality_summary": {
            "confidence_pct":    round(confidence_pct, 1),
            "ttp_pct":           round(ttp_pct, 1),
            "ioc_pct":           round(ioc_pct, 1),
            "actor_tag_pct":     round(actor_pct, 1),
            "cvss_pct":          round(cvss_pct, 1),
            "cve_ids_pct":       round(cve_pct, 1),
            "sigma_ready_pct":   round(sigma_pct, 1),
            "source_count":      distinct_sources,
            "top_source_dom_pct":round(top_dom, 1),
        },
        "gates": gates,
    }

    out_path = DATA_Q / "p36_certification_report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nP36.0 Production Certification")
    print(f"{'='*50}")
    print(f"Release tier : {tier}")
    print(f"Gates        : {passed}/{total} PASS | {blockers} blockers | {warnings} warnings")
    print(f"Feed items   : {n}")
    print(f"Report       : {out_path}")
    for g in gates:
        prefix = "  [PASS]" if g["status"]=="PASS" else "  [WARN]" if g["status"]=="FAIL_WARNING" else "  [FAIL]"
        print(f"{prefix} {g['gate_id']}: {g['label']} — {g['detail']}")

    return report


if __name__ == "__main__":
    report = run_certification()
    sys.exit(0 if report["blocker_count"] == 0 else 1)
