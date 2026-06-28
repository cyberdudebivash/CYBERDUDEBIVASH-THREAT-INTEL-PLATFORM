#!/usr/bin/env python3
"""
scripts/p35_production_certification.py
CYBERDUDEBIVASH® SENTINEL APEX — P35 Enterprise Intelligence Quality Engineering
Production Certification v1.0.0

Scope: intelligence quality, evidence integrity, confidence calibration,
source diversity, freshness, drift detection, FP analytics, engineering KPIs.

Chains from: p34_certification_report.json (G01 is a chain blocker).
Does NOT replace or modify any P20-P34 certification. Additive only.

26 gates across:
  Chain integrity    G01-G05
  Feed quality       G06-G12
  Evidence integrity G13-G16
  Confidence         G17-G19
  Source diversity   G20-G22
  MITRE coverage     G23-G24
  Engineering KPIs   G25-G26

Exit codes:
  0 = WORLDWIDE_RELEASE (0 blockers)
  1 = BLOCKED (1+ blockers)

Output: data/quality/p35_certification_report.json
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Any

_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_DATA   = _ROOT / "data" / "quality"
_HEALTH = _ROOT / "data" / "health"
_GOV    = _ROOT / "data" / "governance"
_AUDIT  = _ROOT / "data" / "audit"
_WORKER = _ROOT / "workers" / "intel-gateway" / "src"

GATES: list[dict[str, Any]] = []
_passed = _blockers = _warnings = 0


def gate(gid: str, label: str, severity: str, result: bool, detail: str) -> None:
    global _passed, _blockers, _warnings
    status = "PASS" if result else ("FAIL_BLOCKER" if severity == "BLOCKER" else "FAIL_WARNING")
    if result:       _passed   += 1
    elif severity == "BLOCKER": _blockers += 1
    else:            _warnings += 1
    GATES.append({"gate_id": gid, "label": label, "severity": severity,
                  "status": status, "detail": detail})
    icon = "✅" if result else ("❌" if severity == "BLOCKER" else "⚠️")
    print(f"  {icon} [{status}] {gid}: {label} — {detail}")


def _load(path: pathlib.Path) -> dict | list | None:
    try:
        return json.loads(path.read_bytes())
    except Exception:
        return None


def _feed() -> list:
    for p in [_ROOT / "feed.json", _ROOT / "api" / "feed.json", _DATA.parent / "feed.json"]:
        if p.exists():
            try:
                raw = json.loads(p.read_bytes())
                if isinstance(raw, list):
                    return raw
                for k in ("items", "advisories", "data"):
                    if isinstance(raw.get(k), list):
                        return raw[k]
            except Exception:
                pass
    return []


def _avg(vals: list) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def main() -> int:
    print("=" * 65)
    print("CYBERDUDEBIVASH® SENTINEL APEX — P35 Quality Engineering Cert")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 65)

    # ─── Chain integrity G01-G05 ─────────────────────────────────────────

    p34 = _load(_DATA / "p34_certification_report.json")
    gate("G01", "P34 certification chain intact", "BLOCKER",
         p34 is not None and p34.get("blocker_count", 1) == 0,
         f"tier={p34.get('release_tier','?')} blockers={p34.get('blocker_count','?')}"
         if p34 else "p34_certification_report.json not found")

    gate("G02", "P34 release tier = WORLDWIDE_RELEASE", "BLOCKER",
         p34 is not None and p34.get("release_tier") == "WORLDWIDE_RELEASE",
         p34.get("release_tier", "N/A") if p34 else "unavailable")

    p33 = _load(_DATA / "p33_certification_report.json")
    gate("G03", "P33 certification report present and WORLDWIDE_RELEASE", "WARNING",
         p33 is not None and p33.get("release_tier") == "WORLDWIDE_RELEASE",
         f"tier={p33.get('release_tier','?')}" if p33 else "not found")

    p26 = _load(_DATA / "p26_certification_report.json")
    gate("G04", "P26 certification report present", "WARNING",
         p26 is not None,
         f"tier={p26.get('release_tier','?')}" if p26 else "not found")

    p25 = _load(_DATA / "p25_enterprise_trust_gate.json")
    gate("G05", "P25 enterprise trust gate cert present", "WARNING",
         p25 is not None,
         f"tier={p25.get('release_tier','?')}" if p25 else "not found")

    # ─── Feed quality G06-G12 ────────────────────────────────────────────

    feed = _feed()
    n = len(feed)

    gate("G06", "Feed non-empty (>= 1 item)", "BLOCKER", n >= 1, f"items={n}")
    gate("G07", "Feed item count >= 10", "BLOCKER", n >= 10, f"items={n}")

    required_fields = ["id", "title", "severity"]
    missing_req = [i for i in feed[:50] if any(not i.get(f) for f in required_fields)]
    gate("G08", "All items have required fields (id, title, severity)", "BLOCKER",
         len(missing_req) == 0,
         f"OK — {min(50,n)} checked" if not missing_req else f"{len(missing_req)} items missing required fields")

    ids = [i.get("id", "") for i in feed if isinstance(i, dict)]
    nids = [x for x in ids if x]
    dupes = [x for x in set(nids) if nids.count(x) > 1]
    gate("G09", "No duplicate IDs in feed", "BLOCKER",
         len(dupes) == 0,
         f"OK — {len(nids)} unique IDs" if not dupes else f"{len(dupes)} duplicate IDs")

    over10 = [i for i in feed if isinstance(i.get("risk_score"), (int, float)) and i["risk_score"] > 10]
    gate("G10", "No items with risk_score > 10 (score ceiling)", "BLOCKER",
         len(over10) == 0,
         "OK — all within ceiling" if not over10 else f"{len(over10)} items exceed ceiling")

    short_title = [i for i in feed[:100] if len(str(i.get("title", ""))) < 10]
    gate("G11", "Items have title >= 10 chars", "WARNING",
         len(short_title) == 0,
         "OK" if not short_title else f"{len(short_title)} short titles")

    has_ch = any(str(i.get("severity","")).upper() in ("CRITICAL","HIGH")
                 or (isinstance(i.get("severity",()), (int,float)) and i["severity"] >= 8)
                 for i in feed)
    gate("G12", "Feed contains >= 1 CRITICAL or HIGH item", "WARNING",
         has_ch, "CRITICAL/HIGH items present" if has_ch else "No high-severity items")

    # ─── Evidence integrity G13-G16 ──────────────────────────────────────

    sample = feed[:200]
    ns = max(len(sample), 1)

    ev_report = _load(_GOV / "evidence_score_enforcement.json")
    gate("G13", "Evidence score enforcement report present", "WARNING",
         ev_report is not None,
         "found" if ev_report else "data/governance/evidence_score_enforcement.json not found (run evidence_score_enforcer.py)")

    with_cvss  = sum(1 for i in sample if i.get("cvss") or i.get("cvss_score"))
    with_cve   = sum(1 for i in sample if str(i.get("cve") or i.get("cve_id") or "").startswith("CVE-"))
    with_ioc   = sum(1 for i in sample if isinstance(i.get("iocs") or i.get("indicators"), list)
                     and len(i.get("iocs") or i.get("indicators") or []) > 0)
    ev_density = (with_cvss + with_cve + with_ioc) / (ns * 3) * 100
    gate("G14", "Evidence density >= 20% (cvss + cve + ioc signals)", "WARNING",
         ev_density >= 20, f"evidence_density={ev_density:.1f}%")

    hse = sum(1 for i in sample
              if (isinstance(i.get("risk_score"),(int,float)) and i["risk_score"] >= 8)
              and not (i.get("cvss") or i.get("cve") or i.get("kev_present")))
    gate("G15", "High-score items without evidence <= 5%", "WARNING",
         hse / ns * 100 <= 5,
         f"high_score_no_evidence={hse} ({hse/ns*100:.1f}%)")

    with_actor = sum(1 for i in sample if i.get("actor") or i.get("threat_actor"))
    gate("G16", "Actor attribution coverage >= 20%", "WARNING",
         with_actor / ns * 100 >= 20,
         f"actor_coverage={with_actor/ns*100:.1f}%")

    # ─── Confidence G17-G19 ───────────────────────────────────────────────

    with_conf = sum(1 for i in sample if i.get("confidence") is not None)
    gate("G17", "Confidence field coverage >= 30%", "WARNING",
         with_conf / ns * 100 >= 30,
         f"confidence_coverage={with_conf/ns*100:.1f}%")

    conf_vals = [float(i["confidence"]) for i in sample
                 if isinstance(i.get("confidence"), (int, float))]
    avg_conf = _avg(conf_vals)
    gate("G18", "Average confidence >= 30 (calibration floor)", "WARNING",
         avg_conf >= 30 or len(conf_vals) == 0,
         f"avg_confidence={avg_conf:.1f} (over {len(conf_vals)} items)" if conf_vals else "no confidence values")

    null_conf = sum(1 for i in sample if "confidence" in i and i["confidence"] is None)
    gate("G19", "No null confidence values", "WARNING",
         null_conf == 0, f"null_confidence={null_conf}")

    # ─── Source diversity G20-G22 ─────────────────────────────────────────

    src_counts: dict[str,int] = {}
    for i in feed[:500]:
        src = str(i.get("source") or i.get("feed_source") or i.get("source_url") or "unknown")
        key = src.replace("http://","").replace("https://","").split("/")[0][:60]
        src_counts[key] = src_counts.get(key, 0) + 1
    unique_srcs = len(src_counts)
    top_dom = max(src_counts.values(), default=0) / max(len(feed[:500]), 1) * 100

    gate("G20", "Feed has >= 2 distinct sources", "WARNING",
         unique_srcs >= 2, f"unique_sources={unique_srcs}")

    gate("G21", "Top source dominance < 80%", "WARNING",
         top_dom < 80, f"top_dominance={top_dom:.1f}%")

    src_trust = _load(_DATA / "source_trust_scores.json")
    gate("G22", "Source trust scores report present", "WARNING",
         src_trust is not None,
         "found" if src_trust else "data/quality/source_trust_scores.json not found")

    # ─── MITRE coverage G23-G24 ─────────────────────────────────────────

    mitre_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    ttp_items = [i for i in sample if isinstance(i.get("ttps"), list) and i["ttps"]]
    ttp_cov   = len(ttp_items) / ns * 100
    gate("G23", "TTP field coverage >= 30%", "WARNING",
         ttp_cov >= 30, f"ttp_coverage={ttp_cov:.1f}%")

    bad_ttp = []
    for i in feed[:50]:
        for t in (i.get("ttps") or []):
            if isinstance(t, str) and t.startswith("T") and not mitre_re.match(t):
                bad_ttp.append(t)
    gate("G24", "MITRE TTP format valid (T####)", "WARNING",
         len(bad_ttp) == 0,
         "OK" if not bad_ttp else f"{len(bad_ttp)} invalid formats: {bad_ttp[:3]}")

    # ─── Engineering KPIs G25-G26 ────────────────────────────────────────

    p35_handler = _WORKER / "p35-handlers.js"
    gate("G25", "p35-handlers.js exists and has required exports", "BLOCKER",
         p35_handler.exists() and "handleP35Quality" in p35_handler.read_text(encoding="utf-8"),
         "found + exports verified" if p35_handler.exists() else "p35-handlers.js not found")

    p35_routes = False
    idx = _WORKER / "index.js"
    if idx.exists():
        p35_routes = "/api/v1/p35/" in idx.read_text(encoding="utf-8")
    gate("G26", "index.js has P35 routes (/api/v1/p35/)", "BLOCKER",
         p35_routes,
         "P35 routes present" if p35_routes else "P35 routes missing from index.js")

    # ─── Summary ─────────────────────────────────────────────────────────

    total_gates  = len(GATES)
    release_tier = "WORLDWIDE_RELEASE" if _blockers == 0 else "BLOCKED"

    print()
    print("=" * 65)
    print(f"P35 CERTIFICATION RESULT: {release_tier}")
    print(f"Gates: {_passed}/{total_gates} PASS · {_blockers} BLOCKERS · {_warnings} WARNINGS")
    print("=" * 65)

    src_top = max(src_counts, key=src_counts.get) if src_counts else "unknown"
    report = {
        "schema_version":   "p35.0",
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "layer":            "P35",
        "scope":            "enterprise_intelligence_quality_engineering",
        "release_tier":     release_tier,
        "passed_count":     _passed,
        "blocker_count":    _blockers,
        "warning_count":    _warnings,
        "total_gates":      total_gates,
        "feed_item_count":  n,
        "p34_tier":         p34.get("release_tier", "UNKNOWN") if p34 else "UNKNOWN",
        "quality_summary": {
            "evidence_density_pct":    round(ev_density, 2),
            "ttp_coverage_pct":        round(ttp_cov, 2),
            "actor_coverage_pct":      round(with_actor / ns * 100, 2),
            "cve_coverage_pct":        round(with_cve / ns * 100, 2),
            "source_diversity_count":  unique_srcs,
            "top_source_dominance_pct": round(top_dom, 2),
            "top_source":              src_top,
            "avg_confidence":          round(avg_conf, 2),
        },
        "gates": GATES,
    }

    _DATA.mkdir(parents=True, exist_ok=True)
    out = _DATA / "p35_certification_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport: {out.relative_to(_ROOT)}")
    return 0 if _blockers == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
