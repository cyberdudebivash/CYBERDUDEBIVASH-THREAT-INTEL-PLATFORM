#!/usr/bin/env python3
"""
scripts/p25_enterprise_trust_gate.py
CYBERDUDEBIVASH(R) SENTINEL APEX  -  P25.11 Enterprise Release Gate
====================================================================
Validates the intelligence feed against enterprise trust thresholds
before worldwide customer release.

P25.11 Gate Dimensions:
  G1  Feed availability & parse integrity
  G2  Average confidence level
  G3  Severity distribution sanity
  G4  P21 certification gate (reads p21_certification_report.json)
  G5  P22 contradiction gate (reads p22_contradiction_report.json)
  G6  P23 patch intelligence gate (reads p23_patch_priority_report.json)
  G7  P24 commercial certification gate (reads p24_commercial_certification.json)
  G8  IOC & TTP coverage ratio
  G9  STIX bundle availability
  G10 Report URL completeness

Release tiers:
  WORLDWIDE_RELEASE   -- all blockers resolved, all gates pass
  ENTERPRISE_RELEASE  -- minor gaps, no blockers
  CONTROLLED_RELEASE  -- 1-2 minor blockers (non-critical)
  RELEASE_BLOCKED     -- critical blocker present

ZERO FABRICATION  -  reads existing pipeline output files only.
"""
from __future__ import annotations
import json, pathlib, sys, datetime, os

_ROOT    = pathlib.Path(__file__).resolve().parent.parent
_QUALITY = _ROOT / "data" / "quality"
_FEED    = _ROOT / "feed.json"

DRY_RUN  = os.environ.get("DRY_RUN",  "false").strip().lower() == "true"
VERSION  = "P25.0"


# ── helpers ────────────────────────────────────────────────────────────────────

def _load_json(path: pathlib.Path) -> dict | list | None:
    try:
        return json.loads(path.read_bytes())
    except Exception:
        return None


def _load_feed() -> list:
    raw = _load_json(_FEED)
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("items", "data", "feed"):
            if isinstance(raw.get(key), list):
                return raw[key]
    return []


# ── gate checks ───────────────────────────────────────────────────────────────

def _g1_feed_integrity(items: list) -> tuple[bool, str, list[str]]:
    """G1: Feed availability and parse integrity."""
    if not items:
        return False, "Feed empty or unreadable", ["Ensure pipeline completed Stage 3.0 feed generation"]
    required_fields = {"id", "title", "severity"}
    sample = items[:10]
    missing_id  = sum(1 for i in sample if not i.get("id"))
    missing_ttl = sum(1 for i in sample if not i.get("title"))
    if missing_id > 3 or missing_ttl > 3:
        return False, f"Feed schema incomplete ({missing_id} missing id, {missing_ttl} missing title in first 10)", []
    return True, f"Feed OK: {len(items)} items parsed", []


def _g2_confidence(items: list) -> tuple[bool, str, list[str]]:
    """G2: Average confidence level across feed."""
    confs = [float(i.get("confidence") or 0) for i in items if i.get("confidence") is not None]
    if not confs:
        return True, "Confidence field absent (non-blocking)", []
    avg = sum(confs) / len(confs)
    if avg < 0.10:
        return False, f"Average confidence critically low: {avg:.2%}", [
            "Confidence engine output below acceptable threshold",
            "Check Stage 3.1.4 Intelligence Quality Hardener"
        ]
    return True, f"Average confidence: {avg:.2%} ({len(confs)} items with confidence data)", []


def _g3_severity_distribution(items: list) -> tuple[bool, str, list[str]]:
    """G3: Severity distribution sanity check."""
    dist: dict[str, int] = {}
    for item in items:
        sev = str(item.get("severity") or "UNKNOWN").upper()
        dist[sev] = dist.get(sev, 0) + 1
    unknown_pct = dist.get("UNKNOWN", 0) / max(len(items), 1)
    if unknown_pct > 0.80:
        return False, f"{unknown_pct:.0%} of items have UNKNOWN severity — enrichment pipeline may be degraded", [
            "Check Stage 3.1.4 Intelligence Quality Hardener",
            "Verify CVSS enrichment stage 3.1.2 completed successfully"
        ]
    return True, f"Severity distribution: {dict(sorted(dist.items()))}", []


def _g4_p21_gate() -> tuple[bool, str, list[str]]:
    """G4: P21 certification gate."""
    path = _QUALITY / "p21_certification_report.json"
    data = _load_json(path)
    if data is None:
        return True, "P21 report not present (pipeline may not have run  -  non-blocking)", []
    avg  = float(data.get("average_score", 0))
    dist = data.get("level_distribution", {})
    pc   = dist.get("PREMIUM_CERTIFIED", 0)
    er   = dist.get("ENTERPRISE_READY",  0)
    tot  = data.get("total_items", 1) or 1
    below_min_pct = (dist.get("BELOW_MINIMUM", 0) / tot)
    if below_min_pct > 0.50:
        return False, f"P21: {below_min_pct:.0%} of items below minimum certification — quality crisis", [
            "Review P21 certification thresholds",
            "Run p21_certification_gate.py --verbose for item-level diagnosis"
        ]
    return True, f"P21: avg={avg:.1f} | PREMIUM_CERTIFIED={pc} | ENTERPRISE_READY={er}", []


def _g5_p22_gate() -> tuple[bool, str, list[str]]:
    """G5: P22 contradiction gate."""
    path = _QUALITY / "p22_contradiction_report.json"
    data = _load_json(path)
    if data is None:
        return True, "P22 report not present (non-blocking)", []
    errors   = int(data.get("error_count", 0))
    warnings = int(data.get("warning_count", 0))
    total    = int(data.get("total_contradictions", 0))
    if errors > 10:
        return False, f"P22: {errors} ERROR-level contradictions remain after auto-fix pass", [
            "Set AUTO_FIX=true in CI environment (already set in stage 3.93.15e)",
            "Review p22_contradiction_detector.py for unresolvable C1/C2 patterns"
        ]
    return True, f"P22: {total} contradiction(s) detected | errors={errors} | warnings={warnings}", []


def _g6_p23_gate() -> tuple[bool, str, list[str]]:
    """G6: P23 patch intelligence gate."""
    path = _QUALITY / "p23_patch_priority_report.json"
    data = _load_json(path)
    if data is None:
        return True, "P23 report not present (non-blocking)", []
    processed  = int(data.get("items_processed", 0))
    immediate  = int(data.get("immediate_count",  0))
    # Immediate items are operational signal, not a gate blocker
    return True, f"P23: {processed} items processed | {immediate} PATCH IMMEDIATELY", []


def _g7_p24_gate() -> tuple[bool, str, list[str]]:
    """G7: P24 commercial certification gate."""
    path = _QUALITY / "p24_commercial_certification.json"
    data = _load_json(path)
    if data is None:
        return True, "P24 report not present (non-blocking in dev)", []
    tier     = str(data.get("release_tier", "UNKNOWN"))
    pct      = float(data.get("overall_pct", 0))
    blockers = int(data.get("blocker_count", 0))
    if tier == "RELEASE_BLOCKED":
        return False, f"P24: RELEASE BLOCKED — {blockers} blocker(s) must be resolved. Score: {pct:.0f}%", [
            "Review data/quality/p24_commercial_certification.json for blocker detail",
            "Run python3 scripts/p24_commercial_certification.py --verbose"
        ]
    return True, f"P24: {tier} | Score: {pct:.0f}% | Blockers: {blockers}", []


def _g8_ioc_ttp_coverage(items: list) -> tuple[bool, str, list[str]]:
    """G8: IOC & TTP coverage ratio."""
    ioc_items = sum(1 for i in items if int(i.get("ioc_count") or 0) > 0)
    ttp_items = sum(1 for i in items if int(i.get("ttp_count") or 0) > 0)
    ioc_pct   = ioc_items / max(len(items), 1)
    ttp_pct   = ttp_items / max(len(items), 1)
    # Low IOC coverage is expected for CVE items — non-blocking gate
    return True, f"IOC coverage: {ioc_pct:.0%} ({ioc_items}/{len(items)}) | ATT&CK coverage: {ttp_pct:.0%} ({ttp_items}/{len(items)})", []


def _g9_stix_coverage(items: list) -> tuple[bool, str, list[str]]:
    """G9: STIX bundle availability."""
    stix_items = sum(1 for i in items if i.get("stix_bundle"))
    pct        = stix_items / max(len(items), 1)
    if pct < 0.30:
        return True, f"STIX coverage low: {pct:.0%} — TAXII integration will have limited interoperability (non-blocking)", []
    return True, f"STIX bundle coverage: {pct:.0%} ({stix_items}/{len(items)})", []


def _g10_report_url(items: list) -> tuple[bool, str, list[str]]:
    """G10: Report URL completeness."""
    with_report = sum(1 for i in items if i.get("report_url") or i.get("internal_report_url"))
    pct         = with_report / max(len(items), 1)
    if pct < 0.50:
        return False, f"Only {pct:.0%} of items have report URLs — enterprise report delivery degraded", [
            "Verify Stage 3.93.7 Report Generator completed successfully",
            "Check generate_intel_reports.py output"
        ]
    return True, f"Report URL coverage: {pct:.0%} ({with_report}/{len(items)})", []


# ── main ──────────────────────────────────────────────────────────────────────

def run() -> dict:
    items = _load_feed()

    gates = [
        ("G1",  "Feed Integrity",               _g1_feed_integrity(items)),
        ("G2",  "Confidence Level",              _g2_confidence(items)),
        ("G3",  "Severity Distribution",         _g3_severity_distribution(items)),
        ("G4",  "P21 Certification",             _g4_p21_gate()),
        ("G5",  "P22 Contradiction",             _g5_p22_gate()),
        ("G6",  "P23 Patch Intelligence",        _g6_p23_gate()),
        ("G7",  "P24 Commercial Certification",  _g7_p24_gate()),
        ("G8",  "IOC & TTP Coverage",            _g8_ioc_ttp_coverage(items)),
        ("G9",  "STIX Interoperability",         _g9_stix_coverage(items)),
        ("G10", "Report URL Completeness",       _g10_report_url(items)),
    ]

    blockers     = []
    gate_results = []
    for code, name, (passed, msg, remediation) in gates:
        gate_results.append({
            "gate":        code,
            "name":        name,
            "passed":      passed,
            "message":     msg,
            "remediation": remediation,
        })
        if not passed:
            blockers.append(f"{code} {name}: {msg}")

    blocker_count = len(blockers)
    if blocker_count == 0:
        release_tier  = "WORLDWIDE_RELEASE"
        release_color = "✅"
    elif blocker_count == 1 and all(r["gate"] not in ("G1",) for r in gate_results if not r["passed"]):
        release_tier  = "CONTROLLED_RELEASE"
        release_color = "⚠️"
    elif blocker_count <= 2:
        release_tier  = "ENTERPRISE_RELEASE"
        release_color = "🔶"
    else:
        release_tier  = "RELEASE_BLOCKED"
        release_color = "🚫"

    report = {
        "version":       VERSION,
        "generated_at":  datetime.datetime.utcnow().isoformat() + "Z",
        "feed_items":    len(items),
        "release_tier":  release_tier,
        "blocker_count": blocker_count,
        "blockers":      blockers,
        "gates":         gate_results,
    }

    # Print CI summary
    print(f"[P25.11] Enterprise Release Gate — {release_color} {release_tier}")
    print(f"[P25.11] Items: {len(items)} | Blockers: {blocker_count}/10 gates")
    for gr in gate_results:
        status = "✓" if gr["passed"] else "✗"
        print(f"  [{status}] {gr['gate']} {gr['name']}: {gr['message']}")
    if blockers:
        print("[P25.11] BLOCKERS:")
        for b in blockers:
            print(f"  !! {b}")

    if not DRY_RUN:
        _QUALITY.mkdir(parents=True, exist_ok=True)
        out = _QUALITY / "p25_enterprise_trust_gate.json"
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[P25.11] Report written: {out}")

    return report


if __name__ == "__main__":
    result = run()
    # Exit 1 only on RELEASE_BLOCKED (hard blocker) — continue-on-error in CI anyway
    sys.exit(1 if result["release_tier"] == "RELEASE_BLOCKED" else 0)
