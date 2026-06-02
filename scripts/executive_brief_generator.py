#!/usr/bin/env python3
"""
SENTINEL APEX v167.0 — EXECUTIVE INTELLIGENCE BRIEF GENERATOR
===============================================================
Phase 8: Auto-generates weekly CEO/CISO/Board-ready intelligence briefs.
Output: data/reports/executive-brief/{date}.json + PDF-ready HTML
"""
from __future__ import annotations
import json, logging, sys
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("EXEC-BRIEF-GEN")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "data" / "reports" / "executive-briefs"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def utc_now(): return datetime.now(timezone.utc).isoformat()

def generate_brief(feed_path: Path) -> dict:
    try:
        raw = json.loads(feed_path.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Cannot load feed: %s", e); return {}

    items = raw if isinstance(raw, list) else raw.get("advisories", raw.get("items", []))
    date_str = datetime.now().strftime("%Y-%m-%d")

    # Compute metrics
    total = len(items)
    critical = sum(1 for i in items if i.get("severity") == "CRITICAL")
    high = sum(1 for i in items if i.get("severity") == "HIGH")
    kev_count = sum(1 for i in items if i.get("kev_present"))
    avg_risk = round(sum(float(i.get("risk_score", 0)) for i in items) / max(total, 1), 1)

    # Top actors
    actor_counts: dict[str, int] = {}
    for item in items:
        actor = (item.get("threat_actor") or {}).get("actor_id", "UNATTR")
        if actor and actor not in ("CDB-UNATTR", "CDB-UNATTR-CVE", "UNKNOWN", "UNATTR"):
            actor_counts[actor] = actor_counts.get(actor, 0) + 1
    top_actors = sorted(actor_counts.items(), key=lambda x: -x[1])[:5]

    # Active campaigns
    campaign_counts: dict[str, int] = {}
    for item in items:
        c = (item.get("campaign_intelligence") or {}).get("primary_campaign")
        if c:
            campaign_counts[c] = campaign_counts.get(c, 0) + 1
    top_campaigns = sorted(campaign_counts.items(), key=lambda x: -x[1])[:3]

    # High-priority items (CRITICAL or KEV)
    priority_items = [i for i in items if i.get("severity") == "CRITICAL" or i.get("kev_present")][:5]

    brief = {
        "report_type": "executive_intelligence_brief",
        "report_id": f"EIB-{date_str}",
        "generated_at": utc_now(),
        "period": f"Week of {date_str}",
        "classification": "TLP:CLEAR",
        "schema_version": "v2.0",
        "platform": "CYBERDUDEBIVASH SENTINEL APEX v167.0",
        "executive_summary": {
            "threat_level": "ELEVATED" if critical > 0 or kev_count > 0 else "MODERATE",
            "total_advisories": total,
            "critical_advisories": critical,
            "high_advisories": high,
            "active_exploits_kev": kev_count,
            "average_risk_score": avg_risk,
            "immediate_action_required": critical > 0 or kev_count > 2,
        },
        "threat_landscape": {
            "top_attributed_actors": [{"actor_id": a, "advisory_count": c} for a, c in top_actors],
            "active_campaigns": [{"campaign_id": c, "advisory_count": cnt} for c, cnt in top_campaigns],
            "sector_exposure": _compute_sector_exposure(items),
        },
        "priority_advisories": [
            {
                "id": i.get("id"),
                "title": i.get("title"),
                "severity": i.get("severity"),
                "risk_score": i.get("risk_score"),
                "kev": i.get("kev_present", False),
                "actor": (i.get("threat_actor") or {}).get("actor_id"),
                "action": "PATCH IMMEDIATELY" if i.get("kev_present") else "PRIORITIZE PATCHING",
            }
            for i in priority_items
        ],
        "board_risk_indicators": {
            "financial_exposure_estimate": _estimate_financial_exposure(critical, kev_count),
            "regulatory_risk": "HIGH" if critical > 0 else "MODERATE",
            "operational_risk": "CRITICAL" if kev_count > 0 else "HIGH" if critical > 0 else "MODERATE",
            "reputational_risk": "HIGH" if critical > 2 else "MODERATE",
        },
        "recommended_actions": _generate_actions(critical, high, kev_count),
        "next_brief_date": _next_week_date(),
    }

    # Save
    out_file = REPORTS_DIR / f"{date_str}.json"
    out_file.write_text(json.dumps(brief, indent=2, ensure_ascii=False), encoding="utf-8")
    # Also write as latest
    (REPORTS_DIR / "latest.json").write_text(json.dumps(brief, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("[EBG] Executive brief generated: %s", out_file.name)
    return brief

def _compute_sector_exposure(items):
    sectors = {}
    for item in items:
        for tag in (item.get("tags") or []):
            if not tag.startswith("T"):
                sectors[tag] = sectors.get(tag, 0) + 1
    return [{"sector": k, "advisory_count": v} for k, v in sorted(sectors.items(), key=lambda x: -x[1])[:5]]

def _estimate_financial_exposure(critical, kev_count):
    base = critical * 2_000_000 + kev_count * 4_000_000
    if base == 0: return "$0-$500K (LOW)"
    if base < 5_000_000: return f"${base/1e6:.1f}M-${(base*2)/1e6:.0f}M (MODERATE)"
    return f"${base/1e6:.0f}M-${(base*3)/1e6:.0f}M (HIGH)"

def _generate_actions(critical, high, kev_count):
    actions = []
    if kev_count > 0:
        actions.append({"priority": "P0", "action": f"IMMEDIATE: Apply patches for {kev_count} actively-exploited vulnerabilities", "timeline": "24-48 hours"})
    if critical > 0:
        actions.append({"priority": "P1", "action": f"URGENT: Remediate {critical} CRITICAL severity vulnerabilities", "timeline": "7 days"})
    if high > 0:
        actions.append({"priority": "P2", "action": f"HIGH: Schedule remediation for {high} HIGH severity vulnerabilities", "timeline": "14-30 days"})
    actions.append({"priority": "P3", "action": "Review and update IOC blocklists in SIEM/Firewall", "timeline": "This week"})
    actions.append({"priority": "P4", "action": "Brief security team on active campaign intelligence", "timeline": "This week"})
    return actions

def _next_week_date():
    from datetime import timedelta
    return (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

def main():
    log.info("="*60); log.info("EXECUTIVE INTELLIGENCE BRIEF GENERATOR v167.0"); log.info("="*60)
    for fp in [REPO_ROOT/"data"/"feed_manifest.json", REPO_ROOT/"data"/"stix"/"feed_manifest.json"]:
        if fp.exists():
            generate_brief(fp); break
    log.info("[EBG] COMPLETE"); return 0

if __name__ == "__main__": sys.exit(main())
