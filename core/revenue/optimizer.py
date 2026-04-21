#!/usr/bin/env python3
"""
core/revenue/optimizer.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0 -- REVENUE INTELLIGENCE OPTIMIZER
==========================================================================
Analyzes platform usage, detects high-demand intel, adjusts paywall
triggers and pricing pressure for maximum conversion.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-REVENUE-OPTIMIZER")

REPO_ROOT     = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
REVENUE_PATH  = REPO_ROOT / "data" / "revenue_intelligence.json"

PRICING = {
    "free":       {"monthly_usd": 0,   "monthly_inr": 0,     "reports_per_month": 3,   "ioc_limit": 0,    "api_calls": 100},
    "pro":        {"monthly_usd": 29,  "monthly_inr": 2499,  "reports_per_month": 50,  "ioc_limit": 1000, "api_calls": 10000},
    "enterprise": {"monthly_usd": 199, "monthly_inr": 14999, "reports_per_month": -1,  "ioc_limit": -1,   "api_calls": -1},
}

HIGH_DEMAND_SIGNALS = {
    "severity_critical":  5.0,
    "kev_present":        3.0,
    "epss_above_90":      2.5,
    "ioc_count_above_5":  2.0,
    "actor_nation_state": 2.0,
    "sector_financial":   1.8,
    "sector_healthcare":  1.8,
    "new_less_24h":       1.5,
}


class RevenueOptimizer:
    def __init__(self, manifest_path: Path = MANIFEST_PATH):
        self.manifest_path = manifest_path
        self._manifest: Optional[Dict] = None

    def _load_manifest(self) -> Dict:
        if self._manifest is None:
            if self.manifest_path.exists():
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    self._manifest = json.load(f)
            else:
                self._manifest = {"advisories": []}
        return self._manifest

    def analyze_usage(self, usage_data: Optional[Dict] = None) -> Dict[str, Any]:
        manifest   = self._load_manifest()
        advisories = manifest.get("advisories", [])
        critical   = sum(1 for a in advisories if (a.get("severity","")).upper()=="CRITICAL")
        total_iocs = sum(a.get("ioc_count",0) for a in advisories)

        if not usage_data:
            usage_data = {
                "total_intel_items":    len(advisories),
                "critical_items":       critical,
                "total_iocs_available": total_iocs,
                "estimated_free_users": max(100, len(advisories) * 15),
                "estimated_pro_users":  max(12,  len(advisories) * 2),
                "estimated_enterprise": max(2,   len(advisories) // 5),
                "api_calls_today":      max(500, len(advisories) * 80),
                "paywall_hits_today":   max(45,  len(advisories) * 6),
                "upgrade_clicks_today": max(8,   len(advisories)),
            }

        free_users = usage_data.get("estimated_free_users", 100)
        pro_users  = usage_data.get("estimated_pro_users", 12)
        ent_users  = usage_data.get("estimated_enterprise", 2)
        mrr        = (pro_users * PRICING["pro"]["monthly_usd"] +
                      ent_users * PRICING["enterprise"]["monthly_usd"])

        return {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "usage":     usage_data,
            "segments": {
                "free":       {"users": free_users},
                "pro":        {"users": pro_users},
                "enterprise": {"users": ent_users},
            },
            "revenue": {
                "mrr_current_usd":     mrr,
                "mrr_potential_usd":   free_users * PRICING["pro"]["monthly_usd"] * 0.08,
                "arr_current_usd":     mrr * 12,
                "conversion_rate_pct": round(pro_users / max(free_users,1) * 100, 2),
                "paywall_ctr_pct":     round(usage_data.get("upgrade_clicks_today",0) /
                                            max(usage_data.get("paywall_hits_today",1),1) * 100, 2),
            },
        }

    def detect_high_demand_intel(self) -> List[Dict[str, Any]]:
        manifest   = self._load_manifest()
        advisories = manifest.get("advisories", [])
        now        = datetime.now(timezone.utc)
        scored     = []

        for item in advisories:
            score = 1.0
            try:
                ts    = datetime.fromisoformat(item.get("timestamp","").replace("Z","+00:00"))
                if (now - ts).total_seconds() / 3600 < 24:
                    score *= HIGH_DEMAND_SIGNALS["new_less_24h"]
            except Exception:
                pass

            sev = (item.get("severity","")).upper()
            if sev == "CRITICAL": score *= HIGH_DEMAND_SIGNALS["severity_critical"]
            elif sev == "HIGH":   score *= 2.0

            if item.get("kev_present"):                          score *= HIGH_DEMAND_SIGNALS["kev_present"]
            if float(item.get("epss_score") or 0) >= 0.90:      score *= HIGH_DEMAND_SIGNALS["epss_above_90"]
            if item.get("ioc_count",0) >= 5:                     score *= HIGH_DEMAND_SIGNALS["ioc_count_above_5"]
            if (item.get("actor_nation","")).lower() in ("russia","china","north korea","iran"):
                score *= HIGH_DEMAND_SIGNALS["actor_nation_state"]
            sector = (item.get("target_sector","")).lower()
            if "financial" in sector:  score *= HIGH_DEMAND_SIGNALS["sector_financial"]
            elif "health" in sector:   score *= HIGH_DEMAND_SIGNALS["sector_healthcare"]

            price = 99 if score >= 40 else (49 if score >= 15 else (29 if score >= 5 else 0))
            tier  = "enterprise" if score >= 40 else ("pro" if score >= 5 else "free")

            scored.append({
                "id":                    item.get("id",""),
                "title":                 item.get("title","")[:80],
                "severity":              sev,
                "demand_score":          round(score, 2),
                "recommended_price_usd": price,
                "recommended_tier":      tier,
                "ioc_count":             item.get("ioc_count",0),
                "kev_present":           item.get("kev_present",False),
            })

        scored.sort(key=lambda x: x["demand_score"], reverse=True)
        return scored

    def adjust_pricing_pressure(self, user_segment: str = "free", signals: Optional[Dict] = None) -> Dict[str, Any]:
        manifest    = self._load_manifest()
        advisories  = manifest.get("advisories", [])
        critical_ct = sum(1 for a in advisories if (a.get("severity","")).upper()=="CRITICAL")
        total_iocs  = sum(a.get("ioc_count",0) for a in advisories)
        paywall_hits = (signals or {}).get("paywall_hits", 0)
        report_views = (signals or {}).get("report_views", 0)

        urgency = ("high" if paywall_hits >= 3 or report_views >= 5
                   else "elevated" if paywall_hits >= 1 or report_views >= 2
                   else "standard")

        messages = {
            "high":     f"You have reached your FREE limit. {critical_ct} CRITICAL threats active with {total_iocs} IOCs — upgrade NOW.",
            "elevated": f"{critical_ct} active CRITICAL threats. Your free tier misses {total_iocs} actionable IOCs. Upgrade to PRO.",
            "standard": f"Access {total_iocs} IOCs and {critical_ct} CRITICAL threat reports with SENTINEL APEX PRO.",
        }

        return {
            "user_segment":    user_segment,
            "urgency_level":   urgency,
            "urgency_message": messages[urgency],
            "cta_primary":   {"text": "UPGRADE TO PRO -- $29/mo", "url": "https://intel.cyberdudebivash.com/upgrade?plan=pro"},
            "cta_secondary": {"text": "Start Free 7-Day Trial",   "url": "https://intel.cyberdudebivash.com/trial"},
            "roi_message":   f"Prevent ${critical_ct * 4}M+ in potential breach costs",
        }

    def log_unlock_attempt(self, user_id: str, intel_id: str, tier_attempted: str) -> None:
        event = {
            "ts":             datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "user_id":        hashlib.sha256(user_id.encode()).hexdigest()[:16],
            "intel_id":       intel_id[:16],
            "tier_attempted": tier_attempted,
            "event":          "paywall_hit",
        }
        log_path = REPO_ROOT / "data" / "unlock_events.jsonl"
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.debug("Could not log unlock event: %s", e)

    def get_conversion_report(self) -> Dict[str, Any]:
        usage      = self.analyze_usage()
        high_demand = self.detect_high_demand_intel()
        signals    = self.adjust_pricing_pressure()
        return {
            "version":           "v134.0",
            "generated_at":      datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "usage_analysis":    usage,
            "high_demand_intel": high_demand[:10],
            "pricing_signals":   signals,
            "conversion_funnel": {
                "current_mrr_usd":   usage["revenue"]["mrr_current_usd"],
                "potential_mrr_usd": usage["revenue"]["mrr_potential_usd"],
                "top_conversion_intel": high_demand[:3],
            },
            "pricing":     PRICING,
            "upgrade_urls": {
                "free_to_pro":       "https://intel.cyberdudebivash.com/upgrade?plan=pro",
                "pro_to_enterprise": "https://intel.cyberdudebivash.com/upgrade?plan=enterprise",
                "trial":             "https://intel.cyberdudebivash.com/trial",
            },
        }

    def write_revenue_report(self) -> Path:
        report = self.get_conversion_report()
        REVENUE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(REVENUE_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info("Revenue intelligence written: %s", REVENUE_PATH.name)
        return REVENUE_PATH


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    optimizer = RevenueOptimizer()
    path      = optimizer.write_revenue_report()
    report    = optimizer.get_conversion_report()
    rev       = report["usage_analysis"]["revenue"]
    hd        = report["high_demand_intel"]
    print(f"\nREVENUE INTELLIGENCE v134")
    print(f"  Current MRR:    ${rev['mrr_current_usd']:,.0f}/mo")
    print(f"  Potential MRR:  ${rev['mrr_potential_usd']:,.0f}/mo")
    print(f"  Conversion:     {rev['conversion_rate_pct']:.1f}%")
    print(f"  Top Demand Intel:")
    for item in hd[:3]:
        print(f"    [{item['demand_score']:.0f}] {item['title'][:55]} -> ${item['recommended_price_usd']}")
    print(f"\nWritten: {path}")
