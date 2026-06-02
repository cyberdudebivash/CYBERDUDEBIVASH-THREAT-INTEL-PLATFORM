#!/usr/bin/env python3
"""
SENTINEL APEX v167.0 — CAMPAIGN INTELLIGENCE ENGINE
=====================================================
Phase 2 of Enterprise CTI Transformation.

Correlates isolated advisories into attributed campaign clusters,
maintains campaign timelines, and generates campaign intelligence reports.

Storage:
  data/campaigns/{campaign_id}/report.json   — campaign report
  data/campaigns/_index.json                 — campaign index
  data/health/campaign_correlation_report.json
"""

from __future__ import annotations
import json, re, math, hashlib, logging, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger("CAMPAIGN-INTEL-ENGINE")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

REPO_ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_DIR = REPO_ROOT / "data" / "campaigns"
CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_dt(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# BASELINE CAMPAIGN LIBRARY
# ─────────────────────────────────────────────────────────────────────────────

CAMPAIGN_LIBRARY: dict[str, dict] = {
    "VOLT-TYPHOON-CI-2023": {
        "campaign_id": "VOLT-TYPHOON-CI-2023",
        "campaign_name": "Volt Typhoon Critical Infrastructure Pre-positioning",
        "attributed_actor": "VOLT-TYPHOON",
        "start_date": "2021-06-01T00:00:00Z",
        "end_date": None,
        "status": "ACTIVE",
        "targeted_sectors": ["Critical_Infrastructure", "Defense", "Energy", "Water", "Communications"],
        "targeted_countries": ["US", "GUAM"],
        "malware_used": ["KV-Botnet", "LOLBAS"],
        "ttps": ["T1190", "T1505.003", "T1133", "T1078", "T1021.001", "T1016"],
        "risk_score": 9.5,
        "confidence": 91,
        "keywords": ["volt typhoon", "living off the land", "lotl", "ics targeting", "guam", "critical infrastructure"],
        "sector_keywords": ["critical infrastructure", "power grid", "water", "communications", "military base"],
        "narrative": "Chinese MSS pre-positioning within US critical infrastructure for potential disruption capability during geopolitical crisis. Focuses exclusively on living-off-the-land techniques to evade detection.",
        "stix_id": "campaign--ef55b7f0-c3e7-4f37-9fc8-b15d4c5f1a2e",
    },
    "SOLARWINDS-SUNBURST-2020": {
        "campaign_id": "SOLARWINDS-SUNBURST-2020",
        "campaign_name": "SolarWinds SUNBURST Supply Chain Attack",
        "attributed_actor": "APT29",
        "start_date": "2019-10-01T00:00:00Z",
        "end_date": "2021-06-01T00:00:00Z",
        "status": "CONCLUDED",
        "targeted_sectors": ["Government", "Technology", "Defense", "Think_Tanks"],
        "targeted_countries": ["US", "EU"],
        "malware_used": ["SUNBURST", "SUNSPOT", "TEARDROP", "GoldMax"],
        "ttps": ["T1195.002", "T1078", "T1059.001", "T1036", "T1027"],
        "risk_score": 10.0,
        "confidence": 95,
        "keywords": ["solarwinds", "sunburst", "orion", "supply chain", "nobelium"],
        "sector_keywords": ["solarwinds", "supply chain", "government", "cloud", "mssp"],
        "narrative": "Sophisticated supply chain compromise of SolarWinds Orion platform affecting 18,000+ organizations. APT29 implanted SUNBURST backdoor into legitimate updates for ~9 months before discovery.",
        "stix_id": "campaign--a4d6aa45-0f73-4b13-9fbb-d8f2e81a2c3d",
    },
    "LOCKBIT-3-GLOBAL": {
        "campaign_id": "LOCKBIT-3-GLOBAL",
        "campaign_name": "LockBit 3.0 Global Ransomware Campaign",
        "attributed_actor": "LOCKBIT",
        "start_date": "2022-06-01T00:00:00Z",
        "end_date": None,
        "status": "MONITORING",
        "targeted_sectors": ["ALL_SECTORS"],
        "targeted_countries": ["GLOBAL"],
        "malware_used": ["LockBit 3.0", "StealBit"],
        "ttps": ["T1566", "T1190", "T1078", "T1486", "T1490", "T1489"],
        "risk_score": 9.0,
        "confidence": 85,
        "keywords": ["lockbit", "lockbit 3.0", "lockbit black", "ransomware", "double extortion"],
        "sector_keywords": ["hospital", "manufacturing", "law firm", "government", "bank"],
        "narrative": "World's most prolific ransomware group with 1,700+ confirmed victims. Operates RaaS model recruiting affiliates. Law enforcement disruption Feb 2024 (Operation Cronos) but remnants remain active.",
        "stix_id": "campaign--7e4d2f91-bb42-4c2b-b8a3-f9c7d5e2a8b1",
    },
    "SCATTERED-SPIDER-TELECOM": {
        "campaign_id": "SCATTERED-SPIDER-TELECOM",
        "campaign_name": "Scattered Spider Telecom and Tech Targeting",
        "attributed_actor": "SCATTERED-SPIDER",
        "start_date": "2022-01-01T00:00:00Z",
        "end_date": None,
        "status": "ACTIVE",
        "targeted_sectors": ["Technology", "Gaming", "Telecommunications", "Finance"],
        "targeted_countries": ["US", "EU"],
        "malware_used": ["BlackCat/ALPHV", "Cobalt Strike"],
        "ttps": ["T1621", "T1556", "T1078", "T1204.001", "T1534"],
        "risk_score": 8.5,
        "confidence": 80,
        "keywords": ["scattered spider", "oktapus", "mgm", "caesars", "sim swap", "mfa bypass", "twilio", "okta"],
        "sector_keywords": ["okta", "mfa", "sms phishing", "sim swap", "telecom"],
        "narrative": "English-speaking criminal group (likely 18-25 years old) using sophisticated social engineering to bypass MFA. Responsible for MGM Resorts and Caesars attacks causing $100M+ losses.",
        "stix_id": "campaign--3b8e4f72-cc53-4d18-a9f5-b2c8d4e7f1a3",
    },
    "LAZARUS-CRYPTO-HEIST": {
        "campaign_id": "LAZARUS-CRYPTO-HEIST",
        "campaign_name": "Lazarus Group Cryptocurrency Theft Operations",
        "attributed_actor": "LAZARUS",
        "start_date": "2017-01-01T00:00:00Z",
        "end_date": None,
        "status": "ACTIVE",
        "targeted_sectors": ["Cryptocurrency", "Finance", "DeFi", "Blockchain"],
        "targeted_countries": ["US", "KR", "JP", "EU", "GLOBAL"],
        "malware_used": ["AppleJeus", "FASTCash", "BLINDINGCAN"],
        "ttps": ["T1566", "T1195", "T1059.001", "T1078", "T1105"],
        "risk_score": 9.5,
        "confidence": 90,
        "keywords": ["lazarus", "hidden cobra", "crypto theft", "defi hack", "blockchain", "ronin", "bybit", "harmony"],
        "sector_keywords": ["cryptocurrency", "defi", "blockchain", "exchange", "wallet", "bridge"],
        "narrative": "DPRK state-sponsored cryptocurrency theft to fund weapons programs. $3B+ stolen since 2017. Responsible for Ronin/Axie Infinity ($625M), Bybit ($1.5B 2025), and 100+ other DeFi exploits.",
        "stix_id": "campaign--c2f7e3a8-5d91-4b2c-8e6f-a9c4b5d8e2f7",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# CAMPAIGN CORRELATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CampaignCorrelationEngine:
    """Correlates advisories with known campaigns using multi-signal scoring."""

    WEIGHTS = {
        "keyword": 0.35,
        "sector": 0.20,
        "ttp": 0.20,
        "actor": 0.15,
        "malware": 0.10,
    }
    THRESHOLD = 0.40

    def __init__(self):
        self.campaigns = CAMPAIGN_LIBRARY

    def correlate(self, item: dict) -> list[dict]:
        """Returns list of matching campaigns sorted by confidence."""
        results = []
        text = self._get_text(item)
        item_actor = (item.get("threat_actor") or {}).get("actor_id", "")
        item_ttps = set(item.get("tags", []))

        for cid, campaign in self.campaigns.items():
            score, signals = self._score_campaign(text, item_ttps, item_actor, campaign)
            if score >= self.THRESHOLD:
                results.append({
                    "campaign_id": cid,
                    "campaign_name": campaign["campaign_name"],
                    "score": round(score, 3),
                    "confidence": min(round(score * 100), 100),
                    "signals": signals,
                    "status": campaign["status"],
                    "attributed_actor": campaign["attributed_actor"],
                    "risk_score": campaign["risk_score"],
                })

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results[:2]

    def _get_text(self, item: dict) -> str:
        return " ".join(filter(None, [
            str(item.get("title", "")),
            str(item.get("description", "")),
            str(item.get("threat_type", "")),
            " ".join(item.get("tags", [])),
        ])).lower()

    def _score_campaign(self, text: str, item_ttps: set, item_actor: str, campaign: dict) -> tuple[float, list]:
        score = 0.0
        signals = []

        # Keyword matching
        for kw in campaign.get("keywords", []):
            if kw.lower() in text:
                score += self.WEIGHTS["keyword"]
                signals.append(f"keyword:{kw}")
                break

        # Sector keyword matching
        for sk in campaign.get("sector_keywords", []):
            if sk.lower() in text:
                score += self.WEIGHTS["sector"]
                signals.append(f"sector:{sk}")
                break

        # TTP overlap
        campaign_ttps = set(campaign.get("ttps", []))
        overlap = item_ttps & campaign_ttps
        if overlap:
            ttp_score = self.WEIGHTS["ttp"] * min(len(overlap) / max(len(campaign_ttps), 1), 1.0)
            score += ttp_score
            signals.append(f"ttp_overlap:{len(overlap)}")

        # Actor match
        if item_actor and item_actor == campaign.get("attributed_actor"):
            score += self.WEIGHTS["actor"]
            signals.append(f"actor_match:{item_actor}")

        return min(score, 1.0), signals


# ─────────────────────────────────────────────────────────────────────────────
# CAMPAIGN MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class CampaignManager:
    """Manages campaign profiles and correlates feed items."""

    def __init__(self):
        self.engine = CampaignCorrelationEngine()

    def bootstrap_all(self) -> int:
        saved = 0
        for cid, campaign in CAMPAIGN_LIBRARY.items():
            self._save_campaign(cid, campaign)
            saved += 1
        self._write_index()
        log.info("[CIE] Bootstrapped %d campaign profiles", saved)
        return saved

    def _save_campaign(self, cid: str, campaign: dict) -> None:
        campaign_path = CAMPAIGN_DIR / cid
        campaign_path.mkdir(parents=True, exist_ok=True)
        full = {**campaign, "updated_at": utc_now(), "schema_version": "v2.0"}
        (campaign_path / "report.json").write_text(
            json.dumps(full, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _write_index(self) -> None:
        index = {
            "generated_at": utc_now(),
            "total_campaigns": len(CAMPAIGN_LIBRARY),
            "active_campaigns": sum(1 for c in CAMPAIGN_LIBRARY.values() if c["status"] == "ACTIVE"),
            "campaigns": [
                {
                    "campaign_id": cid,
                    "campaign_name": c["campaign_name"],
                    "status": c["status"],
                    "attributed_actor": c["attributed_actor"],
                    "risk_score": c["risk_score"],
                    "confidence": c["confidence"],
                    "profile_url": f"/api/v2/campaigns/{cid}",
                }
                for cid, c in CAMPAIGN_LIBRARY.items()
            ],
        }
        (CAMPAIGN_DIR / "_index.json").write_text(
            json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def correlate_feed(self, feed_path: Path) -> dict:
        try:
            raw = json.loads(feed_path.read_text(encoding="utf-8"))
        except Exception as e:
            return {"error": str(e)}

        items = raw if isinstance(raw, list) else raw.get("advisories", raw.get("items", []))
        correlated = 0
        report_items = []

        for item in items:
            matches = self.engine.correlate(item)
            if matches:
                item["campaign_intelligence"] = {
                    "primary_campaign": matches[0]["campaign_id"],
                    "campaign_name": matches[0]["campaign_name"],
                    "confidence": matches[0]["confidence"],
                    "signals": matches[0]["signals"],
                    "all_matches": matches,
                }
                correlated += 1
                report_items.append({
                    "id": item.get("id"),
                    "campaign": matches[0]["campaign_id"],
                    "confidence": matches[0]["confidence"],
                })
            else:
                item.setdefault("campaign_intelligence", {"primary_campaign": None, "confidence": 0})

        if isinstance(raw, list):
            output = items
        else:
            raw["advisories"] = items
            output = raw

        feed_path.write_text(json.dumps(output, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

        report = {
            "generated_at": utc_now(),
            "total_items": len(items),
            "correlated": correlated,
            "correlation_rate_pct": round(correlated / max(len(items), 1) * 100, 1),
            "top_campaigns": self._top_campaigns(report_items),
        }

        (REPO_ROOT / "data" / "health" / "campaign_correlation_report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        return report

    def _top_campaigns(self, items: list) -> list:
        counts: dict[str, int] = {}
        for i in items:
            counts[i["campaign"]] = counts.get(i["campaign"], 0) + 1
        return [{"campaign_id": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])][:5]


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX v167.0 — CAMPAIGN INTELLIGENCE ENGINE")
    log.info("=" * 60)

    manager = CampaignManager()
    manager.bootstrap_all()

    for fp in [REPO_ROOT / "data" / "feed_manifest.json", REPO_ROOT / "data" / "stix" / "feed_manifest.json"]:
        if fp.exists():
            report = manager.correlate_feed(fp)
            log.info("[CIE] Correlated %d/%d items (%.1f%%)",
                     report.get("correlated", 0), report.get("total_items", 0),
                     report.get("correlation_rate_pct", 0))

    log.info("[CIE] COMPLETE")
    return 0

if __name__ == "__main__":
    sys.exit(main())
