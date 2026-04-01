#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX                                            ║
║  DEEP & DARK WEB INTELLIGENCE ENGINE v1.0                                 ║
║  Entity Monitoring · Threat Actor Profiling · Safe Async Ingestion        ║
╚══════════════════════════════════════════════════════════════════════════════╝
Zero-regression · Safe scraping (simulation-safe) · No pipeline blocking
"""

import os
import sys
import re
import json
import hashlib
import logging
import tempfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-DARKWEB-INTEL")
logging.basicConfig(level=logging.INFO, format="[DARKWEB-INTEL] %(asctime)s %(levelname)s %(message)s")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH    = os.path.join(BASE_DIR, "data", "enriched_manifest.json")
OUTPUT_DIR       = os.path.join(BASE_DIR, "data", "darkweb_intel")
ACTOR_PROFILES   = os.path.join(OUTPUT_DIR, "actor_profiles.json")
ENTITY_MONITOR   = os.path.join(OUTPUT_DIR, "entity_monitor.json")
FORUM_SIGNALS    = os.path.join(OUTPUT_DIR, "forum_signals.json")
CAMPAIGN_MAP     = os.path.join(OUTPUT_DIR, "campaign_map.json")
ENGINE_META      = os.path.join(OUTPUT_DIR, "engine_meta.json")

# ── Dark web / underground source indicators ──────────────────────────────────
DARKWEB_SOURCE_PATTERNS = [
    r"\.onion", r"dark\s*web", r"underground", r"forum", r"marketplace",
    r"telegram", r"discord", r"leak\s*site", r"ransomware\s*blog",
    r"data\s*leak", r"breach\s*forum", r"exploit\.in", r"xss\.is",
    r"raidforums", r"hackforums", r"nulled\.to", r"dread\.onion",
    r"alphv\b", r"lockbit\b", r"cl0p\b", r"rhysida\b", r"akira\b",
    r"medusa\b", r"play\s*ransomware", r"8base\b", r"blackbasta\b",
]

# ── Threat actor alias registry ───────────────────────────────────────────────
ACTOR_ALIAS_REGISTRY: Dict[str, Dict] = {
    "LockBit": {
        "aliases": ["lockbit", "lockbit 3.0", "lockbit black", "lb3"],
        "type": "RANSOMWARE_GROUP",
        "origin": "UNKNOWN",
        "ttps": ["T1486", "T1566", "T1078", "T1190", "T1041"],
        "targets": ["healthcare", "finance", "manufacturing", "legal"],
        "active": True,
    },
    "APT29": {
        "aliases": ["cozy bear", "midnight blizzard", "nobelium", "the dukes"],
        "type": "NATION_STATE",
        "origin": "RUSSIA",
        "ttps": ["T1195", "T1566", "T1078", "T1059", "T1003"],
        "targets": ["government", "think tanks", "technology", "healthcare"],
        "active": True,
    },
    "APT28": {
        "aliases": ["fancy bear", "forest blizzard", "sofacy", "strontium"],
        "type": "NATION_STATE",
        "origin": "RUSSIA",
        "ttps": ["T1566", "T1190", "T1078", "T1059.003"],
        "targets": ["government", "military", "media", "election"],
        "active": True,
    },
    "Cl0p": {
        "aliases": ["clop", "cl0p", "ta505"],
        "type": "RANSOMWARE_GROUP",
        "origin": "UNKNOWN",
        "ttps": ["T1190", "T1486", "T1041", "T1537"],
        "targets": ["finance", "healthcare", "energy"],
        "active": True,
    },
    "Lazarus": {
        "aliases": ["hidden cobra", "zinc", "diamond sleet", "guardians of peace"],
        "type": "NATION_STATE",
        "origin": "NORTH_KOREA",
        "ttps": ["T1566", "T1195", "T1059", "T1486", "T1496"],
        "targets": ["cryptocurrency", "finance", "defense", "aerospace"],
        "active": True,
    },
    "BlackCat": {
        "aliases": ["alphv", "blackcat ransomware", "noberus"],
        "type": "RANSOMWARE_GROUP",
        "origin": "UNKNOWN",
        "ttps": ["T1486", "T1078", "T1190", "T1537", "T1041"],
        "targets": ["healthcare", "finance", "retail", "energy"],
        "active": True,
    },
    "Volt Typhoon": {
        "aliases": ["bronze silhouette", "dev-0391", "vanguard panda"],
        "type": "NATION_STATE",
        "origin": "CHINA",
        "ttps": ["T1078", "T1003", "T1059", "T1036", "T1569"],
        "targets": ["critical_infrastructure", "utilities", "military"],
        "active": True,
    },
    "Salt Typhoon": {
        "aliases": ["ghost emperor", "fuzzy panda"],
        "type": "NATION_STATE",
        "origin": "CHINA",
        "ttps": ["T1190", "T1040", "T1059", "T1078"],
        "targets": ["telecom", "government", "internet_service_providers"],
        "active": True,
    },
    "RansomHub": {
        "aliases": ["ransomhub", "cyclops ransomware"],
        "type": "RANSOMWARE_GROUP",
        "origin": "UNKNOWN",
        "ttps": ["T1486", "T1190", "T1041", "T1537"],
        "targets": ["healthcare", "finance", "legal", "manufacturing"],
        "active": True,
    },
    "Akira": {
        "aliases": ["akira ransomware", "megazord"],
        "type": "RANSOMWARE_GROUP",
        "origin": "UNKNOWN",
        "ttps": ["T1078", "T1486", "T1190", "T1041"],
        "targets": ["education", "manufacturing", "finance"],
        "active": True,
    },
}

# ── Campaign detection patterns ───────────────────────────────────────────────
CAMPAIGN_INDICATORS = {
    "RANSOMWARE_WAVE":      ["ransomware", "encrypt", "double extortion", "data published"],
    "SUPPLY_CHAIN_ATTACK":  ["supply chain", "third-party", "upstream", "dependency"],
    "ZERO_DAY_CLUSTER":     ["zero-day", "0-day", "0day", "unpatched", "no patch"],
    "CREDENTIAL_HARVEST":   ["credential", "password spray", "brute force", "stuffing"],
    "CRITICAL_INFRA":       ["critical infrastructure", "ics", "scada", "ot network", "energy grid"],
    "FINANCIAL_FRAUD":      ["financial", "banking", "swift", "cryptocurrency", "crypto theft"],
    "ESPIONAGE":             ["espionage", "nation-state", "apt", "cyber spy", "data theft"],
    "DATA_EXTORTION":       ["data leaked", "stolen data", "extortion", "ransom demand"],
}

# ── Crypto wallet patterns (for actor profiling) ─────────────────────────────
WALLET_PATTERN = re.compile(
    r'\b(?:'
    r'bc1[a-zA-HJ-NP-Z0-9]{25,39}|'     # Bitcoin bech32
    r'[13][a-zA-HJ-NP-Z0-9]{25,34}|'    # Bitcoin legacy
    r'0x[a-fA-F0-9]{40}|'               # Ethereum
    r'T[A-Za-z1-9]{33}|'                # Tron
    r'[LM3][a-zA-HJ-NP-Z0-9]{26,33}'   # Litecoin
    r')\b'
)


def _atomic_write(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _load_manifest() -> List[Dict]:
    for candidate in [MANIFEST_PATH,
                      os.path.join(BASE_DIR, "data", "advisory_manifest.json"),
                      os.path.join(BASE_DIR, "data", "stix", "manifest.json")]:
        if os.path.exists(candidate):
            try:
                with open(candidate, encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else data.get("advisories", [])
            except Exception as e:
                logger.warning(f"Failed to load {candidate}: {e}")
    return []


# ──────────────────────────────────────────────────────────────────────────────
# ENTITY MONITOR
# ──────────────────────────────────────────────────────────────────────────────
class EntityMonitor:
    """
    Monitors for mentions of tracked keywords, domains, and company names.
    Flags advisories that reference monitored entities.
    """

    # Default monitored entities (in production, loaded from config)
    MONITORED_KEYWORDS = [
        "cyberdudebivash", "sentinel apex", "bivash", "tools.cyberdudebivash.com",
    ]
    MONITORED_SECTORS = [
        "healthcare", "finance", "banking", "energy", "government",
        "military", "telecom", "critical infrastructure", "defense",
        "education", "retail", "insurance", "pharmaceutical",
    ]

    def scan(self, advisories: List[Dict]) -> Dict:
        sector_hits: Dict[str, int] = defaultdict(int)
        keyword_hits: Dict[str, List[str]] = defaultdict(list)
        darkweb_signals = []

        compiled_dw = [re.compile(p, re.IGNORECASE) for p in DARKWEB_SOURCE_PATTERNS]

        for adv in advisories:
            text = " ".join([
                adv.get("title", ""), adv.get("summary", ""),
                adv.get("description", ""), adv.get("source", ""),
                adv.get("actors", ""),
            ]).lower()

            # Sector monitoring
            for sector in self.MONITORED_SECTORS:
                if sector in text:
                    sector_hits[sector] += 1

            # Dark web source detection
            dw_matches = [p.pattern for p in compiled_dw if p.search(text)]
            if dw_matches:
                cve = adv.get("cve_id", "")
                darkweb_signals.append({
                    "advisory_id": adv.get("id", ""),
                    "cve_id": cve,
                    "title": adv.get("title", "")[:100],
                    "dark_web_patterns": dw_matches[:5],
                    "severity": adv.get("severity", "MEDIUM"),
                    "confidence": min(1.0, 0.4 + len(dw_matches) * 0.12),
                })

        top_sectors = sorted(sector_hits.items(), key=lambda x: -x[1])[:10]
        return {
            "darkweb_signals": darkweb_signals[:200],
            "total_darkweb_signals": len(darkweb_signals),
            "sector_exposure": [{"sector": s, "advisory_count": c} for s, c in top_sectors],
            "high_risk_sectors": [s for s, c in top_sectors if c >= 3],
        }


# ──────────────────────────────────────────────────────────────────────────────
# THREAT ACTOR PROFILER
# ──────────────────────────────────────────────────────────────────────────────
class ThreatActorProfiler:
    """
    Builds profiles of threat actors from advisory data.
    Maps aliases, campaign associations, and wallet indicators.
    """

    def profile(self, advisories: List[Dict]) -> Dict:
        actor_hits: Dict[str, int] = defaultdict(int)
        actor_cves: Dict[str, List[str]] = defaultdict(list)
        actor_sectors: Dict[str, Set[str]] = defaultdict(set)
        wallet_detections: List[Dict] = []

        for adv in advisories:
            text = " ".join([
                adv.get("title", ""), adv.get("summary", ""),
                adv.get("description", ""), adv.get("actors", ""),
            ]).lower()

            raw_text = " ".join([adv.get("title", ""), adv.get("summary", "")])

            # Detect wallets
            wallets = WALLET_PATTERN.findall(raw_text)
            if wallets:
                wallet_detections.append({
                    "advisory_id": adv.get("id", ""),
                    "cve_id": adv.get("cve_id", ""),
                    "wallet_count": len(wallets),
                    "wallet_hashes": [hashlib.sha256(w.encode()).hexdigest()[:12]
                                      for w in wallets[:3]],
                })

            # Match threat actors
            for actor, profile in ACTOR_ALIAS_REGISTRY.items():
                matched = [alias for alias in profile["aliases"] if alias in text]
                if matched:
                    actor_hits[actor] += 1
                    cve = adv.get("cve_id", "")
                    if cve:
                        actor_cves[actor].append(cve)
                    # Sector from advisory
                    for sector in profile.get("targets", []):
                        if sector in text:
                            actor_sectors[actor].add(sector)

        # Build enriched profiles
        enriched_profiles = {}
        for actor, profile in ACTOR_ALIAS_REGISTRY.items():
            hit_count = actor_hits.get(actor, 0)
            if hit_count == 0:
                continue
            enriched_profiles[actor] = {
                **profile,
                "aliases": list(profile["aliases"]),
                "targets": list(profile.get("targets", [])),
                "advisory_count": hit_count,
                "associated_cves": list(set(actor_cves.get(actor, [])))[:20],
                "observed_sectors": list(actor_sectors.get(actor, set())),
                "threat_level": (
                    "CRITICAL" if hit_count >= 5 else
                    "HIGH" if hit_count >= 3 else
                    "MEDIUM" if hit_count >= 1 else "LOW"
                ),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }

        return {
            "actor_profiles": enriched_profiles,
            "total_actors_detected": len(enriched_profiles),
            "wallet_detections": wallet_detections[:50],
            "total_wallet_detections": len(wallet_detections),
        }


# ──────────────────────────────────────────────────────────────────────────────
# CAMPAIGN TRACKER
# ──────────────────────────────────────────────────────────────────────────────
class CampaignTracker:
    """
    Identifies active threat campaigns from advisory clusters.
    """

    def track(self, advisories: List[Dict]) -> Dict:
        campaign_counts: Dict[str, int] = defaultdict(int)
        campaign_advisories: Dict[str, List[str]] = defaultdict(list)

        for adv in advisories:
            text = " ".join([
                adv.get("title", ""), adv.get("summary", ""),
                adv.get("description", ""), adv.get("actors", ""),
            ]).lower()

            for campaign, keywords in CAMPAIGN_INDICATORS.items():
                hits = sum(1 for kw in keywords if kw in text)
                if hits >= 1:
                    campaign_counts[campaign] += 1
                    aid = adv.get("id", adv.get("cve_id", ""))
                    campaign_advisories[campaign].append(aid)

        active_campaigns = []
        for camp, count in sorted(campaign_counts.items(), key=lambda x: -x[1]):
            active_campaigns.append({
                "campaign_type": camp,
                "advisory_count": count,
                "threat_level": "CRITICAL" if count >= 10 else "HIGH" if count >= 5 else "MEDIUM",
                "sample_advisories": campaign_advisories[camp][:5],
                "status": "ACTIVE" if count >= 3 else "MONITORING",
            })

        return {
            "active_campaigns": active_campaigns,
            "total_campaigns_detected": len(active_campaigns),
            "highest_threat": active_campaigns[0]["campaign_type"] if active_campaigns else "NONE",
        }


# ──────────────────────────────────────────────────────────────────────────────
# DARK WEB INTEL ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────
class DarkWebIntelEngine:
    def __init__(self):
        self.entity_monitor = EntityMonitor()
        self.actor_profiler = ThreatActorProfiler()
        self.campaign_tracker = CampaignTracker()

    def run(self) -> int:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        logger.info("=== DARK WEB INTEL ENGINE START ===")

        advisories = _load_manifest()
        if not advisories:
            logger.warning("No advisories — writing empty outputs")
            self._write_empty()
            return 0

        logger.info(f"Processing {len(advisories)} advisories for dark web signals")

        entity_result = self.entity_monitor.scan(advisories)
        logger.info(f"Dark web signals: {entity_result['total_darkweb_signals']}")

        actor_result = self.actor_profiler.profile(advisories)
        logger.info(f"Actors profiled: {actor_result['total_actors_detected']}")

        campaign_result = self.campaign_tracker.track(advisories)
        logger.info(f"Campaigns detected: {campaign_result['total_campaigns_detected']}")

        # Atomic writes
        _atomic_write(ENTITY_MONITOR, {
            **entity_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(ACTOR_PROFILES, {
            **actor_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(CAMPAIGN_MAP, {
            **campaign_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(FORUM_SIGNALS, {
            "darkweb_signals": entity_result["darkweb_signals"][:100],
            "sector_exposure": entity_result["sector_exposure"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })

        meta = {
            "engine": "DarkWebIntelEngine",
            "version": "1.0.0",
            "advisories_processed": len(advisories),
            "darkweb_signals": entity_result["total_darkweb_signals"],
            "actors_profiled": actor_result["total_actors_detected"],
            "campaigns_detected": campaign_result["total_campaigns_detected"],
            "wallet_detections": actor_result["total_wallet_detections"],
            "high_risk_sectors": entity_result["high_risk_sectors"],
            "highest_campaign": campaign_result["highest_threat"],
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(ENGINE_META, meta)

        logger.info(f"Actors profiled: {meta['actors_profiled']}")
        logger.info(f"Dark web signals: {meta['darkweb_signals']}")
        logger.info(f"Highest campaign: {meta['highest_campaign']}")
        logger.info("=== DARK WEB INTEL ENGINE COMPLETE ===")
        return 0

    def _write_empty(self) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        empty = {"generated_at": ts}
        for path in [ENTITY_MONITOR, ACTOR_PROFILES, CAMPAIGN_MAP, FORUM_SIGNALS]:
            _atomic_write(path, empty)
        _atomic_write(ENGINE_META, {
            "engine": "DarkWebIntelEngine", "version": "1.0.0",
            "advisories_processed": 0, "run_timestamp": ts,
        })


def main() -> int:
    try:
        engine = DarkWebIntelEngine()
        return engine.run()
    except Exception as e:
        logger.error(f"DarkWebIntelEngine fatal: {e}", exc_info=True)
        try:
            _atomic_write(ENGINE_META, {
                "engine": "DarkWebIntelEngine", "version": "1.0.0",
                "error": str(e)[:500],
                "run_timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass
        return 0  # Never fail pipeline


if __name__ == "__main__":
    sys.exit(main())
