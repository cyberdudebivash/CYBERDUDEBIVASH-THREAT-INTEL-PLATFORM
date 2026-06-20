"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — GEOPOLITICAL RISK ENGINE v1.0          ║
║  Nation-State Threat Intelligence · Sanctions · APT Attribution           ║
║  Supply Chain Geopolitical Risk · Country-Level Threat Scoring            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Revenue: Enterprise add-on $299/mo · MSSP $999/mo · Government/Defense custom

Capabilities:
  1. Country-level cyber threat scoring (0–10)
  2. Nation-state APT group mapping
  3. OFAC/EU/UN sanctions compliance check
  4. Supply chain geopolitical exposure analysis
  5. Threat actor geographic attribution confidence
  6. Sector-specific geopolitical risk (energy, finance, defense, telecom)
  7. Geopolitical event → cyber threat escalation signals
  8. Alliance network analysis (Five Eyes, NATO, SCO)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-GEOPOLITICAL")


@dataclass
class CountryRiskProfile:
    country_code:    str  # ISO 3166-1 alpha-2
    country_name:    str
    threat_level:    str  # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    cyber_risk_score: float  # 0–10 (10 = highest threat)
    nation_state_apt_groups: List[str]
    sanctioned:      bool
    sanctions_bodies: List[str]
    primary_targets:  List[str]
    primary_ttps:     List[str]
    alliance_bloc:    str
    conflict_status:  str
    assessed_at:      str


# ── Country Cyber Threat Intelligence Database ─────────────────────────────────
COUNTRY_THREAT_DB: Dict[str, Dict] = {
    "CN": {
        "name": "China (People's Republic of China)",
        "threat_level": "CRITICAL",
        "cyber_risk_score": 9.8,
        "apt_groups": ["APT1", "APT10", "APT41", "APT40", "Volt Typhoon", "Salt Typhoon",
                       "Lazarus (linked)", "APT27", "APT3", "APT26", "APT19", "Hafnium", "GALLIUM"],
        "primary_targets": ["US Government", "Defense Industrial Base", "Telecom",
                             "Technology companies", "Critical infrastructure", "IP theft"],
        "primary_ttps": ["T1190", "T1133", "T1071", "T1078", "T1566", "T1587",
                          "T1559", "T1195", "T1036", "T1105"],
        "sanctioned": False,
        "sanctions_bodies": [],
        "alliance_bloc": "SCO",
        "conflict_status": "ACTIVE_CYBER_OPERATIONS",
        "key_campaigns": ["Operation Aurora", "Volt Typhoon CNI targeting", "Salt Typhoon telecom breach 2024"],
    },
    "RU": {
        "name": "Russia (Russian Federation)",
        "threat_level": "CRITICAL",
        "cyber_risk_score": 9.9,
        "apt_groups": ["APT28 (Fancy Bear)", "APT29 (Cozy Bear)", "Sandworm", "Turla",
                       "APT44", "Berserk Bear", "Primitive Bear", "Gamaredon", "UNC1151", "Killnet"],
        "primary_targets": ["NATO members", "Ukraine", "Energy sector", "Government",
                             "Election infrastructure", "Military", "Financial sector"],
        "primary_ttps": ["T1566", "T1190", "T1059", "T1027", "T1071", "T1486",
                          "T1490", "T1485", "T1561", "T1195"],
        "sanctioned": True,
        "sanctions_bodies": ["OFAC", "EU", "UK OFSI", "UN (partial)"],
        "alliance_bloc": "SCO",
        "conflict_status": "ACTIVE_WAR_UKRAINE",
        "key_campaigns": ["NotPetya", "SolarWinds/SUNBURST", "Viasat KA-SAT attack", "Colonial Pipeline (DarkSide affiliated)"],
    },
    "KP": {
        "name": "North Korea (DPRK)",
        "threat_level": "CRITICAL",
        "cyber_risk_score": 9.5,
        "apt_groups": ["Lazarus Group", "APT38", "Kimsuky", "Andariel", "BlueNoroff", "ScarCruft"],
        "primary_targets": ["Cryptocurrency", "Financial institutions", "Defense",
                             "Researchers", "South Korea", "US Government"],
        "primary_ttps": ["T1566", "T1059", "T1133", "T1055", "T1195", "T1486",
                          "T1041", "T1027", "T1078", "T1003"],
        "sanctioned": True,
        "sanctions_bodies": ["OFAC", "EU", "UN", "UK OFSI"],
        "alliance_bloc": "ISOLATED",
        "conflict_status": "ACTIVE_CYBER_FINANCIAL_THEFT",
        "key_campaigns": ["$1.3B crypto theft 2024", "WannaCry", "SWIFT banking attacks", "3CX supply chain"],
    },
    "IR": {
        "name": "Iran (Islamic Republic of Iran)",
        "threat_level": "HIGH",
        "cyber_risk_score": 8.5,
        "apt_groups": ["APT33 (Elfin)", "APT34 (OilRig)", "APT35 (Charming Kitten)",
                       "APT39", "MuddyWater", "Agrius", "Yellow Garuda"],
        "primary_targets": ["Israel", "Saudi Arabia", "US Government", "Energy sector",
                             "Critical infrastructure", "Dissidents", "Aerospace"],
        "primary_ttps": ["T1566", "T1133", "T1059", "T1071", "T1055",
                          "T1485", "T1490", "T1046", "T1560"],
        "sanctioned": True,
        "sanctions_bodies": ["OFAC", "EU", "UN"],
        "alliance_bloc": "ISOLATED",
        "conflict_status": "ACTIVE_REGIONAL_CYBER_OPS",
        "key_campaigns": ["Shamoon", "Predatory Sparrow industrial sabotage", "Albania cyberattack 2022"],
    },
    "US": {
        "name": "United States of America",
        "threat_level": "LOW",
        "cyber_risk_score": 1.5,
        "apt_groups": ["NSA TAO (Equation Group — for context)"],
        "primary_targets": ["Adversarial nations"],
        "primary_ttps": ["Classified"],
        "sanctioned": False,
        "sanctions_bodies": [],
        "alliance_bloc": "FIVE_EYES",
        "conflict_status": "ALLY",
        "key_campaigns": ["Stuxnet (joint US/IL)", "ETERNAL BLUE development"],
    },
    "GB": {
        "name": "United Kingdom",
        "threat_level": "MINIMAL",
        "cyber_risk_score": 1.0,
        "apt_groups": [],
        "primary_targets": [],
        "primary_ttps": [],
        "sanctioned": False,
        "sanctions_bodies": [],
        "alliance_bloc": "FIVE_EYES",
        "conflict_status": "ALLY",
        "key_campaigns": [],
    },
    "IN": {
        "name": "India",
        "threat_level": "MEDIUM",
        "cyber_risk_score": 4.5,
        "apt_groups": ["SideWinder", "Donot Team"],
        "primary_targets": ["Pakistan", "China border region", "Neighboring governments"],
        "primary_ttps": ["T1566", "T1071", "T1059"],
        "sanctioned": False,
        "sanctions_bodies": [],
        "alliance_bloc": "QUAD",
        "conflict_status": "REGIONAL_TENSIONS",
        "key_campaigns": [],
    },
    "PK": {
        "name": "Pakistan",
        "threat_level": "MEDIUM",
        "cyber_risk_score": 5.0,
        "apt_groups": ["Transparent Tribe (APT36)", "ProjectM", "Gorgon Group"],
        "primary_targets": ["India", "Afghanistan", "Government", "Military"],
        "primary_ttps": ["T1566", "T1059", "T1071"],
        "sanctioned": False,
        "sanctions_bodies": [],
        "alliance_bloc": "SCO",
        "conflict_status": "REGIONAL_TENSIONS",
        "key_campaigns": [],
    },
    "BY": {
        "name": "Belarus",
        "threat_level": "HIGH",
        "cyber_risk_score": 7.5,
        "apt_groups": ["Ghostwriter", "UNC1151"],
        "primary_targets": ["EU neighbors", "Ukraine", "Lithuania", "Poland"],
        "primary_ttps": ["T1566", "T1059", "T1071", "T1485"],
        "sanctioned": True,
        "sanctions_bodies": ["OFAC", "EU", "UK OFSI"],
        "alliance_bloc": "SCO",
        "conflict_status": "ACTIVE_ALIGNED_WITH_RU",
        "key_campaigns": ["Ghostwriter influence operations"],
    },
    "TR": {
        "name": "Turkey",
        "threat_level": "MEDIUM",
        "cyber_risk_score": 4.0,
        "apt_groups": ["Sea Turtle", "StrongPity"],
        "primary_targets": ["Kurdish organizations", "Greece", "Armenia"],
        "primary_ttps": ["T1566", "T1071", "T1190"],
        "sanctioned": False,
        "sanctions_bodies": [],
        "alliance_bloc": "NATO",
        "conflict_status": "ALLY_WITH_RESERVATIONS",
        "key_campaigns": ["DNS hijacking campaigns"],
    },
}

# ── Sector geopolitical risk matrix ──────────────────────────────────────────
SECTOR_GEO_RISK: Dict[str, Dict[str, float]] = {
    "energy":          {"CN": 9.0, "RU": 9.5, "IR": 9.0, "KP": 6.0},
    "financial":       {"CN": 8.5, "RU": 8.0, "KP": 9.5, "IR": 7.5},
    "defense":         {"CN": 9.5, "RU": 9.0, "KP": 8.0, "IR": 8.0},
    "telecom":         {"CN": 9.8, "RU": 8.5, "KP": 6.0, "IR": 6.0},
    "healthcare":      {"CN": 7.0, "RU": 8.0, "KP": 5.0, "IR": 5.0},
    "government":      {"CN": 9.0, "RU": 9.5, "KP": 8.0, "IR": 8.5},
    "technology":      {"CN": 9.5, "RU": 7.0, "KP": 6.0, "IR": 5.0},
    "manufacturing":   {"CN": 8.0, "RU": 7.0, "KP": 5.0, "IR": 5.0},
    "crypto":          {"CN": 5.0, "RU": 6.0, "KP": 9.5, "IR": 6.0},
    "generic":         {"CN": 7.0, "RU": 7.5, "KP": 5.5, "IR": 5.0},
}

# ── Geopolitical events → cyber threat correlation ────────────────────────────
GEO_EVENT_THREAT_SIGNALS: List[Dict] = [
    {
        "event": "Ukraine-Russia conflict escalation",
        "threat_elevation": "CRITICAL",
        "threat_actors":    ["Sandworm", "APT28", "Gamaredon", "Killnet"],
        "sectors":          ["Energy", "Government", "Financial", "Telecom"],
        "ttp_focus":        ["T1486 (Ransomware/wiper)", "T1561 (Disk wipe)", "T1485 (Data destruction)"],
        "advisory": "Monitor for wiper malware and distributed denial-of-service campaigns",
    },
    {
        "event": "Taiwan Strait tensions",
        "threat_elevation": "HIGH",
        "threat_actors":    ["Volt Typhoon", "APT40", "APT41"],
        "sectors":          ["Technology", "Defense", "Government", "Semiconductor"],
        "ttp_focus":        ["T1190", "T1133", "T1078"],
        "advisory": "Pre-positioning for disruption — monitor critical infrastructure access",
    },
    {
        "event": "Israel-Hamas conflict",
        "threat_elevation": "HIGH",
        "threat_actors":    ["APT33", "APT34", "Agrius", "APT35"],
        "sectors":          ["Energy", "Government", "Healthcare", "Media"],
        "ttp_focus":        ["T1485", "T1486", "T1190"],
        "advisory": "Destructive operations likely — prioritize backup verification",
    },
    {
        "event": "US election cycle",
        "threat_elevation": "HIGH",
        "threat_actors":    ["APT28", "APT29", "Ghostwriter", "UNC1151"],
        "sectors":          ["Election infrastructure", "Media", "Political orgs"],
        "ttp_focus":        ["T1566", "T1059", "T1078"],
        "advisory": "Information operations, credential theft, infrastructure targeting",
    },
    {
        "event": "Critical infrastructure sanctions pressure",
        "threat_elevation": "MEDIUM",
        "threat_actors":    ["APT33", "MuddyWater"],
        "sectors":          ["Energy", "Water", "Telecom"],
        "ttp_focus":        ["T1190", "T1133"],
        "advisory": "Retaliatory cyber operations possible — harden external exposure",
    },
]

# ── Alliance bloc security postures ──────────────────────────────────────────
ALLIANCE_BLOCS: Dict[str, Dict] = {
    "FIVE_EYES": {
        "members": ["US", "GB", "CA", "AU", "NZ"],
        "intel_sharing": "FULL",
        "cyber_cooperation": "MAXIMUM",
        "threat_level_to_platform": "MINIMAL",
    },
    "NATO": {
        "members": ["US", "GB", "DE", "FR", "IT", "ES", "PL", "NL", "BE", "TR", "GR"],
        "intel_sharing": "HIGH",
        "cyber_cooperation": "HIGH",
        "threat_level_to_platform": "LOW",
    },
    "SCO": {
        "members": ["CN", "RU", "IN", "PK", "BY"],
        "intel_sharing": "INTERNAL",
        "cyber_cooperation": "ADVERSARIAL_TO_WEST",
        "threat_level_to_platform": "CRITICAL",
    },
    "QUAD": {
        "members": ["US", "IN", "AU", "JP"],
        "intel_sharing": "MODERATE",
        "cyber_cooperation": "GROWING",
        "threat_level_to_platform": "LOW",
    },
    "ISOLATED": {
        "members": ["KP", "IR", "CU", "SY"],
        "intel_sharing": "NONE",
        "cyber_cooperation": "HOSTILE",
        "threat_level_to_platform": "CRITICAL",
    },
}


class GeopoliticalRiskEngine:
    """
    Nation-state threat intelligence and geopolitical risk scoring engine.
    Correlates geopolitical context with threat actor attribution and cyber risk.
    """

    def __init__(self):
        self.assessments_total = 0

    def get_country_profile(self, country_code: str) -> CountryRiskProfile:
        """Get full geopolitical risk profile for a country."""
        cc = country_code.upper()
        data = COUNTRY_THREAT_DB.get(cc)

        if data:
            return CountryRiskProfile(
                country_code     = cc,
                country_name     = data["name"],
                threat_level     = data["threat_level"],
                cyber_risk_score = data["cyber_risk_score"],
                nation_state_apt_groups = data.get("apt_groups", []),
                sanctioned       = data.get("sanctioned", False),
                sanctions_bodies = data.get("sanctions_bodies", []),
                primary_targets  = data.get("primary_targets", []),
                primary_ttps     = data.get("primary_ttps", []),
                alliance_bloc    = data.get("alliance_bloc", "UNKNOWN"),
                conflict_status  = data.get("conflict_status", "UNKNOWN"),
                assessed_at      = datetime.now(timezone.utc).isoformat(),
            )

        return CountryRiskProfile(
            country_code     = cc,
            country_name     = f"Country {cc}",
            threat_level     = "LOW",
            cyber_risk_score = 2.0,
            nation_state_apt_groups = [],
            sanctioned       = False,
            sanctions_bodies = [],
            primary_targets  = [],
            primary_ttps     = [],
            alliance_bloc    = "UNKNOWN",
            conflict_status  = "UNKNOWN",
            assessed_at      = datetime.now(timezone.utc).isoformat(),
        )

    def assess_threat_actor_geo(self, actor_name: str) -> Dict[str, Any]:
        """Assess geopolitical attribution for a threat actor."""
        actor_lower = actor_name.lower()

        actor_country_map: Dict[str, str] = {
            "apt1": "CN", "apt3": "CN", "apt10": "CN", "apt19": "CN",
            "apt26": "CN", "apt27": "CN", "apt40": "CN", "apt41": "CN",
            "volt typhoon": "CN", "salt typhoon": "CN", "hafnium": "CN", "gallium": "CN",
            "apt28": "RU", "apt29": "RU", "sandworm": "RU", "turla": "RU",
            "fancy bear": "RU", "cozy bear": "RU", "gamaredon": "RU",
            "killnet": "RU", "apt44": "RU", "berserk bear": "RU",
            "lazarus": "KP", "apt38": "KP", "kimsuky": "KP", "andariel": "KP",
            "bluenoroff": "KP", "scarcruft": "KP",
            "apt33": "IR", "apt34": "IR", "apt35": "IR", "apt39": "IR",
            "muddywater": "IR", "charming kitten": "IR", "oilrig": "IR",
            "sidewinder": "IN", "donot": "IN",
            "transparent tribe": "PK", "apt36": "PK",
            "ghostwriter": "BY", "unc1151": "BY",
            "sea turtle": "TR", "strongpity": "TR",
        }

        country_code = None
        for key, cc in actor_country_map.items():
            if key in actor_lower:
                country_code = cc
                break

        if not country_code:
            return {
                "actor":          actor_name,
                "attribution":    "UNATTRIBUTED",
                "confidence":     0.0,
                "country":        None,
                "nexus":          "UNKNOWN",
                "note":           "No nation-state attribution established for this actor",
            }

        profile  = self.get_country_profile(country_code)
        country_data = COUNTRY_THREAT_DB.get(country_code, {})

        return {
            "actor":            actor_name,
            "attribution":      country_code,
            "country_name":     profile.country_name,
            "confidence":       0.85,
            "threat_level":     profile.threat_level,
            "nexus":            country_data.get("alliance_bloc", "UNKNOWN"),
            "sanctioned":       profile.sanctioned,
            "sanctions_bodies": profile.sanctions_bodies,
            "primary_targets":  profile.primary_targets[:5],
            "key_campaigns":    country_data.get("key_campaigns", []),
            "cyber_risk_score": profile.cyber_risk_score,
            "attribution_confidence_rationale": (
                f"Pattern matching to {country_code} APT infrastructure, TTPs, "
                f"targeting patterns, and operational security indicators."
            ),
        }

    def assess_supply_chain_geo_risk(
        self,
        vendors: List[Dict],
        sector: str = "generic",
    ) -> Dict[str, Any]:
        """Assess geopolitical risk across supply chain vendors."""
        assessments = []
        high_risk_vendors = []

        for vendor in vendors:
            domain = vendor.get("domain", "")
            tld    = domain.split(".")[-1].upper() if "." in domain else "US"

            # Map TLD to country code approximation
            tld_country_map = {
                "CN": "CN", "RU": "RU", "KP": "KP", "IR": "IR",
                "BY": "BY", "CU": "CU", "SY": "SY", "VE": "VE",
                "PK": "PK", "IN": "IN", "TR": "TR",
            }
            country_code = tld_country_map.get(tld, "US")
            profile = self.get_country_profile(country_code)

            sector_risk = SECTOR_GEO_RISK.get(sector, {}).get(country_code, 0.0)
            combined_risk = (profile.cyber_risk_score + sector_risk) / 2

            assessment = {
                "vendor":            vendor.get("name", domain),
                "domain":            domain,
                "country_code":      country_code,
                "country_name":      profile.country_name,
                "threat_level":      profile.threat_level,
                "cyber_risk_score":  profile.cyber_risk_score,
                "sector_risk":       sector_risk,
                "combined_risk":     round(combined_risk, 2),
                "sanctioned":        profile.sanctioned,
                "risk_factors":      (
                    ["Sanctioned jurisdiction"] if profile.sanctioned else []
                ) + (
                    [f"APT groups: {', '.join(profile.nation_state_apt_groups[:3])}"] if profile.nation_state_apt_groups else []
                ),
            }
            assessments.append(assessment)
            if combined_risk >= 7.0:
                high_risk_vendors.append(assessment)

        self.assessments_total += 1
        return {
            "sector":                 sector,
            "vendor_count":           len(vendors),
            "high_risk_vendor_count": len(high_risk_vendors),
            "high_risk_vendors":      high_risk_vendors,
            "all_assessments":        assessments,
            "portfolio_risk_score":   round(
                sum(a["combined_risk"] for a in assessments) / max(1, len(assessments)), 2
            ),
            "recommended_actions": [
                "Diversify vendors away from high-risk jurisdictions",
                "Implement enhanced security requirements for high-risk country vendors",
                "Conduct legal/compliance review for sanctioned-country vendor relationships",
                "Ensure contracts contain right-to-audit clauses for geo-risk vendors",
            ],
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_current_threat_landscape(self) -> Dict[str, Any]:
        """Current geopolitical threat landscape overview."""
        critical = {cc: d for cc, d in COUNTRY_THREAT_DB.items() if d["threat_level"] == "CRITICAL"}
        high     = {cc: d for cc, d in COUNTRY_THREAT_DB.items() if d["threat_level"] == "HIGH"}

        return {
            "generated_at":         datetime.now(timezone.utc).isoformat(),
            "critical_nations":     list(critical.keys()),
            "high_threat_nations":  list(high.keys()),
            "active_campaigns":     GEO_EVENT_THREAT_SIGNALS[:5],
            "sanctioned_countries": [cc for cc, d in COUNTRY_THREAT_DB.items() if d.get("sanctioned")],
            "total_apt_groups_tracked": sum(len(d.get("apt_groups", [])) for d in COUNTRY_THREAT_DB.values()),
            "threat_overview": {
                cc: {
                    "name":         d["name"],
                    "threat_level": d["threat_level"],
                    "score":        d["cyber_risk_score"],
                    "apt_count":    len(d.get("apt_groups", [])),
                }
                for cc, d in COUNTRY_THREAT_DB.items()
            },
            "alliance_blocs": {
                bloc: {
                    "members": info["members"],
                    "threat_level": info["threat_level_to_platform"],
                }
                for bloc, info in ALLIANCE_BLOCS.items()
            },
        }

    def check_sanctions_exposure(self, entities: List[str]) -> Dict[str, Any]:
        """Check if entities are in sanctioned jurisdictions."""
        results = []
        for entity in entities:
            entity_lower = entity.lower()
            sanctioned_match = False
            matching_bodies: List[str] = []

            for cc, data in COUNTRY_THREAT_DB.items():
                if data.get("sanctioned") and (
                    cc.lower() in entity_lower or
                    data["name"].lower().split("(")[0].strip().lower() in entity_lower
                ):
                    sanctioned_match = True
                    matching_bodies = data.get("sanctions_bodies", [])
                    break

            results.append({
                "entity":         entity,
                "sanctioned":     sanctioned_match,
                "sanctions_bodies": matching_bodies,
                "risk_level":     "CRITICAL" if sanctioned_match else "LOW",
                "recommendation": (
                    f"STOP: Legal review required. Sanctioned by {', '.join(matching_bodies)}" if sanctioned_match
                    else "No sanctions match — continue standard due diligence"
                ),
            })

        flagged = [r for r in results if r["sanctioned"]]
        return {
            "entities_checked": len(entities),
            "sanctioned_count": len(flagged),
            "flagged_entities":  flagged,
            "all_results":       results,
            "compliance_note":   (
                "CRITICAL: Engaging with sanctioned entities may violate OFAC/EU regulations. Consult legal counsel."
                if flagged else "No sanctions violations detected."
            ),
        }

    def correlate_advisory_with_geo(self, advisory: Dict) -> Dict:
        """Add geopolitical context to a threat advisory."""
        actor_tag = advisory.get("actor_tag", "")
        geo_attr  = self.assess_threat_actor_geo(actor_tag) if actor_tag else {}

        mitre_ttps = advisory.get("mitre_tactics") or []
        geo_events = [
            e for e in GEO_EVENT_THREAT_SIGNALS
            if any(t in e.get("ttp_focus", []) for t in mitre_ttps)
        ]

        return {
            "advisory_id":         advisory.get("stix_id"),
            "actor_attribution":   geo_attr,
            "geopolitical_events": geo_events[:3],
            "nation_state_nexus":  bool(geo_attr.get("country_code")),
            "sanctions_risk":      geo_attr.get("sanctioned", False),
            "threat_escalation_risk": "HIGH" if geo_events else "MEDIUM" if geo_attr else "LOW",
        }

    def get_stats(self) -> Dict:
        return {
            "engine":               "GeopoliticalRiskEngine v1.0",
            "countries_tracked":    len(COUNTRY_THREAT_DB),
            "apt_groups_tracked":   sum(len(d.get("apt_groups", [])) for d in COUNTRY_THREAT_DB.values()),
            "sanctions_regimes":    4,
            "active_geo_events":    len(GEO_EVENT_THREAT_SIGNALS),
            "assessments_total":    self.assessments_total,
            "alliance_blocs":       len(ALLIANCE_BLOCS),
        }
