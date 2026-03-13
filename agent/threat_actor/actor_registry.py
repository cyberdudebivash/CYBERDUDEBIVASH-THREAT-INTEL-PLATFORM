#!/usr/bin/env python3
"""
actor_registry.py — CyberDudeBivash SENTINEL APEX v17.0
ADVERSARY INTELLIGENCE REGISTRY

Maintains and expands the threat actor knowledge base with:
  - Extended actor profiles (beyond existing actor_matrix)
  - Actor-to-CVE mapping
  - Actor-to-campaign linking
  - Actor confidence scoring
  - Attribution confidence timeline

NON-BREAKING: Works alongside existing actor_matrix.py.
Extends, never replaces it.
"""

import json
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger("CDB-ACTOR-REGISTRY")

ACTOR_REGISTRY_PATH = "data/actor_registry.json"


class ActorRegistry:
    """
    Extended threat actor intelligence registry.
    Builds upon the existing actor_matrix.py to provide
    adversary-centric intelligence depth.
    """

    # Core actor profile database
    # Each actor entry: name, aliases, origin, motivation, tactics, ttps, sectors, activity_level
    ACTOR_PROFILES: Dict[str, Dict] = {
        "APT28": {
            "name": "APT28",
            "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Strontium"],
            "origin": "Russia",
            "sponsor": "GRU (Military Intelligence)",
            "motivation": ["espionage", "influence_operations"],
            "primary_sectors": ["government", "defense", "aerospace", "media"],
            "primary_ttps": ["T1566", "T1059.001", "T1078", "T1003"],
            "activity_level": "VERY_HIGH",
            "threat_tier": "NATION_STATE",
        },
        "APT29": {
            "name": "APT29",
            "aliases": ["Cozy Bear", "Midnight Blizzard", "Nobelium", "SVR"],
            "origin": "Russia",
            "sponsor": "SVR (Foreign Intelligence)",
            "motivation": ["espionage", "credential_theft"],
            "primary_sectors": ["government", "technology", "healthcare", "ngo"],
            "primary_ttps": ["T1078", "T1550.001", "T1566.002", "T1190"],
            "activity_level": "VERY_HIGH",
            "threat_tier": "NATION_STATE",
        },
        "APT41": {
            "name": "APT41",
            "aliases": ["Double Dragon", "Winnti", "Barium"],
            "origin": "China",
            "sponsor": "MSS (Ministry of State Security)",
            "motivation": ["espionage", "financial_gain"],
            "primary_sectors": ["technology", "healthcare", "gaming", "telecom"],
            "primary_ttps": ["T1195", "T1190", "T1059", "T1027"],
            "activity_level": "HIGH",
            "threat_tier": "NATION_STATE",
        },
        "Lazarus": {
            "name": "Lazarus Group",
            "aliases": ["Hidden Cobra", "Zinc", "Guardians of Peace"],
            "origin": "North Korea",
            "sponsor": "RGB (Reconnaissance General Bureau)",
            "motivation": ["financial_gain", "espionage", "sabotage"],
            "primary_sectors": ["financial", "cryptocurrency", "defense", "aerospace"],
            "primary_ttps": ["T1566", "T1059", "T1203", "T1486"],
            "activity_level": "HIGH",
            "threat_tier": "NATION_STATE",
        },
        "LockBit": {
            "name": "LockBit",
            "aliases": ["LockBit 3.0", "LockBit Black"],
            "origin": "Multiple",
            "sponsor": "Criminal",
            "motivation": ["financial_gain", "ransomware"],
            "primary_sectors": ["manufacturing", "government", "healthcare", "finance"],
            "primary_ttps": ["T1486", "T1490", "T1078", "T1569"],
            "activity_level": "HIGH",
            "threat_tier": "CRIMINAL",
        },
        "BlackCat": {
            "name": "BlackCat / ALPHV",
            "aliases": ["ALPHV", "Noberus"],
            "origin": "Multiple",
            "sponsor": "Criminal",
            "motivation": ["financial_gain", "ransomware"],
            "primary_sectors": ["healthcare", "finance", "energy", "legal"],
            "primary_ttps": ["T1486", "T1078", "T1210", "T1537"],
            "activity_level": "HIGH",
            "threat_tier": "CRIMINAL",
        },
        "Scattered_Spider": {
            "name": "Scattered Spider",
            "aliases": ["0ktapus", "Starfraud", "UNC3944"],
            "origin": "Multiple",
            "sponsor": "Criminal",
            "motivation": ["financial_gain", "credential_theft"],
            "primary_sectors": ["technology", "casino", "retail", "telecom"],
            "primary_ttps": ["T1566", "T1621", "T1078", "T1550"],
            "activity_level": "HIGH",
            "threat_tier": "CRIMINAL",
        },
        "Volt_Typhoon": {
            "name": "Volt Typhoon",
            "aliases": ["Bronze Silhouette", "Vanguard Panda"],
            "origin": "China",
            "sponsor": "PLA (People's Liberation Army)",
            "motivation": ["espionage", "critical_infrastructure"],
            "primary_sectors": ["critical_infrastructure", "defense", "utilities", "government"],
            "primary_ttps": ["T1190", "T1078", "T1574", "T1588"],
            "activity_level": "VERY_HIGH",
            "threat_tier": "NATION_STATE",
        },
        "REvil": {
            "name": "REvil",
            "aliases": ["Sodinokibi", "GandCrab"],
            "origin": "Russia",
            "sponsor": "Criminal",
            "motivation": ["financial_gain", "ransomware"],
            "primary_sectors": ["all"],
            "primary_ttps": ["T1486", "T1195", "T1078", "T1210"],
            "activity_level": "MEDIUM",
            "threat_tier": "CRIMINAL",
        },
    }

    def __init__(self):
        self._runtime_registry: Dict = {}
        self._load_runtime_registry()

    def _load_runtime_registry(self):
        """Load any runtime-added actor data from disk."""
        if os.path.exists(ACTOR_REGISTRY_PATH):
            try:
                with open(ACTOR_REGISTRY_PATH, "r") as f:
                    self._runtime_registry = json.load(f)
            except Exception as e:
                logger.warning(f"Actor registry load failed: {e}")
                self._runtime_registry = {}
        else:
            self._runtime_registry = {"actor_cve_map": {}, "campaign_links": {}}

    def lookup_actor(self, actor_tag: str) -> Optional[Dict]:
        """
        Look up actor profile by tag or alias.
        Returns profile dict or None.
        """
        tag_upper = actor_tag.upper().replace(" ", "_")
        # Direct match
        if tag_upper in self.ACTOR_PROFILES:
            return self.ACTOR_PROFILES[tag_upper]
        # Alias search
        for name, profile in self.ACTOR_PROFILES.items():
            aliases_upper = [a.upper().replace(" ", "_") for a in profile.get("aliases", [])]
            if tag_upper in aliases_upper:
                return profile
        return None

    def map_cve_to_actor(self, cve_id: str, actor_tag: str, confidence: float = 0.7):
        """
        Record a CVE-to-actor attribution mapping.
        Non-destructive: adds to existing mappings.
        """
        if "actor_cve_map" not in self._runtime_registry:
            self._runtime_registry["actor_cve_map"] = {}
        if cve_id not in self._runtime_registry["actor_cve_map"]:
            self._runtime_registry["actor_cve_map"][cve_id] = []
        self._runtime_registry["actor_cve_map"][cve_id].append({
            "actor": actor_tag,
            "confidence": confidence,
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        })
        self._persist()

    def get_actor_threat_tier(self, actor_tag: str) -> str:
        """Return threat tier: NATION_STATE / CRIMINAL / HACKTIVIST / UNKNOWN."""
        profile = self.lookup_actor(actor_tag)
        if profile:
            return profile.get("threat_tier", "UNKNOWN")
        return "UNKNOWN"

    def get_enriched_attribution(self, actor_tag: str) -> Dict:
        """
        Return enriched attribution data for a given actor tag.
        Used to supplement existing actor_matrix.py output.
        """
        profile = self.lookup_actor(actor_tag)
        if not profile:
            return {
                "extended_profile": False,
                "threat_tier": "UNKNOWN",
                "origin": "Unknown",
                "motivation": [],
            }
        return {
            "extended_profile": True,
            "name": profile["name"],
            "aliases": profile.get("aliases", []),
            "origin": profile.get("origin", "Unknown"),
            "sponsor": profile.get("sponsor", "Unknown"),
            "motivation": profile.get("motivation", []),
            "primary_sectors": profile.get("primary_sectors", []),
            "primary_ttps": profile.get("primary_ttps", []),
            "activity_level": profile.get("activity_level", "UNKNOWN"),
            "threat_tier": profile.get("threat_tier", "UNKNOWN"),
        }

    def get_all_actor_names(self) -> List[str]:
        """Return all known actor names and aliases for text matching."""
        names = list(self.ACTOR_PROFILES.keys())
        for profile in self.ACTOR_PROFILES.values():
            names.extend(profile.get("aliases", []))
        return names

    def _persist(self):
        """Persist runtime registry to disk."""
        try:
            os.makedirs("data", exist_ok=True)
            with open(ACTOR_REGISTRY_PATH, "w") as f:
                json.dump(self._runtime_registry, f, indent=2)
        except Exception as e:
            logger.warning(f"Actor registry persist failed: {e}")


# Singleton instance
actor_registry = ActorRegistry()
