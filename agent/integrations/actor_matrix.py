#!/usr/bin/env python3
"""
actor_matrix.py — CyberDudeBivash v12.0 (SENTINEL APEX ULTRA)
EXPANDED: 10+ threat actor profiles with keyword-based attribution
covering APTs, FIN groups, and common threat categories.
"""


class ActorMatrix:
    def __init__(self):
        self.actor_db = {
            "CDB-APT-22": {
                "alias": ["Volt Typhoon", "Vanguard Panda", "Bronze Silhouette"],
                "origin": "East Asia",
                "motivation": "Critical Infrastructure Espionage",
                "tooling": ["Living-off-the-land", "KV-Botnet", "LOTL"],
                "confidence_score": "High (Telemetry Correlated)",
                "keywords": ["volt typhoon", "critical infrastructure", "living off the land"],
            },
            "CDB-FIN-09": {
                "alias": ["Lazarus", "Hidden Cobra", "Zinc", "Diamond Sleet"],
                "origin": "North Korea",
                "motivation": "Financial Gain / Espionage",
                "tooling": ["FastCash", "AppleJeus", "TraderTraitor"],
                "confidence_score": "High (OSINT Correlated)",
                "keywords": ["lazarus", "hidden cobra", "cryptocurrency theft", "north korea"],
            },
            "CDB-APT-28": {
                "alias": ["Fancy Bear", "APT28", "Strontium", "Forest Blizzard"],
                "origin": "Russia",
                "motivation": "Political Espionage / Disruption",
                "tooling": ["X-Agent", "Zebrocy", "Drovorub"],
                "confidence_score": "High",
                "keywords": ["fancy bear", "apt28", "gru", "forest blizzard"],
            },
            "CDB-APT-41": {
                "alias": ["Double Dragon", "APT41", "Barium", "Brass Typhoon"],
                "origin": "China",
                "motivation": "Espionage + Financial Crime",
                "tooling": ["ShadowPad", "Winnti", "KEYPLUG"],
                "confidence_score": "High",
                "keywords": ["apt41", "double dragon", "winnti", "shadowpad"],
            },
            "CDB-FIN-11": {
                "alias": ["Cl0p", "TA505", "FIN11"],
                "origin": "Eastern Europe",
                "motivation": "Ransomware / Extortion",
                "tooling": ["Cl0p Ransomware", "MOVEit", "GoAnywhere"],
                "confidence_score": "High",
                "keywords": ["cl0p", "clop", "ta505", "moveit", "fin11"],
            },
            "CDB-RAN-01": {
                "alias": ["LockBit", "LockBit 3.0"],
                "origin": "Eastern Europe / Russia",
                "motivation": "Ransomware-as-a-Service",
                "tooling": ["LockBit Ransomware", "StealBit"],
                "confidence_score": "High",
                "keywords": ["lockbit", "lock bit"],
            },
            "CDB-RAN-02": {
                "alias": ["BlackCat", "ALPHV", "Noberus"],
                "origin": "Eastern Europe",
                "motivation": "Ransomware / Double Extortion",
                "tooling": ["BlackCat Ransomware (Rust)", "ExMatter"],
                "confidence_score": "High",
                "keywords": ["blackcat", "alphv", "noberus"],
            },
            "CDB-FIN-07": {
                "alias": ["ShinyHunters"],
                "origin": "Unknown / Multi-National",
                "motivation": "Data Theft / Sale",
                "tooling": ["Custom scrapers", "API exploitation"],
                "confidence_score": "Medium",
                "keywords": ["shinyhunters", "shiny hunters", "data marketplace"],
            },
            "CDB-APT-29": {
                "alias": ["Cozy Bear", "APT29", "Nobelium", "Midnight Blizzard"],
                "origin": "Russia",
                "motivation": "Intelligence Collection",
                "tooling": ["EnvyScout", "SUNBURST", "FoggyWeb"],
                "confidence_score": "High",
                "keywords": ["cozy bear", "apt29", "nobelium", "midnight blizzard", "solarwinds"],
            },
            "CDB-FIN-12": {
                "alias": ["Scattered Spider", "UNC3944", "Octo Tempest", "0ktapus", "Oktapus"],
                "origin": "US / UK / Multi-National",
                "motivation": "Financial Gain / Identity Compromise / SIM Swapping",
                "tooling": ["Social Engineering", "SIM Swap", "MFA Fatigue", "Okta Phishing Kits"],
                "confidence_score": "Medium-High",
                "keywords": ["scattered spider", "octo tempest", "sim swap", "mfa fatigue",
                             "0ktapus", "oktapus", "unc3944", "okta phishing", "okta identity",
                             "mfa bypass", "mfa codes"],
            },
        }

    def correlate_actor(self, corpus, iocs):
        """
        Identifies the likely actor cluster based on infrastructure,
        aliases, keywords, and tooling matches.
        """
        corpus_lower = corpus.lower()

        best_match = None
        best_score = 0

        for tracking_id, profile in self.actor_db.items():
            score = 0

            # Check alias matches (strongest signal)
            for alias in profile.get('alias', []):
                if alias.lower() in corpus_lower:
                    score += 3

            # Check keyword matches
            for kw in profile.get('keywords', []):
                if kw in corpus_lower:
                    score += 2

            # Check tooling matches
            for tool in profile.get('tooling', []):
                if tool.lower() in corpus_lower:
                    score += 1

            if score > best_score:
                best_score = score
                best_match = (tracking_id, profile)

        if best_match and best_score >= 2:
            return {
                "tracking_id": best_match[0],
                "profile": best_match[1],
            }

        # Default for unknown clusters
        return {
            "tracking_id": "UNC-CDB-99",
            "profile": {
                "alias": ["Unknown Cluster"],
                "origin": "Under Investigation",
                "motivation": "Under Analysis",
                "tooling": ["Under Analysis"],
                "confidence_score": "Low",
            }
        }


actor_matrix = ActorMatrix()
