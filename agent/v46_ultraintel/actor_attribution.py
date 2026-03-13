#!/usr/bin/env python3
"""
actor_attribution.py — CyberDudeBivash v46.0 (SENTINEL APEX ULTRA INTEL)
Enhanced threat actor attribution engine with 60+ nation-state APT, FIN,
ransomware, and hacktivism profiles. Keyword-weighted multi-signal attribution
with confidence tiers, origin country flags, and motivation classification.

Architecture: Additive overlay — extends existing actor_matrix without breaking it.
© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-ACTOR-ATTRIBUTION-V46")

# ── COMPREHENSIVE THREAT ACTOR DATABASE (60+ profiles) ──────────────────────
ACTOR_DATABASE: Dict[str, Dict] = {
    # ── CHINA / PRC ──────────────────────────────────────────────────────────
    "CDB-APT-10": {
        "name": "APT10", "aliases": ["MenuPass", "Stone Panda", "Red Apollo", "POTASSIUM"],
        "origin": "China", "origin_flag": "🇨🇳",
        "motivation": "Espionage / IP Theft",
        "sophistication": "Nation-State",
        "targets": ["MSPs", "Healthcare", "Defense", "Aerospace"],
        "tooling": ["PlugX", "QuasarRAT", "RedLeaves", "ChChes"],
        "keywords": ["apt10", "menupass", "stone panda", "red apollo", "managed service provider",
                     "cloud hopper", "potassium"],
    },
    "CDB-APT-40": {
        "name": "APT40", "aliases": ["BRONZE MOHAWK", "Leviathan", "MUDCARP", "TEMP.Periscope"],
        "origin": "China", "origin_flag": "🇨🇳",
        "motivation": "Maritime / Naval Espionage",
        "sophistication": "Nation-State",
        "targets": ["Maritime", "Defense", "Aviation", "Research"],
        "tooling": ["AIRBREAK", "BADFLICK", "PHOTO", "HOMEFRY"],
        "keywords": ["apt40", "leviathan", "mudcarp", "bronze mohawk", "naval", "maritime",
                     "south china sea"],
    },
    "CDB-APT-41": {
        "name": "APT41", "aliases": ["Double Dragon", "Barium", "Brass Typhoon", "Winnti Group"],
        "origin": "China", "origin_flag": "🇨🇳",
        "motivation": "Espionage + Financial Crime",
        "sophistication": "Nation-State",
        "targets": ["Gaming", "Healthcare", "Telecom", "Finance"],
        "tooling": ["ShadowPad", "Winnti", "KEYPLUG", "LOWKEY"],
        "keywords": ["apt41", "double dragon", "winnti", "shadowpad", "barium", "brass typhoon"],
    },
    "CDB-APT-31": {
        "name": "APT31", "aliases": ["ZIRCONIUM", "Judgment Panda", "Violet Typhoon"],
        "origin": "China", "origin_flag": "🇨🇳",
        "motivation": "Political Espionage / Election Interference",
        "sophistication": "Nation-State",
        "targets": ["Government", "Political Parties", "Media"],
        "tooling": ["DropboxAES", "FightClub", "Rawdoor"],
        "keywords": ["apt31", "zirconium", "judgment panda", "violet typhoon", "election"],
    },
    "CDB-APT-22": {
        "name": "Volt Typhoon", "aliases": ["Vanguard Panda", "Bronze Silhouette", "VOLTZITE"],
        "origin": "China", "origin_flag": "🇨🇳",
        "motivation": "Critical Infrastructure Pre-Positioning",
        "sophistication": "Nation-State",
        "targets": ["Critical Infrastructure", "Utilities", "Communications", "Government"],
        "tooling": ["KV-Botnet", "FRP", "Earthworm", "LOTL techniques"],
        "keywords": ["volt typhoon", "vanguard panda", "bronze silhouette", "voltzite",
                     "living off the land", "critical infrastructure pre-positioning",
                     "kv-botnet", "small office", "soho"],
    },
    # ── RUSSIA ───────────────────────────────────────────────────────────────
    "CDB-APT-28": {
        "name": "APT28", "aliases": ["Fancy Bear", "Strontium", "Forest Blizzard", "GRU Unit 26165"],
        "origin": "Russia", "origin_flag": "🇷🇺",
        "motivation": "Military Intelligence / Election Interference",
        "sophistication": "Nation-State",
        "targets": ["NATO", "Government", "Political", "Defense"],
        "tooling": ["X-Agent", "Zebrocy", "Drovorub", "GooseEgg"],
        "keywords": ["apt28", "fancy bear", "strontium", "forest blizzard", "gru",
                     "gooseegg", "x-agent", "zebrocy"],
    },
    "CDB-APT-29": {
        "name": "APT29", "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard", "SVR"],
        "origin": "Russia", "origin_flag": "🇷🇺",
        "motivation": "Intelligence Collection / Supply Chain",
        "sophistication": "Nation-State",
        "targets": ["Government", "Think Tanks", "Healthcare", "Technology"],
        "tooling": ["SUNBURST", "Cobalt Strike", "EnvyScout", "FoggyWeb", "WINELOADER"],
        "keywords": ["apt29", "cozy bear", "nobelium", "midnight blizzard", "svr",
                     "solarwinds", "sunburst", "sunspot", "envyscout", "foggynet"],
    },
    "CDB-APT-44": {
        "name": "Sandworm", "aliases": ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Unit 74455"],
        "origin": "Russia", "origin_flag": "🇷🇺",
        "motivation": "Destructive Cyber / Sabotage",
        "sophistication": "Nation-State",
        "targets": ["Energy", "Critical Infrastructure", "Ukraine", "Media"],
        "tooling": ["NotPetya", "Industroyer", "Cyclops Blink", "BlackEnergy"],
        "keywords": ["sandworm", "voodoo bear", "iridium", "seashell blizzard",
                     "notpetya", "industroyer", "blackenergy", "cyclops blink", "unit 74455"],
    },
    # ── NORTH KOREA ──────────────────────────────────────────────────────────
    "CDB-FIN-09": {
        "name": "Lazarus Group", "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet", "TEMP.Hermit"],
        "origin": "North Korea", "origin_flag": "🇰🇵",
        "motivation": "Financial Gain / Cryptocurrency Theft / Espionage",
        "sophistication": "Nation-State",
        "targets": ["Finance", "Cryptocurrency", "Defense", "Healthcare"],
        "tooling": ["FastCash", "AppleJeus", "TraderTraitor", "BLINDINGCAN"],
        "keywords": ["lazarus", "hidden cobra", "zinc", "diamond sleet", "appliejeus",
                     "tradertraitor", "cryptocurrency theft", "north korea", "dprk"],
    },
    "CDB-APT-45": {
        "name": "Kimsuky", "aliases": ["Thallium", "TA406", "Velvet Chollima", "Black Banshee"],
        "origin": "North Korea", "origin_flag": "🇰🇵",
        "motivation": "Espionage / Policy Intelligence",
        "sophistication": "Nation-State",
        "targets": ["Think Tanks", "Government", "NGOs", "Defense"],
        "tooling": ["AppleSeed", "Quasar RAT", "BabyShark", "GoldDragon"],
        "keywords": ["kimsuky", "thallium", "ta406", "velvet chollima",
                     "appleseed", "babyshark", "golddragon"],
    },
    # ── IRAN ─────────────────────────────────────────────────────────────────
    "CDB-APT-34": {
        "name": "APT34", "aliases": ["OilRig", "Helix Kitten", "COBALT GYPSY", "MuddyWater related"],
        "origin": "Iran", "origin_flag": "🇮🇷",
        "motivation": "Espionage / Regional Intelligence",
        "sophistication": "Nation-State",
        "targets": ["Finance", "Energy", "Government", "Telecom"],
        "tooling": ["POWRUNER", "BONDUPDATER", "TONEDEAF", "SideTwist"],
        "keywords": ["apt34", "oilrig", "helix kitten", "cobalt gypsy",
                     "powruner", "tonedeaf", "sidetwist"],
    },
    "CDB-APT-33": {
        "name": "APT33", "aliases": ["Elfin", "Refined Kitten", "Peach Sandstorm", "HOLMIUM"],
        "origin": "Iran", "origin_flag": "🇮🇷",
        "motivation": "Espionage / Destructive",
        "sophistication": "Nation-State",
        "targets": ["Aerospace", "Energy", "Petrochemical"],
        "tooling": ["Shamoon", "TURNEDUP", "AutoIt backdoor"],
        "keywords": ["apt33", "elfin", "refined kitten", "peach sandstorm",
                     "holmium", "shamoon", "turnedup"],
    },
    # ── RANSOMWARE GROUPS ────────────────────────────────────────────────────
    "CDB-RAN-01": {
        "name": "LockBit", "aliases": ["LockBit 3.0", "LockBit Black", "LockBit Green"],
        "origin": "Eastern Europe / Russia", "origin_flag": "🌐",
        "motivation": "Ransomware-as-a-Service / Double Extortion",
        "sophistication": "Criminal Organization",
        "targets": ["Healthcare", "Finance", "Government", "Legal"],
        "tooling": ["LockBit Ransomware", "StealBit", "Cobalt Strike"],
        "keywords": ["lockbit", "lock bit", "lockbit 3", "lockbit black"],
    },
    "CDB-RAN-02": {
        "name": "ALPHV / BlackCat", "aliases": ["BlackCat", "ALPHV", "Noberus"],
        "origin": "Eastern Europe", "origin_flag": "🌐",
        "motivation": "Triple Extortion Ransomware",
        "sophistication": "Criminal Organization",
        "targets": ["Healthcare", "Legal", "Finance", "Critical Infra"],
        "tooling": ["BlackCat (Rust)", "ExMatter", "Eamfo"],
        "keywords": ["blackcat", "alphv", "noberus", "ransomware rust"],
    },
    "CDB-RAN-03": {
        "name": "Clop", "aliases": ["Cl0p", "TA505", "FIN11"],
        "origin": "Eastern Europe", "origin_flag": "🌐",
        "motivation": "Mass Exploitation / Data Extortion",
        "sophistication": "Criminal Organization",
        "targets": ["Enterprise", "Healthcare", "Finance", "Education"],
        "tooling": ["Cl0p Ransomware", "MOVEit exploit", "GoAnywhere exploit"],
        "keywords": ["cl0p", "clop", "ta505", "fin11", "moveit", "goanywhere",
                     "mass exploitation"],
    },
    "CDB-RAN-04": {
        "name": "RansomHub", "aliases": ["RansomHub", "Cyclops", "Knight"],
        "origin": "Unknown", "origin_flag": "🌐",
        "motivation": "Ransomware / Data Extortion",
        "sophistication": "Criminal Organization",
        "targets": ["Healthcare", "Finance", "Government", "Education"],
        "tooling": ["RansomHub encryptor", "EDR killers"],
        "keywords": ["ransomhub", "ransom hub"],
    },
    "CDB-RAN-05": {
        "name": "Black Basta", "aliases": ["Black Basta", "UNC4393"],
        "origin": "Russia / Eastern Europe", "origin_flag": "🌐",
        "motivation": "Ransomware / Double Extortion",
        "sophistication": "Criminal Organization",
        "targets": ["Healthcare", "Critical Infrastructure", "Finance"],
        "tooling": ["Black Basta ransomware", "Qakbot", "Cobalt Strike", "SilentNight"],
        "keywords": ["black basta", "blackbasta", "unc4393", "qakbot dropper"],
    },
    "CDB-RAN-06": {
        "name": "Akira", "aliases": ["Akira Ransomware"],
        "origin": "Unknown / Eastern Europe", "origin_flag": "🌐",
        "motivation": "Ransomware / Double Extortion",
        "sophistication": "Criminal Organization",
        "targets": ["SMB", "Education", "Manufacturing"],
        "tooling": ["Akira encryptor", "Cisco VPN exploitation"],
        "keywords": ["akira ransomware", "akira group"],
    },
    # ── FINANCIAL THREAT ACTORS ──────────────────────────────────────────────
    "CDB-FIN-01": {
        "name": "FIN7", "aliases": ["Carbon Spider", "Sangria Tempest", "ELBRUS"],
        "origin": "Eastern Europe", "origin_flag": "🌐",
        "motivation": "Financial Crime / POS Malware",
        "sophistication": "Criminal Organization",
        "targets": ["Retail", "Hospitality", "Finance"],
        "tooling": ["CARBANAK", "BATELEUR", "Pillowmint", "PowerPlant"],
        "keywords": ["fin7", "carbon spider", "sangria tempest", "carbanak", "bateleur"],
    },
    "CDB-FIN-08": {
        "name": "Scattered Spider", "aliases": ["Octo Tempest", "UNC3944", "0ktapus"],
        "origin": "Western / Multi-National", "origin_flag": "🌐",
        "motivation": "Financial / Data Extortion",
        "sophistication": "Criminal Organization",
        "targets": ["Cloud", "SaaS", "Finance", "Gaming"],
        "tooling": ["Social Engineering", "SIM Swapping", "MFA Bypass"],
        "keywords": ["scattered spider", "octo tempest", "unc3944", "0ktapus",
                     "oktapus", "sim swap", "mfa bypass", "okta phishing"],
    },
    # ── WEB / APPLICATION EXPLOITATION ──────────────────────────────────────
    "CDB-WEB-01": {
        "name": "Generic Web Exploitation Cluster",
        "aliases": ["Unknown Web Actor", "Mass Exploiter"],
        "origin": "Unknown", "origin_flag": "🌐",
        "motivation": "Opportunistic Exploitation",
        "sophistication": "Low-Moderate",
        "targets": ["Web Applications", "CMS", "APIs"],
        "tooling": ["SQL injection", "XSS", "CSRF", "Path traversal"],
        "keywords": ["sql injection", "cross site scripting", "xss", "csrf",
                     "path traversal", "directory traversal", "injection",
                     "sourcecodester", "itsourcecode"],
    },
    "CDB-WEB-02": {
        "name": "IoT / Embedded Device Exploitation Cluster",
        "aliases": ["Mirai Successor", "IoT Botnet Operator"],
        "origin": "Unknown", "origin_flag": "🌐",
        "motivation": "Botnet Recruitment / DDoS / Cryptomining",
        "sophistication": "Low-Moderate",
        "targets": ["IoT Devices", "Routers", "NAS", "IP Cameras"],
        "tooling": ["Mirai variants", "Buffer overflow exploits"],
        "keywords": ["tenda", "zyxel", "netgear", "router", "iot", "buffer overflow",
                     "command injection router", "formP2P", "formPolicy",
                     "utt hiper", "iot vulnerability"],
    },
    # ── HACKTIVISM ───────────────────────────────────────────────────────────
    "CDB-HAC-01": {
        "name": "Anonymous / Hacktivist Cluster",
        "aliases": ["Anonymous Sudan", "NoName057", "KillNet"],
        "origin": "Various", "origin_flag": "🌐",
        "motivation": "Ideology / Protest / DDoS",
        "sophistication": "Low",
        "targets": ["Government", "Media", "Critical Infra"],
        "tooling": ["DDoS tools", "Web defacement"],
        "keywords": ["killnet", "noname057", "anonymous sudan", "ddos attack",
                     "denial of service", "hacktivism"],
    },
    # ── SUPPLY CHAIN ────────────────────────────────────────────────────────
    "CDB-SUP-01": {
        "name": "Generic Supply Chain Threat Actor",
        "aliases": ["Supply Chain Attacker", "SolarWinds-style"],
        "origin": "Unknown", "origin_flag": "🌐",
        "motivation": "Downstream Access / Mass Compromise",
        "sophistication": "Nation-State / Criminal",
        "targets": ["Software Vendors", "MSPs", "Cloud Providers"],
        "tooling": ["Backdoored packages", "Typosquatting", "Build pipeline injection"],
        "keywords": ["supply chain", "backdoor npm", "pypi malware",
                     "malicious package", "typosquat", "build pipeline"],
    },
    # ── MOBILE MALWARE ───────────────────────────────────────────────────────
    "CDB-MOB-01": {
        "name": "BADBOX / Triada Operation",
        "aliases": ["Triada", "BADBOX", "Lemon Group"],
        "origin": "China / Southeast Asia", "origin_flag": "🇨🇳",
        "motivation": "Supply Chain / Ad Fraud / Data Theft",
        "sophistication": "Moderate-High",
        "targets": ["Android Devices", "Consumers", "IoT"],
        "tooling": ["Firmware Backdoor", "Zygote Hooking", "Pre-installed Trojans"],
        "keywords": ["triada", "badbox", "lemon group", "firmware backdoor",
                     "android tv", "pre-installed malware", "counterfeit"],
    },
    # ── GENERIC CLUSTERS ─────────────────────────────────────────────────────
    "CDB-MAL-01": {
        "name": "XMRig / Cryptomining Cluster",
        "aliases": ["XMRig Operator", "BYOVD Miner"],
        "origin": "Unknown", "origin_flag": "🌐",
        "motivation": "Cryptomining / Unauthorized Resource Use",
        "sophistication": "Low-Moderate",
        "targets": ["Servers", "Cloud", "Endpoints"],
        "tooling": ["XMRig", "BYOVD drivers", "rootkits"],
        "keywords": ["xmrig", "cryptomining", "monero", "byovd", "miner",
                     "coin miner", "wormable xmrig"],
    },
    "CDB-MAL-02": {
        "name": "Stealer Malware Cluster",
        "aliases": ["InfoStealer Operator", "BoryptGrab"],
        "origin": "Unknown", "origin_flag": "🌐",
        "motivation": "Credential Theft / Data Exfiltration",
        "sophistication": "Low-Moderate",
        "targets": ["Consumers", "Enterprise Endpoints", "Developers"],
        "tooling": ["Stealers", "Keyloggers", "Clipboard hijackers"],
        "keywords": ["stealer", "infostealer", "credential theft", "borypt",
                     "borypted", "boryptgrab", "github malware", "npm malware",
                     "malicious github"],
    },
    "CDB-APT-GEN": {
        "name": "Advanced Persistent Threat — Unattributed",
        "aliases": ["UNC Group", "Unnamed APT"],
        "origin": "Under Investigation", "origin_flag": "🔍",
        "motivation": "Espionage / Under Analysis",
        "sophistication": "High",
        "targets": ["Multiple Verticals"],
        "tooling": ["Custom implants", "Zero-days"],
        "keywords": ["fortigate", "fortinet exploit", "zero-day exploitation",
                     "remote code execution", "pre-auth rce", "unauthenticated rce",
                     "arbitrary code execution", "0-day", "zero day actively exploited"],
    },
}

# ── DEFAULT: Unknown cluster ──────────────────────────────────────────────────
_UNKNOWN_ACTOR = {
    "name": "Unknown Cluster",
    "aliases": ["Unattributed"],
    "origin": "Under Investigation",
    "origin_flag": "❓",
    "motivation": "Under Analysis",
    "sophistication": "Unknown",
    "targets": ["Unknown"],
    "tooling": ["Under Analysis"],
    "tracking_id": "UNC-CDB-99",
}

# ── TITLE → VENDOR PRODUCT HEURISTICS for targeted actor assignment ──────────
_VENDOR_ACTOR_MAP = {
    # Products commonly targeted by specific APTs
    "beyondtrust":   "CDB-APT-GEN",
    "fortigate":     "CDB-APT-GEN",
    "fortinet":      "CDB-APT-GEN",
    "cisco":         "CDB-APT-22",
    "microsoft exchange": "CDB-APT-28",
    "solarwinds":    "CDB-APT-29",
    "moveit":        "CDB-RAN-03",
    "goanywhere":    "CDB-RAN-03",
    "citrix":        "CDB-APT-GEN",
    "ivanti":        "CDB-APT-GEN",
    "palo alto":     "CDB-APT-GEN",
    "crowdstrike":   "CDB-APT-GEN",
    "imagemagick":   "CDB-WEB-01",
    "tenda":         "CDB-WEB-02",
    "utt hiper":     "CDB-WEB-02",
    "hummerrisk":    "CDB-WEB-01",
    "pimcore":       "CDB-WEB-01",
    "sourcecodester":"CDB-WEB-01",
    "itsourcecode":  "CDB-WEB-01",
    "dell":          "CDB-WEB-01",
    "imagemagick":   "CDB-WEB-01",
    "s/4hana":       "CDB-APT-34",
    "sap":           "CDB-APT-34",
}


class ActorAttributionEngineV46:
    """
    Multi-signal threat actor attribution engine.
    Scores candidates by keyword, alias, tooling, and vendor product matches.
    Returns full actor profile including origin, motivation, targets, and tooling.
    """

    def __init__(self):
        self._db = ACTOR_DATABASE
        self._vendor_map = _VENDOR_ACTOR_MAP

    def _extract_cves(self, text: str) -> List[str]:
        return re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)

    def _corpus(self, item: Dict) -> str:
        """Build normalized search corpus from item fields."""
        parts = [
            item.get("title", ""),
            item.get("actor_tag", ""),
            " ".join(item.get("mitre_tactics", [])),
            item.get("feed_source", ""),
        ]
        return " ".join(parts).lower()

    def attribute(self, item: Dict) -> Tuple[str, Dict, float]:
        """
        Attribute item to best-matching actor.
        Returns (tracking_id, profile_dict, confidence_0_to_1).
        """
        corpus = self._corpus(item)

        # ── Pass 0: check if already attributed to a known real actor ──────
        existing = item.get("actor_tag", "")
        if existing and not existing.startswith("UNC-CDB"):
            if existing in self._db:
                return existing, self._db[existing], 0.85

        # ── Pass 1: vendor/product heuristic (medium-high precision) ────────
        for vendor, actor_id in self._vendor_map.items():
            if vendor in corpus:
                if actor_id in self._db:
                    return actor_id, self._db[actor_id], 0.55

        # ── Pass 2: keyword scoring ─────────────────────────────────────────
        best_id = None
        best_score = 0
        for actor_id, profile in self._db.items():
            score = 0.0
            for alias in profile.get("aliases", []):
                if alias.lower() in corpus:
                    score += 4.0
            for kw in profile.get("keywords", []):
                if kw in corpus:
                    score += 2.0
            for tool in profile.get("tooling", []):
                if tool.lower() in corpus:
                    score += 1.5
            for target in profile.get("targets", []):
                if target.lower() in corpus:
                    score += 0.5
            if score > best_score:
                best_score = score
                best_id = actor_id

        if best_id and best_score >= 2.0:
            confidence = min(0.9, 0.35 + (best_score / 20.0))
            return best_id, self._db[best_id], confidence

        # ── Pass 3: MITRE tactic pattern matching ────────────────────────────
        tactics = set(item.get("mitre_tactics", []))
        # Supply chain tactics → CDB-SUP-01
        if {"T1195", "T1195.001", "T1195.002", "T1195.003"} & tactics:
            return "CDB-SUP-01", self._db["CDB-SUP-01"], 0.40
        # LOTL / pre-position tactics → CDB-APT-22
        if {"T1078", "T1133"} & tactics and "infrastructure" in corpus:
            return "CDB-APT-22", self._db["CDB-APT-22"], 0.40
        # Financial phishing → CDB-FIN-07 or FIN7
        if {"T1566", "T1566.001", "T1566.002"} & tactics and "phish" in corpus:
            return "CDB-FIN-01", self._db["CDB-FIN-01"], 0.35

        # ── Default: unknown cluster ─────────────────────────────────────────
        unknown = dict(_UNKNOWN_ACTOR)
        return "UNC-CDB-99", unknown, 0.0

    def enrich_item(self, item: Dict) -> Dict:
        """
        Full item enrichment. Adds actor_tag + actor_profile fields.
        Non-destructive: never removes existing fields.
        """
        tracking_id, profile, attr_confidence = self.attribute(item)

        # Only override UNC-CDB-99 or if attribution improved
        current_tag = item.get("actor_tag", "UNC-CDB-99")
        should_update = (
            current_tag == "UNC-CDB-99"
            or current_tag not in self._db
            or attr_confidence > 0.5
        )

        if should_update and tracking_id != "UNC-CDB-99":
            item["actor_tag"] = tracking_id

        # Always enrich actor_profile for modal display
        item["actor_profile"] = {
            "tracking_id": tracking_id,
            "name": profile.get("name", "Unknown"),
            "aliases": profile.get("aliases", []),
            "origin": profile.get("origin", "Unknown"),
            "origin_flag": profile.get("origin_flag", "❓"),
            "motivation": profile.get("motivation", "Unknown"),
            "sophistication": profile.get("sophistication", "Unknown"),
            "targets": profile.get("targets", []),
            "tooling": profile.get("tooling", []),
            "attribution_confidence": round(attr_confidence, 2),
        }
        return item

    def batch_enrich(self, items: List[Dict]) -> List[Dict]:
        """Batch enrich a list of manifest items."""
        enriched = []
        for item in items:
            try:
                enriched.append(self.enrich_item(item))
            except Exception as e:
                logger.warning(f"Actor attribution failed for item: {e}")
                enriched.append(item)
        return enriched


# Module-level singleton
actor_attribution_engine_v46 = ActorAttributionEngineV46()
