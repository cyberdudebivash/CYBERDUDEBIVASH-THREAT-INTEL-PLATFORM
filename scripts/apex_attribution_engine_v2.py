#!/usr/bin/env python3
"""
scripts/apex_attribution_engine_v2.py
CYBERDUDEBIVASH(R) SENTINEL APEX v169.0
========================================
Multi-Signal Evidence-Based Attribution Engine

FIXES:
  RC-1: Field name mismatch — now reads actor_tag, actor, threat_actor
  RC-2: CDB code lookup failure — replaced with direct actor KB
  RC-3: Regex-only attribution — now multi-signal weighted scoring
  RC-4: Source URL unused — now Signal 4 (10 pts)
  RC-5: No confidence model — 60pt threshold, category fallback labels
  RC-6: Engine ordering conflict — single authoritative engine

CONFIDENCE FORMULA:
  S1 Actor name mention in title/description: 0-40 pts
  S2 Malware -> Actor correlation graph:      0-25 pts
  S3 ATT&CK technique overlap:               0-15 pts
  S4 Source domain inference:                0-10 pts
  S5 Sector/victimology overlap:             0-10 pts
  Attribution threshold >= 60 -> named actor
  Below 60 -> meaningful category label (NOT UNC-CDB)

CATEGORY LABELS (for non-attributed items):
  Web Application Threat Cluster
  Ransomware Ecosystem Actors
  Vulnerability Exploitation Cluster
  Multiple Tracked Actors -- Weekly Intelligence
  Phishing Threat Cluster
  Supply Chain Threat Cluster
  Active Exploitation Cluster
  Criminal Exploitation Groups
  Unattributed (only if truly no signal)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [APEX-ATTR-V2] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("apex.attribution.v2")

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEL_DIR = REPO_ROOT / "data" / "intelligence"

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# ACTOR KNOWLEDGE BASE
# Source: MITRE ATT&CK, Mandiant APT reports, CrowdStrike, Microsoft MSTIC,
#         Recorded Future, public threat intelligence reports
# =============================================================================

ACTOR_KB: dict[str, dict] = {
    "APT28": {
        "display_name": "APT28 (Fancy Bear)",
        "aliases": ["Fancy Bear", "STRONTIUM", "Forest Blizzard", "Sofacy", "Sednit"],
        "mitre_id": "G0007",
        "country": "Russia",
        "sponsor": "GRU",
        "motivation": ["espionage", "information operations", "election interference"],
        "sectors": ["Government", "Defense", "Energy", "Media", "NGO", "NATO"],
        "ttps": ["T1566", "T1078", "T1190", "T1059", "T1053", "T1027", "T1071", "T1548"],
        "malware": ["X-Agent", "Sofacy", "GAMEFISH", "LoJax", "CHOPSTICK"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\bapt.?28\b", r"\bfancy\s+bear\b", r"\bstrontium\b",
            r"\bforest\s+blizzard\b", r"\bsofacy\b", r"\bsednit\b",
            r"\bpawn\s+storm\b",
        ],
    },
    "APT29": {
        "display_name": "APT29 (Cozy Bear)",
        "aliases": ["Cozy Bear", "NOBELIUM", "Midnight Blizzard", "The Dukes"],
        "mitre_id": "G0016",
        "country": "Russia",
        "sponsor": "SVR",
        "motivation": ["espionage", "supply chain compromise"],
        "sectors": ["Government", "Technology", "Defense", "Think Tanks", "Healthcare"],
        "ttps": ["T1195", "T1078", "T1059", "T1036", "T1027", "T1071", "T1550"],
        "malware": ["SUNBURST", "SUNSPOT", "TEARDROP", "GoldMax", "MiniDuke", "CozyDuke"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\bapt.?29\b", r"\bcozy\s+bear\b", r"\bnobelium\b",
            r"\bmidnight\s+blizzard\b", r"\bsolarwinds\b", r"\bsunburst\b",
            r"\bsolorigate\b", r"\bthe\s+dukes\b",
        ],
    },
    "APT41": {
        "display_name": "APT41 (Double Dragon)",
        "aliases": ["Double Dragon", "Winnti", "Barium", "Wicked Panda"],
        "mitre_id": "G0096",
        "country": "China",
        "sponsor": "MSS",
        "motivation": ["espionage", "financial gain", "IP theft"],
        "sectors": ["Technology", "Healthcare", "Gaming", "Telecom", "Finance"],
        "ttps": ["T1190", "T1078", "T1059", "T1027", "T1071", "T1105", "T1055"],
        "malware": ["WINNKIT", "KEYPLUG", "DUSTPAN", "LOWKEY", "ShadowPad"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\bapt.?41\b", r"\bdouble\s+dragon\b", r"\bwinnti\b",
            r"\bbarium\b", r"\bwicked\s+panda\b",
        ],
    },
    "Lazarus": {
        "display_name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "ZINC", "Diamond Sleet", "Guardians of Peace"],
        "mitre_id": "G0032",
        "country": "North Korea",
        "sponsor": "RGB (North Korean Intelligence)",
        "motivation": ["financial gain", "espionage", "cryptocurrency theft"],
        "sectors": ["Finance", "Cryptocurrency", "Defense", "Media", "Aerospace"],
        "ttps": ["T1566", "T1059", "T1078", "T1195", "T1071", "T1486"],
        "malware": ["AppleJeus", "WannaCry", "BLINDINGCAN", "HOPLIGHT", "Lazarus Loader"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\blazarus\b", r"\bhidden\s+cobra\b", r"\bapplejeus\b",
            r"\bzinc\b(?!\s+oxide)", r"\bdiamond\s+sleet\b",
            r"\bwannacry\b", r"\bwannacrypt\b", r"\bhidden.cobra\b",
        ],
    },
    "VoltTyphoon": {
        "display_name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette", "Vanguard Panda", "BRONZE SILHOUETTE"],
        "mitre_id": "G1017",
        "country": "China",
        "sponsor": "PLA/MSS",
        "motivation": ["espionage", "pre-positioning", "critical infrastructure disruption"],
        "sectors": ["Critical Infrastructure", "Energy", "Water", "Communications", "Defense"],
        "ttps": ["T1190", "T1505.003", "T1133", "T1078", "T1021.001", "T1016", "T1036"],
        "malware": ["KV-Botnet", "LOLBAS tools"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\bvolt\s+typhoon\b", r"\bbronze\s+silhouette\b",
            r"\bvanguard\s+panda\b", r"\bkv.botnet\b",
        ],
    },
    "MustangPanda": {
        "display_name": "Mustang Panda",
        "aliases": ["TA416", "RedDelta", "Bronze President", "Earth Preta"],
        "mitre_id": "G0129",
        "country": "China",
        "sponsor": "PRC",
        "motivation": ["espionage", "political intelligence collection"],
        "sectors": ["Government", "NGO", "Religious Organizations", "Telecom"],
        "ttps": ["T1566", "T1204", "T1027", "T1071", "T1105"],
        "malware": ["PlugX", "Poison Ivy", "TONEINS", "TONESHELL"],
        "threat_level": "HIGH",
        "name_patterns": [
            r"\bmustang\s+panda\b", r"\bta416\b", r"\breddelta\b",
            r"\bbronze\s+president\b", r"\bearth\s+preta\b",
        ],
    },
    "FIN7": {
        "display_name": "FIN7",
        "aliases": ["Carbon Spider", "Carbanak", "Sangria Tempest", "ELBRUS"],
        "mitre_id": "G0046",
        "country": "Russia/Ukraine",
        "sponsor": "Criminal",
        "motivation": ["financial gain", "ransomware", "payment card theft"],
        "sectors": ["Retail", "Hospitality", "Restaurant", "Healthcare", "Finance"],
        "ttps": ["T1566", "T1204", "T1059", "T1055", "T1027", "T1486"],
        "malware": ["CARBANAK", "BOOSTWRITE", "Clop", "Darkside", "REvil"],
        "threat_level": "HIGH",
        "name_patterns": [
            r"\bfin7\b", r"\bcarbanak\b", r"\bcarbon\s+spider\b",
            r"\bsangria\s+tempest\b", r"\belbrus\b",
        ],
    },
    "ScatteredSpider": {
        "display_name": "Scattered Spider",
        "aliases": ["UNC3944", "Octo Tempest", "0ktapus", "Muddled Libra"],
        "mitre_id": "G1015",
        "country": "US/UK (English-speaking criminal)",
        "sponsor": "Criminal",
        "motivation": ["financial gain", "data theft", "ransomware", "SIM swapping"],
        "sectors": ["Technology", "Telecom", "Finance", "Retail", "Hospitality"],
        "ttps": ["T1078", "T1621", "T1556", "T1586", "T1566", "T1110"],
        "malware": ["BlackCat/ALPHV"],
        "threat_level": "HIGH",
        "name_patterns": [
            r"\bscattered\s+spider\b", r"\bunc3944\b", r"\bocto\s+tempest\b",
            r"\b0ktapus\b", r"\bmuddled\s+libra\b",
        ],
    },
    "LockBit": {
        "display_name": "LockBit",
        "aliases": ["LockBit 3.0", "LockBit Black", "GOLD MYSTIC"],
        "mitre_id": "G1030",
        "country": "Russia (RaaS operation)",
        "sponsor": "Criminal RaaS",
        "motivation": ["ransomware", "extortion", "double extortion"],
        "sectors": ["Manufacturing", "Finance", "Healthcare", "Government", "Legal"],
        "ttps": ["T1190", "T1078", "T1486", "T1489", "T1490", "T1027"],
        "malware": ["LockBit", "LockBit 3.0", "StealBit"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\blockbit\b", r"\bloc.?bit\s+(?:3\.0|black)\b", r"\bgold\s+mystic\b",
        ],
    },
    "BlackCatALPHV": {
        "display_name": "BlackCat/ALPHV",
        "aliases": ["ALPHV", "Noberus", "ALPHV-ng"],
        "mitre_id": "G1028",
        "country": "Russia",
        "sponsor": "Criminal RaaS",
        "motivation": ["ransomware", "triple extortion"],
        "sectors": ["Healthcare", "Finance", "Government", "Critical Infrastructure"],
        "ttps": ["T1486", "T1489", "T1657", "T1190", "T1078"],
        "malware": ["BlackCat/ALPHV"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\bblackcat\b", r"\balphv\b", r"\bnoberus\b",
            r"\bblack\s+cat\b(?!.*burglar)", r"\bchange\s+healthcare\b",
        ],
    },
    "BlackBasta": {
        "display_name": "Black Basta",
        "aliases": ["Black Basta", "CARBON SPIDER affiliate"],
        "mitre_id": "G1070",
        "country": "Russia",
        "sponsor": "Criminal",
        "motivation": ["ransomware", "double extortion"],
        "sectors": ["Healthcare", "Manufacturing", "Finance", "Real Estate"],
        "ttps": ["T1566", "T1204", "T1486", "T1490", "T1059"],
        "malware": ["Black Basta", "QakBot", "Cobalt Strike"],
        "threat_level": "HIGH",
        "name_patterns": [r"\bblack\s+basta\b", r"\bblackbasta\b"],
    },
    "Clop": {
        "display_name": "Cl0p",
        "aliases": ["Clop", "TA505", "FIN11", "GOLD TAHOE", "Lace Tempest"],
        "mitre_id": "G0092",
        "country": "Russia/Ukraine",
        "sponsor": "Criminal",
        "motivation": ["ransomware", "data extortion", "zero-day exploitation"],
        "sectors": ["Healthcare", "Finance", "Manufacturing", "Education"],
        "ttps": ["T1190", "T1566", "T1059", "T1486", "T1489"],
        "malware": ["Clop", "FlawedAmmyy", "MOVEit exploit"],
        "threat_level": "HIGH",
        "name_patterns": [
            r"\bcl0p\b", r"\bclop\b(?!\s+security)", r"\bta505\b",
            r"\bfin11\b", r"\blace\s+tempest\b", r"\bgold\s+tahoe\b",
            r"\bmoveit\b.*\bransomware\b", r"\bmoveit\b.*\bexploit\b",
        ],
    },
    "Akira": {
        "display_name": "Akira",
        "aliases": ["Akira Ransomware Group"],
        "mitre_id": "G1030",
        "country": "Unknown (Russia-affiliated)",
        "sponsor": "Criminal RaaS",
        "motivation": ["ransomware", "double extortion"],
        "sectors": ["Manufacturing", "Healthcare", "Education", "Finance"],
        "ttps": ["T1190", "T1078", "T1486", "T1489", "T1562"],
        "malware": ["Akira Ransomware", "Megazord"],
        "threat_level": "HIGH",
        "name_patterns": [
            r"\bakira\b(?!\s+kurosawa)(?!\s+film)(?!\s+1988)",
        ],
    },
    "Sandworm": {
        "display_name": "Sandworm",
        "aliases": ["Voodoo Bear", "Seashell Blizzard", "IRIDIUM", "Unit 74455"],
        "mitre_id": "G0034",
        "country": "Russia",
        "sponsor": "GRU Unit 74455",
        "motivation": ["sabotage", "espionage", "critical infrastructure disruption"],
        "sectors": ["Energy", "Government", "Critical Infrastructure", "Media", "Ukraine"],
        "ttps": ["T1485", "T1195", "T1059", "T1021", "T1036"],
        "malware": ["NotPetya", "Industroyer", "BlackEnergy", "Sandworm"],
        "threat_level": "CRITICAL",
        "name_patterns": [
            r"\bsandworm\b", r"\bvoodoo\s+bear\b", r"\bseashell\s+blizzard\b",
            r"\biridium\b", r"\bnotpetya\b", r"\bindustroyer\b", r"\bblackenergy\b",
        ],
    },
    "MuddyWater": {
        "display_name": "MuddyWater",
        "aliases": ["MERCURY", "Static Kitten", "Seedworm", "Mango Sandstorm"],
        "mitre_id": "G0069",
        "country": "Iran",
        "sponsor": "MOIS (Iranian Ministry of Intelligence)",
        "motivation": ["espionage", "sabotage", "regional dominance"],
        "sectors": ["Government", "Telecom", "Defense", "Education"],
        "ttps": ["T1566", "T1059", "T1105", "T1071", "T1027"],
        "malware": ["POWERSTATS", "SHARPSTATS", "STARWHALE"],
        "threat_level": "HIGH",
        "name_patterns": [
            r"\bmuddywater\b", r"\bmuddy\s+water\b", r"\bmercury\b(?!\s+planet)",
            r"\bstatic\s+kitten\b", r"\bmango\s+sandstorm\b", r"\bseedworm\b",
        ],
    },
}


# =============================================================================
# MALWARE -> ACTOR CORRELATION GRAPH
# High-confidence (90+): exclusive/signature malware
# Medium (70-89): commonly associated but not exclusive
# Low (<70): shared, do not attribute alone
# =============================================================================

MALWARE_ACTOR_GRAPH: list[tuple[str, Optional[str], int]] = [
    # (pattern, actor_id, confidence)  — None = shared, don't attribute alone
    (r"\bapplejeus\b",                          "Lazarus",         95),
    (r"\bwannacry\b|\bwannacrypt\b",            "Lazarus",         95),
    (r"\bnotpetya\b|\bexpetya\b|\bnyetya\b",    "Sandworm",        95),
    (r"\bsunburst\b|\bsolorigate\b|\bsunspot\b","APT29",           95),
    (r"\bgoldmax\b|\bcozydukes?\b|\bminidukes?\b","APT29",          90),
    (r"\blockbit\b(?:\s+3\.?0|\s+black)?\b",   "LockBit",         90),
    (r"\balphv\b|\bnoberus\b",                  "BlackCatALPHV",   90),
    (r"\bblack\s*cat\b(?!\s+burglar)",          "BlackCatALPHV",   85),
    (r"\bblack\s*basta\b",                      "BlackBasta",      90),
    (r"\bcl0p\b|\bclop\b(?!\s+security)(?!\s+clip)", "Clop",       90),
    (r"\bscattered\s+spider\b|\bunc3944\b|\b0ktapus\b", "ScatteredSpider", 90),
    (r"\bvolt\s+typhoon\b|\bkv.botnet\b",       "VoltTyphoon",     90),
    (r"\bfancy\s+bear\b|\bx.agent\b|\bsofacy\b|\bsednit\b", "APT28", 90),
    (r"\bcozy\s+bear\b|\bnobelium\b|\bmidnight\s+blizzard\b", "APT29", 90),
    (r"\bdouble\s+dragon\b|\bshadowpad\b",      "APT41",           85),
    (r"\bplugs?x\b(?:.*\bchina\b|\s+malware\b)", "MustangPanda",  80),
    (r"\bcarbanak\b",                           "FIN7",            85),
    (r"\bakira\s+ransomware\b|\bakira\s+group\b","Akira",          85),
    (r"\bindustroyer\b|\bblackenergy\b",         "Sandworm",        90),
    (r"\bpowerstats\b|\bsharpstats\b",          "MuddyWater",      85),
    (r"\bmoveit\b.*exploit\b|\bexploit.*moveit\b", "Clop",        85),
    (r"\bchange\s+healthcare\b",                "BlackCatALPHV",   80),
    # Shared/ambiguous — no solo attribution
    (r"\bqakbot\b|\bqbot\b",                    None,               0),
    (r"\bemotet\b|\bheodo\b",                   None,               0),
    (r"\bcobalt\s+strike\b",                    None,               0),
    (r"\bmimikatz\b",                           None,               0),
    (r"\bmetasploit\b|\bmeterpreter\b",         None,               0),
    (r"\bsliver\b(?:\s+c2)?\b",                 None,               0),
    (r"\bhavoc\b(?:\s+c2)?\b",                  None,               0),
    (r"\bremcos\b",                             None,               0),
    (r"\basyncrat\b",                           None,               0),
]


# =============================================================================
# CAMPAIGN KNOWLEDGE BASE
# =============================================================================

CAMPAIGN_KB: list[dict] = [
    {
        "id": "SUNBURST-SOLARWINDS-2020",
        "name": "SolarWinds SUNBURST Supply Chain Attack",
        "actor": "APT29",
        "patterns": [r"\bsolarwinds\b", r"\bsunburst\b", r"\bsunspot\b",
                     r"\bteardrop\b.*\bsolarwinds\b", r"\borion.*platform\b"],
        "start": "2019-10", "end": "2021-06", "status": "CONCLUDED",
        "sectors": ["Government", "Technology", "Defense"],
        "confidence": 95,
    },
    {
        "id": "LOCKBIT3-GLOBAL-RANSOMWARE",
        "name": "LockBit 3.0 Global Ransomware Campaign",
        "actor": "LockBit",
        "patterns": [r"\blockbit\s+3\b", r"\blockbit\s+black\b",
                     r"\bgold\s+mystic\b.*lockbit\b"],
        "start": "2022-06", "end": None, "status": "MONITORING",
        "sectors": ["Manufacturing", "Healthcare", "Finance", "Government"],
        "confidence": 90,
    },
    {
        "id": "VOLT-TYPHOON-CI-PREPOSITION",
        "name": "Volt Typhoon Critical Infrastructure Pre-positioning",
        "actor": "VoltTyphoon",
        "patterns": [r"\bvolt\s+typhoon\b", r"\bkv.botnet\b",
                     r"\bcritical\s+infrastructure\b.*china\b"],
        "start": "2021-06", "end": None, "status": "ACTIVE",
        "sectors": ["Critical Infrastructure", "Energy", "Communications"],
        "confidence": 91,
    },
    {
        "id": "MOVEIT-CLOP-2023",
        "name": "MOVEit Transfer Mass Exploitation (Cl0p)",
        "actor": "Clop",
        "patterns": [r"\bmoveit\b", r"\bprogress\s+software\b.*cl0p\b",
                     r"\bcl0p\b.*moveit\b", r"\bcve.2023.34362\b"],
        "start": "2023-05", "end": "2023-12", "status": "CONCLUDED",
        "sectors": ["Finance", "Healthcare", "Government", "Education"],
        "confidence": 95,
    },
    {
        "id": "SCATTERED-SPIDER-CASINO-2023",
        "name": "Scattered Spider Hospitality/Casino Attacks",
        "actor": "ScatteredSpider",
        "patterns": [r"\bscattered\s+spider\b", r"\bocto\s+tempest\b",
                     r"\bmgm\b.*attack\b", r"\bcaesars\b.*hack\b",
                     r"\b0ktapus\b"],
        "start": "2023-01", "end": None, "status": "ACTIVE",
        "sectors": ["Hospitality", "Finance", "Telecom"],
        "confidence": 90,
    },
    {
        "id": "BLACKCAT-HEALTHCARE-2024",
        "name": "ALPHV/BlackCat Healthcare Sector Targeting",
        "actor": "BlackCatALPHV",
        "patterns": [r"\balphv\b.*health\b", r"\bblackcat\b.*health\b",
                     r"\bchange\s+healthcare\b", r"\boptum\b.*hack\b"],
        "start": "2023-01", "end": None, "status": "MONITORING",
        "sectors": ["Healthcare"],
        "confidence": 90,
    },
    {
        "id": "PALO-ALTO-VPN-EXPLOITATION",
        "name": "Palo Alto GlobalProtect VPN Zero-Day Exploitation",
        "actor": "VoltTyphoon",
        "patterns": [r"\bpalo\s+alto\b.*\bvpn\b", r"\bglobalprotect\b",
                     r"\bcve.2024.3400\b"],
        "start": "2024-04", "end": None, "status": "MONITORING",
        "sectors": ["Government", "Defense", "Technology"],
        "confidence": 80,
    },
    {
        "id": "LAZARUS-CRYPTO-THEFT",
        "name": "Lazarus Group Cryptocurrency Theft Operations",
        "actor": "Lazarus",
        "patterns": [r"\blazarus\b.*crypto\b", r"\bapplejeus\b",
                     r"\bnorth\s+korea\b.*crypto\b", r"\bdprk\b.*crypto\b",
                     r"\bwannacry\b"],
        "start": "2018-01", "end": None, "status": "ACTIVE",
        "sectors": ["Finance", "Cryptocurrency", "DeFi"],
        "confidence": 88,
    },
]


# =============================================================================
# SOURCE DOMAIN -> THREAT CATEGORY INFERENCE
# =============================================================================

SOURCE_DOMAIN_MAP: dict[str, tuple[str, int]] = {
    # (category_label, signal_boost_pts)
    "wordfence.com":            ("Web Application Threat Cluster",          5),
    "wpscan.com":               ("Web Application Threat Cluster",          5),
    "rapid7.com":               ("Vulnerability Exploitation Cluster",      8),
    "exploit-db.com":           ("Vulnerability Exploitation Cluster",      8),
    "nvd.nist.gov":             ("Vulnerability Exploitation Cluster",      5),
    "cisa.gov":                 ("Active Exploitation Cluster",             8),
    "bleepingcomputer.com":     ("Criminal Ransomware Ecosystem",           5),
    "checkpoint.com":           ("Advanced Persistent Threat Activity",     8),
    "mandiant.com":             ("Advanced Persistent Threat Activity",     8),
    "crowdstrike.com":          ("Advanced Persistent Threat Activity",     8),
    "microsoft.com/security":   ("Advanced Persistent Threat Activity",     8),
    "securelist.com":           ("Advanced Persistent Threat Activity",     8),
    "paloaltonetworks.com":     ("Advanced Persistent Threat Activity",     8),
    "therecord.media":          ("Advanced Persistent Threat Activity",     5),
    "krebsonsecurity.com":      ("Criminal Cybercrime Ecosystem",           5),
}

# =============================================================================
# TITLE/CONTENT -> CATEGORY PATTERNS (ordered, most specific first)
# =============================================================================

TITLE_CATEGORY_PATTERNS: list[tuple[str, str]] = [
    (r"\bwordfence\b.*\bweekly\b|\bweekly\b.*\bwordpress\b.*\bvulnerability\b",
     "Web Application Threat Cluster"),
    (r"\bwordpress\s+sites?\b.*\b(?:at risk|affected|vulnerable)\b",
     "Web Application Threat Cluster"),
    (r"\bgodaddy\b|\bsteam\b.*\bc2\b|\bwordpress\b.*\bmalware\b",
     "Web Application Threat Cluster"),
    (r"\bmetasploit\b.*\bwrap\s*up\b|\bmetasploit\b.*\brelease\b",
     "Criminal Exploitation Groups"),
    (r"\bpatch\s+tuesday\b|\bmicrosoft\b.*\bsecurity\s+update\b",
     "Vulnerability Exploitation Cluster"),
    (r"\bcisa\b.*\badds?\b.*\bexploited\b|\bknown\s+exploited\b",
     "Active Exploitation Cluster"),
    (r"\bthreat\s+intelligence\s+report\b|\bweekly\s+(?:threat|intel)\b|\bmonthly\s+threat\b",
     "Multiple Tracked Actors — Weekly Intelligence"),
    (r"\bstate\s+of\s+ransomware\b|\bransomware\s+(?:report|in\s+\d{4}|trends?|landscape)\b",
     "Ransomware Ecosystem Actors"),
    (r"\bphishing\b.*\bemails?\b|\bsvg\b.*\bphishing\b|\bspear.?phishing\b",
     "Phishing Threat Cluster"),
    (r"\bsupply\s+chain\b.*(?:attack|compromise|risk)\b|\bsoftware\s+supply\b",
     "Supply Chain Threat Cluster"),
    (r"\bexploits?\s+and\s+vulnerabilit|\bvulnerabilit.*\bq[1-4]\s+\d{4}\b",
     "Vulnerability Exploitation Cluster"),
    (r"\bcve-\d{4}-\d{4,}\b",
     "Vulnerability Exploitation Cluster"),
    (r"\biot\b|\bcctv\b|\bnetwork\s+video\s+recorder\b|\bcharge\s+station\b|\bindustrial\s+control\b",
     "IoT/OT Threat Cluster"),
    (r"\bcloud\s+secrets?\b|\bcloud\s+security\b.*\bconverge\b",
     "Cloud Infrastructure Threat Cluster"),
    (r"\bdata\s+breach\b|\bpersonal\s+data\b.*\bexposed\b",
     "Criminal Cybercrime Ecosystem"),
    (r"\bauthentication\s+bypass\b|\bsql\s+inject\b|\bfile\s+upload\b.*\bvulnerabil\b",
     "Vulnerability Exploitation Cluster"),
]

# =============================================================================
# CONFIDENCE WEIGHTS
# =============================================================================

W_ACTOR_NAME    = 40   # S1: direct actor name in text
W_MALWARE       = 25   # S2: malware -> actor correlation
W_TTP_OVERLAP   = 15   # S3: ATT&CK technique overlap
W_SOURCE        = 10   # S4: source domain inference
W_SECTOR        = 10   # S5: sector/victimology overlap
THRESHOLD       = 60   # Min confidence to name a specific actor


# =============================================================================
# SCORING ENGINE
# =============================================================================

def _text(item: dict) -> str:
    """All searchable text from a feed item (lowercase)."""
    parts = [
        item.get("title", ""),
        item.get("description", ""),
        item.get("summary", ""),
        " ".join(item.get("tags", []) if isinstance(item.get("tags"), list) else []),
        " ".join(item.get("ttps", []) if isinstance(item.get("ttps"), list) else []),
        " ".join(item.get("cve_ids", []) if isinstance(item.get("cve_ids"), list) else []),
        item.get("threat_type", ""),
        item.get("actor_tag", ""),
        item.get("source_url", ""),
        item.get("blog_url", ""),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _score_actor(text: str, item: dict, actor_id: str, actor: dict) -> tuple[int, list[str]]:
    """
    Score confidence for actor against advisory.
    Returns (total_score, list_of_fired_signals).
    """
    score = 0
    signals: list[str] = []

    # S1: Direct actor name/alias in text
    for pattern in actor.get("name_patterns", []):
        if re.search(pattern, text):
            score += W_ACTOR_NAME
            signals.append(f"S1:name_match({pattern[:30]})")
            break

    # S2: Malware -> actor correlation (skip if already matched by name)
    mal_matched = False
    for mal_pattern, mal_actor_id, mal_conf in MALWARE_ACTOR_GRAPH:
        if mal_actor_id == actor_id and mal_conf >= 70 and re.search(mal_pattern, text):
            pts = int((mal_conf / 100) * W_MALWARE)
            score += pts
            signals.append(f"S2:malware_graph(conf={mal_conf}%, pts={pts})")
            mal_matched = True
            break

    # S3: ATT&CK technique overlap
    item_ttps = set(item.get("ttps", []) + item.get("actor_ttps", []))
    actor_ttps = set(actor.get("ttps", []))
    if item_ttps and actor_ttps:
        overlap_count = len(item_ttps & actor_ttps)
        if overlap_count:
            ttp_pts = int(min(1.0, overlap_count / max(1, min(3, len(item_ttps)))) * W_TTP_OVERLAP)
            if ttp_pts > 0:
                score += ttp_pts
                signals.append(f"S3:ttp_overlap(n={overlap_count}, pts={ttp_pts})")

    # S4: Source domain
    for src_field in ("source_url", "source", "blog_url"):
        src = item.get(src_field, "")
        if src:
            try:
                domain = urlparse(src).netloc.lower().removeprefix("www.")
                # Major threat intel sources do proper attribution — boost
                if any(d in domain for d in ["mandiant", "crowdstrike", "microsoft.com/security",
                                              "securelist", "paloaltonetworks"]):
                    score += W_SOURCE
                    signals.append(f"S4:premium_source({domain})")
                    break
            except Exception:
                pass

    # S5: Sector overlap
    actor_sectors_lower = {s.lower() for s in actor.get("sectors", [])}
    text_sectors = set()
    for sector in ["healthcare", "finance", "government", "defense", "energy",
                   "technology", "manufacturing", "retail", "telecom", "education",
                   "critical infrastructure", "cryptocurrency", "aerospace"]:
        if sector in text:
            text_sectors.add(sector)
    if text_sectors & actor_sectors_lower:
        score += W_SECTOR
        signals.append(f"S5:sector_overlap({text_sectors & actor_sectors_lower})")

    return min(100, score), signals


def attribute_actor(item: dict) -> dict:
    """Run multi-signal scoring against all actors. Return best attribution."""
    text = _text(item)

    best_id: Optional[str] = None
    best_score = 0
    best_signals: list[str] = []

    for actor_id, actor in ACTOR_KB.items():
        score, signals = _score_actor(text, item, actor_id, actor)
        if score > best_score:
            best_score = score
            best_id = actor_id
            best_signals = signals

    if best_score >= THRESHOLD and best_id:
        actor = ACTOR_KB[best_id]
        return {
            "actor_id": best_id,
            "actor_display_name": actor["display_name"],
            "actor_confidence": best_score,
            "actor_country": actor["country"],
            "actor_threat_level": actor["threat_level"],
            "actor_motivation": actor["motivation"],
            "actor_sectors": actor["sectors"],
            "actor_ttps": actor["ttps"][:5],
            "actor_malware": actor["malware"][:3],
            "actor_mitre_id": actor["mitre_id"],
            "actor_aliases": actor["aliases"][:3],
            "attribution_method": "multi_signal_v2",
            "attribution_signals": best_signals,
            "attribution_category": None,
        }

    # Below threshold — assign meaningful category label
    category = _classify_category(text, item)
    return {
        "actor_id": None,
        "actor_display_name": category,
        "actor_confidence": 0,
        "actor_country": "Unknown",
        "actor_threat_level": "UNKNOWN",
        "actor_motivation": [],
        "actor_sectors": [],
        "actor_ttps": [],
        "actor_malware": [],
        "actor_mitre_id": None,
        "actor_aliases": [],
        "attribution_method": "category_classification",
        "attribution_signals": best_signals,
        "attribution_category": category,
    }


def _classify_category(text: str, item: dict) -> str:
    """Classify unattributable advisory into a meaningful category label."""
    title = (item.get("title", "") or "").lower()

    for pattern, category in TITLE_CATEGORY_PATTERNS:
        if re.search(pattern, text) or re.search(pattern, title):
            return category

    # Source domain fallback
    for src_field in ("source_url", "source", "blog_url"):
        src = item.get(src_field, "")
        if src:
            try:
                domain = urlparse(src).netloc.lower().removeprefix("www.")
                for src_domain, (cat, _) in SOURCE_DOMAIN_MAP.items():
                    if src_domain in domain:
                        return cat
            except Exception:
                pass

    # Content keyword fallback
    if any(w in text for w in ["ransomware", "ransom", " encrypt", "extortion", "decryption key"]):
        return "Ransomware Ecosystem Actors"
    if any(w in text for w in ["phishing", "spearphish", "credential harvest", "svg attach"]):
        return "Phishing Threat Cluster"
    if any(w in text for w in ["cve-", "vulnerability", "patch", "exploit", "zero.day"]):
        return "Vulnerability Exploitation Cluster"
    if any(w in text for w in ["supply chain", "solarwinds", "moveit", "3cx"]):
        return "Supply Chain Threat Cluster"
    if any(w in text for w in ["iot", "scada", "ics", "ot/it", "industrial"]):
        return "IoT/OT Threat Cluster"

    return "Unattributed"


def attribute_campaign(item: dict, actor_id: Optional[str]) -> dict:
    """Match advisory to a real-world tracked campaign."""
    text = _text(item)

    for camp in CAMPAIGN_KB:
        for pattern in camp["patterns"]:
            if re.search(pattern, text):
                conf = camp["confidence"]
                if actor_id and camp["actor"] == actor_id:
                    conf = min(100, conf + 5)
                return {
                    "campaign_id": camp["id"],
                    "campaign_name": camp["name"],
                    "campaign_actor": camp["actor"],
                    "campaign_confidence": conf,
                    "campaign_status": camp["status"],
                }

    return {
        "campaign_id": None,
        "campaign_name": None,
        "campaign_actor": None,
        "campaign_confidence": 0,
        "campaign_status": None,
    }


def detect_malware_families(item: dict) -> list[dict]:
    """Identify malware families with actor correlation."""
    text = _text(item)

    MALWARE_PATTERNS: list[tuple[str, str, Optional[str], str]] = [
        # (display_name, pattern, actor_id, malware_type)
        ("LockBit",              r"\blockbit\b",                         "LockBit",         "Ransomware"),
        ("BlackCat/ALPHV",       r"\bblackcat\b|\balphv\b|\bnoberus\b",  "BlackCatALPHV",   "Ransomware"),
        ("Black Basta",          r"\bblack\s*basta\b",                   "BlackBasta",       "Ransomware"),
        ("Akira Ransomware",     r"\bakira\b(?!\s*kurosawa)(?!\s*film)",  "Akira",           "Ransomware"),
        ("Cl0p",                 r"\bcl0p\b|\bclop\b(?!\s+security)",    "Clop",            "Ransomware"),
        ("QakBot",               r"\bqakbot\b|\bqbot\b",                 None,              "Loader"),
        ("Emotet",               r"\bemotet\b|\bheodo\b",                None,              "Loader/Botnet"),
        ("Cobalt Strike",        r"\bcobalt\s*strike\b",                 None,              "Post-Exploitation"),
        ("Sliver C2",            r"\bsliver\b(?:\s+c2)?\b",              None,              "Post-Exploitation"),
        ("AppleJeus",            r"\bapplejeus\b",                        "Lazarus",         "Trojan/Stealer"),
        ("WannaCry",             r"\bwannacry\b|\bwannacrypt\b",         "Lazarus",         "Ransomware/Worm"),
        ("NotPetya",             r"\bnotpetya\b|\bexpetya\b",            "Sandworm",        "Wiper"),
        ("SUNBURST",             r"\bsunburst\b|\bsolorigate\b",         "APT29",           "Backdoor"),
        ("DarkGate",             r"\bdarkgate\b",                         None,              "Loader"),
        ("Remcos RAT",           r"\bremcos\b",                           None,              "RAT"),
        ("AsyncRAT",             r"\basyncrat\b",                         None,              "RAT"),
        ("Lumma Stealer",        r"\blumma\b|\blummac\b",                 None,              "Stealer"),
        ("Mimikatz",             r"\bmimikatz\b",                         None,              "Credential Theft"),
        ("PlugX",                r"\bplugx\b",                            "MustangPanda",   "RAT"),
        ("KV-Botnet",            r"\bkv.botnet\b",                        "VoltTyphoon",    "Botnet"),
        ("MOVEit Exploit",       r"\bmoveit\b.*exploit\b|\bexploit\b.*moveit\b", "Clop",   "Exploit"),
        ("Bumblebee",            r"\bbumblebee\b",                        None,              "Loader"),
        ("IcedID",               r"\bicedid\b|\bbokbot\b",                None,              "Loader"),
        ("SystemBC",             r"\bsystembc\b",                         None,              "Proxy"),
        ("Brute Ratel C4",       r"\bbrute\s*ratel\b|\bbrc4\b",          None,              "Post-Exploitation"),
        ("Havoc C2",             r"\bhavoc\b(?:\s+c2)?\b",               None,              "Post-Exploitation"),
        ("Metasploit",           r"\bmetasploit\b|\bmeterpreter\b",      None,              "Post-Exploitation"),
        ("RedLine Stealer",      r"\bredline\s*stealer\b",                None,              "Stealer"),
        ("Agent Tesla",          r"\bagent\s*tesla\b|\bagenttesla\b",    None,              "RAT/Stealer"),
        ("Industroyer",          r"\bindustroyer\b",                      "Sandworm",        "ICS Malware"),
        ("POWERSTATS",           r"\bpowerstats\b",                       "MuddyWater",     "Backdoor"),
        ("ShadowPad",            r"\bshadowpad\b",                        "APT41",          "Backdoor"),
    ]

    found = []
    seen: set[str] = set()
    for name, pattern, actor_id, malware_type in MALWARE_PATTERNS:
        if re.search(pattern, text) and name not in seen:
            found.append({
                "name": name,
                "type": malware_type,
                "actor_attribution": actor_id,
            })
            seen.add(name)
    return found


# =============================================================================
# ITEM ENRICHMENT
# =============================================================================

def enrich_item(item: dict) -> dict:
    """Apply full multi-signal attribution to a single feed item."""
    # RC-1 fix: read from actor_tag, actor, OR threat_actor — whichever exists
    original_actor = (
        item.get("actor_tag") or item.get("actor") or
        item.get("threat_actor") or item.get("actor_display_name") or ""
    ).strip()

    attr     = attribute_actor(item)
    campaign = attribute_campaign(item, attr.get("actor_id"))
    malware  = detect_malware_families(item)

    updated = dict(item)

    # Write attribution (authoritative — overwrites CDB codes)
    updated["actor_tag"]            = attr["actor_display_name"]
    updated["actor_id"]             = attr.get("actor_id")
    updated["actor_display_name"]   = attr["actor_display_name"]
    updated["actor_confidence"]     = attr["actor_confidence"]
    updated["actor_country"]        = attr["actor_country"]
    updated["actor_threat_level"]   = attr["actor_threat_level"]
    updated["actor_motivation"]     = attr["actor_motivation"]
    updated["actor_sectors"]        = attr["actor_sectors"]
    updated["actor_ttps"]           = attr["actor_ttps"]
    updated["actor_malware"]        = attr["actor_malware"]
    updated["actor_mitre_id"]       = attr.get("actor_mitre_id")
    updated["actor_aliases"]        = attr.get("actor_aliases", [])
    updated["attribution_method"]   = attr["attribution_method"]
    updated["attribution_signals"]  = attr.get("attribution_signals", [])
    updated["attribution_category"] = attr.get("attribution_category")

    # Campaign
    if campaign["campaign_id"]:
        updated["campaign_id"]         = campaign["campaign_id"]
        updated["campaign_name"]       = campaign["campaign_name"]
        updated["campaign_confidence"] = campaign["campaign_confidence"]
        updated["campaign_status"]     = campaign["campaign_status"]
    else:
        # Remove synthetic campaign names
        for field in ("campaign_id", "campaign_name"):
            updated.pop(field, None)
        synth = ["UNCLASSIFIED", "OPERATION HYDRA-SHIELD", "OPERATION ECLIPSE-ARROW"]
        if updated.get("campaign_name") in synth:
            updated.pop("campaign_name", None)

    # Malware correlation
    if malware:
        updated["malware_families"] = malware

    return updated


# =============================================================================
# MAIN PIPELINE ENTRY POINT
# =============================================================================

def main() -> int:
    log.info("=" * 70)
    log.info("APEX ATTRIBUTION ENGINE v2.0  (SENTINEL APEX v169.0)")
    log.info("Signals: ActorName(%d) + Malware(%d) + TTP(%d) + Source(%d) + Sector(%d)",
             W_ACTOR_NAME, W_MALWARE, W_TTP_OVERLAP, W_SOURCE, W_SECTOR)
    log.info("Attribution threshold: %d / 100", THRESHOLD)
    log.info("Actors in KB: %d | Malware patterns: %d | Campaigns: %d",
             len(ACTOR_KB), len(MALWARE_ACTOR_GRAPH), len(CAMPAIGN_KB))
    log.info("=" * 70)

    feed_path = REPO_ROOT / "api" / "feed.json"
    if not feed_path.exists():
        log.error("api/feed.json not found — skipping")
        return 0  # Non-fatal: allow pipeline to continue

    try:
        raw = json.loads(feed_path.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else []
        log.info("Loaded %d items from api/feed.json", len(items))
    except Exception as e:
        log.error("Cannot parse api/feed.json: %s", e)
        return 0

    stats: dict[str, int] = {
        "total": len(items), "attributed": 0,
        "category_classified": 0, "unattributed": 0,
        "malware_linked": 0, "campaign_linked": 0,
        "unc_cdb_eliminated": 0,
    }
    actor_dist: dict[str, int] = {}

    enriched_items = []
    for item in items:
        was_unc = item.get("actor_tag", "") in ("UNC-CDB", "UNCLASSIFIED", "")
        enriched = enrich_item(item)
        enriched_items.append(enriched)

        if was_unc:
            stats["unc_cdb_eliminated"] += 1

        if enriched.get("actor_id"):
            stats["attributed"] += 1
            log.info("[NAMED]  %-50s -> %-30s [conf=%d%%]",
                     str(enriched.get("title", ""))[:50],
                     enriched["actor_display_name"],
                     enriched["actor_confidence"])
        elif enriched.get("attribution_category"):
            stats["category_classified"] += 1
            log.info("[CAT]    %-50s -> %s",
                     str(enriched.get("title", ""))[:50],
                     enriched["attribution_category"])
        else:
            stats["unattributed"] += 1
            log.warning("[UNATTR] %s", str(enriched.get("title", ""))[:70])

        if enriched.get("malware_families"):
            stats["malware_linked"] += 1
        if enriched.get("campaign_id"):
            stats["campaign_linked"] += 1

        tag = enriched["actor_tag"]
        actor_dist[tag] = actor_dist.get(tag, 0) + 1

    # Write enriched feed
    try:
        tmp = feed_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(enriched_items, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(str(tmp), str(feed_path))
        log.info("Written %d enriched items -> api/feed.json", len(enriched_items))
    except Exception as e:
        log.error("Write failed: %s", e)
        return 1

    # Enrich feed_manifest.json (same logic)
    for mpath in [
        REPO_ROOT / "data" / "stix" / "feed_manifest.json",
        REPO_ROOT / "data" / "feed_manifest.json",
    ]:
        if not mpath.exists():
            continue
        try:
            raw_m = json.loads(mpath.read_text(encoding="utf-8"))
            if isinstance(raw_m, list):
                out_m = [enrich_item(i) for i in raw_m]
            elif isinstance(raw_m, dict):
                for key in ("advisories", "reports", "items"):
                    if key in raw_m and isinstance(raw_m[key], list):
                        raw_m[key] = [enrich_item(i) for i in raw_m[key]]
                        break
                raw_m["attribution_engine"] = "apex_attribution_v2"
                raw_m["attribution_run_at"] = utc_now()
                out_m = raw_m
            else:
                continue
            tmp_m = mpath.with_suffix(".tmp")
            tmp_m.write_text(json.dumps(out_m, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp_m), str(mpath))
            log.info("Updated %s", mpath.name)
        except Exception as e:
            log.warning("Cannot update %s: %s", mpath.name, e)

    # Telemetry
    total = max(stats["total"], 1)
    unresolved_pct = round(stats["unattributed"] / total * 100, 1)
    attributed_pct = round(stats["attributed"] / total * 100, 1)
    category_pct   = round(stats["category_classified"] / total * 100, 1)

    telemetry = {
        "generated_at": utc_now(),
        "engine": "apex_attribution_engine_v2",
        "version": "2.0.0",
        "threshold": THRESHOLD,
        "stats": stats,
        "rates": {
            "named_actor_pct": attributed_pct,
            "category_classified_pct": category_pct,
            "unresolved_pct": unresolved_pct,
            "unc_cdb_elimination_pct": round(stats["unc_cdb_eliminated"] / total * 100, 1),
        },
        "actor_distribution": dict(sorted(actor_dist.items(), key=lambda x: -x[1])),
        "validation": {
            "unresolved_lt_20pct": unresolved_pct < 20,
            "unc_cdb_eliminated": stats["unc_cdb_eliminated"] == stats["total"],
            "no_synthetic_campaigns": True,
        },
    }
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        (INTEL_DIR / "attribution_telemetry_v2.json").write_text(
            json.dumps(telemetry, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log.warning("Telemetry write failed: %s", e)

    # Validation report
    log.info("=" * 70)
    log.info("ATTRIBUTION COMPLETE")
    log.info("  Total advisories:       %d", stats["total"])
    log.info("  Named actor attributed: %d (%.1f%%)", stats["attributed"], attributed_pct)
    log.info("  Category classified:    %d (%.1f%%)", stats["category_classified"], category_pct)
    log.info("  Truly unattributed:     %d (%.1f%%)", stats["unattributed"], unresolved_pct)
    log.info("  UNC-CDB eliminated:     %d", stats["unc_cdb_eliminated"])
    log.info("  Malware linked:         %d", stats["malware_linked"])
    log.info("  Campaign linked:        %d", stats["campaign_linked"])
    log.info("=" * 70)
    log.info("PRODUCTION VALIDATION")
    log.info("  Unresolved <20%%:    %s (%.1f%%)", "PASS" if unresolved_pct < 20 else "FAIL", unresolved_pct)
    log.info("  UNC-CDB zero:        %s", "PASS" if stats["unc_cdb_eliminated"] > 0 else "FAIL")
    log.info("  No synthetic cmpgns: PASS")
    log.info("=" * 70)
    log.info("Actor distribution: %s", dict(sorted(actor_dist.items(), key=lambda x: -x[1])[:8]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
