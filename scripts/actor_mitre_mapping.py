#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/actor_mitre_mapping.py — CDB Actor Code → MITRE ATT&CK Group Mapping v161.3
================================================================================
Version : 161.3.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Resolves internal CDB actor codes (CDB-RU-01, CDB-FIN-07, etc.) to authoritative
  MITRE ATT&CK group IDs (G0034, G0007, etc.) and aliases used by Mandiant,
  CrowdStrike, and Recorded Future.

  Fixes P3-001 audit finding: internal CDB codes not usable for attribution
  correlation by security researchers and SOC analysts.

USAGE:
  from scripts.actor_mitre_mapping import resolve_actor, enrich_feed_actors

  # Resolve a single actor
  info = resolve_actor("CDB-RU-01")
  # Returns: {"mitre_id": "G0034", "name": "Sandworm Team", "aliases": [...], ...}

  # Enrich all items in feed
  enrich_feed_actors(items)
================================================================================
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("sentinel.actor_mapping")

# ── AUTHORITATIVE ACTOR MAPPING TABLE ─────────────────────────────────────────
# Maps CDB internal actor codes to MITRE ATT&CK Group IDs (G####) and aliases.
# Sources: MITRE ATT&CK v15, Mandiant, CrowdStrike, Recorded Future, CISA advisories.
#
# FORMAT: "CDB-CODE": {
#   "mitre_id":     MITRE ATT&CK Group ID (e.g. "G0034")
#   "name":         Canonical MITRE name
#   "aliases":      List of common aliases from vendor intelligence
#   "country":      Nation-state attribution (ISO 3166-1 alpha-2)
#   "motivation":   Primary motivation (espionage, financial, destruction, hacktivist)
#   "mandiant_id":  Mandiant UNC/APT designation
#   "crowdstrike":  CrowdStrike Bear/Panda/Kitten/Spider designation
#   "description":  Brief attribution context
# }
CDB_ACTOR_MAP: Dict[str, Dict[str, Any]] = {

    # ── RUSSIA ─────────────────────────────────────────────────────────────────
    "CDB-RU-01": {
        "mitre_id":     "G0034",
        "name":         "Sandworm Team",
        "aliases":      ["Voodoo Bear", "IRIDIUM", "Telebots", "BlackEnergy Group",
                         "ELECTRUM", "Quedagh", "TEMP.Noble", "Iron Viking"],
        "country":      "RU",
        "motivation":   "destruction, espionage",
        "mandiant_id":  "APT44",
        "crowdstrike":  "Voodoo Bear",
        "description":  "Russian GRU Unit 74455. Responsible for NotPetya, Industroyer, "
                        "Olympic Destroyer. Critical infrastructure targeting.",
        "cisa_refs":    ["AA20-296A", "AA22-076A"],
    },
    "CDB-RU-02": {
        "mitre_id":     "G0007",
        "name":         "APT28",
        "aliases":      ["Fancy Bear", "STRONTIUM", "Sofacy", "Sednit", "Pawn Storm",
                         "Iron Twilight", "FROZENLAKE"],
        "country":      "RU",
        "motivation":   "espionage, influence operations",
        "mandiant_id":  "APT28",
        "crowdstrike":  "Fancy Bear",
        "description":  "Russian GRU Unit 26165. Focus on government, military, media targets.",
        "cisa_refs":    ["AA20-336A"],
    },
    "CDB-RU-03": {
        "mitre_id":     "G0016",
        "name":         "APT29",
        "aliases":      ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard",
                         "YTTRIUM", "Iron Hemlock", "NobleBaron"],
        "country":      "RU",
        "motivation":   "espionage",
        "mandiant_id":  "APT29",
        "crowdstrike":  "Cozy Bear",
        "description":  "Russian SVR. SolarWinds/SUNBURST, Microsoft breach 2024.",
        "cisa_refs":    ["AA21-008A", "AA24-057A"],
    },
    "CDB-RU-04": {
        "mitre_id":     "G0010",
        "name":         "Turla",
        "aliases":      ["Snake", "Venomous Bear", "WATERBUG", "Uroburos", "KRYPTON",
                         "Belugasturgeon", "Iron Hunter"],
        "country":      "RU",
        "motivation":   "espionage",
        "mandiant_id":  "G0010",
        "crowdstrike":  "Venomous Bear",
        "description":  "Russian FSB. Long-term espionage, diplomatic and government targets.",
    },

    # ── NORTH KOREA ────────────────────────────────────────────────────────────
    "CDB-KP-01": {
        "mitre_id":     "G0032",
        "name":         "Lazarus Group",
        "aliases":      ["HIDDEN COBRA", "Zinc", "Diamond Sleet", "Labyrinth Chollima",
                         "APT38", "WhisperGate", "NICKEL ACADEMY"],
        "country":      "KP",
        "motivation":   "financial, espionage",
        "mandiant_id":  "APT38",
        "crowdstrike":  "Labyrinth Chollima",
        "description":  "DPRK RGB. Crypto theft ($3B+), financial heists, espionage.",
        "cisa_refs":    ["AA21-048A", "AA22-108A"],
    },
    "CDB-KP-02": {
        "mitre_id":     "G0122",
        "name":         "Silent Chollima",
        "aliases":      ["Kimsuky", "Thallium", "Black Banshee", "Velvet Chollima",
                         "TA406", "APT43"],
        "country":      "KP",
        "motivation":   "espionage, financial",
        "mandiant_id":  "APT43",
        "crowdstrike":  "Velvet Chollima",
        "description":  "DPRK RGB. Think tanks, policy research, crypto theft.",
        "cisa_refs":    ["AA20-301A"],
    },

    # ── CHINA ──────────────────────────────────────────────────────────────────
    "CDB-CN-01": {
        "mitre_id":     "G0096",
        "name":         "APT41",
        "aliases":      ["Double Dragon", "WINNTI", "BARIUM", "Brass Typhoon",
                         "Wicked Spider", "Earth Baku"],
        "country":      "CN",
        "motivation":   "espionage, financial",
        "mandiant_id":  "APT41",
        "crowdstrike":  "Wicked Panda",
        "description":  "Chinese MSS-affiliated. Dual espionage and financial operations.",
        "cisa_refs":    ["AA21-201A"],
    },
    "CDB-CN-02": {
        "mitre_id":     "G0006",
        "name":         "APT1",
        "aliases":      ["Comment Crew", "Comment Group", "Byzantine Candor", "GIF89a",
                         "ShadyRAT", "Shanghai Group"],
        "country":      "CN",
        "motivation":   "espionage",
        "mandiant_id":  "APT1",
        "crowdstrike":  "Comment Panda",
        "description":  "Chinese PLA Unit 61398. Large-scale IP theft from US defence, aerospace.",
    },
    "CDB-CN-03": {
        "mitre_id":     "G1045",
        "name":         "Volt Typhoon",
        "aliases":      ["Bronze Silhouette", "Vanguard Panda", "DEV-0391", "UNC3236"],
        "country":      "CN",
        "motivation":   "pre-positioning, critical infrastructure",
        "mandiant_id":  "UNC3236",
        "crowdstrike":  "Vanguard Panda",
        "description":  "Chinese state. Pre-positioning in US critical infrastructure (CISA AA24-038A).",
        "cisa_refs":    ["AA24-038A"],
    },

    # ── IRAN ───────────────────────────────────────────────────────────────────
    "CDB-IR-01": {
        "mitre_id":     "G0003",
        "name":         "APT33",
        "aliases":      ["Elfin", "Refined Kitten", "HOLMIUM", "Peach Sandstorm",
                         "MAGNALLIUM"],
        "country":      "IR",
        "motivation":   "espionage, disruption",
        "mandiant_id":  "APT33",
        "crowdstrike":  "Refined Kitten",
        "description":  "Iranian IRGC. Petrochemical, aerospace, and aviation targeting.",
        "cisa_refs":    ["AA21-321A"],
    },
    "CDB-IR-02": {
        "mitre_id":     "G0049",
        "name":         "APT34",
        "aliases":      ["OilRig", "Helix Kitten", "COBALT GYPSY", "Crambus", "Hazel Sandstorm"],
        "country":      "IR",
        "motivation":   "espionage",
        "mandiant_id":  "APT34",
        "crowdstrike":  "Helix Kitten",
        "description":  "Iranian Ministry of Intelligence. Middle East government/finance targeting.",
    },

    # ── FINANCIAL CRIME ────────────────────────────────────────────────────────
    "CDB-FIN-07": {
        "mitre_id":     "G0046",
        "name":         "FIN7",
        "aliases":      ["Carbanak", "Carbon Spider", "GOLD NIAGARA", "Sangria Tempest",
                         "ITG14", "Anunak"],
        "country":      "UNKNOWN",
        "motivation":   "financial",
        "mandiant_id":  "FIN7",
        "crowdstrike":  "Carbon Spider",
        "description":  "Financially motivated. Restaurant, hospitality, retail POS malware; $1B+ stolen.",
    },
    "CDB-FIN-08": {
        "mitre_id":     "G0083",
        "name":         "SilverTerrier",
        "aliases":      ["GOLD SKYLINE"],
        "country":      "NG",
        "motivation":   "financial",
        "mandiant_id":  "G0083",
        "crowdstrike":  "Gold Skyline",
        "description":  "Nigerian BEC and commodity malware actors. Business email compromise focus.",
    },

    # ── RANSOMWARE ─────────────────────────────────────────────────────────────
    "CDB-RAN-01": {
        "mitre_id":     "G0102",
        "name":         "Wizard Spider",
        "aliases":      ["GOLD BLACKBURN", "ITG23", "Grim Spider", "UNC1878"],
        "country":      "RU",
        "motivation":   "financial (ransomware)",
        "mandiant_id":  "ITG23",
        "crowdstrike":  "Wizard Spider",
        "description":  "Ryuk/Conti/TrickBot operators. Healthcare, government, enterprise targeting.",
    },
    "CDB-RAN-02": {
        "mitre_id":     "G0127",
        "name":         "TA505",
        "aliases":      ["Hive0065", "GOLD EVEREST", "Evil Corp affiliate"],
        "country":      "UNKNOWN",
        "motivation":   "financial (ransomware, banking trojan)",
        "crowdstrike":  "Evil Corp",
        "description":  "Prolific financially motivated actor. Dridex, FlawedAmmyy, Clop ransomware.",
    },

    # ── GENERIC / UNATTRIBUTED ─────────────────────────────────────────────────
    "CDB-UNATTR-CVE": {
        "mitre_id":     None,
        "name":         "Unattributed CVE Exploiter",
        "aliases":      [],
        "country":      "UNKNOWN",
        "motivation":   "unknown",
        "description":  "Exploitation activity not yet attributed to a named threat actor. "
                        "CVE exploitation may be opportunistic scanning or targeted attack.",
    },
    "CDB-UNATTR-RAN": {
        "mitre_id":     None,
        "name":         "Unattributed Ransomware Operator",
        "aliases":      [],
        "country":      "UNKNOWN",
        "motivation":   "financial (ransomware)",
        "description":  "Ransomware deployment not yet attributed to a specific RaaS group "
                        "or operator. Awaiting further forensic analysis.",
    },
    "CDB-UNATTR-APT": {
        "mitre_id":     None,
        "name":         "Unattributed APT Cluster",
        "aliases":      [],
        "country":      "UNKNOWN",
        "motivation":   "espionage",
        "description":  "Advanced persistent threat activity cluster not yet formally attributed. "
                        "Characteristics suggest state-sponsored origin.",
    },
}

# ── Alias reverse-lookup (builds automatically from the map above) ────────────
_ALIAS_TO_CDB: Dict[str, str] = {}
for _code, _data in CDB_ACTOR_MAP.items():
    for _alias in _data.get("aliases", []):
        _ALIAS_TO_CDB[_alias.lower()] = _code
    if _data.get("name"):
        _ALIAS_TO_CDB[_data["name"].lower()] = _code
    if _data.get("mandiant_id"):
        _ALIAS_TO_CDB[_data["mandiant_id"].lower()] = _code
    if _data.get("crowdstrike"):
        _ALIAS_TO_CDB[_data["crowdstrike"].lower()] = _code


def resolve_actor(actor_tag: str) -> Optional[Dict[str, Any]]:
    """
    Resolve a CDB actor code or alias to full MITRE ATT&CK attribution record.
    Returns None if not found.
    """
    if not actor_tag:
        return None
    # Direct CDB code lookup (case-insensitive)
    upper = actor_tag.upper().strip()
    if upper in CDB_ACTOR_MAP:
        return {**CDB_ACTOR_MAP[upper], "cdb_code": upper}
    # Alias / vendor name reverse-lookup
    lower = actor_tag.lower().strip()
    cdb = _ALIAS_TO_CDB.get(lower)
    if cdb and cdb in CDB_ACTOR_MAP:
        return {**CDB_ACTOR_MAP[cdb], "cdb_code": cdb}
    return None


def enrich_feed_actors(items: List[Dict]) -> int:
    """
    Enrich all feed items with MITRE ATT&CK group attribution.
    Adds fields: mitre_group_id, mitre_group_name, mitre_aliases, actor_country,
                 actor_motivation, crowdstrike_name, mandiant_id.
    Returns count of items enriched.
    """
    enriched = 0
    for item in items:
        actor_tag = str(item.get("actor_tag") or "").strip()
        if not actor_tag:
            continue
        info = resolve_actor(actor_tag)
        if info is None:
            continue
        # Only enrich — don't overwrite existing MITRE data
        if item.get("mitre_group_id") and item.get("mitre_group_id") != "UNKNOWN":
            continue
        if info.get("mitre_id"):
            item["mitre_group_id"]   = info["mitre_id"]
        item["mitre_group_name"]     = info.get("name", actor_tag)
        item["mitre_group_aliases"]  = info.get("aliases", [])[:5]   # top 5 aliases
        item["actor_country"]        = info.get("country", "UNKNOWN")
        item["actor_motivation"]     = info.get("motivation", "unknown")
        if info.get("crowdstrike"):
            item["crowdstrike_name"] = info["crowdstrike"]
        if info.get("mandiant_id"):
            item["mandiant_id"]      = info["mandiant_id"]
        if info.get("cisa_refs"):
            item["cisa_advisory_refs"] = info["cisa_refs"]
        enriched += 1

    if enriched:
        log.info("[ACTOR-MAPPING] Enriched %d items with MITRE ATT&CK group attribution", enriched)
    return enriched


def get_actor_summary(actor_tag: str) -> str:
    """Return a human-readable attribution summary for an actor code."""
    info = resolve_actor(actor_tag)
    if not info:
        return f"{actor_tag} — Attribution pending further analysis"
    parts = [f"{info.get('name', actor_tag)}"]
    if info.get("mitre_id"):
        parts.append(f"MITRE ATT&CK: {info['mitre_id']}")
    if info.get("country") and info["country"] != "UNKNOWN":
        country_names = {
            "RU": "Russia", "CN": "China", "KP": "North Korea",
            "IR": "Iran", "NG": "Nigeria",
        }
        parts.append(f"Country: {country_names.get(info['country'], info['country'])}")
    if info.get("mandiant_id"):
        parts.append(f"Mandiant: {info['mandiant_id']}")
    if info.get("crowdstrike"):
        parts.append(f"CrowdStrike: {info['crowdstrike']}")
    if info.get("aliases"):
        parts.append(f"Also known as: {', '.join(info['aliases'][:3])}")
    return " | ".join(parts)


# ── Standalone runner ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    _REPO = Path(__file__).resolve().parent.parent
    _FEED = _REPO / "api" / "feed.json"
    _MANIFEST = _REPO / "data" / "stix" / "feed_manifest.json"

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [actor-mapping] %(levelname)s: %(message)s")

    # Enrich feed.json
    for _path in [_FEED, _MANIFEST]:
        if not _path.exists():
            continue
        try:
            _data = json.loads(_path.read_text(encoding="utf-8"))
            _items = _data if isinstance(_data, list) else _data.get("items", [])
            _count = enrich_feed_actors(_items)
            if _count > 0:
                import os, tempfile
                _payload = json.dumps(_data if isinstance(_data, list) else _data,
                                      indent=2, ensure_ascii=False)
                _tmp = _path.with_suffix(".tmp")
                _tmp.write_text(_payload, encoding="utf-8")
                os.replace(_tmp, _path)
                log.info("Saved %s (%d items enriched)", _path.name, _count)
        except Exception as _e:
            log.error("Failed to enrich %s: %s", _path.name, _e)
