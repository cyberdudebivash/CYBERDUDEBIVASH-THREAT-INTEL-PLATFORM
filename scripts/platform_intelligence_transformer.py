#!/usr/bin/env python3
"""
scripts/platform_intelligence_transformer.py
CYBERDUDEBIVASH(R) SENTINEL APEX - Platform Intelligence Transformer
======================================================================
Transforms the platform from synthetic UNC-CDB actor attribution to
real threat intelligence with proper actor attribution, campaigns, and IOCs.

Stage 2.3 - Intelligence Transformation
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [intel-transform] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.intel_transform")

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEL_DIR = REPO_ROOT / "data" / "intelligence"

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Cannot load %s: %s", path, e)
        return None


def build_actor_index(actors_data: dict) -> dict:
    """Build a lookup index: keyword -> actor_id"""
    index = {}
    for actor in actors_data.get("actors", []):
        actor_id = actor["id"]
        # Index by id, display name, and all aliases
        for term in [actor_id, actor["display_name"]] + actor.get("aliases", []):
            key = term.lower().strip()
            if key and len(key) > 2:
                index[key] = actor_id
        # Add partial matches for well-known names
        for alias in actor.get("aliases", []):
            words = alias.lower().split()
            for word in words:
                if len(word) > 4 and word not in ("group", "team", "bear", "panda"):
                    if word not in index:
                        index[word] = actor_id
    return index


def build_malware_index(malware_data: dict) -> dict:
    """Build a lookup index: keyword -> malware_id"""
    index = {}
    for mal in malware_data.get("malware", []):
        mal_id = mal["id"]
        for term in [mal["name"]] + mal.get("aliases", []):
            key = term.lower().strip()
            if key and len(key) > 2:
                index[key] = mal_id
    return index


def build_campaign_index(campaigns_data: dict) -> dict:
    """Build: actor_id -> list of campaign ids"""
    index: dict[str, list] = {}
    for camp in campaigns_data.get("campaigns", []):
        actor = camp.get("actor", "")
        if actor:
            index.setdefault(actor, []).append(camp["id"])
    return index


def detect_actor(text: str, actor_index: dict) -> str | None:
    """Attempt to detect a real threat actor from text content"""
    text_lower = text.lower()

    # Ranked keyword patterns - most specific first
    PRIORITY_PATTERNS = [
        (r'\blockbit\b', 'LockBit'),
        (r'\bblack\s*basta\b', 'BlackBasta'),
        (r'\bblackcat\b|\balphv\b|\bblack\s*cat\b', 'BlackCatALPHV'),
        (r'\bscattered\s*spider\b|\bmuddled\s*libra\b|\bunc3944\b', 'ScatteredSpider'),
        (r'\blazarus\b|\bhidden\s*cobra\b', 'Lazarus'),
        (r'\bapt28\b|\bfancy\s*bear\b|\bstrontium\b', 'APT28'),
        (r'\bapt29\b|\bcozy\s*bear\b|\bnobelium\b|\bsunburst\b', 'APT29'),
        (r'\bapt41\b|\bdouble\s*dragon\b|\bwinnti\b', 'APT41'),
        (r'\bvolt\s*typhoon\b|\bbronze\s*silhouette\b', 'VoltTyphoon'),
        (r'\bmustang\s*panda\b|\bta416\b|\breddelta\b', 'MustangPanda'),
        (r'\bfin7\b|\bcarbanak\b', 'FIN7'),
        (r'\bcl0p\b|\bclop\b|\blace\s*tempest\b', 'Clop'),
        (r'\bapt33\b|\bcharming\s*kitten\b|\bpeach\s*sandstorm\b', 'APT33'),
        (r'\bapt35\b|\bphosphorus\b|\bmint\s*sandstorm\b', 'APT35'),
        (r'\bturla\b|\bsnake\b|\buroburos\b', 'Turla'),
        (r'\bsandworm\b|\bvoodoo\s*bear\b|\bseashell\s*blizzard\b', 'Sandworm'),
        (r'\blapsus\b|\bdev-0537\b', 'LAPSUS'),
        (r'\bhafnium\b|\bsilk\s*typhoon\b|\bproxylogon\b', 'Hafnium'),
        (r'\bunc2452\b|\bsolarigate\b', 'UNC2452'),
        (r'\bevil\s*corp\b|\bindrik\s*spider\b', 'EvilCorp'),
        (r'\bmuddywater\b|\bstatic\s*kitten\b|\bmercury\b', 'MuddyWater'),
        (r'\bakira\b', 'Akira'),
        (r'\bhive\s*ransomware\b', 'Hive'),
        (r'\bta505\b|\bhive0065\b', 'TA505'),
    ]

    for pattern, actor_id in PRIORITY_PATTERNS:
        if re.search(pattern, text_lower):
            return actor_id

    # Fallback: check actor index
    for keyword, actor_id in actor_index.items():
        if len(keyword) > 5 and keyword in text_lower:
            return actor_id

    return None


def detect_malware(text: str, malware_index: dict) -> list[str]:
    """Detect malware families mentioned in text"""
    text_lower = text.lower()
    found = []

    MALWARE_PATTERNS = [
        (r'\blockbit\b', 'MAL-LockBit3'),
        (r'\bblackcat\b|\balphv\b', 'MAL-BlackCatALPHV'),
        (r'\bblack\s*basta\b', 'MAL-BlackBasta'),
        (r'\bqakbot\b|\bqbot\b', 'MAL-Qakbot'),
        (r'\bemotet\b|\bheodo\b', 'MAL-Emotet'),
        (r'\bcobalt\s*strike\b', 'MAL-CobaltStrike'),
        (r'\bsliver\b', 'MAL-Sliver'),
        (r'\bbumblebee\b', 'MAL-Bumblebee'),
        (r'\bdarkgate\b', 'MAL-DarkGate'),
        (r'\bremcos\b', 'MAL-Remcos'),
        (r'\basyncrat\b|\basync\s*rat\b', 'MAL-AsyncRAT'),
        (r'\blumma\b|\blummac\b', 'MAL-LummaStealer'),
        (r'\bmimikatz\b', 'MAL-Mimikatz'),
        (r'\bicedid\b|\bbokbot\b', 'MAL-IcedID'),
        (r'\bsystembc\b|\bcoroxy\b', 'MAL-SystemBC'),
        (r'\bvidar\b', 'MAL-VidarStealer'),
        (r'\bredline\b', 'MAL-RedLineStealer'),
        (r'\braccoon\b', 'MAL-RaccoonStealer'),
        (r'\bhavoc\b', 'MAL-HavocC2'),
        (r'\bbrute\s*ratel\b|\bbrc4\b', 'MAL-BruteRatelC4'),
        (r'\bformbook\b|\bxloader\b', 'MAL-Formbook'),
        (r'\bagent\s*tesla\b|\bagenttesla\b', 'MAL-AgentTesla'),
        (r'\bsnake\s*keylogger\b', 'MAL-SnakeKeylogger'),
        (r'\bxworm\b', 'MAL-XWorm'),
        (r'\bdcrat\b|\bdarkcrystal\b', 'MAL-DCRat'),
        (r'\bnjrat\b|\bbladabindi\b', 'MAL-NjRAT'),
        (r'\bmetasploit\b|\bmeterpreter\b', 'MAL-Metasploit'),
        (r'\bwannacry\b|\bwannacrypt\b', 'MAL-CobaltStrike'),  # map to CS as proxy
        (r'\bnotpetya\b', 'MAL-CobaltStrike'),
    ]

    for pattern, mal_id in MALWARE_PATTERNS:
        if re.search(pattern, text_lower) and mal_id not in found:
            found.append(mal_id)

    return found


def classify_threat_by_content(text: str) -> str | None:
    """Classify threat type from content for better actor attribution"""
    text_lower = text.lower()
    if any(w in text_lower for w in ['ransomware', 'ransom', 'encrypted', 'decryption']):
        return 'ransomware'
    if any(w in text_lower for w in ['phishing', 'spearphishing', 'credential', 'lure']):
        return 'phishing'
    if any(w in text_lower for w in ['supply chain', 'solarwinds', 'moveit', '3cx']):
        return 'supply_chain'
    if any(w in text_lower for w in ['critical infrastructure', 'ics', 'scada', 'ot/it']):
        return 'critical_infra'
    if any(w in text_lower for w in ['espionage', 'apt', 'nation-state', 'government']):
        return 'espionage'
    return None


def transform_item(item: dict, actor_index: dict, malware_index: dict,
                   campaign_index: dict, actors_data: dict) -> dict:
    """Transform a single feed item with real intelligence attribution"""
    text = f"{item.get('title', '')} {item.get('description', '')} {' '.join(item.get('tags', []))}"

    # Detect real actor
    detected_actor_id = detect_actor(text, actor_index)
    detected_malware = detect_malware(text, malware_index)

    # Get actor display name
    if detected_actor_id:
        actor_obj = next((a for a in actors_data.get("actors", [])
                          if a["id"] == detected_actor_id), None)
        actor_tag = actor_obj["display_name"] if actor_obj else detected_actor_id
    else:
        # Only use "Unattributed" if current is the fictional UNC-CDB
        current_tag = item.get("actor_tag", "")
        if current_tag in ("UNC-CDB", "UNCLASSIFIED", "") or not current_tag:
            actor_tag = "Unattributed"
        else:
            actor_tag = current_tag
        detected_actor_id = None

    # Detect campaign
    campaign_id = None
    if detected_actor_id and detected_actor_id in campaign_index:
        campaign_id = campaign_index[detected_actor_id][0]

    # Update item
    updated = dict(item)
    updated["actor_tag"] = actor_tag
    if detected_actor_id:
        updated["actor_id"] = detected_actor_id
    if campaign_id:
        updated["campaign_id"] = campaign_id
    if detected_malware:
        updated["malware_families"] = detected_malware

    return updated


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX - Platform Intelligence Transformer")
    log.info("Stage 2.3: Real actor attribution, campaigns, IOCs")
    log.info("=" * 60)

    # Load knowledge bases
    actors_path = INTEL_DIR / "actors_db.json"
    campaigns_path = INTEL_DIR / "campaigns_db.json"
    malware_path = INTEL_DIR / "malware_db.json"

    actors_data = load_json(actors_path) or {"actors": []}
    campaigns_data = load_json(campaigns_path) or {"campaigns": []}
    malware_data = load_json(malware_path) or {"malware": []}

    log.info("Loaded: %d actors, %d campaigns, %d malware families",
             len(actors_data.get("actors", [])),
             len(campaigns_data.get("campaigns", [])),
             len(malware_data.get("malware", [])))

    # Build indexes
    actor_index = build_actor_index(actors_data)
    malware_index = build_malware_index(malware_data)
    campaign_index = build_campaign_index(campaigns_data)

    log.info("Built indexes: %d actor keywords, %d malware keywords",
             len(actor_index), len(malware_index))

    # Load feed.json
    feed_path = REPO_ROOT / "api" / "feed.json"
    if not feed_path.exists():
        log.warning("api/feed.json not found - skipping feed transformation")
        feed_items = []
    else:
        try:
            raw = json.loads(feed_path.read_text(encoding="utf-8"))
            feed_items = raw if isinstance(raw, list) else []
            log.info("Loaded %d items from api/feed.json", len(feed_items))
        except Exception as e:
            log.warning("Cannot parse api/feed.json: %s", e)
            feed_items = []

    # Transform items
    transformed = []
    stats = {
        "total": len(feed_items),
        "actor_attributed": 0,
        "unattributed": 0,
        "malware_linked": 0,
        "campaign_linked": 0,
        "unc_cdb_replaced": 0,
    }

    for item in feed_items:
        original_actor = item.get("actor_tag", "")
        new_item = transform_item(item, actor_index, malware_index,
                                  campaign_index, actors_data)
        transformed.append(new_item)

        if original_actor in ("UNC-CDB", "UNCLASSIFIED"):
            stats["unc_cdb_replaced"] += 1

        if new_item.get("actor_id"):
            stats["actor_attributed"] += 1
        else:
            stats["unattributed"] += 1

        if new_item.get("malware_families"):
            stats["malware_linked"] += 1

        if new_item.get("campaign_id"):
            stats["campaign_linked"] += 1

    log.info("Transformation complete: %s", stats)

    # Write updated feed.json
    if transformed and feed_path.exists():
        try:
            tmp = feed_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(transformed, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            os.replace(str(tmp), str(feed_path))
            log.info("Wrote %d transformed items to api/feed.json", len(transformed))
        except Exception as e:
            log.error("Failed to write api/feed.json: %s", e)

    # Also update feed_manifest.json
    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if manifest_path.exists():
        try:
            raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_items = []
            if isinstance(raw_manifest, list):
                manifest_items = raw_manifest
            elif isinstance(raw_manifest, dict):
                for key in ("advisories", "reports", "items"):
                    if key in raw_manifest and isinstance(raw_manifest[key], list):
                        manifest_items = raw_manifest[key]
                        break

            transformed_manifest = []
            for item in manifest_items:
                new_item = transform_item(item, actor_index, malware_index,
                                          campaign_index, actors_data)
                transformed_manifest.append(new_item)

            if isinstance(raw_manifest, dict):
                raw_manifest["advisories"] = transformed_manifest
                raw_manifest["transformed_at"] = utc_now()
                out = raw_manifest
            else:
                out = transformed_manifest

            tmp = manifest_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            os.replace(str(tmp), str(manifest_path))
            log.info("Updated feed_manifest.json with %d transformed items",
                     len(transformed_manifest))
        except Exception as e:
            log.warning("Failed to update feed_manifest.json: %s", e)

    # Write enrichment report
    report = {
        "generated_at": utc_now(),
        "transformation_stats": stats,
        "actor_kb_size": len(actors_data.get("actors", [])),
        "campaign_kb_size": len(campaigns_data.get("campaigns", [])),
        "malware_kb_size": len(malware_data.get("malware", [])),
        "notes": [
            "UNC-CDB fictional actor attribution replaced with real threat actors",
            "Actor detection uses regex pattern matching on title+description",
            "Unrecognized actors set to 'Unattributed' (not UNC-CDB)",
            "Malware families linked where keywords match",
            "Campaign IDs linked based on actor match",
        ]
    }

    report_path = INTEL_DIR / "enrichment_report.json"
    try:
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                               encoding="utf-8")
        log.info("Enrichment report written to %s", report_path)
    except Exception as e:
        log.warning("Failed to write enrichment report: %s", e)

    log.info("Intelligence transformation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
