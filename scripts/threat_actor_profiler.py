#!/usr/bin/env python3
"""
scripts/threat_actor_profiler.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Threat Actor Profiler v1.0
===============================================================
Builds structured profiles of threat actors from feed manifest data.

Capabilities:
  - Aggregate threat intel by actor fingerprint (matches master_p0_fix.py output)
  - Map actors to MITRE ATT&CK groups (APT28, Lazarus, Sandworm, etc.)
  - Track TTPs, campaigns, IOCs, geographic attribution per actor
  - Compute actor threat score and trend (increasing/stable/decreasing activity)
  - PRO+ tier feature (FREE gets actor name only, no detail)
  - STIX 2.1 Threat Actor object generation (ENTERPRISE+)
  - Actor-specific alert integration with alert_engine.py

Output:
  - data/actor_profiles.json  (structured actor registry)
  - CLI: search by actor name, list top actors, generate STIX

MITRE ATT&CK Group mapping sourced from public MITRE CTI repository.

Zero-Regression Mandates:
  - Never modifies feed_manifest.json
  - Never deletes historical actor profiles (append + merge only)
  - Atomic profile writes

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] ACTOR-PROFILER %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("CDB-ACTOR")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR         = Path(__file__).resolve().parent.parent
FEED_MANIFEST    = BASE_DIR / "data" / "feed_manifest.json"
ACTOR_PROFILES   = BASE_DIR / "data" / "actor_profiles.json"

# ---------------------------------------------------------------------------
# MITRE ATT&CK Group Database (curated from public MITRE CTI)
# ---------------------------------------------------------------------------
MITRE_GROUPS: Dict[str, Dict] = {
    "APT28": {
        "mitre_id":    "G0007",
        "aliases":     ["Fancy Bear", "Pawn Storm", "Sofacy", "Sednit", "STRONTIUM", "Tsar Team"],
        "attribution": "Russia (GRU)",
        "motivation":  ["espionage", "political"],
        "targets":     ["government", "military", "political parties", "NATO"],
        "ttps":        ["T1566", "T1078", "T1098", "T1190", "T1027"],
        "since":       2004,
    },
    "APT29": {
        "mitre_id":    "G0016",
        "aliases":     ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
        "attribution": "Russia (SVR)",
        "motivation":  ["espionage", "intelligence_gathering"],
        "targets":     ["government", "healthcare", "technology", "think tanks"],
        "ttps":        ["T1566", "T1195", "T1078", "T1098", "T1071"],
        "since":       2008,
    },
    "LAZARUS": {
        "mitre_id":    "G0032",
        "aliases":     ["HIDDEN COBRA", "Guardians of Peace", "ZINC", "Diamond Sleet"],
        "attribution": "North Korea (RGB)",
        "motivation":  ["financial", "espionage", "sabotage"],
        "targets":     ["cryptocurrency", "financial", "defense", "media"],
        "ttps":        ["T1059", "T1027", "T1070", "T1105", "T1071"],
        "since":       2009,
    },
    "SANDWORM": {
        "mitre_id":    "G0034",
        "aliases":     ["Voodoo Bear", "ELECTRUM", "TeleBots", "Seashell Blizzard"],
        "attribution": "Russia (GRU Unit 74455)",
        "motivation":  ["sabotage", "espionage", "disruption"],
        "targets":     ["energy", "critical infrastructure", "Ukraine", "government"],
        "ttps":        ["T1190", "T1059", "T1485", "T1489", "T1071"],
        "since":       2009,
    },
    "APT41": {
        "mitre_id":    "G0096",
        "aliases":     ["Double Dragon", "Winnti", "Barium", "Earth Baku"],
        "attribution": "China (MSS)",
        "motivation":  ["espionage", "financial"],
        "targets":     ["healthcare", "gaming", "technology", "telecom"],
        "ttps":        ["T1195", "T1190", "T1078", "T1059", "T1027"],
        "since":       2012,
    },
    "APT40": {
        "mitre_id":    "G0065",
        "aliases":     ["Bronze Mohawk", "TEMP.Periscope", "Leviathan", "Kryptonite Panda"],
        "attribution": "China (MSS Hainan)",
        "motivation":  ["espionage", "maritime_intelligence"],
        "targets":     ["maritime", "defense", "aviation", "government"],
        "ttps":        ["T1566", "T1190", "T1105", "T1071", "T1078"],
        "since":       2013,
    },
    "BLACKCAT": {
        "mitre_id":    "G1016",
        "aliases":     ["ALPHV", "Noberus"],
        "attribution": "Criminal (Russia-nexus)",
        "motivation":  ["financial", "ransomware_as_a_service"],
        "targets":     ["healthcare", "critical infrastructure", "enterprise"],
        "ttps":        ["T1486", "T1490", "T1489", "T1059", "T1070"],
        "since":       2021,
    },
    "SCATTERED_SPIDER": {
        "mitre_id":    "G1015",
        "aliases":     ["Muddled Libra", "Star Fraud", "UNC3944", "Octo Tempest"],
        "attribution": "Criminal (English-speaking)",
        "motivation":  ["financial", "data_theft"],
        "targets":     ["hospitality", "retail", "telecom", "cloud"],
        "ttps":        ["T1621", "T1078", "T1534", "T1059", "T1486"],
        "since":       2022,
    },
    "CLOP": {
        "mitre_id":    "G0142",
        "aliases":     ["TA505", "Lace Tempest", "FIN11"],
        "attribution": "Criminal (Russia-nexus)",
        "motivation":  ["financial", "ransomware", "extortion"],
        "targets":     ["enterprise", "healthcare", "energy", "MOVEit_users"],
        "ttps":        ["T1190", "T1486", "T1041", "T1059", "T1070"],
        "since":       2019,
    },
    "VOLT_TYPHOON": {
        "mitre_id":    "G1017",
        "aliases":     ["Bronze Silhouette", "Dev-0391", "Vanguard Panda"],
        "attribution": "China (PLA)",
        "motivation":  ["pre_positioning", "critical_infrastructure"],
        "targets":     ["US critical infrastructure", "military", "utilities"],
        "ttps":        ["T1190", "T1133", "T1078", "T1021", "T1070"],
        "since":       2021,
    },
}

# Build reverse alias → canonical name lookup
_ALIAS_MAP: Dict[str, str] = {}
for _canonical, _info in MITRE_GROUPS.items():
    _ALIAS_MAP[_canonical.lower()] = _canonical
    for _alias in _info.get("aliases", []):
        _ALIAS_MAP[_alias.lower()] = _canonical


def resolve_actor_name(raw_name: str) -> Tuple[str, Optional[str]]:
    """
    Resolve an actor name/alias to canonical MITRE name.
    Returns (canonical_name, mitre_id_or_None)
    """
    if not raw_name or raw_name.upper() in ("UNATTRIBUTED", "UNKNOWN", "N/A", ""):
        return "UNATTRIBUTED", None

    normalized = raw_name.lower().strip()

    # Direct match
    if normalized in _ALIAS_MAP:
        canonical = _ALIAS_MAP[normalized]
        return canonical, MITRE_GROUPS[canonical]["mitre_id"]

    # Partial match (fuzzy)
    for alias, canonical in _ALIAS_MAP.items():
        if alias in normalized or normalized in alias:
            return canonical, MITRE_GROUPS[canonical]["mitre_id"]

    # Unknown actor — return as-is (cleaned)
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\. ]', '', raw_name)[:50].strip()
    return cleaned or "UNATTRIBUTED", None


# ---------------------------------------------------------------------------
# Feed Manifest Loader
# ---------------------------------------------------------------------------

def _load_manifest() -> List[Dict]:
    try:
        if FEED_MANIFEST.exists():
            data = json.loads(FEED_MANIFEST.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
            return data.get("items", [])
    except Exception as e:
        logger.warning(f"Manifest load error: {e}")
    return []


# ---------------------------------------------------------------------------
# Actor Profile Builder
# ---------------------------------------------------------------------------

def build_actor_profiles(
    manifest_items: Optional[List[Dict]] = None,
    merge_existing: bool = True,
) -> Dict[str, Dict]:
    """
    Scan feed manifest and build/update actor profiles.
    Each profile aggregates:
      - Total advisories mentioning this actor
      - Unique IOCs attributed to actor
      - MITRE TTPs seen in actor campaigns
      - Risk score trend (max, average, recent)
      - Active campaign detection (last 30 days)
      - STIX-ready threat actor metadata

    Returns: {actor_canonical_name: profile_dict}
    """
    if manifest_items is None:
        manifest_items = _load_manifest()

    # Load existing profiles for merge
    existing: Dict[str, Dict] = {}
    if merge_existing and ACTOR_PROFILES.exists():
        try:
            existing = json.loads(ACTOR_PROFILES.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    profiles: Dict[str, Dict] = {}
    now = datetime.now(timezone.utc)
    cutoff_30d = (now - timedelta(days=30)).isoformat()

    for item in manifest_items:
        # Extract actor from apex_ai or direct field
        apex_ai    = item.get("apex_ai", {})
        raw_actor  = apex_ai.get("threat_actor", item.get("threat_actor", ""))

        if not raw_actor or not isinstance(raw_actor, str):
            continue

        canonical, mitre_id = resolve_actor_name(raw_actor)
        if canonical == "UNATTRIBUTED":
            continue

        if canonical not in profiles:
            # Start new profile
            profiles[canonical] = _init_profile(canonical, mitre_id, now.isoformat())

        p = profiles[canonical]

        # Increment advisory count
        p["advisory_count"] += 1
        p["last_seen"] = max(p["last_seen"], item.get("published", now.isoformat())[:19])

        # Risk tracking
        risk = float(item.get("risk_score", 0) or 0)
        p["risk_scores"].append(risk)
        p["max_risk_score"] = max(p["max_risk_score"], risk)

        # IOC aggregation
        iocs = item.get("iocs", [])
        if isinstance(iocs, list):
            p["ioc_count"] += len(iocs)
            p["iocs"].extend(iocs[:5])  # Sample only to avoid bloat

        # MITRE TTP collection
        tactics = apex_ai.get("mitre_tactics", [])
        if isinstance(tactics, list):
            p["mitre_tactics"].update(tactics)
        ttps = item.get("mitre_techniques", [])
        if isinstance(ttps, list):
            p["mitre_ttps"].update(ttps)

        # Campaign detection
        title = item.get("title", "")
        source = item.get("source", "")
        p["campaign_mentions"].append({
            "title":     title[:80],
            "source":    source,
            "published": item.get("published", "")[:19],
            "risk":      risk,
        })

        # Active campaign flag (any advisory in last 30 days)
        pub_date = item.get("published", "")
        if pub_date >= cutoff_30d:
            p["active_last_30d"] = True

        # Severity tracking
        sev = item.get("severity", "").upper()
        if sev:
            p["severity_counts"][sev] = p["severity_counts"].get(sev, 0) + 1

    # Finalize profiles
    for canonical, p in profiles.items():
        p["mitre_tactics"]    = sorted(p["mitre_tactics"])
        p["mitre_ttps"]       = sorted(p["mitre_ttps"])[:20]
        p["iocs"]             = list(set(p["iocs"]))[:50]  # Deduplicate, cap

        # Compute average risk
        scores = p.pop("risk_scores", [])
        p["avg_risk_score"] = round(sum(scores) / len(scores), 2) if scores else 0

        # Trim campaign mentions (latest 10)
        p["campaign_mentions"] = sorted(
            p["campaign_mentions"],
            key=lambda x: x.get("published", ""),
            reverse=True,
        )[:10]

        # Threat score (0-100): weighted composite
        threat_score = min(100, int(
            (p["advisory_count"] * 2)
            + (p["max_risk_score"] * 5)
            + (len(p["mitre_ttps"]) * 1)
            + (p["ioc_count"] * 0.1)
            + (10 if p["active_last_30d"] else 0)
        ))
        p["threat_score"] = threat_score

        # Trend vs. existing profile
        if canonical in existing:
            old_count = existing[canonical].get("advisory_count", 0)
            p["trend"] = (
                "INCREASING" if p["advisory_count"] > old_count * 1.1
                else "DECREASING" if p["advisory_count"] < old_count * 0.9
                else "STABLE"
            )
        else:
            p["trend"] = "NEW"

        # Enrich with MITRE group data if known
        if canonical in MITRE_GROUPS:
            mg = MITRE_GROUPS[canonical]
            p["attribution"]  = mg.get("attribution", "Unknown")
            p["motivation"]   = mg.get("motivation", [])
            p["known_targets"]= mg.get("targets", [])
            p["active_since"] = mg.get("since")
            p["known_aliases"]= mg.get("aliases", [])

        p["profile_updated"] = now.isoformat()

    # Merge with existing (preserve historical data not seen in current manifest)
    for old_actor, old_profile in existing.items():
        if old_actor not in profiles:
            # Actor not seen in current scan — preserve but mark
            old_profile["trend"] = "NOT_SEEN_IN_CURRENT_SCAN"
            profiles[old_actor] = old_profile

    return profiles


def _init_profile(canonical: str, mitre_id: Optional[str], now: str) -> Dict:
    """Initialize an empty actor profile dict."""
    return {
        "canonical_name":    canonical,
        "mitre_id":          mitre_id or "N/A",
        "advisory_count":    0,
        "ioc_count":         0,
        "iocs":              [],
        "risk_scores":       [],  # temp, replaced with avg + max
        "max_risk_score":    0.0,
        "avg_risk_score":    0.0,
        "mitre_tactics":     set(),
        "mitre_ttps":        set(),
        "severity_counts":   {},
        "campaign_mentions": [],
        "active_last_30d":   False,
        "threat_score":      0,
        "trend":             "NEW",
        "first_seen":        now,
        "last_seen":         "",
        "attribution":       "Unknown",
        "motivation":        [],
        "known_targets":     [],
        "active_since":      None,
        "known_aliases":     [],
        "profile_updated":   now,
    }


def save_actor_profiles(profiles: Dict[str, Dict]) -> bool:
    """Atomically save actor profiles to disk."""
    try:
        ACTOR_PROFILES.parent.mkdir(parents=True, exist_ok=True)
        # Convert sets to lists for JSON serialization
        serializable = {}
        for actor, p in profiles.items():
            p_copy = dict(p)
            p_copy["mitre_tactics"] = sorted(list(p_copy.get("mitre_tactics", [])))
            p_copy["mitre_ttps"]    = sorted(list(p_copy.get("mitre_ttps", [])))
            serializable[actor] = p_copy

        tmp = ACTOR_PROFILES.with_suffix(".tmp")
        tmp.write_text(json.dumps(serializable, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        tmp.replace(ACTOR_PROFILES)
        logger.info(f"Saved {len(profiles)} actor profiles")
        return True
    except Exception as e:
        logger.error(f"Actor profile save failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Query Functions
# ---------------------------------------------------------------------------

def load_actor_profiles() -> Dict[str, Dict]:
    """Load persisted actor profiles."""
    try:
        if ACTOR_PROFILES.exists():
            return json.loads(ACTOR_PROFILES.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Actor profiles load error: {e}")
    return {}


def get_actor_profile(actor_name: str, tier: str = "FREE") -> Dict:
    """
    Get full profile for a specific actor.
    Applies tier-based field filtering.
    """
    profiles = load_actor_profiles()
    canonical, _ = resolve_actor_name(actor_name)

    if canonical not in profiles:
        return {
            "error": "actor_not_found",
            "actor": actor_name,
            "canonical": canonical,
            "hint": f"Known actors: {', '.join(list(profiles.keys())[:10])}",
        }

    p = dict(profiles[canonical])

    # FREE tier: strip sensitive detail
    if tier == "FREE":
        p.pop("iocs", None)
        p.pop("campaign_mentions", None)
        p.pop("mitre_ttps", None)
        p["tier_limited"] = True
        p["upgrade_cta"] = {
            "message": "Full actor profiles including IOCs, TTPs, and campaign history require PRO.",
            "url": "https://intel.cyberdudebivash.com/get-api-key.html?plan=pro&utm_source=actor_profile",
        }

    return p


def list_top_actors(
    n: int = 10,
    tier: str = "FREE",
    sort_by: str = "threat_score",
    active_only: bool = False,
) -> List[Dict]:
    """
    List top N threat actors sorted by threat_score, advisory_count, or risk.
    """
    profiles = load_actor_profiles()

    actors = list(profiles.values())
    if active_only:
        actors = [a for a in actors if a.get("active_last_30d")]

    actors.sort(key=lambda x: x.get(sort_by, 0), reverse=True)
    actors = actors[:n]

    # Apply tier filter
    if tier == "FREE":
        stripped = []
        for a in actors:
            stripped.append({
                "canonical_name":  a["canonical_name"],
                "threat_score":    a["threat_score"],
                "advisory_count":  a["advisory_count"],
                "active_last_30d": a["active_last_30d"],
                "trend":           a["trend"],
                "attribution":     a.get("attribution", "Unknown"),
                "tier_limited":    True,
            })
        return stripped

    return actors


def search_actors_by_ttp(ttp: str) -> List[str]:
    """Return actor names that use a specific MITRE TTP."""
    profiles = load_actor_profiles()
    return [
        name for name, p in profiles.items()
        if ttp.upper() in [t.upper() for t in p.get("mitre_ttps", [])]
    ]


def get_actor_iocs(actor_name: str, tier: str = "PRO") -> Dict:
    """Return IOCs attributed to a specific actor (PRO+ only)."""
    if tier == "FREE":
        return {
            "error": "tier_insufficient",
            "required_tier": "PRO",
            "upgrade_url": "https://intel.cyberdudebivash.com/get-api-key.html?plan=pro",
        }

    p = get_actor_profile(actor_name, tier=tier)
    if "error" in p:
        return p

    return {
        "actor":      p["canonical_name"],
        "ioc_count":  p.get("ioc_count", 0),
        "iocs":       p.get("iocs", []),
        "attribution": p.get("attribution", "Unknown"),
    }


# ---------------------------------------------------------------------------
# STIX 2.1 Threat Actor Object (ENTERPRISE+)
# ---------------------------------------------------------------------------

def build_stix_threat_actor(actor_name: str, tier: str = "ENTERPRISE") -> Dict:
    """
    Generate a STIX 2.1 threat-actor object for integration with SIEM/SOAR.
    ENTERPRISE/MSSP only.
    """
    if tier not in ("ENTERPRISE", "MSSP"):
        return {
            "error": "tier_insufficient",
            "required_tier": "ENTERPRISE",
            "upgrade_url": "https://intel.cyberdudebivash.com/contact-enterprise.html",
        }

    import uuid
    p = get_actor_profile(actor_name, tier="ENTERPRISE")
    if "error" in p:
        return p

    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": f"threat-actor--{str(uuid.uuid4())}",
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": p["canonical_name"],
        "description": (
            f"Threat actor tracked by SENTINEL APEX. "
            f"Attribution: {p.get('attribution', 'Unknown')}. "
            f"Last seen: {p.get('last_seen', 'N/A')}. "
            f"Advisory count: {p.get('advisory_count', 0)}."
        ),
        "aliases": p.get("known_aliases", []),
        "sophistication": "advanced",
        "resource_level": "government" if "APT" in actor_name.upper() else "criminal-infrastructure",
        "primary_motivation": p.get("motivation", ["unknown"])[0] if p.get("motivation") else "unknown",
        "goals": p.get("motivation", []),
        "labels": ["apt"] if "APT" in actor_name.upper() else ["criminal"],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": p.get("mitre_id", "N/A"),
                "url": f"https://attack.mitre.org/groups/{p.get('mitre_id', '')}",
            },
            {
                "source_name": "sentinel-apex",
                "url": "https://intel.cyberdudebivash.com",
                "description": f"SENTINEL APEX actor profile — {p['canonical_name']}",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Main Run Function
# ---------------------------------------------------------------------------

def run_profiler(
    manifest_items: Optional[List[Dict]] = None,
    save: bool = True,
    tier: str = "PRO",
) -> Dict:
    """
    Full profiler run: scan manifest, build profiles, save.
    Returns summary dict.
    """
    ts_start = time.time()
    profiles = build_actor_profiles(manifest_items=manifest_items, merge_existing=True)

    if save:
        save_actor_profiles(profiles)

    # Summary stats
    active_actors    = sum(1 for p in profiles.values() if p.get("active_last_30d"))
    known_apt        = sum(1 for name in profiles if name in MITRE_GROUPS)
    top_by_threat    = sorted(profiles.values(), key=lambda p: p.get("threat_score", 0), reverse=True)[:3]

    return {
        "total_actors":      len(profiles),
        "active_last_30d":   active_actors,
        "known_apt_groups":  known_apt,
        "new_actors":        sum(1 for p in profiles.values() if p.get("trend") == "NEW"),
        "increasing_actors": sum(1 for p in profiles.values() if p.get("trend") == "INCREASING"),
        "top_threat_actors": [
            {
                "name":         p["canonical_name"],
                "threat_score": p.get("threat_score", 0),
                "advisory_count": p.get("advisory_count", 0),
                "active":       p.get("active_last_30d", False),
            }
            for p in top_by_threat
        ],
        "profile_file":  str(ACTOR_PROFILES),
        "runtime_ms":    round((time.time() - ts_start) * 1000),
        "generated_at":  datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse, sys

    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH SENTINEL APEX — Threat Actor Profiler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/threat_actor_profiler.py --run
  python scripts/threat_actor_profiler.py --actor APT28
  python scripts/threat_actor_profiler.py --list --n 10
  python scripts/threat_actor_profiler.py --list --active-only
  python scripts/threat_actor_profiler.py --ttp T1566
  python scripts/threat_actor_profiler.py --stix APT29 --tier ENTERPRISE
  python scripts/threat_actor_profiler.py --iocs Lazarus --tier PRO
        """,
    )
    parser.add_argument("--run",         action="store_true", help="Build/refresh all actor profiles from manifest")
    parser.add_argument("--actor",       type=str, help="Get profile for specific actor")
    parser.add_argument("--list",        action="store_true", help="List top actors")
    parser.add_argument("--n",           type=int, default=10, help="Number of actors to list")
    parser.add_argument("--active-only", action="store_true", help="Only show actors active in last 30 days")
    parser.add_argument("--ttp",         type=str, help="Find actors using a specific MITRE TTP")
    parser.add_argument("--stix",        type=str, help="Generate STIX object for actor")
    parser.add_argument("--iocs",        type=str, help="Get IOCs for actor (PRO+)")
    parser.add_argument("--tier",        type=str, default="PRO",
                        choices=["FREE", "PRO", "ENTERPRISE", "MSSP"])
    parser.add_argument("--json",        action="store_true", help="Output JSON")
    parser.add_argument("--groups",      action="store_true", help="List all MITRE groups in database")

    args = parser.parse_args()

    if args.groups:
        for name, info in MITRE_GROUPS.items():
            print(f"  {name} ({info['mitre_id']}) — {info['attribution']} | Aliases: {', '.join(info['aliases'][:3])}")
        return

    if args.run:
        result = run_profiler(tier=args.tier)
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return

    if args.list:
        actors = list_top_actors(n=args.n, tier=args.tier, active_only=args.active_only)
        if args.json:
            print(json.dumps(actors, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\n{'='*65}")
            print(f"  Top {args.n} Threat Actors — SENTINEL APEX")
            print(f"{'='*65}")
            for i, a in enumerate(actors, 1):
                active_flag = " [ACTIVE]" if a.get("active_last_30d") else ""
                print(f"  {i:2}. {a['canonical_name']:25} Score:{a.get('threat_score','?'):>4} "
                      f"Advisories:{a.get('advisory_count','?'):>4} "
                      f"Trend:{a.get('trend','?'):>12}{active_flag}")
        return

    if args.ttp:
        actors = search_actors_by_ttp(args.ttp)
        print(f"Actors using TTP {args.ttp}: {', '.join(actors) or 'None found'}")
        return

    if args.stix:
        result = build_stix_threat_actor(args.stix, tier=args.tier)
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return

    if args.iocs:
        result = get_actor_iocs(args.iocs, tier=args.tier)
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return

    if args.actor:
        profile = get_actor_profile(args.actor, tier=args.tier)
        if args.json:
            print(json.dumps(profile, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\n{'='*65}")
            print(f"  Threat Actor Profile — {profile.get('canonical_name', args.actor)}")
            print(f"{'='*65}")
            for k, v in profile.items():
                if k in ("campaign_mentions", "iocs", "upgrade_cta"):
                    continue
                print(f"  {k:25}: {v}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
