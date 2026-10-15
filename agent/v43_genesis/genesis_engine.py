#!/usr/bin/env python3
"""
genesis_engine.py - CYBERDUDEBIVASH(R) SENTINEL APEX v43.1 (GENESIS)
=====================================================================
The 12 GENESIS engines behind the homepage "Global Cybersecurity
Intelligence Powerhouse" grid and /api/v1/intel/genesis_output.json.

Every figure is computed from the intelligence feed items (the STIX feed
manifest, or items passed in by a caller). v43.1 (2026-09-27) removed
figures that had no data behind them: an 8-region AWS "sensor network"
(events = advisories x 47, random uptime, fixed source-country shares), an
8-trap "honeypot grid" (captures = keyword hits x 12, sample credentials),
9 "monitored" dark-web sources, sandbox/scanner capability lists, attack
flows whose source country was random.choice() when unknown, TAXII URLs
and a WebSocket stream that do not exist, and Suricata/Snort/EDR "rules"
with no rule body. Capabilities the platform does not operate (sensors,
honeypots, dark-web monitoring) report operated=False with a note and the
feed-derived figure that is real (ingestion sources, KEV/exploit evidence,
ransomware/leak advisories).

Writes to data/genesis/ (canonical producer: genesis-powerhouse.yml).
scripts/regenerate_engine_data.py calls GenesisOrchestrator.compute() for
api/engines.json instead of computing a second GENESIS of its own.

Author: CyberDudeBivash Pvt. Ltd. - GOC
"""

import os, re, json, hashlib, logging, time, statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict

logger = logging.getLogger("CDB-Genesis")

MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
GENESIS_DIR = os.environ.get("GENESIS_DIR", "data/genesis")
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
TECHNIQUE_RE = re.compile(r'^T\d{4}(?:\.\d{3})?$')

# Actor tags the pipeline writes when nothing is attributed. They are not
# actors: counting them made "UNC-CDB-INGEST" a registry actor and a campaign.
_PLACEHOLDER_ACTORS = {"", "UNC-CDB-99", "UNC-CDB-INGEST", "UNC-UNKNOWN", "UNKNOWN",
                       "UNATTRIBUTED", "NONE", "NULL", "N/A", "-"}
# Country placeholders; same set as the homepage geographic panel (buildHeatmap).
_PLACEHOLDER_GEO = re.compile(r'^(unknown|unattributed|n/a|none|null|-)$', re.IGNORECASE)
_EXPLOIT_MATURITY = {"POC", "WEAPONIZED", "FUNCTIONAL", "HIGH", "ACTIVE"}
# Per-item detection fields written by scripts/detection_bundle_injector.py;
# same map as workers/intel-gateway/src/detection-registry.js RULE_FIELD.
DETECTION_FIELDS = {"sigma": "sigma_rule", "kql": "kql_query", "suricata": "suricata_rule", "yara": "yara_rule"}


def _load(p):
    try:
        with open(p, 'r', encoding='utf-8') as f: return json.load(f)
    except Exception: return None

def _save(p, d):
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        t = p + ".tmp"
        with open(t, 'w', encoding='utf-8') as f: json.dump(d, f, indent=2, default=str)
        os.replace(t, p); return True
    except Exception: return False

def _entries():
    """Advisory rows from the manifest. A list, or the first non-empty list
    under the keys the rest of the pipeline writes. An empty list is not
    guessed from another file."""
    d = _load(MANIFEST_PATH)
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        keys = ("entries", "items", "advisories", "data", "results", "reports")
        lists = [(k, d[k]) for k in keys if isinstance(d.get(k), list)]
        for _, rows in lists:
            if rows:
                return rows
        if lists:
            return lists[0][1]
    return []

def _items(entries):
    """Feed items to compute from: the given list, else the manifest."""
    return [e for e in (_entries() if entries is None else entries) if isinstance(e, dict)]

def _gid(pfx, seed):
    return f"{pfx}--{hashlib.sha256(seed.encode()).hexdigest()[:12]}"

def _now():
    return datetime.now(timezone.utc).isoformat()

def _num(v, default=0.0):
    try:
        f = float(v)
        return f if f == f else default
    except (TypeError, ValueError):
        return default

def _risk(e):
    return _num(e.get("risk_score"))

def _title(e):
    return str(e.get("title") or "")

def _ts(e) -> Optional[datetime]:
    for k in ("published_at", "timestamp", "published", "processed_at"):
        v = e.get(k)
        if not v: continue
        try:
            dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def _is_placeholder_actor(tag) -> bool:
    t = str(tag or "").strip().upper()
    return t in _PLACEHOLDER_ACTORS or t.startswith("CDB-UNATTR")

def _actor(e) -> str:
    """The item's actor tag, or "" when it is a placeholder."""
    a = str(e.get("actor_tag") or "").strip()
    return "" if _is_placeholder_actor(a) else a

def _kev(e) -> bool:
    if e.get("kev_present") is True or e.get("kev") is True: return True
    return str(e.get("kev") or "").strip().upper() in ("YES", "TRUE", "CONFIRMED")

def _public_exploit(e) -> bool:
    return (str(e.get("exploit_maturity") or "").strip().upper() in _EXPLOIT_MATURITY
            or _num(e.get("exploit_count")) > 0 or _num(e.get("poc_github_count")) > 0
            or e.get("metasploit_available") is True)

def _epss(e) -> Optional[float]:
    v = e.get("epss_score")
    if v is None: return None
    f = _num(v, -1.0)
    if f < 0: return None
    return f / 100.0 if f > 1.0 else f   # tolerate a percentage

def _techniques(e) -> List[str]:
    out = []
    for src in (e.get("attck_technique_ids") or [], e.get("mitre_tactics") or []):
        for t in src if isinstance(src, list) else []:
            tid = t if isinstance(t, str) else (t.get("id") or t.get("technique_id") or "") if isinstance(t, dict) else ""
            tid = str(tid).strip().upper()
            if TECHNIQUE_RE.match(tid) and tid not in out: out.append(tid)
    return out

def _cves(e) -> List[str]:
    found = []
    for c in list(e.get("cve_ids") or []) + CVE_RE.findall(_title(e)):
        c = str(c).upper()
        if CVE_RE.fullmatch(c) and c not in found: found.append(c)
    return found


# ===============================================================================
# G01 - INGESTION SOURCE NETWORK (no sensors are operated)
# ===============================================================================

class GlobalCyberSensorNetwork:
    """The intelligence feed sources the platform ingests. No sensor
    network is operated, so no sensor telemetry is reported."""

    NOTE = "No sensor network is operated. These are the intelligence feed sources the platform ingests."

    def generate_telemetry(self, entries=None) -> Dict:
        items = _items(entries)
        now = datetime.now(timezone.utc)
        by_src = defaultdict(lambda: {"advisories": 0, "latest": None})
        unsourced = 0
        n24 = n7 = 0
        for e in items:
            ts = _ts(e)
            if ts and ts >= now - timedelta(hours=24): n24 += 1
            if ts and ts >= now - timedelta(days=7): n7 += 1
            src = str(e.get("feed_source") or e.get("source") or "").strip()
            if not src:
                unsourced += 1; continue
            s = by_src[src[:80]]
            s["advisories"] += 1
            if ts and (s["latest"] is None or ts > s["latest"]): s["latest"] = ts
        sources = [{"source": k, "advisories": v["advisories"],
                    "latest_published": v["latest"].isoformat() if v["latest"] else None}
                   for k, v in sorted(by_src.items(), key=lambda kv: kv[1]["advisories"], reverse=True)]
        return {
            "operated": False,
            "capability": "feed_ingestion",
            "note": self.NOTE,
            "sensors_operated": 0,
            "source_count": len(sources),
            "sources": sources[:25],
            "advisories_total": len(items),
            "advisories_without_source": unsourced,
            "advisories_24h": n24,
            "advisories_7d": n7,
            "global_threat_level": self._compute_global_threat_level(items),
            "generated_at": _now(),
        }

    def _compute_global_threat_level(self, entries):
        if not entries: return "LOW"
        avg_risk = statistics.mean(_risk(e) for e in entries)
        if avg_risk >= 7: return "CRITICAL"
        if avg_risk >= 5: return "HIGH"
        if avg_risk >= 3: return "ELEVATED"
        return "LOW"


# ===============================================================================
# G02 - EXPLOITATION EVIDENCE (no honeypots are operated)
# ===============================================================================

class HoneypotGrid:
    """Exploitation evidence carried by the feed: CISA KEV status, public
    exploit references, EPSS. No honeypots are operated."""

    NOTE = ("No honeypots are operated. Exploitation evidence comes from the feed: "
            "CISA KEV status, public exploit references and EPSS.")

    def generate_grid_telemetry(self, entries=None) -> Dict:
        items = _items(entries)
        kev = [e for e in items if _kev(e)]
        expl = [e for e in items if _public_exploit(e)]
        weaponized = [e for e in items if str(e.get("exploit_maturity") or "").upper() == "WEAPONIZED"]
        epss_scored = [x for x in (_epss(e) for e in items) if x is not None]
        return {
            "operated": False,
            "capability": "exploitation_evidence",
            "note": self.NOTE,
            "honeypots_operated": 0,
            "kev_confirmed": len(kev),
            "public_exploit_available": len(expl),
            "weaponized": len(weaponized),
            "epss_scored": len(epss_scored),
            "epss_high": sum(1 for x in epss_scored if x >= 0.5),
            "kev_advisories": [{"stix_id": e.get("stix_id") or e.get("id"), "title": _title(e)[:120],
                                "risk_score": _risk(e)}
                               for e in sorted(kev, key=_risk, reverse=True)[:10]],
            "generated_at": _now(),
        }


# ===============================================================================
# G03 - MALWARE FAMILIES NAMED IN ADVISORIES
# ===============================================================================

class MalwareAnalysisCloud:
    """Malware families named in advisory titles, and the ATT&CK techniques
    those advisories carry. No sandbox or sample analysis is operated."""

    FAMILIES = ["lockbit", "cl0p", "alphv", "blackcat", "akira", "play", "medusa",
                "rhysida", "black basta", "ransomhub", "xmrig", "cobalt strike",
                "emotet", "qbot", "trickbot", "mimikatz", "metasploit", "sliver", "havoc"]

    def analyze_landscape(self, entries=None) -> Dict:
        items = _items(entries)
        families, techniques = Counter(), Counter()
        for e in items:
            title = _title(e).lower()
            for family in self.FAMILIES:
                if re.search(r'\b' + re.escape(family) + r'\b', title):
                    families[family.title()] += 1
            for tid in _techniques(e): techniques[tid] += 1
        return {
            "method": "Malware family names matched in advisory titles (no sandbox or sample analysis is operated).",
            "malware_families_detected": len(families),
            "top_families": families.most_common(10),
            "technique_distribution": techniques.most_common(15),
            "advisories_with_family": sum(1 for e in items
                                          if any(re.search(r'\b' + re.escape(f) + r'\b', _title(e).lower())
                                                 for f in self.FAMILIES)),
            "generated_at": _now(),
        }


# ===============================================================================
# G04 - THREAT ACTOR REGISTRY (actors observed in the feed)
# ===============================================================================

class ThreatActorIntelRegistry:
    """Actors observed in the feed (placeholder tags excluded), enriched with
    a reference profile where one exists."""

    ACTOR_DB = {
        "APT28": {"aliases": ["Fancy Bear", "Sofacy", "Strontium", "Forest Blizzard"],
                  "origin": "Russia", "motivation": "Espionage", "sectors": ["Government", "Defense", "Media"],
                  "active_since": "2004", "confidence": "HIGH"},
        "APT29": {"aliases": ["Cozy Bear", "Midnight Blizzard", "Nobelium"],
                  "origin": "Russia", "motivation": "Espionage", "sectors": ["Government", "Think Tanks"],
                  "active_since": "2008", "confidence": "HIGH"},
        "Lazarus": {"aliases": ["Hidden Cobra", "ZINC", "Labyrinth Chollima"],
                    "origin": "North Korea", "motivation": "Financial/Espionage", "sectors": ["Finance", "Crypto"],
                    "active_since": "2007", "confidence": "HIGH"},
        "LockBit": {"aliases": ["LockBit 3.0", "LockBit Black"],
                    "origin": "Russia/CIS", "motivation": "Financial", "sectors": ["Cross-Sector"],
                    "active_since": "2019", "confidence": "HIGH"},
        "Cl0p": {"aliases": ["TA505", "FIN11"],
                 "origin": "Russia/Ukraine", "motivation": "Financial", "sectors": ["Finance", "Healthcare"],
                 "active_since": "2019", "confidence": "HIGH"},
        "Volt Typhoon": {"aliases": ["Bronze Silhouette", "Vanguard Panda"],
                         "origin": "China", "motivation": "Pre-positioning", "sectors": ["Critical Infrastructure"],
                         "active_since": "2021", "confidence": "HIGH"},
        "Scattered Spider": {"aliases": ["Octo Tempest", "UNC3944", "Star Fraud"],
                             "origin": "USA/UK", "motivation": "Financial", "sectors": ["Telecom", "Technology"],
                             "active_since": "2022", "confidence": "MEDIUM"},
        "ALPHV": {"aliases": ["BlackCat", "Noberus"],
                  "origin": "Russia/CIS", "motivation": "Financial", "sectors": ["Cross-Sector"],
                  "active_since": "2021", "confidence": "HIGH"},
    }

    def build_registry(self, entries=None) -> Dict:
        items = _items(entries)
        activity = defaultdict(lambda: {"advisories": 0, "max_risk": 0.0, "techniques": set(), "cves": set()})
        unattributed = 0
        for e in items:
            actor = _actor(e)
            if not actor:
                unattributed += 1; continue
            a = activity[actor]
            a["advisories"] += 1
            a["max_risk"] = max(a["max_risk"], _risk(e))
            a["techniques"].update(_techniques(e))
            a["cves"].update(_cves(e))

        registry = []
        for name, a in activity.items():
            profile = self.ACTOR_DB.get(name)
            registry.append({
                "actor_id": _gid("actor", name),
                "name": name,
                **(profile or {"aliases": [], "origin": "Unknown", "motivation": "Unknown",
                               "sectors": [], "active_since": "Unknown", "confidence": "LOW"}),
                "profiled": profile is not None,
                "observed_advisories": a["advisories"],
                "max_observed_risk": a["max_risk"],
                "observed_techniques": sorted(a["techniques"]),
                "observed_cves": sorted(a["cves"]),
                "threat_level": "CRITICAL" if a["max_risk"] >= 9 else "HIGH" if a["max_risk"] >= 7 else "MEDIUM",
            })
        known = sum(1 for r in registry if r["profiled"])
        return {
            "registry_id": _gid("registry", _now()),
            "method": "Actor tags observed in the feed; placeholder tags (UNC-CDB-*, CDB-UNATTR-*) are not actors.",
            "total_actors": len(registry),
            "known_actors": known,
            "discovered_actors": len(registry) - known,
            "profiles_available": len(self.ACTOR_DB),
            "unattributed_advisories": unattributed,
            "actors": sorted(registry, key=lambda r: (r["max_observed_risk"], r["observed_advisories"]), reverse=True),
            "generated_at": _now(),
        }


# ===============================================================================
# G05 - CAMPAIGN CORRELATION (actor-tag grouping + same-day bursts)
# ===============================================================================

class CampaignCorrelationEngine:
    """Groups advisories by attributed actor tag, and flags days where two
    or more attributed actors appear in five or more advisories."""

    def correlate(self, entries=None) -> Dict:
        items = _items(entries)
        by_actor, by_day = defaultdict(list), defaultdict(list)
        for e in items:
            actor = _actor(e)
            if actor: by_actor[actor].append(e)
            ts = _ts(e)
            if ts: by_day[ts.date().isoformat()].append(e)

        campaigns = []
        for actor, group in by_actor.items():
            if len(group) < 2: continue
            techs = sorted({t for e in group for t in _techniques(e)})
            cves = sorted({c for e in group for c in _cves(e)})
            max_risk = max(_risk(e) for e in group)
            campaigns.append({
                "campaign_id": _gid("campaign", f"{actor}:{len(group)}"),
                "name": f"{actor} activity cluster",
                "actor": actor,
                "advisory_count": len(group),
                "techniques": techs[:15],
                "cves": cves[:10],
                "max_risk": max_risk,
                "severity": "CRITICAL" if max_risk >= 9 else "HIGH" if max_risk >= 7 else "MEDIUM",
                "confidence": min(95, 30 + len(group) * 10 + len(techs) * 3),
                "confidence_basis": "heuristic: advisory and technique counts",
                "correlation_type": "actor_tag_grouping",
            })
        for day, group in by_day.items():
            actors = sorted({_actor(e) for e in group} - {""})
            if len(group) >= 5 and len(actors) >= 2:
                campaigns.append({
                    "campaign_id": _gid("campaign", f"burst:{day}"),
                    "name": f"Same-day activity: {day}",
                    "actor": ", ".join(actors[:3]),
                    "advisory_count": len(group),
                    "techniques": [], "cves": [],
                    "max_risk": max(_risk(e) for e in group),
                    "severity": "HIGH",
                    "confidence": min(80, 20 + len(group) * 5),
                    "confidence_basis": "heuristic: advisory count",
                    "correlation_type": "same_day_burst",
                })
        return {
            "total_campaigns": len(campaigns),
            "campaigns": sorted(campaigns, key=lambda c: c["max_risk"], reverse=True),
            "correlation_methods": ["actor_tag_grouping", "same_day_burst"],
            "generated_at": _now(),
        }


# ===============================================================================
# G06 - CVE REPUTATION
# ===============================================================================

class IOCReputationEngine:
    """Reputation score per CVE referenced by the feed (sightings, risk,
    actor associations, KEV, source spread)."""

    def compute_reputations(self, entries=None) -> Dict:
        items = _items(entries)
        scores = defaultdict(lambda: {"sightings": 0, "max_risk": 0.0, "actors": set(), "kev": False, "sources": set()})
        for e in items:
            for cve in _cves(e):
                s = scores[f"cve:{cve}"]
                s["sightings"] += 1
                s["max_risk"] = max(s["max_risk"], _risk(e))
                if _actor(e): s["actors"].add(_actor(e))
                if _kev(e): s["kev"] = True
                src = str(e.get("feed_source") or "").strip()
                if src: s["sources"].add(src[:30])
        reputations = []
        for key, d in scores.items():
            score = min(100.0, d["max_risk"] * 8 + min(d["sightings"], 10) * 3 + len(d["actors"]) * 5
                        + (20 if d["kev"] else 0) + len(d["sources"]) * 2)
            reputations.append({
                "ioc": key,
                "reputation_score": round(score, 1),
                "verdict": "MALICIOUS" if score >= 70 else "SUSPICIOUS" if score >= 40 else "UNKNOWN",
                "sightings": d["sightings"],
                "max_risk": d["max_risk"],
                "actor_associations": sorted(d["actors"]),
                "kev_confirmed": d["kev"],
                "source_count": len(d["sources"]),
            })
        reputations.sort(key=lambda r: r["reputation_score"], reverse=True)
        return {
            "ioc_types_scored": ["cve"],
            "total_iocs_scored": len(reputations),
            "malicious_count": sum(1 for r in reputations if r["verdict"] == "MALICIOUS"),
            "suspicious_count": sum(1 for r in reputations if r["verdict"] == "SUSPICIOUS"),
            "kev_cves": sum(1 for r in reputations if r["kev_confirmed"]),
            "ioc_reputations": reputations[:100],
            "generated_at": _now(),
        }


# ===============================================================================
# G07 - DETECTION CONTENT (rules actually attached to feed items)
# ===============================================================================

class AutoDetectionGenerator:
    """Counts the detection rules attached to feed items by
    scripts/detection_bundle_injector.py (served per item at
    /api/v1/detections). No rules are synthesized here."""

    def generate_full_pack(self, entries=None) -> Dict:
        items = _items(entries)
        lists = {kind: [] for kind in DETECTION_FIELDS}
        covered = 0
        for e in items:
            has_any = False
            for kind, field in DETECTION_FIELDS.items():
                if str(e.get(field) or "").strip():
                    has_any = True
                    lists[kind].append({"stix_id": e.get("stix_id") or e.get("id"), "title": _title(e)[:100]})
            covered += has_any
        high_risk = [e for e in items if _risk(e) >= 7]
        uncovered_high = sum(1 for e in high_risk
                             if not any(str(e.get(f) or "").strip() for f in DETECTION_FIELDS.values()))
        counts = {k: len(v) for k, v in lists.items()}
        return {
            "detection_pack_id": _gid("detpack", _now()),
            "source": "Per-advisory rules from scripts/detection_bundle_injector.py (served at /api/v1/detections).",
            "sigma_rules": lists["sigma"][:50],
            "kql_queries": lists["kql"][:50],
            "suricata_rules": lists["suricata"][:50],
            "yara_rules": lists["yara"][:50],
            "total_rules": sum(counts.values()),
            "sigma_count": counts["sigma"], "kql_count": counts["kql"],
            "suricata_count": counts["suricata"], "yara_count": counts["yara"],
            "advisories_with_detections": covered,
            "high_risk_without_detections": uncovered_high,
            "stats": {
                "total_rules": sum(counts.values()),
                "sigma": counts["sigma"], "kql": counts["kql"], "yara": counts["yara"],
                "suricata": counts["suricata"],
            },
            "generated_at": _now(),
        }


# ===============================================================================
# G08 - TAXII 2.1 (the collections the Worker serves)
# ===============================================================================

class TAXIIServer:
    """The TAXII 2.1 surface the intel-gateway Worker serves. Collection ids
    mirror TAXII_COLLECTION_ID / TAXII_KEV_COLL in
    workers/intel-gateway/src/index.js (parity is tested)."""

    COLLECTIONS = [
        {"id": "sentinel-apex-main", "title": "SENTINEL APEX - Primary Threat Intelligence",
         "access": "PRO or ENTERPRISE", "can_read": True, "can_write": False},
        {"id": "sentinel-apex-kev", "title": "SENTINEL APEX - CISA KEV Confirmed",
         "access": "ENTERPRISE", "can_read": True, "can_write": False},
    ]

    def generate_server_config(self, entries=None) -> Dict:
        items = _items(entries)
        return {
            "taxii_server": {
                "title": "SENTINEL APEX TAXII 2.1",
                "version": "2.1",
                "discovery": "/taxii/",
                "collections_endpoint": "/taxii/collections/",
                "objects_endpoint": "/taxii/collections/{id}/objects/",
                "auth": "PRO or ENTERPRISE API key (JWT via /auth/login)",
            },
            "collections": self.COLLECTIONS,
            "collection_count": len(self.COLLECTIONS),
            "current_stats": {
                "advisories_available": len(items),
                "kev_advisories": sum(1 for e in items if _kev(e)),
            },
            "generated_at": _now(),
        }


# ===============================================================================
# G09 - RANSOMWARE & LEAK ADVISORIES (no dark-web monitoring is operated)
# ===============================================================================

class DarkWebIntelligence:
    """Advisories in the feed about ransomware and data leaks. No dark-web
    monitoring is operated (the Worker's /api/dark-web/* routes return 503)."""

    NOTE = ("No dark-web monitoring is operated (/api/dark-web/* returns 503). "
            "Figures count feed advisories about ransomware and data leaks.")
    RANSOMWARE_KW = ["ransomware", "extort", "ransom", "lockbit", "cl0p", "alphv", "akira", "rhysida"]
    LEAK_KW = ["credential", "password", "breach", "leak", "stolen", "dump"]

    def generate_darkweb_report(self, entries=None) -> Dict:
        items = _items(entries)
        ransomware = [e for e in items if any(kw in _title(e).lower() for kw in self.RANSOMWARE_KW)]
        leaks = [e for e in items if any(kw in _title(e).lower() for kw in self.LEAK_KW)]
        relevant = {id(e) for e in ransomware} | {id(e) for e in leaks}
        return {
            "operated": False,
            "capability": "feed_advisories",
            "note": self.NOTE,
            "sources_monitored": 0,
            "source_count": 0,
            "ransomware_advisories": len(ransomware),
            "leak_or_credential_advisories": len(leaks),
            "relevant_advisories": len(relevant),
            "intelligence_signals": {
                "ransomware_leak_activity": len(ransomware),
                "credential_exposure_signals": len(leaks),
                "total_advisories_with_darkweb_relevance": len(relevant),
            },
            "top_ransomware_groups": self._extract_ransomware_groups(items),
            "generated_at": _now(),
        }

    def _extract_ransomware_groups(self, entries):
        groups = Counter()
        for e in entries:
            title = _title(e).lower()
            for group in ["lockbit", "cl0p", "alphv", "blackcat", "play", "medusa",
                          "bianlian", "8base", "akira", "rhysida", "hunters"]:
                if re.search(r'\b' + re.escape(group) + r'\b', title):
                    groups[group.title()] += 1
        return groups.most_common(10)


# ===============================================================================
# G10 - EXPOSURE SIGNALS IN ADVISORIES
# ===============================================================================

class AttackSurfaceIntelligence:
    """Exposure-related signals in advisory titles (misconfiguration,
    unauthenticated RCE, API/admin exposure) and the products named. No
    external scanning is operated."""

    SERVICES = ["apache", "nginx", "wordpress", "exchange", "fortinet",
                "cisco", "palo alto", "vmware", "citrix", "jenkins"]

    def analyze_exposure(self, entries=None) -> Dict:
        items = _items(entries)
        categories = defaultdict(int)
        services = Counter()
        for e in items:
            title = _title(e).lower()
            if any(kw in title for kw in ["exposed", "misconfigur", "default credential", "default password"]):
                categories["misconfiguration"] += 1
            if any(kw in title for kw in ["rce", "remote code", "unauthenticated"]):
                categories["critical_vulnerability"] += 1
            if any(kw in title for kw in [" api", "endpoint", "rest api"]):
                categories["api_exposure"] += 1
            if any(kw in title for kw in ["dashboard", "admin panel", "admin interface"]):
                categories["admin_exposure"] += 1
            for svc in self.SERVICES:
                if svc in title: services[svc.title()] += 1
        return {
            "report_id": _gid("asm", _now()),
            "method": "Keyword signals in advisory titles; no external scanning is operated.",
            "exposure_categories": dict(categories),
            "vulnerable_services": services.most_common(15),
            "total_exposures": sum(categories.values()),
            "critical_exposures": categories.get("critical_vulnerability", 0),
            "risk_summary": {
                "total_exposure_signals": sum(categories.values()),
                "critical_exposures": categories.get("critical_vulnerability", 0),
                "misconfigurations": categories.get("misconfiguration", 0),
            },
            "generated_at": _now(),
        }


# ===============================================================================
# G11 - ACTOR COUNTRY AND ATTACK FLOWS
# A flow exists only when one advisory has both an actor country and a
# target or victim country. source_country is not an origin. Origins are
# not estimated.
# ===============================================================================

# A single country name. Codes, slash compounds, and profile phrases
# ("US/UK (English-speaking criminal)") are not origins.
_COUNTRY_NAME = re.compile(r"^[A-Za-z][A-Za-z .'-]{2,39}$")
_NOT_A_COUNTRY = re.compile(r"criminal|speaking|operation|ransomware|hacker|unknown|unattributed", re.IGNORECASE)


def _country_label(value) -> str:
    """A single country name, or ""."""
    c = str(value or "").strip()
    if not c or _PLACEHOLDER_GEO.match(c) or not _COUNTRY_NAME.match(c) or _NOT_A_COUNTRY.search(c):
        return ""
    return c


def _public_geo_summary(key, value):
    """Keep measured country objects. Every other collection stays compacted."""
    if key == "origin_countries" and isinstance(value, dict):
        clean = {}
        for name, count in value.items():
            label = _country_label(name)
            if not label or isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                continue
            clean[label] = count
            if len(clean) >= 15:
                break
        return clean
    rows = []
    if key == "hotspots" and isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            label = _country_label(item.get("country"))
            count = item.get("advisories")
            if not label or isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                continue
            rows.append({"country": label, "advisories": count})
            if len(rows) >= 15:
                break
        return rows
    if key == "attack_flows" and isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            origin = _country_label(item.get("origin"))
            target = _country_label(item.get("target"))
            count = item.get("advisories")
            if not origin or not target or isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                continue
            rows.append({"origin": origin, "target": target, "advisories": count})
            if len(rows) >= 15:
                break
    return rows


class GlobalAttackMap:
    """Actor-country counts, plus a flow only when the same advisory names
    both an actor country and a target or victim country. Origins are not
    estimated."""

    NOTE = ("A flow is counted only when the same advisory has an actor country and a target country. "
            "Origins count advisories whose threat actor has a country. Origins are not estimated.")

    def generate_map_data(self, entries=None) -> Dict:
        items = _items(entries)
        origins = Counter()
        pairs = Counter()
        for e in items:
            origin = _country_label(e.get("actor_country"))
            if origin:
                origins[origin] += 1
            target = _country_label(e.get("target_country") or e.get("victim_country"))
            if origin and target:
                pairs[(origin, target)] += 1
        attributed = sum(origins.values())
        return {
            "map_id": _gid("attackmap", _now()),
            "note": self.NOTE,
            "attack_flows": [{"origin": o, "target": t, "advisories": n} for (o, t), n in pairs.most_common(15)],
            "total_flows": sum(pairs.values()),
            "active_corridors": len(pairs),
            "attributed_advisories": attributed,
            "unattributed_advisories": len(items) - attributed,
            "origin_countries": dict(origins.most_common(15)),
            "hotspots": [{"country": c, "advisories": n} for c, n in origins.most_common(15)],
            "generated_at": _now(),
        }


# ===============================================================================
# G12 - THREAT HUNTING (technique clusters and velocity)
# ===============================================================================

class AIThreatHuntingEngine:
    """Clusters advisories that share ATT&CK techniques, finds actors with
    overlapping techniques, and reports techniques trending in 7 days."""

    def execute_hunt(self, entries=None) -> Dict:
        items = _items(entries)
        clusters = self._cluster_threats(items)
        overlap = self._detect_infra_reuse(items)
        trending = self._predict_emerging(items)
        hunts = self._generate_hunt_hypotheses(items, clusters)
        return {
            "hunt_id": _gid("aihunt", _now()),
            "method": "Grouping by shared ATT&CK techniques and 7-day technique counts.",
            "threat_clusters": clusters,
            "infrastructure_reuse": overlap,
            "emerging_predictions": trending,
            "hunt_hypotheses": hunts,
            "clusters_identified": len(clusters),
            "trending_techniques": len(trending),
            "stats": {
                "clusters_identified": len(clusters),
                "infra_reuse_cases": len(overlap),
                "predictions_generated": len(trending),
                "hunt_hypotheses": len(hunts),
            },
            "generated_at": _now(),
        }

    def _cluster_threats(self, entries):
        groups = defaultdict(list)
        for e in entries:
            techs = tuple(sorted(_techniques(e)))
            if techs: groups[techs].append(_title(e)[:50])
        clusters = []
        for techs, titles in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            if len(titles) >= 2:
                clusters.append({
                    "cluster_id": _gid("cluster", str(techs)),
                    "techniques": list(techs),
                    "advisory_count": len(titles),
                    "sample_titles": titles[:3],
                    "assessment": "Shared technique set" if len(titles) >= 5 else "Related activity",
                })
        return clusters

    def _detect_infra_reuse(self, entries):
        """Attributed actors whose observed techniques overlap (3+ shared)."""
        by_actor = defaultdict(set)
        for e in entries:
            actor = _actor(e)
            if actor: by_actor[actor].update(_techniques(e))
        actors = sorted(by_actor)
        cases = []
        for i in range(len(actors)):
            for j in range(i + 1, len(actors)):
                shared = by_actor[actors[i]] & by_actor[actors[j]]
                if len(shared) >= 3:
                    cases.append({"actors": [actors[i], actors[j]], "shared_techniques": sorted(shared),
                                  "overlap_count": len(shared),
                                  "assessment": "Overlapping techniques (not proof of shared infrastructure)"})
        return cases

    def _predict_emerging(self, entries):
        """Techniques seen 3+ times in advisories published in the last 7 days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        velocity = Counter(t for e in entries if (_ts(e) or cutoff) > cutoff for t in _techniques(e))
        return [{"technique": tech, "velocity": count,
                 "prediction": f"{tech} in {count} advisories in the last 7 days",
                 "confidence": min(85, 30 + count * 10),
                 "action": f"Review detection coverage for {tech}"}
                for tech, count in velocity.most_common(5) if count >= 3]

    def _generate_hunt_hypotheses(self, entries, clusters):
        return [{"hypothesis": f"{c['advisory_count']} advisories share techniques {', '.join(c['techniques'][:3])}; "
                               f"hunt for their use in your environment",
                 "priority": "CRITICAL" if c["advisory_count"] >= 5 else "HIGH",
                 "data_sources": ["Process Creation", "Network Connection", "DNS Query"],
                 "recommended_action": "Targeted hunt for these techniques"}
                for c in clusters[:5]]


# ===============================================================================
# GENESIS ORCHESTRATOR
# ===============================================================================

class GenesisOrchestrator:
    """Runs the 12 GENESIS engines over one set of feed items."""

    VERSION = "43.1.0"

    def __init__(self):
        self.sensor_net = GlobalCyberSensorNetwork()
        self.honeypot = HoneypotGrid()
        self.malware = MalwareAnalysisCloud()
        self.actor_registry = ThreatActorIntelRegistry()
        self.campaign_engine = CampaignCorrelationEngine()
        self.ioc_reputation = IOCReputationEngine()
        self.detection_gen = AutoDetectionGenerator()
        self.taxii = TAXIIServer()
        self.darkweb = DarkWebIntelligence()
        self.asm = AttackSurfaceIntelligence()
        self.attack_map = GlobalAttackMap()
        self.ai_hunter = AIThreatHuntingEngine()

    def _engines(self) -> List[Tuple[str, Any, str]]:
        return [
            ("G01_SensorNetwork", self.sensor_net.generate_telemetry, "sensor_network.json"),
            ("G02_HoneypotGrid", self.honeypot.generate_grid_telemetry, "honeypot_grid.json"),
            ("G03_MalwareCloud", self.malware.analyze_landscape, "malware_analysis.json"),
            ("G04_ActorRegistry", self.actor_registry.build_registry, "actor_registry.json"),
            ("G05_CampaignCorrelation", self.campaign_engine.correlate, "campaign_correlation.json"),
            ("G06_IOCReputation", self.ioc_reputation.compute_reputations, "ioc_reputations.json"),
            ("G07_DetectionGenerator", self.detection_gen.generate_full_pack, "detection_pack.json"),
            ("G08_TAXIIServer", self.taxii.generate_server_config, "taxii_config.json"),
            ("G09_DarkWebIntel", self.darkweb.generate_darkweb_report, "darkweb_intel.json"),
            ("G10_AttackSurface", self.asm.analyze_exposure, "attack_surface.json"),
            ("G11_GlobalAttackMap", self.attack_map.generate_map_data, "attack_map.json"),
            ("G12_AIThreatHunter", self.ai_hunter.execute_hunt, "ai_threat_hunter.json"),
        ]

    def compute(self, entries=None) -> Tuple[Dict, Dict[str, Dict]]:
        """(genesis_output, {engine: full result}) for one set of items. No files written."""
        items = _items(entries)
        start = time.time()
        results = {"version": self.VERSION, "codename": "GENESIS", "generated_at": _now(),
                   "items_analyzed": len(items), "engines": {}}
        raw = {}
        for name, func, _ in self._engines():
            try:
                r = func(items)
                raw[name] = r
                results["engines"][name] = {"status": "OK", "summary": self._summarize(r)}
            except Exception as e:
                logger.error(f"[GENESIS-{name}] Failed: {e}")
                results["engines"][name] = {"status": "ERROR", "error": str(e)}
        results["execution_time_ms"] = max(0.01, round((time.time() - start) * 1000, 2))
        results["engines_ok"] = sum(1 for v in results["engines"].values() if v["status"] == "OK")
        results["engines_total"] = len(self._engines())
        return results, raw

    def execute_full_cycle(self, entries=None) -> Dict:
        raw_manifest = _load(MANIFEST_PATH) if entries is None else None
        if entries is None:
            if isinstance(raw_manifest, dict):
                shapes = {k: len(v) for k, v in raw_manifest.items() if isinstance(v, list)}
                logger.info("[GENESIS] manifest object keys-with-lists=%s", shapes or "none")
            else:
                logger.info("[GENESIS] manifest %s len=%s", type(raw_manifest).__name__,
                            len(raw_manifest) if isinstance(raw_manifest, list) else 0)
        logger.info("[GENESIS] Starting 12-engine cycle...")
        results, raw = self.compute(entries)
        for name, _, filename in self._engines():
            if name in raw: _save(os.path.join(GENESIS_DIR, filename), raw[name])
        _save(os.path.join(GENESIS_DIR, "genesis_output.json"), results)
        logger.info(f"[GENESIS] {results['engines_ok']}/{results['engines_total']} engines OK "
                    f"over {results['items_analyzed']} items in {results['execution_time_ms']}ms")
        return results

    def _summarize(self, result):
        if isinstance(result, dict):
            summary = {}
            for k, v in result.items():
                if isinstance(v, (int, float, str, bool)):
                    summary[k] = v
                elif k in ("origin_countries", "hotspots", "attack_flows"):
                    summary[k] = _public_geo_summary(k, v)
                elif isinstance(v, list):
                    summary[k] = f"{len(v)} items"
                elif isinstance(v, dict):
                    summary[k] = f"{len(v)} keys"
            return summary
        return str(result)[:100]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    print("=" * 70)
    print("CYBERDUDEBIVASH(R) SENTINEL APEX - GENESIS")
    print("=" * 70)
    r = GenesisOrchestrator().execute_full_cycle()
    print(f"\nGENESIS cycle: {r['engines_ok']}/{r['engines_total']} engines OK over "
          f"{r['items_analyzed']} items in {r['execution_time_ms']}ms")
    for name, info in r["engines"].items():
        print(f"   [{info['status']}] {name}")
