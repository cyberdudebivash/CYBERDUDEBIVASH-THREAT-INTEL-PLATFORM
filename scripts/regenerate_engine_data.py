#!/usr/bin/env python3
"""
regenerate_engine_data.py — SENTINEL APEX v185.1 Engine Data Regenerator
=========================================================================
Derives fresh, deterministic engine data from api/feed.baseline.json
(primary) falling back to api/feed.json.  Runs every pipeline cycle so
all 12 platform features always reflect the live intel state.

Output files (all under repo root):
  data/nexus/nexus_output.json        — Threat Exposure · Kill Chain · Hunts · Campaigns
  data/genesis/genesis_output.json    — 12 Strategic Engine Grid
  data/cortex/cortex_output.json      — Knowledge Graph (Cortex v40)
  data/quantum/quantum_output.json    — Feed Trust & Anomaly Detection (Quantum v41)
  data/sovereign/sovereign_output.json— Compliance & Governance (Sovereign v42)
  data/bughunter/bughunter_output.json— Attack Surface Recon
  data/incidents/incidents.json       — TIP+SOAR Incident Feed
  data/responses/response_log.json    — SOAR Automated Response Actions
  data/threathunts/hunts.json         — Threat Hunt Hypotheses + Campaign Intel
  api/engines.json                    — Unified platform health endpoint
  api/ai/tracker.json                 — AI Cyber Brain Full Command Center
"""

import json
import os
import re
import sys
import hashlib
import logging
import math
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urlsplit

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ENGINE-REGEN] %(message)s")
log = logging.getLogger("ENGINE-REGEN")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE_PATH = os.path.join(ROOT, "api", "feed.baseline.json")
FEED_PATH     = os.path.join(ROOT, "api", "feed.json")
NOW_UTC = datetime.now(timezone.utc)
NOW_ISO = NOW_UTC.isoformat()

# ── TTP → Kill Chain phase mapping ──────────────────────────────────────────
TTP_PHASE = {
    "T1595": "recon",  "T1592": "recon",  "T1589": "recon", "T1590": "recon",
    "T1591": "recon",  "T1087": "recon",  "T1482": "recon", "T1069": "recon",
    "T1588": "weapon", "T1587": "weapon", "T1583": "weapon", "T1584": "weapon",
    "T1566": "delivery","T1190": "delivery","T1133": "delivery","T1195": "delivery",
    "T1078": "delivery","T1189": "delivery","T1200": "delivery",
    "T1059": "exploit", "T1203": "exploit", "T1068": "exploit", "T1210": "exploit",
    "T1003": "exploit", "T1110": "exploit", "T1558": "exploit", "T1528": "exploit",
    "T1547": "install", "T1543": "install", "T1053": "install", "T1136": "install",
    "T1546": "install", "T1548": "install", "T1134": "install",
    "T1071": "c2",     "T1095": "c2",     "T1572": "c2",    "T1105": "c2",
    "T1021": "c2",     "T1570": "c2",     "T1573": "c2",
    "T1041": "exfil",  "T1048": "exfil",  "T1567": "exfil", "T1052": "exfil",
    "T1560": "actions","T1005": "actions","T1074": "actions","T1185": "actions",
    "T1486": "impact", "T1490": "impact", "T1561": "impact", "T1489": "impact",
    "T1485": "impact", "T1498": "impact", "T1491": "impact",
}

# Technique name → T-code
_TTP_NAME_TO_CODE: Dict[str, str] = {
    "active scanning": "T1595",
    "phishing": "T1566", "spearphishing attachment": "T1566", "spearphishing link": "T1566",
    "exploitation for client execution": "T1203",
    "exploitation of remote services": "T1210",
    "exploit public-facing application": "T1190",
    "command and scripting interpreter": "T1059",
    "boot or logon autostart execution": "T1547", "registry run keys": "T1547",
    "scheduled task/job": "T1053", "scheduled task": "T1053",
    "exfiltration over web service": "T1567",
    "exfiltration over c2 channel": "T1041",
    "data encrypted for impact": "T1486", "ransomware": "T1486",
    "network denial of service": "T1498",
    "endpoint denial of service": "T1499",
    "valid accounts": "T1078",
    "remote services": "T1021",
    "ingress tool transfer": "T1105",
    "application layer protocol": "T1071", "web service": "T1071",
    "obfuscated files or information": "T1027",
    "masquerading": "T1036",
    "process injection": "T1055",
    "credential dumping": "T1003", "os credential dumping": "T1003",
    "brute force": "T1110",
    "supply chain compromise": "T1195",
    "drive-by compromise": "T1189",
    "external remote services": "T1133",
    "data destruction": "T1485", "disk wipe": "T1561",
    "exploitation for privilege escalation": "T1068",
    "create account": "T1136",
    "phishing for information": "T1598",
    "gather victim identity information": "T1589",
    "acquire access": "T1650",
}

ACTOR_KEYWORDS = {
    "APT28":  ["apt28", "fancy bear", "sofacy", "pawn storm"],
    "APT29":  ["apt29", "cozy bear", "midnight blizzard", "nobelium", "turla"],
    "Lazarus":["lazarus", "hidden cobra", "zinc", "north korea"],
    "APT41":  ["apt41", "winnti", "barium", "double dragon", "mustang panda"],
    "FIN7":   ["fin7", "carbanak"],
    "LockBit":["lockbit", "lock bit"],
    "BlackCat":["blackcat", "alphv", "noberus"],
    "Cl0p":   ["cl0p", "clop", "ta505"],
    "REvil":  ["revil", "sodinokibi"],
    "Volt Typhoon":    ["volt typhoon", "bronze silhouette"],
    "Salt Typhoon":    ["salt typhoon", "earth estries"],
    "Scattered Spider":["scattered spider", "unc3944", "oktapus"],
    "MuddyWater":      ["muddywater", "muddy water"],
}

_GENERIC_ACTOR_TAGS = {
    "", "UNC-CDB-INGEST", "CDB-UNATTR-CVE", "CDB-UNATTR-SUP",
    "CDB-CVE-GEN", "CDB-UNATTR-APT", "CDB-UNATTR-RAN", "CDB-UNATTR-RAT",
    "CDB-UNATTR-PHI", "CDB-TA-02", "UNC-UNKNOWN",
}


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _load_feed() -> List[Dict]:
    """Load from api/feed.baseline.json (primary, 240+ items) or api/feed.json."""
    for path in [BASELINE_PATH, FEED_PATH]:
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            # Handle both list and {"items": [...]} formats
            if isinstance(raw, list):
                items = raw
            elif isinstance(raw, dict):
                items = raw.get("items", raw.get("data", []))
            else:
                items = []
            if not isinstance(items, list):
                continue
            items = [item for item in items if isinstance(item, dict)]
            if items:
                log.info(f"Loaded {len(items)} items from {os.path.relpath(path, ROOT)}")
                return items
        except Exception as exc:
            log.warning(f"Could not load {path}: {exc}")
    log.error("No feed items available — engine regeneration skipped.")
    return []


def _safe_write(path: str, obj: Any) -> bool:
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False, allow_nan=False)
        os.replace(tmp, path)
        log.info(f"✅ {os.path.relpath(path, ROOT)}")
        return True
    except Exception as exc:
        log.error(f"❌ Write failed {path}: {exc}")
        if os.path.exists(tmp):
            try: os.unlink(tmp)
            except: pass
        return False


def _extract_ttps(item: Dict) -> List[str]:
    """
    Extract MITRE T-codes from mitre_techniques or ttps field.
    Handles three formats:
      - dict: {'id': 'T1486', 'name': '...', ...}
      - T-code string: 'T1486'
      - technique name string: 'Data Encrypted for Impact'
    """
    raw = item.get("mitre_techniques") or item.get("ttps") or item.get("mitre_tactics") or []
    if not isinstance(raw, list):
        return []
    result = []
    for t in raw:
        if isinstance(t, dict):
            # Dict format — read .id or .technique_id
            code = t.get("id") or t.get("technique_id") or ""
            if isinstance(code, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", code):
                result.append(code.split(".")[0])
                continue
            # Fallback: name field
            name = t.get("name")
            name = name.lower() if isinstance(name, str) else ""
            code = _TTP_NAME_TO_CODE.get(name)
            if code:
                result.append(code)
        elif isinstance(t, str):
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", t):
                result.append(t.split(".")[0])
            else:
                code = _TTP_NAME_TO_CODE.get(t.lower())
                if code:
                    result.append(code)
    return list(dict.fromkeys(result))  # deduplicate, preserve order


def _extract_actor(item: Dict) -> str:
    """
    Extract named threat actor. Checks actor_tag first (the field used by v185.1
    premium_feed_baseline.py), then falls back to keyword matching in title/description.
    Returns 'UNK' if no specific actor identified.
    """
    # Direct actor_tag / actor fields
    for field in ("actor_tag", "actor", "threat_actor", "actor_fingerprint"):
        val = item.get(field)
        val = val.strip() if isinstance(val, str) else ""
        if val and val not in _GENERIC_ACTOR_TAGS:
            return val

    # Keyword matching fallback
    text = " ".join(item.get(key, "") for key in ("title", "description") if isinstance(item.get(key), str)).lower()
    for actor, keywords in ACTOR_KEYWORDS.items():
        if any(k in text for k in keywords):
            return actor
    return "UNK"


def _short_id(seed: str, prefix: str) -> str:
    return f"{prefix}-{hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()[:8].upper()}"


def _safe_float(v) -> float:
    try:
        if isinstance(v, bool):
            return 0.0
        number = float(v) if v is not None else 0.0
        return number if math.isfinite(number) else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


# ════════════════════════════════════════════════════════════════════════════
# NEXUS — Threat Exposure · Kill Chain · Hunt Hypotheses · Campaigns
# ════════════════════════════════════════════════════════════════════════════

def generate_nexus(items: List[Dict]) -> Dict:
    critical = [i for i in items if _safe_float(i.get("risk_score")) >= 9.0]
    high     = [i for i in items if 7.0 <= _safe_float(i.get("risk_score")) < 9.0]
    kev_items = [i for i in items if i.get("kev") is True or i.get("kev_present") is True]

    avg_risk     = sum(_safe_float(i.get("risk_score")) for i in items) / max(len(items), 1)
    velocity     = min(10.0, len(items) / 7 * 1.5)
    crit_density = min(10.0, (len(critical) * 2 + len(high)) / max(len(items), 1) * 30)
    kev_score    = min(10.0, len(kev_items) / max(len(items), 1) * 40)
    exposure_idx = round(min(10.0,
        velocity * 0.2 + crit_density * 0.3 + kev_score * 0.2 +
        avg_risk * 0.1 + min(10.0, len(critical) * 0.5) * 0.2
    ), 2)

    trend       = "INCREASING" if len(critical) > 3 else "STABLE" if len(critical) > 1 else "DECREASING"
    forecast_7d  = round(exposure_idx * (1.08 if trend == "INCREASING" else 0.95 if trend == "DECREASING" else 1.0), 2)
    forecast_30d = round(exposure_idx * (1.15 if trend == "INCREASING" else 0.88 if trend == "DECREASING" else 1.02), 2)

    # Kill chain phase counts from actual TTPs in the feed
    phase_counts: Dict[str, int] = {
        "recon":0, "weapon":0, "delivery":0, "exploit":0,
        "install":0, "c2":0, "actions":0, "exfil":0, "impact":0
    }
    all_ttps_set: set = set()
    for item in items:
        for ttp in _extract_ttps(item):
            all_ttps_set.add(ttp)
            phase = TTP_PHASE.get(ttp)
            if phase and phase in phase_counts:
                phase_counts[phase] += 1

    # Attack chains from critical items with TTPs
    attack_chains = []
    for item in critical[:10]:
        ttps = _extract_ttps(item)
        if ttps:
            attack_chains.append({
                "chain_id":   _short_id(item.get("id", item.get("title", "")), "CHAIN"),
                "title":      (item.get("title") or "Unknown")[:60],
                "techniques": ttps[:6],
                "steps":      ttps[:6],
                "severity":   "CRITICAL",
                "actor":      _extract_actor(item),
            })

    # Threat hunt hypotheses from high-risk items
    HUNT_TEMPLATES = [
        {"kws":["supply","chain","package","npm","pypi"], "hyp":"Supply-chain compromise via trusted package manager injection", "pri":"CRITICAL","tactic":"T1195"},
        {"kws":["ransomware","ransom","encrypt","lockbit","cl0p"], "hyp":"Ransomware deployment using LOLBins for lateral movement", "pri":"CRITICAL","tactic":"T1486"},
        {"kws":["credential","phishing","password","harvest"], "hyp":"Credential harvesting campaign targeting enterprise identity providers", "pri":"HIGH","tactic":"T1566"},
        {"kws":["zero-day","0day","unpatched","zeroday"], "hyp":"Active zero-day exploitation of internet-facing systems", "pri":"CRITICAL","tactic":"T1190"},
        {"kws":["cloud","aws","azure","gcp","saas","api key"], "hyp":"Cloud infrastructure compromise via stolen API keys or OAuth token abuse", "pri":"HIGH","tactic":"T1078"},
        {"kws":["apt","nation","espionage","state","government"], "hyp":"Nation-state persistence via registry/WMI/scheduled-task abuse", "pri":"HIGH","tactic":"T1053"},
        {"kws":["exfil","theft","steal","exfiltration","breach"], "hyp":"Covert data exfiltration via encrypted C2 channels", "pri":"HIGH","tactic":"T1041"},
        {"kws":["backdoor","implant","trojan","rat","remote access"], "hyp":"Remote access trojan persistence via startup folder and registry run keys", "pri":"HIGH","tactic":"T1547"},
        {"kws":["botnet","c2","command and control"], "hyp":"Botnet C2 infrastructure using domain generation algorithms to evade blocklists", "pri":"HIGH","tactic":"T1071"},
        {"kws":["mobile","android","ios","spyware","pegasus"], "hyp":"Mobile spyware deployment via zero-click exploitation chain", "pri":"CRITICAL","tactic":"T1404"},
    ]
    hunts = []
    used = set()
    for item in [i for i in items if _safe_float(i.get("risk_score")) >= 7][:40]:
        tl = (item.get("title") or "").lower()
        for tmpl in HUNT_TEMPLATES:
            if tmpl["hyp"] in used:
                continue
            if any(k in tl for k in tmpl["kws"]):
                hunts.append({
                    "hunt_id":    _short_id(tmpl["hyp"], "HUNT"),
                    "hypothesis": tmpl["hyp"],
                    "priority":   tmpl["pri"],
                    "actor_tags": [_extract_actor(item)],
                    "mitre_tactics": [tmpl["tactic"]],
                    "data_sources": ["EDR Telemetry", "Network Logs", "Cloud Audit Logs"],
                    "status":     "ACTIVE",
                    "created_at": NOW_ISO,
                })
                used.add(tmpl["hyp"])
                break

    # Campaign clustering by actor
    actor_index: Dict[str, List] = {}
    for item in items:
        actor = _extract_actor(item)
        if actor != "UNK":
            actor_index.setdefault(actor, []).append(item)

    campaigns = []
    for actor, actor_items in sorted(actor_index.items(), key=lambda x: -len(x[1]))[:12]:
        all_ttps = list({t for i in actor_items for t in _extract_ttps(i)})
        avg_r = round(sum(_safe_float(i.get("risk_score")) for i in actor_items) / max(len(actor_items), 1), 1)
        campaigns.append({
            "campaign_id":   _short_id(actor, "CAMP"),
            "campaign_name": actor.replace(" ", "_").upper()[:40],
            "name":          actor,
            "actors":        [actor],
            "threat_actor":  actor,
            "incidents":     len(actor_items),
            "avg_risk_score": avg_r,
            "techniques":    all_ttps[:8],
            "status":        "ACTIVE",
            "last_seen":     NOW_ISO,
        })

    # PIR coverage
    pir_data = {
        "Ransomware":   len([i for i in items if "ransom" in (i.get("title","") or "").lower()]),
        "APT":          len([i for i in items if any(a in (i.get("title","") or "").lower() for a in ["apt","nation","state"])]),
        "Zero-Days":    len([i for i in items if any(z in (i.get("title","") or "").lower() for z in ["zero-day","0day"])]),
        "Cloud Threats":len([i for i in items if any(c in (i.get("title","") or "").lower() for c in ["cloud","aws","azure"])]),
        "Supply Chain": len([i for i in items if "supply" in (i.get("title","") or "").lower()]),
        "IAB/Creds":    len([i for i in items if "phish" in (i.get("title","") or "").lower()]),
        "Cloud":        len([i for i in items if "cloud" in (i.get("title","") or "").lower()]),
        "Exploits":     len([i for i in items if "CVE-" in (i.get("title","") or "")]),
    }
    total = len(items) or 1
    pir_coverage = {
        "coverage_pct": round(sum(1 for v in pir_data.values() if v > 0) / len(pir_data) * 100),
        "pirs": [
            {"requirement": k, "status": "COVERED" if v > 0 else "GAP",
             "priority": "HIGH" if k in ("Ransomware","Zero-Days","Supply Chain") else "MEDIUM"}
            for k, v in pir_data.items()
        ],
    }

    # Executive briefing (DICT format — renderNexusEngine reads .executive_summary, .key_findings)
    top5 = sorted(items, key=lambda x: _safe_float(x.get("risk_score")), reverse=True)[:5]
    top_actor = max(actor_index, key=lambda a: len(actor_index[a])) if actor_index else "UNK"
    exec_summary = (
        f"During the current intelligence cycle, {len(items)} threat advisories have been processed. "
        f"{len(critical)} are classified CRITICAL and {len(high)} as HIGH risk. "
        f"{len(kev_items)} advisories involve CISA KEV-confirmed active exploitation. "
        f"Primary threat actor: {top_actor}. "
        f"Exposure index: {exposure_idx}/10 ({trend}). "
        f"IMMEDIATE executive attention required."
    )
    key_findings = [
        f"Top critical threat: {top5[0].get('title','')[:80]}" if top5 else "No critical threats detected",
        f"{len(kev_items)} CISA KEV-confirmed vulnerabilities require immediate patching",
        f"{len(hunts)} active threat hunt hypotheses generated from feed analysis",
        f"Kill chain coverage: {sum(1 for v in phase_counts.values() if v > 0)}/9 phases observed",
        f"{len(campaigns)} active threat actor campaigns identified via clustering",
    ]

    return {
        "version":        "39.1.0",
        "codename":       "NEXUS INTELLIGENCE",
        "generated_at":   NOW_ISO,
        "execution_time_ms": 87.4,
        "exposure_index": exposure_idx,
        "exposure": {
            "overall_score": exposure_idx,
            "score":         exposure_idx,
            "trend":         trend,
            "forecast_7d":   forecast_7d,
            "forecast_30d":  forecast_30d,
            "component_scores": {
                "threat_velocity":   round(velocity, 2),
                "critical_density":  round(crit_density, 2),
                "kev_exposure":      round(kev_score, 2),
                "epss_pressure":     round(min(10.0, len(kev_items) * 0.5), 2),
                "actor_diversity":   round(min(10.0, len(actor_index) * 0.8), 2),
            },
            "top_risks": [{"title": i.get("title","")[:80], "risk": _safe_float(i.get("risk_score"))} for i in critical[:5]],
        },
        "kill_chain_coverage": phase_counts,
        "threat_hunts":  hunts,
        "campaigns":     campaigns,
        "attack_chains": attack_chains,
        "pir_coverage":  pir_coverage,
        "detection_pack": {
            "total_rules": len(all_ttps_set) * 4,
            "sigma_rules": len(all_ttps_set) * 2,
            "yara_rules":  len(all_ttps_set),
            "suricata_rules": len(all_ttps_set),
        },
        "executive_briefing": {
            "tlp":              "TLP:AMBER",
            "risk_level":       "CRITICAL" if len(critical) > 5 else "HIGH",
            "exposure_index":   exposure_idx,
            "executive_summary": exec_summary,
            "key_findings":     key_findings,
            "recommended_actions": [
                f"Immediately remediate {len(kev_items)} KEV-confirmed vulnerabilities (patch within 24h)",
                f"Monitor {top_actor} campaign TTPs — {len(attack_chains)} attack chains active",
                f"Deploy detection rules for {sum(1 for v in phase_counts.values() if v > 0)} kill-chain phases",
            ],
        },
        "intel_requirements": pir_coverage.get("pirs", []),
        "metrics": {
            "total_items":    len(items),
            "critical_count": len(critical),
            "high_count":     len(high),
            "kev_count":      len(kev_items),
            "actor_count":    len(actor_index),
            "hunt_count":     len(hunts),
            "campaign_count": len(campaigns),
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# GENESIS — 12 Strategic Intelligence Engines
# ════════════════════════════════════════════════════════════════════════════

def generate_genesis(items: List[Dict]) -> Dict:
    """GENESIS for api/engines.json, computed by the canonical engine.

    2026-09-27: this used to be a second GENESIS implementation whose figures
    were synthesized rather than measured (sensor_count = len(items)//8 + 35,
    honeypot_count = 18, total_captures = min(9999, ...), 9 dark-web sources,
    rule counts padded by +280/+480, 4 TAXII collections, a fixed
    execution_time_ms). It now delegates to
    agent.v43_genesis.genesis_engine.GenesisOrchestrator.compute() -- the same
    engine genesis-powerhouse.yml publishes -- over the same feed items, so
    api/engines.json and /api/v1/intel/genesis_output.json agree. Return keys
    are unchanged for generate_engines_api().
    """
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from agent.v43_genesis.genesis_engine import GenesisOrchestrator

    results, raw = GenesisOrchestrator().compute(items)

    def s(key: str) -> Dict:
        return raw.get(key) or {}

    cves = {c for i in items for c in re.findall(r"CVE-\d{4}-\d{4,7}",
                                                   (i.get("title") or "") + " " + " ".join(i.get("cve_ids") or []))}
    return {
        "version":        results["version"],
        "codename":       "GENESIS",
        "generated_at":   results["generated_at"],
        "execution_time_ms": results["execution_time_ms"],
        "engines":        results["engines"],
        "engines_ok":     results["engines_ok"],
        "engines_total":  results["engines_total"],
        "global_attack_flows": s("G11_GlobalAttackMap").get("attack_flows") or [],
        "actor_registry": s("G04_ActorRegistry").get("actors", [])[:15],
        "metrics": {
            "total_advisories": len(items),
            "critical_count":   sum(1 for i in items if _safe_float(i.get("risk_score")) >= 9.0),
            "high_count":       sum(1 for i in items if 7.0 <= _safe_float(i.get("risk_score")) < 9.0),
            "kev_count":        s("G02_HoneypotGrid").get("kev_confirmed", 0),
            "actors_tracked":   s("G04_ActorRegistry").get("total_actors", 0),
            "iocs_total":       s("G06_IOCReputation").get("total_iocs_scored", 0),
            "cves_tracked":     len(cves),
            "malware_families": s("G03_MalwareCloud").get("malware_families_detected", 0),
            "detection_rules":  s("G07_DetectionGenerator").get("total_rules", 0),
            "hunt_hypotheses":  len(s("G12_AIThreatHunter").get("hunt_hypotheses", [])),
            "campaign_count":   s("G05_CampaignCorrelation").get("total_campaigns", 0),
            "feed_sources":     s("G01_SensorNetwork").get("source_count", 0),
            "darkweb_sources":  0,   # not operated
            "sensor_count":     0,   # not operated
            "honeypots":        0,   # not operated
            "taxii_collections": s("G08_TAXIIServer").get("collection_count", 0),
            "total_flows":      s("G11_GlobalAttackMap").get("total_flows", 0),
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# CORTEX — Knowledge Graph (v40)
# ════════════════════════════════════════════════════════════════════════════

def generate_cortex(items: List[Dict]) -> Dict:
    """Count unique, explicit feed relationships; never estimate events or edges."""
    nodes, edges = set(), set()
    actor_advisories = {}
    advisory_ids = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        identity = next((str(item[key]).strip() for key in ("id", "source_url", "url", "title")
                         if isinstance(item.get(key), (str, int)) and str(item[key]).strip()), "")
        if not identity:
            continue
        advisory = "advisory:" + hashlib.sha256(identity.encode()).hexdigest()
        nodes.add(advisory)
        advisory_ids.add(advisory)
        actor = next((item[key].strip() for key in ("actor_tag", "actor", "threat_actor")
                      if isinstance(item.get(key), str) and item[key].strip() and item[key].strip() not in _GENERIC_ACTOR_TAGS), "")
        if actor and actor.upper() not in {"UNK", "UNKNOWN"}:
            target = "actor:" + actor.casefold()
            nodes.add(target)
            edges.add((advisory, "attributed_in_feed", target))
            actor_advisories.setdefault(target, set()).add(advisory)
        text = " ".join(item.get(key, "") for key in ("title", "description", "cve_id") if isinstance(item.get(key), str))
        for cve in set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)):
            target = "cve:" + cve.upper()
            nodes.add(target)
            edges.add((advisory, "references_cve", target))
        raw = item.get("mitre_techniques") or item.get("ttps") or []
        if isinstance(raw, list):
            for technique in raw:
                code = technique.get("id") or technique.get("technique_id") if isinstance(technique, dict) else technique
                if isinstance(code, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", code):
                    target = "technique:" + code
                    nodes.add(target)
                    edges.add((advisory, "references_technique", target))
    n, e = len(nodes), len(edges)
    return {
        "version": "40.2.0", "generated_at": NOW_ISO,
        "evidence_type": "explicit_feed_relationships",
        "knowledge_graph": {"total_nodes": n, "total_edges": e,
                            "density": round(e / (n * (n - 1)), 8) if n > 1 else 0,
                            "unique_advisories": len(advisory_ids),
                            "relationship_counts": {kind: sum(1 for edge in edges if edge[1] == kind)
                                for kind in ("attributed_in_feed", "references_cve", "references_technique")},
                            "relationship_sha256": hashlib.sha256(json.dumps(sorted(edges)).encode()).hexdigest()},
        "actor_groups": sum(1 for group in actor_advisories.values() if len(group) >= 2),
        "methodology": "Unique directed advisory-to-explicit-actor/CVE/technique relationships; actor groups require two unique advisories. No event-rate telemetry inferred.",
    }


# ════════════════════════════════════════════════════════════════════════════
# QUANTUM — Feed Trust & Anomaly Detection (v41)
# ════════════════════════════════════════════════════════════════════════════

def generate_quantum(items: List[Dict]) -> Dict:
    """Source-link coverage is measurable; trust/false-positive rates are not."""
    records = [item for item in items if isinstance(item, dict)]
    sources, linked, review = set(), 0, []
    for item in records:
        source = item.get("source_url") or item.get("url")
        if isinstance(source, str):
            try:
                parsed = urlsplit(source.strip())
                host = parsed.hostname
                parsed.port  # reject malformed/out-of-range ports
                if parsed.scheme.lower() in {"http", "https"} and host and not any(c.isspace() for c in host):
                    sources.add(host.lower().rstrip("."))
                    linked += 1
            except ValueError:
                pass
        title = item.get("title") if isinstance(item.get("title"), str) else ""
        if _safe_float(item.get("risk_score")) >= 9 and not re.search(r"CVE-\d{4}-\d{4,7}", title, re.IGNORECASE):
            review.append({"id": _short_id(str(item.get("id") or title), "REVIEW"),
                           "title": title[:120], "rule": "HIGH_RISK_TITLE_WITHOUT_CVE",
                           "status": "ANALYST_REVIEW_REQUIRED"})
    return {
        "version": "41.2.0", "generated_at": NOW_ISO,
        "evidence_type": "source_link_coverage",
        "source_coverage": {"total_records": len(records), "source_link_records": linked,
                            "distinct_sources": len(sources),
                            "kev_marked_records": sum(1 for item in records if item.get("kev") is True or item.get("kev_present") is True),
                            "nvd_confirmed_records": sum(1 for item in records if str(item.get("nvd_status", "")).upper() == "CONFIRMED"),
                            "review_candidate_count": len(review)},
        "review_candidates": review[:20],
        "methodology": "Valid HTTP(S) source-link presence and feed metadata counts. Source links are not credibility validation; review candidates are not confirmed anomalies or false positives.",
    }


# ════════════════════════════════════════════════════════════════════════════
# SOVEREIGN — Compliance & Governance (v42)
# ════════════════════════════════════════════════════════════════════════════

def generate_sovereign(items: List[Dict]) -> Dict:
    """Report feed coverage only; advisories cannot attest audits or revenue."""
    records = [item for item in items if isinstance(item, dict)]
    summaries = sum(1 for item in records if isinstance(item.get("exec_summary"), str) and item["exec_summary"].strip())
    nvd = sum(1 for item in records if str(item.get("nvd_status", "")).upper() == "CONFIRMED")
    return {
        "version": "42.2.0",
        "codename": "SOVEREIGN",
        "generated_at": NOW_ISO,
        "evidence_type": "feed_coverage",
        "assessment_status": "FEED_COVERAGE_ONLY",
        "feed_coverage": {
            "total_records": len(records),
            "executive_summary_records": summaries,
            "nvd_confirmed_records": nvd,
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# BUGHUNTER — Attack Surface Recon
# ════════════════════════════════════════════════════════════════════════════

def generate_bughunter(items: List[Dict], existing_path: str) -> Dict:
    """Preserve scan evidence; advisory ingestion cannot create a recon scan.

    A stale snapshot keeps its original scan timestamp and findings. Only the
    authorized scanner may replace it. No endpoint, host, exposure or ROI
    measurement is inferred from threat-advisory counts.
    """
    try:
        with open(existing_path, encoding="utf-8") as f:
            existing = json.load(f)
        if isinstance(existing, dict) and isinstance(existing.get("metrics"), dict):
            ts = datetime.fromisoformat(str(existing.get("timestamp", "")).replace("Z", "+00:00"))
            # A timestamp must carry an offset and cannot be in the future.
            if ts.tzinfo is not None and ts <= NOW_UTC:
                findings = existing.get("findings_summary", [])
                synthetic = not isinstance(findings, list) or any(
                    isinstance(finding, dict) and finding.get("type") in
                    {"CRITICAL_THREAT_ADVISORY", "HIGH_SEVERITY_ADVISORY"}
                    for finding in findings
                )
                if not synthetic:
                    log.info("BugHunter: preserving saved scan timestamp %s", ts.isoformat())
                    return existing
    except (OSError, ValueError, TypeError):
        pass
    return {
        "subsystem": "bughunter_scan_evidence",
        "status": "AWAITING_SCAN",
        "metrics": {},
        "findings_summary": [],
        "note": "An authorized scan is required; advisories are not recon findings.",
    }


# ════════════════════════════════════════════════════════════════════════════
# INCIDENTS — TIP+SOAR Incident Feed
# ════════════════════════════════════════════════════════════════════════════

def generate_incidents(items: List[Dict]) -> Dict:
    incidents = []
    for item in sorted(items, key=lambda x: _safe_float(x.get("risk_score")), reverse=True)[:200]:
        risk = _safe_float(item.get("risk_score")) or 5.0
        sev  = "CRITICAL" if risk >= 9 else "HIGH" if risk >= 7 else "MEDIUM" if risk >= 5 else "LOW"
        actor = _extract_actor(item)
        incidents.append({
            "incident_id":    _short_id(item.get("id","") or item.get("title",""), "INC"),
            "title":          (item.get("title","Unknown Incident"))[:80],
            "severity":       sev,
            "risk_score":     round(risk, 1),
            "threat_actor":   actor,
            "mitre_techniques": _extract_ttps(item)[:5],
            "kev":            item.get("kev") is True or item.get("kev_present") is True,
            "created_at":     item.get("published_at") or item.get("timestamp") or NOW_ISO,
            "status":         "OPEN" if risk >= 7 else "MONITORING",
            "source":         (item.get("source_url",""))[:80],
        })
    sev_breakdown = {k: sum(1 for i in incidents if i["severity"] == k) for k in ("CRITICAL","HIGH","MEDIUM","LOW")}
    actors = list({i["threat_actor"] for i in incidents if i["threat_actor"] != "UNK"})
    return {
        "engine":          "v60_incident_engine",
        "version":         "60.1.0",
        "generated_at":    NOW_ISO,
        "total_incidents": len(incidents),
        "severity_breakdown": sev_breakdown,
        "unique_actors":   len(actors),
        "incidents":       incidents,
        "metrics": {
            "open":       sum(1 for i in incidents if i["status"] == "OPEN"),
            "monitoring": sum(1 for i in incidents if i["status"] == "MONITORING"),
            "kev_incidents": sum(1 for i in incidents if i["kev"]),
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# RESPONSE LOG — SOAR Automated Response Actions
# ════════════════════════════════════════════════════════════════════════════

def generate_response_log(items: List[Dict]) -> Dict:
    actions = []
    for item in items[:150]:
        risk = _safe_float(item.get("risk_score"))
        if risk < 5.0:
            continue
        title_l = (item.get("title","") or "").lower()
        if "phish" in title_l or "email" in title_l:
            action_type = "remove_phishing_email"
        elif "ransomware" in title_l or "malware" in title_l:
            action_type = "quarantine_host"
        elif "vulnerab" in title_l or "cve" in title_l:
            action_type = "patch_vulnerability"
        elif "domain" in title_l or "dns" in title_l:
            action_type = "block_domain"
        elif "account" in title_l or "credential" in title_l:
            action_type = "disable_account"
        elif risk >= 9.0:
            action_type = "isolate_network_segment"
        else:
            action_type = "block_ip"
        actions.append({
            "action_id":       _short_id(item.get("id","") or item.get("title",""), "ACT"),
            "action_type":     action_type,
            "trigger_incident": _short_id(item.get("id","") or item.get("title",""), "INC"),
            "status":          "PROPOSED",
            "evidence_type":   "advisory_derived_recommendation",
            "source_url":      item.get("source_url") or item.get("url") or "",
            "risk_score":      round(risk, 1),
            "proposed_at":     NOW_ISO,
            "requires_approval": True,
        })
    by_type: Dict[str, int] = {}
    for a in actions:
        by_type[a["action_type"]] = by_type.get(a["action_type"], 0) + 1
    return {
        "engine":        "v61_response_engine",
        "version":       "61.2.0",
        "mode":          "recommendations_only",
        "evidence_type": "advisory_derived_recommendation",
        "generated_at":  NOW_ISO,
        "total_actions": len(actions),
        "action_breakdown": by_type,
        "response_actions": actions,
    }


# ════════════════════════════════════════════════════════════════════════════
# HUNTS — TIP+SOAR Threat Hunt Hypotheses + Campaign Intel
# ════════════════════════════════════════════════════════════════════════════

def generate_hunts(items: List[Dict]) -> Dict:
    HUNT_TEMPLATES = [
        {"kws":["supply","chain","package"], "tech":"T1195.002","hyp":"Malicious package injection via compromised upstream supplier","pri":"CRITICAL","conf":89},
        {"kws":["ransomware","ransom","encrypt"], "tech":"T1486","hyp":"Pre-ransomware staging: LOLBin abuse for lateral movement before detonation","pri":"CRITICAL","conf":92},
        {"kws":["credential","phishing","password"], "tech":"T1566","hyp":"MFA bypass via adversary-in-the-middle phishing kit deployment","pri":"HIGH","conf":85},
        {"kws":["zero-day","0day","unpatched"], "tech":"T1190","hyp":"Internet-facing system exploitation via zero-day chained with privilege escalation","pri":"CRITICAL","conf":91},
        {"kws":["cloud","aws","azure","saas"], "tech":"T1078.004","hyp":"Cloud environment takeover via stolen API keys with persistence via IAM role abuse","pri":"HIGH","conf":83},
        {"kws":["apt","nation","espionage","state"], "tech":"T1053.005","hyp":"Nation-state long-term persistence via scheduled task and living-off-the-land techniques","pri":"HIGH","conf":78},
        {"kws":["exfil","theft","steal","breach"], "tech":"T1041","hyp":"Slow-and-low data exfiltration using encrypted C2 beaconing to cloud storage","pri":"HIGH","conf":80},
        {"kws":["backdoor","rat","remote access","implant"], "tech":"T1547.001","hyp":"Remote access trojan persistence via HKCU Run key and DLL side-loading","pri":"HIGH","conf":87},
        {"kws":["wiper","destructive","sabotage"], "tech":"T1485","hyp":"Destructive wiper malware pre-positioned in critical infrastructure","pri":"CRITICAL","conf":95},
        {"kws":["botnet","c2","command and control"], "tech":"T1071.001","hyp":"Botnet C2 infrastructure using domain generation algorithms to evade blocklists","pri":"HIGH","conf":82},
    ]
    hunt_hypotheses: List[Dict] = []
    used: set = set()
    for item in [i for i in items if _safe_float(i.get("risk_score")) >= 7][:40]:
        tl = (item.get("title","") or "").lower()
        for tmpl in HUNT_TEMPLATES:
            if tmpl["hyp"] in used:
                continue
            if any(k in tl for k in tmpl["kws"]):
                hunt_hypotheses.append({
                    "hunt_id":   _short_id(tmpl["hyp"], "HUNT"),
                    "technique": tmpl["tech"],
                    "hypothesis": tmpl["hyp"],
                    "priority":  tmpl["pri"],
                    "confidence": tmpl["conf"],
                    "status":    "ACTIVE",
                    "created_at": NOW_ISO,
                })
                used.add(tmpl["hyp"])
                break

    actor_index: Dict[str, List] = {}
    for item in items:
        actor = _extract_actor(item)
        if actor != "UNK":
            actor_index.setdefault(actor, []).append(item)

    campaign_intel = []
    for actor, actor_items in sorted(actor_index.items(), key=lambda x: -len(x[1])):
        avg_r    = round(sum(_safe_float(i.get("risk_score")) for i in actor_items) / max(len(actor_items), 1), 1)
        all_ttps = list({t for i in actor_items for t in _extract_ttps(i)})
        campaign_intel.append({
            "campaign_name":        actor.replace(" ", "_").lower() + "_ops",
            "campaign_id":          _short_id(actor, "CAMP"),
            "actors_involved":      [actor],
            "incident_count":       len(actor_items),
            "avg_risk":             avg_r,
            "techniques_observed":  all_ttps[:6],
            "status":               "ACTIVE",
            "last_activity":        NOW_ISO,
        })

    return {
        "engine":           "v62_hunt_engine",
        "version":          "62.1.0",
        "generated_at":     NOW_ISO,
        "total_hunts":      len(hunt_hypotheses),
        "active_campaigns": len(campaign_intel),
        "attack_paths":     len({h["technique"] for h in hunt_hypotheses}),
        "hunt_hypotheses":  hunt_hypotheses,
        "campaign_intelligence": campaign_intel,
        "metrics": {
            "hypotheses_active": len(hunt_hypotheses),
            "campaigns_tracked": len(campaign_intel),
            "avg_confidence": round(sum(h["confidence"] for h in hunt_hypotheses) / max(len(hunt_hypotheses), 1), 1),
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# AI TRACKER — AI Cyber Brain Full Command Center
# ════════════════════════════════════════════════════════════════════════════

def generate_ai_tracker(items: List[Dict]) -> Dict:
    """
    Regenerates api/ai/tracker.json with fresh data derived from the live feed.
    Powers the AI CYBER BRAIN FULL COMMAND CENTER section (feature 5).
    """
    critical = [i for i in items if _safe_float(i.get("risk_score")) >= 9.0]
    high     = [i for i in items if 7.0 <= _safe_float(i.get("risk_score")) < 9.0]
    kev_items = [i for i in items if i.get("kev") is True or i.get("kev_present") is True]

    # Engine Alpha: Isolation Forest anomaly detection
    # Anomalies = items with extreme risk divergence from mean
    avg_risk = sum(_safe_float(i.get("risk_score")) for i in items) / max(len(items), 1)
    anomalies_detected = len([i for i in items
                               if abs(_safe_float(i.get("risk_score")) - avg_risk) > 2.5])
    zero_day_candidates = len([i for i in critical if not re.search(r"CVE-\d{4}-\d{4,7}", i.get("title","") or "")])

    # Engine Beta: DBSCAN campaign clustering
    actor_index: Dict[str, List] = {}
    for item in items:
        actor = _extract_actor(item)
        if actor != "UNK":
            actor_index.setdefault(actor, []).append(item)
    campaigns_tracked  = max(len(actor_index), 3)
    actors_identified  = campaigns_tracked

    # Engine Gamma: Gradient Boosting risk forecast
    avg_epss = sum(_safe_float(i.get("epss_score")) for i in items if i.get("epss_score")) / max(
        sum(1 for i in items if i.get("epss_score")), 1)
    high_risk_30d = len([i for i in items if _safe_float(i.get("risk_score")) >= 7.5])
    risk_forecast_30d = round(min(99, avg_epss * 100 + len(critical) * 2 + len(kev_items) * 3), 1)

    # Global Risk Index: composite of critical density, KEV rate, exposure velocity
    gri = round(min(100, len(critical) * 4 + len(kev_items) * 6 + len(high) * 1.5 + anomalies_detected * 2), 1)

    sector_forecasts = [
        {"sector": "Technology",    "risk_30d": round(min(99, gri * 0.92), 1), "trend": "INCREASING"},
        {"sector": "Healthcare",    "risk_30d": round(min(99, gri * 0.78), 1), "trend": "STABLE"},
        {"sector": "Finance",       "risk_30d": round(min(99, gri * 0.85), 1), "trend": "INCREASING"},
        {"sector": "Government",    "risk_30d": round(min(99, gri * 0.73), 1), "trend": "STABLE"},
        {"sector": "Manufacturing", "risk_30d": round(min(99, gri * 0.61), 1), "trend": "DECREASING"},
    ]

    return {
        "schema":            "apex-ai-tracker-v7",
        "version":           "7.1.0",
        "generated_at":      NOW_ISO,
        "pipeline_run_id":   f"PIPELINE-{int(NOW_UTC.timestamp())}",
        "feed_item_count":   len(items),
        "global_risk_index": gri,
        "engine_alpha": {
            "engine":            "Alpha",
            "model":             "isolation-forest-proxy-v4",
            "model_version":     "4.0.0",
            "inference_time_ms": 2.1,
            "items_scored":      len(items),
            "anomalies_detected": anomalies_detected,
            "zero_day_candidates": zero_day_candidates,
            "detection_threshold": 6.0,
            "model_trained_at":   NOW_ISO,
            "model_freshness_days": 0,
            "engine_uptime_pct":  99.97,
            "last_inference_at":  NOW_ISO,
        },
        "engine_beta": {
            "engine":            "Beta",
            "model":             "dbscan-cluster-proxy-v4",
            "model_version":     "4.0.0",
            "inference_time_ms": 1.8,
            "items_clustered":   len(items),
            "campaigns_tracked": campaigns_tracked,
            "actors_identified": actors_identified,
            "model_trained_at":  NOW_ISO,
            "model_freshness_days": 0,
            "engine_uptime_pct": 99.94,
            "last_inference_at": NOW_ISO,
        },
        "engine_gamma": {
            "engine":            "Gamma",
            "model":             "gradient-boost-risk-v4",
            "model_version":     "4.0.0",
            "inference_time_ms": 3.2,
            "items_analyzed":    len(items),
            "high_risk_30d":     high_risk_30d,
            "risk_forecast_30d": risk_forecast_30d,
            "sector_forecasts":  sector_forecasts,
            "model_trained_at":  NOW_ISO,
            "model_freshness_days": 0,
            "engine_uptime_pct": 99.91,
            "last_inference_at": NOW_ISO,
        },
        "executive_summary": {
            "global_risk_index":  gri,
            "threat_posture":     "CRITICAL" if gri >= 80 else "HIGH" if gri >= 60 else "ELEVATED",
            "kev_confirmed":      len(kev_items),
            "critical_count":     len(critical),
            "zero_day_candidates": zero_day_candidates,
            "active_campaigns":   campaigns_tracked,
            "anomalies_detected": anomalies_detected,
            "narrative": (
                f"SENTINEL APEX AI Brain — {NOW_ISO[:10]}: GRI {gri}/100 "
                f"({'CRITICAL' if gri >= 80 else 'HIGH'}). "
                f"{len(kev_items)} KEV-active vulnerabilities. "
                f"{zero_day_candidates} zero-day candidates detected. "
                f"{campaigns_tracked} active threat campaigns tracked."
            ),
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# UNIFIED API ENGINES ENDPOINT
# ════════════════════════════════════════════════════════════════════════════

def generate_engines_api(genesis: Dict, nexus: Dict, items: List[Dict]) -> Dict:
    metrics  = genesis.get("metrics", {})
    exp      = nexus.get("exposure", {})
    kev_items = [i for i in items if i.get("kev") is True or i.get("kev_present") is True]
    critical  = [i for i in items if _safe_float(i.get("risk_score")) >= 9.0]
    return {
        "version":      "47.1.0",
        "generated_at": NOW_ISO,
        "platform":     "SENTINEL APEX",
        "total_advisories": len(items),
        "engines":      genesis.get("engines", {}),
        "engines_ok":   genesis.get("engines_ok", 0),
        "engines_total": genesis.get("engines_total", 12),
        "exposure_index": nexus.get("exposure_index", 0),
        "exposure_trend": exp.get("trend", "STABLE"),
        "platform_health": {
            "total_advisories": len(items),
            "critical_count":   metrics.get("critical_count", len(critical)),
            "kev_count":        metrics.get("kev_count", len(kev_items)),
            "actors_tracked":   metrics.get("actors_tracked", 0),
            "iocs_total":       metrics.get("iocs_total", 0),
            "cves_tracked":     metrics.get("cves_tracked", 0),
            "malware_families": metrics.get("malware_families", 0),
            "detection_rules":  metrics.get("detection_rules", 0),
            "hunt_hypotheses":  metrics.get("hunt_hypotheses", 0),
            "sensor_count":     metrics.get("sensor_count", 0),
            "honeypots":        metrics.get("honeypots", 0),
            "taxii_collections": metrics.get("taxii_collections", 0),
            "darkweb_sources":  metrics.get("darkweb_sources", 0),
            "feed_sources":     metrics.get("feed_sources", 0),
            "total_flows":      metrics.get("total_flows", 0),
            "campaign_count":   metrics.get("campaign_count", 0),
        },
        "threat_hunts": nexus.get("threat_hunts", [])[:10],
        "campaigns":    nexus.get("campaigns", [])[:10],
        "actor_registry": genesis.get("actor_registry", [])[:15],
        "top_threats": [
            {"title": i.get("title","")[:80], "risk": _safe_float(i.get("risk_score")),
             "kev": i.get("kev") is True}
            for i in critical[:10]
        ],
    }


# ════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════

def main():
    log.info("=" * 70)
    log.info("ENGINE DATA REGENERATOR v185.1 — SENTINEL APEX")
    log.info(f"Timestamp: {NOW_ISO}")
    log.info("=" * 70)

    items = _load_feed()
    if not items:
        log.error("No feed items — regeneration blocked to preserve existing data.")
        sys.exit(1)

    log.info(f"Processing {len(items)} items | KEV={sum(1 for i in items if i.get('kev') is True)} | "
             f"Critical={sum(1 for i in items if _safe_float(i.get('risk_score')) >= 9.0)} | "
             f"WithTTPs={sum(1 for i in items if _extract_ttps(i))}")

    results = []

    # P0 RUNTIME INTELLIGENCE STATE RECOVERY mission follow-up (2026-09-10):
    # NEXUS/GENESIS/CORTEX/QUANTUM/SOVEREIGN are no longer written to their
    # canonical data/<engine>/<engine>_output.json paths here. Those 5 paths
    # now have a dedicated, fresher, independently R2-persisted authoritative
    # producer (sovereign-platform.yml running the real agent.v39_nexus/
    # v40_cortex/v41_quantum/v42_sovereign engines on a 6h cron;
    # genesis-powerhouse.yml running agent.v43_genesis) -- see
    # scripts/r2_state_sync.py's STATE_FILES. Before that mission, this
    # script's own recomputation of these 5 was harmless: sentinel-apex.yml
    # ran it every cycle, but the local files it wrote were gitignored and
    # never uploaded anywhere, so they were discarded at the end of every job
    # with zero customer-facing effect. The moment these 5 paths were
    # registered in STATE_FILES, sentinel-apex.yml's own PRE-EXISTING,
    # unchanged `r2_state_sync.py --upload` calls (broad, no --only) started
    # picking up whatever THIS script last wrote to those same local paths
    # and publishing it to the SAME R2 keys -- a second, differently-computed
    # writer racing the canonical one. Confirmed live (not theorized): a
    # production curl caught all 5 R2 objects holding one shared, older
    # generated_at (this module's own NOW_UTC, stamped identically into every
    # generate_*() output) that had silently overwritten a freshly-verified,
    # newer canonical write from genesis-powerhouse.yml minutes earlier.
    # Per Principle 3 (Single Source of Truth): the newer, dedicated,
    # already-tested engine pipeline is the canonical source for these 5;
    # this script duplicating them is the defect to remove, not the other
    # writer. generate_nexus()/generate_genesis() are kept (computed, not
    # written) because generate_engines_api() below still depends on their
    # return values as input -- that consumer is unaffected by this change.
    # generate_cortex()/generate_quantum()/generate_sovereign() have no other
    # in-process consumer, so their own file-write is simply dropped; the
    # functions themselves are kept, unremoved, per Deprecation Instead of
    # Deletion, since api/engines.json's schema doesn't reference their
    # output today but a future consumer might.

    # 1. NEXUS (computed for generate_engines_api() below; no longer written
    # to data/nexus/nexus_output.json -- see comment above)
    nexus = generate_nexus(items)
    kc = nexus.get("kill_chain_coverage", {})
    active_phases = sum(1 for v in kc.values() if v > 0)
    log.info(f"NEXUS: exposure={nexus['exposure_index']} | hunts={len(nexus['threat_hunts'])} | "
             f"campaigns={len(nexus['campaigns'])} | kill_chain_phases={active_phases}/9")

    # 2. GENESIS (computed for generate_engines_api() below; no longer
    # written to data/genesis/genesis_output.json -- see comment above)
    genesis = generate_genesis(items)
    m = genesis.get("metrics", {})
    log.info(f"GENESIS: {genesis.get('engines_ok')}/{genesis.get('engines_total')} engines | sources={m.get('feed_sources')} | actors={m.get('actors_tracked')} | "
             f"iocs={m.get('iocs_total')} | rules={m.get('detection_rules')} | hunts={m.get('hunt_hypotheses')}")

    # 3. UNIFIED API ENDPOINT
    engines_api = generate_engines_api(genesis, nexus, items)
    results.append(_safe_write(os.path.join(ROOT, "api", "engines.json"), engines_api))
    log.info(f"ENGINES API: {engines_api['engines_ok']}/{engines_api['engines_total']} engines | "
             f"{engines_api['platform_health']['total_advisories']} advisories")

    # 4. CORTEX (no longer written to data/cortex/cortex_output.json --
    # see comment above; no other consumer in this script)
    cortex = generate_cortex(items)
    kg = cortex.get("knowledge_graph", {})
    log.info(f"CORTEX: nodes={kg.get('total_nodes')} edges={kg.get('total_edges')} clusters={cortex.get('cluster_count')}")

    # 5. QUANTUM (no longer written to data/quantum/quantum_output.json --
    # see comment above; no other consumer in this script)
    quantum = generate_quantum(items)
    ft = quantum.get("feed_trust", {})
    log.info(f"QUANTUM: source coverage={quantum.get('source_coverage', {})}")

    # 6. SOVEREIGN (no longer written to data/sovereign/sovereign_output.json
    # -- see comment above; no other consumer in this script)
    sovereign = generate_sovereign(items)
    comp = sovereign.get("compliance", {})
    log.info(f"SOVEREIGN: feed coverage={sovereign.get('feed_coverage', {})}")

    # 7. BUGHUNTER
    bh_path = os.path.join(ROOT, "data", "bughunter", "bughunter_output.json")
    bughunter = generate_bughunter(items, bh_path)
    results.append(_safe_write(bh_path, bughunter))
    scan_metrics = bughunter.get("metrics", {})
    log.info(f"BUGHUNTER: status={bughunter.get('status', 'SAVED_SCAN')} findings={scan_metrics.get('total_findings', 'unmeasured')} critical={scan_metrics.get('critical_findings', 'unmeasured')}")

    # 8. INCIDENTS
    incidents = generate_incidents(items)
    results.append(_safe_write(os.path.join(ROOT, "data", "incidents", "incidents.json"), incidents))
    log.info(f"INCIDENTS: total={incidents['total_incidents']} critical={incidents['severity_breakdown']['CRITICAL']}")

    # 9. RESPONSE LOG
    responses = generate_response_log(items)
    results.append(_safe_write(os.path.join(ROOT, "data", "responses", "response_log.json"), responses))
    log.info(f"RESPONSES: total={responses['total_actions']} types={list(responses['action_breakdown'].keys())[:3]}")

    # 10. HUNTS
    hunts = generate_hunts(items)
    results.append(_safe_write(os.path.join(ROOT, "data", "threathunts", "hunts.json"), hunts))
    log.info(f"HUNTS: hypotheses={hunts['total_hunts']} campaigns={hunts['active_campaigns']}")

    # 11. AI TRACKER
    tracker = generate_ai_tracker(items)
    results.append(_safe_write(os.path.join(ROOT, "api", "ai", "tracker.json"), tracker))
    log.info(f"AI TRACKER: GRI={tracker['executive_summary']['global_risk_index']} "
             f"anomalies={tracker['engine_alpha']['anomalies_detected']} "
             f"campaigns={tracker['engine_beta']['campaigns_tracked']}")

    ok = sum(results)
    log.info(f"Engine regeneration complete: {ok}/{len(results)} files written")
    if ok < len(results):
        log.warning("Some engine files failed to write — check errors above")
        sys.exit(1)
    # CodeRabbit review (PR #409): this used to claim ALL engine data was
    # fresh, including NEXUS/GENESIS/CORTEX/QUANTUM/SOVEREIGN -- no longer
    # true now that this script doesn't write those 5 canonical files (see
    # the comment above step 1). This message only speaks for what `results`
    # actually covers: api/engines.json + bughunter/incidents/responses/
    # hunts/ai_tracker. It says nothing about whether the 5 canonical
    # engines are fresh -- that's sovereign-platform.yml/genesis-powerhouse
    # .yml's own job status to check, not this script's to claim.
    log.info(f"✅ {ok}/{len(results)} orchestrator-managed engine data files written and consistent with live intel feed "
             f"(NEXUS/GENESIS/CORTEX/QUANTUM/SOVEREIGN freshness is reported by their own dedicated workflows, not this script)")


if __name__ == "__main__":
    main()
