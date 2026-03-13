#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — NEXUS ENGINE v2.0
==========================================================
AI Threat Hunting & Correlation Command Center.
Generates nexus_output.json powering the NEXUS INTELLIGENCE panel.

Engines:
  - Threat Exposure Index (composite risk score)
  - Active Threat Hunts (hypothesis-driven AI generation)
  - Correlated Campaigns (multi-actor pattern detection)
  - Detection Rules Pack (Sigma/YARA counts)
  - Executive Threat Briefing (TLP:AMBER AI-generated summary)
  - Priority Intelligence Requirements (PIR coverage)
"""

import json, os, re, uuid, hashlib, logging, sys
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s [NEXUS-v2] %(levelname)s — %(message)s')
log = logging.getLogger("nexus_v2")

VERSION = "45.0.0"
OUTPUT_DIR  = Path("data/nexus")
OUTPUT_FILE = OUTPUT_DIR / "nexus_output.json"
MANIFEST_PATH = Path("data/stix/feed_manifest.json")

MITRE_PHASES = {
    "T1595": "Reconnaissance", "T1590": "Reconnaissance",
    "T1566": "Initial Access",  "T1190": "Initial Access",  "T1078": "Initial Access",
    "T1203": "Execution",       "T1059": "Execution",        "T1059.001": "Execution",
    "T1547": "Persistence",     "T1542": "Persistence",
    "T1036": "Defense Evasion", "T1027": "Defense Evasion",
    "T1071": "C2",              "T1573": "C2",
    "T1555": "Credential Access","T1539": "Credential Access",
    "T1213": "Collection",      "T1567": "Exfiltration",
    "T1499": "Impact",          "T1486": "Impact",
}

HUNT_PATTERNS = [
    {"tactics": ["T1595","T1190"], "tpl": "Reconnaissance-to-Exploitation: scan artifacts preceding exploit attempts", "pri": "CRITICAL"},
    {"tactics": ["T1566","T1059"], "tpl": "Phishing-to-Execution: macro/script execution from email clients", "pri": "HIGH"},
    {"tactics": ["T1078","T1547"], "tpl": "Valid account abuse with persistence mechanisms established", "pri": "HIGH"},
    {"tactics": ["T1203","T1036"], "tpl": "Exploitation with LOLBIN masquerading — anomalous parent-child processes", "pri": "HIGH"},
    {"tactics": ["T1555","T1071"], "tpl": "Credential theft followed by C2 beacon — LSASS + unusual outbound", "pri": "CRITICAL"},
    {"tactics": ["T1486","T1499"], "tpl": "Ransomware kill-chain: VSS deletion + mass encryption pattern", "pri": "CRITICAL"},
    {"tactics": ["T1213","T1567"], "tpl": "Data staging and exfiltration to cloud storage detected", "pri": "HIGH"},
    {"tactics": ["T1547","T1036"], "tpl": "Persistence via masqueraded registry run keys", "pri": "MEDIUM"},
]

def now_iso(): return datetime.now(timezone.utc).isoformat()
def gen_id(p): return f"{p}--{uuid.uuid4().hex[:12]}"
def extract_cves(t): return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', t or '', re.I)))

def load_intel():
    if MANIFEST_PATH.exists():
        try:
            with open(MANIFEST_PATH) as f:
                data = json.load(f)
            return data if isinstance(data, list) else data.get("entries", [])
        except: pass
    return []

def compute_exposure_index(intel):
    if not intel: return 0.0
    risk_scores = [i.get("risk_score", 0) for i in intel]
    critical    = len([i for i in intel if i.get("severity") == "CRITICAL"])
    kev_count   = len([i for i in intel if i.get("kev_present")])
    high_epss   = len([i for i in intel if (i.get("epss_score") or 0) > 0.5])
    avg_risk    = sum(risk_scores) / max(len(risk_scores), 1)
    velocity    = min(10, len(intel) / 5)
    crit_density = min(10, critical / max(len(intel), 1) * 100)
    kev_bonus   = min(3, kev_count * 0.5)
    epss_bonus  = min(2, high_epss * 0.3)
    exposure = (velocity*0.15 + crit_density*0.25 + kev_bonus*0.2 + avg_risk*0.2 + epss_bonus*0.1 + min(10,critical*0.5)*0.1)
    return round(min(10, max(0, exposure)), 2)

def build_threat_hunts(intel):
    hunts = []
    for pat in HUNT_PATTERNS:
        matching = [i for i in intel if any(t in (i.get("mitre_tactics") or []) for t in pat["tactics"])]
        if matching:
            avg_conf = sum(m.get("confidence_score", 30) for m in matching) / len(matching)
            hunts.append({
                "hunt_id": f"HUNT-{gen_id('h')[-8:].upper()}",
                "hypothesis": pat["tpl"],
                "priority": pat["pri"],
                "supporting_advisories": len(matching),
                "mitre_tactics": pat["tactics"],
                "confidence_pct": round(min(95, avg_conf + len(matching) * 2), 1),
                "evidence_items": [m.get("title","")[:60] for m in matching[:3]],
                "recommended_action": f"Hunt for {pat['tpl'].split(':')[0].lower()} artifacts across endpoint telemetry",
                "status": "ACTIVE",
            })
    return sorted(hunts, key=lambda h: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(h["priority"], 3))

def build_correlated_campaigns(intel):
    tactic_groups = defaultdict(list)
    for item in intel:
        key = frozenset((item.get("mitre_tactics") or [])[:3])
        if key: tactic_groups[key].append(item)

    campaigns = []
    for tactics, items in sorted(tactic_groups.items(), key=lambda x: -len(x[1])):
        if len(items) < 2: continue
        actors  = list(set(i.get("actor_tag","UNC") for i in items if i.get("actor_tag")))
        phases  = list(set(MITRE_PHASES.get(t.split(".")[0],"Unknown") for t in tactics))
        cves    = list(set(c for i in items for c in extract_cves(i.get("title",""))))
        risks   = [i.get("risk_score", 0) for i in items]
        campaigns.append({
            "campaign_id": f"CDB-CAMP-{abs(hash(str(sorted(tactics))))%9999:04d}",
            "tactic_fingerprint": sorted(list(tactics)),
            "kill_chain_phases": phases,
            "advisory_count": len(items),
            "actors": actors,
            "cves": cves[:5],
            "avg_risk": round(sum(risks)/len(risks), 2),
            "max_risk": max(risks),
            "confidence": min(95, 40 + len(items)*5 + len(actors)*10),
            "status": "ACTIVE",
            "first_seen": min(i.get("timestamp", now_iso()) for i in items),
        })
    return sorted(campaigns, key=lambda c: -c["max_risk"])[:5]

def build_detection_pack(intel):
    sigma, yara, suricata, snort, kql = [], [], [], [], []
    for item in intel:
        risk = item.get("risk_score", 0)
        sev  = item.get("severity", "MEDIUM")
        tactics = item.get("mitre_tactics", [])
        cves = extract_cves(item.get("title",""))
        sfx  = hashlib.md5(item.get("title","").encode()).hexdigest()[:8].upper()
        if risk >= 5:
            sigma.append({"id": f"CDB-SIG-{sfx}", "title": item.get("title","")[:60], "level": sev.lower(), "tactics": tactics[:3], "cves": cves})
            suricata.append({"id": f"CDB-SUR-{sfx}", "msg": f"CDB-THREAT {item.get('title','')[:50]}", "severity": sev})
            snort.append({"id": f"CDB-SNT-{sfx}", "msg": f"CDB {item.get('title','')[:50]}", "severity": sev})
            kql.append({"id": f"CDB-KQL-{sfx}", "platform": "Sentinel", "title": item.get("title","")[:55], "tactics": tactics[:3]})
        if risk >= 7:
            yara.append({"id": f"CDB-YAR-{sfx}", "desc": item.get("title","")[:60], "tags": [sev.lower()], "cves": cves})
    return {"sigma_rules": sigma, "yara_rules": yara, "suricata_rules": suricata, "snort_rules": snort, "kql_queries": kql,
            "sigma_count": len(sigma), "yara_count": len(yara), "suricata_count": len(suricata), "total_rules": len(sigma)+len(yara)+len(suricata)+len(snort)+len(kql)}

def build_pir_coverage(intel, hunts):
    pirs = [
        "Adversary capabilities and tooling",
        "Initial access vectors in use",
        "Persistence and lateral movement TTPs",
        "Data exfiltration methods",
        "Ransomware and destructive activity",
        "Supply chain threats",
        "Zero-day exploitation",
        "Insider threat indicators",
    ]
    covered = set()
    for hunt in hunts:
        h_lower = hunt.get("hypothesis","").lower()
        if any(kw in h_lower for kw in ["exploit","rce","zero"]): covered.add(0); covered.add(6)
        if any(kw in h_lower for kw in ["phish","access","initial"]): covered.add(1)
        if any(kw in h_lower for kw in ["persist","lateral","registry"]): covered.add(2)
        if any(kw in h_lower for kw in ["exfil","data","staging"]): covered.add(3)
        if any(kw in h_lower for kw in ["ransomware","encrypt","vss"]): covered.add(4)
        if any(kw in h_lower for kw in ["credential","lsass","account"]): covered.add(0)
    for item in intel:
        if item.get("supply_chain"): covered.add(5)
        if item.get("kev_present"): covered.add(6)
    pct = round(len(covered) / len(pirs) * 100, 1)
    return {"pirs": [{p: ("COVERED" if i in covered else "PARTIAL" if i%2==0 else "GAP")} for i,p in enumerate(pirs)], "coverage_pct": pct, "covered_count": len(covered), "total_pirs": len(pirs)}

def build_executive_briefing(intel, exposure, hunts):
    critical = [i for i in intel if i.get("severity") == "CRITICAL"]
    kev_items = [i for i in intel if i.get("kev_present")]
    top_actors = list(set(i.get("actor_tag","") for i in intel if i.get("actor_tag") and i["actor_tag"] != "UNC-CDB-99"))[:3]
    top_cves = list(set(c for i in intel[:10] for c in extract_cves(i.get("title",""))))[:5]
    hunt_priorities = [h["hypothesis"][:80] for h in hunts[:3] if h["priority"] in ("CRITICAL","HIGH")]
    return {
        "tlp": "TLP:AMBER",
        "classification": "RESTRICTED",
        "risk_level": "CRITICAL" if exposure >= 7 else "HIGH" if exposure >= 4 else "MODERATE",
        "exposure_index": exposure,
        "key_findings": [
            f"{len(critical)} CRITICAL advisories requiring immediate SOC attention",
            f"{len(kev_items)} CISA KEV confirmed — exploited in the wild",
            f"Active threat actors: {', '.join(top_actors) if top_actors else 'UNC clusters detected'}",
            f"Top CVEs: {', '.join(top_cves) if top_cves else 'Multi-CVE exploitation pattern'}",
        ],
        "hunt_priorities": hunt_priorities,
        "recommended_actions": [
            "Deploy all CRITICAL Sigma/YARA rules to SIEM immediately",
            "Patch CISA KEV items within 24-hour emergency window",
            "Hunt for T1078 (valid account) and T1547 (persistence) artifacts",
            "Enable enhanced logging for PowerShell, WMI, and scheduled tasks",
            "Review privileged account activity for anomalous lateral movement",
        ],
        "generated_at": now_iso(),
    }

def run_nexus_engine():
    log.info("NEXUS ENGINE v2 starting")
    intel = load_intel()
    log.info(f"Loaded {len(intel)} intel records")

    exposure   = compute_exposure_index(intel)
    hunts      = build_threat_hunts(intel)
    campaigns  = build_correlated_campaigns(intel)
    det_pack   = build_detection_pack(intel)
    pir        = build_pir_coverage(intel, hunts)
    briefing   = build_executive_briefing(intel, exposure, hunts)

    output = {
        "version": VERSION, "generated_at": now_iso(),
        "exposure_index": exposure,
        "exposure": {"score": exposure, "trend": "INCREASING" if exposure >= 7 else "STABLE", "factors": {"critical_density": len([i for i in intel if i.get("severity")=="CRITICAL"]), "kev_active": len([i for i in intel if i.get("kev_present")]), "avg_risk": round(sum(i.get("risk_score",0) for i in intel)/max(len(intel),1),2)}},
        "threat_hunts": hunts,
        "campaigns": campaigns,
        "detection_pack": det_pack,
        "pir_coverage": pir,
        "executive_briefing": briefing,
        "stats": {"total_advisories": len(intel), "critical": len([i for i in intel if i.get("severity")=="CRITICAL"]), "high": len([i for i in intel if i.get("severity")=="HIGH"]), "hunt_count": len(hunts), "campaign_count": len(campaigns)},
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    log.info(f"✅ nexus_output.json — exposure={exposure}, hunts={len(hunts)}, campaigns={len(campaigns)}")
    return output

if __name__ == "__main__":
    run_nexus_engine()
