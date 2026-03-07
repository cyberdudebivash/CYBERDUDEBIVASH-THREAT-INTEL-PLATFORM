#!/usr/bin/env python3
"""
analyst_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v37.0 (AI THREAT ANALYST)
==============================================================================
Autonomous AI-powered threat analysis engine with 10 integrated subsystems.

Pipeline: Monitor → Analyze → Triage → Generate (Mitigations + Detections +
          Playbooks + Reports) → Knowledge Graph → Copilot Output

Reads from: manifest, STIX bundles, fusion entity store, ZDH alerts/forecasts
Writes to: data/analyst/ (isolated, non-breaking)

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os, re, json, math, hashlib, logging, statistics, textwrap
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import Counter, defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("CDB-AIAnalyst")

MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
STIX_DIR = os.environ.get("STIX_DIR", "data/stix")
FUSION_DIR = os.environ.get("FUSION_DIR", "data/fusion")
ZDH_DIR = os.environ.get("ZDH_DIR", "data/zerodayhunter")
ANALYST_DIR = os.environ.get("ANALYST_DIR", "data/analyst")

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

def _load(path):
    try:
        with open(path) as f: return json.load(f)
    except: return None

def _entries():
    d = _load(MANIFEST_PATH)
    return d if isinstance(d, list) else (d.get("entries", []) if d else [])

def _stix_iocs(stix_file: str) -> Dict[str, List[str]]:
    """Extract IOCs from STIX bundle."""
    iocs = {"ips": [], "domains": [], "urls": [], "hashes": [], "files": []}
    path = os.path.join(STIX_DIR, stix_file)
    if not os.path.exists(path): return iocs
    try:
        bundle = _load(path)
        for obj in (bundle or {}).get("objects", []):
            if obj.get("type") != "indicator": continue
            p = obj.get("pattern", "")
            m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", p)
            if m: iocs["ips"].append(m.group(1))
            m = re.search(r"domain-name:value\s*=\s*'([^']+)'", p)
            if m: iocs["domains"].append(m.group(1))
            m = re.search(r"url:value\s*=\s*'([^']+)'", p)
            if m: iocs["urls"].append(m.group(1))
            m = re.search(r"file:hashes\.'[^']+'\s*=\s*'([^']+)'", p)
            if m: iocs["hashes"].append(m.group(1))
    except: pass
    return iocs


# ═══════════════════════════════════════════════════════════════════════════════
# A1 — THREAT MONITOR
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatMonitor:
    """Collects and normalizes threat signals from all platform data sources."""

    def scan(self, window_hours: int = 168) -> List[Dict]:
        entries = _entries()
        fusion = _load(os.path.join(FUSION_DIR, "entity_store.json")) or {}
        zdh_alerts = _load(os.path.join(ZDH_DIR, "zeroday_alerts.json")) or []

        threats = []
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()

        for e in entries:
            ts = e.get("timestamp", "")
            if ts and ts < cutoff: continue
            title = e.get("title", "")
            risk = e.get("risk_score", 0)
            cves = [c.upper() for c in CVE_RE.findall(title)]
            iocs = _stix_iocs(e.get("stix_file", ""))

            # Cross-reference with ZDH
            zd_match = [a for a in zdh_alerts if a.get("entity", "").upper() in [c for c in cves]]

            threats.append({
                "threat_id": f"thr-{hashlib.md5(e.get('stix_file', title).encode()).hexdigest()[:12]}",
                "title": title, "risk_score": risk, "cves": cves,
                "actor": e.get("actor_tag", ""), "mitre": e.get("mitre_tactics", []),
                "kev": e.get("kev_present", False), "cvss": e.get("cvss_score"),
                "epss": e.get("epss_score"), "supply_chain": e.get("supply_chain", False),
                "iocs": iocs, "ioc_counts": e.get("ioc_counts", {}),
                "stix_file": e.get("stix_file", ""), "timestamp": ts,
                "zeroday_match": len(zd_match) > 0,
                "fusion_mentions": sum(1 for eid, ent in fusion.items()
                    if any(c.lower() in eid.lower() for c in cves)) if cves else 0,
            })

        threats.sort(key=lambda t: t["risk_score"], reverse=True)
        logger.info(f"A1 Monitor: {len(threats)} threats scanned")
        return threats


# ═══════════════════════════════════════════════════════════════════════════════
# A2 — EXPLOIT ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class ExploitAnalyzer:
    """Analyzes exploit characteristics, attack vectors, and exploit chains."""

    VECTOR_MAP = {
        "T1190": "Network — Exploit Public-Facing Application",
        "T1133": "Network — External Remote Services",
        "T1566": "Email — Phishing",
        "T1195": "Supply Chain — Compromise",
        "T1078": "Credential — Valid Accounts",
        "T1059": "Execution — Command and Scripting Interpreter",
        "T1203": "Client — Exploitation for Client Execution",
        "T1068": "Local — Exploitation for Privilege Escalation",
        "T1055": "Memory — Process Injection",
        "T1021": "Network — Remote Services",
    }

    IMPACT_CLASS = {
        (9.0, 10.0): "CATASTROPHIC — Complete system compromise likely",
        (7.0, 8.9): "SEVERE — Significant unauthorized access or data loss",
        (4.0, 6.9): "MODERATE — Limited impact, conditional exploitation",
        (0.0, 3.9): "LOW — Minimal direct impact",
    }

    def analyze(self, threats: List[Dict]) -> List[Dict]:
        analyses = []
        for t in threats:
            if t["risk_score"] < 4: continue  # Skip low-risk

            # Attack vector analysis
            vectors = [self.VECTOR_MAP.get(m, f"Technique {m}") for m in t.get("mitre", [])[:5]]

            # Impact classification
            risk = t["risk_score"]
            impact = "UNKNOWN"
            for (lo, hi), desc in self.IMPACT_CLASS.items():
                if lo <= risk <= hi: impact = desc; break

            # Exploit chain reconstruction
            chain = self._build_chain(t)

            # Exploitability score
            exploit_score = self._exploitability(t)

            analyses.append({
                "threat_id": t["threat_id"],
                "title": t["title"][:80],
                "risk_score": risk,
                "attack_vectors": vectors,
                "impact_classification": impact,
                "exploit_chain": chain,
                "exploitability_score": round(exploit_score, 2),
                "exploitability_label": "CRITICAL" if exploit_score >= 8 else "HIGH" if exploit_score >= 6 else "MEDIUM" if exploit_score >= 3 else "LOW",
                "kev_confirmed": t.get("kev", False),
                "supply_chain_risk": t.get("supply_chain", False),
            })

        analyses.sort(key=lambda a: a["exploitability_score"], reverse=True)
        logger.info(f"A2 Exploit: {len(analyses)} analyses")
        return analyses

    def _build_chain(self, t: Dict) -> List[Dict]:
        mitre = t.get("mitre", [])
        chain = []
        stages = [("Initial Access", ["T1190", "T1566", "T1195", "T1133", "T1078"]),
                  ("Execution", ["T1059", "T1203", "T1047"]),
                  ("Persistence", ["T1053", "T1098", "T1136"]),
                  ("Privilege Escalation", ["T1068", "T1055"]),
                  ("Defense Evasion", ["T1070", "T1027", "T1562"]),
                  ("Lateral Movement", ["T1021", "T1071"]),
                  ("Impact", ["T1486", "T1489", "T1529"])]
        for stage, techs in stages:
            matched = [m for m in mitre if m in techs]
            if matched:
                chain.append({"stage": stage, "techniques": matched, "status": "OBSERVED"})
        return chain

    def _exploitability(self, t: Dict) -> float:
        score = t["risk_score"] * 0.5
        if t.get("kev"): score += 2.5
        if t.get("epss") and t["epss"] > 0.5: score += 1.5
        if t.get("supply_chain"): score += 1.0
        if t.get("zeroday_match"): score += 1.5
        ioc_total = sum(v for v in t.get("ioc_counts", {}).values() if isinstance(v, (int, float)))
        if ioc_total >= 10: score += 0.5
        return min(10.0, score)


# ═══════════════════════════════════════════════════════════════════════════════
# A3 — AI THREAT REASONER
# ═══════════════════════════════════════════════════════════════════════════════

class AIThreatReasoner:
    """Generates contextual intelligence analysis for each threat."""

    def reason(self, threats: List[Dict], analyses: List[Dict]) -> List[Dict]:
        analysis_map = {a["threat_id"]: a for a in analyses}
        reports = []
        for t in threats[:25]:
            a = analysis_map.get(t["threat_id"], {})
            parts = []

            # Threat context
            parts.append(f"Threat: {t['title'][:100]}")
            parts.append(f"Risk Score: {t['risk_score']}/10 | Exploitability: {a.get('exploitability_score', 'N/A')}/10")

            if t.get("cves"):
                parts.append(f"Vulnerabilities: {', '.join(t['cves'][:5])}")
            if t.get("actor") and not t["actor"].startswith("UNC-CDB"):
                parts.append(f"Attributed Actor: {t['actor']}")
            if a.get("attack_vectors"):
                parts.append(f"Attack Vectors: {'; '.join(a['attack_vectors'][:3])}")
            if a.get("impact_classification"):
                parts.append(f"Impact: {a['impact_classification']}")

            # Chain analysis
            if a.get("exploit_chain"):
                stages = [f"{c['stage']} ({','.join(c['techniques'])})" for c in a["exploit_chain"]]
                parts.append(f"Attack Chain: {' → '.join(stages)}")

            # Zero-day / KEV correlation
            if t.get("zeroday_match"):
                parts.append("⚠ ZERO-DAY CORRELATION: Active exploitation signals detected by Zero-Day Hunter")
            if t.get("kev"):
                parts.append("⚠ CISA KEV: Confirmed active exploitation — federal patch mandate active")

            # Assessment
            risk = t["risk_score"]
            if risk >= 9:
                parts.append("ASSESSMENT: CRITICAL — Immediate defensive action required. Activate IR procedures.")
            elif risk >= 7:
                parts.append("ASSESSMENT: HIGH — Prioritize patching and detection deployment within 24-48 hours.")
            elif risk >= 5:
                parts.append("ASSESSMENT: MEDIUM — Monitor closely. Deploy detection rules proactively.")
            else:
                parts.append("ASSESSMENT: LOW — Standard monitoring. Track for escalation.")

            reports.append({
                "threat_id": t["threat_id"],
                "entity": t["cves"][0] if t.get("cves") else t["title"][:60],
                "reasoning": "\n".join(parts),
                "risk_level": "CRITICAL" if risk >= 9 else "HIGH" if risk >= 7 else "MEDIUM" if risk >= 5 else "LOW",
            })

        logger.info(f"A3 Reasoner: {len(reports)} intelligence reports")
        return reports


# ═══════════════════════════════════════════════════════════════════════════════
# A4 — AUTOMATED TRIAGE
# ═══════════════════════════════════════════════════════════════════════════════

class AutomatedTriage:
    """SOC-level threat triage with priority classification."""

    def triage(self, threats: List[Dict], analyses: List[Dict]) -> List[Dict]:
        analysis_map = {a["threat_id"]: a for a in analyses}
        triaged = []
        for t in threats:
            a = analysis_map.get(t["threat_id"], {})
            es = a.get("exploitability_score", t["risk_score"] * 0.6)
            kev = t.get("kev", False)
            zd = t.get("zeroday_match", False)

            # Priority matrix
            if kev or es >= 8 or (zd and t["risk_score"] >= 8):
                priority, sla = "P1_CRITICAL", "1 hour"
            elif es >= 6 or t["risk_score"] >= 8:
                priority, sla = "P2_HIGH", "4 hours"
            elif es >= 4 or t["risk_score"] >= 6:
                priority, sla = "P3_MEDIUM", "24 hours"
            else:
                priority, sla = "P4_LOW", "72 hours"

            triaged.append({
                "threat_id": t["threat_id"], "title": t["title"][:80],
                "priority": priority, "sla": sla,
                "risk_score": t["risk_score"], "exploitability": round(es, 1),
                "kev": kev, "zeroday": zd, "actor": t.get("actor", ""),
                "cves": t.get("cves", [])[:5],
                "affected_products": self._infer_products(t),
                "mitigation_urgency": "IMMEDIATE" if priority == "P1_CRITICAL" else "URGENT" if priority == "P2_HIGH" else "STANDARD",
            })

        triaged.sort(key=lambda x: {"P1_CRITICAL": 0, "P2_HIGH": 1, "P3_MEDIUM": 2, "P4_LOW": 3}[x["priority"]])
        dist = Counter(x["priority"] for x in triaged)
        logger.info(f"A4 Triage: {len(triaged)} triaged | P1={dist.get('P1_CRITICAL',0)} P2={dist.get('P2_HIGH',0)}")
        return triaged

    def _infer_products(self, t: Dict) -> List[str]:
        title = t.get("title", "").lower()
        products = []
        for kw in ["cisco", "microsoft", "apache", "linux", "windows", "chrome", "firefox",
                    "vmware", "fortinet", "palo alto", "juniper", "wordpress", "docker", "kubernetes"]:
            if kw in title: products.append(kw.title())
        return products or ["Unknown"]


# ═══════════════════════════════════════════════════════════════════════════════
# A5 — MITIGATION SCRIPT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class MitigationScriptGenerator:
    """Generates defensive automation scripts: firewall, WAF, SIEM, hardening."""

    def generate(self, threats: List[Dict]) -> List[Dict]:
        scripts = []
        for t in threats:
            if t["risk_score"] < 6: continue
            iocs = t.get("iocs", {})
            ips = iocs.get("ips", [])
            domains = iocs.get("domains", [])
            hashes = iocs.get("hashes", [])
            cves = t.get("cves", [])

            pack = {"threat_id": t["threat_id"], "title": t["title"][:80], "scripts": []}

            # Firewall rules (iptables)
            if ips:
                rules = "\n".join(f"iptables -A INPUT -s {ip} -j DROP" for ip in ips[:15])
                rules += "\n" + "\n".join(f"iptables -A OUTPUT -d {ip} -j DROP" for ip in ips[:15])
                pack["scripts"].append({"type": "firewall_iptables", "content": f"#!/bin/bash\n# CDB APEX v37.0 — Block threat IPs for: {t['title'][:60]}\n{rules}\necho 'Firewall rules applied'"})

            # WAF rules (ModSecurity format)
            if domains:
                dom_pattern = "|".join(re.escape(d) for d in domains[:10])
                waf = f'SecRule REQUEST_HEADERS:Host "@rx {dom_pattern}" "id:370001,phase:1,deny,status:403,msg:\'CDB APEX Block: {t["threat_id"]}\'"'
                pack["scripts"].append({"type": "waf_modsecurity", "content": waf})

            # SIEM query (Splunk SPL)
            if ips or domains:
                parts = []
                if ips: parts.append(f'(dest_ip IN ({",".join(f"\"{ip}\"" for ip in ips[:10])}))')
                if domains: parts.append(f'(query IN ({",".join(f"\"{d}\"" for d in domains[:10])}))')
                spl = f'index=* ({" OR ".join(parts)}) | stats count by src_ip, dest_ip, action | sort -count'
                pack["scripts"].append({"type": "siem_splunk_spl", "content": f"| CDB APEX v37.0 Threat Hunt Query\n{spl}"})

            # Security hardening script
            if cves or t["risk_score"] >= 8:
                harden = f"""#!/bin/bash
# CDB APEX v37.0 — Emergency Hardening Script
# Threat: {t['title'][:60]}
# Generated: {datetime.now(timezone.utc).isoformat()}

echo "[*] Updating system packages..."
apt-get update && apt-get upgrade -y 2>/dev/null || yum update -y 2>/dev/null

echo "[*] Enabling firewall..."
ufw enable 2>/dev/null || firewall-cmd --set-default-zone=drop 2>/dev/null

echo "[*] Disabling unnecessary services..."
systemctl disable --now telnet.socket 2>/dev/null
systemctl disable --now rsh.socket 2>/dev/null

echo "[*] Setting secure SSH configuration..."
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

echo "[+] Hardening complete for threat: {t['threat_id']}"
"""
                pack["scripts"].append({"type": "hardening_bash", "content": harden})

            if pack["scripts"]:
                scripts.append(pack)

        logger.info(f"A5 Mitigation: {len(scripts)} script packs ({sum(len(s['scripts']) for s in scripts)} total scripts)")
        return scripts


# ═══════════════════════════════════════════════════════════════════════════════
# A6 — DETECTION RULE GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionRuleGenerator:
    """Generates detection rules: Sigma, YARA, Snort, Suricata, Elastic, KQL."""

    def generate(self, threats: List[Dict]) -> List[Dict]:
        packs = []
        for t in threats:
            iocs = t.get("iocs", {})
            ips = iocs.get("ips", [])
            domains = iocs.get("domains", [])
            hashes = iocs.get("hashes", [])
            if not any([ips, domains, hashes]): continue

            rules = {"threat_id": t["threat_id"], "title": t["title"][:80], "rules": {}}
            safe = re.sub(r'[^a-zA-Z0-9_]', '_', t["title"][:40])
            date = datetime.now().strftime('%Y/%m/%d')

            # Sigma
            if ips or domains:
                sel_parts = []
                if ips: sel_parts.append("    selection_ip:\n        dst_ip:\n" + "\n".join(f"            - '{ip}'" for ip in ips[:15]))
                if domains: sel_parts.append("    selection_dns:\n        query:\n" + "\n".join(f"            - '*{d}*'" for d in domains[:15]))
                cond = " or ".join(f"selection_{'ip' if 'ip' in s else 'dns'}" for s in sel_parts)
                rules["rules"]["sigma"] = f"title: CDB APEX v37.0 — {t['title'][:60]}\nstatus: experimental\nauthor: CyberDudeBivash SENTINEL APEX\ndate: {date}\nlogsource:\n    category: firewall\ndetection:\n{chr(10).join(sel_parts)}\n    condition: {cond}\nlevel: high"

            # YARA
            if hashes:
                strings = "\n".join(f'        $h{i} = "{h}" ascii nocase' for i, h in enumerate(hashes[:10]))
                rules["rules"]["yara"] = f'rule CDB_APEX_{safe} {{\n    meta:\n        description = "{t["title"][:60]}"\n        author = "CyberDudeBivash"\n    strings:\n{strings}\n    condition:\n        any of them\n}}'

            # Suricata
            for ip in ips[:10]:
                sid = abs(hash(f"sur-{ip}-{t['threat_id']}")) % 9000000 + 1000000
                rules.setdefault("rules", {}).setdefault("suricata", [])
                rules["rules"]["suricata"].append(f'alert ip any any -> {ip} any (msg:"CDB APEX — {safe[:30]}"; sid:{sid}; rev:1;)')

            # Snort
            for ip in ips[:10]:
                sid = abs(hash(f"snort-{ip}-{t['threat_id']}")) % 9000000 + 1000000
                rules.setdefault("rules", {}).setdefault("snort", [])
                rules["rules"]["snort"].append(f'alert ip any any -> {ip} any (msg:"CDB APEX {safe[:30]}"; sid:{sid}; rev:1;)')

            # Elastic DSL
            if ips or domains or hashes:
                should = []
                if ips: should.append({"terms": {"destination.ip": ips[:15]}})
                if domains: should.append({"terms": {"dns.question.name": domains[:15]}})
                if hashes: should.append({"terms": {"file.hash.sha256": [h for h in hashes if len(h) == 64][:15]}})
                rules["rules"]["elastic"] = json.dumps({"query": {"bool": {"should": should, "minimum_should_match": 1}}}, indent=2)

            # KQL
            kql_parts = []
            if ips: kql_parts.append(f'DeviceNetworkEvents | where RemoteIP in ({", ".join(f"\"{ip}\"" for ip in ips[:10])})')
            if domains: kql_parts.append(f'DeviceNetworkEvents | where RemoteUrl has_any ({", ".join(f"\"{d}\"" for d in domains[:10])})')
            if kql_parts: rules["rules"]["kql"] = "\n// OR\n".join(kql_parts)

            rule_count = sum(1 if isinstance(v, str) else len(v) for v in rules["rules"].values())
            rules["rule_count"] = rule_count
            packs.append(rules)

        logger.info(f"A6 Detection: {len(packs)} packs, {sum(p['rule_count'] for p in packs)} rules")
        return packs


# ═══════════════════════════════════════════════════════════════════════════════
# A7 — PLAYBOOK ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class PlaybookEngine:
    """Generates structured incident response playbooks."""

    def generate(self, triaged: List[Dict], analyses: List[Dict]) -> List[Dict]:
        analysis_map = {a["threat_id"]: a for a in analyses}
        playbooks = []
        for t in triaged:
            if t["priority"] not in ("P1_CRITICAL", "P2_HIGH"): continue
            a = analysis_map.get(t["threat_id"], {})
            entity = t["cves"][0] if t.get("cves") else t["title"][:40]

            pb = {
                "playbook_id": f"pb-{t['threat_id'][4:]}",
                "title": f"IR Playbook: {entity}",
                "priority": t["priority"], "sla": t["sla"],
                "created": datetime.now(timezone.utc).isoformat(),
                "phases": {
                    "detection": [
                        f"Deploy Sigma/YARA/Suricata detection rules for {entity}",
                        f"Hunt for {entity} exploitation indicators in SIEM logs",
                        "Check EDR telemetry for post-exploitation behaviors",
                        "Review network traffic for C2 communication patterns",
                    ],
                    "containment": [
                        "Isolate confirmed compromised systems from network",
                        "Block threat IOCs (IPs, domains, hashes) at perimeter",
                        f"Apply virtual patching for {entity} via WAF/IPS",
                        "Implement emergency network micro-segmentation",
                    ],
                    "investigation": [
                        "Collect forensic artifacts from affected endpoints",
                        "Analyze malware samples in sandbox environment",
                        "Map lateral movement paths using authentication logs",
                        f"Correlate with {t.get('actor', 'unknown')} actor TTPs",
                    ],
                    "eradication": [
                        f"Apply vendor patch for {entity}",
                        "Remove all identified malicious artifacts and persistence",
                        "Reset all credentials on affected systems",
                        "Rebuild compromised systems from verified clean images",
                    ],
                    "recovery": [
                        "Restore services from verified clean backups",
                        "Validate system integrity before reconnection",
                        "Resume operations with enhanced monitoring",
                        "Conduct post-incident review within 48 hours",
                    ],
                },
                "escalation": {
                    "T+0": "SOC Tier 1 — Initial triage and detection deployment",
                    "T+30min": "SOC Tier 2 — Deep analysis and containment",
                    "T+2hr": "SOC Tier 3 — Advanced forensics if unresolved",
                    "T+4hr": "CISO briefing if P1 or data breach confirmed",
                },
            }
            playbooks.append(pb)

        logger.info(f"A7 Playbook: {len(playbooks)} playbooks")
        return playbooks


# ═══════════════════════════════════════════════════════════════════════════════
# A8 — THREAT REPORT GENERATOR (Blogger-compatible)
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatReportGenerator:
    """Generates structured intel reports compatible with Blogger publishing pipeline."""

    def generate(self, threats: List[Dict], analyses: List[Dict],
                 reasoning: List[Dict], triaged: List[Dict]) -> List[Dict]:
        analysis_map = {a["threat_id"]: a for a in analyses}
        reason_map = {r["threat_id"]: r for r in reasoning}
        triage_map = {t["threat_id"]: t for t in triaged}
        reports = []

        for t in threats[:15]:
            if t["risk_score"] < 5: continue
            a = analysis_map.get(t["threat_id"], {})
            r = reason_map.get(t["threat_id"], {})
            tri = triage_map.get(t["threat_id"], {})
            iocs = t.get("iocs", {})
            entity = t["cves"][0] if t.get("cves") else t["title"][:60]

            # Build HTML-compatible report sections
            sections = {
                "executive_summary": (
                    f"This report covers {entity} — a threat with risk score {t['risk_score']}/10. "
                    f"Priority: {tri.get('priority', 'N/A')}. "
                    f"{'CISA KEV confirms active exploitation. ' if t.get('kev') else ''}"
                    f"{'Zero-day signals detected. ' if t.get('zeroday_match') else ''}"
                    f"Affected sectors: {', '.join(tri.get('affected_products', ['Unknown']))}."
                ),
                "technical_analysis": r.get("reasoning", "Analysis pending."),
                "attack_chain": a.get("exploit_chain", []),
                "ioc_intelligence": {
                    "ips": iocs.get("ips", [])[:15],
                    "domains": iocs.get("domains", [])[:15],
                    "hashes": iocs.get("hashes", [])[:10],
                    "urls": iocs.get("urls", [])[:10],
                },
                "mitre_mapping": t.get("mitre", []),
                "mitigation_guidance": [
                    f"Apply vendor patches for {entity}",
                    "Block IOCs at network perimeter",
                    "Deploy provided detection rules",
                    "Review and harden affected configurations",
                ],
                "risk_assessment": {
                    "risk_score": t["risk_score"],
                    "exploitability": a.get("exploitability_score", "N/A"),
                    "impact": a.get("impact_classification", "N/A"),
                    "priority": tri.get("priority", "N/A"),
                },
            }

            reports.append({
                "report_id": f"rpt-{t['threat_id'][4:]}",
                "title": f"Sentinel APEX Intelligence Report: {entity}",
                "entity": entity,
                "classification": t.get("kev", False) and "TLP:RED" or "TLP:AMBER" if t["risk_score"] >= 7 else "TLP:GREEN",
                "sections": sections,
                "generated": datetime.now(timezone.utc).isoformat(),
                "platform": "CYBERDUDEBIVASH SENTINEL APEX v37.0 — AI THREAT ANALYST",
            })

        logger.info(f"A8 Reports: {len(reports)} intelligence reports")
        return reports


# ═══════════════════════════════════════════════════════════════════════════════
# A9 — THREAT KNOWLEDGE GRAPH
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatKnowledgeGraph:
    """Builds entity-relationship intelligence graph from all analyzed data."""

    def build(self, threats: List[Dict], analyses: List[Dict]) -> Dict:
        nodes = {}
        edges = []

        for t in threats:
            # CVE nodes
            for cve in t.get("cves", []):
                nid = f"cve:{cve}"
                nodes[nid] = {"id": nid, "type": "cve", "name": cve, "risk": t["risk_score"]}

            # Actor nodes
            actor = t.get("actor", "")
            if actor and not actor.startswith("UNC-CDB"):
                nid = f"actor:{actor}"
                nodes[nid] = {"id": nid, "type": "actor", "name": actor}
                for cve in t.get("cves", []):
                    edges.append({"source": nid, "target": f"cve:{cve}", "relationship": "exploits"})

            # Technique nodes
            for tech in t.get("mitre", []):
                nid = f"technique:{tech}"
                nodes[nid] = {"id": nid, "type": "technique", "name": tech}
                for cve in t.get("cves", []):
                    edges.append({"source": f"cve:{cve}", "target": nid, "relationship": "uses_technique"})
                if actor and not actor.startswith("UNC-CDB"):
                    edges.append({"source": f"actor:{actor}", "target": nid, "relationship": "employs"})

            # IOC nodes
            iocs = t.get("iocs", {})
            for ip in iocs.get("ips", [])[:5]:
                nid = f"ioc:ip:{ip}"
                nodes[nid] = {"id": nid, "type": "ioc", "name": ip, "ioc_type": "ipv4"}
                for cve in t.get("cves", []):
                    edges.append({"source": f"cve:{cve}", "target": nid, "relationship": "indicates"})

            for dom in iocs.get("domains", [])[:5]:
                nid = f"ioc:domain:{dom}"
                nodes[nid] = {"id": nid, "type": "ioc", "name": dom, "ioc_type": "domain"}
                for cve in t.get("cves", []):
                    edges.append({"source": f"cve:{cve}", "target": nid, "relationship": "indicates"})

        # Deduplicate edges
        seen_edges = set()
        unique_edges = []
        for e in edges:
            key = f"{e['source']}:{e['target']}:{e['relationship']}"
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        graph = {
            "nodes": list(nodes.values()),
            "edges": unique_edges,
            "stats": {
                "node_count": len(nodes),
                "edge_count": len(unique_edges),
                "node_types": dict(Counter(n["type"] for n in nodes.values())),
            },
        }
        logger.info(f"A9 Graph: {len(nodes)} nodes, {len(unique_edges)} edges")
        return graph


# ═══════════════════════════════════════════════════════════════════════════════
# A10 — AI SECURITY COPILOT
# ═══════════════════════════════════════════════════════════════════════════════

class AISecurityCopilot:
    """Analyst assistance engine — generates threat explanations and investigation guidance."""

    def assist(self, threats: List[Dict], analyses: List[Dict],
               reasoning: List[Dict], triaged: List[Dict]) -> List[Dict]:
        analysis_map = {a["threat_id"]: a for a in analyses}
        reason_map = {r["threat_id"]: r for r in reasoning}
        triage_map = {t["threat_id"]: t for t in triaged}
        guidance = []

        for t in threats[:20]:
            if t["risk_score"] < 5: continue
            a = analysis_map.get(t["threat_id"], {})
            r = reason_map.get(t["threat_id"], {})
            tri = triage_map.get(t["threat_id"], {})
            entity = t["cves"][0] if t.get("cves") else t["title"][:60]

            # Analyst briefing
            briefing = []
            briefing.append(f"THREAT BRIEFING: {entity}")
            briefing.append(f"Priority: {tri.get('priority', 'N/A')} | SLA: {tri.get('sla', 'N/A')}")
            briefing.append(f"Risk: {t['risk_score']}/10 | Exploitability: {a.get('exploitability_score', 'N/A')}/10")

            if t.get("kev"):
                briefing.append("STATUS: CISA KEV — Active exploitation confirmed. Treat as emergency.")
            if t.get("zeroday_match"):
                briefing.append("STATUS: Zero-day signals detected — exploitation imminent or active.")

            # Investigation steps
            investigation = [
                f"1. Search SIEM for {entity} exploitation indicators in last 72 hours",
                f"2. Check EDR for processes matching MITRE techniques: {', '.join(t.get('mitre', [])[:3])}",
            ]
            iocs = t.get("iocs", {})
            if iocs.get("ips"):
                investigation.append(f"3. Hunt for connections to: {', '.join(iocs['ips'][:5])}")
            if iocs.get("domains"):
                investigation.append(f"4. Check DNS logs for: {', '.join(iocs['domains'][:5])}")
            investigation.append(f"5. Review authentication logs for anomalies on affected systems")

            # Detection suggestions
            suggestions = []
            if t.get("mitre"):
                suggestions.append(f"Enable Sigma rules for techniques: {', '.join(t['mitre'][:5])}")
            if iocs.get("ips") or iocs.get("domains"):
                suggestions.append("Deploy network IOC blocklist from generated Suricata/Snort rules")
            if iocs.get("hashes"):
                suggestions.append("Deploy YARA rules for hash-based detection on endpoints")

            guidance.append({
                "threat_id": t["threat_id"],
                "entity": entity,
                "briefing": "\n".join(briefing),
                "investigation_steps": investigation,
                "detection_suggestions": suggestions,
                "next_actions": tri.get("mitigation_urgency", "STANDARD"),
            })

        logger.info(f"A10 Copilot: {len(guidance)} analyst briefings")
        return guidance


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class AIThreatAnalystEngine:
    """
    Master orchestrator — runs the complete AI Threat Analyst pipeline.
    Pipeline: Monitor → Analyze → Reason → Triage → Generate (Scripts +
              Detections + Playbooks + Reports) → Graph → Copilot
    """

    def __init__(self, output_dir: str = ANALYST_DIR):
        self.output_dir = output_dir
        for d in ["", "scripts", "detections", "playbooks", "reports"]:
            os.makedirs(os.path.join(output_dir, d), exist_ok=True)

    def run(self, window_hours: int = 168) -> Dict:
        logger.info("=" * 65)
        logger.info("SENTINEL APEX v37.0 — AI THREAT ANALYST")
        logger.info("=" * 65)
        now = datetime.now(timezone.utc).isoformat()

        # A1 — Monitor
        logger.info("[A1/10] Threat Monitoring...")
        threats = ThreatMonitor().scan(window_hours)

        # A2 — Exploit Analysis
        logger.info("[A2/10] Exploit Analysis...")
        analyses = ExploitAnalyzer().analyze(threats)

        # A3 — AI Reasoning
        logger.info("[A3/10] AI Threat Reasoning...")
        reasoning = AIThreatReasoner().reason(threats, analyses)

        # A4 — Triage
        logger.info("[A4/10] Automated Triage...")
        triaged = AutomatedTriage().triage(threats, analyses)

        # A5 — Mitigation Scripts
        logger.info("[A5/10] Mitigation Script Generation...")
        scripts = MitigationScriptGenerator().generate(threats)

        # A6 — Detection Rules
        logger.info("[A6/10] Detection Rule Generation...")
        detections = DetectionRuleGenerator().generate(threats)

        # A7 — Playbooks
        logger.info("[A7/10] Playbook Generation...")
        playbooks = PlaybookEngine().generate(triaged, analyses)

        # A8 — Intelligence Reports
        logger.info("[A8/10] Intelligence Report Generation...")
        reports = ThreatReportGenerator().generate(threats, analyses, reasoning, triaged)

        # A9 — Knowledge Graph
        logger.info("[A9/10] Knowledge Graph Construction...")
        graph = ThreatKnowledgeGraph().build(threats, analyses)

        # A10 — Security Copilot
        logger.info("[A10/10] AI Security Copilot...")
        copilot = AISecurityCopilot().assist(threats, analyses, reasoning, triaged)

        # Compile result
        priority_dist = Counter(t["priority"] for t in triaged)
        total_scripts = sum(len(s["scripts"]) for s in scripts)
        total_rules = sum(p["rule_count"] for p in detections)

        result = {
            "status": "success", "version": "37.0.0", "codename": "AI THREAT ANALYST",
            "timestamp": now,
            "pipeline_stats": {
                "threats_monitored": len(threats),
                "exploits_analyzed": len(analyses),
                "ai_reasoning_reports": len(reasoning),
                "threats_triaged": len(triaged),
                "mitigation_script_packs": len(scripts),
                "total_scripts": total_scripts,
                "detection_rule_packs": len(detections),
                "total_detection_rules": total_rules,
                "playbooks_generated": len(playbooks),
                "intelligence_reports": len(reports),
                "knowledge_graph_nodes": graph["stats"]["node_count"],
                "knowledge_graph_edges": graph["stats"]["edge_count"],
                "copilot_briefings": len(copilot),
            },
            "triage_distribution": dict(priority_dist),
            "graph_stats": graph["stats"],
            "top_threats": [{"entity": t["cves"][0] if t.get("cves") else t["title"][:40],
                            "risk": t["risk_score"], "priority": next((tr["priority"] for tr in triaged if tr["threat_id"] == t["threat_id"]), "N/A")}
                           for t in threats[:10]],
        }

        # Save all outputs
        self._save(result, threats, analyses, reasoning, triaged, scripts, detections, playbooks, reports, graph, copilot)

        logger.info("=" * 65)
        logger.info(f"AI THREAT ANALYST COMPLETE")
        logger.info(f"  {len(threats)} threats | {len(analyses)} analyzed | P1={priority_dist.get('P1_CRITICAL',0)}")
        logger.info(f"  {total_scripts} scripts | {total_rules} rules | {len(playbooks)} playbooks | {len(reports)} reports")
        logger.info("=" * 65)
        return result

    def _save(self, result, threats, analyses, reasoning, triaged, scripts, detections, playbooks, reports, graph, copilot):
        d = self.output_dir
        saves = [
            ("analyst_report.json", result),
            ("threats_monitored.json", threats),
            ("exploit_analyses.json", analyses),
            ("ai_reasoning.json", reasoning),
            ("triage_results.json", triaged),
            ("knowledge_graph.json", graph),
            ("copilot_briefings.json", copilot),
        ]
        for name, data in saves:
            with open(os.path.join(d, name), 'w') as f:
                json.dump(data, f, indent=2, default=str)

        # Save script packs
        for sp in scripts:
            sp_path = os.path.join(d, "scripts", f"{sp['threat_id']}.json")
            with open(sp_path, 'w') as f:
                json.dump(sp, f, indent=2, default=str)

        # Save detection packs
        for dp in detections:
            dp_path = os.path.join(d, "detections", f"{dp['threat_id']}.json")
            with open(dp_path, 'w') as f:
                json.dump(dp, f, indent=2, default=str)

        # Save playbooks
        for pb in playbooks:
            pb_path = os.path.join(d, "playbooks", f"{pb['playbook_id']}.json")
            with open(pb_path, 'w') as f:
                json.dump(pb, f, indent=2, default=str)

        # Save intelligence reports
        for rpt in reports:
            rpt_path = os.path.join(d, "reports", f"{rpt['report_id']}.json")
            with open(rpt_path, 'w') as f:
                json.dump(rpt, f, indent=2, default=str)

        logger.info(f"All outputs saved to {d}/")


def main():
    logging.basicConfig(level=logging.INFO, format="[AI-ANALYST] %(asctime)s — %(levelname)s — %(message)s")
    engine = AIThreatAnalystEngine()
    result = engine.run(window_hours=168)
    print(json.dumps({"pipeline_stats": result["pipeline_stats"], "triage_distribution": result["triage_distribution"],
                       "graph_stats": result["graph_stats"], "top_threats": result["top_threats"][:5]}, indent=2))

if __name__ == "__main__":
    main()
