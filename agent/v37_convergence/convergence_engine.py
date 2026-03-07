#!/usr/bin/env python3
"""
convergence_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v37.0 (CONVERGENCE)
============================================================================
Zero Day Hunter ↔ Sentinel APEX Integration Layer

Bridges extended features from the CYBERDUDEBIVASH ZERO-DAY HUNTER project
into the production Sentinel APEX platform.

8 Integration Modules:
  C1 — Detection Rules Repository: Consolidates all rules from v33 DetectionForge,
       v35 ZDH, and v36 OmniShield into unified, searchable repository
  C2 — Mitigation Script Library: Auto-generated defensive scripts
       (iptables, ModSecurity, Splunk SPL, PowerShell, hardening)
  C3 — Code Exposure Monitor: GitHub Security Advisory scanning for
       CVEs referenced in platform intelligence
  C4 — Threat Radar Data Feed: Structured data feed for the dashboard
       integrating all platform intelligence layers
  C5 — Report-to-Blogger Bridge: Generates Blogger-ready intelligence
       reports from ZDH/Fusion/OmniShield outputs
  C6 — Agent Telemetry Ingestion: Accepts and normalizes telemetry
       from external ZDH binary agents
  C7 — Unified API Manifest: Consolidates all API endpoints into
       a single OpenAPI-compatible service catalog
  C8 — Plugin Framework: Extensible plugin loading architecture

Non-Breaking: Reads from all existing data layers. Writes to data/convergence/.
Zero modification to any existing file.

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os, re, json, hashlib, logging, statistics, glob
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import Counter, defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("CDB-Convergence")

MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
STIX_DIR = os.environ.get("STIX_DIR", "data/stix")
FUSION_DIR = os.environ.get("FUSION_DIR", "data/fusion")
ZDH_DIR = os.environ.get("ZDH_DIR", "data/zerodayhunter")
OMNISHIELD_DIR = os.environ.get("OMNISHIELD_DIR", "data/omnishield")
OUTPUT_DIR = os.environ.get("CONVERGENCE_DIR", "data/convergence")

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

try:
    import requests; _HTTP = True
except ImportError:
    _HTTP = False

def _load(path):
    try:
        with open(path) as f: return json.load(f)
    except: return None

def _entries():
    d = _load(MANIFEST_PATH)
    return d if isinstance(d, list) else (d.get("entries", []) if d else [])


# ═══════════════════════════════════════════════════════════════════════════════
# C1 — DETECTION RULES REPOSITORY
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionRulesRepository:
    """Consolidates detection rules from v33 DetectionForge, v35 ZDH, and generates
    new rules — unified searchable repository with per-format export."""

    def build(self) -> Dict:
        rules_db = {"sigma": [], "yara": [], "suricata": [], "snort": [], "elastic": [], "kql": []}
        entries = _entries()

        # Scan v33 DetectionForge outputs
        forge_dir = os.path.join(FUSION_DIR, "detections")
        if os.path.isdir(forge_dir):
            for pack_dir in glob.glob(os.path.join(forge_dir, "dp-*")):
                for fmt, ext in [("sigma", "sigma_rules.yml"), ("yara", "yara_rules.yar"),
                                 ("suricata", "suricata.rules"), ("snort", "snort.rules"),
                                 ("elastic", "elastic_queries.json"), ("kql", "kql_queries.txt")]:
                    fpath = os.path.join(pack_dir, ext)
                    if os.path.exists(fpath):
                        try:
                            content = open(fpath).read().strip()
                            if content:
                                rules_db[fmt].append({"source": "v33_DetectionForge",
                                    "pack": os.path.basename(pack_dir), "content": content})
                        except: pass

        # Generate fresh rules from STIX IOCs
        for entry in entries[-30:]:
            sf = entry.get("stix_file", "")
            spath = os.path.join(STIX_DIR, sf)
            if not os.path.exists(spath): continue
            try:
                bundle = _load(spath)
                ips, domains = [], []
                for obj in (bundle or {}).get("objects", []):
                    if obj.get("type") != "indicator": continue
                    p = obj.get("pattern", "")
                    m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", p)
                    if m: ips.append(m.group(1))
                    m = re.search(r"domain-name:value\s*=\s*'([^']+)'", p)
                    if m: domains.append(m.group(1))

                if not ips and not domains: continue
                title = entry.get("title", "")[:60]
                safe = re.sub(r'[^a-zA-Z0-9_]', '_', title[:40])

                # Sigma
                if ips or domains:
                    parts = []
                    if ips: parts.append("    selection_ip:\n        dst_ip:\n" + "\n".join(f"            - '{ip}'" for ip in ips[:15]))
                    if domains: parts.append("    selection_dns:\n        query:\n" + "\n".join(f"            - '*{d}*'" for d in domains[:15]))
                    cond = " or ".join("selection_ip" if "ip" in p else "selection_dns" for p in parts)
                    sigma = f"title: CDB APEX v37.0 — {title}\nstatus: experimental\nauthor: CyberDudeBivash\ndate: {datetime.now().strftime('%Y/%m/%d')}\nlogsource:\n    category: firewall\ndetection:\n{chr(10).join(parts)}\n    condition: {cond}\nlevel: high"
                    rules_db["sigma"].append({"source": "v37_convergence", "stix": sf, "content": sigma})

                # Suricata
                for ip in ips[:10]:
                    sid = abs(hash(f"conv-{ip}-{sf}")) % 9000000 + 1000000
                    rules_db["suricata"].append({"source": "v37_convergence", "stix": sf,
                        "content": f'alert ip any any -> {ip} any (msg:"CDB APEX v37 — {safe[:30]}"; sid:{sid}; rev:1;)'})

                # KQL
                if ips or domains:
                    kql_parts = []
                    if ips: kql_parts.append(f'DeviceNetworkEvents | where RemoteIP in ({", ".join(f"\"{ip}\"" for ip in ips[:10])})')
                    if domains: kql_parts.append(f'DeviceNetworkEvents | where RemoteUrl has_any ({", ".join(f"\"{d}\"" for d in domains[:10])})')
                    rules_db["kql"].append({"source": "v37_convergence", "stix": sf, "content": "\n// OR\n".join(kql_parts)})

            except: pass

        total = sum(len(v) for v in rules_db.values())
        result = {
            "subsystem": "C1_DetectionRulesRepository",
            "total_rules": total,
            "by_format": {fmt: len(rules) for fmt, rules in rules_db.items()},
            "sources": list(set(r["source"] for rules in rules_db.values() for r in rules)),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"C1 Rules Repo: {total} rules across {len(rules_db)} formats")
        return result, rules_db


# ═══════════════════════════════════════════════════════════════════════════════
# C2 — MITIGATION SCRIPT LIBRARY
# ═══════════════════════════════════════════════════════════════════════════════

class MitigationScriptLibrary:
    """Auto-generates defensive scripts from platform intelligence."""

    def build(self) -> Dict:
        entries = _entries()
        scripts = {"iptables": [], "modsecurity": [], "splunk_spl": [], "powershell": [], "hardening": []}

        for entry in entries[-25:]:
            sf = entry.get("stix_file", "")
            risk = entry.get("risk_score", 0)
            if risk < 6: continue
            title = entry.get("title", "")[:60]
            spath = os.path.join(STIX_DIR, sf)
            ips, domains = [], []
            if os.path.exists(spath):
                try:
                    bundle = _load(spath)
                    for obj in (bundle or {}).get("objects", []):
                        if obj.get("type") != "indicator": continue
                        p = obj.get("pattern", "")
                        m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", p)
                        if m: ips.append(m.group(1))
                        m = re.search(r"domain-name:value\s*=\s*'([^']+)'", p)
                        if m: domains.append(m.group(1))
                except: pass

            # iptables
            if ips:
                rules = "\n".join(f"iptables -A INPUT -s {ip} -j DROP\niptables -A OUTPUT -d {ip} -j DROP" for ip in ips[:15])
                scripts["iptables"].append({"threat": title, "content": f"#!/bin/bash\n# CDB APEX v37.0 — {title}\n{rules}"})

            # ModSecurity
            if domains:
                pat = "|".join(re.escape(d) for d in domains[:10])
                scripts["modsecurity"].append({"threat": title,
                    "content": f'SecRule REQUEST_HEADERS:Host "@rx {pat}" "id:{abs(hash(sf))%900000+100000},phase:1,deny,status:403,msg:\'CDB Block\'"'})

            # Splunk SPL
            if ips or domains:
                parts = []
                if ips: parts.append(f'dest_ip IN ({",".join(f"\"{ip}\"" for ip in ips[:10])})')
                if domains: parts.append(f'query IN ({",".join(f"\"{d}\"" for d in domains[:10])})')
                scripts["splunk_spl"].append({"threat": title,
                    "content": f'index=* ({" OR ".join(parts)}) | stats count by src_ip, dest_ip | sort -count'})

            # PowerShell (Windows Defender)
            if ips:
                ps_rules = "\n".join(f'New-NetFirewallRule -DisplayName "CDB-Block-{ip}" -Direction Outbound -RemoteAddress {ip} -Action Block' for ip in ips[:10])
                scripts["powershell"].append({"threat": title, "content": f"# CDB APEX v37.0 — {title}\n{ps_rules}"})

            # Hardening
            if risk >= 8:
                scripts["hardening"].append({"threat": title, "content": f"""#!/bin/bash
# CDB APEX v37.0 Emergency Hardening — {title}
apt-get update && apt-get upgrade -y 2>/dev/null || yum update -y 2>/dev/null
ufw enable 2>/dev/null; sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd 2>/dev/null
echo '[+] Hardening applied for: {sf}'"""})

        total = sum(len(v) for v in scripts.values())
        result = {
            "subsystem": "C2_MitigationScriptLibrary",
            "total_scripts": total,
            "by_type": {t: len(s) for t, s in scripts.items()},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"C2 Scripts: {total} scripts across {len(scripts)} types")
        return result, scripts


# ═══════════════════════════════════════════════════════════════════════════════
# C3 — CODE EXPOSURE MONITOR
# ═══════════════════════════════════════════════════════════════════════════════

class CodeExposureMonitor:
    """Scans GitHub Security Advisories for CVEs referenced in platform intelligence."""

    GHSA_API = "https://api.github.com/advisories"

    def scan(self) -> Dict:
        entries = _entries()
        # Extract all CVEs from manifest
        all_cves = set()
        for e in entries:
            all_cves.update(c.upper() for c in CVE_RE.findall(e.get("title", "")))

        advisories = []
        # Try GitHub Advisory Database
        if _HTTP and all_cves:
            sample_cves = list(all_cves)[:10]  # Limit API calls
            for cve in sample_cves:
                try:
                    r = requests.get(f"{self.GHSA_API}?cve_id={cve}", timeout=10,
                        headers={"Accept": "application/vnd.github+json", "User-Agent": "CDB-APEX/37.0"})
                    if r.status_code == 200:
                        for adv in r.json()[:3]:
                            advisories.append({
                                "ghsa_id": adv.get("ghsa_id", ""),
                                "cve": cve,
                                "severity": adv.get("severity", "unknown"),
                                "summary": (adv.get("summary") or "")[:120],
                                "published": adv.get("published_at", ""),
                                "updated": adv.get("updated_at", ""),
                                "affected_packages": len(adv.get("vulnerabilities", [])),
                                "url": adv.get("html_url", ""),
                            })
                except: pass

        # Assess code exposure
        exposure_score = 0
        if advisories:
            critical = sum(1 for a in advisories if a.get("severity") in ("critical", "high"))
            exposure_score = min(10, critical * 2 + len(advisories) * 0.5)

        result = {
            "subsystem": "C3_CodeExposureMonitor",
            "cves_tracked": len(all_cves),
            "cves_scanned": min(10, len(all_cves)),
            "advisories_found": len(advisories),
            "advisories": advisories[:20],
            "exposure_score": round(exposure_score, 1),
            "exposure_level": "CRITICAL" if exposure_score >= 8 else "HIGH" if exposure_score >= 5 else "MODERATE" if exposure_score >= 2 else "LOW",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"C3 CodeExposure: {len(advisories)} advisories, score={exposure_score:.1f}")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# C4 — THREAT RADAR DATA FEED
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatRadarFeed:
    """Generates structured data feed for the intel.cyberdudebivash.com dashboard,
    integrating all platform intelligence layers."""

    def build(self) -> Dict:
        entries = _entries()
        fusion_entities = _load(os.path.join(FUSION_DIR, "entity_store.json")) or {}
        zdh_report = _load(os.path.join(ZDH_DIR, "zdh_report.json")) or {}
        zdh_alerts = _load(os.path.join(ZDH_DIR, "zeroday_alerts.json")) or []
        zdh_forecasts = _load(os.path.join(ZDH_DIR, "threat_forecasts.json")) or []
        omnishield = _load(os.path.join(OMNISHIELD_DIR, "omnishield_report.json")) or {}
        gti = _load(os.path.join(ZDH_DIR, "global_threat_index.json")) or {}

        # Threat timeline (last 50 entries)
        timeline = []
        for e in entries[-50:]:
            timeline.append({
                "title": e.get("title", "")[:80],
                "risk": e.get("risk_score", 0),
                "severity": e.get("severity", ""),
                "actor": e.get("actor_tag", ""),
                "timestamp": e.get("timestamp", ""),
                "kev": e.get("kev_present", False),
                "mitre": e.get("mitre_tactics", []),
            })

        # Active zero-day alerts
        active_zd = [{"entity": a.get("entity", ""), "severity": a.get("severity", ""),
                       "status": a.get("exploitation_status", ""), "type": a.get("alert_type", "")}
                      for a in zdh_alerts[:10]]

        # Top forecasts
        top_forecasts = [{"entity": f.get("entity", ""), "probability": f.get("probability_pct", 0),
                          "window": f.get("window", ""), "risk": f.get("risk_level", "")}
                         for f in zdh_forecasts[:10]]

        # Entity type distribution
        entity_types = Counter(v.get("entity_type", "") for v in fusion_entities.values())

        # Sector heat map
        sector_counts = Counter()
        for e in entries:
            title = e.get("title", "").lower()
            for sector, keywords in [("Finance", ["bank", "financial", "payment"]),
                                     ("Healthcare", ["health", "hospital", "medical"]),
                                     ("Government", ["government", "federal", "military"]),
                                     ("Technology", ["cloud", "saas", "software", "api"]),
                                     ("Energy", ["energy", "oil", "power", "scada"]),
                                     ("Telecom", ["telecom", "5g", "carrier"])]:
                if any(kw in title for kw in keywords):
                    sector_counts[sector] += 1

        radar = {
            "subsystem": "C4_ThreatRadarFeed",
            "global_threat_index": gti,
            "platform_security_score": omnishield.get("platform_security_score", {}),
            "threat_timeline": timeline,
            "active_zeroday_alerts": active_zd,
            "top_forecasts": top_forecasts,
            "entity_distribution": dict(entity_types),
            "sector_heatmap": dict(sector_counts),
            "pipeline_stats": zdh_report.get("pipeline_stats", {}),
            "feed_metadata": {
                "total_entries": len(entries),
                "total_stix_bundles": len(glob.glob(os.path.join(STIX_DIR, "CDB-APEX-*.json"))),
                "fusion_entities": len(fusion_entities),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "platform_version": "37.0.0",
            },
        }
        logger.info(f"C4 Radar: {len(timeline)} timeline entries, {len(active_zd)} ZD alerts")
        return radar


# ═══════════════════════════════════════════════════════════════════════════════
# C5 — REPORT-TO-BLOGGER BRIDGE
# ═══════════════════════════════════════════════════════════════════════════════

class ReportBloggerBridge:
    """Generates Blogger-ready intelligence summaries from ZDH/Fusion/OmniShield data
    that can be consumed by the existing sentinel_blogger.py publishing pipeline."""

    def generate(self) -> List[Dict]:
        zdh_alerts = _load(os.path.join(ZDH_DIR, "zeroday_alerts.json")) or []
        zdh_forecasts = _load(os.path.join(ZDH_DIR, "threat_forecasts.json")) or []
        gti = _load(os.path.join(ZDH_DIR, "global_threat_index.json")) or {}

        reports = []

        # Weekly ZDH Summary Report
        if zdh_alerts or zdh_forecasts:
            critical_alerts = [a for a in zdh_alerts if a.get("severity") == "CRITICAL"]
            high_forecasts = [f for f in zdh_forecasts if f.get("probability_pct", 0) >= 50]

            summary_sections = []
            summary_sections.append(f"Global Threat Index: {gti.get('index', 'N/A')}/10 ({gti.get('level', 'N/A')})")
            summary_sections.append(f"Zero-Day Alerts: {len(zdh_alerts)} total, {len(critical_alerts)} CRITICAL")
            summary_sections.append(f"High-Probability Forecasts: {len(high_forecasts)}")

            if critical_alerts:
                summary_sections.append("CRITICAL ZERO-DAY ALERTS:")
                for a in critical_alerts[:5]:
                    summary_sections.append(f"  — {a.get('entity', '')} [{a.get('alert_type', '')}]: {a.get('exploitation_status', '').upper()}")

            if high_forecasts:
                summary_sections.append("HIGH-PROBABILITY EXPLOITATION FORECASTS:")
                for f in high_forecasts[:5]:
                    summary_sections.append(f"  — {f.get('entity', '')}: {f.get('probability_pct', 0)}% within {f.get('window', 'N/A')}")

            reports.append({
                "report_type": "zdh_weekly_summary",
                "title": f"Sentinel APEX Zero-Day Hunter Weekly Intelligence Summary — GTI: {gti.get('index', 'N/A')}/10",
                "classification": "TLP:AMBER",
                "content": "\n".join(summary_sections),
                "risk_score": gti.get("index", 5),
                "generated": datetime.now(timezone.utc).isoformat(),
                "blogger_compatible": True,
            })

        # Per-alert reports for critical zero-days
        for alert in zdh_alerts[:5]:
            if alert.get("severity") != "CRITICAL": continue
            entity = alert.get("entity", "Unknown")
            reports.append({
                "report_type": "zeroday_advisory",
                "title": f"SENTINEL APEX Zero-Day Advisory: {entity}",
                "classification": "TLP:RED",
                "content": (
                    f"Entity: {entity}\n"
                    f"Alert Type: {alert.get('alert_type', '')}\n"
                    f"Exploitation Status: {alert.get('exploitation_status', '').upper()}\n"
                    f"Confidence: {alert.get('confidence', 0)}\n"
                    f"Chain Evidence: {', '.join(alert.get('chain_evidence', []))}\n"
                    f"Recommended Actions:\n" +
                    "\n".join(f"  — {a}" for a in alert.get("recommended_actions", [])[:5])
                ),
                "risk_score": 10 if alert.get("exploitation_status") == "confirmed" else 8,
                "generated": datetime.now(timezone.utc).isoformat(),
                "blogger_compatible": True,
            })

        logger.info(f"C5 BloggerBridge: {len(reports)} reports generated")
        return reports


# ═══════════════════════════════════════════════════════════════════════════════
# C6 — AGENT TELEMETRY INGESTION
# ═══════════════════════════════════════════════════════════════════════════════

class AgentTelemetryIngestion:
    """Defines the ingestion schema and validation for external ZDH binary agent telemetry.
    In production, this accepts HTTP POST from the ZDH Zig binary agent."""

    TELEMETRY_SCHEMA = {
        "required_fields": ["agent_id", "timestamp", "event_type", "payload"],
        "event_types": [
            "syscall_anomaly",      # Suspicious syscall sequences
            "memory_scan_hit",      # In-memory pattern match
            "process_injection",    # Process injection detected
            "file_integrity",       # File hash mismatch
            "network_anomaly",      # Unexpected network connection
            "credential_access",    # Credential file access
            "persistence_detected", # Persistence mechanism found
        ],
        "payload_format": {
            "syscall_anomaly": {"pid": "int", "syscall_id": "int", "anomaly_score": "float"},
            "memory_scan_hit": {"pid": "int", "pattern": "str", "offset": "int"},
            "network_anomaly": {"src_ip": "str", "dst_ip": "str", "port": "int", "proto": "str"},
            "file_integrity": {"path": "str", "expected_hash": "str", "actual_hash": "str"},
        },
    }

    def validate_telemetry(self, telemetry: Dict) -> Tuple[bool, str]:
        """Validate incoming telemetry against schema."""
        for field in self.TELEMETRY_SCHEMA["required_fields"]:
            if field not in telemetry:
                return False, f"Missing required field: {field}"
        if telemetry.get("event_type") not in self.TELEMETRY_SCHEMA["event_types"]:
            return False, f"Unknown event_type: {telemetry.get('event_type')}"
        return True, "valid"

    def ingest(self, telemetry_batch: List[Dict]) -> Dict:
        """Ingest and validate a batch of agent telemetry events."""
        valid, invalid = [], []
        for t in telemetry_batch:
            ok, msg = self.validate_telemetry(t)
            if ok: valid.append(t)
            else: invalid.append({"telemetry": t, "error": msg})

        result = {
            "subsystem": "C6_AgentTelemetryIngestion",
            "received": len(telemetry_batch),
            "valid": len(valid),
            "invalid": len(invalid),
            "schema": self.TELEMETRY_SCHEMA,
            "api_endpoint": "POST /api/v1/telemetry/ingest",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"C6 Telemetry: schema defined, {len(self.TELEMETRY_SCHEMA['event_types'])} event types")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# C7 — UNIFIED API MANIFEST
# ═══════════════════════════════════════════════════════════════════════════════

class UnifiedAPIManifest:
    """Consolidates all API endpoints across platform versions into a single service catalog."""

    def build(self) -> Dict:
        catalog = {
            "platform": "CYBERDUDEBIVASH SENTINEL APEX v37.0",
            "base_url": "https://intel.cyberdudebivash.com/api",
            "endpoints": {
                "intelligence": {
                    "GET /api/v1/intel/latest": {"tier": "FREE", "desc": "Latest threat intelligence entries"},
                    "GET /api/v1/intel/cve/{id}": {"tier": "STANDARD", "desc": "CVE lookup with enrichment"},
                    "GET /api/v1/intel/iocs": {"tier": "STANDARD", "desc": "IOC feed (JSON/STIX)"},
                    "GET /api/v1/intel/stix/{bundle_id}": {"tier": "STANDARD", "desc": "STIX 2.1 bundle download"},
                    "GET /api/v1/intel/manifest": {"tier": "FREE", "desc": "Feed manifest"},
                },
                "zeroday_hunter": {
                    "GET /api/v1/zdh/alerts": {"tier": "PRO", "desc": "Zero-day alerts"},
                    "GET /api/v1/zdh/forecasts": {"tier": "PRO", "desc": "Exploitation forecasts"},
                    "GET /api/v1/zdh/waves": {"tier": "PRO", "desc": "Attack wave detections"},
                    "GET /api/v1/zdh/gti": {"tier": "FREE", "desc": "Global Threat Index"},
                },
                "fusion": {
                    "GET /api/v1/fusion/entities": {"tier": "PRO", "desc": "Fused entity store"},
                    "GET /api/v1/fusion/relationships": {"tier": "ENTERPRISE", "desc": "Entity relationships"},
                    "GET /api/v1/fusion/contexts": {"tier": "ENTERPRISE", "desc": "Fusion intelligence contexts"},
                    "GET /api/v1/fusion/graph": {"tier": "ENTERPRISE", "desc": "Threat knowledge graph"},
                },
                "detection": {
                    "GET /api/v1/rules/sigma": {"tier": "PRO", "desc": "Sigma detection rules"},
                    "GET /api/v1/rules/yara": {"tier": "PRO", "desc": "YARA detection rules"},
                    "GET /api/v1/rules/suricata": {"tier": "PRO", "desc": "Suricata IDS rules"},
                    "GET /api/v1/rules/snort": {"tier": "PRO", "desc": "Snort IDS rules"},
                    "GET /api/v1/rules/elastic": {"tier": "PRO", "desc": "Elastic DSL queries"},
                    "GET /api/v1/rules/kql": {"tier": "PRO", "desc": "KQL detection queries"},
                    "GET /api/v1/rules/all": {"tier": "ENTERPRISE", "desc": "Complete detection pack"},
                },
                "defense": {
                    "GET /api/v1/scripts/iptables": {"tier": "PRO", "desc": "Firewall mitigation scripts"},
                    "GET /api/v1/scripts/waf": {"tier": "PRO", "desc": "WAF rules"},
                    "GET /api/v1/scripts/siem": {"tier": "PRO", "desc": "SIEM hunt queries"},
                    "GET /api/v1/playbooks": {"tier": "ENTERPRISE", "desc": "IR playbooks"},
                },
                "platform": {
                    "GET /api/v1/health": {"tier": "FREE", "desc": "Platform health status"},
                    "GET /api/v1/radar": {"tier": "FREE", "desc": "Threat radar data feed"},
                    "GET /api/v1/omnishield": {"tier": "ENTERPRISE", "desc": "OmniShield security posture"},
                    "POST /api/v1/telemetry/ingest": {"tier": "ENTERPRISE", "desc": "Agent telemetry ingestion"},
                },
            },
            "tiers": {
                "FREE": {"rate_limit": "60 req/min", "auth": "None"},
                "STANDARD": {"rate_limit": "150 req/min", "auth": "API Key"},
                "PRO": {"rate_limit": "500 req/min", "auth": "API Key"},
                "ENTERPRISE": {"rate_limit": "1000 req/min", "auth": "JWT / API Key"},
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        total_endpoints = sum(len(v) for v in catalog["endpoints"].values())
        catalog["total_endpoints"] = total_endpoints
        logger.info(f"C7 API Manifest: {total_endpoints} endpoints across {len(catalog['endpoints'])} groups")
        return catalog


# ═══════════════════════════════════════════════════════════════════════════════
# C8 — PLUGIN FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════════

class PluginFramework:
    """Extensible plugin loading architecture — defines the contract for ZDH plugins."""

    PLUGIN_CONTRACT = {
        "required_methods": ["initialize", "execute", "health_check"],
        "lifecycle": ["LOADED", "INITIALIZED", "RUNNING", "STOPPED", "ERROR"],
        "isolation": "Process-level isolation via subprocess",
        "communication": "JSON event bus via stdin/stdout",
    }

    BUILT_IN_PLUGINS = [
        {"id": "sentinel-apex-core", "version": "37.0.0", "status": "RUNNING", "type": "core",
         "desc": "Core threat intelligence pipeline"},
        {"id": "fusion-engine", "version": "33.0.0", "status": "RUNNING", "type": "intelligence",
         "desc": "Intelligence Fusion Engine with knowledge graph"},
        {"id": "zerodayhunter", "version": "35.0.0", "status": "RUNNING", "type": "detection",
         "desc": "Zero-Day Hunter with predictive forecasting"},
        {"id": "omnishield", "version": "36.0.0", "status": "RUNNING", "type": "defense",
         "desc": "12-subsystem AI defense platform"},
        {"id": "convergence", "version": "37.0.0", "status": "RUNNING", "type": "integration",
         "desc": "ZDH ↔ Sentinel APEX integration layer"},
    ]

    EXTERNAL_PLUGIN_SLOTS = [
        {"id": "zdh-binary-agent", "type": "agent", "desc": "ZDH Zig binary endpoint agent",
         "status": "AVAILABLE", "install": "Deploy ZDH binary to target hosts"},
        {"id": "zdh-tauri-desktop", "type": "ui", "desc": "ZDH Tauri desktop application",
         "status": "AVAILABLE", "install": "Install from cyberdudebivash.gumroad.com"},
        {"id": "siem-connector", "type": "integration", "desc": "SIEM bidirectional connector",
         "status": "AVAILABLE", "install": "Configure via API key"},
    ]

    def status(self) -> Dict:
        result = {
            "subsystem": "C8_PluginFramework",
            "plugin_contract": self.PLUGIN_CONTRACT,
            "built_in_plugins": self.BUILT_IN_PLUGINS,
            "external_plugin_slots": self.EXTERNAL_PLUGIN_SLOTS,
            "total_active": sum(1 for p in self.BUILT_IN_PLUGINS if p["status"] == "RUNNING"),
            "total_available": len(self.EXTERNAL_PLUGIN_SLOTS),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"C8 Plugins: {result['total_active']} active, {result['total_available']} available")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# CONVERGENCE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ConvergenceEngine:
    """Master orchestrator — runs all 8 ZDH integration modules."""

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.output_dir = output_dir
        for d in ["", "rules", "scripts", "reports"]:
            os.makedirs(os.path.join(output_dir, d), exist_ok=True)

    def run(self) -> Dict:
        logger.info("=" * 65)
        logger.info("SENTINEL APEX v37.0 — CONVERGENCE ENGINE")
        logger.info("Zero Day Hunter ↔ Sentinel APEX Integration")
        logger.info("=" * 65)
        now = datetime.now(timezone.utc).isoformat()

        # C1 — Detection Rules Repository
        logger.info("[C1/8] Detection Rules Repository...")
        rules_result, rules_db = DetectionRulesRepository().build()

        # C2 — Mitigation Script Library
        logger.info("[C2/8] Mitigation Script Library...")
        scripts_result, scripts_db = MitigationScriptLibrary().build()

        # C3 — Code Exposure Monitor
        logger.info("[C3/8] Code Exposure Monitor...")
        exposure = CodeExposureMonitor().scan()

        # C4 — Threat Radar Data Feed
        logger.info("[C4/8] Threat Radar Data Feed...")
        radar = ThreatRadarFeed().build()

        # C5 — Report-to-Blogger Bridge
        logger.info("[C5/8] Report-to-Blogger Bridge...")
        blogger_reports = ReportBloggerBridge().generate()

        # C6 — Agent Telemetry Ingestion
        logger.info("[C6/8] Agent Telemetry Schema...")
        telemetry = AgentTelemetryIngestion().ingest([])

        # C7 — Unified API Manifest
        logger.info("[C7/8] Unified API Manifest...")
        api_manifest = UnifiedAPIManifest().build()

        # C8 — Plugin Framework
        logger.info("[C8/8] Plugin Framework Status...")
        plugins = PluginFramework().status()

        result = {
            "status": "success", "version": "37.0.0", "codename": "CONVERGENCE",
            "timestamp": now,
            "integration_stats": {
                "detection_rules": rules_result["total_rules"],
                "mitigation_scripts": scripts_result["total_scripts"],
                "code_advisories": exposure["advisories_found"],
                "radar_entries": len(radar.get("threat_timeline", [])),
                "blogger_reports": len(blogger_reports),
                "api_endpoints": api_manifest["total_endpoints"],
                "active_plugins": plugins["total_active"],
                "telemetry_event_types": len(telemetry["schema"]["event_types"]),
            },
            "rules_by_format": rules_result["by_format"],
            "scripts_by_type": scripts_result["by_type"],
            "code_exposure": {"score": exposure["exposure_score"], "level": exposure["exposure_level"]},
            "global_threat_index": radar.get("global_threat_index", {}),
            "api_endpoint_count": api_manifest["total_endpoints"],
        }

        # Save outputs
        self._save(result, rules_db, scripts_db, exposure, radar, blogger_reports, telemetry, api_manifest, plugins)

        total = result["integration_stats"]
        logger.info("=" * 65)
        logger.info(f"CONVERGENCE COMPLETE — {total['detection_rules']} rules | {total['mitigation_scripts']} scripts")
        logger.info(f"  {total['blogger_reports']} reports | {total['api_endpoints']} API endpoints | {total['active_plugins']} plugins")
        logger.info("=" * 65)
        return result

    def _save(self, result, rules_db, scripts_db, exposure, radar, reports, telemetry, api_manifest, plugins):
        d = self.output_dir
        saves = [
            ("convergence_report.json", result),
            ("code_exposure.json", exposure),
            ("threat_radar_feed.json", radar),
            ("blogger_bridge_reports.json", reports),
            ("telemetry_schema.json", telemetry),
            ("api_manifest.json", api_manifest),
            ("plugin_status.json", plugins),
        ]
        for name, data in saves:
            with open(os.path.join(d, name), 'w') as f:
                json.dump(data, f, indent=2, default=str)

        # Save rules by format
        for fmt, rules in rules_db.items():
            if rules:
                with open(os.path.join(d, "rules", f"{fmt}_rules.json"), 'w') as f:
                    json.dump(rules, f, indent=2, default=str)

        # Save scripts by type
        for stype, slist in scripts_db.items():
            if slist:
                with open(os.path.join(d, "scripts", f"{stype}_scripts.json"), 'w') as f:
                    json.dump(slist, f, indent=2, default=str)

        # Save blogger reports individually
        for rpt in reports:
            rid = hashlib.md5(rpt.get("title", "").encode()).hexdigest()[:10]
            with open(os.path.join(d, "reports", f"rpt-{rid}.json"), 'w') as f:
                json.dump(rpt, f, indent=2, default=str)

        logger.info(f"All outputs saved to {d}/")


def main():
    logging.basicConfig(level=logging.INFO, format="[CONVERGENCE] %(asctime)s — %(levelname)s — %(message)s")
    engine = ConvergenceEngine()
    result = engine.run()
    print(json.dumps({
        "integration_stats": result["integration_stats"],
        "rules_by_format": result["rules_by_format"],
        "scripts_by_type": result["scripts_by_type"],
        "code_exposure": result["code_exposure"],
        "global_threat_index": result.get("global_threat_index", {}),
    }, indent=2))


if __name__ == "__main__":
    main()
