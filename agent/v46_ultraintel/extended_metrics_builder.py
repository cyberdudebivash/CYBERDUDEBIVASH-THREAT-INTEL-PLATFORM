#!/usr/bin/env python3
"""
extended_metrics_builder.py — CyberDudeBivash v46.0 (SENTINEL APEX ULTRA INTEL)
Comprehensive extended_metrics field builder.
Populates the previously-empty extended_metrics{} with:
  - affected_products: list of product names detected
  - vulnerability_class: primary vuln type (RCE, SQLi, XSS, etc.)
  - patch_priority: IMMEDIATE / HIGH / MEDIUM / LOW
  - remediation_urgency: hours to recommended patch (SLA)
  - geo_attribution: attacker origin + likely victim geographies
  - detection_coverage: estimated coverage with standard rules
  - affected_component: specific component or function from title
  - disclosure_type: vendor advisory / researcher / darkweb / government
  - cvss_vector_class: Network/Local/Adjacent/Physical (if derivable)
  - days_since_disclosure: freshness signal

This is a pure additive engine — never destroys existing fields.

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-EXTENDED-METRICS-V46")

# ── PRODUCT DETECTION PATTERNS ───────────────────────────────────────────────
_PRODUCT_PATTERNS = [
    # Enterprise / Cloud
    (r"microsoft exchange", "Microsoft Exchange"),
    (r"sharepoint", "Microsoft SharePoint"),
    (r"windows server", "Windows Server"),
    (r"solarwinds", "SolarWinds Orion"),
    (r"citrix", "Citrix"),
    (r"vmware", "VMware"),
    (r"cisco\b", "Cisco"),
    (r"palo alto\b", "Palo Alto Networks"),
    (r"fortinet|fortigate|forticlient", "Fortinet/FortiGate"),
    (r"ivanti", "Ivanti"),
    (r"beyondtrust", "BeyondTrust"),
    (r"crowdstrike", "CrowdStrike"),
    (r"splunk", "Splunk"),
    # Open Source
    (r"imagemagick", "ImageMagick"),
    (r"apache\b", "Apache"),
    (r"nginx", "Nginx"),
    (r"openssl", "OpenSSL"),
    (r"389.ds", "389 Directory Server"),
    (r"hummerrisk", "HummerRisk"),
    (r"pimcore", "Pimcore"),
    (r"muyucms", "MuYuCMS"),
    (r"datalinkdc|dinky", "DatalinkDC Dinky"),
    (r"wordpress", "WordPress"),
    # IoT / Embedded
    (r"tenda\b", "Tenda Router"),
    (r"utt hiper", "UTT HiPER Router"),
    (r"d-link", "D-Link"),
    (r"tp-link", "TP-Link"),
    (r"zyxel", "ZyXEL"),
    # Business Apps
    (r"s/4hana|sap hana", "SAP S/4HANA"),
    (r"dell repository", "Dell Repository Manager"),
    (r"security center", "Security Center"),
    # Web Apps (SourceCodester etc.)
    (r"sourcecodester", "SourceCodester App"),
    (r"itsourcecode", "itsourcecode App"),
    (r"pidetu cita", "PideTuCita"),
    (r"responsive lightbox", "Responsive Lightbox & Gallery (WP)"),
    (r"modern image gallery", "Modern Image Gallery App"),
    (r"android\b", "Android"),
    (r"ios\b|webkit", "Apple iOS / WebKit"),
    (r"apple.*security", "Apple Platform"),
]

# ── VULNERABILITY CLASS DETECTION ────────────────────────────────────────────
_VULN_CLASS_PATTERNS = [
    (r"remote code execution|rce|arbitrary code", "Remote Code Execution (RCE)"),
    (r"sql injection|sqli", "SQL Injection"),
    (r"cross.site scripting|xss", "Cross-Site Scripting (XSS)"),
    (r"cross.site request forgery|csrf", "CSRF"),
    (r"path traversal|directory traversal", "Path Traversal"),
    (r"server.side request forgery|ssrf", "Server-Side Request Forgery (SSRF)"),
    (r"authentication bypass|missing authentication|unauthenticated", "Authentication Bypass"),
    (r"privilege escalation|improper privilege", "Privilege Escalation"),
    (r"buffer overflow|heap overflow|stack overflow", "Buffer Overflow"),
    (r"use after free|use-after-free", "Use-After-Free"),
    (r"command injection|os command", "Command Injection"),
    (r"denial of service|dos attack|memory exhaustion", "Denial of Service (DoS)"),
    (r"information disclosure|data exposure|sensitive.*data", "Information Disclosure"),
    (r"improper access control|broken access control", "Access Control Bypass"),
    (r"idor|indirect object reference|broken object", "IDOR"),
    (r"cryptomining|xmrig|coin miner", "Cryptomining Malware"),
    (r"ransomware|extortion|double extortion", "Ransomware"),
    (r"supply chain|backdoor.*package", "Supply Chain Attack"),
    (r"firmware|bootkit|secure boot", "Firmware/Bootloader Attack"),
    (r"clickjacking", "Clickjacking"),
    (r"open redirect", "Open Redirect"),
    (r"deserialization", "Insecure Deserialization"),
    (r"session.*fixation|session.*exposure", "Session Security Issue"),
    (r"credential.*exposure|plaintext.*credential", "Credential Exposure"),
    (r"stealer|infostealer", "Information Stealer"),
    (r"uncontrolled search path|dll hijacking", "DLL/Search Path Hijacking"),
    (r"xxe|xml external", "XML External Entity (XXE)"),
]

# ── PATCH PRIORITY RULES ─────────────────────────────────────────────────────
def _compute_patch_priority(item: Dict) -> Dict:
    kev = item.get("kev_present", False)
    cvss = item.get("cvss_score") or 0
    epss = item.get("epss_score") or 0
    risk = item.get("risk_score", 0)
    exploit_status = item.get("exploit_status", {}).get("status", "THEORETICAL")
    severity = item.get("severity", "MEDIUM")

    # IMMEDIATE: KEV or ITW or CVSS≥9 + exploitation signals
    if kev or exploit_status == "ITW":
        return {
            "priority": "IMMEDIATE",
            "color": "#dc2626",
            "sla_hours": 24,
            "label": "⚡ IMMEDIATE — Patch within 24 hours",
            "rationale": "CISA KEV confirmed or active exploitation detected",
        }
    if cvss >= 9.0 and exploit_status == "ACTIVE":
        return {
            "priority": "IMMEDIATE",
            "color": "#dc2626",
            "sla_hours": 24,
            "label": "⚡ IMMEDIATE — Patch within 24 hours",
            "rationale": f"CVSS {cvss} Critical + active exploitation signals",
        }
    # HIGH: CVSS≥7 or high risk or PoC available
    if cvss >= 7.0 or risk >= 7.0 or exploit_status in ("ACTIVE", "POC_PUBLIC"):
        return {
            "priority": "HIGH",
            "color": "#ea580c",
            "sla_hours": 72,
            "label": "🔴 HIGH — Patch within 72 hours",
            "rationale": f"CVSS {cvss or '—'} / Risk {risk}/10 / {exploit_status}",
        }
    # MEDIUM
    if cvss >= 4.0 or risk >= 4.0:
        return {
            "priority": "MEDIUM",
            "color": "#d97706",
            "sla_hours": 168,  # 7 days
            "label": "🟡 MEDIUM — Patch within 7 days",
            "rationale": f"CVSS {cvss or '—'} / Risk {risk}/10",
        }
    # LOW
    return {
        "priority": "LOW",
        "color": "#16a34a",
        "sla_hours": 720,  # 30 days
        "label": "🟢 LOW — Patch within 30 days",
        "rationale": "Low severity / informational advisory",
    }


# ── DISCLOSURE TYPE DETECTION ────────────────────────────────────────────────
def _detect_disclosure_type(item: Dict) -> str:
    src = item.get("feed_source", "").lower()
    url = item.get("source_url", "").lower()
    title = item.get("title", "").lower()
    if "cisa" in src + url + title or "kev" in title:
        return "Government Advisory"
    if "nvd.nist" in url or "nvd_url" in item:
        return "NVD / Vendor Advisory"
    if "securityaffairs" in src or "hackernews" in src or "cyberscoop" in src:
        return "Security Research Media"
    if "cvefeed" in src or "cvefeed" in url:
        return "CVE Feed / Researcher"
    if "rapid7" in src or "tenable" in src or "qualys" in src:
        return "Vendor Security Blog"
    if "github" in url:
        return "GitHub / OSS Advisory"
    return "Threat Intelligence Feed"


# ── GEO ATTRIBUTION (simplified from actor profile) ─────────────────────────
def _derive_geo_attribution(item: Dict) -> Dict:
    actor_profile = item.get("actor_profile", {})
    origin = actor_profile.get("origin", "Unknown")
    origin_flag = actor_profile.get("origin_flag", "❓")
    # Map origin to likely victim geographies
    victim_map = {
        "China": ["US", "UK", "Taiwan", "Japan", "India"],
        "Russia": ["US", "EU", "Ukraine", "NATO nations"],
        "North Korea": ["US", "South Korea", "Financial Sector Global"],
        "Iran": ["Israel", "US", "Gulf States", "Energy Sector"],
        "Eastern Europe": ["US", "EU", "Global Enterprise"],
        "Unknown": ["Global"],
    }
    victims = victim_map.get(origin, ["Global"])
    return {
        "attacker_origin": origin,
        "attacker_flag": origin_flag,
        "likely_victim_regions": victims,
    }


def _extract_affected_component(title: str) -> Optional[str]:
    """Extract function/component from CVE title (e.g. 'formP2PLimitConfig strcpy')."""
    # Match patterns like "ProductName component_name function_name vuln_type"
    match = re.search(
        r'(?:CVE-[\d-]+\s+-\s+)?(?:[A-Za-z0-9\s]+?)\s+([\w\.]+)\s+([\w]+)\s+(?:buffer overflow|command injection|sql injection|path traversal|ssrf|xss|csrf|rce)',
        title, re.I
    )
    if match:
        return f"{match.group(1)} → {match.group(2)}"
    return None


def _days_since_disclosure(item: Dict) -> Optional[int]:
    ts = item.get("timestamp") or item.get("generated_at")
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - dt).days
    except Exception:
        return None


class ExtendedMetricsBuilderV46:
    """
    Builds rich extended_metrics payload for every manifest item.
    Completely replaces the previously-empty {} with structured intelligence.
    """

    def _detect_products(self, title: str) -> List[str]:
        title_lower = title.lower()
        found = []
        for pattern, product_name in _PRODUCT_PATTERNS:
            if re.search(pattern, title_lower):
                found.append(product_name)
        return list(dict.fromkeys(found))  # dedup preserving order

    def _detect_vuln_class(self, title: str) -> str:
        title_lower = title.lower()
        for pattern, vuln_class in _VULN_CLASS_PATTERNS:
            if re.search(pattern, title_lower):
                return vuln_class
        return "General Advisory"

    def build(self, item: Dict) -> Dict:
        """Build complete extended_metrics for one item."""
        title = item.get("title", "")
        products = self._detect_products(title)
        vuln_class = self._detect_vuln_class(title)
        patch_priority = _compute_patch_priority(item)
        geo = _derive_geo_attribution(item)
        disclosure_type = _detect_disclosure_type(item)
        component = _extract_affected_component(title)
        days_old = _days_since_disclosure(item)

        # Detection coverage estimate based on available signals
        ioc_total = sum(item.get("ioc_counts", {}).values())
        mitre_count = len(item.get("mitre_tactics", []))
        det_pct = min(100, (ioc_total * 15) + (mitre_count * 10) +
                     (20 if item.get("kev_present") else 0) +
                     (10 if item.get("cvss_score") else 0))

        return {
            "affected_products": products,
            "product_count": len(products),
            "vulnerability_class": vuln_class,
            "patch_priority": patch_priority,
            "geo_attribution": geo,
            "disclosure_type": disclosure_type,
            "detection_coverage_pct": det_pct,
            "affected_component": component,
            "days_since_disclosure": days_old,
            "intel_enriched_at": datetime.now(timezone.utc).isoformat(),
            "enrichment_version": "v46.0",
        }

    def enrich_item(self, item: Dict) -> Dict:
        """Enrich item with full extended_metrics payload."""
        try:
            item["extended_metrics"] = self.build(item)
        except Exception as e:
            logger.warning(f"Extended metrics build failed: {e}")
            item.setdefault("extended_metrics", {})
        return item

    def batch_enrich(self, items: List[Dict]) -> List[Dict]:
        """Batch enrich all items. Requires actor_profile + exploit_status to be set first."""
        enriched = []
        for item in items:
            enriched.append(self.enrich_item(item))
        return enriched


extended_metrics_builder_v46 = ExtendedMetricsBuilderV46()
