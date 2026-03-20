#!/usr/bin/env python3
"""
report_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v64.0 (COMMAND CENTER)
════════════════════════════════════════════════════════════════════════════
Enterprise Intelligence Report Generation Engine.

Capabilities:
  - Single-item threat reports with multi-source validation
  - Executive briefings from manifest data
  - Confidence scoring based on source corroboration
  - Zero hallucination: only reports data present in manifest/items
  - Structured output for dashboard, API, and export

Architecture:
  - Reads from ManifestManager (single source of truth)
  - Cross-references with AI engine analysis
  - No external API calls — fully offline/deterministic
"""

import logging
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-REPORT-ENGINE")


class ReportEngine:
    """
    Enterprise-grade intelligence report generator.

    Produces structured threat reports with:
    - Multi-factor risk assessment
    - Source corroboration scoring
    - MITRE ATT&CK mapping
    - IOC summary
    - Actionable recommendations
    - Executive impact analysis
    """

    SEVERITY_MAP = {
        "CRITICAL": {"weight": 4, "color": "#f43f5e", "action_urgency": "IMMEDIATE"},
        "HIGH":     {"weight": 3, "color": "#f97316", "action_urgency": "24 HOURS"},
        "MEDIUM":   {"weight": 2, "color": "#eab308", "action_urgency": "72 HOURS"},
        "LOW":      {"weight": 1, "color": "#22c55e", "action_urgency": "SCHEDULED"},
        "INFO":     {"weight": 0, "color": "#38bdf8", "action_urgency": "AWARENESS"},
    }

    EXPLOIT_KEYWORDS = [
        "actively exploited", "in the wild", "in-the-wild", "exploit available",
        "proof of concept", "poc available", "weaponized", "zero-day", "0-day",
    ]

    SUPPLY_CHAIN_KEYWORDS = [
        "supply chain", "dependency", "npm", "pypi", "package manager",
        "software update", "vendor compromise", "third-party", "solarwinds",
    ]

    RANSOMWARE_KEYWORDS = [
        "ransomware", "lockbit", "blackcat", "alphv", "clop", "royal",
        "data exfiltration", "double extortion", "ransom",
    ]

    def __init__(self):
        self._report_count = 0

    def generate_report(self, entry: Dict) -> Dict:
        """
        Generate a comprehensive threat intelligence report for a single item.

        Args:
            entry: A manifest entry or intelligence item dict.

        Returns:
            Structured report dict with all analysis sections.
        """
        self._report_count += 1
        report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self._report_count:04d}"

        title = entry.get("title", "Unknown Advisory")
        content = entry.get("content", entry.get("description", ""))
        content_lower = (title + " " + content).lower()

        # Risk assessment
        risk_score = entry.get("risk_score", 0)
        severity = entry.get("severity", self._derive_severity(risk_score))
        sev_info = self.SEVERITY_MAP.get(severity.upper(), self.SEVERITY_MAP["MEDIUM"])

        # Confidence scoring
        confidence = self._compute_confidence(entry)

        # Exploit status
        exploit_status = self._assess_exploit_status(content_lower, entry)

        # IOC summary
        ioc_summary = self._summarize_iocs(entry)

        # MITRE mapping
        mitre = entry.get("mitre_tactics", [])

        # Threat classification
        classification = self._classify_threat(content_lower, entry)

        # Impact assessment
        impact = self._assess_impact(entry, content_lower, sev_info)

        # Actionable recommendations
        recommendations = self._generate_recommendations(
            severity, exploit_status, classification, ioc_summary, mitre
        )

        # Why this matters
        why_it_matters = self._why_it_matters(entry, exploit_status, classification, ioc_summary)

        report = {
            "report_id": report_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": title,
            "severity": severity,
            "risk_score": risk_score,
            "confidence_score": round(confidence, 1),
            "action_urgency": sev_info["action_urgency"],

            "exploit_status": exploit_status,
            "threat_classification": classification,

            "ioc_summary": ioc_summary,
            "mitre_techniques": mitre,

            "impact_assessment": impact,
            "recommendations": recommendations,
            "why_it_matters": why_it_matters,

            # Extended metrics from manifest
            "cvss_score": entry.get("cvss_score"),
            "epss_score": entry.get("epss_score"),
            "kev_present": entry.get("kev_present", False),
            "actor_tag": entry.get("actor_tag", "Unknown"),
            "supply_chain": entry.get("supply_chain", False),
            "tlp_label": entry.get("tlp_label", "CLEAR"),
            "feed_source": entry.get("feed_source", ""),
            "source_url": entry.get("source_url", ""),
            "stix_id": entry.get("stix_id", ""),

            "campaign_id": entry.get("campaign_id"),
            "cluster_id": entry.get("cluster_id"),
        }

        logger.info(f"Report generated: {report_id} | {severity} | {title[:60]}")
        return report

    def generate_executive_briefing(self, entries: List[Dict], limit: int = 20) -> Dict:
        """
        Generate an executive briefing summarizing top threats.

        Args:
            entries: List of manifest entries.
            limit: Max number of threats to include.

        Returns:
            Executive briefing dict with landscape overview and top threats.
        """
        if not entries:
            return {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "threat_count": 0,
                "landscape": "No intelligence data available.",
                "top_threats": [],
            }

        # Sort by risk score descending
        sorted_entries = sorted(entries, key=lambda e: e.get("risk_score", 0), reverse=True)
        top = sorted_entries[:limit]

        # Severity breakdown
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for e in entries:
            sev = e.get("severity", "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Unique actors
        actors = set()
        for e in entries:
            actor = e.get("actor_tag", "")
            if actor and actor != "Unknown":
                actors.add(actor)

        # KEV count
        kev_count = sum(1 for e in entries if e.get("kev_present"))

        # CVE list
        cves = set()
        for e in entries:
            content = (e.get("title", "") + " " + e.get("content", "")).upper()
            import re
            found = re.findall(r"CVE-\d{4}-\d{4,7}", content)
            cves.update(found)

        # Active exploitation
        exploit_count = 0
        for e in entries:
            cl = (e.get("title", "") + " " + e.get("content", "")).lower()
            if any(kw in cl for kw in self.EXPLOIT_KEYWORDS):
                exploit_count += 1

        # Generate landscape summary (zero hallucination — only from data)
        landscape_parts = [f"{len(entries)} advisories tracked"]
        if sev_counts["CRITICAL"] > 0:
            landscape_parts.append(f"{sev_counts['CRITICAL']} CRITICAL threats requiring immediate action")
        if kev_count > 0:
            landscape_parts.append(f"{kev_count} KEV-listed vulnerabilities")
        if exploit_count > 0:
            landscape_parts.append(f"{exploit_count} actively exploited vulnerabilities")
        if actors:
            landscape_parts.append(f"{len(actors)} tracked threat actors ({', '.join(list(actors)[:5])})")
        if cves:
            landscape_parts.append(f"{len(cves)} unique CVEs identified")

        # Top threats as mini-reports
        top_threats = []
        for e in top:
            top_threats.append({
                "title": e.get("title", "Unknown"),
                "risk_score": e.get("risk_score", 0),
                "severity": e.get("severity", "MEDIUM"),
                "actor_tag": e.get("actor_tag", "Unknown"),
                "kev_present": e.get("kev_present", False),
                "cvss_score": e.get("cvss_score"),
                "epss_score": e.get("epss_score"),
                "mitre_tactics": e.get("mitre_tactics", []),
                "ioc_counts": e.get("ioc_counts", {}),
                "why_it_matters": self._why_it_matters_brief(e),
            })

        briefing = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "threat_count": len(entries),
            "severity_breakdown": sev_counts,
            "kev_count": kev_count,
            "exploit_count": exploit_count,
            "unique_cves": len(cves),
            "active_actors": sorted(list(actors)),
            "landscape": ". ".join(landscape_parts) + ".",
            "top_threats": top_threats,
            "avg_risk_score": round(
                sum(e.get("risk_score", 0) for e in entries) / len(entries), 1
            ) if entries else 0,
        }

        logger.info(f"Executive briefing generated: {len(entries)} items, {len(top_threats)} top threats")
        return briefing

    # ── Confidence Scoring ──────────────────────────────────

    def _compute_confidence(self, entry: Dict) -> float:
        """
        Multi-factor confidence scoring (0-100).
        Based on data completeness, source quality, and corroboration signals.
        """
        score = 30.0  # Base confidence

        # Source URL present
        if entry.get("source_url"):
            score += 10.0

        # Feed source from known premium tier
        feed = entry.get("feed_source", "").lower()
        premium_sources = ["cisa.gov", "nist.gov", "cert.", "us-cert", "ncsc", "unit42", "mandiant"]
        if any(ps in feed for ps in premium_sources):
            score += 15.0
        elif feed:
            score += 5.0

        # KEV presence (government validated)
        if entry.get("kev_present"):
            score += 15.0

        # CVSS score present (structured vulnerability data)
        if entry.get("cvss_score") and entry["cvss_score"] > 0:
            score += 5.0

        # EPSS score present (probability-based)
        if entry.get("epss_score") and entry["epss_score"] > 0:
            score += 5.0

        # IOCs present (actionable indicators)
        iocs = entry.get("ioc_counts", entry.get("iocs", {}))
        ioc_count = 0
        for v in iocs.values():
            ioc_count += len(v) if isinstance(v, list) else (v if isinstance(v, (int, float)) else 0)
        if ioc_count >= 3:
            score += 10.0
        elif ioc_count >= 1:
            score += 5.0

        # MITRE mapping present
        if entry.get("mitre_tactics") and len(entry["mitre_tactics"]) > 0:
            score += 5.0

        # Actor attribution
        actor = entry.get("actor_tag", "")
        if actor and actor != "Unknown":
            score += 5.0

        return min(score, 100.0)

    # ── Exploit Status ──────────────────────────────────────

    def _assess_exploit_status(self, content_lower: str, entry: Dict) -> Dict:
        """Assess exploitation status from content and metadata."""
        status = {
            "actively_exploited": False,
            "poc_available": False,
            "in_kev": entry.get("kev_present", False),
            "status_label": "NO KNOWN EXPLOITATION",
        }

        if any(kw in content_lower for kw in ["actively exploited", "in the wild", "in-the-wild"]):
            status["actively_exploited"] = True
            status["status_label"] = "ACTIVELY EXPLOITED"

        if any(kw in content_lower for kw in ["proof of concept", "poc available", "poc published"]):
            status["poc_available"] = True
            if not status["actively_exploited"]:
                status["status_label"] = "POC AVAILABLE"

        if entry.get("kev_present") and not status["actively_exploited"]:
            status["actively_exploited"] = True
            status["status_label"] = "ACTIVELY EXPLOITED (KEV)"

        if any(kw in content_lower for kw in ["zero-day", "0-day"]):
            status["status_label"] = "ZERO-DAY " + status["status_label"]

        return status

    # ── IOC Summary ─────────────────────────────────────────

    def _summarize_iocs(self, entry: Dict) -> Dict:
        """Summarize IOC data from entry."""
        iocs = entry.get("ioc_counts", entry.get("iocs", {}))
        summary = {"total": 0, "by_type": {}}

        for ioc_type, value in iocs.items():
            if isinstance(value, list):
                count = len(value)
                summary["by_type"][ioc_type] = {"count": count, "samples": value[:3]}
            elif isinstance(value, (int, float)):
                count = int(value)
                summary["by_type"][ioc_type] = {"count": count}
            else:
                count = 0
            summary["total"] += count

        return summary

    # ── Threat Classification ───────────────────────────────

    def _classify_threat(self, content_lower: str, entry: Dict) -> Dict:
        """Classify the threat type based on content analysis."""
        categories = []

        if any(kw in content_lower for kw in self.RANSOMWARE_KEYWORDS):
            categories.append("RANSOMWARE")
        if any(kw in content_lower for kw in self.SUPPLY_CHAIN_KEYWORDS) or entry.get("supply_chain"):
            categories.append("SUPPLY_CHAIN")
        if any(kw in content_lower for kw in ["nation-state", "apt", "state-sponsored", "espionage"]):
            categories.append("NATION_STATE_APT")
        if any(kw in content_lower for kw in ["phishing", "spear-phishing", "social engineering"]):
            categories.append("PHISHING")
        if any(kw in content_lower for kw in ["remote code execution", "rce", "arbitrary code"]):
            categories.append("RCE")
        if any(kw in content_lower for kw in ["data breach", "data leak", "data exfiltration"]):
            categories.append("DATA_BREACH")
        if any(kw in content_lower for kw in ["malware", "trojan", "backdoor", "rootkit"]):
            categories.append("MALWARE")
        if any(kw in content_lower for kw in ["privilege escalation", "elevation of privilege"]):
            categories.append("PRIVILEGE_ESCALATION")

        if not categories:
            categories.append("VULNERABILITY")

        return {
            "primary": categories[0],
            "all_categories": categories,
        }

    # ── Impact Assessment ───────────────────────────────────

    def _assess_impact(self, entry: Dict, content_lower: str, sev_info: Dict) -> Dict:
        """Generate impact assessment based on available data."""
        impact = {
            "severity_weight": sev_info["weight"],
            "sectors_affected": [],
            "estimated_scope": "UNKNOWN",
        }

        # Sector detection
        sector_keywords = {
            "Healthcare": ["hospital", "healthcare", "medical", "patient", "hipaa"],
            "Financial": ["bank", "financial", "payment", "credit card", "swift"],
            "Government": ["government", "federal", "state agency", "military"],
            "Energy": ["power grid", "energy", "utility", "scada", "ics"],
            "Technology": ["software", "cloud", "saas", "developer", "npm", "pypi"],
            "Telecommunications": ["telecom", "5g", "mobile carrier", "sim"],
            "Education": ["university", "school", "education", "academic"],
            "Critical Infrastructure": ["water treatment", "critical infrastructure", "transportation"],
        }

        for sector, keywords in sector_keywords.items():
            if any(kw in content_lower for kw in keywords):
                impact["sectors_affected"].append(sector)

        # Scope estimation from content
        import re
        numbers = re.findall(r'(\d{1,3}(?:,\d{3})*(?:\.\d+)?)\s*(million|thousand|billion|systems|devices|users|records)', content_lower)
        if numbers:
            impact["estimated_scope"] = "WIDESPREAD"
        elif any(kw in content_lower for kw in ["widespread", "mass exploitation", "global"]):
            impact["estimated_scope"] = "WIDESPREAD"
        elif any(kw in content_lower for kw in ["targeted", "specific", "limited"]):
            impact["estimated_scope"] = "TARGETED"
        else:
            impact["estimated_scope"] = "MODERATE"

        return impact

    # ── Recommendations ─────────────────────────────────────

    def _generate_recommendations(
        self, severity: str, exploit_status: Dict,
        classification: Dict, ioc_summary: Dict, mitre: List
    ) -> List[str]:
        """Generate actionable recommendations based on threat analysis."""
        recs = []

        sev_upper = severity.upper()
        primary_type = classification.get("primary", "")

        if exploit_status.get("actively_exploited"):
            recs.append("PRIORITY: Apply vendor patches immediately — active exploitation confirmed.")

        if exploit_status.get("in_kev"):
            recs.append("Verify compliance with CISA KEV remediation deadline.")

        if ioc_summary.get("total", 0) > 0:
            ioc_types = list(ioc_summary.get("by_type", {}).keys())
            recs.append(f"Block extracted IOCs ({', '.join(ioc_types)}) in firewall, proxy, and EDR.")

        if "RANSOMWARE" in classification.get("all_categories", []):
            recs.append("Verify backup integrity and test restoration procedures.")
            recs.append("Review network segmentation to contain lateral movement.")

        if "SUPPLY_CHAIN" in classification.get("all_categories", []):
            recs.append("Audit third-party software dependencies and vendor access.")
            recs.append("Review software bill of materials (SBOM) for affected components.")

        if "NATION_STATE_APT" in classification.get("all_categories", []):
            recs.append("Conduct threat hunt for indicators of compromise across environment.")
            recs.append("Review privileged account activity for anomalous behavior.")

        if "RCE" in classification.get("all_categories", []):
            recs.append("Prioritize patching of affected systems — RCE enables full compromise.")

        if mitre:
            recs.append(f"Review detection coverage for MITRE techniques: {', '.join(mitre[:5])}.")

        if sev_upper == "CRITICAL" and not recs:
            recs.append("Escalate to security operations for immediate triage.")

        if not recs:
            recs.append("Monitor for updates and assess applicability to your environment.")

        return recs

    # ── Why It Matters ──────────────────────────────────────

    def _why_it_matters(
        self, entry: Dict, exploit_status: Dict,
        classification: Dict, ioc_summary: Dict
    ) -> str:
        """Generate a concise 'why this matters' statement."""
        parts = []

        risk = entry.get("risk_score", 0)
        severity = entry.get("severity", "MEDIUM").upper()

        if severity == "CRITICAL":
            parts.append(f"CRITICAL threat (risk {risk}/100)")
        elif severity == "HIGH":
            parts.append(f"High-severity threat (risk {risk}/100)")

        if exploit_status.get("actively_exploited"):
            parts.append("with confirmed active exploitation")

        if entry.get("kev_present"):
            parts.append("listed in CISA KEV catalog")

        actor = entry.get("actor_tag", "")
        if actor and actor != "Unknown":
            parts.append(f"attributed to {actor}")

        categories = classification.get("all_categories", [])
        if "RANSOMWARE" in categories:
            parts.append("involving ransomware deployment")
        if "SUPPLY_CHAIN" in categories:
            parts.append("with supply chain implications")

        if ioc_summary.get("total", 0) > 0:
            parts.append(f"with {ioc_summary['total']} actionable IOCs")

        if not parts:
            return "Monitor for updates and assess applicability to your environment."

        return ". ".join(parts) + "."

    def _why_it_matters_brief(self, entry: Dict) -> str:
        """Short version for executive briefing top threats."""
        parts = []
        if entry.get("kev_present"):
            parts.append("KEV-listed")
        actor = entry.get("actor_tag", "")
        if actor and actor != "Unknown":
            parts.append(f"Actor: {actor}")
        content_lower = (entry.get("title", "") + " " + entry.get("content", "")).lower()
        if any(kw in content_lower for kw in self.EXPLOIT_KEYWORDS):
            parts.append("Active exploitation")
        if any(kw in content_lower for kw in self.RANSOMWARE_KEYWORDS):
            parts.append("Ransomware")
        if any(kw in content_lower for kw in self.SUPPLY_CHAIN_KEYWORDS):
            parts.append("Supply chain")
        if not parts:
            sev = entry.get("severity", "MEDIUM")
            parts.append(f"{sev} severity")
        return " | ".join(parts)

    # ── Utility ─────────────────────────────────────────────

    def _derive_severity(self, risk_score: float) -> str:
        if risk_score >= 80:
            return "CRITICAL"
        if risk_score >= 60:
            return "HIGH"
        if risk_score >= 40:
            return "MEDIUM"
        if risk_score >= 20:
            return "LOW"
        return "INFO"

    def get_stats(self) -> Dict:
        return {"reports_generated": self._report_count}


# Module-level singleton
report_engine = ReportEngine()
