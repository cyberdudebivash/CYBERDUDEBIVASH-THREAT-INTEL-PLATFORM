"""
SENTINEL APEX v70 — Enhanced Blog Report Generator
=====================================================
Produces analyst-grade blog reports with:
- Attack chain modeling (kill chain phases)
- Threat actor mapping and profiling
- Real-world exploitation context
- Cross-reference to related advisories
- MITRE ATT&CK technique detail
- Structured HTML output for Blogger

Does NOT just rephrase NVD — adds real intelligence context.
"""

import html
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..core.models import Advisory, Severity, ThreatType, ConfidenceLevel

logger = logging.getLogger("sentinel.blog.report_gen")


# ---------------------------------------------------------------------------
# Kill Chain Phase Mapping
# ---------------------------------------------------------------------------

KILL_CHAIN_PHASES = {
    "reconnaissance": {
        "phase": "1. Reconnaissance",
        "description": "Adversary gathers information about the target.",
        "techniques": ["T1595", "T1592", "T1589", "T1590", "T1591", "T1593", "T1594"],
    },
    "weaponization": {
        "phase": "2. Weaponization",
        "description": "Adversary creates exploit payload or malicious deliverable.",
        "techniques": ["T1583", "T1584", "T1587", "T1588"],
    },
    "delivery": {
        "phase": "3. Delivery",
        "description": "Payload delivered to the target environment.",
        "techniques": ["T1566", "T1195", "T1189", "T1199"],
    },
    "exploitation": {
        "phase": "4. Exploitation",
        "description": "Vulnerability exploited to gain initial access.",
        "techniques": ["T1190", "T1203", "T1059", "T1204"],
    },
    "installation": {
        "phase": "5. Installation",
        "description": "Malware/tooling installed for persistence.",
        "techniques": ["T1547", "T1053", "T1136", "T1098", "T1543"],
    },
    "command_control": {
        "phase": "6. Command & Control",
        "description": "Communication channel established with attacker infrastructure.",
        "techniques": ["T1071", "T1105", "T1572", "T1573"],
    },
    "actions_on_objectives": {
        "phase": "7. Actions on Objectives",
        "description": "Adversary achieves their goal (data theft, encryption, etc.).",
        "techniques": ["T1486", "T1048", "T1565", "T1529", "T1490"],
    },
}


def infer_kill_chain_phases(techniques: List[str]) -> List[str]:
    """Map MITRE techniques to kill chain phases."""
    phases = set()
    for phase_name, phase_data in KILL_CHAIN_PHASES.items():
        for tech in techniques:
            tech_base = tech.split(".")[0]  # Handle sub-techniques
            if tech_base in phase_data["techniques"]:
                phases.add(phase_data["phase"])
    return sorted(phases)


# ---------------------------------------------------------------------------
# Threat Actor Knowledge Base (lightweight, embedded)
# ---------------------------------------------------------------------------

KNOWN_ACTORS: Dict[str, Dict[str, Any]] = {
    "apt28": {
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
        "origin": "Russia",
        "motivation": "Espionage",
        "targets": ["Government", "Military", "Defense", "Media"],
    },
    "apt29": {
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
        "origin": "Russia",
        "motivation": "Espionage",
        "targets": ["Government", "Technology", "Think Tanks"],
    },
    "apt41": {
        "aliases": ["Winnti", "Barium", "Double Dragon"],
        "origin": "China",
        "motivation": "Espionage / Financial",
        "targets": ["Technology", "Healthcare", "Gaming", "Telecom"],
    },
    "lazarus": {
        "aliases": ["Lazarus Group", "HIDDEN COBRA", "Diamond Sleet"],
        "origin": "North Korea",
        "motivation": "Financial / Espionage",
        "targets": ["Financial", "Cryptocurrency", "Defense"],
    },
    "sandworm": {
        "aliases": ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard"],
        "origin": "Russia",
        "motivation": "Destruction / Espionage",
        "targets": ["Energy", "Critical Infrastructure", "Government"],
    },
    "apt1": {
        "aliases": ["Comment Crew", "PLA Unit 61398"],
        "origin": "China",
        "motivation": "Espionage",
        "targets": ["Defense", "Aerospace", "Technology"],
    },
    "fin7": {
        "aliases": ["Carbanak", "Carbon Spider"],
        "origin": "Russia",
        "motivation": "Financial",
        "targets": ["Retail", "Hospitality", "Financial"],
    },
    "lockbit": {
        "aliases": ["LockBit", "LockBit 3.0", "LockBit Black"],
        "origin": "Russia-linked",
        "motivation": "Financial (Ransomware)",
        "targets": ["All sectors — opportunistic"],
    },
    "clop": {
        "aliases": ["Cl0p", "TA505"],
        "origin": "Russia-linked",
        "motivation": "Financial (Ransomware/Extortion)",
        "targets": ["Enterprise", "Government", "Financial"],
    },
}


def lookup_actor_info(actor_name: str) -> Optional[Dict[str, Any]]:
    """Lookup known threat actor information."""
    key = actor_name.lower().strip().replace(" ", "")
    for ak, info in KNOWN_ACTORS.items():
        if ak in key:
            return info
        for alias in info.get("aliases", []):
            if alias.lower().replace(" ", "") in key:
                return info
    return None


# ---------------------------------------------------------------------------
# Blog Report Generator
# ---------------------------------------------------------------------------

class BlogReportGenerator:
    """
    Generates enhanced HTML blog reports for Blogger publishing.
    Each report is analyst-grade with real intelligence context.
    """

    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    SEVERITY_BADGES = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🔵 LOW",
        "info": "⚪ INFO",
    }

    def generate_report(
        self,
        advisory: Advisory,
        related_advisories: Optional[List[Advisory]] = None,
    ) -> Dict[str, str]:
        """
        Generate a complete blog report.
        Returns {"title": ..., "html": ..., "labels": [...]}.
        """
        sev = advisory.severity.value
        color = self.SEVERITY_COLORS.get(sev, "#6b7280")
        badge = self.SEVERITY_BADGES.get(sev, "⚪ INFO")

        # Build attack chain
        kill_chain = infer_kill_chain_phases(advisory.mitre_techniques)
        advisory.attack_chain = kill_chain

        sections = []

        # ── Header Section ──
        sections.append(self._header_section(advisory, badge, color))

        # ── Executive Summary ──
        sections.append(self._executive_summary(advisory))

        # ── Threat Intelligence Details ──
        sections.append(self._threat_details(advisory, color))

        # ── Attack Chain Analysis ──
        if kill_chain:
            sections.append(self._attack_chain_section(kill_chain, advisory.mitre_techniques))

        # ── Threat Actor Profile ──
        if advisory.actors:
            sections.append(self._actor_profile_section(advisory.actors))

        # ── IOC Section ──
        if advisory.iocs:
            sections.append(self._ioc_section(advisory))

        # ── CVE Detail Section ──
        if advisory.cves:
            sections.append(self._cve_section(advisory))

        # ── Cross-References ──
        if related_advisories:
            sections.append(self._cross_reference_section(related_advisories))

        # ── Recommendations ──
        sections.append(self._recommendations_section(advisory))

        # ── Footer ──
        sections.append(self._footer_section(advisory))

        full_html = "\n".join(sections)

        # Generate labels
        labels = self._generate_labels(advisory)

        return {
            "title": f"[{badge}] {advisory.title}",
            "html": full_html,
            "labels": labels,
        }

    def _header_section(self, adv: Advisory, badge: str, color: str) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return f"""
<div style="border-left:4px solid {color};padding:12px 16px;margin-bottom:20px;background:#f8f9fa;border-radius:4px;">
  <h2 style="margin:0 0 8px 0;color:#1a1a1a;">{badge} {html.escape(adv.title)}</h2>
  <p style="margin:0;color:#666;font-size:0.9em;">
    Published: {html.escape(adv.published_date or 'N/A')} | Source: {html.escape(adv.source_name or 'N/A')} | Generated: {ts}
  </p>
  <p style="margin:4px 0 0 0;color:#666;font-size:0.85em;">
    Threat Score: <strong>{adv.threat_score}/100</strong> |
    Confidence: <strong>{adv.confidence:.1f}%</strong> ({adv.confidence_level.value}) |
    Classification: <strong>{html.escape(adv.ai_classification or adv.threat_type.value)}</strong>
  </p>
</div>"""

    def _executive_summary(self, adv: Advisory) -> str:
        summary_text = adv.ai_summary or adv.summary or "No summary available."
        return f"""
<h3>📋 Executive Summary</h3>
<p>{html.escape(summary_text)}</p>"""

    def _threat_details(self, adv: Advisory, color: str) -> str:
        rows = []
        rows.append(f"<tr><td><strong>Threat Type</strong></td><td>{html.escape(adv.threat_type.value)}</td></tr>")
        rows.append(f"<tr><td><strong>Severity</strong></td><td style='color:{color};font-weight:bold;'>{adv.severity.value.upper()}</td></tr>")
        rows.append(f"<tr><td><strong>Risk Level</strong></td><td>{html.escape(adv.risk_level or 'N/A')}</td></tr>")
        rows.append(f"<tr><td><strong>Threat Score</strong></td><td>{adv.threat_score}/100</td></tr>")
        rows.append(f"<tr><td><strong>Confidence</strong></td><td>{adv.confidence:.1f}% ({adv.confidence_level.value})</td></tr>")

        if adv.cves:
            rows.append(f"<tr><td><strong>CVEs</strong></td><td>{html.escape(', '.join(adv.cves[:10]))}</td></tr>")
        if adv.mitre_techniques:
            rows.append(f"<tr><td><strong>MITRE ATT&CK</strong></td><td>{html.escape(', '.join(adv.mitre_techniques[:8]))}</td></tr>")
        if adv.actors:
            rows.append(f"<tr><td><strong>Threat Actors</strong></td><td>{html.escape(', '.join(adv.actors[:5]))}</td></tr>")
        if adv.affected_products:
            rows.append(f"<tr><td><strong>Affected Products</strong></td><td>{html.escape(', '.join(adv.affected_products[:5]))}</td></tr>")

        rows.append(f"<tr><td><strong>Source</strong></td><td><a href='{html.escape(adv.source_url or '#')}'>{html.escape(adv.source_name or 'Original Advisory')}</a></td></tr>")

        table_rows = "\n".join(rows)
        return f"""
<h3>🔍 Threat Intelligence Details</h3>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
<tbody>
{table_rows}
</tbody>
</table>"""

    def _attack_chain_section(self, kill_chain: List[str], techniques: List[str]) -> str:
        phases_html = ""
        for phase in kill_chain:
            # Find matching techniques for this phase
            phase_key = phase.split(". ", 1)[1].lower().replace(" & ", "_").replace(" ", "_") if ". " in phase else ""
            phase_data = None
            for pk, pd in KILL_CHAIN_PHASES.items():
                if pd["phase"] == phase:
                    phase_data = pd
                    break

            matched_techs = []
            if phase_data:
                for t in techniques:
                    if t.split(".")[0] in phase_data["techniques"]:
                        matched_techs.append(t)

            desc = phase_data["description"] if phase_data else ""
            tech_str = f" ({', '.join(matched_techs)})" if matched_techs else ""
            phases_html += f'<li><strong>{html.escape(phase)}</strong>{html.escape(tech_str)}<br/><em>{html.escape(desc)}</em></li>\n'

        return f"""
<h3>⚔️ Attack Chain Analysis</h3>
<p>Based on observed techniques, this threat maps to the following kill chain phases:</p>
<ol style="line-height:1.8;">
{phases_html}
</ol>"""

    def _actor_profile_section(self, actors: List[str]) -> str:
        profiles = []
        for actor in actors[:3]:
            info = lookup_actor_info(actor)
            if info:
                aliases = ", ".join(info.get("aliases", [])[:4])
                profiles.append(f"""
<div style="background:#f0f4ff;padding:12px;border-radius:4px;margin-bottom:8px;">
  <strong>{html.escape(actor)}</strong>
  {'<br/>Aliases: ' + html.escape(aliases) if aliases else ''}
  <br/>Origin: {html.escape(info.get('origin', 'Unknown'))}
  | Motivation: {html.escape(info.get('motivation', 'Unknown'))}
  <br/>Known Targets: {html.escape(', '.join(info.get('targets', [])[:5]))}
</div>""")
            else:
                profiles.append(f"<p><strong>{html.escape(actor)}</strong> — No known profile in database.</p>")

        return f"""
<h3>🎭 Threat Actor Profile</h3>
{''.join(profiles)}"""

    def _ioc_section(self, adv: Advisory) -> str:
        rows = []
        for ioc in adv.iocs[:20]:
            if hasattr(ioc, 'value'):
                val = html.escape(ioc.value)
                itype = html.escape(ioc.ioc_type.value if hasattr(ioc, 'ioc_type') else 'unknown')
            elif isinstance(ioc, dict):
                val = html.escape(str(ioc.get('value', '')))
                itype = html.escape(str(ioc.get('type', 'unknown')))
            else:
                val = html.escape(str(ioc))
                itype = "unknown"
            rows.append(f"<tr><td><code>{val}</code></td><td>{itype}</td></tr>")

        return f"""
<h3>🎯 Indicators of Compromise (IOCs)</h3>
<table style="width:100%;border-collapse:collapse;">
<thead><tr><th style="text-align:left;">Value</th><th style="text-align:left;">Type</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
<p style="font-size:0.85em;color:#666;">Total IOCs: {len(adv.iocs)}</p>"""

    def _cve_section(self, adv: Advisory) -> str:
        cve_items = []
        for cve in adv.cves[:10]:
            cve_escaped = html.escape(cve)
            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_escaped}"
            cve_items.append(
                f'<li><a href="{nvd_link}" target="_blank"><strong>{cve_escaped}</strong></a> — '
                f'<a href="https://www.cvedetails.com/cve/{cve_escaped}/" target="_blank">Details</a></li>'
            )
        return f"""
<h3>🛡️ CVE References</h3>
<ul>
{''.join(cve_items)}
</ul>"""

    def _cross_reference_section(self, related: List[Advisory]) -> str:
        items = []
        for r in related[:5]:
            sev_badge = self.SEVERITY_BADGES.get(r.severity.value, "⚪")
            items.append(
                f"<li>{sev_badge} {html.escape(r.title)} "
                f"(Score: {r.threat_score}, {html.escape(r.published_date or 'N/A')})"
                f"{'  — ' + html.escape(r.blog_post_url) if r.blog_post_url else ''}</li>"
            )
        return f"""
<h3>🔗 Related Advisories</h3>
<ul>
{''.join(items)}
</ul>"""

    def _recommendations_section(self, adv: Advisory) -> str:
        recs = []
        if adv.cves:
            recs.append("Apply vendor patches immediately for referenced CVEs.")
        if any(t.startswith("T1566") for t in adv.mitre_techniques):
            recs.append("Strengthen email security controls and user awareness training.")
        if any(t.startswith("T1190") for t in adv.mitre_techniques):
            recs.append("Audit internet-facing assets and apply WAF rules.")
        if any(t.startswith("T1486") for t in adv.mitre_techniques):
            recs.append("Verify backup integrity and test restore procedures.")
        if any(t.startswith("T1078") for t in adv.mitre_techniques):
            recs.append("Enforce MFA and audit privileged account access.")
        if adv.iocs:
            recs.append("Ingest provided IOCs into SIEM/EDR for detection.")
        if not recs:
            recs.append("Monitor vendor advisories and apply patches per your risk tolerance.")
            recs.append("Review detection coverage for referenced MITRE techniques.")

        items = "\n".join(f"<li>{html.escape(r)}</li>" for r in recs)
        return f"""
<h3>✅ Recommendations</h3>
<ul>
{items}
</ul>"""

    def _footer_section(self, adv: Advisory) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return f"""
<hr/>
<p style="font-size:0.8em;color:#888;">
  Generated by <strong>CYBERDUDEBIVASH SENTINEL APEX v70</strong> | {ts}<br/>
  Advisory ID: {html.escape(adv.advisory_id)} | Cluster: {html.escape(adv.ai_cluster_id or 'N/A')}<br/>
  <a href="https://intel.cyberdudebivash.com" target="_blank">intel.cyberdudebivash.com</a> |
  <a href="https://cyberdudebivash.com" target="_blank">cyberdudebivash.com</a>
</p>"""

    def _generate_labels(self, adv: Advisory) -> List[str]:
        """Generate Blogger labels/tags for the post."""
        labels = ["SENTINEL APEX", "Threat Intelligence"]
        labels.append(adv.severity.value.capitalize())
        labels.append(adv.threat_type.value.replace("-", " ").title())
        for cve in adv.cves[:3]:
            labels.append(cve)
        for actor in adv.actors[:2]:
            labels.append(actor)
        for tech in adv.mitre_techniques[:3]:
            labels.append(f"MITRE {tech}")
        return list(set(labels))[:20]  # Blogger label limit
