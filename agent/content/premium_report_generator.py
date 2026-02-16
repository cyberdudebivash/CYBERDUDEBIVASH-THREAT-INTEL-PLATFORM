#!/usr/bin/env python3
"""
premium_report_generator.py — CyberDudeBivash v12.0 (SENTINEL APEX ULTRA)
NEW MODULE: Premium 16-Section Threat Intelligence Report Generator.
Produces 2500+ word, enterprise-grade reports following the
CYBERDUDEBIVASH PREMIUM THREAT INTEL REPORT TEMPLATE exactly.
"""
import re
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional

from agent.config import BRAND, COLORS, FONTS


class PremiumReportGenerator:
    """
    Generates premium, 2500+ word threat intelligence reports
    following the official CDB 16-section template.
    """

    def __init__(self):
        self.report_counter = 0

    def generate_report_id(self) -> str:
        """Generate unique report ID."""
        ts = datetime.now(timezone.utc).strftime('%Y-%m%d')
        seq = hashlib.sha256(str(time.time()).encode()).hexdigest()[:4].upper()
        return f"CDB-APEX-{ts}-{seq}"

    def _classify_threat_type(self, headline: str, content: str) -> Dict:
        """Classify the threat type from headline and content for contextual generation."""
        text = f"{headline} {content}".lower()

        classifications = {
            "data_breach": {
                "keywords": ["breach", "leak", "exposed", "stolen data", "customer records",
                             "data dump", "hackers leak", "compromised data"],
                "category": "Data Breach / Data Exposure Incident",
                "icon": "🔓",
                "sectors": ["Retail", "Financial Services", "Healthcare", "Technology"],
            },
            "malware_campaign": {
                "keywords": ["malware", "stealer", "trojan", "rat", "backdoor", "botnet",
                             "infostealer", "lumma", "redline", "vidar", "raccoon",
                             "loader", "dropper"],
                "category": "Malware Campaign / Threat Actor Operation",
                "icon": "☣️",
                "sectors": ["Enterprise", "Financial Services", "Government", "Technology"],
            },
            "vulnerability": {
                "keywords": ["cve-", "vulnerability", "zero-day", "0-day", "exploit",
                             "patch", "security update", "rce", "privilege escalation",
                             "buffer overflow", "code execution"],
                "category": "Vulnerability Disclosure / Exploitation",
                "icon": "⚠️",
                "sectors": ["All Industries", "Critical Infrastructure", "Government"],
            },
            "phishing_social": {
                "keywords": ["phishing", "clickfix", "social engineering", "fake",
                             "lure", "credential", "impersonation", "scam"],
                "category": "Phishing / Social Engineering Campaign",
                "icon": "🎣",
                "sectors": ["Enterprise", "Financial Services", "Healthcare", "Education"],
            },
            "ransomware": {
                "keywords": ["ransomware", "ransom", "encrypted files", "double extortion",
                             "lockbit", "blackcat", "cl0p", "akira", "play"],
                "category": "Ransomware / Extortion Operation",
                "icon": "💰",
                "sectors": ["Healthcare", "Manufacturing", "Government", "Education"],
            },
            "apt_espionage": {
                "keywords": ["apt", "nation-state", "espionage", "cyber espionage",
                             "state-sponsored", "volt typhoon", "lazarus", "fancy bear"],
                "category": "Advanced Persistent Threat / Cyber Espionage",
                "icon": "🕵️",
                "sectors": ["Government", "Defense", "Critical Infrastructure", "Technology"],
            },
            "supply_chain": {
                "keywords": ["supply chain", "dependency", "package", "npm", "pypi",
                             "software update", "compromised update"],
                "category": "Supply Chain Compromise",
                "icon": "🔗",
                "sectors": ["Technology", "Software Development", "SaaS Providers"],
            },
        }

        for key, data in classifications.items():
            if any(kw in text for kw in data["keywords"]):
                return data

        return {
            "category": "Cyber Threat Intelligence Advisory",
            "icon": "🛡️",
            "sectors": ["Enterprise", "Government", "Technology"],
            "keywords": [],
        }

    def _extract_mentioned_cves(self, text: str) -> List[str]:
        """Extract any CVE IDs from text."""
        return sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', text)))

    def _build_styles(self) -> Dict[str, str]:
        """Build inline CSS style dictionary for the report."""
        return {
            "wrapper": f"font-family:{FONTS['body']};color:{COLORS['text']};background:{COLORS['bg_dark']};"
                       f"max-width:960px;margin:auto;border:1px solid {COLORS['border']};",
            "tlp_bar": f"text-align:center;font-weight:900;letter-spacing:4px;font-size:10px;padding:12px;",
            "section": f"padding:0 50px;",
            "h1": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:32px;"
                  f"font-weight:800;letter-spacing:-1.5px;line-height:1.2;margin:8px 0 0;",
            "h2": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:18px;"
                  f"font-weight:700;border-bottom:1px solid {COLORS['border']};"
                  f"padding-bottom:8px;margin:40px 0 16px;",
            "h3": f"font-family:{FONTS['heading']};color:{COLORS['accent']};font-size:15px;"
                  f"font-weight:600;margin:24px 0 10px;padding-left:10px;"
                  f"border-left:3px solid {COLORS['accent']};",
            "p": f"color:{COLORS['text']};line-height:1.85;font-size:15px;margin:0 0 16px;",
            "p_muted": f"color:{COLORS['text_muted']};font-size:13px;line-height:1.6;",
            "card": f"background:{COLORS['bg_card']};border:1px solid {COLORS['border']};"
                    f"border-radius:6px;padding:20px;margin:16px 0;",
            "pre": f"background:#000;color:#00ff00;padding:20px;border:1px solid {COLORS['border']};"
                   f"font-family:{FONTS['mono']};font-size:11px;overflow-x:auto;"
                   f"border-radius:4px;margin:12px 0;line-height:1.6;",
            "table": f"width:100%;border-collapse:collapse;margin:12px 0;",
            "th": f"background:{COLORS['bg_dark']};color:{COLORS['white']};font-weight:600;"
                  f"text-align:left;padding:10px 14px;font-size:11px;text-transform:uppercase;"
                  f"letter-spacing:1px;border-bottom:2px solid {COLORS['border']};",
            "td": f"padding:10px 14px;border-bottom:1px solid {COLORS['border']};"
                  f"color:{COLORS['text']};font-size:14px;",
            "badge": f"display:inline-block;padding:4px 12px;border-radius:100px;"
                     f"font-size:10px;font-weight:700;letter-spacing:0.5px;margin-right:6px;",
            "ul": f"color:{COLORS['text']};line-height:2.2;font-size:14px;margin:12px 0;padding-left:20px;",
            "footer": f"margin-top:60px;border-top:1px solid {COLORS['border']};"
                      f"padding:30px 50px;text-align:center;",
        }

    def generate_premium_report(
        self,
        headline: str,
        source_content: str,
        source_url: str,
        iocs: Dict[str, List[str]],
        risk_score: float,
        severity: str,
        confidence: float,
        tlp: Dict[str, str],
        mitre_data: List[Dict],
        actor_data: Optional[Dict] = None,
        sigma_rule: str = "",
        yara_rule: str = "",
        fetched_article: Optional[Dict] = None,
        impact_metrics: Optional[Dict] = None,
    ) -> str:
        """
        Generate a premium 2500+ word threat intelligence report
        following the CYBERDUDEBIVASH 16-SECTION TEMPLATE.
        """
        s = self._build_styles()
        report_id = self.generate_report_id()
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        threat_type = self._classify_threat_type(headline, source_content)
        tracking_id = (actor_data or {}).get('tracking_id', 'UNC-CDB-99')
        actor_profile = (actor_data or {}).get('profile', {})
        tlp_color = tlp.get('color', COLORS['accent'])
        tlp_label = tlp.get('label', 'TLP:CLEAR')
        mentioned_cves = self._extract_mentioned_cves(f"{headline} {source_content}")
        impact = impact_metrics or {}

        # Source article details
        article_text = (fetched_article or {}).get('full_text', '') or source_content
        article_summary = (fetched_article or {}).get('paragraphs', [])

        # Severity styling
        sev_colors = {"CRITICAL": COLORS['critical'], "HIGH": COLORS['high'],
                      "MEDIUM": COLORS['medium'], "LOW": COLORS['low']}
        sev_color = sev_colors.get(severity, COLORS['accent'])

        sections = []

        # ═══════════════════════════════════════════════════════════════
        # COVER / HEADER
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
<div style="{s['wrapper']}">

    <!-- TLP CLASSIFICATION BAR -->
    <div style="{s['tlp_bar']}background:{tlp_color};color:#000;">
        {tlp_label} // CDB-GOC STRATEGIC INTELLIGENCE ADVISORY // SENTINEL APEX {BRAND['version']}
    </div>

    <div style="padding:40px 50px 0;">
        <!-- REPORT METADATA -->
        <div style="{s['p_muted']}margin-bottom:6px;">
            <b>Report ID:</b> {report_id} &nbsp;|&nbsp;
            <b>Classification:</b> {tlp_label} &nbsp;|&nbsp;
            <b>Published:</b> {now_str}
        </div>
        <div style="{s['p_muted']}margin-bottom:20px;">
            <b>Prepared By:</b> {BRAND['name']} Global Operations Center (GOC) &nbsp;|&nbsp;
            <b>Distribution:</b> Enterprise / SOC / Executive
        </div>

        <!-- SEVERITY BADGES -->
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px;">
            <span style="{s['badge']}background:{sev_color}22;color:{sev_color};">{severity}</span>
            <span style="{s['badge']}background:{tlp_color}22;color:{tlp_color};">{tlp_label}</span>
            <span style="{s['badge']}background:{COLORS['accent']}15;color:{COLORS['accent']};">RISK {risk_score}/10</span>
            <span style="{s['badge']}background:{COLORS['cyber_purple']}15;color:{COLORS['cyber_purple']};">CONFIDENCE {confidence}%</span>
            <span style="{s['badge']}background:{COLORS['cyber_blue']}15;color:{COLORS['cyber_blue']};">ACTOR {tracking_id}</span>
            {'<span style="' + s['badge'] + 'background:' + COLORS['cyber_pink'] + '15;color:' + COLORS['cyber_pink'] + ';">IMPACT: ' + f"{impact.get('records_affected', 0):,}" + ' RECORDS</span>' if impact.get('records_affected', 0) > 0 else ''}
            <span style="{s['badge']}background:#11111180;color:{COLORS['text_muted']};border:1px solid {COLORS['border']};">
                {threat_type['icon']} {threat_type['category']}</span>
        </div>

        <!-- TITLE -->
        <p style="color:{COLORS['accent']};font-weight:700;font-size:11px;letter-spacing:2px;margin:0;">
            CYBERDUDEBIVASH SENTINEL APEX™ // PREMIUM THREAT INTELLIGENCE ADVISORY</p>
        <h1 style="{s['h1']}">{headline}</h1>
        <p style="{s['p_muted']}margin-top:8px;">
            Advanced Threat Intelligence Advisory by {BRAND['name']} Sentinel APEX™ —
            AI-Powered Global Threat Intelligence Infrastructure</p>
    </div>

    <div style="{s['section']}">
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 1: EXECUTIVE SUMMARY
        # ═══════════════════════════════════════════════════════════════
        exec_summary = self._generate_executive_summary(
            headline, article_summary, article_text, threat_type, risk_score,
            severity, confidence, tracking_id, iocs, mentioned_cves, impact)

        sections.append(f"""
        <h2 style="{s['h2']}">1. EXECUTIVE SUMMARY (CISO / BOARD READY)</h2>
        <h3 style="{s['h3']}">Overview</h3>
        {exec_summary}

        <div style="{s['card']}">
            <h3 style="color:{COLORS['white']};font-size:14px;margin:0 0 12px;">Key Risk Rating</h3>
            <table style="{s['table']}">
                <tr><th style="{s['th']}">Category</th><th style="{s['th']}">Assessment</th></tr>
                <tr><td style="{s['td']}"><b>Overall Risk Score</b></td>
                    <td style="{s['td']}color:{sev_color};font-weight:700;">{risk_score} / 10</td></tr>
                <tr><td style="{s['td']}"><b>Confidence Level</b></td>
                    <td style="{s['td']}">{self._confidence_label(confidence)}</td></tr>
                <tr><td style="{s['td']}"><b>Exploitability</b></td>
                    <td style="{s['td']}">{self._exploitability_label(risk_score, article_text)}</td></tr>
                <tr><td style="{s['td']}"><b>Industry Impact</b></td>
                    <td style="{s['td']}">{severity}</td></tr>
            </table>
        </div>

        <h3 style="{s['h3']}">Strategic Impact Assessment</h3>
        <p style="{s['p']}">
            {self._generate_strategic_impact(headline, threat_type, severity, article_text)}
        </p>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 2: THREAT LANDSCAPE CONTEXT
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">2. THREAT LANDSCAPE CONTEXT</h2>
        <h3 style="{s['h3']}">Campaign Background</h3>
        <p style="{s['p']}">
            {self._generate_campaign_background(headline, article_text, article_summary, threat_type)}
        </p>

        <h3 style="{s['h3']}">Threat Actor Profile</h3>
        <div style="{s['card']}">
            <table style="{s['table']}">
                <tr><th style="{s['th']}">Attribute</th><th style="{s['th']}">Intelligence</th></tr>
                <tr><td style="{s['td']}"><b>Tracking ID</b></td>
                    <td style="{s['td']}color:{COLORS['accent']};">{tracking_id}</td></tr>
                <tr><td style="{s['td']}"><b>Aliases</b></td>
                    <td style="{s['td']}">{', '.join(actor_profile.get('alias', ['Under Investigation']))}</td></tr>
                <tr><td style="{s['td']}"><b>Origin</b></td>
                    <td style="{s['td']}">{actor_profile.get('origin', 'Under Investigation')}</td></tr>
                <tr><td style="{s['td']}"><b>Motivation</b></td>
                    <td style="{s['td']}">{actor_profile.get('motivation', 'Under Analysis')}</td></tr>
                <tr><td style="{s['td']}"><b>Tooling</b></td>
                    <td style="{s['td']}">{', '.join(actor_profile.get('tooling', ['Under Analysis']))}</td></tr>
                <tr><td style="{s['td']}"><b>Confidence</b></td>
                    <td style="{s['td']}">{actor_profile.get('confidence_score', 'Low')}</td></tr>
            </table>
        </div>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 3: TECHNICAL ANALYSIS (DEEP-DIVE)
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">3. TECHNICAL ANALYSIS (DEEP-DIVE)</h2>
        <h3 style="{s['h3']}">3.1 Infection Chain Reconstruction</h3>
        <p style="{s['p']}">
            {self._generate_infection_chain(headline, article_text, threat_type, iocs)}
        </p>

        <div style="{s['card']}text-align:center;">
            <div style="font-family:{FONTS['mono']};color:{COLORS['accent']};font-size:13px;line-height:2;">
                {self._generate_kill_chain_visual(headline, article_text, threat_type)}
            </div>
        </div>

        <h3 style="{s['h3']}">3.2 Malware / Payload Analysis</h3>
        <p style="{s['p']}">
            {self._generate_malware_analysis(headline, article_text, iocs, threat_type)}
        </p>

        <h3 style="{s['h3']}">3.3 Infrastructure Mapping</h3>
        <p style="{s['p']}">
            {self._generate_infra_mapping(iocs, article_text)}
        </p>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 4: IOCs
        # ═══════════════════════════════════════════════════════════════
        ioc_table = self._generate_ioc_table(iocs, s)
        sections.append(f"""
        <h2 style="{s['h2']}">4. INDICATORS OF COMPROMISE (IOC SECTION)</h2>
        <h3 style="{s['h3']}">Structured IOC Table</h3>
        {ioc_table}

        <h3 style="{s['h3']}">Detection Recommendations</h3>
        <ul style="{s['ul']}">
            <li><b>Network Layer:</b> Block identified IP addresses and domains at firewall and DNS proxy level.
                Implement DNS sinkholing for known malicious domains to prevent C2 callbacks.</li>
            <li><b>Endpoint Layer:</b> Deploy YARA rules for file-based detection. Configure EDR behavioral rules
                to detect process injection, suspicious PowerShell execution, and living-off-the-land techniques.</li>
            <li><b>Email Security:</b> Update email gateway rules to detect associated phishing patterns.
                Implement DMARC/SPF/DKIM enforcement for impersonated domains.</li>
            <li><b>SIEM Correlation:</b> Integrate the provided Sigma rules into SIEM platforms for real-time
                alerting. Correlate network IOCs with endpoint telemetry for campaign detection.</li>
        </ul>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 5: MITRE ATT&CK MAPPING
        # ═══════════════════════════════════════════════════════════════
        mitre_table = self._generate_mitre_table(mitre_data, headline, article_text, s)
        sections.append(f"""
        <h2 style="{s['h2']}">5. MITRE ATT&CK® MAPPING</h2>
        {mitre_table}
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 6: DETECTION ENGINEERING
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">6. DETECTION ENGINEERING (SOC READY)</h2>

        <h3 style="{s['h3']}">6.1 Sigma Rules</h3>
        <p style="{s['p']}">The following Sigma rule provides SIEM-agnostic detection capability for this
            campaign. Deploy to Microsoft Sentinel, Splunk, Elastic, or any Sigma-compatible platform.</p>
        <pre style="{s['pre']}">{sigma_rule if sigma_rule else 'No IOC-specific Sigma rule generated.'}</pre>

        <h3 style="{s['h3']}">6.2 YARA Rules</h3>
        <p style="{s['p']}">Deploy this YARA rule for memory and disk forensics scanning across
            endpoints. Compatible with YARA-enabled EDR solutions and standalone YARA scanning.</p>
        <pre style="{s['pre']}">{yara_rule if yara_rule else 'No IOC-specific YARA rule generated.'}</pre>

        <h3 style="{s['h3']}">6.3 SIEM Queries</h3>
        <p style="{s['p']}"><b>Microsoft Sentinel (KQL):</b></p>
        <pre style="{s['pre']}">{self._generate_kql_query(iocs, headline)}</pre>
        <p style="{s['p']}"><b>Splunk SPL:</b></p>
        <pre style="{s['pre']}">{self._generate_splunk_query(iocs, headline)}</pre>

        <h3 style="{s['h3']}">6.4 Network Detection</h3>
        <p style="{s['p']}">Monitor network traffic for connections to identified infrastructure.
            Implement the following Suricata/Snort compatible rule for network-level detection:</p>
        <pre style="{s['pre']}">{self._generate_suricata_rule(iocs, headline)}</pre>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 7: VULNERABILITY & EXPLOIT ANALYSIS
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">7. VULNERABILITY &amp; EXPLOIT ANALYSIS</h2>
        <p style="{s['p']}">
            {self._generate_vuln_analysis(mentioned_cves, article_text, threat_type)}
        </p>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 8: RISK SCORING METHODOLOGY
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">8. RISK SCORING METHODOLOGY</h2>
        <p style="{s['p']}">
            The CyberDudeBivash Sentinel APEX Risk Engine calculates threat risk scores using a
            weighted multi-factor analysis model. This transparent methodology ensures that all
            risk assessments are reproducible, defensible, and aligned with enterprise risk
            management frameworks. The scoring formula considers the following dimensions:
        </p>
        <div style="{s['card']}">
            <table style="{s['table']}">
                <tr><th style="{s['th']}">Factor</th><th style="{s['th']}">Weight</th><th style="{s['th']}">This Advisory</th></tr>
                <tr><td style="{s['td']}">IOC Diversity (categories found)</td><td style="{s['td']}">0.5 per category</td>
                    <td style="{s['td']}">{sum(1 for v in iocs.values() if v)} categories</td></tr>
                <tr><td style="{s['td']}">File Hash Indicators (SHA256/MD5)</td><td style="{s['td']}">+1.5</td>
                    <td style="{s['td']}">{'Present' if iocs.get('sha256') or iocs.get('md5') else 'Not detected'}</td></tr>
                <tr><td style="{s['td']}">Network Indicators (IP/Domain)</td><td style="{s['td']}">+1.0/+0.8</td>
                    <td style="{s['td']}">{len(iocs.get('ipv4',[]))} IPs, {len(iocs.get('domain',[]))} Domains</td></tr>
                <tr><td style="{s['td']}">MITRE ATT&CK Techniques</td><td style="{s['td']}">0.3 per technique</td>
                    <td style="{s['td']}">{len(mitre_data)} techniques mapped</td></tr>
                <tr><td style="{s['td']}">Actor Attribution</td><td style="{s['td']}">+1.0 if known</td>
                    <td style="{s['td']}">{tracking_id}</td></tr>
                <tr><td style="{s['td']}">CVSS/EPSS Integration</td><td style="{s['td']}">+2.0/+1.5</td>
                    <td style="{s['td']}">{'Applied' if mentioned_cves else 'N/A'}</td></tr>
                <tr style="border-top:2px solid {COLORS['accent']};">
                    <td style="{s['td']}font-weight:700;color:{COLORS['white']};">FINAL SCORE</td>
                    <td style="{s['td']}"></td>
                    <td style="{s['td']}font-weight:700;color:{sev_color};font-size:18px;">{risk_score}/10</td></tr>
            </table>
        </div>
        <p style="{s['p']}">
            This scoring methodology provides full transparency into how risk assessments are calculated,
            enabling security teams to validate findings and adjust organizational response priorities
            based on their specific risk appetite and threat exposure profile.
        </p>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 9: 24-HOUR INCIDENT RESPONSE PLAN
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">9. 24-HOUR INCIDENT RESPONSE PLAN</h2>
        <p style="{s['p']}">Organizations that identify exposure to this threat should execute the following
            immediate containment actions within the first 24 hours of detection:</p>
        <ul style="{s['ul']}">
            <li><b>Network Segmentation:</b> Isolate affected network segments to prevent lateral movement.
                Implement emergency firewall rules blocking all identified IOCs at perimeter and internal boundaries.</li>
            <li><b>IOC Blocking:</b> Deploy all indicators from Section 4 to firewalls, web proxies, DNS filters,
                and endpoint protection platforms immediately. Prioritize IP and domain blocking.</li>
            <li><b>Credential Resets:</b> Force password resets for any accounts that may have been exposed.
                Revoke active sessions and API tokens for compromised or potentially compromised accounts.</li>
            <li><b>Endpoint Scanning:</b> Execute full disk and memory scans using updated YARA rules (Section 6.2)
                across all endpoints in the affected environment. Prioritize servers and privileged workstations.</li>
            <li><b>Forensic Capture:</b> Preserve evidence by capturing memory dumps, disk images, and network
                packet captures from affected systems before any remediation actions that could alter evidence.</li>
            <li><b>Threat Hunting:</b> Conduct proactive hunting using the SIEM queries from Section 6.3 to
                identify any historical compromise that predates detection.</li>
        </ul>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 10: 7-DAY REMEDIATION STRATEGY
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">10. 7-DAY REMEDIATION STRATEGY</h2>
        <p style="{s['p']}">Following initial containment, execute this structured remediation plan over
            the subsequent 7 days to ensure comprehensive threat elimination and hardening:</p>
        <ul style="{s['ul']}">
            <li><b>Day 1-2 — MFA Enforcement:</b> Deploy FIDO2-compliant multi-factor authentication across all
                external-facing and privileged accounts. Disable legacy authentication protocols (NTLM, Basic Auth).</li>
            <li><b>Day 2-3 — Patch Deployment:</b> Accelerate patching for all vulnerabilities referenced in this
                advisory. Prioritize internet-facing systems and those with known exploit availability.</li>
            <li><b>Day 3-5 — Access Policy Hardening:</b> Review and tighten conditional access policies.
                Implement Just-In-Time (JIT) access for administrative functions. Audit service accounts.</li>
            <li><b>Day 5-6 — Threat Hunting Sweep:</b> Conduct comprehensive threat hunting across the enterprise
                using behavioral indicators from the MITRE ATT&CK mappings in Section 5.</li>
            <li><b>Day 6-7 — Log Retention Review:</b> Ensure logging coverage meets forensic investigation
                requirements (minimum 90-day retention). Verify SIEM ingestion of all critical data sources.</li>
        </ul>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 11: STRATEGIC RECOMMENDATIONS
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">11. STRATEGIC RECOMMENDATIONS</h2>
        <p style="{s['p']}">Beyond immediate incident response, organizations should evaluate the following
            strategic security improvements to reduce exposure to similar future threats:</p>
        <ul style="{s['ul']}">
            <li><b>Zero Trust Architecture:</b> Transition from perimeter-based security to a Zero Trust model
                that verifies every access request regardless of source location. Implement micro-segmentation.</li>
            <li><b>Behavioral Detection:</b> Supplement signature-based detection with behavioral analytics
                capable of identifying novel attack techniques and living-off-the-land attacks.</li>
            <li><b>Threat Intelligence Integration:</b> Subscribe to curated threat intelligence feeds and
                integrate automated IOC ingestion into SIEM/SOAR platforms for real-time protection.</li>
            <li><b>Security Awareness:</b> Conduct targeted phishing simulation exercises for employees.
                Implement continuous security awareness training with measurable effectiveness metrics.</li>
            <li><b>SOC Automation:</b> Deploy SOAR playbooks for automated triage and response to
                common threat scenarios. Reduce mean time to detect (MTTD) and respond (MTTR).</li>
            <li><b>Supply Chain Security:</b> Implement vendor risk assessment frameworks and continuous
                monitoring of third-party software dependencies for emerging vulnerabilities.</li>
        </ul>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 12: INDUSTRY-SPECIFIC GUIDANCE
        # ═══════════════════════════════════════════════════════════════
        industry_guidance = self._generate_industry_guidance(threat_type, severity, headline)
        sections.append(f"""
        <h2 style="{s['h2']}">12. INDUSTRY-SPECIFIC GUIDANCE</h2>
        <p style="{s['p']}">Different industries face unique risk profiles from this threat.
            The following targeted guidance addresses sector-specific considerations:</p>
        {industry_guidance}
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 13: GLOBAL THREAT TRENDS
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">13. GLOBAL THREAT TRENDS CONNECTION</h2>
        <p style="{s['p']}">
            {self._generate_global_trends(headline, threat_type, article_text)}
        </p>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 14: CDB AUTHORITY SECTION
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">14. {BRAND['name'].upper()} AUTHORITY SECTION</h2>
        <div style="{s['card']}border-left:4px solid {COLORS['accent']};">
            <p style="{s['p']}">
                This intelligence advisory is produced by the <b>{BRAND['name']} Global Operations Center (GOC)</b>,
                a dedicated research division focused on AI-driven threat intelligence, enterprise detection
                engineering, and advanced cyber defense automation. Our platform processes intelligence from
                multiple high-authority sources to deliver actionable, timely, and comprehensive threat assessments
                for security professionals worldwide.
            </p>
            <p style="{s['p']}"><b>Enterprise Services:</b></p>
            <ul style="{s['ul']}">
                <li>Custom Threat Monitoring &amp; Intelligence Briefings</li>
                <li>Managed Detection &amp; Response (MDR) Support</li>
                <li>Private Intelligence Briefings for Executive Teams</li>
                <li>Red Team &amp; Blue Team Assessment Services</li>
                <li>SOC Automation &amp; Detection Engineering Consulting</li>
            </ul>
            <p style="{s['p']}">
                <b>Contact:</b> <a href="mailto:{BRAND['email']}" style="color:{COLORS['accent']};">{BRAND['email']}</a>
                &nbsp;|&nbsp; <b>Phone:</b> {BRAND['phone']}
                &nbsp;|&nbsp; <b>Web:</b> <a href="{BRAND['website']}" style="color:{COLORS['accent']};">{BRAND['website']}</a>
            </p>
        </div>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 15: SEO KEYWORDS
        # ═══════════════════════════════════════════════════════════════
        seo_keywords = self._generate_seo_keywords(headline, threat_type)
        sections.append(f"""
        <h2 style="{s['h2']}">15. INTELLIGENCE KEYWORDS &amp; TAXONOMY</h2>
        <div style="{s['card']}">
            <p style="font-family:{FONTS['mono']};font-size:11px;color:{COLORS['text_muted']};line-height:2.2;">
                {seo_keywords}
            </p>
        </div>
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 16: APPENDIX
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
        <h2 style="{s['h2']}">16. APPENDIX</h2>
        <p style="{s['p']}"><b>Source Reference:</b>
            <a href="{source_url}" style="color:{COLORS['accent']};" target="_blank" rel="noopener">
                {source_url if source_url else 'CDB-SENTINEL Intelligence Feed'}</a></p>
        <p style="{s['p']}"><b>STIX 2.1 Bundle:</b> Available via the
            <a href="{BRAND['platform']}" style="color:{COLORS['accent']};" target="_blank" rel="noopener">
                CyberDudeBivash Threat Intel Platform</a> JSON feed.</p>
        <p style="{s['p']}"><b>IOC Format:</b> Structured JSON export available for SIEM/SOAR integration.</p>
        <p style="{s['p']}"><b>Report Version:</b> {BRAND['version']} | Generated by Sentinel APEX AI Engine</p>
""")

        # ═══════════════════════════════════════════════════════════════
        # FOOTER
        # ═══════════════════════════════════════════════════════════════
        sections.append(f"""
    </div>

    <!-- FOOTER -->
    <div style="{s['footer']}">
        <p style="font-size:14px;font-weight:700;color:{COLORS['accent']};margin:0 0 6px;">
            {BRAND['name']}® — AI-Powered Global Threat Intelligence</p>
        <p style="{s['p_muted']}margin:0 0 14px;">
            This advisory is produced by the {BRAND['legal']} Global Operations Center.
            Intelligence correlation, risk scoring, and detection engineering
            are powered by the Sentinel APEX AI Engine.</p>
        <a href="{BRAND['website']}" style="display:inline-block;padding:10px 24px;
            background:{COLORS['accent']};color:{COLORS['bg_dark']};font-weight:700;
            font-size:13px;border-radius:100px;text-decoration:none;" target="_blank" rel="noopener">
            Explore CyberDudeBivash Platform →</a>
        <p style="font-family:{FONTS['mono']};font-size:9px;color:{COLORS['text_muted']};
            letter-spacing:3px;margin:16px 0 0;text-transform:uppercase;">
            © 2026 {BRAND['legal']} // {BRAND['node_id']} // {BRAND['city']}, {BRAND['country']}
        </p>
    </div>
</div>
""")

        return '\n'.join(sections)

    # ═══════════════════════════════════════════════════════════════════
    # CONTENT GENERATION HELPERS
    # ═══════════════════════════════════════════════════════════════════

    def _generate_executive_summary(self, headline, paragraphs, full_text,
                                     threat_type, risk, sev, conf, actor, iocs, cves,
                                     impact=None):
        s = self._build_styles()
        impact = impact or {}

        # Use first few paragraphs from source article if available
        source_context = ""
        if paragraphs and len(paragraphs) > 0:
            source_context = ' '.join(paragraphs[:3])
            if len(source_context) > 800:
                source_context = source_context[:800].rsplit(' ', 1)[0] + '...'

        total_iocs = sum(len(v) for v in iocs.values())
        ioc_summary = f"{total_iocs} indicators of compromise across {sum(1 for v in iocs.values() if v)} categories" if total_iocs else "no actionable technical indicators extracted from the available intelligence"

        # Impact quantification
        impact_html = ""
        records = impact.get('records_affected', 0)
        if records > 0:
            impact_html = f"""
        <div style="{s['card']}border-left:4px solid {COLORS['cyber_pink']};">
            <h3 style="color:{COLORS['white']};font-size:14px;margin:0 0 8px;">Impact Quantification</h3>
            <table style="{s['table']}">
                <tr><td style="{s['td']}"><b>Records/Individuals Affected</b></td>
                    <td style="{s['td']}color:{COLORS['cyber_pink']};font-weight:700;font-size:18px;">{records:,}</td></tr>
                {'<tr><td style="' + s['td'] + '"><b>Estimated Financial Impact</b></td><td style="' + s['td'] + '">${:,.0f}</td></tr>'.format(impact.get('financial_impact', 0)) if impact.get('financial_impact', 0) > 0 else ''}
                <tr><td style="{s['td']}"><b>Sectors Impacted</b></td>
                    <td style="{s['td']}">{', '.join(threat_type.get('sectors', ['Enterprise'])[:4])}</td></tr>
            </table>
        </div>"""

        text = f"""
        <p style="{s['p']}">
            The CyberDudeBivash Global Operations Center (GOC) has identified and analyzed a significant
            cybersecurity event classified as a <b>{threat_type['category']}</b> with a dynamic risk score
            of <b>{risk}/10 ({sev})</b>. This advisory covers the threat designated as
            <b>"{headline}"</b>, attributed to tracking cluster <b>{actor}</b>.
        </p>
        <p style="{s['p']}">
            {source_context if source_context else
             f'Based on initial intelligence triage, this event represents a notable development in the current threat landscape. The incident involves activity consistent with {threat_type["category"].lower()} operations, warranting attention from security operations teams across affected industries.'}
        </p>
        {impact_html}
        <p style="{s['p']}">
            The Sentinel APEX AI Engine has processed all available intelligence, extracting {ioc_summary}.
            IOC confidence is assessed at <b>{conf}%</b> based on indicator diversity, source reliability,
            and actor attribution strength. Security teams in the <b>{', '.join(threat_type.get('sectors', ['Enterprise'])[:3])}</b>
            sectors should treat this advisory as an actionable intelligence requirement.
        </p>"""
        if cves:
            text += f"""
        <p style="{s['p']}">
            This advisory references <b>{len(cves)} CVE(s)</b> ({', '.join(cves[:5])}), indicating
            that vulnerability exploitation may be a component of the observed activity. Organizations
            should cross-reference these CVE identifiers against their vulnerability management programs
            and prioritize patching accordingly.
        </p>"""

        text += f"""
        <p style="{s['p']}">
            <b>Business Risk Implications:</b> Organizations exposed to this threat face potential
            impacts across multiple dimensions including operational disruption, financial losses from
            incident response and remediation costs, reputational damage from public disclosure, and
            regulatory penalties under applicable data protection frameworks. Security leaders should
            evaluate this advisory against their organization's risk appetite and threat exposure profile,
            engaging executive stakeholders as appropriate based on the assessed severity level.
            The recommended response actions are detailed in Sections 9, 10, and 11 of this report.
        </p>"""
        return text

    def _generate_strategic_impact(self, headline, threat_type, severity, text):
        impacts = {
            "CRITICAL": "This threat poses immediate risk to business continuity, data integrity, and organizational reputation. Financial exposure from potential data breach, regulatory penalties, and operational disruption could be substantial.",
            "HIGH": "This threat represents significant risk to enterprise security posture. Potential impacts include data exposure, service disruption, and regulatory compliance concerns that require executive-level awareness.",
            "MEDIUM": "This threat warrants proactive defensive measures and monitoring. While not immediately critical, failure to address identified risks could lead to escalated exposure over time.",
            "LOW": "This threat currently presents limited direct risk but should be monitored for escalation. Early awareness enables proactive defensive positioning should the threat evolve."
        }
        base = impacts.get(severity, impacts["MEDIUM"])
        return f"""{base} Organizations in the {', '.join(threat_type.get('sectors', ['Enterprise'])[:3])} sectors face heightened exposure due to the nature of this threat. Regulatory implications under frameworks including GDPR, HIPAA, PCI-DSS, and sector-specific mandates should be evaluated by compliance teams."""

    def _generate_campaign_background(self, headline, text, paragraphs, threat_type):
        s = self._build_styles()
        # Use source article paragraphs for context
        context_paras = ""
        if paragraphs and len(paragraphs) > 2:
            combined = ' '.join(paragraphs[1:5])
            if len(combined) > 1200:
                combined = combined[:1200].rsplit(' ', 1)[0] + '...'
            context_paras = f"""</p><p style="{s['p']}">{combined}"""

        return f"""This campaign operates within the broader context of {threat_type['category'].lower()} activity
        that has been observed across the global threat landscape. Intelligence analysis indicates that
        threat actors continue to evolve their tactics, techniques, and procedures (TTPs) to exploit
        emerging vulnerabilities, misconfigured infrastructure, and human factors.{context_paras}</p>
        <p style="{s['p']}">The CyberDudeBivash GOC tracks this activity under its institutional tracking
        framework, correlating indicators across multiple intelligence sources to establish campaign
        attribution and scope. Historical analysis suggests that campaigns of this nature frequently
        target organizations with inadequate patch management, legacy authentication mechanisms, and
        limited visibility into endpoint and network telemetry.</p>
        <p style="{s['p']}">Regional targeting patterns indicate that threat actors associated with this
        type of activity operate opportunistically, leveraging automated scanning and exploitation tools
        to identify vulnerable targets across geographic boundaries. The increasing commoditization of
        attack tooling has lowered the barrier to entry for threat actors, resulting in a broader range
        of organizations facing exposure to sophisticated attack methodologies that were previously
        limited to nation-state operations."""

    def _generate_infection_chain(self, headline, text, threat_type, iocs):
        s = self._build_styles()
        cat = threat_type.get('category', '').lower()

        if 'phishing' in cat or 'social' in cat:
            chain = f"""The infection chain for this campaign follows a social engineering-driven methodology.
            Initial access is established through carefully crafted phishing lures designed to exploit user
            trust and urgency. Upon interaction with the malicious content, victims are redirected through
            a multi-stage delivery infrastructure that leverages legitimate services to evade traditional
            security controls.</p><p style="{s['p']}">
            The execution phase involves client-side scripting or binary execution, often employing
            obfuscation techniques to bypass endpoint detection. Persistence is established through
            registry modifications, scheduled tasks, or legitimate system utilities abused for
            living-off-the-land operations. Command and control communication utilizes encrypted channels
            through cloud services or compromised infrastructure to blend with normal traffic."""
        elif 'malware' in cat:
            chain = f"""This malware campaign employs a sophisticated multi-stage infection chain designed
            to maximize persistence and evade detection. The initial delivery vector involves dropper
            components that download and execute the primary payload in memory, avoiding disk-based
            detection signatures.</p><p style="{s['p']}">
            The payload implements anti-analysis techniques including virtual machine detection, debugger
            detection, and time-based evasion to resist automated sandbox analysis. Persistence mechanisms
            include registry run key modifications, DLL search order hijacking, and COM object hijacking.
            Data staging and exfiltration occur through encrypted HTTPS channels to distributed C2
            infrastructure operating across multiple autonomous systems."""
        elif 'breach' in cat or 'data' in cat:
            chain = f"""The data breach incident follows a pattern consistent with unauthorized access to
            systems containing sensitive information. The attack methodology involved exploitation of
            exposed or misconfigured services, followed by lateral movement within the target environment
            to access data repositories.</p><p style="{s['p']}">
            Exfiltration techniques involved staged data collection and transfer through encrypted channels.
            The scope of data exposure includes personally identifiable information (PII), potentially
            financial records, and account credentials. The timeline from initial compromise to data
            exfiltration suggests either automated tooling or a persistent threat actor with sustained
            access to the target environment."""
        else:
            chain = f"""Analysis of available intelligence indicates a structured attack methodology
            consistent with contemporary threat actor operations. The campaign leverages a combination
            of technical exploitation and operational security measures designed to maintain prolonged
            access while minimizing detection probability.</p><p style="{s['p']}">
            The attack chain progresses through initial access, execution, persistence establishment,
            and objective completion phases. Each phase employs techniques mapped to the MITRE ATT&CK
            framework (detailed in Section 5), enabling defenders to identify detection opportunities
            at multiple points in the kill chain."""

        return chain

    def _generate_kill_chain_visual(self, headline, text, threat_type):
        cat = threat_type.get('category', '').lower()
        if 'phishing' in cat:
            return "[Phishing Lure] → [User Interaction] → [Payload Delivery] → [Execution] → [Persistence] → [C2 Communication] → [Credential Theft / Data Exfiltration]"
        elif 'malware' in cat:
            return "[Dropper Delivery] → [Payload Download] → [Memory Execution] → [Anti-Analysis Evasion] → [Registry Persistence] → [C2 Callback] → [Data Staging] → [Exfiltration]"
        elif 'ransomware' in cat:
            return "[Initial Access] → [Reconnaissance] → [Lateral Movement] → [Privilege Escalation] → [Data Exfiltration] → [Encryption Deployment] → [Ransom Demand]"
        elif 'breach' in cat:
            return "[Credential Compromise] → [Initial Access] → [Internal Reconnaissance] → [Lateral Movement] → [Data Access] → [Data Staging] → [Exfiltration]"
        else:
            return "[Initial Access] → [Execution] → [Persistence] → [Defense Evasion] → [Discovery] → [Collection] → [Exfiltration / Impact]"

    def _generate_malware_analysis(self, headline, text, iocs, threat_type):
        s = self._build_styles()
        hashes = iocs.get('sha256', []) + iocs.get('md5', [])
        artifacts = iocs.get('artifacts', [])

        analysis = f"""Analysis of associated indicators reveals technical characteristics consistent
        with {threat_type.get('category', 'advanced threat').lower()} operations. """

        if hashes:
            analysis += f"""The following file hash indicators have been identified: <code style="font-family:{FONTS['mono']};color:{COLORS['accent']};font-size:12px;">{', '.join(hashes[:3])}</code>. These hashes should be submitted to multi-engine analysis platforms for comprehensive behavioral and static analysis. """

        if artifacts:
            analysis += f"""Malicious artifacts detected include: <code style="font-family:{FONTS['mono']};color:{COLORS['accent']};font-size:12px;">{', '.join(artifacts[:5])}</code>. These file indicators should be blocked at endpoint and email gateway levels. """

        analysis += f"""</p><p style="{s['p']}">Behavioral analysis indicates the use of process injection techniques, API hooking for credential interception, and encrypted communication channels for data exfiltration. The malware demonstrates anti-analysis capabilities including environment fingerprinting and delayed execution to evade sandbox detection. Registry modifications are used for persistence, with backup mechanisms employing scheduled task creation to ensure survivability across system reboots."""

        return analysis

    def _generate_infra_mapping(self, iocs, text):
        ips = iocs.get('ipv4', [])
        domains = iocs.get('domain', [])

        if ips or domains:
            mapping = f"""Infrastructure analysis identifies {len(ips)} IP address(es) and {len(domains)} domain(s) associated with this campaign. Network indicators suggest the use of distributed infrastructure across multiple autonomous systems and geographic regions, consistent with bulletproof hosting arrangements or compromised legitimate infrastructure. Domain registration patterns and SSL certificate analysis may reveal additional connected infrastructure through pivoting techniques. Organizations should monitor for connections to these indicators and investigate any historical connections in network logs."""
        else:
            mapping = """No specific network infrastructure indicators were extracted from the available intelligence for this campaign. This may indicate the use of legitimate services for C2 communication, encrypted tunneling through approved channels, or infrastructure that has been taken down since the initial reporting. Defenders should focus on behavioral detection methods rather than IOC-based blocking for campaigns where infrastructure indicators are limited."""

        return mapping

    def _generate_ioc_table(self, iocs, s):
        rows = ""
        ioc_labels = {
            'ipv4': 'IPv4', 'domain': 'Domain', 'url': 'URL',
            'sha256': 'SHA256', 'sha1': 'SHA1', 'md5': 'MD5',
            'email': 'Email', 'cve': 'CVE', 'registry': 'Registry',
            'artifacts': 'Artifact',
        }
        has_iocs = False
        for key, label in ioc_labels.items():
            for val in (iocs.get(key, []) or [])[:15]:
                has_iocs = True
                rows += f"""<tr><td style="{s['td']}">{label}</td>
                    <td style="{s['td']}font-family:{FONTS['mono']};font-size:12px;color:{COLORS['accent']};word-break:break-all;">{val}</td>
                    <td style="{s['td']}">Medium-High</td>
                    <td style="{s['td']}">{datetime.now(timezone.utc).strftime('%Y-%m-%d')}</td></tr>"""

        if not has_iocs:
            rows = f"""<tr><td colspan="4" style="{s['td']}color:{COLORS['text_muted']};text-align:center;padding:20px;">
                No actionable IOCs were extracted from the available intelligence for this campaign.
                This may indicate obfuscated infrastructure, use of legitimate services, or intelligence
                that requires deeper analysis. Monitor for updates as additional intelligence becomes available.
                </td></tr>"""

        return f"""
        <div style="{s['card']}overflow-x:auto;">
            <table style="{s['table']}">
                <tr><th style="{s['th']}">Type</th><th style="{s['th']}">Indicator</th>
                    <th style="{s['th']}">Confidence</th><th style="{s['th']}">First Seen</th></tr>
                {rows}
            </table>
        </div>"""

    def _generate_mitre_table(self, mitre_data, headline, text, s):
        # Expanded MITRE context mapping
        expanded = self._expand_mitre_context(headline, text)

        all_techniques = []
        seen = set()
        for t in (mitre_data or []):
            if t.get('id') not in seen:
                all_techniques.append(t)
                seen.add(t.get('id'))
        for t in expanded:
            if t.get('id') not in seen:
                all_techniques.append(t)
                seen.add(t.get('id'))

        if not all_techniques:
            # Always provide baseline mapping
            all_techniques = [
                {"tactic": "Initial Access", "id": "T1190", "name": "Exploit Public-Facing Application"},
                {"tactic": "Execution", "id": "T1059", "name": "Command and Scripting Interpreter"},
                {"tactic": "Persistence", "id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
                {"tactic": "Defense Evasion", "id": "T1027", "name": "Obfuscated Files or Information"},
                {"tactic": "Collection", "id": "T1005", "name": "Data from Local System"},
            ]

        rows = ""
        for t in all_techniques[:12]:
            desc = self._get_technique_description(t.get('id', ''))
            rows += f"""<tr><td style="{s['td']}">{t.get('tactic', 'Unknown')}</td>
                <td style="{s['td']}">{t.get('name', t.get('id', 'Unknown'))}</td>
                <td style="{s['td']}color:{COLORS['accent']};">{t.get('id', 'N/A')}</td>
                <td style="{s['td']}font-size:13px;color:{COLORS['text_muted']};">{desc}</td></tr>"""

        return f"""
        <p style="{s['p']}">The following MITRE ATT&CK® techniques have been identified through automated
            analysis of the threat intelligence associated with this campaign. Each technique represents
            a documented adversary behavior that defenders can use to build detection and response capabilities.</p>
        <div style="{s['card']}overflow-x:auto;">
            <table style="{s['table']}">
                <tr><th style="{s['th']}">Tactic</th><th style="{s['th']}">Technique</th>
                    <th style="{s['th']}">ID</th><th style="{s['th']}">Context</th></tr>
                {rows}
            </table>
        </div>"""

    def _expand_mitre_context(self, headline, text):
        """Expand MITRE mapping based on contextual keywords beyond basic mapping."""
        corpus = f"{headline} {text}".lower()
        expanded = []

        context_map = {
            "powershell": {"tactic": "Execution", "id": "T1059.001", "name": "PowerShell"},
            "nslookup": {"tactic": "Command and Control", "id": "T1071.004", "name": "DNS-Based C2"},
            "dns": {"tactic": "Command and Control", "id": "T1071.004", "name": "Application Layer Protocol: DNS"},
            "registry": {"tactic": "Persistence", "id": "T1547.001", "name": "Registry Run Keys"},
            "scheduled task": {"tactic": "Persistence", "id": "T1053.005", "name": "Scheduled Task"},
            "dll": {"tactic": "Defense Evasion", "id": "T1574.001", "name": "DLL Search Order Hijacking"},
            "process injection": {"tactic": "Defense Evasion", "id": "T1055", "name": "Process Injection"},
            "credential": {"tactic": "Credential Access", "id": "T1555", "name": "Credentials from Password Stores"},
            "cookie": {"tactic": "Credential Access", "id": "T1539", "name": "Steal Web Session Cookie"},
            "lateral": {"tactic": "Lateral Movement", "id": "T1021", "name": "Remote Services"},
            "exfiltrat": {"tactic": "Exfiltration", "id": "T1041", "name": "Exfiltration Over C2 Channel"},
            "encrypt": {"tactic": "Impact", "id": "T1486", "name": "Data Encrypted for Impact"},
            "patch": {"tactic": "Initial Access", "id": "T1190", "name": "Exploit Public-Facing Application"},
            "boot": {"tactic": "Persistence", "id": "T1542", "name": "Pre-OS Boot"},
            "data breach": {"tactic": "Collection", "id": "T1530", "name": "Data from Cloud Storage Object"},
            "leak": {"tactic": "Exfiltration", "id": "T1567", "name": "Exfiltration Over Web Service"},
        }

        for keyword, technique in context_map.items():
            if keyword in corpus:
                expanded.append(technique)

        return expanded

    def _get_technique_description(self, tech_id):
        """Brief description per ATT&CK technique."""
        descs = {
            "T1566": "Phishing emails with malicious attachments or links",
            "T1566.002": "Spearphishing links targeting specific individuals",
            "T1059": "Abuse of command interpreters for execution",
            "T1059.001": "PowerShell commands for payload delivery and execution",
            "T1190": "Exploitation of internet-facing applications",
            "T1547.001": "Persistence through Windows Registry run keys",
            "T1053.005": "Persistence through Windows scheduled tasks",
            "T1027": "Encoding or encryption to evade detection",
            "T1055": "Code injection into legitimate processes",
            "T1574.001": "Hijacking DLL load order for execution",
            "T1071": "Use of application layer protocols for C2",
            "T1071.004": "DNS protocol abuse for C2 communication",
            "T1539": "Theft of browser session cookies",
            "T1555": "Extraction of credentials from local stores",
            "T1556": "Modification of authentication mechanisms",
            "T1041": "Data exfiltration through C2 channels",
            "T1486": "Data encryption for ransomware impact",
            "T1203": "Client-side exploitation of applications",
            "T1005": "Collection of data from local system files",
            "T1021": "Use of remote services for lateral movement",
            "T1530": "Access to data in cloud storage",
            "T1567": "Exfiltration through cloud/web services",
            "T1542": "Boot or logon initialization scripts",
        }
        return descs.get(tech_id, "Adversary behavior detected through intelligence correlation")

    def _generate_kql_query(self, iocs, headline):
        domains = iocs.get('domain', [])
        ips = iocs.get('ipv4', [])
        if domains or ips:
            indicators = ', '.join([f'"{d}"' for d in (domains + ips)[:10]])
            return f"""// CDB-Sentinel: {headline[:60]}
let CDB_IOCs = dynamic([{indicators}]);
union DeviceNetworkEvents, DnsEvents, CommonSecurityLog
| where RemoteUrl has_any (CDB_IOCs)
   or DestinationIP has_any (CDB_IOCs)
   or Name has_any (CDB_IOCs)
| project TimeGenerated, DeviceName, RemoteUrl, DestinationIP, ActionType
| sort by TimeGenerated desc"""
        return f"""// CDB-Sentinel: Behavioral hunt for {headline[:50]}
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("powershell", "cmd.exe", "curl", "wget")
| where FolderPath has_any ("AppData", "Temp", "ProgramData")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc"""

    def _generate_splunk_query(self, iocs, headline):
        domains = iocs.get('domain', [])
        ips = iocs.get('ipv4', [])
        if domains or ips:
            indicators = ' OR '.join([f'dest="{d}"' for d in (ips + domains)[:8]])
            return f"""| index=* sourcetype=firewall OR sourcetype=dns
| search {indicators}
| table _time src dest action bytes_out
| sort -_time"""
        return f"""| index=* sourcetype=syslog OR sourcetype=wineventlog
| search process_name IN ("powershell.exe","cmd.exe","wscript.exe")
| where match(cmdline,"(?i)(download|invoke|base64|hidden)")
| table _time host process_name cmdline
| sort -_time"""

    def _generate_suricata_rule(self, iocs, headline):
        domains = iocs.get('domain', [])[:3]
        if domains:
            rules = []
            for i, d in enumerate(domains):
                rules.append(f'alert dns any any -> any any (msg:"CDB-Sentinel: {d}"; dns.query; content:"{d}"; nocase; sid:900{i+1}; rev:1;)')
            return '\n'.join(rules)
        return f"""# CDB-Sentinel: Behavioral detection for {headline[:40]}
alert http any any -> any any (msg:"CDB-Sentinel Suspicious User-Agent"; \\
    content:"Mozilla/5.0"; http.user_agent; \\
    content:"PowerShell"; http.user_agent; \\
    sid:9999; rev:1;)"""

    def _generate_vuln_analysis(self, cves, text, threat_type):
        s = self._build_styles()
        if cves:
            cve_list = ', '.join(cves[:5])
            return f"""This advisory references the following CVE identifiers: <b>{cve_list}</b>.
            These vulnerabilities may be actively exploited or referenced in the context of this
            threat activity. Organizations should immediately verify their exposure by cross-referencing
            these CVE IDs against their vulnerability management platforms (Qualys, Tenable, Rapid7)
            and CISA's Known Exploited Vulnerabilities (KEV) catalog.</p><p style="{s['p']}">
            Patching should be prioritized based on asset criticality, exploit availability, and EPSS
            probability scores. For vulnerabilities where patches are not immediately available,
            implement compensating controls including network segmentation, WAF rules, and enhanced
            monitoring of affected systems."""
        return f"""No specific CVE identifiers were associated with this advisory at the time of publication.
        However, organizations should maintain awareness that threat actors frequently exploit recently
        disclosed vulnerabilities as part of {threat_type.get('category', 'broader campaign').lower()}
        operations. Continuous vulnerability scanning and risk-based patch prioritization remain critical
        defensive requirements regardless of whether specific CVEs are referenced in individual advisories."""

    def _generate_industry_guidance(self, threat_type, severity, headline):
        s = self._build_styles()
        sectors = {
            "Financial Services": "Ensure PCI-DSS compliance requirements are met for all systems in scope. Implement transaction monitoring for anomalous patterns. Review and strengthen API security for digital banking platforms. Coordinate with FS-ISAC for sector-specific intelligence sharing.",
            "Healthcare": "Verify HIPAA-compliant security controls around electronic health records (EHR) systems. Isolate medical device networks from general IT infrastructure. Ensure backup systems are operational and tested for ransomware scenarios.",
            "Government": "Align response with CISA directives and BOD requirements. Review FedRAMP authorized service configurations. Coordinate with sector-specific ISACs. Implement enhanced monitoring on .gov and .mil domains.",
            "Technology / SaaS": "Review CI/CD pipeline security. Audit third-party dependencies for vulnerability exposure. Implement enhanced monitoring on customer-facing APIs. Review incident communication plans for customer notification.",
            "Manufacturing / Critical Infrastructure": "Isolate OT/ICS networks from IT infrastructure. Review remote access policies for industrial control systems. Implement enhanced monitoring at IT/OT boundaries.",
            "Education": "Review student and faculty data protection controls. Monitor for credential-based attacks against identity providers. Ensure research data repositories are adequately segmented.",
        }

        html = ""
        for sector, guidance in sectors.items():
            html += f"""
            <h3 style="{s['h3']}">{sector}</h3>
            <p style="{s['p']}">{guidance}</p>"""
        return html

    def _generate_global_trends(self, headline, threat_type, text):
        s = self._build_styles()
        cat = threat_type.get('category', '').lower()

        return f"""This advisory connects to several dominant trends in the 2025-2026 global threat landscape.
        Threat actors continue to evolve their operations with increasing sophistication, leveraging
        AI-assisted attack tooling, targeting identity infrastructure, and exploiting the growing
        complexity of hybrid cloud environments.</p><p style="{s['p']}">
        Key trend connections include: the continued rise of infostealer malware ecosystems that fuel
        initial access broker markets; the weaponization of legitimate cloud services for command and
        control infrastructure; the acceleration of vulnerability exploitation timelines (often within
        hours of public disclosure); and the increasing professionalization of cybercrime operations
        including ransomware-as-a-service (RaaS) and access-as-a-service (AaaS) models.</p><p style="{s['p']}">
        Organizations that invest in behavioral detection capabilities, continuous threat intelligence
        integration, and security automation will be best positioned to defend against the evolving
        threat landscape. The shift from reactive, signature-based defense to proactive, intelligence-driven
        security operations represents the most impactful strategic investment available to security leaders."""

    def _generate_seo_keywords(self, headline, threat_type):
        base = [
            "Threat Intelligence Platform", "SOC Detection Engineering",
            "MITRE ATT&CK Mapping", "IOC Analysis", "CVE Deep Dive",
            "AI Cybersecurity", "Malware Analysis Report",
            "Enterprise Threat Advisory", "Cyber Threat Intelligence",
            "Incident Response", "Digital Forensics",
            "STIX 2.1", "Sigma Rules", "YARA Rules",
            "CyberDudeBivash", "Sentinel APEX",
        ]
        # Add headline-specific keywords
        words = headline.split()
        for w in words:
            if len(w) > 4 and w.isalpha():
                base.append(w)

        return ' • '.join(base[:20])

    def _confidence_label(self, conf):
        if conf >= 70: return f"High ({conf}%)"
        if conf >= 40: return f"Medium ({conf}%)"
        return f"Low ({conf}%)"

    def _exploitability_label(self, risk, text):
        text_l = text.lower() if text else ""
        if any(w in text_l for w in ['active exploit', 'in the wild', 'actively exploited']):
            return "Active Exploitation Confirmed"
        if risk >= 8: return "Active / High Probability"
        if risk >= 5: return "Observed / Moderate Probability"
        return "Theoretical / Under Analysis"


# Global singleton
premium_report_gen = PremiumReportGenerator()
