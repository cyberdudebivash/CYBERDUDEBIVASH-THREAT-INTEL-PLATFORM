"""
CyberDudeBivash Authority CVE Deep-Dive Formatter
FINAL • PRODUCTION • LONG-FORM INTELLIGENCE

Purpose:
Generate standalone, authority-grade CVE intelligence reports
suitable for executive, SOC, and research audiences.
"""

from datetime import datetime, timezone
from typing import Dict


# =================================================
# TIME UTILITY
# =================================================

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# =================================================
# MAIN FORMATTER
# =================================================

def format_cve_deep_dive(
    cve: Dict,
    author: str = "CyberDudeBivash Threat Intelligence Team",
    site_url: str = "",
) -> str:
    """
    Generate a long-form CVE deep-dive report (5k+ chars).
    """

    cve_id = cve.get("id", "Unknown CVE")
    severity = cve.get("severity", "Unknown")
    cvss = cve.get("cvss", "N/A")
    epss = round(float(cve.get("epss") or 0.0), 3)
    description = cve.get("description", "No description available.")

    sections = []

    # -------------------------------------------------
    # HEADER
    # -------------------------------------------------
    sections.append(f"""
<h2>{cve_id} — Cyber Threat Intelligence Deep Dive</h2>
<p>
<strong>Severity:</strong> {severity}<br>
<strong>CVSS Score:</strong> {cvss}<br>
<strong>EPSS Probability:</strong> {epss}<br>
<strong>Published:</strong> {_utc_now()}<br>
<strong>Author:</strong> {author}
</p>
""")

    # -------------------------------------------------
    # EXECUTIVE THREAT SUMMARY
    # -------------------------------------------------
    sections.append(f"""
<h3>Executive Threat Summary</h3>
<p>
{cve_id} represents a vulnerability with significant operational relevance.
Based on severity classification, exploitation probability metrics, and
real-world threat actor behavior, this issue should be considered a
high-priority security concern for affected organizations.
</p>
<p>
Threat actors increasingly leverage vulnerabilities of this nature to gain
initial access, establish persistence, and deploy follow-on payloads such as
credential harvesters, backdoors, and ransomware.
</p>
""")

    # -------------------------------------------------
    # VULNERABILITY OVERVIEW
    # -------------------------------------------------
    sections.append(f"""
<h3>Vulnerability Overview</h3>
<p>
<strong>{cve_id}</strong> is described as follows:
</p>
<p>
{description}
</p>
<p>
The affected components are commonly deployed across enterprise and cloud
environments, increasing the likelihood of broad exposure.
</p>
""")

    # -------------------------------------------------
    # TECHNICAL ROOT CAUSE ANALYSIS
    # -------------------------------------------------
    sections.append("""
<h3>Technical Root Cause Analysis</h3>
<p>
At a technical level, this vulnerability stems from insufficient validation,
improper boundary enforcement, or flawed trust assumptions within the affected
code path. Exploitation allows attackers to manipulate execution flow or system
state beyond intended constraints.
</p>
<p>
Such weaknesses frequently arise in complex, network-exposed services where
error handling, authentication, or input sanitization is incomplete.
</p>
""")

    # -------------------------------------------------
    # EXPLOITATION & THREAT ACTOR INTEREST
    # -------------------------------------------------
    sections.append(f"""
<h3>Exploitation & Threat Actor Interest</h3>
<p>
The EPSS score of <strong>{epss}</strong> indicates a measurable probability of
exploitation in the wild. Vulnerabilities with similar characteristics are often
rapidly weaponized following public disclosure.
</p>
<p>
Both opportunistic attackers and advanced threat actors may leverage this issue
as part of broader intrusion campaigns.
</p>
""")

    # -------------------------------------------------
    # MITRE ATT&CK CONTEXT
    # -------------------------------------------------
    sections.append("""
<h3>MITRE ATT&CK Context</h3>
<p>
Exploitation of this vulnerability may enable multiple ATT&CK tactics,
including Initial Access, Execution, Privilege Escalation, and Persistence.
Attackers frequently chain such vulnerabilities with living-off-the-land
techniques to evade detection.
</p>
""")

    # -------------------------------------------------
    # ATTACK SCENARIOS & IMPACT
    # -------------------------------------------------
    sections.append("""
<h3>Attack Scenarios & Impact</h3>
<p>
In realistic scenarios, adversaries may exploit this vulnerability to gain
remote access to exposed systems. Once access is established, attackers can
deploy additional tooling, exfiltrate sensitive data, or disrupt operations.
</p>
<p>
Potential business impact includes data breaches, ransomware deployment,
operational downtime, and regulatory exposure.
</p>
""")

    # -------------------------------------------------
    # DETECTION & MONITORING
    # -------------------------------------------------
    sections.append("""
<h3>Detection & Monitoring Guidance</h3>
<p>
Defenders should monitor for anomalous process execution, unexpected network
connections, and deviations from established baselines associated with the
affected software. Behavioral detections are critical where exploit signatures
may not yet exist.
</p>
""")

    # -------------------------------------------------
    # MITIGATION & REMEDIATION
    # -------------------------------------------------
    sections.append("""
<h3>Mitigation & Remediation</h3>
<p>
Organizations should apply vendor-provided patches or mitigations immediately.
If patching is not feasible, compensating controls such as network segmentation,
access restrictions, and enhanced monitoring should be implemented.
</p>
""")

    # -------------------------------------------------
    # STRATEGIC SECURITY IMPLICATIONS
    # -------------------------------------------------
    sections.append("""
<h3>Strategic Security Implications</h3>
<p>
This vulnerability underscores the persistent challenges of secure software
development and vulnerability management. Proactive threat modeling, continuous
patching, and detection engineering remain critical to reducing enterprise risk.
</p>
""")

    # -------------------------------------------------
    # CYBERDUDEBIVASH ASSESSMENT
    # -------------------------------------------------
    sections.append(f"""
<h3>CyberDudeBivash Intelligence Assessment</h3>
<p>
CyberDudeBivash assesses <strong>{cve_id}</strong> as a vulnerability that warrants
immediate attention based on its exploitation potential and relevance to modern
attack campaigns.
</p>
<p>
For more threat intelligence, tools, and research, visit:
<a href="{site_url}">{site_url}</a>
</p>
""")

    return "\n".join(sections)
