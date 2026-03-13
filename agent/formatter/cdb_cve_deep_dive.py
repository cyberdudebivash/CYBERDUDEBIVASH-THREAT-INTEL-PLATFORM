"""
CyberDudeBivash CVE Deep-Dive Formatter v4.0
Generates authority-grade, inline-styled CVE intelligence reports.
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

from datetime import datetime, timezone
from typing import Dict

from agent.config import BRAND, COLORS, FONTS


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sev_color(sev: str) -> str:
    return {"CRITICAL": COLORS["critical"], "HIGH": COLORS["high"],
            "MEDIUM": COLORS["medium"]}.get(sev.upper(), COLORS["text_muted"])


_s = {
    "h2": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:22px;font-weight:700;margin:28px 0 10px;padding-bottom:8px;border-bottom:2px solid {COLORS['border']};",
    "h3": f"font-family:{FONTS['heading']};color:{COLORS['accent']};font-size:17px;font-weight:600;margin:20px 0 6px;padding-left:10px;border-left:3px solid {COLORS['accent']};",
    "p": f"margin:0 0 14px;color:{COLORS['text']};line-height:1.8;font-size:16px;",
    "card": f"background:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:10px;padding:20px;margin:16px 0;",
    "badge": f"display:inline-block;padding:3px 10px;border-radius:100px;font-size:11px;font-weight:700;text-transform:uppercase;",
    "muted": f"color:{COLORS['text_muted']};font-size:13px;",
    "link": f"color:{COLORS['accent']};text-decoration:none;font-weight:600;",
    "cta": f"display:inline-block;padding:10px 24px;background:{COLORS['accent']};color:{COLORS['bg_dark']};font-weight:700;font-size:14px;border-radius:100px;text-decoration:none;",
    "td": f"padding:8px 14px;border-bottom:1px solid {COLORS['border']};color:{COLORS['text']};font-size:15px;",
    "th": f"background:{COLORS['bg_dark']};color:{COLORS['white']};font-weight:600;text-align:left;padding:8px 14px;font-size:12px;text-transform:uppercase;",
}


def format_cve_deep_dive(
    cve: Dict,
    author: str = "CyberDudeBivash Threat Intelligence Team",
    site_url: str = "",
) -> str:
    cve_id = cve.get("id", "Unknown CVE")
    severity = (cve.get("severity") or "Unknown").upper()
    cvss = cve.get("cvss", "N/A")
    epss = round(float(cve.get("epss") or 0.0), 3)
    desc = cve.get("description", "No description available.")
    trend = cve.get("epss_trend", "STABLE")
    accel = cve.get("epss_acceleration", "STABLE")
    sc = _sev_color(severity)
    site_url = site_url or BRAND["website"]

    return f"""
<div style="{_s['card']}border-left:4px solid {sc};">
  <h2 style="font-family:{FONTS['heading']};color:{COLORS['white']};font-size:24px;font-weight:800;margin:0 0 8px;">{cve_id} — Cyber Threat Intelligence Deep Dive</h2>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;">
    <span style="{_s['badge']}background:rgba({','.join(str(int(sc[i:i+2],16)) for i in (1,3,5))},0.15);color:{sc};">⚡ {severity}</span>
    <span style="{_s['badge']}background:rgba(0,212,170,0.1);color:{COLORS['accent']};">CVSS {cvss}</span>
    <span style="{_s['badge']}background:rgba(59,130,246,0.1);color:{COLORS['cyber_blue']};">EPSS {epss}</span>
  </div>
  <p style="{_s['muted']}">
    <strong>Published:</strong> {_utc_now()} &nbsp;|&nbsp;
    <strong>Author:</strong> {author} &nbsp;|&nbsp;
    <strong>EPSS Trend:</strong> {trend} &nbsp;|&nbsp;
    <strong>Acceleration:</strong> {accel}
  </p>
</div>

<h2 style="{_s['h2']}">Executive Threat Summary</h2>
<p style="{_s['p']}">
<strong>{cve_id}</strong> represents a vulnerability with significant operational relevance.
Based on its {severity} severity classification, EPSS exploitation probability of {epss},
and real-world threat actor behavior patterns, this issue should be treated as a
high-priority security concern for all affected organizations.
</p>
<p style="{_s['p']}">
Threat actors increasingly weaponize vulnerabilities of this nature to gain initial
access, establish persistence, and deploy follow-on payloads including credential
harvesters, backdoors, and ransomware — often within hours of public disclosure.
</p>

<h2 style="{_s['h2']}">Vulnerability Overview</h2>
<p style="{_s['p']}">{desc}</p>
<p style="{_s['p']}">
The affected components are commonly deployed across enterprise, cloud, and hybrid
environments, increasing the likelihood of broad exposure and exploitation at scale.
</p>

<h3 style="{_s['h3']}">Risk Summary</h3>
<div style="{_s['card']}">
  <table style="width:100%;border-collapse:collapse;">
    <tr><th style="{_s['th']}">Metric</th><th style="{_s['th']}">Value</th></tr>
    <tr><td style="{_s['td']}"><strong>CVE ID</strong></td><td style="{_s['td']}">{cve_id}</td></tr>
    <tr><td style="{_s['td']}"><strong>Severity</strong></td><td style="{_s['td']}color:{sc};font-weight:700;">{severity}</td></tr>
    <tr><td style="{_s['td']}"><strong>CVSS Score</strong></td><td style="{_s['td']}">{cvss}</td></tr>
    <tr><td style="{_s['td']}"><strong>EPSS Probability</strong></td><td style="{_s['td']}">{epss}</td></tr>
    <tr><td style="{_s['td']}"><strong>EPSS 7-Day Trend</strong></td><td style="{_s['td']}">{trend}</td></tr>
    <tr><td style="{_s['td']}"><strong>24h Acceleration</strong></td><td style="{_s['td']}">{accel}</td></tr>
  </table>
</div>

<h2 style="{_s['h2']}">Technical Root Cause Analysis</h2>
<p style="{_s['p']}">
At a technical level, this vulnerability stems from insufficient validation,
improper boundary enforcement, or flawed trust assumptions within the affected
code path. Exploitation enables attackers to manipulate execution flow or system
state beyond intended constraints — bypassing authorization controls, achieving
code execution, or exfiltrating sensitive data.
</p>

<h2 style="{_s['h2']}">Exploitation &amp; Threat Actor Interest</h2>
<p style="{_s['p']}">
The EPSS score of <strong>{epss}</strong> indicates measurable probability of
exploitation in the wild. Vulnerabilities with similar characteristics are
rapidly weaponized following public disclosure. Both opportunistic attackers
and advanced persistent threat groups may leverage this issue as part of
broader intrusion campaigns.
</p>

<h2 style="{_s['h2']}">MITRE ATT&amp;CK Context</h2>
<p style="{_s['p']}">
Exploitation may enable multiple ATT&CK tactics including Initial Access (T1190),
Execution (T1059), Privilege Escalation (T1068), and Persistence (T1078).
Adversaries frequently chain such vulnerabilities with living-off-the-land
techniques to evade detection and maintain long-term access.
</p>

<h2 style="{_s['h2']}">Detection &amp; Monitoring Guidance</h2>
<p style="{_s['p']}">
Defenders should monitor for anomalous process execution, unexpected network
connections, and deviations from established baselines associated with the
affected software. Behavioral detections are critical where exploit signatures
may not yet exist. Deploy Sigma rules and KQL queries targeting the specific
attack surface.
</p>

<h2 style="{_s['h2']}">Mitigation &amp; Remediation</h2>
<p style="{_s['p']}">
Organizations should apply vendor-provided patches immediately. If patching is
not feasible within 24–48 hours, implement compensating controls: network
segmentation, WAF rules, access restrictions, and enhanced monitoring. Verify
remediation through vulnerability scanning and penetration testing.
</p>

<h2 style="{_s['h2']}">CyberDudeBivash Intelligence Assessment</h2>
<div style="{_s['card']}text-align:center;border-color:rgba(0,212,170,0.2);">
  <p style="font-size:17px;font-weight:700;color:{COLORS['accent']};margin:0 0 6px;">
    CyberDudeBivash assesses {cve_id} as requiring immediate attention.
  </p>
  <p style="{_s['muted']}margin:0 0 14px;">
    Based on exploitation potential, affected software prevalence, and relevance
    to modern attack campaigns, this vulnerability poses real-world risk.
  </p>
  <a href="{site_url}" style="{_s['cta']}" target="_blank" rel="noopener">Explore CyberDudeBivash Platform →</a>
  <p style="{_s['muted']}margin:12px 0 0;">
    © 2026 {BRAND['legal']} — {BRAND['city']}, {BRAND['country']}
  </p>
</div>
"""
