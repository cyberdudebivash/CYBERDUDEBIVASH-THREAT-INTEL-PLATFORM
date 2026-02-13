"""
CyberDudeBivash Authority Threat Intelligence Formatter v4.0
Generates professional, inline-styled daily threat reports.

Interface-hardened: All parameters optional. Never breaks pipelines.
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from agent.config import BRAND, BLOGS, COLORS, FONTS


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sev_color(sev: str) -> str:
    return {"CRITICAL": COLORS["critical"], "HIGH": COLORS["high"],
            "MEDIUM": COLORS["medium"]}.get(sev, COLORS["text_muted"])


# Inline style shortcuts
_s = {
    "h2": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:22px;font-weight:700;margin:28px 0 10px;padding-bottom:8px;border-bottom:2px solid {COLORS['border']};",
    "h3": f"font-family:{FONTS['heading']};color:{COLORS['accent']};font-size:17px;font-weight:600;margin:20px 0 6px;padding-left:10px;border-left:3px solid {COLORS['accent']};",
    "h4": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:16px;font-weight:600;margin:16px 0 4px;",
    "p": f"margin:0 0 14px;color:{COLORS['text']};line-height:1.8;font-size:16px;",
    "card": f"background:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:10px;padding:20px;margin:16px 0;",
    "badge": f"display:inline-block;padding:3px 10px;border-radius:100px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;",
    "muted": f"color:{COLORS['text_muted']};font-size:13px;",
    "link": f"color:{COLORS['accent']};text-decoration:none;font-weight:600;",
    "cta": f"display:inline-block;padding:10px 24px;background:{COLORS['accent']};color:{COLORS['bg_dark']};font-weight:700;font-size:14px;border-radius:100px;text-decoration:none;",
}


def format_daily_report(
    cves: Optional[List[Dict]] = None,
    kev_items: Optional[List[Dict]] = None,
    malware_items: Optional[List[Dict]] = None,
    coverage_gaps: Optional[List[Dict]] = None,
    author: str = "CyberDudeBivash Threat Intelligence Team",
    site_url: str = "",
    **_: Any,
) -> str:
    cves = cves or []
    kev_items = kev_items or []
    malware_items = malware_items or []
    coverage_gaps = coverage_gaps or []
    site_url = site_url or BRAND["website"]
    sections: List[str] = []

    # ── HEADER ──
    sections.append(f"""
<div style="{_s['card']}border-left:4px solid {COLORS['accent']};">
  <h2 style="font-family:{FONTS['heading']};color:{COLORS['white']};font-size:24px;font-weight:800;margin:0 0 8px;">
    Daily Cyber Threat Intelligence Report
  </h2>
  <p style="{_s['muted']}">
    <strong>Published:</strong> {_utc_now()} &nbsp;|&nbsp;
    <strong>Prepared By:</strong> {author} &nbsp;|&nbsp;
    <strong>Classification:</strong> TLP:CLEAR
  </p>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;">
    <span style="{_s['badge']}background:rgba(0,212,170,0.12);color:{COLORS['accent']};">📊 {len(cves)} CVEs</span>
    <span style="{_s['badge']}background:rgba(220,38,38,0.12);color:{COLORS['critical']};">🔴 {len(kev_items)} KEVs</span>
    <span style="{_s['badge']}background:rgba(139,92,246,0.12);color:{COLORS['cyber_purple']};">🧬 {len(malware_items)} Malware</span>
    <span style="{_s['badge']}background:rgba(59,130,246,0.12);color:{COLORS['cyber_blue']};">🎯 {len(coverage_gaps)} Gaps</span>
  </div>
</div>
""")

    # ── EXECUTIVE SUMMARY ──
    sections.append(f"""
<h2 style="{_s['h2']}">Executive Intelligence Summary</h2>
<p style="{_s['p']}">
This report provides a high-confidence assessment of the current cyber threat
landscape based on {len(cves)} newly disclosed vulnerabilities,
{len(kev_items)} confirmed actively-exploited CVEs, and {len(malware_items)}
observed malware campaigns. The intelligence reflects sustained attacker focus
on exploiting operational weaknesses, delayed patch cycles, and internet-facing
services.
</p>
<p style="{_s['p']}">
<strong>Security leaders should treat every finding in this advisory as
immediately relevant to enterprise risk management.</strong>
</p>
""")

    # ── CISA KEV ──
    sections.append(f'<h2 style="{_s["h2"]}">Known Exploited Vulnerabilities (CISA KEV)</h2>')
    if kev_items:
        for kev in kev_items[:10]:
            cve_id = kev.get("cveID", "Unknown")
            sections.append(f"""
<div style="{_s['card']}border-left:4px solid {COLORS['critical']};">
  <h4 style="{_s['h4']}">{cve_id}</h4>
  <p style="{_s['muted']}margin-bottom:6px;">
    <strong>Vendor:</strong> {kev.get('vendorProject', 'Unknown')} &nbsp;|&nbsp;
    <strong>Product:</strong> {kev.get('product', 'Unknown')} &nbsp;|&nbsp;
    <span style="color:{COLORS['critical']};font-weight:700;">⚡ Actively Exploited</span>
  </p>
  <p style="{_s['p']}">
    Confirmed exploitation by real-world threat actors. Unpatched systems
    remain at immediate risk of compromise. Remediation deadline:
    <strong>{kev.get('dueDate', 'ASAP')}</strong>.
  </p>
</div>""")
    else:
        sections.append(f"""
<p style="{_s['p']}">
No newly added CISA KEVs were identified during this reporting window.
Previously cataloged KEVs remain relevant and should continue to be prioritized.
</p>""")

    # ── CVEs ──
    sections.append(f'<h2 style="{_s["h2"]}">Critical &amp; High-Risk Vulnerabilities</h2>')
    if cves:
        for cve in cves[:15]:
            sev = cve.get("severity", "Unknown")
            sc = _sev_color(sev)
            epss = round(float(cve.get("epss", 0)), 3)
            trend = cve.get("epss_trend", "STABLE")
            sections.append(f"""
<div style="{_s['card']}border-left:4px solid {sc};">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
    <span style="{_s['badge']}background:rgba({','.join(str(int(sc[i:i+2],16)) for i in (1,3,5))},0.15);color:{sc};">{sev}</span>
    <strong style="color:{COLORS['white']};font-size:16px;">{cve.get('id', 'N/A')}</strong>
  </div>
  <p style="{_s['muted']}margin-bottom:6px;">
    <strong>CVSS:</strong> {cve.get('cvss', 'N/A')} &nbsp;|&nbsp;
    <strong>EPSS:</strong> {epss} &nbsp;|&nbsp;
    <strong>Trend:</strong> {trend}
  </p>
  <p style="{_s['p']}">
    {(cve.get('description', '')[:300] + '...') if len(cve.get('description', '')) > 300 else cve.get('description', 'No description available.')}
  </p>
</div>""")
    else:
        sections.append(f'<p style="{_s["p"]}">No newly disclosed high-impact CVEs during this window.</p>')

    # ── MALWARE ──
    sections.append(f'<h2 style="{_s["h2"]}">Malware &amp; Campaign Activity</h2>')
    if malware_items:
        for m in malware_items[:8]:
            sections.append(f"""
<div style="{_s['card']}">
  <strong style="color:{COLORS['white']};">{m.get('family', 'Unknown')}</strong>
  <span style="{_s['badge']}background:rgba(234,88,12,0.12);color:{COLORS['high']};margin-left:8px;">{m.get('severity', 'HIGH')}</span>
  <p style="{_s['p']}margin-top:6px;">
    Active malware exhibiting stealthy execution, C2 communication, and
    post-exploitation behavior. SHA256: <code style="font-family:{FONTS['mono']};font-size:12px;color:{COLORS['accent']};">{m.get('sha256', 'N/A')[:24]}...</code>
  </p>
</div>""")
    else:
        sections.append(f'<p style="{_s["p"]}">No confirmed malware samples retrieved during this window.</p>')

    # ── COVERAGE GAPS ──
    sections.append(f'<h2 style="{_s["h2"]}">MITRE ATT&amp;CK Coverage Gaps</h2>')
    if coverage_gaps:
        for gap in coverage_gaps:
            gs = gap.get("gap_severity", "MEDIUM")
            gc = _sev_color(gs)
            sections.append(f"""
<div style="{_s['card']}border-left:4px solid {gc};">
  <strong style="color:{COLORS['white']};">{gap.get('technique_id')} — {gap.get('technique_name')}</strong>
  <span style="{_s['badge']}background:rgba({','.join(str(int(gc[i:i+2],16)) for i in (1,3,5))},0.12);color:{gc};margin-left:8px;">{gs}</span>
  <p style="{_s['p']}margin-top:6px;">
    Tactic: {gap.get('tactic', 'Unknown')} — Defensive blind spot enabling
    undetected adversary progression. <strong>Action: {gap.get('recommended_action', 'DETECTION REQUIRED')}</strong>
  </p>
</div>""")
    else:
        sections.append(f'<p style="{_s["p"]}">No immediate ATT&CK coverage gaps identified.</p>')

    # ── STRATEGIC TAKEAWAYS ──
    sections.append(f"""
<h2 style="{_s['h2']}">Strategic Security Takeaways</h2>
<p style="{_s['p']}">
Continued exploitation of known vulnerabilities underscores the importance of
disciplined patch management, behavior-based detection, and threat-informed
defensive strategies. Organizations relying on perimeter-only defenses are
operating at unacceptable risk levels in the current threat environment.
</p>
""")

    # ── CDB FOOTER ──
    sections.append(f"""
<div style="{_s['card']}text-align:center;border-color:rgba(0,212,170,0.2);margin-top:28px;">
  <p style="font-size:18px;font-weight:700;color:{COLORS['accent']};margin:0 0 4px;">CyberDudeBivash Intelligence Note</p>
  <p style="{_s['muted']}margin:0 0 12px;">
    Generated by the CDB-SENTINEL Threat Intelligence Platform using automated
    intelligence correlation, risk enrichment, and adversary behavior analysis.
  </p>
  <a href="{site_url}" style="{_s['cta']}" target="_blank" rel="noopener">Explore Platform →</a>
  <p style="{_s['muted']}margin:12px 0 0;">
    © 2026 {BRAND['legal']} — {BRAND['city']}, {BRAND['country']}
  </p>
</div>
""")

    return "\n".join(sections)


# Stable entrypoint alias
def format_daily_threat_report(**kwargs: Any) -> str:
    return format_daily_report(**kwargs)
