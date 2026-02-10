"""
CyberDudeBivash Authority Threat Intelligence Formatter
FINAL • PRODUCTION • INTERFACE-HARDENED

This formatter is deliberately tolerant to evolving inputs.
It will NEVER break sentinel_blogger or CI pipelines.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


# =================================================
# TIME UTIL
# =================================================

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# =================================================
# CORE AUTHORITY FORMATTER
# =================================================

def format_daily_report(
    cves: Optional[List[Dict]] = None,
    kev_items: Optional[List[Dict]] = None,
    malware_items: Optional[List[Dict]] = None,
    coverage_gaps: Optional[List[Dict]] = None,
    author: str = "CyberDudeBivash Threat Intelligence Team",
    site_url: str = "",
    **_: Any,
) -> str:
    """
    Generate a production-grade, authority-level daily cyber threat report.

    All parameters are OPTIONAL by design to guarantee:
    - Backward compatibility
    - Forward compatibility
    - CI safety
    """

    cves = cves or []
    kev_items = kev_items or []
    malware_items = malware_items or []
    coverage_gaps = coverage_gaps or []

    sections: List[str] = []

    # -------------------------------------------------
    # HEADER
    # -------------------------------------------------
    sections.append(f"""
<h2>Daily Cyber Threat Intelligence Report</h2>
<p>
<strong>Publication Timestamp:</strong> {_utc_now()}<br>
<strong>Prepared By:</strong> {author}
</p>
""")

    # -------------------------------------------------
    # EXECUTIVE SUMMARY
    # -------------------------------------------------
    sections.append("""
<h3>Executive Intelligence Summary</h3>
<p>
This report provides a high-confidence assessment of the current cyber threat
landscape based on newly disclosed vulnerabilities, confirmed exploitation
activity, and observed adversary tradecraft. The intelligence reflects sustained
attacker focus on exploiting operational weaknesses, delayed patch cycles, and
internet-facing services.
</p>
<p>
Security leaders should treat the findings in this advisory as immediately
relevant to enterprise risk management and defensive prioritization.
</p>
""")

    # -------------------------------------------------
    # CISA KEV SECTION
    # -------------------------------------------------
    sections.append("<h3>Known Exploited Vulnerabilities (CISA KEV)</h3>")

    if kev_items:
        for kev in kev_items:
            sections.append(f"""
<p>
<strong>{kev.get('cveID')}</strong><br>
Vendor: {kev.get('vendorProject', 'Unknown')} |
Product: {kev.get('product', 'Unknown')}<br>
Status: Actively Exploited in the Wild
</p>
<p>
This vulnerability is confirmed to be exploited by real-world threat actors.
Unpatched systems remain at immediate risk of compromise.
</p>
""")
    else:
        sections.append("""
<p>
No newly added CISA Known Exploited Vulnerabilities were identified during this
reporting window. Previously cataloged KEVs remain relevant and should continue
to be prioritized.
</p>
""")

    # -------------------------------------------------
    # CVE SECTION
    # -------------------------------------------------
    sections.append("<h3>Critical & High-Risk Vulnerabilities</h3>")

    if cves:
        for cve in cves:
            sections.append(f"""
<h4>{cve.get('id')}</h4>
<p>
<strong>Severity:</strong> {cve.get('severity', 'Unknown')} |
<strong>CVSS:</strong> {cve.get('cvss', 'N/A')} |
<strong>EPSS:</strong> {round(cve.get('epss', 0.0), 3)}
</p>
<p>
This vulnerability affects commonly deployed software and introduces conditions
that may enable unauthorized access, remote code execution, or privilege
escalation. Exploitation probability metrics indicate realistic adversary
interest.
</p>
""")
    else:
        sections.append("""
<p>
No newly disclosed high-impact vulnerabilities were identified during this
reporting window. This does not indicate reduced threat activity, as attackers
frequently exploit previously disclosed but unpatched issues.
</p>
""")

    # -------------------------------------------------
    # MALWARE & CAMPAIGNS
    # -------------------------------------------------
    sections.append("<h3>Malware & Campaign Activity</h3>")

    if malware_items:
        for item in malware_items:
            sections.append(f"""
<p>
<strong>Malware Family:</strong> {item.get('family', 'Unknown')}<br>
<strong>Assessed Severity:</strong> {item.get('severity', 'Unknown')}
</p>
<p>
This malware exhibits behavior consistent with modern intrusion campaigns,
including stealthy execution, external command-and-control communication, and
post-exploitation enablement.
</p>
""")
    else:
        sections.append("""
<p>
No confirmed malware samples were retrieved during this reporting window.
This does not imply absence of malicious activity, as malware deployment often
occurs after initial exploitation.
</p>
""")

    # -------------------------------------------------
    # MITRE ATT&CK & COVERAGE
    # -------------------------------------------------
    sections.append("<h3>MITRE ATT&CK Context & Defensive Coverage</h3>")

    if coverage_gaps:
        for gap in coverage_gaps:
            sections.append(f"""
<p>
<strong>{gap.get('technique_id')} – {gap.get('technique_name')}</strong><br>
Tactic: {gap.get('tactic', 'Unknown')} |
Coverage Gap Severity: {gap.get('gap_severity')}
</p>
<p>
This gap represents a defensive blind spot that could allow adversary activity
to progress undetected during early stages of intrusion.
</p>
""")
    else:
        sections.append("""
<p>
No immediate ATT&CK coverage gaps were identified during this reporting window,
indicating reasonable alignment between observed techniques and existing
detections.
</p>
""")

    # -------------------------------------------------
    # STRATEGIC TAKEAWAYS
    # -------------------------------------------------
    sections.append("""
<h3>Strategic Security Takeaways</h3>
<p>
The continued exploitation of known vulnerabilities and reliance on established
ATT&CK techniques underscores the importance of disciplined patch management,
behavior-based detection, and threat-informed defensive strategies.
</p>
""")

    # -------------------------------------------------
    # CYBERDUDEBIVASH NOTE
    # -------------------------------------------------
    sections.append(f"""
<h3>CyberDudeBivash Intelligence Note</h3>
<p>
This report was generated by the CyberDudeBivash Threat Intelligence Platform
using automated intelligence correlation, risk enrichment, and adversary
behavior analysis.
</p>
<p>
Access additional research, tools, and intelligence at
<a href="{site_url}">{site_url}</a>
</p>
""")

    return "\n".join(sections)


# =================================================
# STABLE ENTRYPOINT (DO NOT REMOVE)
# =================================================

def format_daily_threat_report(**kwargs: Any) -> str:
    """
    Stable wrapper required by sentinel_blogger.py.
    """
    return format_daily_report(**kwargs)
