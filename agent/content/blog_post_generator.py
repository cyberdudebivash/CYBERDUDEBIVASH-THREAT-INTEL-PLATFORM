"""
blog_post_generator.py — CyberDudeBivash v4.2 APEX
Technical Content Engine with Forensic Indicator Tables.
"""
from typing import List, Dict, Optional
from datetime import datetime

def generate_headline(intel_items: List[Dict]) -> str:
    """Generates a high-impact, consolidated headline."""
    if not intel_items: return "CDB Sentinel Intel Sweep"
    primary = intel_items[0]['title']
    return f"CRITICAL: {primary} (+{len(intel_items)-1} Updates)" if len(intel_items) > 1 else f"ADVISORY: {primary}"

def generate_full_post_content(intel_items: List[Dict], iocs: Optional[Dict] = None) -> str:
    """Renders the final HTML including technical indicator tables."""
    html = [f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #1a1f36; line-height: 1.8;">
        <div style="background: #1a1f36; color: #ffffff; padding: 20px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 24px;">CYBERDUDEBIVASH THREAT REPORT</h1>
            <p style="margin: 5px 0 0; opacity: 0.8;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC</p>
        </div>
    """]

    # Intelligence Nodes
    for item in intel_items:
        html.append(f"""
        <div style="border-bottom: 1px solid #e3e8ee; padding: 20px 0;">
            <h3 style="color: #5469d4;"><a href="{item['link']}" style="color: inherit; text-decoration: none;">{item['title']}</a></h3>
            <p>{item['summary']}</p>
        </div>
        """)

    # Technical Indicators (IoCs)
    if iocs and any(iocs.values()):
        html.append("""
        <h2 style="color: #cf1124; margin-top: 30px; border-left: 4px solid #cf1124; padding-left: 10px;">Technical Indicators (IoCs)</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 15px; background: #fdfdfd;">
            <thead>
                <tr style="background: #f7fafc; border-bottom: 2px solid #e3e8ee;">
                    <th style="padding: 12px; text-align: left;">Type</th>
                    <th style="padding: 12px; text-align: left;">Indicator Value</th>
                </tr>
            </thead>
            <tbody>""")
        
        for ioc_type, values in iocs.items():
            for val in values:
                html.append(f"""
                <tr style="border-bottom: 1px solid #e3e8ee;">
                    <td style="padding: 12px; font-weight: bold; color: #4f566b;">{ioc_type.upper()}</td>
                    <td style="padding: 12px; font-family: 'Courier New', monospace; color: #cf1124;">{val}</td>
                </tr>""")
        html.append("</tbody></table>")

    html.append("""
        <div style="margin-top: 40px; padding: 20px; background: #f7fafc; border-radius: 8px; text-align: center; font-size: 12px; color: #a3acb9;">
            © 2026 CyberDudeBivash Pvt Ltd | Automated Intelligence via Sentinel APEX Engine
        </div>
    </div>""")
    return "".join(html)

def _calculate_cdb_score(title: str, corpus: str) -> float:
    score = 5.0
    keywords = {"ransomware": 2.0, "zero-day": 2.5, "critical": 1.5, "exploit": 1.0}
    for word, weight in keywords.items():
        if word in corpus.lower(): score += weight
    return min(10.0, score)
