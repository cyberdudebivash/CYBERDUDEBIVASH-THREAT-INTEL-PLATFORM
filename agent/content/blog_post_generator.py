"""
blog_post_generator.py — CyberDudeBivash v4.6 APEX
Technical Content Engine with Geo-IP and Infrastructure Tables.
"""
from typing import List, Dict, Optional
from datetime import datetime, timezone

def generate_headline(intel_items: List[Dict]) -> str:
    """Generates a high-impact, consolidated headline."""
    if not intel_items: return "CDB Sentinel Intel Sweep"
    primary = intel_items[0].get('title', 'Unknown Threat')
    return f"CRITICAL: {primary} (+{len(intel_items)-1} Updates)" if len(intel_items) > 1 else f"ADVISORY: {primary}"

def generate_full_post_content(intel_items: List[Dict], iocs: Optional[Dict] = None, pro_data: Optional[Dict] = None) -> str:
    """Renders final HTML with forensic enrichment and Geo-IP context."""
    html = [f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #1a1f36; line-height: 1.8; max-width: 850px; margin: auto; border: 1px solid #e3e8ee; border-radius: 8px;">
        <div style="background: #1a1f36; color: #ffffff; padding: 25px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 24px;">CYBERDUDEBIVASH THREAT REPORT</h1>
            <p style="margin: 5px 0 0; opacity: 0.8; font-family: monospace;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC | APEX v4.6</p>
        </div>
        <div style="padding: 25px;">
    """]

    # 1. Executive Summaries
    for item in intel_items:
        html.append(f"""
        <div style="border-bottom: 1px solid #e3e8ee; padding: 15px 0; margin-bottom: 15px;">
            <h3 style="color: #5469d4; margin: 0;"><a href="{item.get('link','#')}" style="color: inherit; text-decoration: none;">{item.get('title')}</a></h3>
            <p style="font-size: 15px; color: #4f566b;">{item.get('summary')}</p>
        </div>
        """)

    # 2. Enhanced Forensic Indicators (With Geo-IP)
    if iocs and any(iocs.values()):
        html.append("""
        <h2 style="color: #cf1124; margin-top: 30px; border-left: 5px solid #cf1124; padding-left: 15px;">Actionable Indicators (IoCs)</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px;">
            <thead>
                <tr style="background: #f7fafc; border-bottom: 2px solid #e3e8ee; text-align: left;">
                    <th style="padding: 12px;">Indicator / Type</th>
                    <th style="padding: 12px;">Origin (Geo-IP)</th>
                    <th style="padding: 12px;">Infrastructure Provider</th>
                </tr>
            </thead>
            <tbody>""")
        
        for ioc_type, values in iocs.items():
            for val in values:
                # Retrieve contextual data if this is an IP
                meta = pro_data.get(val, {"location": "-", "isp": "-"}) if pro_data else {"location": "-", "isp": "-"}
                
                html.append(f"""
                <tr style="border-bottom: 1px solid #e3e8ee;">
                    <td style="padding: 12px;">
                        <span style="font-weight: bold; color: #4f566b;">{val}</span><br>
                        <small style="color: #a3acb9;">{ioc_type.upper()}</small>
                    </td>
                    <td style="padding: 12px; color: #1a73e8;">{meta.get('location')}</td>
                    <td style="padding: 12px; color: #697386; font-family: monospace;">{meta.get('isp')}</td>
                </tr>""")
        html.append("</tbody></table>")

    html.append("""
        <div style="margin-top: 40px; padding: 20px; background: #f7fafc; text-align: center; font-size: 12px; color: #a3acb9;">
            © 2026 CyberDudeBivash Pvt Ltd — Advanced Threat Intelligence Dashboard
        </div>
    </div>""")
    return "".join(html)

def _calculate_cdb_score(title: str, corpus: str) -> float:
    score = 5.0
    keywords = {"ransomware": 2.0, "zero-day": 2.5, "critical": 1.5, "exploit": 1.0}
    for word, weight in keywords.items():
        if word in corpus.lower(): score += weight
    return min(10.0, score)
