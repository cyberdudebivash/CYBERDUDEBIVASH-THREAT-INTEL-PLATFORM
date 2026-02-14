"""
blog_post_generator.py — CyberDudeBivash v5.0 APEX
Final UI: Spatial Visualization & Reputation Dashboard.
"""
from typing import List, Dict, Optional
from datetime import datetime, timezone

def generate_headline(intel_items: List[Dict]) -> str:
    """Generates a high-impact, consolidated headline."""
    if not intel_items: return "CDB Sentinel Intel Sweep"
    primary = intel_items[0].get('title', 'Unknown Threat')
    return f"CRITICAL: {primary} (+{len(intel_items)-1} Updates)" if len(intel_items) > 1 else f"ADVISORY: {primary}"

def generate_full_post_content(intel_items: List[Dict], iocs: Optional[Dict] = None, pro_data: Optional[Dict] = None, map_html: str = "") -> str:
    """Renders final HTML with spatial heat map and reputation triage."""
    html = [f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #1a1f36; line-height: 1.8; max-width: 900px; margin: auto; border: 1px solid #e3e8ee; border-radius: 8px;">
        <div style="background: #1a1f36; color: #ffffff; padding: 25px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 24px;">CYBERDUDEBIVASH SENTINEL APEX</h1>
            <p style="margin: 5px 0 0; opacity: 0.8; font-family: monospace;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC | VERSION 5.0</p>
        </div>
        
        <div style="padding: 20px; background: #f8f9fa;">
            {map_html}
        </div>

        <div style="padding: 25px;">
    """]

    # Intelligence Nodes
    html.append('<h2 style="color: #5469d4; border-bottom: 2px solid #f7fafc; padding-bottom: 10px;">Executive Summary</h2>')
    for item in intel_items:
        html.append(f"""
        <div style="border-bottom: 1px solid #e3e8ee; padding: 15px 0; margin-bottom: 15px;">
            <h3 style="margin: 0;"><a href="{item.get('link','#')}" style="color: #1a73e8; text-decoration: none;">{item.get('title')}</a></h3>
            <p style="font-size: 15px; color: #4f566b;">{item.get('summary')}</p>
        </div>
        """)

    # Technical Reputation Dashboard
    if iocs and any(iocs.values()):
        html.append("""
        <h2 style="color: #cf1124; margin-top: 30px; border-left: 5px solid #cf1124; padding-left: 15px;">Forensic Evidence & Reputation</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; background: #ffffff;">
            <thead>
                <tr style="background: #f7fafc; border-bottom: 2px solid #e3e8ee; text-align: left;">
                    <th style="padding: 12px;">Indicator</th>
                    <th style="padding: 12px;">VT Verdict</th>
                    <th style="padding: 12px;">Geo-Origin</th>
                    <th style="padding: 12px;">Infrastructure</th>
                </tr>
            </thead>
            <tbody>""")
        
        for ioc_type, values in iocs.items():
            for val in values:
                meta = pro_data.get(val, {"location": "-", "isp": "-", "reputation": "-"})
                
                # Dynamic coloring for malicious verdicts
                is_malicious = "Flags" in meta['reputation'] and int(meta['reputation'].split('/')[0]) > 0
                vt_style = "color: #cf1124; font-weight: bold;" if is_malicious else "color: #188038;"

                html.append(f"""
                <tr style="border-bottom: 1px solid #e3e8ee;">
                    <td style="padding: 12px;">
                        <span style="font-weight: bold; color: #4f566b;">{val}</span><br>
                        <small style="color: #a3acb9;">{ioc_type.upper()}</small>
                    </td>
                    <td style="padding: 12px; {vt_style}">{meta.get('reputation')}</td>
                    <td style="padding: 12px; color: #1a73e8;">{meta.get('location')}</td>
                    <td style="padding: 12px; color: #697386; font-family: monospace;">{meta.get('isp')}</td>
                </tr>""")
        html.append("</tbody></table>")

    html.append("""
        <div style="margin-top: 40px; padding: 20px; background: #f7fafc; text-align: center; font-size: 11px; color: #a3acb9;">
            © 2026 CyberDudeBivash Pvt Ltd — Advanced Threat Intelligence Dashboard
        </div>
    </div>""")
    return "".join(html)

def _calculate_cdb_score(title: str, corpus: str) -> float:
    score = 5.0
    keywords = {"ransomware": 2.0, "zero-day": 2.5, "critical": 1.5, "exploit": 1.0}
    for word, weight in keywords.items():
        if word in f"{title} {corpus}".lower(): score += weight
    return min(10.0, score)
