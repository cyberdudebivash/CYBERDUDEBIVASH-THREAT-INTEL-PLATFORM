"""
blog_post_generator.py — CyberDudeBivash v5.4 APEX
Final UI: reputation-based color coding and SIEM integration.
"""
from typing import List, Dict, Optional
from datetime import datetime, timezone

def generate_headline(intel_items: List[Dict]) -> str:
    if not intel_items: return "Sentinel Intel Sweep"
    primary = intel_items[0].get('title', 'Unknown')
    return f"CRITICAL: {primary} (+{len(intel_items)-1} Updates)" if len(intel_items) > 1 else f"ADVISORY: {primary}"

def generate_full_post_content(intel_items: List[Dict], iocs: Optional[Dict] = None, pro_data: Optional[Dict] = None, map_html: str = "", stix_id: str = "") -> str:
    html = [f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #1a1f36; line-height: 1.8; max-width: 900px; margin: auto; border: 1px solid #e3e8ee; border-radius: 8px;">
        <div style="background: #1a1f36; color: #ffffff; padding: 25px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 24px;">CYBERDUDEBIVASH SENTINEL APEX</h1>
            <p style="margin: 5px 0 0; opacity: 0.8; font-family: monospace;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC | VERIFIED INTEL</p>
        </div>
        <div style="padding: 20px; background: #f8f9fa;">{map_html}</div>
        <div style="padding: 25px;">
    """]

    for item in intel_items:
        html.append(f"<div style='border-bottom: 1px solid #eee; padding-bottom: 15px; margin-bottom: 15px;'>")
        html.append(f"<h3><a href='{item.get('link','#')}'>{item.get('title')}</a></h3><p>{item.get('summary')}</p></div>")

    if iocs and any(iocs.values()):
        html.append("""
        <h2 style="color: #cf1124; margin-top: 30px; border-left: 5px solid #cf1124; padding-left: 15px;">Forensic Evidence & Reputation</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; background: #ffffff;">
            <thead>
                <tr style="background: #f7fafc; border-bottom: 2px solid #e3e8ee; text-align: left;">
                    <th style="padding: 12px;">Indicator</th>
                    <th style="padding: 12px;">VT Verdict</th>
                    <th style="padding: 12px;">Origin</th>
                    <th style="padding: 12px;">Infrastructure</th>
                </tr>
            </thead>
            <tbody>""")
        
        for ioc_type, values in iocs.items():
            for val in values:
                meta = pro_data.get(val, {"location": "-", "isp": "-", "reputation": "0/0"})
                # Color logic for Reputation Score
                is_malicious = "Flags" in meta['reputation'] and int(meta['reputation'].split('/')[0]) > 0
                vt_style = "color: #cf1124; font-weight: bold;" if is_malicious else "color: #188038;"

                html.append(f"""
                <tr style="border-bottom: 1px solid #e3e8ee;">
                    <td style="padding: 12px;"><strong>{val}</strong><br><small style="color: #a3acb9;">{ioc_type.upper()}</small></td>
                    <td style="padding: 12px; {vt_style}">{meta.get('reputation')}</td>
                    <td style="padding: 12px; color: #1a73e8;">{meta.get('location')}</td>
                    <td style="padding: 12px; color: #697386; font-family: monospace;">{meta.get('isp')}</td>
                </tr>""")
        html.append("</tbody></table>")

    if stix_id:
        html.append(f"<div style='margin-top: 30px; border: 1px dashed #5469d4; padding: 15px; background: #f1f3f4; font-size: 11px;'>")
        html.append(f"<strong>SIEM REFERENCE ID:</strong> {stix_id} | STIX 2.1 MACHINE-READABLE READY</div>")

    html.append("</div><div style='text-align: center; padding: 20px; font-size: 10px; color: #a3acb9;'>© 2026 CyberDudeBivash</div></div>")
    return "".join(html)

def _calculate_cdb_score(title: str, corpus: str) -> float:
    score = 5.0
    keywords = {"ransomware": 2.0, "zero-day": 2.5, "critical": 1.5, "exploit": 1.0}
    for word, weight in keywords.items():
        if word in f"{title} {corpus}".lower(): score += weight
    return min(10.0, score)
