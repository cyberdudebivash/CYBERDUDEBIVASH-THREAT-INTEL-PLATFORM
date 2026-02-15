#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v7.5.2
Deep-Dive Edition: Integrated Technical Analysis & Attribution Narrative.
"""

def generate_headline(intel_items):
    if not intel_items:
        return "Autonomous Threat Intelligence Brief"
    return f"Threat Advisory: {intel_items[0]['title']}"

def _generate_detection_playbook(iocs):
    """Generates actionable SOC hunting logic."""
    domains = iocs.get('domain', [])
    ips = iocs.get('ipv4', [])
    kql = "DeviceNetworkEvents\n| where "
    if domains:
        kql += f"RemoteUrl has_any (\"{', '.join(domains[:3])}\")"
    elif ips:
        kql += f"RemoteIP has_any (\"{', '.join(ips[:3])}\")"
    else:
        kql += "RemoteUrl contains \"suspicious-entity\""
    kql += "\n| summarize count() by DeviceName, RemoteUrl"
    spl = f"index=network_logs ({' OR '.join(domains[:2] + ips[:2])}) | stats count by src_ip, dest_url"
    return kql, spl

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None, risk_score=7.0):
    """
    v7.5.2 Template: Adds Section 2 (Detailed Technical Analysis) to provide the 'How' and 'Why'.
    """
    tlp_label = "TLP:AMBER" if risk_score >= 8.0 else "TLP:CLEAR"
    tlp_color = "#ffbf00" if risk_score >= 8.0 else "#00d4aa"
    confidence = "HIGH" if risk_score >= 8.5 else ("MEDIUM" if risk_score >= 6.0 else "LOW")
    
    # Extract Community Context
    top_insight = "No specific community attribution found."
    tags_found = []
    for ioc, data in pro_data.items():
        if data.get('analyst_comments') and data['analyst_comments'] != "No community comments available.":
            top_insight = data['analyst_comments']
        if data.get('tags'): tags_found.extend(data['tags'])
    unique_tags = list(set(tags_found))[:8]

    # SECTION 2: Technical Deep-Dive Synthesis
    intel_details = ""
    for item in intel_items:
        clean_desc = item.get('summary', 'Forensic artifacts pending.').replace('\n', ' ')
        intel_details += f"<li style='margin-bottom:12px;'><b>{item['title']}:</b> {clean_desc}</li>"

    kql, spl = _generate_detection_playbook(iocs)
    
    html = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Segoe UI', sans-serif; border:1px solid #1a1a1a; border-radius:12px; overflow:hidden;">
        <div style="background:{tlp_color}; color:#000; padding:15px; text-align:center; font-weight:bold; letter-spacing:3px; font-size:12px;">
            {tlp_label} // CDB-SENTINEL-APEX-V7.5.2 // CONFIDENCE: {confidence}
        </div>

        <div style="padding:40px;">
            <h1 style="color:#fff; font-size:28px; letter-spacing:-1px;">{intel_items[0]['title']}</h1>
            <p style="color:#555; font-size:11px;">ADVISORY ID: {stix_id} | RISK: {risk_score}/10</p>

            <div style="background:rgba(255,255,255,0.02); border-left:4px solid {tlp_color}; padding:25px; margin:30px 0;">
                <h3 style="color:{tlp_color}; font-size:14px; text-transform:uppercase; margin:0;">1. Executive Summary (BLUF)</h3>
                <p style="line-height:1.7; color:#ccc; font-size:14px;">Targeted campaign identified involving infrastructure clusters and tactical overlap. Recommended urgency: {'Immediate' if risk_score >= 8.0 else 'Routine'}.</p>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">2. Detailed Technical Analysis</h3>
            <div style="background:rgba(255,255,255,0.01); padding:20px; border-radius:8px; margin:20px 0;">
                <ul style="color:#ccc; font-size:13px; line-height:1.8; padding-left:20px;">
                    {intel_details}
                </ul>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">3. Community Attribution & Context</h3>
            <div style="background:rgba(0,212,170,0.03); border:1px dashed #00d4aa; padding:20px; border-radius:8px; margin:20px 0;">
                <b style="color:#00d4aa; font-size:11px;">ANALYST NOTES:</b>
                <p style="font-size:13px; font-style:italic; color:#aaa;">"{top_insight}"</p>
                <div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:12px;">
                    {" ".join([f'<span style="background:#111; border:1px solid #333; padding:2px 8px; border-radius:4px; font-size:10px;">{tag}</span>' for tag in unique_tags])}
                </div>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">4. Tactics, Techniques & Procedures (TTPs)</h3>
            <table style="width:100%; border-collapse:collapse; margin:20px 0; font-size:12px;">
                <tr style="background:#111; color:{tlp_color}; text-align:left;">
                    <th style="padding:12px; border:1px solid #222;">ID</th>
                    <th style="padding:12px; border:1px solid #222;">Technique Name</th>
                    <th style="padding:12px; border:1px solid #222;">Tactic</th>
                </tr>
                {"".join([f"<tr><td style='padding:12px; border:1px solid #222;'>{m['id']}</td><td style='padding:12px; border:1px solid #222;'>{m['technique']}</td><td style='padding:12px; border:1px solid #222;'>{m['tactic']}</td></tr>" for m in (mitre_data or [])])}
            </table>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">5. Detection & Hunting Logic</h3>
            <div style="background:#0a0a0a; border:1px solid #1a1a1a; padding:20px; border-radius:8px; margin-top:15px;">
                <b style="color:#00d4aa; font-size:11px; text-transform:uppercase;">Azure Sentinel (KQL)</b>
                <pre style="background:#000; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; margin-top:10px; overflow-x:auto;">{kql}</pre>
                <b style="color:#00d4aa; font-size:11px; text-transform:uppercase; display:block; margin-top:20px;">Splunk (SPL)</b>
                <pre style="background:#000; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; margin-top:10px; overflow-x:auto;">{spl}</pre>
            </div>

            <div style="margin-top:60px; border-top:1px solid #222; padding-top:20px; text-align:center; font-size:10px; color:#333;">
                CYBERDUDEBIVASH GOC // AUTONOMOUS SENTINEL NODE // {stix_id}
            </div>
        </div>
    </div>
    """
    return html
