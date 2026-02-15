#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v7.5.1
Final Enterprise Version: Merged Attribution, MITRE TTPs, and SOC Playbooks.
"""

def generate_headline(intel_items):
    """Generates an action-oriented enterprise headline."""
    if not intel_items:
        return "Autonomous Threat Intelligence Brief"
    return f"Threat Advisory: {intel_items[0]['title']}"

def _generate_detection_playbook(iocs):
    """Generates actionable SOC hunting logic for Microsoft Sentinel and Splunk."""
    domains = iocs.get('domain', [])
    ips = iocs.get('ipv4', [])
    
    # Azure Sentinel KQL
    kql = "DeviceNetworkEvents\n| where "
    if domains:
        kql += f"RemoteUrl has_any (\"{', '.join(domains[:3])}\")"
    elif ips:
        kql += f"RemoteIP has_any (\"{', '.join(ips[:3])}\")"
    else:
        kql += "RemoteUrl contains \"suspicious-entity\""
    kql += "\n| summarize count() by DeviceName, RemoteUrl"
    
    # Splunk SPL
    spl = f"index=network_logs ({' OR '.join(domains[:2] + ips[:2])}) | stats count by src_ip, dest_url"
    
    return kql, spl

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None, risk_score=7.0):
    """
    Final Enterprise Template: Incorporates Analyst Comments and Crowdsourced Tags.
    """
    # 1. Metadata & Classification Logic
    tlp_label = "TLP:AMBER" if risk_score >= 8.0 else "TLP:CLEAR"
    tlp_color = "#ffbf00" if risk_score >= 8.0 else "#00d4aa"
    confidence = "HIGH" if risk_score >= 8.5 else ("MEDIUM" if risk_score >= 6.0 else "LOW")
    
    # 2. Attribution Context Extraction (v7.5.1 vt_lookup Sync)
    top_insight = "No specific community attribution found for this cluster."
    tags_found = []
    
    for ioc, data in pro_data.items():
        # Captures crowdsourced analyst notes
        if data.get('analyst_comments') and data['analyst_comments'] != "No community comments available.":
            top_insight = data['analyst_comments']
        # Captures attribution tags (e.g., malware families)
        if data.get('tags'):
            tags_found.extend(data['tags'])
    
    unique_tags = list(set(tags_found))[:8]
    kql, spl = _generate_detection_playbook(iocs)
    
    # 3. Final HTML Synthesis
    html = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Segoe UI', Tahoma, sans-serif; border:1px solid #1a1a1a; border-radius:12px; overflow:hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
        
        <div style="background:{tlp_color}; color:#000; padding:15px; text-align:center; font-weight:bold; letter-spacing:3px; font-size:12px;">
            {tlp_label} // CDB-SENTINEL-APEX-V7.5.1 // CONFIDENCE: {confidence}
        </div>

        <div style="padding:40px;">
            <h1 style="color:#fff; font-size:28px; letter-spacing:-1px; margin-bottom:10px;">{intel_items[0]['title']}</h1>
            <p style="color:#555; font-size:11px; text-transform:uppercase;">Advisory ID: {stix_id} | Risk Score: {risk_score}/10</p>

            <div style="background:rgba(255,255,255,0.02); border-left:4px solid {tlp_color}; padding:25px; margin:30px 0;">
                <h3 style="color:{tlp_color}; font-size:14px; text-transform:uppercase; margin-top:0;">1. Executive Summary (BLUF)</h3>
                <p style="line-height:1.7; color:#ccc; font-size:14px;">{intel_items[0].get('summary', 'Detailed analysis in progress.')[:600]}...</p>
                <div style="margin-top:15px; border-top:1px solid #222; padding-top:15px;">
                    <b style="color:#fff; font-size:12px;">Strategic Impact:</b>
                    <p style="color:#888; font-size:13px; margin:5px 0;">Infrastructure rotation suggests active adversary maintenance. High risk of data exfiltration for targeted sectors.</p>
                </div>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px;">2. Analyst Insights & Crowdsourced Context</h3>
            <div style="background:rgba(0,212,170,0.03); border:1px dashed #00d4aa; padding:20px; border-radius:8px; margin:20px 0;">
                <b style="color:#00d4aa; font-size:11px; text-transform:uppercase;">Community Intelligence:</b>
                <p style="font-size:13px; font-style:italic; color:#aaa; margin:10px 0;">"{top_insight}"</p>
                
                <div style="margin-top:15px;">
                    <b style="color:#00d4aa; font-size:11px; text-transform:uppercase;">Attribution Tags:</b>
                    <div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:8px;">
                        {" ".join([f'<span style="background:#111; color:#fff; border:1px solid #333; padding:2px 8px; border-radius:4px; font-size:10px;">{tag}</span>' for tag in unique_tags]) if unique_tags else '<span style="color:#444; font-size:10px;">No tags identified.</span>'}
                    </div>
                </div>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">3. Tactics, Techniques & Procedures (TTPs)</h3>
            <table style="width:100%; border-collapse:collapse; margin:20px 0; font-size:12px; color:#ccc;">
                <tr style="background:#111; color:{tlp_color}; text-align:left;">
                    <th style="padding:12px; border:1px solid #222;">ID</th>
                    <th style="padding:12px; border:1px solid #222;">Technique Name</th>
                    <th style="padding:12px; border:1px solid #222;">Tactic</th>
                </tr>
                {"".join([f"<tr style='border-bottom:1px solid #222;'><td style='padding:12px; font-family:monospace;'>{m.get('id', 'T1071')}</td><td style='padding:12px;'>{m.get('technique', 'Standard Traffic')}</td><td style='padding:12px;'>{m['tactic']}</td></tr>" for m in (mitre_data or [{"id":"T1071","tactic":"C2","technique":"Application Layer Protocol"}])])}
            </table>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">4. Detection & Hunting Logic</h3>
            <div style="background:#0a0a0a; border:1px solid #1a1a1a; border-radius:8px; padding:20px; margin-top:15px;">
                <div style="margin-bottom:20px;">
                    <b style="color:#00d4aa; font-size:11px; text-transform:uppercase;">Azure Sentinel (KQL)</b>
                    <pre style="background:#000; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; font-family:'JetBrains Mono', monospace; border:1px solid #222; margin-top:10px; overflow-x:auto;">{kql}</pre>
                </div>
                <div>
                    <b style="color:#00d4aa; font-size:11px; text-transform:uppercase;">Splunk Enterprise (SPL)</b>
                    <pre style="background:#000; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; font-family:'JetBrains Mono', monospace; border:1px solid #222; margin-top:10px; overflow-x:auto;">{spl}</pre>
                </div>
            </div>

            <h3 style="color:#fff; font-size:16px; margin-top:40px;">5. Adversary Infrastructure Topology</h3>
            <div style="border:1px solid #222; border-radius:12px; overflow:hidden; margin-top:15px; background:#111;">
                {map_html}
            </div>

            <div style="margin-top:60px; border-top:1px solid #222; padding-top:20px; text-align:center; font-size:10px; color:#333;">
                CYBERDUDEBIVASH GOC // AUTONOMOUS SENTINEL NODE // {stix_id}<br>
                PROPRIETARY INTELLIGENCE PRODUCT. REDISTRIBUTION REQUIRES {tlp_label} CLEARANCE.
            </div>
        </div>
    </div>
    """
    return html
