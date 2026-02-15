#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v8.0
Elite Intelligence Producer: Mandatory Structural Pillars & SOC Playbooks.
"""

def generate_headline(intel_items):
    """Action-oriented headline for high-fidelity advisories."""
    if not intel_items:
        return "Autonomous Threat Intelligence Brief"
    return f"TACTICAL ADVISORY: {intel_items[0]['title']}"

def _generate_detection_engineering(iocs):
    """Generates actionable logic for multi-platform detection."""
    domains = iocs.get('domain', [])
    ips = iocs.get('ipv4', [])
    
    # Azure Sentinel (KQL)
    kql = "DeviceNetworkEvents\n| where "
    if domains:
        kql += f"RemoteUrl has_any (\"{', '.join(domains[:3])}\")"
    elif ips:
        kql += f"RemoteIP has_any (\"{', '.join(ips[:3])}\")"
    else:
        kql += "RemoteUrl contains \"suspicious-entity\""
    kql += "\n| summarize count() by DeviceName, RemoteUrl"
    
    # Splunk (SPL)
    spl = f"index=network_logs ({' OR '.join(domains[:2] + ips[:2])}) | stats count by src_ip, dest_url"
    
    return kql, spl

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None, risk_score=7.0, actor_data=None):
    """
    v8.0 Elite Production Template: The Structural Transformation.
    Consolidates Actor Profiles, Deep-Dive Analysis, and Detection Playbooks.
    """
    # 1. Metadata Preparation
    profile = actor_data.get('profile', {}) if actor_data else {}
    tracking_id = actor_data.get('tracking_id', 'UNC-CDB-99') if actor_data else 'UNC-CDB-99'
    tlp_label = "TLP:AMBER" if risk_score >= 8.5 else "TLP:CLEAR"
    tlp_color = "#ff3e3e" if risk_score >= 8.5 else "#00d4aa"
    confidence = profile.get('confidence_score', 'MEDIUM (OSINT CORRELATED)')
    
    kql, spl = _generate_detection_engineering(iocs)

    # 2. Deep-Dive Intel Synthesis
    intel_details = ""
    for item in intel_items:
        clean_desc = item.get('summary', 'Forensic details pending.').replace('\n', ' ')
        intel_details += f"<li style='margin-bottom:15px; color:#ccc;'><b>{item['title']}:</b> {clean_desc}</li>"

    # 3. Final World-Class HTML Structure
    html = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Inter', 'Segoe UI', sans-serif; border:1px solid #222; border-radius:12px; overflow:hidden; box-shadow: 0 20px 50px rgba(0,0,0,0.6);">
        
        <div style="background:{tlp_color}; color:#000; padding:15px; text-align:center; font-weight:bold; letter-spacing:4px; font-size:12px;">
            {tlp_label} // CDB-SENTINEL-GOC // STRATEGIC ADVISORY
        </div>

        <div style="padding:45px;">
            <h1 style="color:#fff; font-size:32px; letter-spacing:-1.5px; margin-bottom:10px;">{intel_items[0]['title']}</h1>
            <p style="color:#666; font-size:12px; margin-bottom:30px;">ADVISORY ID: {stix_id} | AUTH: CDB-APEX-V8.0</p>

            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-bottom:40px;">
                <div style="background:#111; padding:25px; border:1px solid #222; border-radius:8px;">
                    <h3 style="color:{tlp_color}; font-size:14px; margin-top:0; text-transform:uppercase;">1. Intel Snapshot</h3>
                    <p style="font-size:13px; margin:8px 0;"><b>ACTOR ID:</b> <span style="color:#fff;">{tracking_id}</span></p>
                    <p style="font-size:13px; margin:8px 0;"><b>CONFIDENCE:</b> <span style="color:#fff;">{confidence}</span></p>
                    <p style="font-size:13px; margin:8px 0;"><b>URGENCY:</b> <span style="color:#fff;">{'CRITICAL' if risk_score >= 9.0 else 'HIGH'}</span></p>
                </div>
                <div style="background:#111; padding:25px; border:1px solid #222; border-radius:8px; text-align:center;">
                    <h3 style="color:{tlp_color}; font-size:14px; margin-top:0; text-transform:uppercase;">Severity Index</h3>
                    <div style="font-size:42px; font-weight:bold; color:#fff; line-height:1;">{risk_score}<span style="font-size:16px; color:#444;">/10</span></div>
                    <p style="font-size:10px; color:#555; margin-top:10px;">CDB-FRAMEWORK V4.0 // CVSS ALIGNED</p>
                </div>
            </div>

            <div style="background:rgba(255,255,255,0.02); border:1px solid #333; padding:30px; border-radius:8px; margin-bottom:40px;">
                <h3 style="color:#fff; font-size:18px; margin-top:0; border-bottom:1px solid #333; padding-bottom:15px;">2. Threat Actor Profile: {tracking_id}</h3>
                <table style="width:100%; border-collapse:collapse; font-size:13px; color:#ccc;">
                    <tr><td style="padding:10px 0; border-bottom:1px solid #222;"><b>ALIASES:</b></td><td style="padding:10px 0; border-bottom:1px solid #222; color:#fff;">{", ".join(profile.get('alias', ['UNC-CDB-CLUSTER']))}</td></tr>
                    <tr><td style="padding:10px 0; border-bottom:1px solid #222;"><b>ORIGIN:</b></td><td style="padding:10px 0; border-bottom:1px solid #222; color:#fff;">{profile.get('origin', 'Under Investigation')}</td></tr>
                    <tr><td style="padding:10px 0; border-bottom:1px solid #222;"><b>MOTIVATION:</b></td><td style="padding:10px 0; border-bottom:1px solid #222; color:#fff;">{profile.get('motivation', 'Espionage / Disruption')}</td></tr>
                    <tr><td style="padding:10px 0; border-bottom:1px solid #222;"><b>TOOLSET:</b></td><td style="padding:10px 0; border-bottom:1px solid #222; color:#fff;">{", ".join(profile.get('tooling', ['Proprietary Backdoors']))}</td></tr>
                </table>
            </div>

            <h3 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">3. Technical Intelligence Deep-Dive</h3>
            <div style="background:rgba(255,255,255,0.01); padding:25px; border-radius:8px; margin:20px 0;">
                <ul style="padding-left:20px; font-size:14px; line-height:1.8;">
                    {intel_details}
                </ul>
            </div>

            <h3 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">4. Detection & Hunting Logic</h3>
            <div style="background:#0a0a0a; border:1px solid #222; border-radius:8px; padding:25px; margin-top:20px;">
                <div style="margin-bottom:25px;">
                    <b style="color:{tlp_color}; font-size:11px; text-transform:uppercase; letter-spacing:1px;">Azure Sentinel (KQL)</b>
                    <pre style="background:#000; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; font-family:'JetBrains Mono', monospace; border:1px solid #333; margin-top:10px; overflow-x:auto;">{kql}</pre>
                </div>
                <div>
                    <b style="color:{tlp_color}; font-size:11px; text-transform:uppercase; letter-spacing:1px;">Splunk Enterprise (SPL)</b>
                    <pre style="background:#000; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; font-family:'JetBrains Mono', monospace; border:1px solid #333; margin-top:10px; overflow-x:auto;">{spl}</pre>
                </div>
            </div>

            <div style="margin-top:60px; border-top:1px solid #222; padding-top:20px; text-align:center; font-size:10px; color:#444; letter-spacing:1px;">
                CYBERDUDEBIVASH GLOBAL OPERATIONS CENTER // v8.0 ELITE NODE<br>
                PROPRIETARY STRATEGIC ASSET. REPRODUCTION REQUIRES {tlp_label} CLEARANCE.
            </div>
        </div>
    </div>
    """
    return html
