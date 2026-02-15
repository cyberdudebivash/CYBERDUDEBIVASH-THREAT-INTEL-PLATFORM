#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v7.5
Enterprise Refactor: Mandatory Structure, MITRE Tables, and Detection Playbooks.
"""
import json

def generate_headline(intel_items):
    if not intel_items:
        return "Autonomous Threat Intelligence Brief"
    # Enterprise standard: Action-oriented headlines
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
    Refactored for Microsoft/Google/Cisco level consumption.
    Includes BLUF, TTP Tables, Detection Queries, and Risk Framing.
    """
    # 1. Classification & BLUF
    tlp_label = "TLP:AMBER" if risk_score >= 8.0 else "TLP:CLEAR"
    tlp_color = "#ffbf00" if risk_score >= 8.0 else "#00d4aa"
    confidence = "HIGH" if risk_score >= 8.5 else ("MEDIUM" if risk_score >= 6.0 else "LOW")
    
    # 2. Generate Detection Logic
    kql, spl = _generate_detection_playbook(iocs)
    
    # 3. Content Construction
    html = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Segoe UI', Tahoma, sans-serif; border:1px solid #1a1a1a; padding:0; border-radius:8px; overflow:hidden;">
        
        <div style="background:{tlp_color}; color:#000; padding:12px; text-align:center; font-weight:bold; letter-spacing:2px; font-size:13px;">
            {tlp_label} // CDB-SENTINEL-APEX-V7.5 // CONFIDENCE: {confidence}
        </div>

        <div style="padding:40px;">
            <h1 style="color:#fff; font-size:32px; margin-bottom:10px;">{intel_items[0]['title']}</h1>
            <p style="color:#666; font-size:12px;">ID: {stix_id} | DATE: {stix_id.split('-')[-1]} | CLASS: Cyber Threat Advisory</p>

            <div style="background:rgba(255,255,255,0.03); border-left:5px solid {tlp_color}; padding:25px; margin:30px 0;">
                <h2 style="color:{tlp_color}; font-size:16px; text-transform:uppercase; margin-top:0;">1. Executive Summary (BLUF)</h2>
                <p style="line-height:1.7; color:#ccc;">{intel_items[0].get('summary', 'Analysis in progress.')[:500]}...</p>
                <p style="font-weight:bold; color:#fff;">Impact: <span style="color:{tlp_color};">Significant risk to enterprise cloud infrastructure and credential integrity.</span></p>
            </div>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px;">2. Tactics, Techniques & Procedures (TTPs)</h2>
            <table style="width:100%; border-collapse:collapse; margin:20px 0; font-size:13px;">
                <tr style="background:#111; color:{tlp_color}; text-align:left;">
                    <th style="padding:12px; border:1px solid #222;">ID</th>
                    <th style="padding:12px; border:1px solid #222;">Technique</th>
                    <th style="padding:12px; border:1px solid #222;">Tactic / Phase</th>
                </tr>
                {"".join([f"<tr style='border-bottom:1px solid #222;'><td style='padding:12px;'>{m.get('id', 'T1071')}</td><td style='padding:12px;'>{m.get('technique', 'Standard Activity')}</td><td style='padding:12px;'>{m['tactic']}</td></tr>" for m in (mitre_data or [{"id":"T1071","tactic":"C2","technique":"Application Layer Protocol"}])])}
            </table>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">3. Indicators of Compromise (IOCs)</h2>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px; margin:20px 0;">
                <div style="background:#0a0a0a; border:1px solid #222; padding:15px; border-radius:4px;">
                    <b style="color:{tlp_color}; font-size:11px;">IPV4 ADDRESSES</b>
                    <p style="font-family:'Courier New', monospace; font-size:12px;">{", ".join(iocs.get('ipv4', [])) or "No IPs identified"}</p>
                </div>
                <div style="background:#0a0a0a; border:1px solid #222; padding:15px; border-radius:4px;">
                    <b style="color:{tlp_color}; font-size:11px;">DOMAINS / HOSTS</b>
                    <p style="font-family:'Courier New', monospace; font-size:12px;">{", ".join(iocs.get('domain', [])) or "No domains identified"}</p>
                </div>
            </div>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">4. Detection & Hunting Guidance</h2>
            <div style="background:#111; border-radius:8px; padding:20px; margin-top:15px;">
                <b style="color:#00d4aa; font-size:12px;">MICROSOFT SENTINEL (KQL)</b>
                <pre style="background:#000; color:#00ff00; padding:15px; border-radius:4px; font-size:11px; overflow-x:auto;">{kql}</pre>
                
                <b style="color:#00d4aa; font-size:12px; display:block; margin-top:20px;">SPLUNK (SPL)</b>
                <pre style="background:#000; color:#00ff00; padding:15px; border-radius:4px; font-size:11px; overflow-x:auto;">{spl}</pre>
            </div>

            <h2 style="color:#fff; font-size:18px; margin-top:40px;">5. Infrastructure Visualization</h2>
            <div style="border:1px solid #222; border-radius:8px; overflow:hidden; margin-top:10px;">
                {map_html}
            </div>

            <div style="margin-top:60px; border-top:1px solid #222; padding-top:20px; text-align:center; font-size:10px; color:#444;">
                THIS IS AN AUTONOMOUS INTELLIGENCE PRODUCT. VERIFY DATA BEFORE DEPLOYMENT.<br>
                © 2026 CYBERDUDEBIVASH PVT. LTD. // GLOBAL OPERATIONS CENTER
            </div>
        </div>
    </div>
    """
    return html
