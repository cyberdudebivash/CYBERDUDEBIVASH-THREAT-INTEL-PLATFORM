#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v8.4
Full Spectrum Edition: Long-form Technical Dossiers with Structured IOCs.
"""

def generate_headline(intel_items):
    """Clean, high-authority tactical headline for public consumption."""
    if not intel_items:
        return "Autonomous Threat Intelligence Brief"
    return f"TACTICAL ADVISORY: {intel_items[0]['title']}"

def _generate_signatures(title, iocs):
    """Generates mandatory SIEM and EDR logic for the Detection Section."""
    domains = iocs.get('domain', [])
    ips = iocs.get('ipv4', [])
    
    # Azure Sentinel (KQL)
    kql = f"DeviceNetworkEvents | where RemoteUrl has_any (\"{', '.join(domains[:2])}\") | summarize count() by DeviceName"
    
    # SIEM-Agnostic Sigma
    sigma = f"title: CDB-Sentinel-{title[:20]}\nlogsource: {{category: dns}}\ndetection:\n  selection: {{query: {domains[:2]}}}\n  condition: selection"
    
    # Forensic YARA
    yara = f"rule CDB_{title[:10].replace(' ','_')} {{\n    meta:\n        author = \"CyberDudeBivash GOC\"\n    strings:\n        $s1 = \"{ips[0] if ips else '127.0.0.1'}\" ascii wide\n    condition:\n        any of them\n}}"
    
    return kql, sigma, yara

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None, risk_score=7.0, actor_data=None, cve_data=None):
    """v8.4 Template: Long-form structural alignment with 6 mandatory pillars."""
    profile = actor_data.get('profile', {}) if actor_data else {}
    tracking_id = actor_data.get('tracking_id', 'UNC-CDB-99')
    tlp_color = "#ff3e3e" if risk_score >= 8.5 else "#00d4aa"
    kql, sigma, yara = _generate_signatures(intel_items[0]['title'], iocs)
    
    # SECTION 3: Deep Technical Analysis Expansion
    tech_details = "".join([f"<div style='margin-bottom:25px;'><b style='color:#fff; font-size:15px;'>Technical Observation: {i['title']}</b><p style='color:#aaa; font-size:14px; line-height:1.8; margin-top:8px;'>{i.get('summary', 'Forensic details pending.')}</p></div>" for i in intel_items])

    # SECTION 4: Structured Machine-Readable IOCs
    ioc_list = "".join([f"<li style='font-family:monospace; margin-bottom:5px;'>{ip}</li>" for ip in iocs.get('ipv4', [])])
    domain_list = "".join([f"<li style='font-family:monospace; margin-bottom:5px;'>{dom}</li>" for dom in iocs.get('domain', [])])

    html = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Inter', sans-serif; border:1px solid #222; border-radius:12px; overflow:hidden; max-width:900px; margin:auto; box-shadow: 0 20px 50px rgba(0,0,0,0.5);">
        
        <div style="background:{tlp_color}; color:#000; padding:15px; text-align:center; font-weight:bold; letter-spacing:4px; font-size:12px;">
            TLP:{'AMBER' if risk_score >= 8.5 else 'CLEAR'} // CDB-SENTINEL-GOC // v8.4 FULL SPECTRUM
        </div>
        <div style="padding:45px;">
            <h1 style="color:#fff; font-size:32px; letter-spacing:-1.5px; margin-bottom:5px;">{intel_items[0]['title']}</h1>
            <p style="color:#555; font-size:12px; text-transform:uppercase;">Advisory ID: {stix_id} | Risk Score: {risk_score}/10</p>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">1. Executive Summary</h2>
            <div style="background:rgba(255,255,255,0.02); border-left:4px solid {tlp_color}; padding:20px; margin:20px 0;">
                <p style="line-height:1.7; color:#ccc; font-size:14px;">
                    CDB Sentinel has identified a significant campaign associated with <b>{tracking_id}</b>. 
                    This activity is characterized by tactical sophistication in infrastructure rotation and 
                    the targeting of high-value enterprise cloud environments. Urgent review of the 
                    provided indicators and detection playbooks is recommended to mitigate potential exposure.
                </p>
            </div>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">2. Technical Analysis & Deep-Dive</h2>
            <div style="margin:20px 0;">
                {tech_details}
            </div>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">3. Indicators of Compromise (IOCs)</h2>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin:20px 0;">
                <div style="background:#0a0a0a; padding:20px; border:1px solid #222; border-radius:8px;">
                    <b style="color:{tlp_color}; font-size:11px; text-transform:uppercase;">Network: IPv4 Addresses</b>
                    <ul style="list-style:none; padding:15px 0 0 0; color:#00d4aa; font-size:13px;">{ioc_list if ioc_list else "<li>No IP indicators extracted.</li>"}</ul>
                </div>
                <div style="background:#0a0a0a; padding:20px; border:1px solid #222; border-radius:8px;">
                    <b style="color:{tlp_color}; font-size:11px; text-transform:uppercase;">Network: Domains / Hosts</b>
                    <ul style="list-style:none; padding:15px 0 0 0; color:#00d4aa; font-size:13px;">{domain_list if domain_list else "<li>No domain indicators extracted.</li>"}</ul>
                </div>
            </div>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">4. Detection & Hunting Playbooks</h2>
            <div style="background:#000; border:1px solid #222; padding:30px; border-radius:8px; margin-top:20px;">
                <div style="margin-bottom:25px;">
                    <b style="color:{tlp_color}; font-size:11px; text-transform:uppercase; letter-spacing:1px;">SIEM SIGMA RULE</b>
                    <pre style="background:#0a0a0a; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; margin-top:10px; border:1px solid #111; overflow-x:auto;">{sigma}</pre>
                </div>
                <div>
                    <b style="color:{tlp_color}; font-size:11px; text-transform:uppercase; letter-spacing:1px;">AZURE SENTINEL (KQL)</b>
                    <pre style="background:#0a0a0a; color:#00ff00; padding:15px; border-radius:6px; font-size:11px; margin-top:10px; border:1px solid #111; overflow-x:auto;">{kql}</pre>
                </div>
            </div>

            <h2 style="color:#fff; font-size:18px; border-bottom:1px solid #333; padding-bottom:10px; margin-top:40px;">5. Strategic Conclusion</h2>
            <div style="margin:20px 0;">
                <p style="color:#aaa; line-height:1.7; font-size:14px;">
                    The persistence of <b>{tracking_id}</b> across multiple clusters underscores the need for a 
                    multi-layered defense-in-depth strategy. Organizations should pivot from reactive 
                    blocklists to proactive threat hunting using the provided Sigma and KQL logic. 
                    CDB GOC continues to monitor these infrastructure nodes for further tactical evolution.
                </p>
            </div>

            <div style="margin-top:60px; border-top:1px solid #222; padding-top:20px; text-align:center; font-size:10px; color:#333; letter-spacing:2px;">
                CYBERDUDEBIVASH GLOBAL OPERATIONS CENTER // v8.4 FULL SPECTRUM
            </div>
        </div>
    </div>
    """
    return html
