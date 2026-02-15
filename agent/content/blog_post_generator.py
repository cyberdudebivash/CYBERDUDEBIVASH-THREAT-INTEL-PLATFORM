#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v8.2
Elite Template: Attribution Profile, CVE Metrics, and Multi-Platform Detection.
"""

def generate_headline(intel_items):
    return f"TACTICAL ADVISORY: {intel_items[0]['title']}"

def _generate_exploit_chain_visual():
    """Tactical kill-chain diagram for SOC comprehension."""
    return (
        "[RECON] --> [EXPLOIT] --> [STAGING] --> [C2] --> [EXFIL]\n"
        "   |           |            |          |         |\n"
        "Scanning    RCE (CVE)    Payload     Beacon    Data"
    )

def _generate_signatures(title, iocs):
    """Generates mandatory Sigma and YARA logic."""
    domains = iocs.get('domain', [])
    ips = iocs.get('ipv4', [])
    
    # Sigma (Log Source Defense)
    sigma = f"title: CDB-Sentinel-{title[:20]}\nlogsource: {{category: dns}}\ndetection:\n  selection: {{query: {domains[:2]}}}\n  condition: selection"
    
    # YARA (Forensic Classification)
    yara = f"rule CDB_{title[:10].replace(' ','_')} {{\n    meta:\n        author = \"CyberDudeBivash GOC\"\n    strings:\n        $s1 = \"{ips[0] if ips else '127.0.0.1'}\" ascii wide\n    condition:\n        any of them\n}}"
    
    # KQL (Cloud Native)
    kql = f"DeviceNetworkEvents | where RemoteUrl has_any (\"{', '.join(domains[:2])}\") | summarize count() by DeviceName"
    
    return kql, sigma, yara

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None, risk_score=7.0, actor_data=None, cve_data=None):
    """Final enterprise layout following Tier-1 vendor standards."""
    profile = actor_data.get('profile', {}) if actor_data else {}
    tracking_id = actor_data.get('tracking_id', 'UNC-CDB-99')
    tlp_color = "#ff3e3e" if risk_score >= 8.5 else "#00d4aa"
    kql, sigma, yara = _generate_signatures(intel_items[0]['title'], iocs)
    
    intel_details = "".join([f"<li style='margin-bottom:12px;'><b>{i['title']}:</b> {i.get('summary', '')[:500]}</li>" for i in intel_items])

    html = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Inter', sans-serif; border:1px solid #222; border-radius:12px; overflow:hidden; box-shadow: 0 20px 50px rgba(0,0,0,0.6);">
        <div style="background:{tlp_color}; color:#000; padding:15px; text-align:center; font-weight:bold; letter-spacing:4px; font-size:12px;">
            TLP:{'AMBER' if risk_score >= 8.5 else 'CLEAR'} // CDB-SENTINEL-GOC // v8.2 ELITE ADVISORY
        </div>

        <div style="padding:45px;">
            <h1 style="color:#fff; font-size:28px; letter-spacing:-1px;">{intel_items[0]['title']}</h1>
            
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin:30px 0;">
                <div style="background:#111; padding:20px; border:1px solid #222; border-radius:8px;">
                    <h3 style="color:{tlp_color}; font-size:13px; margin-top:0;">1. INTELLIGENCE SNAPSHOT</h3>
                    <p style="font-size:13px; margin:5px 0;"><b>ACTOR ID:</b> {tracking_id}</p>
                    <p style="font-size:13px; margin:5px 0;"><b>CONFIDENCE:</b> {profile.get('confidence_score', 'MEDIUM')}</p>
                </div>
                <div style="background:#111; padding:20px; border:1px solid #222; border-radius:8px; text-align:center;">
                    <h3 style="color:{tlp_color}; font-size:13px; margin-top:0;">RISK SCORE: {risk_score}/10</h3>
                    <p style="font-size:11px; color:#555;">CDB-FRAMEWORK V4.0 (CVSS ALIGNED)</p>
                </div>
            </div>

            <div style="background:rgba(255,255,255,0.02); border:1px solid #333; padding:25px; border-radius:8px; margin-bottom:30px;">
                <h3 style="color:#fff; font-size:16px; margin-top:0;">2. THREAT ACTOR PROFILE: {tracking_id}</h3>
                <p style="font-size:13px; color:#ccc;"><b>Known Aliases:</b> {", ".join(profile.get('alias', ['UNC-Cluster']))} | <b>Motivation:</b> {profile.get('motivation', 'Espionage')}</p>
            </div>

            {"".join([f'''<div style="background:rgba(255,255,255,0.02); border:1px solid #333; padding:25px; border-radius:8px; margin-bottom:30px;">
                <h3 style="color:#fff; font-size:16px; margin-top:0;">3. VULNERABILITY INTEL: {c['id']}</h3>
                <p style="font-size:13px; color:#ccc;"><b>CVSS:</b> {c['cvss_v4']} | <b>EPSS:</b> {c['epss_score']}</p>
                <pre style="background:#000; color:#00d4aa; padding:15px; border-radius:4px; font-size:11px; margin-top:10px;">{_generate_exploit_chain_visual()}</pre>
            </div>''' for c in ([cve_data] if cve_data else [])])}

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">4. Advanced Detection & Playbooks</h3>
            <div style="background:#0a0a0a; border:1px solid #222; padding:20px; border-radius:8px; margin-top:15px;">
                <b style="color:{tlp_color}; font-size:11px;">SIGMA (SIEM-AGNOSTIC)</b>
                <pre style="background:#000; color:#00ff00; padding:12px; border-radius:4px; font-size:11px; overflow-x:auto;">{sigma}</pre>
                <b style="color:{tlp_color}; font-size:11px; display:block; margin-top:15px;">KQL (AZURE SENTINEL)</b>
                <pre style="background:#000; color:#00ff00; padding:12px; border-radius:4px; font-size:11px; overflow-x:auto;">{kql}</pre>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">5. Technical Intelligence Deep-Dive</h3>
            <ul style="color:#ccc; font-size:13px; line-height:1.7;">{intel_details}</ul>

            <div style="margin-top:50px; text-align:center; font-size:10px; color:#444;">CYBERDUDEBIVASH GOC // v8.2 ELITE NODE</div>
        </div>
    </div>
    """
    return html
