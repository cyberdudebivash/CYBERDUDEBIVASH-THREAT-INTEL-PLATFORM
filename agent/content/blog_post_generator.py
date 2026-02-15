#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v8.3
Stealth Elite: Professional Narrative Synthesis and Clean Headlines.
"""

def generate_headline(intel_items):
    """Clean, high-authority tactical headline."""
    if not intel_items:
        return "Autonomous Threat Intelligence Brief"
    return f"TACTICAL ADVISORY: {intel_items[0]['title']}"

def _generate_signatures(title, iocs):
    """Generates KQL, Sigma, and YARA logic."""
    domains = iocs.get('domain', [])
    kql = f"DeviceNetworkEvents | where RemoteUrl has_any (\"{', '.join(domains[:2])}\")"
    sigma = f"logsource: {{category: dns}}\ndetection: {{selection: {{query: {domains[:2]}}}, condition: selection}}"
    yara = f"rule CDB_Detection {{ strings: $s1 = \"{domains[0] if domains else 'cdb.intel'}\" condition: any of them }}"
    return kql, sigma, yara

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None, risk_score=7.0, actor_data=None, cve_data=None):
    """v8.3 Elite Template: Contextual Analyst Narrative & Pillar Architecture."""
    profile = actor_data.get('profile', {}) if actor_data else {}
    tracking_id = actor_data.get('tracking_id', 'UNC-CDB-99')
    tlp_color = "#ff3e3e" if risk_score >= 8.5 else "#00d4aa"
    kql, sigma, yara = _generate_signatures(intel_items[0]['title'], iocs)
    
    # Refined Narrative Deep-Dive
    # Replaces raw summaries with analyst observation framing
    analysis_narrative = ""
    for i, item in enumerate(intel_items[:3]):
        analysis_narrative += f"""
        <div style="margin-bottom:20px; padding-bottom:15px; border-bottom:1px solid #222;">
            <b style="color:#fff; font-size:14px;">Observation {i+1}: {item['title']}</b>
            <p style="color:#aaa; font-size:13px; line-height:1.6; margin-top:8px;">
                CDB sensors have identified tactical shifts within this cluster. 
                {item.get('summary', '')[:500]}
            </p>
        </div>
        """

    html = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Inter', sans-serif; border:1px solid #222; border-radius:12px; overflow:hidden;">
        <div style="background:{tlp_color}; color:#000; padding:15px; text-align:center; font-weight:bold; letter-spacing:4px; font-size:12px;">
            TLP:{'AMBER' if risk_score >= 8.5 else 'CLEAR'} // CDB-SENTINEL-GOC // v8.3 ELITE ADVISORY
        </div>

        <div style="padding:45px;">
            <h1 style="color:#fff; font-size:28px; letter-spacing:-1px; margin-bottom:30px;">{intel_items[0]['title']}</h1>
            
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-bottom:40px;">
                <div style="background:#111; padding:20px; border:1px solid #222; border-radius:8px;">
                    <h3 style="color:{tlp_color}; font-size:13px; margin-top:0;">1. INTELLIGENCE SNAPSHOT</h3>
                    <p style="font-size:13px; margin:5px 0;"><b>ACTOR ID:</b> {tracking_id}</p>
                    <p style="font-size:13px; margin:5px 0;"><b>CONFIDENCE:</b> {profile.get('confidence_score', 'MEDIUM')}</p>
                </div>
                <div style="background:#111; padding:20px; border:1px solid #222; border-radius:8px; text-align:center;">
                    <h3 style="color:{tlp_color}; font-size:13px; margin-top:0;">RISK SCORE: {risk_score}/10</h3>
                    <p style="font-size:11px; color:#555;">v8.3 STEALTH AUTHORITY NODE</p>
                </div>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">2. Advanced Campaign Analysis</h3>
            <div style="background:rgba(255,255,255,0.01); padding:30px; border-radius:8px; margin:20px 0;">
                {analysis_narrative}
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px; margin-top:40px;">3. Detection Engineering Center</h3>
            <div style="background:#0a0a0a; border:1px solid #222; padding:20px; border-radius:8px; margin-top:15px;">
                <b style="color:{tlp_color}; font-size:11px;">SIGMA (SIEM-AGNOSTIC)</b>
                <pre style="background:#000; color:#00ff00; padding:12px; border-radius:4px; font-size:11px; overflow-x:auto;">{sigma}</pre>
                <b style="color:{tlp_color}; font-size:11px; display:block; margin-top:15px;">KQL (AZURE SENTINEL)</b>
                <pre style="background:#000; color:#00ff00; padding:12px; border-radius:4px; font-size:11px; overflow-x:auto;">{kql}</pre>
            </div>

            <div style="margin-top:50px; text-align:center; font-size:10px; color:#444;">CYBERDUDEBIVASH GOC // v8.3 ELITE NODE</div>
        </div>
    </div>
    """
    return html
