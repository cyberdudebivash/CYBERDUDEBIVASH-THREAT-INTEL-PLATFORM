#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v7.4
Enterprise-Grade Intelligence Template: TLP, Diamond Model, and Multi-Tier Analysis.
"""

def generate_headline(intel_items):
    if not intel_items:
        return "Autonomous Threat Intelligence Brief"
    return f"Threat Advisory: {intel_items[0]['title']}"

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None, risk_score=5.0):
    """
    Generates a standardized NIST-style intelligence report.
    Includes TLP marking and Diamond Model attribution.
    """
    # P0 Task 3: TLP Classification
    tlp_color = "#ffbf00" if risk_score >= 7.0 else "#00d4aa" # Amber vs Green
    tlp_label = "TLP:AMBER" if risk_score >= 7.0 else "TLP:CLEAR"
    
    # P0 Task 4: Diamond Model Attribution
    # Extracting infrastructure and capabilities for the matrix
    infra_list = ", ".join(iocs.get('ipv4', [])[:5]) or "Internal/Cloud"
    capabilities = ", ".join([m['tactic'] for m in mitre_data]) if mitre_data else "General Exploitation"
    
    # P0 Task 5: Executive Summary vs Technical Deep-Dive
    summary_text = intel_items[0].get('summary', 'No summary available.')[:400]

    html_template = f"""
    <div style="background:#050505; color:#e5e5e5; font-family:'Inter', sans-serif; border:1px solid #1a1a1a; border-radius:12px; overflow:hidden;">
        
        <div style="background:{tlp_color}; color:#000; padding:10px; text-align:center; font-weight:900; letter-spacing:3px; font-size:12px;">
            {tlp_label} // GOC-APEX-VERIFIED-INTELLIGENCE
        </div>

        <div style="padding:30px;">
            <h1 style="margin-top:0; color:#fff; font-size:28px; letter-spacing:-1px;">{intel_items[0]['title']}</h1>
            <p style="color:#666; font-size:11px; text-transform:uppercase;">ID: {stix_id} | Risk: {risk_score}/10 | Generated: {stix_id.split('-')[-1]}</p>

            <div style="background:rgba(255,255,255,0.03); border-left:4px solid {tlp_color}; padding:20px; margin:25px 0;">
                <h3 style="color:{tlp_color}; margin-top:0; font-size:14px; text-transform:uppercase;">Executive Summary (BLUF)</h3>
                <p style="line-height:1.6; color:#ccc;">{summary_text}...</p>
            </div>

            <h3 style="color:#fff; font-size:16px; border-bottom:1px solid #222; padding-bottom:10px;">Tactical Correlation (Diamond Model)</h3>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px; margin:20px 0;">
                <div style="background:#111; padding:15px; border-radius:8px;">
                    <b style="color:{tlp_color}; font-size:10px; text-transform:uppercase;">Adversary / Capability</b>
                    <p style="margin:5px 0; font-size:13px;">{capabilities}</p>
                </div>
                <div style="background:#111; padding:15px; border-radius:8px;">
                    <b style="color:{tlp_color}; font-size:10px; text-transform:uppercase;">Infrastructure / Assets</b>
                    <p style="margin:5px 0; font-size:13px; font-family:monospace;">{infra_list}</p>
                </div>
            </div>

            <div style="margin:30px 0;">
                <h3 style="color:#fff; font-size:16px;">Visual Geographic Intelligence</h3>
                <div style="background:#111; padding:10px; border-radius:10px;">
                    {map_html}
                </div>
            </div>

            <details style="background:#0a0a0a; border:1px solid #1a1a1a; border-radius:8px; padding:15px; cursor:pointer;">
                <summary style="color:{tlp_color}; font-weight:bold; font-size:13px;">[+] Open Technical Annex (IOCs & Raw Data)</summary>
                <div style="margin-top:15px; font-family:monospace; font-size:12px; color:#888;">
                    { "".join([f"<p><b>{k.upper()}:</b> {', '.join(v)}</p>" for k,v in iocs.items() if v]) }
                </div>
            </details>

            <div style="margin-top:40px; border-top:1px solid #222; padding-top:20px; font-size:10px; color:#444; text-align:center;">
                This document is a machine-generated intelligence advisory from <b>CyberDudeBivash Pvt. Ltd.</b> 
                Unauthorized distribution of {tlp_label} data is prohibited.
            </div>
        </div>
    </div>
    """
    return html_template
