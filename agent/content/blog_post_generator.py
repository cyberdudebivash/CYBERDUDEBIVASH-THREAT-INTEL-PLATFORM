#!/usr/bin/env python3
"""
blog_post_generator.py — CyberDudeBivash v7.2
Enterprise Content Engine: Standardized HTML with MITRE & STIX Context.
"""

def generate_headline(intel_items):
    if not intel_items:
        return "Daily Threat Intelligence Brief"
    return f"Threat Advisory: {intel_items[0]['title']}"

def generate_full_post_content(intel_items, iocs, pro_data, map_html, stix_id, mitre_data=None):
    """Generates the full HTML report for Blogger dispatch."""
    
    # NEW: Tactical Attribution Table
    mitre_section = ""
    if mitre_data:
        rows = "".join([
            f"<tr style='border-bottom:1px solid #333;'><td style='padding:10px;'>{m['id']}</td>"
            f"<td style='padding:10px;'>{m['tactic']}</td></tr>"
            for m in mitre_data
        ])
        mitre_section = f"""
        <div style="background:#0a0a0a; border:1px solid #00d4aa; padding:20px; border-radius:10px; margin-bottom:20px;">
            <h3 style="color:#00d4aa; margin-top:0;">[#] MITRE ATT&CK Mapping</h3>
            <table style="width:100%; color:#ccc; font-size:12px; border-collapse:collapse;">
                <tr style="text-align:left; color:#00d4aa; border-bottom:2px solid #00d4aa;">
                    <th style="padding:10px;">ID</th><th style="padding:10px;">Tactic</th>
                </tr>
                {rows}
            </table>
        </div>
        """

    # Forensic Metadata
    ioc_html = "<ul>" + "".join([f"<li><b>{k.upper()}:</b> {', '.join(v)}</li>" for k, v in iocs.items() if v]) + "</ul>"

    # Assemble Final Body
    html = f"""
    <div style="font-family:Arial, sans-serif; background:#050505; color:#e5e5e5; padding:20px;">
        <h2 style="color:#00d4aa;">Intelligence Advisory: {stix_id}</h2>
        <p style="color:#888;">Automated Forensic Triage by CyberDudeBivash Sentinel APEX</p>
        <hr style="border:0; border-top:1px solid #333;">
        
        {mitre_section}
        
        <h3>Forensic Indicators (IOCs)</h3>
        {ioc_html}
        
        <h3>Geospatial Context</h3>
        {map_html}
        
        <div style="margin-top:30px; padding:15px; background:#111; border-radius:5px;">
            <p style="font-size:12px; color:#555;">
                This report is machine-generated. Raw STIX 2.1 data is available via the 
                <a href="https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/" style="color:#00d4aa;">Command Center</a>.
            </p>
        </div>
    </div>
    """
    return html
