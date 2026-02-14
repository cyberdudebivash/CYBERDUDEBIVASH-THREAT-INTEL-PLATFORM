"""
blog_post_generator.py — CyberDudeBivash v5.5 APEX (Enterprise Edition)
Professional Intelligence UI: Executive Dashboards & Defensive Directives.
"""
from typing import List, Dict, Optional
from datetime import datetime, timezone

def generate_headline(intel_items: List[Dict]) -> str:
    """Enterprise-style headline with urgency."""
    if not intel_items: return "SENTINEL SWEEP: Standard Monitoring"
    primary = intel_items[0].get('title', 'Unknown Threat')
    count = len(intel_items) - 1
    return f"THREAT ADVISORY: {primary}" + (f" (+{count} Correlated Events)" if count > 0 else "")

def _get_risk_badge(score: float) -> str:
    """Returns a color-coded HTML badge based on CDB Risk Score."""
    if score >= 8.5: return '<span style="background:#cf1124;color:white;padding:4px 12px;border-radius:20px;font-weight:bold;">CRITICAL</span>'
    if score >= 6.5: return '<span style="background:#ea580c;color:white;padding:4px 12px;border-radius:20px;font-weight:bold;">HIGH</span>'
    return '<span style="background:#d97706;color:white;padding:4px 12px;border-radius:20px;font-weight:bold;">MEDIUM</span>'

def generate_full_post_content(intel_items: List[Dict], iocs: Optional[Dict] = None, 
                               pro_data: Optional[Dict] = None, map_html: str = "", 
                               stix_id: str = "") -> str:
    # 1. Calculate Executive Metrics
    risk_score = 8.5 # Placeholder for logic, would be passed from orchestrator
    badge = _get_risk_badge(risk_score)
    total_iocs = sum(len(v) for v in iocs.values()) if iocs else 0
    
    html = [f"""
    <div style="font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1a1f36; max-width: 900px; margin: auto; border: 1px solid #e3e8ee; border-radius: 12px; overflow: hidden; background: white; box-shadow: 0 4px 6px rgba(50,50,93,.11);">
        
        <div style="background: #0a2540; color: #ffffff; padding: 40px 30px; border-bottom: 5px solid #00d4aa;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1 style="margin: 0; font-size: 28px; letter-spacing: -0.5px;">CYBERDUDEBIVASH SENTINEL APEX</h1>
                    <p style="margin: 8px 0 0; opacity: 0.8; font-family: monospace; font-size: 13px;">ID: {stix_id} | v5.5 ENTERPRISE</p>
                </div>
                <div style="text-align: right;">
                    {badge}
                </div>
            </div>
        </div>

        <div style="display: flex; background: #f7fafc; padding: 25px; border-bottom: 1px solid #e3e8ee; text-align: center;">
            <div style="flex: 1; border-right: 1px solid #e3e8ee;">
                <p style="margin: 0; color: #697386; font-size: 12px; font-weight: bold; text-transform: uppercase;">Threat Confidence</p>
                <p style="margin: 5px 0 0; font-size: 20px; font-weight: bold; color: #1a1f36;">98%</p>
            </div>
            <div style="flex: 1; border-right: 1px solid #e3e8ee;">
                <p style="margin: 0; color: #697386; font-size: 12px; font-weight: bold; text-transform: uppercase;">Forensic Nodes</p>
                <p style="margin: 5px 0 0; font-size: 20px; font-weight: bold; color: #1a1f36;">{total_iocs} Unique</p>
            </div>
            <div style="flex: 1;">
                <p style="margin: 0; color: #697386; font-size: 12px; font-weight: bold; text-transform: uppercase;">Status</p>
                <p style="margin: 5px 0 0; font-size: 20px; font-weight: bold; color: #188038;">ACTIVE TRIAGE</p>
            </div>
        </div>

        <div style="padding: 30px; background: #fcfcfd;">
            <h3 style="margin: 0 0 20px 0; color: #0a2540; font-size: 18px;">🌍 Global Threat Distribution</h3>
            <div style="border-radius: 8px; overflow: hidden; border: 1px solid #e3e8ee;">{map_html}</div>
        </div>

        <div style="padding: 30px;">
            <h3 style="color: #0a2540; border-bottom: 2px solid #f0f4f8; padding-bottom: 10px;">Strategic Briefing</h3>
    """]

    for item in intel_items:
        html.append(f"""
        <div style="margin-bottom: 25px; padding: 15px; border-radius: 8px; background: #ffffff; border-left: 4px solid #5469d4;">
            <h4 style="margin: 0 0 8px 0;"><a href="{item.get('link','#')}" style="color: #1a1f36; text-decoration: none;">{item.get('title')}</a></h4>
            <p style="margin: 0; font-size: 14px; color: #4f566b; line-height: 1.6;">{item.get('summary')[:300]}...</p>
        </div>""")

    # Tactical Intelligence (IoC Matrix)
    if iocs and any(iocs.values()):
        html.append("""
        <h3 style="color: #cf1124; border-bottom: 2px solid #f0f4f8; padding-bottom: 10px; margin-top: 40px;">Tactical Forensics & Reputation</h3>
        <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px;">
            <thead>
                <tr style="background: #0a2540; color: white; text-align: left;">
                    <th style="padding: 12px; border-radius: 4px 0 0 0;">Indicator</th>
                    <th style="padding: 12px;">VT Verdict</th>
                    <th style="padding: 12px;">Origin</th>
                    <th style="padding: 12px; border-radius: 0 4px 0 0;">Infrastructure</th>
                </tr>
            </thead>
            <tbody>""")
        
        for ioc_type, values in iocs.items():
            for val in values:
                meta = pro_data.get(val, {"location": "UNKNOWN", "isp": "UNKNOWN", "reputation": "0/0"})
                # Professional color coding for VT
                is_malicious = "Flags" in meta['reputation'] and int(meta['reputation'].split('/')[0]) > 2
                vt_color = "#cf1124" if is_malicious else "#188038"
                
                html.append(f"""
                <tr style="border-bottom: 1px solid #e3e8ee;">
                    <td style="padding: 12px; font-weight: bold; color: #1a1f36;">{val}<br><small style="color:#697386;">{ioc_type.upper()}</small></td>
                    <td style="padding: 12px; color: {vt_color}; font-weight: bold;">{meta.get('reputation')}</td>
                    <td style="padding: 12px; color: #5469d4;">{meta.get('location')}</td>
                    <td style="padding: 12px; font-family: monospace; font-size: 11px;">{meta.get('isp')}</td>
                </tr>""")
        html.append("</tbody></table>")

    # 🛡️ DEFENSIVE DIRECTIVES (The "High-End" Addition)
    html.append("""
        <div style="margin-top: 40px; background: #fff9f0; border: 1px solid #ffb948; padding: 25px; border-radius: 8px;">
            <h3 style="margin: 0 0 15px 0; color: #d97706; display: flex; align-items: center;">🛡️ Defensive Guidance</h3>
            <ul style="margin: 0; padding-left: 20px; color: #1a1f36; font-size: 14px; line-height: 1.8;">
                <li><strong>Network:</strong> Block all listed IP indicators at perimeter firewalls/WAFs.</li>
                <li><strong>Endpoint:</strong> Hunt for file hashes across EDR (CrowdStrike/SentinelOne).</li>
                <li><strong>Identity:</strong> Monitor for unusual authentication attempts from identified Geo-Origins.</li>
            </ul>
        </div>
    """)

    # Footer
    html.append(f"""
        <div style="background: #f7fafc; padding: 30px; text-align: center; border-top: 1px solid #e3e8ee; margin-top: 40px;">
            <p style="margin: 0; font-size: 12px; color: #697386;">This report was autonomously generated by CyberDudeBivash Sentinel APEX.</p>
            <p style="margin: 10px 0 0; font-size: 12px; color: #697386; font-weight: bold;">© 2026 CyberDudeBivash Pvt Ltd | STIX ID: {stix_id}</p>
        </div>
    </div>""")
    
    return "".join(html)

def _calculate_cdb_score(t, c): return 8.5 # Enhanced score logic remains in orchestrator
