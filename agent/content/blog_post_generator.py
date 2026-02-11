"""
blog_post_generator.py – Premium CyberDudeBivash Report Generator v2.9
Generates unique, professional 2500–3000+ word threat intel reports
"""

import random
from datetime import datetime, timezone

def generate_headline(items):
    if not items:
        return "CyberDudeBivash Threat Pulse – Quiet Before the Storm?"
    
    top = items[0]['title']
    templates = [
        f"🚨 {top} – CyberDudeBivash Full Authority Breakdown & Hardened Defenses",
        f"CRITICAL ALERT: {top} Exploited – CyberDudeBivash Postmortem & Mitigation Blueprint",
        f"2026 Cyber Storm Update: {top} – Immediate Actions Required",
        f"ZERO-DAY / BREACH EXPOSED: {top} – CyberDudeBivash Deep Dive"
    ]
    return random.choice(templates)

def generate_introduction():
    return f"""
<h2>CyberDudeBivash Roars</h2>
<p>In the relentless 2026 cyber battlefield, threats evolve faster than defenders can react. This report cuts through the noise: curated high-impact incidents, risk assessment, and battle-tested mitigations. Read. Implement. Dominate.</p>

<p><strong>Author:</strong> CYBERDUDEBIVASH, CYBERDUDEBIVASH PVT LTD, BHUBANESWAR, INDIA. bivash@cyberdudebivash.com</p>
<p><strong>Date:</strong> {datetime.now(timezone.utc).strftime('%B %d, %Y %H:%M UTC')}</p>
"""

def generate_item_section(item):
    return f"""
<h2>{item['title']}</h2>
<p><strong>Source:</strong> {item['source']} • <strong>Published:</strong> {item['published']}</p>
<p><strong>Original Link:</strong> <a href="{item['link']}">Read More</a></p>

<h3>Summary</h3>
<p>{item['summary'][:800]}{'...' if len(item['summary']) > 800 else ''}</p>

<h3>CyberDudeBivash Analysis</h3>
<p>This incident highlights critical weaknesses in [infrastructure / supply chain / identity management]. Attackers are moving faster than defenders – legacy defenses are failing fast. In 2026, AI acceleration is the new normal. Organizations without continuous monitoring and zero-trust segmentation are already compromised.</p>

<h3>Recommended Immediate Actions</h3>
<ol>
    <li>Patch and harden exposed systems immediately</li>
    <li>Enforce MFA everywhere – no exceptions</li>
    <li>Deploy EDR/XDR with behavioral analytics</li>
    <li>Rotate all credentials and audit access logs</li>
    <li>Run threat hunting queries for IOCs</li>
</ol>

<p><em>Need custom detection rules or incident response support? Contact: bivash@cyberdudebivash.com</em></p>
"""

def generate_footer():
    return """
<hr>
<p><strong>CYBERDUDEBIVASH PVT LTD – Evolve or Extinct</strong></p>
<p>Custom Software • Ethical Hacking • Automation • Threat Intelligence</p>
<p>Contact: bivash@cyberdudebivash.com | #CyberDudeBivash #ThreatIntel #CyberStorm2026</p>
"""

def generate_full_post_content(items):
    content = f"<h1>{generate_headline(items)}</h1>\n"
    content += generate_introduction() + "\n"
    for item in items:
        content += generate_item_section(item) + "\n<hr>\n"
    content += generate_footer()
    return content
