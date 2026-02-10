"""
blog_post_generator.py – Premium CyberDudeBivash Report Generator
"""

import random
from datetime import datetime, timezone

def generate_headline(items):
    if not items:
        return "CyberDudeBivash Threat Pulse – Quiet in the Shadows"
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
<p>In the relentless 2026 cyber battlefield, threats evolve hourly. This report distills the most critical signals: curated intel, risk assessment, and battle-tested mitigations. Read. Act. Survive.</p>
<p><strong>Author:</strong> Bivash Kumar Nayak – CyberDudeBivash | Cybersecurity Automation Specialist | Revonesoft Technologies Pvt. Ltd.</p>
<p><strong>Date:</strong> {datetime.now(timezone.utc).strftime('%B %d, %Y %H:%M UTC')}</p>
"""

def generate_item_section(item):
    return f"""
<h2>{item['title']}</h2>
<p><strong>Source:</strong> {item['source']} • <strong>Published:</strong> {item['published']}</p>
<p><a href="{item['link']}">Read Original</a></p>

<h3>Summary</h3>
<p>{item['summary'][:600]}{'...' if len(item['summary']) > 600 else ''}</p>

<h3>Analysis</h3>
<p>This highlights gaps in [infrastructure / patching / trust]. AI acceleration is changing the game – legacy defenses are failing fast.</p>

<h3>Mitigations</h3>
<ol>
    <li>Patch immediately</li>
    <li>Enforce MFA</li>
    <li>Deploy EDR/behavioral detection</li>
    <li>Rotate creds & audit logs</li>
    <li>Hunt IOCs</li>
</ol>
"""

def generate_footer():
    return """
<hr>
<p><strong>CyberDudeBivash Pvt Ltd</strong> – Evolve or Extinct</p>
<p>Contact: contact@cyberdudebivash.com | #CyberDudeBivash #ThreatIntel #CyberStorm2026</p>
"""

def generate_full_post_content(items):
    content = f"<h1>{generate_headline(items)}</h1>\n"
    content += generate_introduction() + "\n"
    for item in items:
        content += generate_item_section(item) + "\n<hr>\n"
    content += generate_footer()
    return content
