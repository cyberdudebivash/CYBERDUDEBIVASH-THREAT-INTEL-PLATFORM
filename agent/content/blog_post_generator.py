"""
blog_post_generator.py — CyberDudeBivash Premium Report Generator v16.8
ENHANCEMENT: AI Risk Scoring Engine & Enterprise Severity Badging.

© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import random
import hashlib
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional

from agent.config import BRAND, BLOGS, COLORS, FONTS

# ═══════════════════════════════════════════════════
# UTILITY HELPERS
# ═══════════════════════════════════════════════════

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%B %d, %Y — %H:%M UTC")

def _calculate_cdb_score(title: str, summary: str) -> float:
    """Calculates a 0.0-10.0 risk score based on technical severity factors."""
    score = 2.0  # Base visibility score
    text = (title + " " + summary).lower()
    
    # Criticality Multipliers
    if any(w in text for w in ["zero-day", "0-day", "no patch", "actively exploited"]): score += 3.5
    elif any(w in text for w in ["exploit available", "poc", "proof of concept"]): score += 2.5
    elif "cve-" in text: score += 1.0
    
    # Impact Multipliers
    if any(w in text for w in ["rce", "remote code execution", "unauthenticated"]): score += 2.0
    if any(w in text for w in ["ransomware", "exfiltration", "breach"]): score += 1.5
    if any(w in text for w in ["critical infrastructure", "government", "finance"]): score += 1.0
    
    return round(min(10.0, score), 1)

def _get_score_color(score: float) -> str:
    if score >= 8.5: return "#ff3e3e"  # Critical Red
    if score >= 6.5: return "#ff9f43"  # High Orange
    if score >= 4.0: return "#feca57"  # Medium Yellow
    return "#00e5c3"  # Low Cyan (Accent)

def _severity_from_score(score: float) -> str:
    if score >= 8.5: return "CRITICAL"
    if score >= 6.5: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

# ═══════════════════════════════════════════════════
# HEADLINE GENERATOR
# ═══════════════════════════════════════════════════

def generate_headline(items: List[Dict]) -> str:
    if not items:
        return "CyberDudeBivash Threat Pulse — Quiet Before the Storm?"

    top = items[0]["title"]
    if len(top) > 90:
        top = top[:87] + "..."

    templates = [
        f"🚨 CDB-ALERT: {top} — Priority Analysis",
        f"CRITICAL INTEL: {top} — Defense Blueprint",
        f"ZERO-DAY WATCH: {top} — Expert Mitigation",
        f"THREAT ADVISORY: {top} — SOC Response Playbook",
    ]
    return random.choice(templates)

# ═══════════════════════════════════════════════════
# INLINE STYLE SYSTEM
# ═══════════════════════════════════════════════════

S = {
    "h1": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:28px;font-weight:800;line-height:1.25;margin:0 0 16px 0;",
    "h2": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:22px;font-weight:700;line-height:1.3;margin:32px 0 12px 0;padding-bottom:8px;border-bottom:2px solid {COLORS['border']};",
    "p": f"margin:0 0 16px 0;color:{COLORS['text']};line-height:1.8;font-size:17px;",
    "muted": f"color:{COLORS['text_muted']};font-size:14px;line-height:1.6;",
    "badge": f"display:inline-block;padding:4px 12px;border-radius:100px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;",
    "card": f"background:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:12px;padding:24px;margin:20px 0;",
    "link": f"color:{COLORS['accent']};text-decoration:none;font-weight:600;",
}

# ═══════════════════════════════════════════════════
# UI COMPONENT GENERATORS
# ═══════════════════════════════════════════════════

def _risk_meter_html(score: float) -> str:
    color = _get_score_color(score)
    label = _severity_from_score(score)
    return f"""
<div style="background:rgba(10,14,23,0.8); border:1px solid {color}; padding:15px; border-radius:12px; margin-bottom:25px; box-shadow:0 0 15px rgba({color},0.1);">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
    <span style="color:{color}; font-family:'JetBrains Mono'; font-weight:900; font-size:13px; letter-spacing:2px;">CDB-RISK INDEX: {score}/10.0</span>
    <span style="background:{color}; color:#000; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:900;">{label}</span>
  </div>
  <div style="width:100%; background:#1e293b; height:6px; border-radius:3px; overflow:hidden;">
    <div style="width:{score*10}%; background:{color}; height:100%; box-shadow:0 0 10px {color};"></div>
  </div>
</div>
"""

def _incident_section(item: Dict, index: int) -> str:
    title = item.get("title", "Unknown Incident")
    summary = re.sub(r'<[^>]+>', '', item.get("summary", ""))
    link = item.get("link", "#")
    score = _calculate_cdb_score(title, summary)
    color = _get_score_color(score)

    return f"""
<div style="{S['card']}border-left:4px solid {color};">
  <div style="margin-bottom:10px;">
    <span style="{S['badge']}background:rgba(255,255,255,0.05);color:{color};border:1px solid {color};">Unit #{index} · Score {score}</span>
  </div>
  <h3 style="color:white; font-size:19px; font-weight:700; margin:0 0 10px 0;">{title}</h3>
  <p style="{S['p']}">{summary[:500]}...</p>
  <p><a href="{link}" style="{S['link']}" target="_blank">View Technical Source →</a></p>
</div>
"""

# ═══════════════════════════════════════════════════
# MAIN PUBLIC API
# ═══════════════════════════════════════════════════

def generate_full_post_content(items: List[Dict]) -> str:
    headline = generate_headline(items)
    
    # Calculate global post risk
    full_corpus = " ".join(i.get("title", "") + " " + i.get("summary", "") for i in items)
    global_score = _calculate_cdb_score("", full_corpus)
    risk_meter = _risk_meter_html(global_score)
    
    sections = []
    for idx, item in enumerate(items, start=1):
        sections.append(_incident_section(item, idx))

    final_body = "\n".join(sections)

    # V17.0 ENHANCED WRAPPER
    wrapped_body = f"""
<div class="forced-page-content">
  <div class="ai-badge">AI-ENGINE: CDB-SENTINEL v16.8</div>
  
  <h1 style="{S['h1']}">{headline}</h1>
  <p style="{S['muted']} margin-bottom:20px;">
    <strong>Triage Date:</strong> {_utc_now()} | 
    <strong>Classification:</strong> PROPRIETARY INTEL | 
    <strong>Status:</strong> ACTIONABLE
  </p>

  {risk_meter}

  <div class="hero-box" style="margin-bottom:30px; border-left:6px solid #00e5c3;">
    <h2 style="margin-top:0; color:white; font-size:20px;">Automated Triage Assessment</h2>
    <p style="color:#cbd5e1; font-size:15px;">
      The <strong>CYBERDUDEBIVASH THREAT INTEL PLATFORM</strong> has identified 
      {len(items)} relevant threat indicators. Organizations are advised to verify 
      internal telemetry against the CDB-Risk Index provided above.
    </p>
  </div>

  {final_body}

  <div style="margin-top:40px; border-top:1px solid #1e293b; padding-top:20px; text-align:center;">
    <p style="font-size: 13px; color: #94a3b8;">
      © 2026 <b>CYBERDUDEBIVASH PVT LTD</b>.
      <br/>For SOC Integration or Custom Intel Feeds: 
      <a href="https://wa.me/918179881447" 
         style="color: #00e5c3; text-decoration: none; font-weight: 700;">
         CONTACT HQ
      </a>
    </p>
  </div>
</div>
"""
    return wrapped_body
