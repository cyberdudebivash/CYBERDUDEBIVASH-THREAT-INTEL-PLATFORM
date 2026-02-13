"""
blog_post_generator.py — CyberDudeBivash Premium Report Generator v16.6
FIX: Restored generate_headline to public scope to resolve Pipeline failure.

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


def _severity_from_content(text: str) -> str:
    t = text.lower()
    if any(w in t for w in ["critical", "zero-day", "0day", "rce", "actively exploited", "emergency"]):
        return "CRITICAL"
    if any(w in t for w in ["high", "ransomware", "breach", "exploit", "malware", "backdoor"]):
        return "HIGH"
    if any(w in t for w in ["medium", "vulnerability", "cve-", "patch"]):
        return "MEDIUM"
    return "LOW"


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": COLORS["critical"],
        "HIGH": COLORS["high"],
        "MEDIUM": COLORS["medium"],
        "LOW": COLORS["low"],
    }.get(severity, COLORS["text_muted"])


# ═══════════════════════════════════════════════════
# HEADLINE GENERATOR (Exposed to Public Scope)
# ═══════════════════════════════════════════════════

def generate_headline(items: List[Dict]) -> str:
    """Public function required by sentinel_blogger.py"""
    if not items:
        return "CyberDudeBivash Threat Pulse — Quiet Before the Storm?"

    top = items[0]["title"]
    if len(top) > 90:
        top = top[:87] + "..."

    templates = [
        f"🚨 CRITICAL: {top} — Full Breakdown & Defense Blueprint",
        f"ALERT: {top} — CyberDudeBivash Authority Analysis",
        f"2026 Cyber Storm: {top} — Immediate Actions Required",
        f"ZERO-DAY EXPOSED: {top} — Deep Dive & Mitigation",
        f"BREAKING: {top} — What You Must Do Right Now",
        f"THREAT INTEL: {top} — Expert Analysis & Hardening Guide",
    ]
    return random.choice(templates)


# ═══════════════════════════════════════════════════
# INLINE STYLE SYSTEM
# ═══════════════════════════════════════════════════

S = {
    "h1": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:28px;font-weight:800;line-height:1.25;margin:0 0 16px 0;",
    "h2": f"font-family:{FONTS['heading']};color:{COLORS['white']};font-size:22px;font-weight:700;line-height:1.3;margin:32px 0 12px 0;padding-bottom:8px;border-bottom:2px solid {COLORS['border']};",
    "h3": f"font-family:{FONTS['heading']};color:{COLORS['accent']};font-size:18px;font-weight:600;line-height:1.35;margin:24px 0 8px 0;padding-left:12px;border-left:3px solid {COLORS['accent']};",
    "p": f"margin:0 0 16px 0;color:{COLORS['text']};line-height:1.8;font-size:17px;",
    "muted": f"color:{COLORS['text_muted']};font-size:14px;line-height:1.6;",
    "badge": f"display:inline-block;padding:4px 12px;border-radius:100px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;",
    "card": f"background:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:12px;padding:24px;margin:20px 0;",
    "link": f"color:{COLORS['accent']};text-decoration:none;font-weight:600;",
}


# ═══════════════════════════════════════════════════
# SECTION GENERATORS
# ═══════════════════════════════════════════════════

def _header_section(headline: str, severity: str, item_count: int) -> str:
    sev_color = _severity_color(severity)
    return f"""
<div style="{S['card']}border-left:4px solid {sev_color};">
  <h1 style="{S['h1']}">{headline}</h1>
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;">
    <span style="{S['badge']}background:rgba({','.join(str(int(sev_color[i:i+2],16)) for i in (1,3,5))},0.15);color:{sev_color};">⚡ {severity}</span>
    <span style="{S['badge']}background:rgba(0,212,170,0.1);color:{COLORS['accent']};">📊 {item_count} Incidents</span>
  </div>
  <p style="{S['muted']}">
    <strong>Published:</strong> {_utc_now()} &nbsp;|&nbsp;
    <strong>Author:</strong> {BRAND['name']} Intelligence Team
  </p>
</div>
"""


def _incident_section(item: Dict, index: int) -> str:
    title = item.get("title", "Unknown Incident")
    summary = re.sub(r'<[^>]+>', '', item.get("summary", ""))
    link = item.get("link", "#")
    severity = _severity_from_content(title + " " + summary)
    sev_color = _severity_color(severity)

    return f"""
<div style="{S['card']}border-left:4px solid {sev_color};">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
    <span style="{S['badge']}background:rgba({','.join(str(int(sev_color[i:i+2],16)) for i in (1,3,5))},0.15);color:{sev_color};">{severity}</span>
    <span style="{S['muted']}">Triage Unit #{index}</span>
  </div>
  <h3 style="color:{COLORS['white']};font-size:19px;font-weight:700;margin:0 0 8px 0;">{title}</h3>
  <p style="{S['p']}">{summary[:600]}...</p>
  <p><a href="{link}" style="{S['link']}" target="_blank">📖 Read Full Advisory →</a></p>
</div>
"""


# ═══════════════════════════════════════════════════
# MAIN PUBLIC API
# ═══════════════════════════════════════════════════

def generate_full_post_content(items: List[Dict]) -> str:
    """Assembles sections into the Elite V16.0 Theme Wrapper."""
    
    headline = generate_headline(items)
    sections = []
    severity = _severity_from_content(" ".join(i.get("title", "") for i in items))
    
    sections.append(_header_section(headline, severity, len(items)))
    for idx, item in enumerate(items, start=1):
        sections.append(_incident_section(item, idx))

    final_body = "\n".join(sections)

    # WRAPPER FOR V16.0 XML THEME
    wrapped_body = f"""
<div class="forced-page-content">
  <div class="ai-badge">AI-GENERATED THREAT ADVISORY</div>

  <div class="hero-box" style="margin-bottom:30px; border-left:6px solid #00e5c3;">
    <h2 style="margin-top:0; color:white;">Autonomous Threat Intelligence Report</h2>
    <p style="color:#cbd5e1;">
      Automated Forensic Analysis provided by the 
      <strong>CYBERDUDEBIVASH THREAT INTEL PLATFORM</strong>.
    </p>
  </div>

  {final_body}

  <div style="margin-top:40px; border-top:1px solid #1e293b; padding-top:20px; text-align:center;">
    <p style="font-size: 13px; color: #94a3b8;">
      © 2026 <b>CYBERDUDEBIVASH PVT LTD</b>.
      <br/>For consultation: 
      <a href="https://wa.me/918179881447" 
         style="color: #00e5c3; text-decoration: none; font-weight: 700;">
         CONTACT HQ
      </a>
    </p>
  </div>
</div>
"""
    return wrapped_body
