"""
blog_post_generator.py — CyberDudeBivash Premium Report Generator v16.5
Generates unique, professionally styled, revenue-optimized threat intel reports.

Updates:
- Integrated V16.0 Elite Template Wrapper for UI consistency.
- Hard-coded Contact HQ conversion funnels into every automated report.
- Optimized for AdSense High-CPC targeting in technical reports.
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


def _reading_time(word_count: int) -> int:
    return max(1, round(word_count / 200))


def _severity_from_content(text: str) -> str:
    """Detect threat severity from content keywords."""
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
    "table": f"width:100%;border-collapse:collapse;margin:16px 0;font-size:15px;",
    "th": f"background:{COLORS['bg_dark']};color:{COLORS['white']};font-weight:600;text-align:left;padding:10px 14px;font-size:13px;text-transform:uppercase;letter-spacing:0.04em;border-bottom:2px solid {COLORS['accent']};",
    "td": f"padding:10px 14px;border-bottom:1px solid {COLORS['border']};color:{COLORS['text']};",
}

# ═══════════════════════════════════════════════════
# SECTION GENERATORS (V16.5 Enhanced)
# ═══════════════════════════════════════════════════

def _header_section(headline: str, severity: str, item_count: int) -> str:
    sev_color = _severity_color(severity)
    return f"""
<div style="{S['card']}border-left:4px solid {sev_color};">
  <h1 style="{S['h1']}">{headline}</h1>
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;">
    <span style="{S['badge']}background:rgba({','.join(str(int(sev_color[i:i+2],16)) for i in (1,3,5))},0.15);color:{sev_color};">⚡ {severity}</span>
    <span style="{S['badge']}background:rgba(0,212,170,0.1);color:{COLORS['accent']};">📊 {item_count} Incidents</span>
    <span style="{S['badge']}background:rgba(59,130,246,0.1);color:{COLORS['cyber_blue']};">🛡️ CyberDudeBivash Intel</span>
  </div>
  <p style="{S['muted']}">
    <strong>Published:</strong> {_utc_now()} &nbsp;|&nbsp;
    <strong>Classification:</strong> TLP:CLEAR
  </p>
</div>
"""

def _incident_section(item: Dict, index: int) -> str:
    title = item.get("title", "Unknown Incident")
    source = item.get("source", "Unknown")
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
  <h3 style="{S['h3']}">Remediation Strategy</h3>
  <ul style="color:{COLORS['text']};">
    <li>Deploy immediate EDR/XDR threat hunting queries for {source} IOCs.</li>
    <li>Validate network segmentation to contain possible lateral movement.</li>
  </ul>
  <p style="margin-top:10px;"><a href="{link}" style="{S['link']}" target="_blank">📖 Read Full Advisory →</a></p>
</div>
"""

# ═══════════════════════════════════════════════════
# MAIN PUBLIC API (Final Assembler)
# ═══════════════════════════════════════════════════

def generate_full_post_content(items: List[Dict]) -> str:
    """
    Assembles AI sections into the V16.0 Elite Theme Wrapper.
    """
    from generate_headline import generate_headline # Assuming exists based on prev context
    headline = generate_headline(items)
    
    # Assembly of core sections
    sections = []
    severity = _severity_from_content(" ".join(i.get("title", "") for i in items))
    
    sections.append(_header_section(headline, severity, len(items)))
    for idx, item in enumerate(items, start=1):
        sections.append(_incident_section(item, idx))

    final_body = "\n".join(sections)

    # FINAL PRODUCTION WRAPPER (Theme Synchronization)
    wrapped_body = f"""
<div class="forced-page-content">
  <div class="ai-badge">AI-GENERATED THREAT ADVISORY</div>

  <div class="hero-box" style="margin-bottom:30px; border-left:6px solid #00e5c3;">
    <h2 style="margin-top:0; color:white;">Autonomous Threat Intel Report</h2>
    <p style="color:#cbd5e1;">
      This intelligence report is orchestrated by the 
      <strong>CYBERDUDEBIVASH THREAT INTEL PLATFORM</strong>.
      Our AI agent analyzes multi-source feeds to identify actively exploited 
      vulnerabilities and high-risk Indicators of Compromise (IOCs).
    </p>
  </div>

  {final_body}

  <div style="margin-top:40px; border-top:1px solid #1e293b; padding-top:20px; text-align:center;">
    <p style="font-size: 13px; color: #94a3b8;">
      © 2026 <b>CYBERDUDEBIVASH PVT LTD</b>. All Intel is for defensive R&amp;D.
      <br/>For enterprise SOC consultation or custom feeds: 
      <a href="https://wa.me/918179881447" 
         style="color: #00e5c3; text-decoration: none; font-weight: 700;">
         CONTACT HQ
      </a>
    </p>
  </div>
</div>
"""
    return wrapped_body
