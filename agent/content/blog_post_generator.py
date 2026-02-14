"""
blog_post_generator.py — CyberDudeBivash Premium Report Generator v16.9
FINAL: AI Risk Scoring + STIX 2.1 JSON Export Layer.

© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import random
import hashlib
import re
import json
import base64
from datetime import datetime, timezone
from typing import List, Dict, Optional

from agent.config import BRAND, BLOGS, COLORS, FONTS

# ═══════════════════════════════════════════════════
# INTELLIGENCE & EXTRACTION ENGINE
# ═══════════════════════════════════════════════════

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%B %d, %Y — %H:%M UTC")

def _calculate_cdb_score(title: str, summary: str) -> float:
    """Calculates a 0.0-10.0 risk score based on technical severity factors."""
    score = 2.0
    text = (title + " " + summary).lower()
    if any(w in text for w in ["zero-day", "0-day", "no patch", "actively exploited"]): score += 3.5
    elif any(w in text for w in ["exploit available", "poc", "proof of concept"]): score += 2.5
    elif "cve-" in text: score += 1.0
    if any(w in text for w in ["rce", "remote code execution", "unauthenticated"]): score += 2.0
    if any(w in text for w in ["ransomware", "exfiltration", "breach"]): score += 1.5
    if any(w in text for w in ["critical infrastructure", "government", "finance"]): score += 1.0
    return round(min(10.0, score), 1)

def _extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extracts machine-readable IoCs from AI-generated content."""
    iocs = {
        "ipv4": list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text))),
        "cves": list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE))),
        "domains": list(set(re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text.lower()))),
        "hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)))
    }
    # Clean noise (internal domains)
    iocs["domains"] = [d for d in iocs["domains"] if "cyberbivash" not in d and "google" not in d]
    return iocs

# ═══════════════════════════════════════════════════
# UI COMPONENT GENERATORS
# ═══════════════════════════════════════════════════

def _risk_meter_html(score: float) -> str:
    color = "#ff3e3e" if score >= 8.5 else "#ff9f43" if score >= 6.5 else "#feca57" if score >= 4.0 else "#00e5c3"
    label = "CRITICAL" if score >= 8.5 else "HIGH" if score >= 6.5 else "MEDIUM" if score >= 4.0 else "LOW"
    return f"""
<div style="background:rgba(10,14,23,0.8); border:1px solid {color}; padding:15px; border-radius:12px; margin-bottom:25px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
    <span style="color:{color}; font-family:'JetBrains Mono'; font-weight:900; font-size:13px; letter-spacing:2px;">CDB-RISK INDEX: {score}/10.0</span>
    <span style="background:{color}; color:#000; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:900;">{label}</span>
  </div>
  <div style="width:100%; background:#1e293b; height:6px; border-radius:3px; overflow:hidden;">
    <div style="width:{score*10}%; background:{color}; height:100%; box-shadow:0 0 10px {color};"></div>
  </div>
</div>"""

def _json_export_html(iocs: Dict, score: float, headline: str) -> str:
    """Generates a base64 STIX-aligned download button."""
    stix_payload = {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(headline.encode()).hexdigest()}",
        "objects": [{"type": "indicator", "spec_version": "2.1", "name": headline, 
                     "description": f"CDB-Score: {score}", "pattern": str(iocs), "pattern_type": "stix"}]
    }
    encoded = base64.b64encode(json.dumps(stix_payload).encode()).decode()
    return f"""
<div style="margin: 30px 0; padding: 25px; background: rgba(0, 229, 195, 0.05); border: 2px dashed #00e5c3; border-radius: 16px; text-align: center;">
  <h3 style="color: white; font-size: 16px; margin-bottom: 10px; font-family: 'JetBrains Mono';">STRUCTURED INTEL EXPORT (STIX 2.1)</h3>
  <p style="color: #94a3b8; font-size: 12px; margin-bottom: 20px;">Ready for SIEM ingestion. Includes IPs, CVEs, and hashes extracted by CyberBivash AI.</p>
  <a href="data:application/json;base64,{encoded}" download="CDB_INTEL_{datetime.now().strftime('%Y%m%d')}.json" 
     style="display: inline-block; background: #00e5c3; color: #000; padding: 14px 30px; border-radius: 8px; font-weight: 900; text-decoration: none; font-size: 14px;">
    ⬇️ DOWNLOAD RAW IOC DATA (JSON)
  </a>
</div>"""

# ═══════════════════════════════════════════════════
# MAIN PUBLIC API
# ═══════════════════════════════════════════════════

def generate_full_post_content(items: List[Dict]) -> str:
    from agent.content.blog_post_generator import generate_headline # Ensure scoped
    headline = generate_headline(items)
    full_corpus = " ".join(i.get("title", "") + " " + i.get("summary", "") for i in items)
    
    score = _calculate_cdb_score("", full_corpus)
    raw_iocs = _extract_iocs(full_corpus)
    
    sections = []
    for idx, item in enumerate(items, start=1):
        clean_sum = re.sub(r'<[^>]+>', '', item.get("summary", ""))[:500]
        color = "#ff3e3e" if _calculate_cdb_score(item.get("title",""), clean_sum) >= 8.5 else "#00e5c3"
        sections.append(f"""
<div style="background:{COLORS['bg_card']}; border:1px solid {COLORS['border']}; border-left:4px solid {color}; border-radius:12px; padding:24px; margin:20px 0;">
  <h3 style="color:white; font-size:19px; font-weight:700; margin:0 0 10px 0;">{item.get('title')}</h3>
  <p style="color:{COLORS['text']}; line-height:1.8; font-size:16px;">{clean_sum}...</p>
  <p><a href="{item.get('link')}" style="color:{COLORS['accent']}; text-decoration:none; font-weight:600;" target="_blank">Technical Source →</a></p>
</div>""")

    final_body = "\n".join(sections)

    return f"""
<div class="forced-page-content">
  <div class="ai-badge">AI-ENGINE: CDB-SENTINEL v16.9</div>
  <h1 style="color:white; font-size:28px; font-weight:800; margin:0 0 20px 0;">{headline}</h1>
  {_risk_meter_html(score)}
  <div class="hero-box" style="margin-bottom:30px; border-left:6px solid #00e5c3; padding:25px; background:{COLORS['bg_card']};">
    <h2 style="margin-top:0; color:white; font-size:20px;">Automated Triage Assessment</h2>
    <p style="color:#cbd5e1; font-size:15px;">The <strong>CYBERDUDEBIVASH AI</strong> has triaged {len(items)} incidents. Download the STIX bundle below for your local SIEM.</p>
  </div>
  {final_body}
  {_json_export_html(raw_iocs, score, headline)}
  <div style="margin-top:40px; border-top:1px solid #1e293b; padding-top:20px; text-align:center;">
    <p style="font-size: 13px; color: #94a3b8;">© 2026 <b>CYBERDUDEBIVASH PVT LTD</b>. <br/> For SOC Integration: <a href="https://wa.me/918179881447" style="color: #00e5c3; text-decoration: none; font-weight: 700;">CONTACT HQ</a></p>
  </div>
</div>"""

def generate_headline(items: List[Dict]) -> str:
    top = items[0]["title"][:85] + "..." if len(items[0]["title"]) > 85 else items[0]["title"]
    return random.choice([f"🚨 CDB-ALERT: {top}", f"CRITICAL INTEL: {top}", f"THREAT ADVISORY: {top}"])
