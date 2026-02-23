#!/usr/bin/env python3
"""
upsell_injector.py — CYBERDUDEBIVASH® SENTINEL APEX v18.0
REVENUE BRIDGE & MULTI-TIER CTA INJECTION ENGINE

v18.0 UPGRADE:
  - Threat-category → Gumroad product URL mapping (was static/empty)
  - UTM parameter tracking on every Gumroad link
  - Mid-report inline CTA + footer CTA (dual placement)
  - Tier-aware messaging (Free → Pro → Enterprise funnel)
  - Emergency kit CTA for CRITICAL threats (score >= 9.0)
  - Zero breaking changes — inject_premium_cta() signature preserved
"""

import logging
from urllib.parse import urlencode

logger = logging.getLogger("CDB-INJECTOR")

# Gumroad Product Catalog — keyed by threat category
GUMROAD_PRODUCTS = {
    "vulnerability":        "https://cyberdudebivash.gumroad.com/l/pwynns",
    "zero_day":             "https://cyberdudebivash.gumroad.com/l/pwynns",
    "malware_campaign":     "https://cyberdudebivash.gumroad.com/l/ytqra",
    "ransomware":           "https://cyberdudebivash.gumroad.com/l/ytqra",
    "mobile_malware":       "https://cyberdudebivash.gumroad.com/l/ytqra",
    "data_breach":          "https://cyberdudebivash.gumroad.com/l/yrjznw",
    "apt":                  "https://cyberdudebivash.gumroad.com/l/pwynns",
    "supply_chain":         "https://cyberdudebivash.gumroad.com/l/pwynns",
    "phishing":             "https://cyberdudebivash.gumroad.com/l/ytqra",
    "browser_extension":    "https://cyberdudebivash.gumroad.com/l/ytqra",
    "cloud_attack":         "https://cyberdudebivash.gumroad.com/l/yrjznw",
    "ddos":                 "https://cyberdudebivash.gumroad.com/l/yrjznw",
    "default":              "https://cyberdudebivash.gumroad.com/l/pwynns",
}

ENTERPRISE_INQUIRY_URL = "https://www.cyberdudebivash.com/#contact"
ENTERPRISE_EMAIL = "bivash@cyberdudebivash.com"
WHATSAPP_URL = "https://wa.me/918179881447"
PLATFORM_URL = "https://intel.cyberdudebivash.com"
GUMROAD_STORE = "https://cyberdudebivash.gumroad.com/"


def _utm_url(base_url, threat_category, risk_score):
    severity = "critical" if risk_score >= 8.5 else "high" if risk_score >= 6.5 else "medium"
    params = {
        "utm_source": "cyberbivash-blog",
        "utm_medium": "threat-report-cta",
        "utm_campaign": f"sentinel-apex-{severity}",
        "utm_content": threat_category,
    }
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{urlencode(params)}"


class UpsellInjector:
    def __init__(self):
        self.button_style = (
            "display:inline-block;padding:14px 28px;margin:10px 6px;"
            "background:linear-gradient(135deg,#00d4aa,#00b891);color:#020205;"
            "text-decoration:none;font-weight:900;border-radius:4px;"
            "font-family:'JetBrains Mono',monospace;font-size:12px;"
            "letter-spacing:1px;box-shadow:0 4px 20px rgba(0,212,170,0.35);"
        )

    def inject_premium_cta(self, report_html, product_url, risk_score, threat_category="default"):
        """
        Inject dual CTA (mid-report + footer) into threat report HTML.
        v18.0: threat_category enables contextual product matching.
        Backward compatible — existing calls still work unchanged.
        """
        resolved_url = product_url or GUMROAD_PRODUCTS.get(threat_category, GUMROAD_PRODUCTS["default"])
        tracked_url  = _utm_url(resolved_url, threat_category, risk_score)
        enterprise_url = _utm_url(ENTERPRISE_INQUIRY_URL, threat_category, risk_score)
        store_url    = _utm_url(GUMROAD_STORE, threat_category, risk_score)

        if risk_score >= 9.0:
            badge_color = "#ff3e3e"; badge_label = "CRITICAL THREAT ACTIVE"
            kit_title   = "EMERGENCY DEFENSE KIT — Deploy Immediately"
            kit_desc    = "CRITICAL severity threat. Pre-built SIGMA rules, YARA signatures, IR playbook and remediation scripts ready for immediate deployment."
            primary_btn = "GET EMERGENCY DEFENSE KIT ->"
        elif risk_score >= 7.0:
            badge_color = "#ea580c"; badge_label = "HIGH PRIORITY THREAT"
            kit_title   = "ENTERPRISE RESPONSE PACKAGE"
            kit_desc    = "High-priority threat requiring immediate defensive action. Production-ready detection rules, IR playbook and automated remediation scripts."
            primary_btn = "GET ENTERPRISE RESPONSE PACKAGE ->"
        else:
            badge_color = "#d97706"; badge_label = "THREAT INTELLIGENCE REPORT"
            kit_title   = "PROFESSIONAL DEFENSE KIT"
            kit_desc    = "Operationalize this intelligence with production-grade SIGMA rules, detection playbook and automated response scripts."
            primary_btn = "GET DEFENSE KIT ->"

        mid_cta = f"""
<div style="margin:40px 0;padding:22px 28px;background:#080a10;border:1px solid {badge_color}44;border-left:4px solid {badge_color};font-family:'Segoe UI',Arial,sans-serif;">
  <p style="font-family:'JetBrains Mono',monospace;font-size:9px;color:{badge_color};letter-spacing:3px;margin:0 0 8px 0;text-transform:uppercase;">{badge_label}</p>
  <p style="color:#94a3b8;font-size:14px;margin:0 0 14px 0;line-height:1.6;">Need detection rules and response automation for this threat? CyberDudeBivash has pre-built enterprise assets ready to deploy.</p>
  <a href="{tracked_url}" target="_blank" rel="noopener" style="{self.button_style}">{primary_btn}</a>
  <a href="{WHATSAPP_URL}" target="_blank" rel="noopener" style="display:inline-block;padding:12px 22px;margin:10px 6px;background:transparent;color:#00d4aa;text-decoration:none;font-weight:700;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;border:1.5px solid #00d4aa;">CHAT WITH ANALYST</a>
</div>"""

        footer_cta = f"""
<hr style="border:0;border-top:1px solid #151a24;margin:50px 0 40px 0;">
<div style="background:#06080d;border:1px solid #00d4aa22;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="background:#080a10;padding:28px 32px;border-bottom:1px solid #151a24;">
    <p style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#00d4aa;letter-spacing:4px;margin:0 0 8px 0;text-transform:uppercase;">CYBERDUDEBIVASH SENTINEL APEX — OPERATIONAL INTELLIGENCE</p>
    <h3 style="color:#f0f4f8;font-size:20px;margin:0 0 8px 0;font-weight:900;">{kit_title}</h3>
    <p style="color:#64748b;font-size:14px;margin:0;line-height:1.6;">{kit_desc}</p>
  </div>
  <div style="padding:24px 32px;display:flex;gap:16px;flex-wrap:wrap;">
    <div style="flex:1;min-width:180px;background:#0d1017;border:1px solid #1e293b;padding:18px;">
      <p style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#00d4aa;letter-spacing:2px;margin:0 0 6px 0;">DEFENSE KIT</p>
      <p style="color:#f0f4f8;font-size:14px;font-weight:700;margin:0 0 8px 0;">SIGMA + YARA + Playbook</p>
      <p style="color:#64748b;font-size:12px;margin:0 0 14px 0;line-height:1.5;">Production-ready detection rules, IR playbook and remediation scripts.</p>
      <a href="{tracked_url}" target="_blank" rel="noopener" style="{self.button_style}padding:9px 18px;font-size:11px;">BUY NOW -></a>
    </div>
    <div style="flex:1;min-width:180px;background:#0d1017;border:1px solid #00d4aa33;padding:18px;">
      <p style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#8b5cf6;letter-spacing:2px;margin:0 0 6px 0;">ENTERPRISE</p>
      <p style="color:#f0f4f8;font-size:14px;font-weight:700;margin:0 0 8px 0;">Full Threat Intel Suite</p>
      <p style="color:#64748b;font-size:12px;margin:0 0 14px 0;line-height:1.5;">Complete intel access, API, STIX feeds and direct analyst support.</p>
      <a href="{enterprise_url}" target="_blank" rel="noopener" style="{self.button_style}background:linear-gradient(135deg,#8b5cf6,#7c3aed);box-shadow:0 4px 20px rgba(139,92,246,0.35);padding:9px 18px;font-size:11px;">CONTACT US -></a>
    </div>
    <div style="flex:1;min-width:180px;background:#0d1017;border:1px solid #1e293b;padding:18px;">
      <p style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#3b82f6;letter-spacing:2px;margin:0 0 6px 0;">ALL PRODUCTS</p>
      <p style="color:#f0f4f8;font-size:14px;font-weight:700;margin:0 0 8px 0;">Full Product Catalog</p>
      <p style="color:#64748b;font-size:12px;margin:0 0 14px 0;line-height:1.5;">IOC databases, detection packs, IR templates and more.</p>
      <a href="{store_url}" target="_blank" rel="noopener" style="{self.button_style}background:linear-gradient(135deg,#3b82f6,#2563eb);box-shadow:0 4px 20px rgba(59,130,246,0.35);padding:9px 18px;font-size:11px;">BROWSE STORE -></a>
    </div>
  </div>
  <div style="padding:18px 32px;border-top:1px solid #151a24;">
    <p style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#5a6578;margin:0;">
      Enterprise: <a href="mailto:{ENTERPRISE_EMAIL}" style="color:#00d4aa;text-decoration:none;font-weight:700;">{ENTERPRISE_EMAIL}</a>
      &nbsp;|&nbsp;
      <a href="{WHATSAPP_URL}" target="_blank" style="color:#25d366;text-decoration:none;font-weight:700;">WhatsApp: +91 8179881447</a>
      &nbsp;|&nbsp;
      <a href="{PLATFORM_URL}" target="_blank" style="color:#5a6578;text-decoration:none;">intel.cyberdudebivash.com</a>
    </p>
  </div>
</div>"""

        # Inject mid-CTA at ~60% of report
        lines = report_html.split('\n')
        mid   = len(lines) * 6 // 10
        for i in range(mid, max(0, mid - 50), -1):
            if lines[i].strip() in ('</div>', '</section>', '</table>'):
                mid = i + 1
                break
        lines.insert(mid, mid_cta)
        return '\n'.join(lines) + footer_cta


# Global instance
upsell_engine = UpsellInjector()
