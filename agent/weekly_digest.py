#!/usr/bin/env python3
"""
weekly_digest.py — CYBERDUDEBIVASH® SENTINEL APEX v18.0
WEEKLY THREAT INTELLIGENCE DIGEST EMAIL ENGINE

Reads the threat manifest, picks the top 5 highest-risk threats from
the past 7 days, and sends a beautifully-formatted HTML digest to all
subscribers via SendGrid.

Run: python -m agent.weekly_digest
Scheduled: Every Sunday via GitHub Actions (weekly-digest.yml)

Revenue impact: Weekly touchpoint → subscriber retention → Gumroad conversions.
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("CDB-WEEKLY-DIGEST")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-DIGEST] %(message)s")

MANIFEST_PATH = "data/stix/feed_manifest.json"
GUMROAD_STORE = "https://cyberdudebivash.gumroad.com/"
PLATFORM_URL  = "https://intel.cyberdudebivash.com"
BLOG_URL      = "https://cyberbivash.blogspot.com"
WEBSITE_URL   = "https://cyberdudebivash.com"
ENTERPRISE_EMAIL = "bivash@cyberdudebivash.com"
WHATSAPP_URL  = "https://wa.me/918179881447"

# UTM params for digest links
UTM = "utm_source=email-digest&utm_medium=weekly-briefing&utm_campaign=sentinel-apex-digest"


def _load_manifest() -> List[Dict]:
    """Load threat manifest entries."""
    p = Path(MANIFEST_PATH)
    if not p.exists():
        logger.warning(f"Manifest not found: {MANIFEST_PATH}")
        return []
    try:
        data = json.loads(p.read_text())
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return data.get("entries", [])
    except Exception as e:
        logger.error(f"Failed to load manifest: {e}")
    return []


def _get_top_threats(days: int = 7, top_n: int = 5) -> List[Dict]:
    """Get top N threats from the past N days by risk score."""
    entries = _load_manifest()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    recent = []
    for entry in entries:
        if entry.get("status") == "archived":
            continue
        ts_str = entry.get("generated_at", "")
        try:
            # Handle both ISO format and timestamp
            if isinstance(ts_str, (int, float)):
                ts = datetime.fromtimestamp(ts_str, tz=timezone.utc)
            else:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts >= cutoff:
                recent.append(entry)
        except Exception:
            recent.append(entry)  # Include if we can't parse date

    # Sort by risk score descending
    recent.sort(key=lambda x: float(x.get("risk_score", 0)), reverse=True)
    return recent[:top_n]


def _severity_color(score: float) -> str:
    if score >= 9.0:   return "#ff3e3e"
    if score >= 7.0:   return "#ea580c"
    if score >= 5.0:   return "#d97706"
    return "#16a34a"


def _severity_label(score: float) -> str:
    if score >= 9.0:   return "CRITICAL"
    if score >= 7.0:   return "HIGH"
    if score >= 5.0:   return "MEDIUM"
    return "LOW"


def _build_threat_card(threat: Dict, index: int) -> str:
    """Build HTML card for a single threat entry."""
    title     = threat.get("title", "Threat Intelligence Report")
    score     = float(threat.get("risk_score", 5.0))
    url       = threat.get("blog_url", BLOG_URL)
    color     = _severity_color(score)
    sev_label = _severity_label(score)
    tlp       = threat.get("tlp", "TLP:GREEN")
    ioc_count = threat.get("total_iocs", 0)
    mitre     = len(threat.get("mitre_techniques", []))

    tracked_url = f"{url}?{UTM}" if "?" not in url else f"{url}&{UTM}"

    return f"""
    <div style="background:#0a0e17;border:1px solid #1e293b;border-left:4px solid {color};
                padding:20px 24px;margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:10px;">
            <span style="font-family:'Courier New',monospace;font-size:9px;color:{color};
                         letter-spacing:3px;text-transform:uppercase;">
                #{index} — {sev_label} — CDB-RISK {score:.1f}/10
            </span>
            <span style="font-family:'Courier New',monospace;font-size:9px;
                         color:#334155;letter-spacing:1px;">{tlp}</span>
        </div>
        <h3 style="color:#e2e8f0;font-size:16px;margin:0 0 10px 0;line-height:1.4;font-weight:700;">
            {title[:120]}
        </h3>
        <div style="display:flex;gap:16px;margin-bottom:14px;flex-wrap:wrap;">
            <span style="font-family:'Courier New',monospace;font-size:11px;color:#475569;">
                IOCs: <strong style="color:#94a3b8;">{ioc_count}</strong>
            </span>
            <span style="font-family:'Courier New',monospace;font-size:11px;color:#475569;">
                MITRE: <strong style="color:#94a3b8;">{mitre} techniques</strong>
            </span>
        </div>
        <a href="{tracked_url}" target="_blank"
           style="display:inline-block;padding:9px 20px;background:{color};color:#ffffff;
                  text-decoration:none;font-weight:700;border-radius:3px;font-size:12px;
                  font-family:'Courier New',monospace;letter-spacing:1px;">
            READ FULL REPORT ->
        </a>
    </div>"""


def build_digest_html(threats: List[Dict], week_label: str) -> str:
    """Build the full weekly digest HTML email."""
    threat_cards = "".join(_build_threat_card(t, i+1) for i, t in enumerate(threats))
    total_threats = len(threats)
    avg_score = sum(float(t.get("risk_score", 5)) for t in threats) / max(total_threats, 1)
    critical_count = sum(1 for t in threats if float(t.get("risk_score", 0)) >= 9.0)
    high_count = sum(1 for t in threats if 7.0 <= float(t.get("risk_score", 0)) < 9.0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CyberDudeBivash Weekly Threat Digest — {week_label}</title></head>
<body style="margin:0;padding:0;background:#06080d;font-family:'Segoe UI',Arial,sans-serif;">
<div style="max-width:640px;margin:0 auto;background:#06080d;color:#94a3b8;">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#080a10,#0d1017);padding:36px 32px;
              border-bottom:1px solid #1e293b;text-align:center;">
    <p style="font-family:'Courier New',monospace;font-size:9px;color:#00d4aa;
              letter-spacing:5px;margin:0 0 12px 0;text-transform:uppercase;">
      CYBERDUDEBIVASH® SENTINEL APEX v18.0
    </p>
    <h1 style="color:#f0f4f8;font-size:26px;margin:0 0 8px 0;font-weight:900;letter-spacing:-1px;">
      Weekly Threat Intelligence Digest
    </h1>
    <p style="color:#475569;font-size:13px;margin:0;font-family:'Courier New',monospace;
              letter-spacing:1px;">{week_label} · Global Operations Center</p>
  </div>

  <!-- Stats Bar -->
  <div style="display:flex;background:#080a10;border-bottom:1px solid #1e293b;">
    <div style="flex:1;padding:18px;text-align:center;border-right:1px solid #1e293b;">
      <p style="font-size:24px;font-weight:900;color:#ff3e3e;margin:0;line-height:1;">{critical_count}</p>
      <p style="font-family:'Courier New',monospace;font-size:9px;color:#475569;letter-spacing:2px;margin:4px 0 0 0;">CRITICAL</p>
    </div>
    <div style="flex:1;padding:18px;text-align:center;border-right:1px solid #1e293b;">
      <p style="font-size:24px;font-weight:900;color:#ea580c;margin:0;line-height:1;">{high_count}</p>
      <p style="font-family:'Courier New',monospace;font-size:9px;color:#475569;letter-spacing:2px;margin:4px 0 0 0;">HIGH</p>
    </div>
    <div style="flex:1;padding:18px;text-align:center;border-right:1px solid #1e293b;">
      <p style="font-size:24px;font-weight:900;color:#00d4aa;margin:0;line-height:1;">{total_threats}</p>
      <p style="font-family:'Courier New',monospace;font-size:9px;color:#475569;letter-spacing:2px;margin:4px 0 0 0;">TOP THREATS</p>
    </div>
    <div style="flex:1;padding:18px;text-align:center;">
      <p style="font-size:24px;font-weight:900;color:#f0f4f8;margin:0;line-height:1;">{avg_score:.1f}</p>
      <p style="font-family:'Courier New',monospace;font-size:9px;color:#475569;letter-spacing:2px;margin:4px 0 0 0;">AVG RISK</p>
    </div>
  </div>

  <!-- Threat Cards -->
  <div style="padding:24px 28px;">
    <p style="font-family:'Courier New',monospace;font-size:9px;color:#00d4aa;
              letter-spacing:4px;text-transform:uppercase;margin:0 0 20px 0;">
      TOP THREATS THIS WEEK
    </p>
    {threat_cards}
  </div>

  <!-- CTA Block -->
  <div style="background:#080a10;margin:0 28px 24px 28px;padding:24px;border:1px solid #1e293b;">
    <p style="font-family:'Courier New',monospace;font-size:9px;color:#8b5cf6;
              letter-spacing:3px;margin:0 0 10px 0;text-transform:uppercase;">
      OPERATIONALIZE THIS INTELLIGENCE
    </p>
    <p style="color:#64748b;font-size:14px;margin:0 0 18px 0;line-height:1.6;">
      Deploy production-ready SIGMA detection rules, YARA signatures, and IR playbooks
      engineered for these exact threat vectors.
    </p>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <a href="{GUMROAD_STORE}?{UTM}" target="_blank"
         style="display:inline-block;padding:12px 22px;background:linear-gradient(135deg,#00d4aa,#00b891);
                color:#020205;text-decoration:none;font-weight:900;border-radius:4px;
                font-size:12px;font-family:'Courier New',monospace;letter-spacing:1px;">
        BROWSE DEFENSE KITS ->
      </a>
      <a href="mailto:{ENTERPRISE_EMAIL}"
         style="display:inline-block;padding:12px 22px;background:transparent;
                color:#00d4aa;text-decoration:none;font-weight:700;border-radius:4px;
                font-size:12px;font-family:'Courier New',monospace;letter-spacing:1px;
                border:1.5px solid #00d4aa;">
        ENTERPRISE INQUIRY
      </a>
    </div>
  </div>

  <!-- Live Feed CTA -->
  <div style="margin:0 28px 24px 28px;padding:20px 24px;background:#0d1017;
              border:1px solid #1e293b;text-align:center;">
    <p style="color:#475569;font-size:13px;margin:0 0 10px 0;">
      Live threat feed + STIX exports + IOC downloads available at:
    </p>
    <a href="{PLATFORM_URL}?{UTM}" target="_blank"
       style="color:#00d4aa;text-decoration:none;font-weight:700;
              font-family:'Courier New',monospace;font-size:14px;">
      intel.cyberdudebivash.com ->
    </a>
  </div>

  <!-- Footer -->
  <div style="padding:24px 28px;border-top:1px solid #1e293b;text-align:center;">
    <p style="font-family:'Courier New',monospace;font-size:10px;color:#334155;
              line-height:1.8;margin:0;">
      CYBERDUDEBIVASH PVT. LTD. · Bhubaneswar, Odisha, India · © 2026<br>
      <a href="{WEBSITE_URL}" style="color:#475569;text-decoration:none;">cyberdudebivash.com</a>
      &nbsp;|&nbsp;
      <a href="{WHATSAPP_URL}" target="_blank" style="color:#25d366;text-decoration:none;">WhatsApp</a>
      &nbsp;|&nbsp;
      <a href="mailto:{ENTERPRISE_EMAIL}" style="color:#475569;text-decoration:none;">{ENTERPRISE_EMAIL}</a>
    </p>
  </div>

</div>
</body>
</html>"""


def send_weekly_digest():
    """Build and send the weekly digest to all configured subscribers."""
    week_label = datetime.now(timezone.utc).strftime("Week of %B %d, %Y")
    logger.info(f"Building weekly digest: {week_label}")

    threats = _get_top_threats(days=7, top_n=5)
    if not threats:
        logger.warning("No threats found in past 7 days. Skipping digest.")
        return

    logger.info(f"Top threats selected: {len(threats)} entries")

    html_body = build_digest_html(threats, week_label)

    # Send via SendGrid
    api_key = os.getenv("SENDGRID_API_KEY", "")
    sender  = os.getenv("SENDER_EMAIL", "")
    recipients_raw = os.getenv("SUBSCRIBER_EMAILS", "")

    if not api_key or not sender or not recipients_raw:
        logger.warning("Email config incomplete (SENDGRID_API_KEY / SENDER_EMAIL / SUBSCRIBER_EMAILS). Saving HTML locally.")
        Path("data/last_weekly_digest.html").write_text(html_body)
        logger.info("Digest HTML saved to data/last_weekly_digest.html")
        return

    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    subject = f"[CyberDudeBivash] Weekly Threat Digest — {week_label} | {len(threats)} Active Threats"

    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail, To

        sg = SendGridAPIClient(api_key)
        for recipient in recipients:
            msg = Mail(
                from_email=sender,
                to_emails=recipient,
                subject=subject,
                html_content=html_body,
            )
            response = sg.send(msg)
            if response.status_code in (200, 201, 202):
                logger.info(f"  ✅ Digest sent to: {recipient}")
            else:
                logger.warning(f"  ⚠️  Digest failed for {recipient}: HTTP {response.status_code}")

    except ImportError:
        logger.error("sendgrid package not installed. pip install sendgrid")
        # Save locally as fallback
        Path("data/last_weekly_digest.html").write_text(html_body)
    except Exception as e:
        logger.error(f"Digest send failed: {e}")
        Path("data/last_weekly_digest.html").write_text(html_body)

    logger.info("Weekly digest complete.")


if __name__ == "__main__":
    send_weekly_digest()
