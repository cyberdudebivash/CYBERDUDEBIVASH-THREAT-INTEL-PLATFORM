"""
lead_autoresponder.py — CyberDudeBivash SENTINEL APEX v20.0
LEAD-TO-CASH AUTO-RESPONDER

Monitors Gumroad sales from the last 24 hours and sends a targeted
follow-up email via SendGrid to buyers who paid $0 or a low amount,
offering a discount on the Enterprise tier.

Strategy:
  - Free / low buyers ($0–$49)  → Upsell to Enterprise with SENTINEL20 (20% off)
  - Higher buyers ($50+)         → Thank + upsell to annual subscription
  - All new buyers               → Receive the "Welcome" onboarding sequence

Run:
  python -m agent.lead_autoresponder          # Manual
  # or via GitHub Actions (daily cron)

Required ENV:
  GUMROAD_ACCESS_TOKEN
  SENDGRID_API_KEY
  SENDER_EMAIL               (e.g. bivash@cyberdudebivash.com)
  SENDER_NAME                (optional, default: CyberDudeBivash Sentinel)
"""

import os
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger("CDB-AUTORESPONDER")

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

SENDGRID_KEY   = os.environ.get("SENDGRID_API_KEY", "")
SENDER_EMAIL   = os.environ.get("SENDER_EMAIL", "bivash@cyberdudebivash.com")
SENDER_NAME    = os.environ.get("SENDER_NAME", "CyberDudeBivash SENTINEL APEX")

ENTERPRISE_URL  = "https://intel.cyberdudebivash.com/pricing"
STORE_URL       = "https://cyberdudebivash.gumroad.com"
PLATFORM_URL    = "https://intel.cyberdudebivash.com"
WHATSAPP_URL    = "https://wa.me/918179881447"
ENTERPRISE_EMAIL = "bivash@cyberdudebivash.com"

DISCOUNT_CODE   = "SENTINEL20"    # 20% off Enterprise
DISCOUNT_PCT    = "20%"
DISCOUNT_HOURS  = 48               # FOMO urgency window

UPSELL_THRESHOLD_CENTS = 5000      # $50 — below this = upsell to Enterprise


# ─────────────────────────────────────────────
# Email Templates
# ─────────────────────────────────────────────

def _email_upsell_low_buyer(name: str, product_title: str, expiry: str) -> str:
    """Email for buyers who paid $0–$49."""
    return f"""
<div style="background:#06080d; color:#94a3b8; font-family:'Segoe UI',Arial,sans-serif;
            padding:32px; border:1px solid #1e293b; max-width:600px; margin:auto;
            border-top:4px solid #00d4aa;">

    <div style="margin-bottom:24px;">
        <h1 style="color:#ffffff; font-size:20px; margin:0; letter-spacing:1px;">
            🛡️ CYBERDUDEBIVASH SENTINEL
        </h1>
        <p style="color:#00d4aa; font-size:11px; letter-spacing:2px; margin:4px 0;">
            AUTOMATED THREAT INTELLIGENCE PLATFORM
        </p>
    </div>

    <p>Hi {name},</p>

    <p>Thanks for downloading <strong style="color:#ffffff;">{product_title}</strong> from the
    CyberDudeBivash Sentinel APEX platform.</p>

    <p>Since you've taken the step to access actionable threat intel, we'd like to offer you
    exclusive access to our <strong style="color:#00d4aa;">Enterprise SENTINEL Tier</strong> —
    where you get:</p>

    <ul style="padding-left:20px; line-height:2;">
        <li>✅ <strong>Daily automated threat reports</strong> delivered to your inbox</li>
        <li>✅ <strong>Priority detection packs</strong> (Sigma + YARA + KQL + SPL)</li>
        <li>✅ <strong>STIX/MISP export</strong> for direct SIEM ingestion</li>
        <li>✅ <strong>MITRE ATT&CK heatmaps</strong> and adversary attribution</li>
        <li>✅ <strong>24/7 IR Hotline</strong> for critical incidents</li>
        <li>✅ <strong>Custom detection rules</strong> for your environment</li>
    </ul>

    <div style="background:#0a0e17; border:1px solid #00d4aa; border-radius:6px;
                padding:20px; margin:28px 0; text-align:center;">
        <p style="color:#ffffff; font-size:18px; font-weight:bold; margin:0 0 8px;">
            {DISCOUNT_PCT} OFF — Limited Time Offer
        </p>
        <p style="color:#00d4aa; font-size:24px; font-weight:900; letter-spacing:3px; margin:8px 0;">
            {DISCOUNT_CODE}
        </p>
        <p style="color:#64748b; font-size:12px; margin:4px 0;">
            Expires: {expiry} UTC — {DISCOUNT_HOURS}h window
        </p>
    </div>

    <div style="text-align:center; margin:24px 0;">
        <a href="{ENTERPRISE_URL}?utm_source=autoresponder&utm_medium=email&utm_campaign=pwyw-upsell"
           style="background:linear-gradient(135deg,#00d4aa,#00b891); color:#020205;
                  padding:14px 32px; text-decoration:none; font-weight:900; border-radius:4px;
                  display:inline-block; font-size:13px; letter-spacing:1px;">
            UPGRADE TO ENTERPRISE NOW →
        </a>
    </div>

    <p style="font-size:13px;">Or reach us directly:</p>
    <ul style="padding-left:20px; font-size:13px; line-height:1.8;">
        <li>📧 <a href="mailto:{ENTERPRISE_EMAIL}" style="color:#00d4aa;">{ENTERPRISE_EMAIL}</a></li>
        <li>📞 <a href="{WHATSAPP_URL}" style="color:#00d4aa;">WhatsApp: +91 8179881447</a></li>
        <li>🌐 <a href="{PLATFORM_URL}" style="color:#00d4aa;">{PLATFORM_URL}</a></li>
    </ul>

    <hr style="border:0; border-top:1px solid #1e293b; margin:28px 0;">
    <p style="font-size:11px; color:#475569; text-align:center; line-height:1.6;">
        © 2026 CyberDudeBivash Pvt. Ltd. — Bhubaneswar, Odisha, India<br>
        <a href="{STORE_URL}" style="color:#00d4aa;">Store</a> |
        <a href="{PLATFORM_URL}" style="color:#00d4aa;">Platform</a> |
        <a href="https://cyberbivash.blogspot.com" style="color:#00d4aa;">Blog</a>
    </p>
</div>
"""


def _email_thank_high_buyer(name: str, product_title: str) -> str:
    """Email for buyers who paid $50+."""
    return f"""
<div style="background:#06080d; color:#94a3b8; font-family:'Segoe UI',Arial,sans-serif;
            padding:32px; border:1px solid #1e293b; max-width:600px; margin:auto;
            border-top:4px solid #8b5cf6;">

    <h1 style="color:#ffffff; font-size:20px;">🛡️ Thank You — CyberDudeBivash SENTINEL</h1>

    <p>Hi {name},</p>

    <p>Your support means everything! Thank you for your contribution toward
    <strong style="color:#ffffff;">{product_title}</strong>.</p>

    <p>As a valued contributor, you're eligible for our
    <strong style="color:#8b5cf6;">Annual Enterprise Subscription</strong> at a 30% discount.
    Contact us directly to activate:</p>

    <ul style="padding-left:20px; line-height:2;">
        <li>📧 <a href="mailto:{ENTERPRISE_EMAIL}" style="color:#8b5cf6;">{ENTERPRISE_EMAIL}</a></li>
        <li>📞 <a href="{WHATSAPP_URL}" style="color:#8b5cf6;">WhatsApp: +91 8179881447</a></li>
    </ul>

    <div style="text-align:center; margin:24px 0;">
        <a href="{PLATFORM_URL}?utm_source=autoresponder&utm_medium=email&utm_campaign=highbuyer-thankyou"
           style="background:#8b5cf6; color:#ffffff; padding:12px 28px; text-decoration:none;
                  font-weight:900; border-radius:4px; display:inline-block;">
            VISIT SENTINEL PLATFORM →
        </a>
    </div>

    <hr style="border:0; border-top:1px solid #1e293b; margin:28px 0;">
    <p style="font-size:11px; color:#475569; text-align:center;">
        © 2026 CyberDudeBivash Pvt. Ltd. | {PLATFORM_URL}
    </p>
</div>
"""


# ─────────────────────────────────────────────
# SendGrid Dispatch
# ─────────────────────────────────────────────

def _send_email(to_email: str, to_name: str, subject: str, html_body: str) -> bool:
    """Send email via SendGrid API v3. Returns True on success."""
    if not SENDGRID_KEY:
        logger.warning("SENDGRID_API_KEY not set — skipping email")
        return False

    try:
        # Try sendgrid library first
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail

        message = Mail(
            from_email=(SENDER_EMAIL, SENDER_NAME),
            to_emails=[(to_email, to_name)],
            subject=subject,
            html_content=html_body,
        )
        sg = SendGridAPIClient(SENDGRID_KEY)
        resp = sg.send(message)
        if resp.status_code in (200, 202):
            logger.info(f"  📧 Email sent to {to_email} (status {resp.status_code})")
            return True
        else:
            logger.warning(f"  ⚠️  Email failed: {resp.status_code}")
            return False

    except ImportError:
        # Fallback: raw requests
        import requests
        url  = "https://api.sendgrid.com/v3/mail/send"
        hdrs = {"Authorization": f"Bearer {SENDGRID_KEY}", "Content-Type": "application/json"}
        data = {
            "personalizations": [{"to": [{"email": to_email, "name": to_name}]}],
            "from": {"email": SENDER_EMAIL, "name": SENDER_NAME},
            "subject": subject,
            "content": [{"type": "text/html", "value": html_body}],
        }
        resp = requests.post(url, headers=hdrs, json=data, timeout=30)
        ok = resp.status_code in (200, 202)
        if ok:
            logger.info(f"  📧 Email sent to {to_email}")
        else:
            logger.warning(f"  ⚠️  Email failed: {resp.status_code} {resp.text[:100]}")
        return ok

    except Exception as e:
        logger.warning(f"  ⚠️  Email dispatch error: {e}")
        return False


# ─────────────────────────────────────────────
# Sale Processing
# ─────────────────────────────────────────────

def _load_processed_ids() -> set:
    path = Path("data/autoresponder_processed.json")
    if path.exists():
        try:
            with path.open() as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()

def _save_processed_ids(ids: set):
    path = Path("data/autoresponder_processed.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(list(ids)[-500:], f)  # Keep last 500


def process_sales(sales: List[Dict], dry_run: bool = False) -> Dict:
    """
    Process a list of Gumroad sales and dispatch appropriate emails.
    Returns stats dict.
    """
    processed_ids = _load_processed_ids()
    expiry_ts = (datetime.now(timezone.utc) + timedelta(hours=DISCOUNT_HOURS)).strftime('%Y-%m-%d %H:%M')

    stats = {"total": 0, "upsell_sent": 0, "thank_sent": 0, "skipped_dup": 0, "failed": 0}

    for sale in sales:
        sale_id    = sale.get("id", "")
        email      = sale.get("email", "").strip()
        name       = (sale.get("full_name") or email.split("@")[0] or "Security Professional").strip()
        price      = sale.get("price", 0)  # in cents
        product_name = sale.get("product_name", "Sentinel APEX Detection Pack")

        if not email:
            continue

        stats["total"] += 1

        # Skip already processed
        if sale_id in processed_ids:
            stats["skipped_dup"] += 1
            continue

        processed_ids.add(sale_id)

        if dry_run:
            logger.info(f"  [DRY RUN] Would email: {email} | Price: ${price/100:.2f} | Product: {product_name}")
            stats["upsell_sent"] += 1
            continue

        if price < UPSELL_THRESHOLD_CENTS:
            # Low/Free buyer → aggressive enterprise upsell
            subject = f"🛡️ Your {DISCOUNT_PCT} Enterprise Discount — Expires in {DISCOUNT_HOURS}h | CyberDudeBivash"
            body    = _email_upsell_low_buyer(name, product_name, expiry_ts)
            ok = _send_email(email, name, subject, body)
            if ok:
                stats["upsell_sent"] += 1
            else:
                stats["failed"] += 1
        else:
            # Higher buyer → thank + soft upsell to annual
            subject = f"Thank You for Supporting CyberDudeBivash SENTINEL APEX 🛡️"
            body    = _email_thank_high_buyer(name, product_name)
            ok = _send_email(email, name, subject, body)
            if ok:
                stats["thank_sent"] += 1
            else:
                stats["failed"] += 1

    _save_processed_ids(processed_ids)
    return stats


# ─────────────────────────────────────────────
# Main Entry
# ─────────────────────────────────────────────

def run(dry_run: bool = False) -> Dict:
    """
    Main entry point — fetch last 24h sales from Gumroad and dispatch emails.
    """
    from tools.gumroad_publisher import get_recent_sales

    logger.info("=" * 60)
    logger.info("CDB LEAD-TO-CASH AUTO-RESPONDER — Starting")
    logger.info(f"Dry Run: {dry_run}")

    # Fetch sales from last 24h
    after = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    sales = get_recent_sales(after_iso=after)
    logger.info(f"Fetched {len(sales)} sale(s) from last 24h")

    if not sales:
        logger.info("No sales to process.")
        return {"total": 0, "upsell_sent": 0, "thank_sent": 0, "skipped_dup": 0, "failed": 0}

    stats = process_sales(sales, dry_run=dry_run)

    logger.info(f"Auto-Responder Complete: {stats}")
    return stats


if __name__ == "__main__":
    import logging as _log
    _log.basicConfig(level=_log.INFO, format="%(asctime)s [CDB-AUTORESPONDER] %(message)s")
    import sys
    dry = "--dry-run" in sys.argv
    result = run(dry_run=dry)
    print(f"\nResult: {result}")
