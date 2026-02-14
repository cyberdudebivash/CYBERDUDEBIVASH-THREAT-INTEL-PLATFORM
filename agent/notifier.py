"""
notifier.py — CyberDudeBivash Alert Dispatcher v1.0
Handles real-time broadcasting of threat intel to Telegram and Discord.
"""

import requests
import os
import logging

logger = logging.getLogger("CDB-NOTIFIER")

def send_sentinel_alert(title: str, score: float, url: str):
    """Dispatches color-coded alerts to social ecosystems."""
    
    # 1. Configuration from GitHub Secrets
    tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
    tg_chat_id = os.getenv("TELEGRAM_CHAT_ID")
    discord_url = os.getenv("DISCORD_WEBHOOK_URL")

    # Severity Logic
    emoji = "🔴" if score >= 8.5 else "🟠" if score >= 6.5 else "🟡"
    color = 16726590 if score >= 8.5 else 16752451 if score >= 6.5 else 16701783

    # --- TELEGRAM DISPATCH ---
    if tg_token and tg_chat_id:
        tg_msg = (
            f"{emoji} *CYBERBIVASH INTEL ALERT*\n"
            f"━━━━━━━━━━━━━━━\n"
            f"*THREAT:* {title}\n"
            f"*RISK INDEX:* {score}/10.0\n"
            f"*STATUS:* ACTIONABLE / TLP:CLEAR\n\n"
            f"🔗 [VIEW FULL REPORT & JSON]({url})"
        )
        try:
            requests.post(f"https://api.telegram.org/bot{tg_token}/sendMessage", 
                          data={"chat_id": tg_chat_id, "text": tg_msg, "parse_mode": "Markdown"}, timeout=10)
            logger.info("Telegram alert dispatched successfully.")
        except Exception as e:
            logger.error(f"Telegram dispatch failed: {e}")

    # --- DISCORD DISPATCH ---
    if discord_url:
        payload = {
            "embeds": [{
                "title": f"{emoji} CDB-SENTINEL: {title}",
                "url": url,
                "color": color,
                "fields": [
                    {"name": "CDB-Risk Score", "value": f"**{score}/10.0**", "inline": True},
                    {"name": "Classification", "value": "TLP:CLEAR", "inline": True}
                ],
                "footer": {"text": "© 2026 CyberDudeBivash Pvt Ltd — Global Digital Sovereignty"}
            }]
        }
        try:
            requests.post(discord_url, json=payload, timeout=10)
            logger.info("Discord alert dispatched successfully.")
        except Exception as e:
            logger.error(f"Discord dispatch failed: {e}")
