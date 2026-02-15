#!/usr/bin/env python3
"""
notifier.py — CyberDudeBivash v7.4.1
Final Production Version: Red Alert Engine with MITRE & TLP Awareness.
"""
import os
import requests
import logging

# Initialize Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CDB-NOTIFIER")

def send_sentinel_alert(headline, risk_score, post_url, mitre_data=None):
    """
    Dispatches real-time alerts to Discord and Slack for high-risk threats.
    FIX: Added 'mitre_data=None' to resolve TypeError.
    """
    
    # 1. Threshold Gate: Only alert for critical threats (Risk >= 9.0)
    if risk_score < 9.0:
        logger.info(f"[-] Risk Score {risk_score} is below Red Alert threshold (9.0).")
        return

    # 2. Retrieve Webhook URLs from GitHub Secrets
    discord_webhook = os.environ.get('DISCORD_WEBHOOK')
    slack_webhook = os.environ.get('SLACK_WEBHOOK')

    if not discord_webhook and not slack_webhook:
        logger.warning("[!] No notification webhooks configured. Skipping alerts.")
        return

    # 3. Intelligence Preparation
    tlp_label = "TLP:AMBER" if risk_score >= 7.0 else "TLP:CLEAR"
    tactic_summary = ", ".join([m['tactic'] for m in mitre_data]) if mitre_data else "General Exploit"

    # 4. Dispatch Discord Red Alert
    if discord_webhook:
        discord_payload = {
            "username": "CDB Sentinel Red Alert",
            "avatar_url": "https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/assets/logo.png",
            "embeds": [{
                "title": f"🚨 CRITICAL ADVISORY: {headline}",
                "url": post_url,
                "color": 15158332, # Vibrant Red
                "description": f"The APEX Engine has triaged a high-severity threat node requiring immediate attention.",
                "fields": [
                    {"name": "Severity", "value": f"**{risk_score}/10**", "inline": True},
                    {"name": "Classification", "value": f"**{tlp_label}**", "inline": True},
                    {"name": "Tactics Identified", "value": f"```{tactic_summary}```", "inline": False}
                ],
                "footer": {"text": "CyberDudeBivash GOC Infrastructure | v7.4.1"}
            }]
        }
        try:
            resp = requests.post(discord_webhook, json=discord_payload, timeout=10)
            if resp.status_code == 204:
                logger.info("✓ Discord Red Alert successfully dispatched.")
        except Exception as e:
            logger.error(f"✖ Discord Webhook Failure: {e}")

    # 5. Dispatch Slack Red Alert
    if slack_webhook:
        slack_payload = {
            "text": f"*🚨 RED ALERT: {headline}*",
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🚨 CRITICAL THREAT DETECTED*\n*Advisory:* {headline}\n*Risk Score:* `{risk_score}/10` | *TLP:* `{tlp_label}`"}
                },
                {
                    "type": "section", 
                    "text": {"type": "mrkdwn", "text": f"*Tactics:* {tactic_summary}"}
                },
                {
                    "type": "actions",
                    "elements": [{
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Technical Report"},
                        "url": post_url,
                        "style": "danger"
                    }]
                }
            ]
        }
        try:
            resp = requests.post(slack_webhook, json=slack_payload, timeout=10)
            if resp.status_code == 200:
                logger.info("✓ Slack Red Alert successfully dispatched.")
        except Exception as e:
            logger.error(f"✖ Slack Webhook Failure: {e}")
