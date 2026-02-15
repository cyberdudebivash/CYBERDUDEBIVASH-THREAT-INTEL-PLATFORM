#!/usr/bin/env python3
"""
notifier.py — CyberDudeBivash v7.4.1
Red Alert Engine: Real-time Discord & Slack Webhooks with MITRE Context.
"""
import os
import requests
import logging

logger = logging.getLogger("CDB-NOTIFIER")

def send_sentinel_alert(headline, risk_score, post_url, mitre_data=None):
    """
    Dispatches alerts to Discord/Slack if risk score is critical.
    Fixed: Now accepts mitre_data to resolve TypeError.
    """
    if risk_score < 9.0:
        logger.info(f"Risk Score {risk_score} below alert threshold. No webhook sent.")
        return

    discord_webhook = os.environ.get('DISCORD_WEBHOOK')
    slack_webhook = os.environ.get('SLACK_WEBHOOK')

    if discord_webhook:
        # Use mitre_data to enhance the alert description
        tactic_count = len(mitre_data) if mitre_data else 0
        payload = {
            "username": "CDB Sentinel Red Alert",
            "embeds": [{
                "title": f"🚨 CRITICAL THREAT: {headline}",
                "color": 15158332, # Red
                "fields": [
                    {"name": "Risk Score", "value": f"**{risk_score}/10**", "inline": True},
                    {"name": "MITRE Tactics", "value": f"{tactic_count} Detected", "inline": True},
                    {"name": "Action", "value": f"[View Full Advisory]({post_url})"}
                ],
                "footer": {"text": "CyberDudeBivash Pvt. Ltd. | APEX v7.4.1"}
            }]
        }
        try:
            requests.post(discord_webhook, json=payload)
            logger.info("✓ Discord Red Alert Dispatched.")
        except Exception as e:
            logger.error(f"Discord Alert Failure: {e}")

    if slack_webhook:
        slack_payload = {
            "text": f"*🚨 RED ALERT: {headline}*",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*🚨 RED ALERT: {headline}*\nRisk: `{risk_score}/10`"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"<{post_url}|View Technical Report>"}}
            ]
        }
        try:
            requests.post(slack_webhook, json=slack_payload)
            logger.info("✓ Slack Red Alert Dispatched.")
        except Exception as e:
            logger.error(f"Slack Alert Failure: {e}")
