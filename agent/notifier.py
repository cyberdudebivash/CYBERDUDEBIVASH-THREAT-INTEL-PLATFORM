#!/usr/bin/env python3
"""
notifier.py — CyberDudeBivash v17.0 (SENTINEL APEX ULTRA)
ENHANCED: Red Alert Engine with MITRE & TLP Awareness.

v17.0 ADDITIONS (fully non-breaking):
  - Microsoft Teams webhook support (TEAMS_WEBHOOK env var)
  - Generic webhook publisher (GENERIC_WEBHOOK_URL env var)
  - Enhanced structured logging for all dispatch events
  - Alert dispatch summary returned as dict for telemetry integration
  - send_sentinel_alert() signature UNCHANGED
"""
import os
import json
import requests
import logging
from typing import Optional, List, Dict

# Initialize Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CDB-NOTIFIER")


def send_sentinel_alert(headline, risk_score, post_url, mitre_data=None):
    """
    Dispatches real-time alerts to Discord, Slack, Teams, and Generic webhooks.
    SIGNATURE UNCHANGED from v7.4.1 — fully backward compatible.

    v17.0: Added Teams + Generic webhook dispatchers.
    Returns: dict summary of dispatch results for telemetry.
    """

    # 1. Threshold Gate: Only alert for critical threats (Risk >= 9.0)
    if risk_score < 9.0:
        logger.info(f"[-] Risk Score {risk_score} is below Red Alert threshold (9.0).")
        return {"dispatched": False, "reason": "below_threshold", "risk_score": risk_score}

    # 2. Retrieve Webhook URLs from environment
    discord_webhook = os.environ.get('DISCORD_WEBHOOK')
    slack_webhook = os.environ.get('SLACK_WEBHOOK')
    teams_webhook = os.environ.get('TEAMS_WEBHOOK')
    generic_webhook = os.environ.get('GENERIC_WEBHOOK_URL')

    if not any([discord_webhook, slack_webhook, teams_webhook, generic_webhook]):
        logger.warning("[!] No notification webhooks configured. Skipping alerts.")
        return {"dispatched": False, "reason": "no_webhooks_configured"}

    # 3. Intelligence Preparation
    tlp_label = "TLP:RED" if risk_score >= 9.0 else ("TLP:AMBER" if risk_score >= 7.0 else "TLP:CLEAR")
    tactic_summary = ", ".join([m['tactic'] for m in mitre_data]) if mitre_data else "General Exploit"
    severity_label = "CRITICAL" if risk_score >= 8.5 else "HIGH"

    dispatch_results = {
        "dispatched": True,
        "headline": headline[:80],
        "risk_score": risk_score,
        "severity": severity_label,
        "tlp": tlp_label,
        "channels": {},
    }

    # 4. Discord Red Alert
    if discord_webhook:
        success = _dispatch_discord(discord_webhook, headline, risk_score, post_url, tlp_label, tactic_summary)
        dispatch_results["channels"]["discord"] = "sent" if success else "failed"

    # 5. Slack Red Alert
    if slack_webhook:
        success = _dispatch_slack(slack_webhook, headline, risk_score, post_url, tlp_label, tactic_summary)
        dispatch_results["channels"]["slack"] = "sent" if success else "failed"

    # 6. Microsoft Teams Red Alert (NEW in v17.0)
    if teams_webhook:
        success = _dispatch_teams(teams_webhook, headline, risk_score, post_url, tlp_label, tactic_summary)
        dispatch_results["channels"]["teams"] = "sent" if success else "failed"

    # 7. Generic Webhook (NEW in v17.0)
    if generic_webhook:
        success = _dispatch_generic(generic_webhook, headline, risk_score, post_url, tlp_label, tactic_summary, mitre_data)
        dispatch_results["channels"]["generic"] = "sent" if success else "failed"

    total_sent = sum(1 for v in dispatch_results["channels"].values() if v == "sent")
    logger.info(
        f"✅ Alert Dispatch Complete | "
        f"Channels attempted: {len(dispatch_results['channels'])} | "
        f"Sent: {total_sent} | "
        f"Risk: {risk_score}/10 | TLP: {tlp_label}"
    )

    return dispatch_results


# ── Individual channel dispatchers ────────────────────────────────────────────

def _dispatch_discord(
    webhook_url: str, headline: str, risk_score: float,
    post_url: str, tlp_label: str, tactic_summary: str
) -> bool:
    """Dispatch Discord alert embed."""
    payload = {
        "username": "CDB Sentinel Red Alert",
        "avatar_url": "https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/assets/logo.png",
        "embeds": [{
            "title": f"🚨 CRITICAL ADVISORY: {headline}",
            "url": post_url,
            "color": 15158332,
            "description": "The APEX Engine has triaged a high-severity threat node requiring immediate attention.",
            "fields": [
                {"name": "Risk Score", "value": f"**{risk_score}/10**", "inline": True},
                {"name": "Classification", "value": f"**{tlp_label}**", "inline": True},
                {"name": "Tactics Identified", "value": f"```{tactic_summary}```", "inline": False},
            ],
            "footer": {"text": "CyberDudeBivash GOC Infrastructure | v17.0"}
        }]
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 204:
            logger.info("✓ Discord Red Alert successfully dispatched.")
            return True
        else:
            logger.warning(f"Discord returned status {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"✖ Discord Webhook Failure: {e}")
        return False


def _dispatch_slack(
    webhook_url: str, headline: str, risk_score: float,
    post_url: str, tlp_label: str, tactic_summary: str
) -> bool:
    """Dispatch Slack Block Kit alert."""
    payload = {
        "text": f"*🚨 RED ALERT: {headline}*",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🚨 CRITICAL THREAT DETECTED*\n*Advisory:* {headline}\n*Risk Score:* `{risk_score}/10` | *TLP:* `{tlp_label}`"
                }
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
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("✓ Slack Red Alert successfully dispatched.")
            return True
        else:
            logger.warning(f"Slack returned status {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"✖ Slack Webhook Failure: {e}")
        return False


def _dispatch_teams(
    webhook_url: str, headline: str, risk_score: float,
    post_url: str, tlp_label: str, tactic_summary: str
) -> bool:
    """
    Dispatch Microsoft Teams Adaptive Card alert.
    Uses Teams Incoming Webhook format (MessageCard / Adaptive Card).
    """
    severity_color = "FF0000" if risk_score >= 9.0 else "FF9F43"
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": severity_color,
        "summary": f"CDB SENTINEL RED ALERT: {headline}",
        "sections": [{
            "activityTitle": f"🚨 CRITICAL THREAT ADVISORY",
            "activitySubtitle": "CyberDudeBivash SENTINEL APEX v17.0",
            "activityText": headline,
            "facts": [
                {"name": "Risk Score", "value": f"{risk_score}/10"},
                {"name": "Classification", "value": tlp_label},
                {"name": "Tactics", "value": tactic_summary},
                {"name": "Platform", "value": "SENTINEL APEX GOC"},
            ],
            "markdown": True,
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "View Full Report",
            "targets": [{"os": "default", "uri": post_url}]
        }]
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("✓ Teams Red Alert successfully dispatched.")
            return True
        else:
            logger.warning(f"Teams returned status {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"✖ Teams Webhook Failure: {e}")
        return False


def _dispatch_generic(
    webhook_url: str, headline: str, risk_score: float,
    post_url: str, tlp_label: str, tactic_summary: str,
    mitre_data: Optional[List[Dict]] = None,
) -> bool:
    """
    Dispatch structured JSON payload to a generic webhook endpoint.
    Compatible with: Zapier, Make (Integromat), PagerDuty, JIRA, custom SOAR.
    """
    payload = {
        "source": "CyberDudeBivash SENTINEL APEX",
        "version": "v17.0",
        "event_type": "CRITICAL_THREAT_ALERT",
        "alert": {
            "headline": headline,
            "risk_score": risk_score,
            "severity": "CRITICAL" if risk_score >= 8.5 else "HIGH",
            "tlp": tlp_label,
            "report_url": post_url,
            "tactics": tactic_summary,
            "mitre_techniques": [
                {"id": m.get("id"), "name": m.get("name"), "tactic": m.get("tactic")}
                for m in (mitre_data or [])
            ],
        },
    }
    try:
        resp = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if 200 <= resp.status_code < 300:
            logger.info(f"✓ Generic Webhook dispatched (HTTP {resp.status_code}).")
            return True
        else:
            logger.warning(f"Generic webhook returned status {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"✖ Generic Webhook Failure: {e}")
        return False
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
