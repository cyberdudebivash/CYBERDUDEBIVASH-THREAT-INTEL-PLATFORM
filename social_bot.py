"""
social_bot.py — CyberDudeBivash Social Dispatcher v1.2
Enterprise-safe automated broadcasting to X and LinkedIn Member Feed.
"""

import os
import requests
import logging
import tweepy

logger = logging.getLogger("CDB-SOCIAL")

# ==============================
# Helper: Format Social Message
# ==============================
def build_message(title, url, score):
    """
    Constructs the high-impact threat advisory message.
    Optimized for professional engagement.
    """
    severity = "🔴 CRITICAL" if score >= 8.5 else "🟠 HIGH" if score >= 7 else "🟡 MODERATE"
    
    base_message = (
        f"{severity} THREAT DETECTED\n"
        f"━━━━━━━━━━━━━━━\n"
        f"THREAT: {title}\n"
        f"CDB-RISK SCORE: {score}/10.0\n\n"
        f"Our AI Sentinel has triaged this incident. "
        f"Full technical analysis and STIX JSON data available below.\n\n"
        f"🔗 Data: {url}\n\n"
        f"#CyberSecurity #ThreatIntel #CyberBivash #InfoSec"
    )

    # X (Twitter) character safety (280 limit)
    if len(base_message) > 275:
        # Truncate title if needed to keep the URL visible
        truncated_title = title[:100] + "..."
        base_message = (
            f"{severity} THREAT: {truncated_title}\n"
            f"Risk: {score}/10\n"
            f"Analysis: {url}\n\n"
            f"#CyberSecurity #ThreatIntel"
        )

    return base_message


# ==============================
# X (Twitter) Broadcaster
# ==============================
def post_to_x(message):
    """Dispatches the alert to X (Twitter) using Tweepy v2."""
    try:
        # Check for presence of all X secrets
        keys = ["X_API_KEY", "X_API_SECRET", "X_ACCESS_TOKEN", "X_ACCESS_SECRET"]
        if not all(os.getenv(key) for key in keys):
            logger.warning("X (Twitter) credentials missing. Skipping.")
            return

        client = tweepy.Client(
            consumer_key=os.getenv("X_API_KEY"),
            consumer_secret=os.getenv("X_API_SECRET"),
            access_token=os.getenv("X_ACCESS_TOKEN"),
            access_token_secret=os.getenv("X_ACCESS_SECRET"),
        )

        client.create_tweet(text=message)
        logger.info("✓ X broadcast successful.")
    except Exception as e:
        logger.error(f"X dispatch failed: {e}")


# ==============================
# LinkedIn Broadcaster (Member Feed)
# ==============================
def post_to_linkedin(message, url):
    """
    Dispatches to your personal LinkedIn feed using w_member_social scope.
    Target URN: ACoAAE4OXHYBPtyv_08XVs788TBLr9xYyHno_gI
    """
    try:
        access_token = os.getenv("LINKEDIN_ACCESS_TOKEN")
        member_urn = os.getenv("LINKEDIN_MEMBER_URN")

        if not access_token or not member_urn:
            logger.warning("LinkedIn Member credentials or URN missing. Skipping.")
            return

        # API V2 Endpoint for User-Generated Content (ugcPosts)
        endpoint = "https://api.linkedin.com/v2/ugcPosts"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }

        # Payload formatted specifically for Person (Member) author type
        payload = {
            "author": f"urn:li:person:{member_urn}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {
                        "text": message
                    },
                    "shareMediaCategory": "ARTICLE",
                    "media": [
                        {
                            "status": "READY",
                            "originalUrl": url
                        }
                    ]
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
            }
        }

        response = requests.post(endpoint, headers=headers, json=payload)

        if response.status_code == 201:
            logger.info("✓ LinkedIn Personal Feed broadcast successful.")
        else:
            logger.error(f"LinkedIn failed: {response.status_code} - {response.text}")

    except Exception as e:
        logger.error(f"LinkedIn dispatch failed: {e}")


# ==============================
# Master Social Orchestrator
# ==============================
def broadcast_to_social(title, url, score):
    """Entry point for the social media amplification layer."""
    logger.info("Initiating global professional broadcast...")

    # Build optimized message
    message = build_message(title, url, score)

    # Dispatch to platforms
    post_to_x(message)
    post_to_linkedin(message, url)
