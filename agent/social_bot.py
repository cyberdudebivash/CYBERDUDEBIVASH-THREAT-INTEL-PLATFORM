"""
social_bot.py — CyberDudeBivash Social Dispatcher v1.5
Final Production Version: Validated for LinkedIn Member URN.
"""
import os
import requests
import logging

logger = logging.getLogger("CDB-SOCIAL")

def post_to_linkedin(message, url):
    """Broadcasts to personal LinkedIn feed using member URN logic."""
    try:
        access_token = os.getenv("LINKEDIN_ACCESS_TOKEN")
        member_id = os.getenv("LINKEDIN_MEMBER_URN")

        if not access_token or not member_id:
            logger.warning("LinkedIn credentials missing. Skipping.")
            return

        endpoint = "https://api.linkedin.com/v2/ugcPosts"
        headers = {
            "Authorization": f"Bearer {access_token.strip()}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }

        # FINAL FIX: Using urn:li:member as explicitly required by API logs
        payload = {
            "author": f"urn:li:member:{member_id}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": message},
                    "shareMediaCategory": "ARTICLE",
                    "media": [{"status": "READY", "originalUrl": url}]
                }
            },
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"}
        }

        response = requests.post(endpoint, headers=headers, json=payload)
        
        if response.status_code == 201:
            logger.info("✓ LinkedIn Personal Feed broadcast successful.")
        else:
            logger.error(f"LinkedIn failed {response.status_code}: {response.text}")

    except Exception as e:
        logger.error(f"Social component failed: {e}")

def broadcast_to_social(title, url, score):
    """Constructs and dispatches the advisory message."""
    severity = "🔴 CRITICAL" if score >= 8.5 else "🟠 HIGH"
    message = (
        f"{severity} THREAT ADVISORY\n"
        f"━━━━━━━━━━━━━━━\n"
        f"THREAT: {title}\n"
        f"CDB-RISK INDEX: {score}/10.0\n\n"
        f"🔗 Analysis: {url}\n\n"
        f"#CyberSecurity #ThreatIntel #CyberDudeBivash"
    )
    post_to_linkedin(message, url)
