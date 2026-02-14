"""
social_bot.py — CyberDudeBivash Social Dispatcher v2.0
APEX Edition: Token Sanitization & Multi-URN Fallback.
"""
import os
import requests
import logging

logger = logging.getLogger("CDB-SOCIAL")

def post_to_linkedin(message, url):
    """Broadcasts to personal feed with sanitized token handling."""
    try:
        # Use .strip() to remove hidden spaces/newlines from GitHub Secrets
        token = os.getenv("LINKEDIN_ACCESS_TOKEN", "").strip()
        member_id = os.getenv("LINKEDIN_MEMBER_URN", "").strip()

        if not token or not member_id:
            logger.warning("LinkedIn credentials missing or empty.")
            return

        endpoint = "https://api.linkedin.com/v2/ugcPosts"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }

        # Industry-standard personal profile payload
        payload = {
            "author": f"urn:li:person:{member_id}",
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

        # Primary attempt with 'person' URN
        response = requests.post(endpoint, headers=headers, json=payload)
        
        # Fallback logic for transitioning member URNs
        if response.status_code in [403, 422]:
            logger.info("Access denied for person URN. Retrying with member URN...")
            payload["author"] = f"urn:li:member:{member_id}"
            response = requests.post(endpoint, headers=headers, json=payload)

        if response.status_code == 201:
            logger.info("✓ LinkedIn broadcast successful! Post live.")
        else:
            logger.error(f"LinkedIn API Refusal {response.status_code}: {response.text}")

    except Exception as e:
        logger.error(f"Social broadcast system failure: {e}")

def broadcast_to_social(title, url, score):
    """Main entry point for professional network dispatch."""
    severity = "🔴 CRITICAL" if score >= 8.5 else "🟠 HIGH"
    message = (
        f"{severity} THREAT ADVISORY\n"
        f"━━━━━━━━━━━━━━━\n"
        f"THREAT: {title}\n"
        f"RISK: {score}/10.0\n\n"
        f"🔗 Technical Analysis: {url}\n\n"
        f"#CyberSecurity #ThreatIntel #CyberDudeBivash"
    )
    post_to_linkedin(message, url)
