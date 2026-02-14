"""
social_bot.py — CyberDudeBivash Social Dispatcher v1.9
Final Production Edition: Validated with Three-Scope Handshake.
"""
import os
import requests
import logging

logger = logging.getLogger("CDB-SOCIAL")

def post_to_linkedin(message, url):
    """Broadcasts threat intel to personal feed with multi-URN fallback."""
    try:
        token = os.getenv("LINKEDIN_ACCESS_TOKEN")
        member_id = os.getenv("LINKEDIN_MEMBER_URN")

        if not token or not member_id:
            logger.warning("LinkedIn credentials missing. Check GitHub Secrets.")
            return

        endpoint = "https://api.linkedin.com/v2/ugcPosts"
        headers = {
            "Authorization": f"Bearer {token.strip()}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }

        # Optimized payload using the member ID confirmed in previous logs
        payload = {
            "author": f"urn:li:person:{member_id.strip()}",
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

        # First attempt: standard 'person' URN
        response = requests.post(endpoint, headers=headers, json=payload)
        
        # If person fails with 403 or 422, automatically retry with 'member'
        if response.status_code in [403, 422]:
            logger.info(f"Retrying with member URN fallback...")
            payload["author"] = f"urn:li:member:{member_id.strip()}"
            response = requests.post(endpoint, headers=headers, json=payload)

        if response.status_code == 201:
            logger.info("✓ LinkedIn broadcast successful! Post is live.")
        else:
            logger.error(f"LinkedIn final failure {response.status_code}: {response.text}")

    except Exception as e:
        logger.error(f"Social broadcast system encountered an error: {e}")

def broadcast_to_social(title, url, score):
    """Main orchestrator for professional network amplification."""
    severity = "🔴 CRITICAL" if score >= 8.5 else "🟠 HIGH"
    message = (
        f"{severity} THREAT ADVISORY\n"
        f"━━━━━━━━━━━━━━━\n"
        f"THREAT: {title}\n"
        f"CDB-RISK SCORE: {score}/10.0\n\n"
        f"🔗 Technical Analysis: {url}\n\n"
        f"#CyberSecurity #ThreatIntel #CyberDudeBivash"
    )
    post_to_linkedin(message, url)
