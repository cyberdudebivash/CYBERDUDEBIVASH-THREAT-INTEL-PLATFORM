"""
social_bot.py — CyberDudeBivash Social Dispatcher v2.2
APEX Edition: Hardened Authorization & Diagnostic Logging.
"""
import os
import requests
import logging

logger = logging.getLogger("CDB-SOCIAL")

def post_to_linkedin(message, url):
    """Broadcasts to feed with hardened token validation and URN fallback."""
    try:
        # Standardize credential extraction
        token = os.getenv("LINKEDIN_ACCESS_TOKEN", "").strip()
        member_id = os.getenv("LINKEDIN_MEMBER_URN", "").strip()

        if not token or not member_id:
            logger.warning("LinkedIn broadcast skipped: Credentials missing.")
            return

        endpoint = "https://api.linkedin.com/v2/ugcPosts"
        
        # 2026 OAuth Protocol Headers
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }

        # Modern Personal Member Payload
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

        # Attempt broadcast with smart URN retry logic
        response = requests.post(endpoint, headers=headers, json=payload)
        
        if response.status_code in [403, 422]:
            logger.info("Transitioning to member URN fallback...")
            payload["author"] = f"urn:li:member:{member_id}"
            response = requests.post(endpoint, headers=headers, json=payload)

        if response.status_code == 201:
            logger.info("✓ LinkedIn broadcast successful! Advisory is live.")
        else:
            # Enhanced diagnostic logging for Run-time debugging
            logger.error(f"LinkedIn API Refusal {response.status_code}: {response.text}")

    except Exception as e:
        logger.error(f"Social broadcast system encountered a critical failure: {e}")

def broadcast_to_social(title, url, score):
    """Main entry point for professional network alert distribution."""
    severity = "🔴 CRITICAL" if score >= 8.5 else "🟠 HIGH"
    message = (
        f"{severity} THREAT ADVISORY\n"
        f"━━━━━━━━━━━━━━━\n"
        f"THREAT: {title}\n"
        f"CDB-RISK INDEX: {score}/10.0\n\n"
        f"🔗 Technical Analysis: {url}\n\n"
        f"#CyberSecurity #ThreatIntel #CyberDudeBivash"
    )
    post_to_linkedin(message, url)
