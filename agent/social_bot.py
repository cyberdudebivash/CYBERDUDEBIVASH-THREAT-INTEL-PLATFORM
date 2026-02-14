"""
social_bot.py — CyberDudeBivash Social Dispatcher v2.3
APEX Edition: Bearer-Audit & Diagnostic Header Layer.
"""
import os
import requests
import logging

logger = logging.getLogger("CDB-SOCIAL")

def post_to_linkedin(message, url):
    """Broadcasts to feed with hardened validation for 2026 protocols."""
    try:
        # Sanitization: Ensure no hidden newline/space corrupts the header
        token = os.getenv("LINKEDIN_ACCESS_TOKEN", "").strip()
        member_id = os.getenv("LINKEDIN_MEMBER_URN", "").strip()

        if not token or not member_id:
            logger.warning("LinkedIn broadcast aborted: Missing credentials.")
            return

        endpoint = "https://api.linkedin.com/v2/ugcPosts"
        
        # Standardized 2026 Authorization Header
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }

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

        # Attempt primary dispatch
        response = requests.post(endpoint, headers=headers, json=payload)
        
        # Fallback for transitionary Member URN types
        if response.status_code in [403, 422]:
            logger.info("Transitioning author URN to member fallback...")
            payload["author"] = f"urn:li:member:{member_id}"
            response = requests.post(endpoint, headers=headers, json=payload)

        if response.status_code == 201:
            logger.info("✓ LinkedIn broadcast successful! Advisory is live.")
        else:
            # Detailed Refusal Audit
            logger.error(f"LinkedIn API Refusal {response.status_code}: {response.text}")

    except Exception as e:
        logger.error(f"Social broadcast system failure: {e}")

def broadcast_to_social(title, url, score):
    """Master orchestrator for professional network alerts."""
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
