"""
social_bot.py — CyberDudeBivash Social Dispatcher v1.4
Standardized for LinkedIn 'member' URN logic.
Resolves 422 Unprocessable Entity error.
"""
import os
import requests
import logging

# Initialize CDB-SOCIAL Logger
logger = logging.getLogger("CDB-SOCIAL")

def post_to_linkedin(message, url):
    """
    Dispatches threat intelligence to the personal LinkedIn feed.
    Uses the modern 'member' URN type for personal profile authorization.
    """
    try:
        # Fetching credentials from GitHub Environment
        access_token = os.getenv("LINKEDIN_ACCESS_TOKEN")
        member_id = os.getenv("LINKEDIN_MEMBER_URN")

        if not access_token or not member_id:
            logger.warning("LinkedIn credentials missing (Token or Member ID). Skipping broadcast.")
            return

        # LinkedIn ugcPosts Endpoint (v2)
        endpoint = "https://api.linkedin.com/v2/ugcPosts"
        
        headers = {
            "Authorization": f"Bearer {access_token.strip()}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }

        # The 'author' field must use 'urn:li:member:' with a numeric ID
        payload = {
            "author": f"urn:li:member:{member_id}",
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

        # Execution of the POST request
        response = requests.post(endpoint, headers=headers, json=payload)
        
        if response.status_code == 201:
            logger.info("✓ LinkedIn broadcast successful. Post is now live on your feed.")
        else:
            # Captures exact API response for failure troubleshooting
            logger.error(f"LinkedIn failure {response.status_code}: {response.text}")

    except Exception as e:
        logger.error(f"Social component encountered a critical failure: {e}")

def broadcast_to_social(title, url, score):
    """
    Orchestrates the social broadcast across different platforms.
    Constructs a high-impact advisory message for the professional audience.
    """
    severity = "🔴 CRITICAL" if score >= 8.5 else "🟠 HIGH"
    
    # Constructing the LinkedIn-optimized message
    message = (
        f"{severity} THREAT ADVISORY\n"
        f"━━━━━━━━━━━━━━━\n"
        f"THREAT: {title}\n"
        f"CDB-RISK INDEX: {score}/10.0\n\n"
        f"Our Sentinel has triaged this incident. Full technical analysis "
        f"and indicators of compromise (IoC) are available below.\n\n"
        f"🔗 Technical Details: {url}\n\n"
        f"#CyberSecurity #ThreatIntel #CyberDudeBivash #InfoSec"
    )

    # Trigger the LinkedIn Dispatch
    post_to_linkedin(message, url)
    
    # Note: X (Twitter) logic is currently dormant until keys are provided.
