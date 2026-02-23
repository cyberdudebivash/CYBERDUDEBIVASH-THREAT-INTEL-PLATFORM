"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — LinkedIn Platform
Posts to LinkedIn Company/Showcase Page and optionally personal profile.
API: LinkedIn Marketing Developer Platform v2 (UGC Posts)

Requires:
  - LINKEDIN_ACCESS_TOKEN  : OAuth2 access token (w_organization_social scope)
  - LINKEDIN_AUTHOR_URN    : urn:li:organization:XXXXXXX  (Showcase/Company page)
  - LINKEDIN_PERSONAL_URN  : urn:li:person:XXXXXXX        (personal profile, optional)
"""

import logging
import requests
from typing import Dict, Any

log = logging.getLogger("LinkedIn")

UGCPOST_URL = "https://api.linkedin.com/v2/ugcPosts"


class LinkedInPoster:
    def __init__(self, config):
        self.token = config.LINKEDIN_ACCESS_TOKEN
        self.author_urn = config.LINKEDIN_AUTHOR_URN       # showcase/org page
        self.personal_urn = config.LINKEDIN_PERSONAL_URN   # personal profile (optional)

    def is_configured(self) -> bool:
        return bool(self.token and self.author_urn)

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Post article share to LinkedIn organization page."""
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json',
            'X-Restli-Protocol-Version': '2.0.0',
        }

        payload = {
            "author": self.author_urn,
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {
                        "text": post_text
                    },
                    "shareMediaCategory": "ARTICLE",
                    "media": [
                        {
                            "status": "READY",
                            "originalUrl": item['link'],
                            "title": {
                                "text": item['title']
                            },
                            "description": {
                                "text": item.get('summary', '')[:200]
                            }
                        }
                    ]
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
            }
        }

        try:
            resp = requests.post(UGCPOST_URL, headers=headers, json=payload, timeout=30)
            if resp.status_code in (200, 201):
                post_id = resp.headers.get('X-RestLi-Id', resp.json().get('id', ''))
                log.info(f"LinkedIn posted: {post_id}")
                return {'success': True, 'post_id': post_id}
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                log.error(f"LinkedIn post failed: {error_msg}")
                return {'success': False, 'error': error_msg}
        except requests.RequestException as e:
            log.error(f"LinkedIn request exception: {e}")
            return {'success': False, 'error': str(e)}
