"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Facebook Platform
Posts to Facebook Page via Graph API.

Requires:
  - FACEBOOK_PAGE_ID           : Your Page numeric ID
  - FACEBOOK_PAGE_ACCESS_TOKEN : Long-lived page access token (never expires if refreshed)

How to get: https://developers.facebook.com > My Apps > Graph API Explorer
  - Get User Access Token with pages_manage_posts + pages_read_engagement permissions
  - Exchange for long-lived page access token via:
    GET /oauth/access_token?grant_type=fb_exchange_token&...
  - Then GET /{user-id}/accounts to get Page Access Token
"""

import logging
import requests
from typing import Dict, Any

log = logging.getLogger("Facebook")

GRAPH_URL = "https://graph.facebook.com/v18.0"


class FacebookPoster:
    def __init__(self, config):
        self.page_id = config.FACEBOOK_PAGE_ID
        self.page_token = config.FACEBOOK_PAGE_ACCESS_TOKEN

    def is_configured(self) -> bool:
        return bool(self.page_id and self.page_token)

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Post link share to Facebook Page."""
        url = f"{GRAPH_URL}/{self.page_id}/feed"
        payload = {
            'message': post_text[:2000],
            'link': item.get('link', ''),
            'access_token': self.page_token,
        }

        try:
            resp = requests.post(url, data=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                post_id = data.get('id', '')
                log.info(f"Facebook posted: {post_id}")
                return {'success': True, 'post_id': post_id}
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                log.error(f"Facebook post failed: {error_msg}")
                return {'success': False, 'error': error_msg}
        except requests.RequestException as e:
            log.error(f"Facebook request exception: {e}")
            return {'success': False, 'error': str(e)}
