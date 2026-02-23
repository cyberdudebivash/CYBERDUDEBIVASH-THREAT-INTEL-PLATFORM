"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Reddit Platform
Posts links to user profile subreddit (u/Immediate_Gold9789) via Reddit API.
Free tier: 100 requests/minute.

Requires:
  - REDDIT_CLIENT_ID
  - REDDIT_CLIENT_SECRET
  - REDDIT_USERNAME
  - REDDIT_PASSWORD
  - REDDIT_SUBREDDIT : e.g. u_Immediate_Gold9789

How to get: https://www.reddit.com/prefs/apps > Create App (script type)
"""

import logging
import requests
from typing import Dict, Any

log = logging.getLogger("Reddit")

REDDIT_API = "https://oauth.reddit.com"
TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
USER_AGENT = "CyberDudeBivash-Syndication/1.0 by cyberdudebivash"


class RedditPoster:
    def __init__(self, config):
        self.client_id = config.REDDIT_CLIENT_ID
        self.client_secret = config.REDDIT_CLIENT_SECRET
        self.username = config.REDDIT_USERNAME
        self.password = config.REDDIT_PASSWORD
        self.subreddit = config.REDDIT_SUBREDDIT
        self._token = None

    def is_configured(self) -> bool:
        return all([self.client_id, self.client_secret, self.username, self.password, self.subreddit])

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Submit link post to Reddit."""
        try:
            token = self._get_token()
            if not token:
                return {'success': False, 'error': 'Reddit auth failed'}

            headers = {
                'Authorization': f'bearer {token}',
                'User-Agent': USER_AGENT,
            }

            payload = {
                'sr': self.subreddit,
                'kind': 'link',
                'title': item.get('title', '')[:300],
                'url': item.get('link', ''),
                'resubmit': True,
                'nsfw': False,
                'spoiler': False,
            }

            resp = requests.post(
                f"{REDDIT_API}/api/submit",
                headers=headers,
                data=payload,
                timeout=30,
            )

            if resp.status_code == 200:
                data = resp.json()
                post_data = data.get('json', {}).get('data', {})
                post_url = post_data.get('url', '')
                post_id = post_data.get('id', '')
                if post_id:
                    log.info(f"Reddit posted: {post_url}")
                    return {'success': True, 'post_id': post_id, 'post_url': post_url}
                else:
                    errors = data.get('json', {}).get('errors', [])
                    error_msg = str(errors) if errors else resp.text[:300]
                    log.error(f"Reddit post failed: {error_msg}")
                    return {'success': False, 'error': error_msg}
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                log.error(f"Reddit post failed: {error_msg}")
                return {'success': False, 'error': error_msg}

        except requests.RequestException as e:
            log.error(f"Reddit request exception: {e}")
            return {'success': False, 'error': str(e)}

    def _get_token(self) -> str:
        """Get OAuth access token via password flow."""
        if self._token:
            return self._token

        try:
            resp = requests.post(
                TOKEN_URL,
                auth=(self.client_id, self.client_secret),
                data={
                    'grant_type': 'password',
                    'username': self.username,
                    'password': self.password,
                },
                headers={'User-Agent': USER_AGENT},
                timeout=30,
            )
            if resp.status_code == 200:
                self._token = resp.json().get('access_token', '')
                log.info("Reddit authenticated successfully")
                return self._token
            else:
                log.error(f"Reddit auth failed: HTTP {resp.status_code}")
                return None
        except requests.RequestException as e:
            log.error(f"Reddit auth exception: {e}")
            return None
