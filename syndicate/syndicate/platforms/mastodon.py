"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Mastodon Platform
Posts to mastodon.social via REST API.
Completely free. No API approval needed.

Requires:
  - MASTODON_INSTANCE_URL  : e.g. https://mastodon.social
  - MASTODON_ACCESS_TOKEN  : from mastodon.social > Preferences > Development > New App
"""

import logging
import requests
from typing import Dict, Any

log = logging.getLogger("Mastodon")


class MastodonPoster:
    def __init__(self, config):
        self.instance_url = config.MASTODON_INSTANCE_URL.rstrip('/')
        self.token = config.MASTODON_ACCESS_TOKEN

    def is_configured(self) -> bool:
        return bool(self.token and self.instance_url)

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Post status to Mastodon."""
        url = f"{self.instance_url}/api/v1/statuses"
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json',
        }
        payload = {
            'status': post_text[:500],  # Mastodon 500 char limit
            'visibility': 'public',
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code in (200, 201):
                data = resp.json()
                post_id = data.get('id', '')
                post_url = data.get('url', '')
                log.info(f"Mastodon posted: {post_id}")
                return {'success': True, 'post_id': post_id, 'post_url': post_url}
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                log.error(f"Mastodon post failed: {error_msg}")
                return {'success': False, 'error': error_msg}
        except requests.RequestException as e:
            log.error(f"Mastodon request exception: {e}")
            return {'success': False, 'error': str(e)}
