"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Threads Platform
Posts via Threads API (Meta Graph API).

Requires:
  - THREADS_ACCESS_TOKEN : Long-lived access token from Meta Developers
  - THREADS_USER_ID      : Your Threads user numeric ID

How to get: https://developers.facebook.com
  Create app > Add Threads product > Authorize + exchange for long-lived token
  Permissions: threads_basic, threads_content_publish
"""

import logging
import requests
from typing import Dict, Any

log = logging.getLogger("Threads")

GRAPH_URL = "https://graph.threads.net/v1.0"


class ThreadsPoster:
    def __init__(self, config):
        self.token = config.THREADS_ACCESS_TOKEN
        self.user_id = config.THREADS_USER_ID

    def is_configured(self) -> bool:
        return bool(self.token and self.user_id)

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Post to Threads using 2-step: create container → publish."""
        try:
            # Step 1: Create media container
            container_id = self._create_container(item, post_text[:500])
            if not container_id:
                return {'success': False, 'error': 'Failed to create Threads container'}

            # Step 2: Publish container
            return self._publish_container(container_id)

        except requests.RequestException as e:
            log.error(f"Threads request exception: {e}")
            return {'success': False, 'error': str(e)}

    def _create_container(self, item: Dict[str, Any], text: str) -> str:
        """Create a Threads media container."""
        url = f"{GRAPH_URL}/{self.user_id}/threads"
        params = {
            'media_type': 'TEXT',
            'text': text,
            'access_token': self.token,
        }

        resp = requests.post(url, params=params, timeout=30)
        if resp.status_code == 200:
            container_id = resp.json().get('id', '')
            log.debug(f"Threads container created: {container_id}")
            return container_id
        else:
            log.error(f"Threads container creation failed: HTTP {resp.status_code} {resp.text[:200]}")
            return None

    def _publish_container(self, container_id: str) -> Dict[str, Any]:
        """Publish a Threads container."""
        import time
        time.sleep(2)  # Brief pause before publishing

        url = f"{GRAPH_URL}/{self.user_id}/threads_publish"
        params = {
            'creation_id': container_id,
            'access_token': self.token,
        }

        resp = requests.post(url, params=params, timeout=30)
        if resp.status_code == 200:
            post_id = resp.json().get('id', '')
            log.info(f"Threads published: {post_id}")
            return {'success': True, 'post_id': post_id}
        else:
            error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
            log.error(f"Threads publish failed: {error_msg}")
            return {'success': False, 'error': error_msg}
