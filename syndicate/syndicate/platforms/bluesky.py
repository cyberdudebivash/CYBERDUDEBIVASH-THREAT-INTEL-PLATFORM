"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Bluesky Platform
Posts via AT Protocol (atproto). 100% free.

Requires:
  - BLUESKY_HANDLE      : e.g. cyberdudebivash.bsky.social
  - BLUESKY_APP_PASSWORD: from bsky.app > Settings > App Passwords
"""

import logging
import requests
from datetime import datetime, timezone
from typing import Dict, Any

log = logging.getLogger("Bluesky")

ATP_HOST = "https://bsky.social"


class BlueSkyPoster:
    def __init__(self, config):
        self.handle = config.BLUESKY_HANDLE
        self.app_password = config.BLUESKY_APP_PASSWORD
        self._session = None

    def is_configured(self) -> bool:
        return bool(self.handle and self.app_password)

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Post to Bluesky using AT Protocol."""
        try:
            session = self._get_session()
            if not session:
                return {'success': False, 'error': 'Authentication failed'}

            text = post_text[:300]

            # Build post record with link facet
            record = {
                '$type': 'app.bsky.feed.post',
                'text': text,
                'createdAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'langs': ['en'],
            }

            # Add link embed card
            link_url = item.get('link', '')
            if link_url:
                record['embed'] = {
                    '$type': 'app.bsky.embed.external',
                    'external': {
                        'uri': link_url,
                        'title': item.get('title', ''),
                        'description': item.get('summary', '')[:200],
                    }
                }

            payload = {
                'repo': session['did'],
                'collection': 'app.bsky.feed.post',
                'record': record,
            }

            resp = requests.post(
                f"{ATP_HOST}/xrpc/com.atproto.repo.createRecord",
                headers={
                    'Authorization': f"Bearer {session['accessJwt']}",
                    'Content-Type': 'application/json',
                },
                json=payload,
                timeout=30,
            )

            if resp.status_code in (200, 201):
                data = resp.json()
                uri = data.get('uri', '')
                log.info(f"Bluesky posted: {uri}")
                return {'success': True, 'post_id': uri}
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                log.error(f"Bluesky post failed: {error_msg}")
                return {'success': False, 'error': error_msg}

        except requests.RequestException as e:
            log.error(f"Bluesky request exception: {e}")
            return {'success': False, 'error': str(e)}

    def _get_session(self) -> Dict[str, Any]:
        """Authenticate and return session data."""
        if self._session:
            return self._session

        try:
            resp = requests.post(
                f"{ATP_HOST}/xrpc/com.atproto.server.createSession",
                json={
                    'identifier': self.handle,
                    'password': self.app_password,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                self._session = resp.json()
                log.info(f"Bluesky authenticated as: {self.handle}")
                return self._session
            else:
                log.error(f"Bluesky auth failed: HTTP {resp.status_code} {resp.text[:200]}")
                return None
        except requests.RequestException as e:
            log.error(f"Bluesky auth exception: {e}")
            return None
