"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Twitter/X Platform
Posts via Twitter API v2 using OAuth 1.0a.
Free tier: 1,500 tweets/month.

Requires:
  - TWITTER_API_KEY
  - TWITTER_API_SECRET
  - TWITTER_ACCESS_TOKEN
  - TWITTER_ACCESS_SECRET
"""

import logging
import time
import hmac
import hashlib
import base64
import urllib.parse
import secrets
import requests
from typing import Dict, Any

log = logging.getLogger("Twitter")

TWEETS_URL = "https://api.twitter.com/2/tweets"


class TwitterPoster:
    def __init__(self, config):
        self.api_key = config.TWITTER_API_KEY
        self.api_secret = config.TWITTER_API_SECRET
        self.access_token = config.TWITTER_ACCESS_TOKEN
        self.access_secret = config.TWITTER_ACCESS_SECRET

    def is_configured(self) -> bool:
        return all([self.api_key, self.api_secret, self.access_token, self.access_secret])

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Post tweet using OAuth 1.0a."""
        # Trim to 280 chars
        text = post_text[:280]

        payload = {'text': text}
        auth_header = self._build_oauth_header('POST', TWEETS_URL, {})

        headers = {
            'Authorization': auth_header,
            'Content-Type': 'application/json',
        }

        try:
            resp = requests.post(TWEETS_URL, headers=headers, json=payload, timeout=30)
            if resp.status_code in (200, 201):
                data = resp.json().get('data', {})
                tweet_id = data.get('id', '')
                tweet_url = f"https://x.com/cyberbivash/status/{tweet_id}" if tweet_id else ''
                log.info(f"Twitter posted: {tweet_id}")
                return {'success': True, 'post_id': tweet_id, 'post_url': tweet_url}
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                log.error(f"Twitter post failed: {error_msg}")
                return {'success': False, 'error': error_msg}
        except requests.RequestException as e:
            log.error(f"Twitter request exception: {e}")
            return {'success': False, 'error': str(e)}

    def _build_oauth_header(self, method: str, url: str, extra_params: dict) -> str:
        """Build OAuth 1.0a Authorization header."""
        oauth_params = {
            'oauth_consumer_key': self.api_key,
            'oauth_nonce': secrets.token_hex(16),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_token': self.access_token,
            'oauth_version': '1.0',
        }

        all_params = {**oauth_params, **extra_params}
        sorted_params = sorted(all_params.items())
        param_string = '&'.join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
            for k, v in sorted_params
        )

        base_string = '&'.join([
            method.upper(),
            urllib.parse.quote(url, safe=''),
            urllib.parse.quote(param_string, safe='')
        ])

        signing_key = f"{urllib.parse.quote(self.api_secret, safe='')}&{urllib.parse.quote(self.access_secret, safe='')}"
        hashed = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1)
        signature = base64.b64encode(hashed.digest()).decode()

        oauth_params['oauth_signature'] = signature
        header_parts = ', '.join(
            f'{urllib.parse.quote(k, safe="")}="{urllib.parse.quote(v, safe="")}"'
            for k, v in sorted(oauth_params.items())
        )
        return f'OAuth {header_parts}'
