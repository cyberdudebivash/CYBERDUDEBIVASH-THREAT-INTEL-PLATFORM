"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Tumblr Platform
Posts HTML blog posts via Tumblr API v2 using OAuth1.

Requires:
  - TUMBLR_CONSUMER_KEY
  - TUMBLR_CONSUMER_SECRET
  - TUMBLR_OAUTH_TOKEN
  - TUMBLR_OAUTH_SECRET
  - TUMBLR_BLOG_NAME : e.g. cyberdudebivash-news

How to get: https://www.tumblr.com/oauth/apps > Register App
  Then use oauth-dance or Tumblr's interactive auth to get tokens.
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

log = logging.getLogger("Tumblr")


class TumblrPoster:
    def __init__(self, config):
        self.consumer_key = config.TUMBLR_CONSUMER_KEY
        self.consumer_secret = config.TUMBLR_CONSUMER_SECRET
        self.oauth_token = config.TUMBLR_OAUTH_TOKEN
        self.oauth_secret = config.TUMBLR_OAUTH_SECRET
        self.blog_name = config.TUMBLR_BLOG_NAME

    def is_configured(self) -> bool:
        return all([
            self.consumer_key, self.consumer_secret,
            self.oauth_token, self.oauth_secret, self.blog_name
        ])

    def post(self, item: Dict[str, Any], post_text: str) -> Dict[str, Any]:
        """Post HTML content to Tumblr blog."""
        url = f"https://api.tumblr.com/v2/blog/{self.blog_name}.tumblr.com/posts"
        params = {
            'type': 'text',
            'title': item.get('title', ''),
            'body': post_text,
            'tags': 'cybersecurity,threatintelligence,cyberdudebivash,infosec,cti',
            'native_inline_images': 'false',
        }

        auth_header = self._build_oauth_header('POST', url, params)
        headers = {'Authorization': auth_header}

        try:
            resp = requests.post(url, headers=headers, data=params, timeout=30)
            if resp.status_code in (200, 201):
                data = resp.json()
                post_id = str(data.get('response', {}).get('id', ''))
                post_url = f"https://{self.blog_name}.tumblr.com/post/{post_id}"
                log.info(f"Tumblr posted: {post_id}")
                return {'success': True, 'post_id': post_id, 'post_url': post_url}
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                log.error(f"Tumblr post failed: {error_msg}")
                return {'success': False, 'error': error_msg}
        except requests.RequestException as e:
            log.error(f"Tumblr request exception: {e}")
            return {'success': False, 'error': str(e)}

    def _build_oauth_header(self, method: str, url: str, body_params: dict) -> str:
        """Build OAuth 1.0a Authorization header."""
        oauth_params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_nonce': secrets.token_hex(16),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_token': self.oauth_token,
            'oauth_version': '1.0',
        }

        all_params = {**oauth_params, **body_params}
        sorted_params = sorted(all_params.items())
        param_string = '&'.join(
            f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}"
            for k, v in sorted_params
        )

        base_string = '&'.join([
            method.upper(),
            urllib.parse.quote(url, safe=''),
            urllib.parse.quote(param_string, safe='')
        ])

        signing_key = (
            f"{urllib.parse.quote(self.consumer_secret, safe='')}"
            f"&{urllib.parse.quote(self.oauth_secret, safe='')}"
        )
        hashed = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1)
        signature = base64.b64encode(hashed.digest()).decode()

        oauth_params['oauth_signature'] = signature
        header_parts = ', '.join(
            f'{urllib.parse.quote(k, safe="")}="{urllib.parse.quote(v, safe="")}"'
            for k, v in sorted(oauth_params.items())
        )
        return f'OAuth {header_parts}'
