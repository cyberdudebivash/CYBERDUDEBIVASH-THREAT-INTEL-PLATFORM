"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — RSS Poller
Fetches and parses Blogger RSS feed, returns new items only.
"""

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Set, Dict, Any

import requests

log = logging.getLogger("RSSPoller")


class RSSPoller:
    def __init__(self, rss_url: str, timeout: int = 30):
        self.rss_url = rss_url
        self.timeout = timeout

    def fetch_new_items(self, already_posted: Set[str]) -> List[Dict[str, Any]]:
        """Fetch RSS and return only items not already posted."""
        raw_xml = self._fetch_raw()
        all_items = self._parse_items(raw_xml)

        new_items = [
            item for item in all_items
            if item['guid'] not in already_posted
        ]

        log.info(f"RSS: {len(all_items)} total items | {len(new_items)} new")
        return new_items

    def _fetch_raw(self) -> str:
        headers = {
            'User-Agent': 'CyberDudeBivash-Syndication-Engine/1.0 (+https://cyberdudebivash.com)'
        }
        try:
            resp = requests.get(self.rss_url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as e:
            log.error(f"Failed to fetch RSS feed: {e}")
            raise

    def _parse_items(self, xml_text: str) -> List[Dict[str, Any]]:
        items = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            log.error(f"XML parse error: {e}")
            return items

        channel = root.find('channel')
        if channel is None:
            log.error("No <channel> element found in RSS")
            return items

        for item_el in channel.findall('item'):
            try:
                title = self._get_text(item_el, 'title', 'Untitled')
                link = self._get_text(item_el, 'link', '')
                guid = self._get_text(item_el, 'guid', link)
                description = self._get_text(item_el, 'description', '')
                pub_date_str = self._get_text(item_el, 'pubDate', '')
                categories = [c.text for c in item_el.findall('category') if c.text]

                # Clean HTML from description for plain summary
                summary = self._strip_html(description)[:300].strip()
                if len(summary) == 300:
                    summary += "..."

                items.append({
                    'title': title,
                    'link': link,
                    'guid': guid,
                    'summary': summary,
                    'pub_date': pub_date_str,
                    'categories': categories,
                    'description_raw': description,
                })
            except Exception as e:
                log.warning(f"Failed to parse RSS item: {e}")
                continue

        # Sort oldest-first so we post chronologically
        return list(reversed(items))

    @staticmethod
    def _get_text(element, tag: str, default: str = '') -> str:
        el = element.find(tag)
        if el is not None and el.text:
            return el.text.strip()
        return default

    @staticmethod
    def _strip_html(html: str) -> str:
        """Remove HTML tags and decode common entities."""
        clean = re.sub(r'<[^>]+>', ' ', html)
        clean = clean.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        clean = clean.replace('&nbsp;', ' ').replace('&#39;', "'").replace('&quot;', '"')
        clean = re.sub(r'\s+', ' ', clean)
        return clean.strip()
