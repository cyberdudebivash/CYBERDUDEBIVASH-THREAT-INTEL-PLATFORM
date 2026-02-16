#!/usr/bin/env python3
"""
source_fetcher.py — CyberDudeBivash v11.5 (SENTINEL APEX ULTRA)
Fetches full source article content from news URLs for rich report generation.
Extracts meaningful text, strips navigation/ads, handles various site structures.
"""
import re
import logging
import requests
from typing import Dict, Optional, List

logger = logging.getLogger("CDB-FETCHER")


class SourceFetcher:
    """Fetches and extracts meaningful content from source article URLs."""

    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (compatible; CDB-Sentinel-ThreatIntel/11.5; +https://cyberdudebivash.com)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    # Tags that definitely contain non-article content
    STRIP_TAGS = ['script', 'style', 'nav', 'footer', 'header', 'aside',
                  'noscript', 'iframe', 'form', 'button', 'svg', 'figure',
                  'figcaption', 'menu', 'template']

    # CSS class/id patterns that indicate non-article content
    NON_CONTENT_PATTERNS = [
        r'sidebar', r'comment', r'footer', r'header', r'nav', r'menu',
        r'social', r'share', r'related', r'popular', r'trending',
        r'advertisement', r'ad-', r'cookie', r'popup', r'modal',
        r'newsletter', r'subscribe', r'signup',
    ]

    def fetch_article(self, url: str, timeout: int = 15) -> Dict:
        """
        Fetch and parse a source article URL.
        Returns dict with: full_text, paragraphs (list), word_count, fetch_status
        """
        result = {
            "full_text": "",
            "paragraphs": [],
            "word_count": 0,
            "source_url": url,
            "fetch_status": "failed",
        }

        if not url or not url.startswith("http"):
            return result

        try:
            resp = requests.get(
                url, headers=self.HEADERS, timeout=timeout,
                allow_redirects=True, verify=True
            )
            if resp.status_code != 200:
                logger.warning(f"Source fetch HTTP {resp.status_code}: {url}")
                return result

            html = resp.text

            # Try to find main article content area first
            article_html = self._extract_article_region(html)
            text = self._extract_text(article_html if article_html else html)

            # Filter to meaningful paragraphs
            paragraphs = [p.strip() for p in text.split('\n')
                         if len(p.strip()) > 40 and not self._is_boilerplate(p)]

            result["full_text"] = '\n'.join(paragraphs)
            result["paragraphs"] = paragraphs
            result["word_count"] = sum(len(p.split()) for p in paragraphs)
            result["fetch_status"] = "success"

            logger.info(f"Source fetched: {len(paragraphs)} paragraphs, "
                       f"{result['word_count']} words from {url[:60]}")

        except requests.Timeout:
            logger.warning(f"Source fetch timeout: {url}")
        except requests.RequestException as e:
            logger.warning(f"Source fetch network error: {e}")
        except Exception as e:
            logger.warning(f"Source fetch error: {e}")

        return result

    def _extract_article_region(self, html: str) -> Optional[str]:
        """Try to find the main article content region."""
        # Look for common article container patterns
        patterns = [
            r'<article[^>]*>(.*?)</article>',
            r'<div[^>]*class="[^"]*(?:article|post|entry|content|story)[^"]*"[^>]*>(.*?)</div>',
            r'<div[^>]*id="[^"]*(?:article|post|entry|content|story)[^"]*"[^>]*>(.*?)</div>',
            r'<main[^>]*>(.*?)</main>',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                content = match.group(1)
                # Only use if substantial
                if len(content) > 500:
                    return content
        return None

    def _extract_text(self, html: str) -> str:
        """Extract meaningful text from HTML."""
        # Remove non-content tags
        for tag in self.STRIP_TAGS:
            html = re.sub(rf'<{tag}[\s>].*?</{tag}>', '', html,
                         flags=re.DOTALL | re.IGNORECASE)

        # Remove HTML comments
        html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

        # Remove elements with non-content classes/ids
        for pattern in self.NON_CONTENT_PATTERNS:
            html = re.sub(
                rf'<[^>]+(?:class|id)="[^"]*{pattern}[^"]*"[^>]*>.*?</(?:div|section|aside|nav)>',
                '', html, flags=re.DOTALL | re.IGNORECASE
            )

        # Preserve line breaks at block boundaries
        html = re.sub(r'<br\s*/?>', '\n', html, flags=re.IGNORECASE)
        html = re.sub(r'</?(?:p|div|h[1-6]|li|tr|td|th|blockquote|pre|article|section)[^>]*>',
                      '\n', html, flags=re.IGNORECASE)

        # Remove remaining HTML tags
        text = re.sub(r'<[^>]+>', ' ', html)

        # Clean HTML entities
        text = re.sub(r'&nbsp;', ' ', text)
        text = re.sub(r'&amp;', '&', text)
        text = re.sub(r'&lt;', '<', text)
        text = re.sub(r'&gt;', '>', text)
        text = re.sub(r'&quot;', '"', text)
        text = re.sub(r'&#?\w+;', ' ', text)

        # Clean whitespace
        text = re.sub(r'[ \t]+', ' ', text)
        text = re.sub(r'\n\s*\n', '\n', text)

        return text.strip()

    def _is_boilerplate(self, text: str) -> bool:
        """Check if a paragraph is likely boilerplate/navigation."""
        text_lower = text.lower().strip()
        boilerplate_phrases = [
            'cookie', 'subscribe', 'newsletter', 'sign up', 'log in',
            'privacy policy', 'terms of', 'all rights reserved',
            'share this', 'follow us', 'related articles',
            'read more', 'click here', 'learn more',
            'advertisement', 'sponsored', 'powered by',
            'copyright ©', 'footer', 'navigation',
        ]
        for phrase in boilerplate_phrases:
            if phrase in text_lower and len(text_lower) < 150:
                return True

        # Very short lines are likely UI elements
        if len(text.split()) < 5:
            return True

        return False


# Global singleton
source_fetcher = SourceFetcher()
