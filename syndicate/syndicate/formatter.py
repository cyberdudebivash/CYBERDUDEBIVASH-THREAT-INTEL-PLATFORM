"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Post Formatter
Generates platform-optimized post text from RSS items.
"""

import re
from typing import Dict, Any


class PostFormatter:
    # Character limits per platform
    LIMITS = {
        'twitter': 280,
        'mastodon': 500,
        'bluesky': 300,
        'linkedin': 3000,
        'facebook': 2000,
        'tumblr': 4096,
        'reddit': 6000,
        'threads': 500,
    }

    def __init__(self, config):
        self.config = config

    def format_post(self, item: Dict[str, Any], platform: str = 'default') -> str:
        """Generate platform-specific post text."""
        title = item.get('title', 'Threat Intelligence Report')
        summary = item.get('summary', '')
        link = item.get('link', '')
        categories = item.get('categories', [])

        hashtags = self._build_hashtags(categories, platform)
        limit = self.LIMITS.get(platform, 2000)

        if platform == 'twitter':
            return self._format_twitter(title, link, hashtags, limit)
        elif platform == 'linkedin':
            return self._format_linkedin(title, summary, link, hashtags)
        elif platform == 'mastodon':
            return self._format_mastodon(title, summary, link, hashtags, limit)
        elif platform == 'bluesky':
            return self._format_bluesky(title, link, hashtags, limit)
        elif platform == 'facebook':
            return self._format_facebook(title, summary, link, hashtags)
        elif platform == 'tumblr':
            return self._format_tumblr(title, summary, link, hashtags)
        elif platform == 'reddit':
            return self._format_reddit(title, summary, link)
        elif platform == 'threads':
            return self._format_threads(title, link, hashtags, limit)
        else:
            return self._format_generic(title, summary, link, hashtags)

    def _format_twitter(self, title, link, hashtags, limit):
        """Twitter: 280 chars. Lead with impact, include link + key tags."""
        base = f"🚨 {title}\n\n{link}\n\n"
        remaining = limit - len(base) - 5
        tags = self._trim_hashtags(hashtags, remaining)
        return f"🚨 {title}\n\n{link}\n\n{tags}"

    def _format_linkedin(self, title, summary, link, hashtags):
        """LinkedIn: Professional, full content, strong CTA."""
        return (
            f"🔐 NEW THREAT INTEL REPORT — CYBERDUDEBIVASH SENTINEL APEX\n\n"
            f"📌 {title}\n\n"
            f"{summary}\n\n"
            f"🔗 Full Report → {link}\n\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Stay ahead of adversaries. Follow CYBERDUDEBIVASH for daily threat intelligence.\n"
            f"🌐 intel.cyberdudebivash.com\n\n"
            f"{hashtags}"
        )

    def _format_mastodon(self, title, summary, link, hashtags, limit):
        """Mastodon: 500 chars, include link + summary."""
        base = f"🔐 {title}\n\n{summary[:150]}...\n\n🔗 {link}\n\n{hashtags}"
        if len(base) > limit:
            available = limit - len(f"🔐 {title}\n\n...\n\n🔗 {link}\n\n{hashtags}") - 10
            short_summary = summary[:max(0, available)] + "..."
            return f"🔐 {title}\n\n{short_summary}\n\n🔗 {link}\n\n{hashtags}"
        return base

    def _format_bluesky(self, title, link, hashtags, limit):
        """Bluesky: 300 chars. Compact but impactful."""
        base = f"🔐 {title}\n\n{link}"
        remaining = limit - len(base) - 2
        tags = self._trim_hashtags(hashtags, remaining)
        post = f"🔐 {title}\n\n{link}\n\n{tags}" if tags else base
        return post[:limit]

    def _format_facebook(self, title, summary, link, hashtags):
        """Facebook: Engaging, community-focused."""
        return (
            f"🚨 NEW THREAT INTELLIGENCE REPORT\n\n"
            f"📌 {title}\n\n"
            f"{summary}\n\n"
            f"🔗 Read the full report: {link}\n\n"
            f"Follow CYBERDUDEBIVASH for daily cybersecurity threat intelligence!\n"
            f"🌐 cyberdudebivash.com\n\n"
            f"{hashtags}"
        )

    def _format_tumblr(self, title, summary, link, hashtags):
        """Tumblr: Supports HTML, use rich format."""
        return (
            f"<h2>🔐 {title}</h2>"
            f"<p>{summary}</p>"
            f"<p><strong>🔗 <a href='{link}'>Read Full Report → CyberDudeBivash Threat Intel</a></strong></p>"
            f"<p><em>Powered by CYBERDUDEBIVASH SENTINEL APEX — AI-Powered Global Threat Intelligence</em></p>"
            f"<p>{hashtags}</p>"
        )

    def _format_reddit(self, title, summary, link):
        """Reddit: No hashtags, clean text with URL."""
        return (
            f"**{title}**\n\n"
            f"{summary}\n\n"
            f"Full report: {link}\n\n"
            f"---\n"
            f"*Source: CyberDudeBivash Threat Intelligence — intel.cyberdudebivash.com*"
        )

    def _format_threads(self, title, link, hashtags, limit):
        """Threads: Similar to Instagram, 500 chars."""
        base = f"🔐 {title}\n\n🔗 {link}\n\n"
        remaining = limit - len(base)
        tags = self._trim_hashtags(hashtags, remaining)
        return (base + tags)[:limit]

    def _format_generic(self, title, summary, link, hashtags):
        return f"🔐 {title}\n\n{summary}\n\n{link}\n\n{hashtags}"

    def _build_hashtags(self, categories: list, platform: str) -> str:
        """Build hashtag string from categories + common tags."""
        common = self.config.HASHTAGS_COMMON
        extra = self.config.HASHTAGS_EXTRA if platform not in ('twitter', 'bluesky') else ''

        # Convert categories to hashtags
        cat_tags = []
        for cat in categories[:3]:
            tag = '#' + re.sub(r'[^a-zA-Z0-9]', '', cat.replace(' ', ''))
            if len(tag) > 1:
                cat_tags.append(tag)

        parts = [common]
        if cat_tags:
            parts.append(' '.join(cat_tags))
        if extra:
            parts.append(extra)

        return ' '.join(parts)

    @staticmethod
    def _trim_hashtags(hashtags: str, max_chars: int) -> str:
        """Trim hashtag string to fit within char limit."""
        if max_chars <= 0:
            return ''
        tags = hashtags.split()
        result = []
        total = 0
        for tag in tags:
            if total + len(tag) + 1 <= max_chars:
                result.append(tag)
                total += len(tag) + 1
        return ' '.join(result)
