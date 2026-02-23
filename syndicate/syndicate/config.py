"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — Configuration
All secrets loaded from environment variables (GitHub Secrets)
"""

import os


class SyndicationConfig:
    # ── RSS Source ──────────────────────────────────────────────────────────
    RSS_URL: str = os.getenv(
        "RSS_URL",
        "https://cyberbivash.blogspot.com/feeds/posts/default?alt=rss"
    )

    # ── State / Storage ─────────────────────────────────────────────────────
    STATE_FILE: str = os.getenv("STATE_FILE", "data/syndication_state.json")
    MAX_ITEMS_PER_RUN: int = int(os.getenv("MAX_ITEMS_PER_RUN", "5"))

    # ── Branding ─────────────────────────────────────────────────────────────
    BRAND_NAME: str = "CyberDudeBivash"
    BRAND_URL: str = "https://cyberdudebivash.com"
    BLOG_URL: str = "https://cyberbivash.blogspot.com"
    HASHTAGS_COMMON: str = "#CyberSecurity #ThreatIntelligence #CyberDudeBivash #InfoSec #CTI"
    HASHTAGS_EXTRA: str = "#Malware #APT #ZeroDay #SOC #MITRE #CyberThreat #MadeInIndia"

    # ── LinkedIn ─────────────────────────────────────────────────────────────
    LINKEDIN_ACCESS_TOKEN: str = os.getenv("LINKEDIN_ACCESS_TOKEN", "")
    # For Showcase Page posting — set to showcase org URN: urn:li:organization:XXXXXXX
    LINKEDIN_AUTHOR_URN: str = os.getenv("LINKEDIN_AUTHOR_URN", "")
    # Also post to personal profile (set to urn:li:person:XXXXXXX)
    LINKEDIN_PERSONAL_URN: str = os.getenv("LINKEDIN_PERSONAL_URN", "")

    # ── Twitter / X ──────────────────────────────────────────────────────────
    TWITTER_API_KEY: str = os.getenv("TWITTER_API_KEY", "")
    TWITTER_API_SECRET: str = os.getenv("TWITTER_API_SECRET", "")
    TWITTER_ACCESS_TOKEN: str = os.getenv("TWITTER_ACCESS_TOKEN", "")
    TWITTER_ACCESS_SECRET: str = os.getenv("TWITTER_ACCESS_SECRET", "")

    # ── Mastodon ──────────────────────────────────────────────────────────────
    MASTODON_INSTANCE_URL: str = os.getenv("MASTODON_INSTANCE_URL", "https://mastodon.social")
    MASTODON_ACCESS_TOKEN: str = os.getenv("MASTODON_ACCESS_TOKEN", "")

    # ── Bluesky ───────────────────────────────────────────────────────────────
    BLUESKY_HANDLE: str = os.getenv("BLUESKY_HANDLE", "cyberdudebivash.bsky.social")
    BLUESKY_APP_PASSWORD: str = os.getenv("BLUESKY_APP_PASSWORD", "")

    # ── Facebook ──────────────────────────────────────────────────────────────
    FACEBOOK_PAGE_ID: str = os.getenv("FACEBOOK_PAGE_ID", "")
    FACEBOOK_PAGE_ACCESS_TOKEN: str = os.getenv("FACEBOOK_PAGE_ACCESS_TOKEN", "")

    # ── Tumblr ────────────────────────────────────────────────────────────────
    TUMBLR_CONSUMER_KEY: str = os.getenv("TUMBLR_CONSUMER_KEY", "")
    TUMBLR_CONSUMER_SECRET: str = os.getenv("TUMBLR_CONSUMER_SECRET", "")
    TUMBLR_OAUTH_TOKEN: str = os.getenv("TUMBLR_OAUTH_TOKEN", "")
    TUMBLR_OAUTH_SECRET: str = os.getenv("TUMBLR_OAUTH_SECRET", "")
    TUMBLR_BLOG_NAME: str = os.getenv("TUMBLR_BLOG_NAME", "cyberdudebivash-news")

    # ── Reddit ────────────────────────────────────────────────────────────────
    REDDIT_CLIENT_ID: str = os.getenv("REDDIT_CLIENT_ID", "")
    REDDIT_CLIENT_SECRET: str = os.getenv("REDDIT_CLIENT_SECRET", "")
    REDDIT_USERNAME: str = os.getenv("REDDIT_USERNAME", "")
    REDDIT_PASSWORD: str = os.getenv("REDDIT_PASSWORD", "")
    REDDIT_SUBREDDIT: str = os.getenv("REDDIT_SUBREDDIT", "u_Immediate_Gold9789")

    # ── Threads ───────────────────────────────────────────────────────────────
    THREADS_ACCESS_TOKEN: str = os.getenv("THREADS_ACCESS_TOKEN", "")
    THREADS_USER_ID: str = os.getenv("THREADS_USER_ID", "")
