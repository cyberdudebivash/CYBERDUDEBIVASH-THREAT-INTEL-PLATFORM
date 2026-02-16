#!/usr/bin/env python3
"""
config.py — CyberDudeBivash v11.0 (SENTINEL APEX ULTRA)
Global Configuration for the Sentinel APEX Intelligence Platform.
UPGRADED: All missing constants defined, multi-feed, dynamic scoring params.
"""
import os

# ═══════════════════════════════════════════════════════════
# BLOGGER CONFIGURATION
# ═══════════════════════════════════════════════════════════
BLOG_ID = os.environ.get('BLOG_ID', '8435132226685160824')

# ═══════════════════════════════════════════════════════════
# FORENSIC PERSISTENCE
# ═══════════════════════════════════════════════════════════
STATE_FILE = "data/blogger_processed.json"
MAX_STATE_SIZE = 500
MAX_PER_FEED = 5

# ═══════════════════════════════════════════════════════════
# INTELLIGENCE SOURCES (Multi-Feed Fusion)
# ═══════════════════════════════════════════════════════════
# Primary CDB Feed (own blog)
CDB_RSS_FEED = "https://cyberdudebivash-news.blogspot.com/feeds/posts/default?alt=rss"

# High-Authority External Feeds (Expanded for comprehensive coverage)
RSS_FEEDS = [
    # Tier 1: Premium Threat Intel Sources
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/feed/",
    # Tier 2: Industry Authority Sources
    "https://www.securityweek.com/feed/",
    "https://darkreading.com/rss.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    # Tier 3: Technical/Research Sources
    "https://cyberscoop.com/feed/",
    "https://www.scworld.com/feed",
    "https://threatpost.com/feed/",
]

# Maximum entries to process per feed per run
MAX_ENTRIES_PER_FEED = 3

# Source article fetch settings
SOURCE_FETCH_TIMEOUT = 15  # Seconds
SOURCE_FETCH_ENABLED = True  # Enable/disable source article fetching

# ═══════════════════════════════════════════════════════════
# ORCHESTRATION SETTINGS
# ═══════════════════════════════════════════════════════════
PUBLISH_RETRY_MAX = 3
PUBLISH_RETRY_DELAY = 10  # Seconds
RATE_LIMIT_DELAY = 2       # Seconds between API calls (rate-limit protection)

# ═══════════════════════════════════════════════════════════
# MANIFEST SETTINGS
# ═══════════════════════════════════════════════════════════
MANIFEST_MAX_ENTRIES = 50   # Upgraded from 10 → 50 for historical archive
MANIFEST_DIR = "data/stix"

# ═══════════════════════════════════════════════════════════
# WEEKLY CVE REPORT SETTINGS
# ═══════════════════════════════════════════════════════════
WEEKLY_CVE_HOURS = 168       # 7 days
WEEKLY_TOP_N = 10

# ═══════════════════════════════════════════════════════════
# BRANDING (Required by formatters)
# ═══════════════════════════════════════════════════════════
BRAND = {
    "name": "CyberDudeBivash",
    "legal": "CyberDudeBivash Pvt. Ltd.",
    "website": "https://www.cyberdudebivash.com",
    "platform": "https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/",
    "city": "Bhubaneswar",
    "state": "Odisha",
    "country": "India",
    "email": "bivash@cyberdudebivash.com",
    "phone": "+91 8179881447",
    "tagline": "Global Cybersecurity Intelligence Infrastructure",
    "node_id": "CDB-GOC-01",
    "version": "v12.0",
}

BLOGS = {
    "primary": "https://cyberbivash.blogspot.com",
    "news": "https://cyberdudebivash-news.blogspot.com",
    "crypto": "https://cryptobivash.code.blog",
    "medium": "https://medium.com/@cyberdudebivash",
}

# ═══════════════════════════════════════════════════════════
# DESIGN SYSTEM (Required by formatters)
# ═══════════════════════════════════════════════════════════
COLORS = {
    # Core
    "accent": "#00d4aa",
    "white": "#ffffff",
    "bg_dark": "#06080d",
    "bg_card": "#0d1117",
    "border": "#1e293b",
    "text": "#cbd5e1",
    "text_muted": "#64748b",
    # Severity
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#16a34a",
    "info": "#3b82f6",
    # Cyber Theme
    "cyber_purple": "#8b5cf6",
    "cyber_blue": "#3b82f6",
    "cyber_pink": "#ec4899",
    "cyber_yellow": "#f59e0b",
    # TLP
    "tlp_red": "#ff3e3e",
    "tlp_amber": "#ff9f43",
    "tlp_green": "#00e5c3",
    "tlp_clear": "#94a3b8",
}

FONTS = {
    "heading": "'Inter', 'Segoe UI', system-ui, sans-serif",
    "body": "'Inter', 'Segoe UI', sans-serif",
    "mono": "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
}

# ═══════════════════════════════════════════════════════════
# TLP CLASSIFICATION MATRIX
# ═══════════════════════════════════════════════════════════
TLP_MATRIX = {
    "RED":   {"label": "TLP:RED",   "color": "#ff3e3e", "min_score": 9.0},
    "AMBER": {"label": "TLP:AMBER", "color": "#ff9f43", "min_score": 7.0},
    "GREEN": {"label": "TLP:GREEN", "color": "#00e5c3", "min_score": 4.0},
    "CLEAR": {"label": "TLP:CLEAR", "color": "#94a3b8", "min_score": 0.0},
}

# ═══════════════════════════════════════════════════════════
# DYNAMIC RISK SCORING WEIGHTS
# ═══════════════════════════════════════════════════════════
RISK_WEIGHTS = {
    "base_ioc_count": 0.5,       # Per IOC category found
    "has_sha256": 1.5,           # File hash = high confidence
    "has_ipv4": 1.0,             # Network indicators
    "has_domain": 0.8,           # Domain indicators
    "has_url": 0.7,              # URL indicators
    "has_email": 0.5,            # Email indicators
    "has_registry": 1.2,         # Registry = persistence
    "has_artifacts": 1.0,        # Malicious files
    "cvss_above_9": 2.0,        # Critical CVSS
    "epss_above_09": 1.5,       # High exploit probability
    "actor_mapped": 1.0,        # Known threat actor attribution
    "mitre_technique_count": 0.3, # Per MITRE technique mapped
    "base_score": 2.0,          # Minimum baseline for any campaign
    "max_score": 10.0,          # Cap
}

# ═══════════════════════════════════════════════════════════
# IOC VALIDATION
# ═══════════════════════════════════════════════════════════
# Private IP ranges to exclude from IOC extraction
PRIVATE_IP_RANGES = [
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "127.",
    "0.0.0.0",
    "255.255.255.255",
]

# Common false-positive domains to exclude
FALSE_POSITIVE_DOMAINS = {
    "example.com", "example.org", "example.net",
    "localhost", "test.com", "domain.com",
    "schema.org", "w3.org", "www.w3.org",
    "googleapis.com", "google.com", "gstatic.com",
    "fonts.googleapis.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net",
}

# ═══════════════════════════════════════════════════════════
# API KEYS (from environment)
# ═══════════════════════════════════════════════════════════
VT_API_KEY = os.environ.get('VT_API_KEY', '')
