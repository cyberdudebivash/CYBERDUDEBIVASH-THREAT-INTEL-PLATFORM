#!/usr/bin/env python3
"""
config.py — CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
Global Configuration for the Sentinel APEX Intelligence Platform.
UPGRADED v22.0: API rate limiting, EPSS endpoint, supply chain patterns,
JWT secret, new tier limits, MISP config, audit settings.
All existing constants preserved — 100% backward compatible.
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
CDB_RSS_FEED = "https://cyberdudebivash-news.blogspot.com/feeds/posts/default?alt=rss"

RSS_FEEDS = [
    # Tier 1: Premium Breaking News
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/feed/",
    # Tier 2: Industry Authority Sources
    "https://www.securityweek.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    # Tier 3: Investigative / Research Sources
    "https://cyberscoop.com/feed/",
    "https://therecord.media/feed/",
    "https://securityaffairs.com/feed",
    # Tier 4: CVE / Vulnerability Intelligence
    "https://cvefeed.io/rssfeed/latest.xml",
    "https://www.rapid7.com/blog/rss/",
    "https://blog.qualys.com/feed",
    # Tier 5: Vendor Threat Research
    "https://www.sentinelone.com/blog/feed/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://securelist.com/feed/",
]

MAX_ENTRIES_PER_FEED = 5
SOURCE_FETCH_TIMEOUT = 15
SOURCE_FETCH_ENABLED = True

# ═══════════════════════════════════════════════════════════
# ORCHESTRATION SETTINGS
# ═══════════════════════════════════════════════════════════
PUBLISH_RETRY_MAX = 3
PUBLISH_RETRY_DELAY = 10
RATE_LIMIT_DELAY = 2

# ═══════════════════════════════════════════════════════════
# MANIFEST SETTINGS
# ═══════════════════════════════════════════════════════════
MANIFEST_MAX_ENTRIES = 50
MANIFEST_DIR = "data/stix"

# ═══════════════════════════════════════════════════════════
# WEEKLY CVE REPORT SETTINGS
# ═══════════════════════════════════════════════════════════
WEEKLY_CVE_HOURS = 168
WEEKLY_TOP_N = 10

# ═══════════════════════════════════════════════════════════
# BRANDING
# ═══════════════════════════════════════════════════════════
BRAND = {
    "name": "CyberDudeBivash",
    "legal": "CyberDudeBivash Pvt. Ltd.",
    "website": "https://www.cyberdudebivash.com",
    "platform": "https://intel.cyberdudebivash.com",
    "city": "Bhubaneswar",
    "state": "Odisha",
    "country": "India",
    "email": "bivash@cyberdudebivash.com",
    "phone": "+91 8179881447",
    "tagline": "Global Cybersecurity Intelligence Infrastructure",
    "node_id": "CDB-GOC-01",
    "version": "v22.0",
}

BLOGS = {
    "primary": "https://cyberbivash.blogspot.com",
    "news": "https://cyberdudebivash-news.blogspot.com",
    "crypto": "https://cryptobivash.code.blog",
    "medium": "https://medium.com/@cyberdudebivash",
}

# ═══════════════════════════════════════════════════════════
# DESIGN SYSTEM
# ═══════════════════════════════════════════════════════════
COLORS = {
    "accent": "#00d4aa", "white": "#ffffff", "bg_dark": "#06080d",
    "bg_card": "#0d1117", "border": "#1e293b", "text": "#cbd5e1",
    "text_muted": "#64748b", "critical": "#dc2626", "high": "#ea580c",
    "medium": "#d97706", "low": "#16a34a", "info": "#3b82f6",
    "cyber_purple": "#8b5cf6", "cyber_blue": "#3b82f6",
    "cyber_pink": "#ec4899", "cyber_yellow": "#f59e0b",
    "tlp_red": "#ff3e3e", "tlp_amber": "#ff9f43",
    "tlp_green": "#00e5c3", "tlp_clear": "#94a3b8",
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
# DYNAMIC RISK SCORING WEIGHTS (preserved + v22.0 additions)
# ═══════════════════════════════════════════════════════════
RISK_WEIGHTS = {
    # IOC scoring (preserved)
    "base_ioc_count": 0.5,
    "has_sha256": 1.5,
    "has_ipv4": 1.0,
    "has_domain": 0.8,
    "has_url": 0.7,
    "has_email": 0.5,
    "has_registry": 1.2,
    "has_artifacts": 1.0,
    # Vulnerability scoring (preserved)
    "cvss_above_9": 2.0,
    "epss_above_09": 1.5,
    "actor_mapped": 1.0,
    "mitre_technique_count": 0.3,
    "base_score": 2.0,
    "max_score": 10.0,
    # v22.0 NEW weights
    "kev_present": 2.5,            # CISA KEV = confirmed exploited
    "epss_tier_very_high": 1.8,    # EPSS >= 0.70
    "epss_tier_high": 1.2,         # EPSS >= 0.40
    "epss_tier_medium": 0.6,       # EPSS >= 0.10
    "supply_chain_signal": 2.0,    # Supply chain attack patterns
    "poc_public": 1.5,             # Public PoC available
    "active_exploitation": 2.0,   # Active in-the-wild exploitation
    "nation_state": 1.8,           # Nation-state actor involvement
    "cve_count_multi": 0.4,        # Per additional CVE (beyond first)
    "critical_infra": 1.5,         # Critical infrastructure target
}

# ═══════════════════════════════════════════════════════════
# IOC VALIDATION
# ═══════════════════════════════════════════════════════════
PRIVATE_IP_RANGES = [
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.0.0.0", "255.255.255.255",
]

FALSE_POSITIVE_DOMAINS = {
    "example.com", "example.org", "example.net",
    "localhost", "test.com", "domain.com",
    "schema.org", "w3.org", "www.w3.org",
    "googleapis.com", "google.com", "gstatic.com",
    "fonts.googleapis.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net",
    "kaspersky.com", "securelist.com", "microsoft.com",
    "bleepingcomputer.com", "virustotal.com", "github.com",
    "blogspot.com", "wordpress.com", "medium.com",
    "twitter.com", "linkedin.com", "youtube.com",
    "arstechnica.com", "reuters.com", "cnn.com",
    "nist.gov", "mitre.org", "cisa.gov",
}

JAVA_PACKAGE_PREFIXES = [
    "com.android", "com.google", "com.apple", "com.microsoft",
    "com.amazon", "com.samsung", "com.huawei", "com.xiaomi",
    "com.facebook", "com.meta", "com.tencent", "com.alibaba",
    "com.aiworks", "com.ak.", "com.action",
    "org.apache", "org.eclipse", "org.json", "org.xml",
    "android.app", "android.os", "android.content", "android.util",
    "android.widget", "android.view", "android.net", "android.hardware",
    "android.media", "android.provider", "android.shopping",
    "java.lang", "java.util", "java.io", "java.net",
    "javax.crypto", "javax.net", "javax.xml",
    "dalvik.system", "kotlin.", "kotlinx.",
    "io.reactivex", "io.netty", "io.grpc",
    "net.bytebuddy", "net.sf.",
]

FALSE_POSITIVE_EXTENSIONS = [
    ".jar", ".dex", ".apk", ".class", ".so", ".aar",
    ".gradle", ".properties", ".xml", ".json",
]

# ═══════════════════════════════════════════════════════════
# API KEYS (from environment)
# ═══════════════════════════════════════════════════════════
VT_API_KEY = os.environ.get('VT_API_KEY', '')

# ═══════════════════════════════════════════════════════════
# v17.0 CONFIGURATION ADDITIONS (preserved)
# ═══════════════════════════════════════════════════════════
ARCHIVE_RETENTION_DAYS = int(os.environ.get('ARCHIVE_RETENTION_DAYS', '15'))
ARCHIVE_DIR = "data/archive"

DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', '')
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK', '')
TEAMS_WEBHOOK = os.environ.get('TEAMS_WEBHOOK', '')
GENERIC_WEBHOOK_URL = os.environ.get('GENERIC_WEBHOOK_URL', '')

CDB_CREDENTIALS_PATH = os.environ.get('CDB_CREDENTIALS_PATH', 'credentials/credentials.json')
CDB_TOKEN_PATH = os.environ.get('CDB_TOKEN_PATH', 'credentials/token.json')

TELEMETRY_ENABLED = os.environ.get('TELEMETRY_ENABLED', 'true').lower() == 'true'
TELEMETRY_LOG_PATH = "data/telemetry_log.json"

API_PUBLIC_MAX_ENTRIES = 10
API_ENTERPRISE_MAX_ENTRIES = 500

PREDICTIVE_ENABLED = os.environ.get('PREDICTIVE_ENABLED', 'true').lower() == 'true'
CAMPAIGN_TRACKER_ENABLED = os.environ.get('CAMPAIGN_TRACKER_ENABLED', 'true').lower() == 'true'

# ═══════════════════════════════════════════════════════════
# v22.0 NEW CONFIGURATION
# ═══════════════════════════════════════════════════════════

# ── EPSS / NVD Enrichment ──
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_FETCH_ENABLED = os.environ.get('EPSS_FETCH_ENABLED', 'true').lower() == 'true'
EPSS_FETCH_TIMEOUT = 8  # Seconds

# ── API Rate Limiting ──
API_RATE_LIMIT_PUBLIC = int(os.environ.get('API_RATE_LIMIT_PUBLIC', '60'))      # req/min
API_RATE_LIMIT_PRO = int(os.environ.get('API_RATE_LIMIT_PRO', '300'))           # req/min
API_RATE_LIMIT_ENTERPRISE = int(os.environ.get('API_RATE_LIMIT_ENTERPRISE', '1000'))  # req/min
API_RATE_WINDOW_SECONDS = 60

# ── API Authentication ──
# Store API keys as comma-separated env vars: CDB_PRO_KEYS, CDB_ENTERPRISE_KEYS
CDB_JWT_SECRET = os.environ.get('CDB_JWT_SECRET', 'cdb-sentinel-apex-v22-secret-change-in-prod')
CDB_PRO_API_KEYS = set(filter(None, os.environ.get('CDB_PRO_KEYS', '').split(',')))
CDB_ENTERPRISE_API_KEYS = set(filter(None, os.environ.get('CDB_ENTERPRISE_KEYS', '').split(',')))

# ── Audit Logging ──
AUDIT_LOG_ENABLED = os.environ.get('AUDIT_LOG_ENABLED', 'true').lower() == 'true'
AUDIT_LOG_PATH = "data/audit_log.json"
AUDIT_MAX_ENTRIES = 10000

# ── Supply Chain Detection Patterns ──
SUPPLY_CHAIN_SIGNALS = [
    "supply chain", "software supply chain", "build pipeline",
    "npm package", "pypi package", "dependency confusion",
    "typosquatting", "solarwinds", "xz utils", "3cx",
    "polyfill.io", "event-stream", "compromised package",
    "malicious update", "poisoned", "backdoored library",
    "ci/cd pipeline", "github action", "package manager",
    "upstream compromise",
]

# ── MISP Integration ──
MISP_URL = os.environ.get('MISP_URL', '')
MISP_KEY = os.environ.get('MISP_KEY', '')
MISP_VERIFYCERT = os.environ.get('MISP_VERIFYCERT', 'true').lower() == 'true'

# ── Response Cache TTL ──
API_CACHE_TTL_PUBLIC = 300     # 5 minutes
API_CACHE_TTL_ENTERPRISE = 60  # 1 minute

# ── STIX 2.1 Marking Definitions ──
STIX_IDENTITY_ID = "identity--cyberdudebivash-sentinel-apex-v22"
STIX_TLP_MARKING = {
    "GREEN": "marking-definition--34098fce-860f-479c-ad6f-e09814c4f58a",
    "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "RED":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    "CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519a4",
}


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

# High-Authority External Feeds (v14.0 — 15 feeds, dead feeds removed)
RSS_FEEDS = [
    # Tier 1: Premium Breaking News (highest volume + reliability)
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/feed/",
    # Tier 2: Industry Authority Sources
    "https://www.securityweek.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    # Tier 3: Investigative / Research Sources
    "https://cyberscoop.com/feed/",
    "https://therecord.media/feed/",
    "https://securityaffairs.com/feed",
    # Tier 4: CVE / Vulnerability Intelligence
    "https://cvefeed.io/rssfeed/latest.xml",
    "https://www.rapid7.com/blog/rss/",
    "https://blog.qualys.com/feed",
    # Tier 5: Vendor Threat Research
    "https://www.sentinelone.com/blog/feed/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://securelist.com/feed/",
]

# Maximum entries to process per feed per run (was 3, now 5)
MAX_ENTRIES_PER_FEED = 5

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
    "platform": "https://intel.cyberdudebivash.com",
    "city": "Bhubaneswar",
    "state": "Odisha",
    "country": "India",
    "email": "bivash@cyberdudebivash.com",
    "phone": "+91 8179881447",
    "tagline": "Global Cybersecurity Intelligence Infrastructure",
    "node_id": "CDB-GOC-01",
    "version": "v15.0",
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
