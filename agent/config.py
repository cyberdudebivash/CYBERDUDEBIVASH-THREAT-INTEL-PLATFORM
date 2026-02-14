"""
CDB-SENTINEL Platform Configuration
Central configuration for all modules.

© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import os

# ═══════════════════════════════════════════════
# BRAND IDENTITY
# ═══════════════════════════════════════════════

BRAND = {
    "name": "CyberDudeBivash",
    "legal": "CyberDudeBivash Pvt. Ltd.",
    "tagline": "Evolve or Extinct — Your Cybersecurity Authority",
    "founder": "Bivash Kumar Nayak",
    "role": "CEO & CTO",
    "email": "iambivash@cyberdudebivash.com",
    "phone": "+91 81798 81447",
    "city": "Bhubaneswar",
    "state": "Odisha",
    "country": "India",
    "website": "https://www.cyberdudebivash.com",
    "github": "https://github.com/cyberdudebivash",
    "linkedin": "https://www.linkedin.com/company/cyberdudebivash",
    "tools_page": "https://cyberdudebivash.github.io/cyberdudebivash-top-10-tools/",
    "publisher_id": "pub-8343951291888650",
}

BLOGS = {
    "news": "https://cyberdudebivash-news.blogspot.com",
    "technical": "https://cyberbivash.blogspot.com",
    "crypto": "https://cryptobivash.code.blog",
}

# ═══════════════════════════════════════════════
# API CREDENTIALS & REPUTATION ENGINE
# ═══════════════════════════════════════════════

# Primary Blogger ID for automated publishing
BLOG_ID = os.getenv("BLOG_ID", "1735779547938854877")

# Securely pulls the VirusTotal Key from GitHub Secrets
# REQUIRED: Ensure 'VT_API_KEY' is added to GitHub Settings > Secrets
VT_API_KEY = os.getenv("VT_API_KEY", "").strip() 

# ═══════════════════════════════════════════════
# INTEL SOURCES
# ═══════════════════════════════════════════════

RSS_FEEDS = [
    "https://thehackernews.com/feeds/posts/default",
    "https://feeds.feedburner.com/Securityweek",
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss_simple.asp",
    "https://www.us-cert.gov/ncas/alerts.xml",
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
    "https://cert-in.org.in/RSSFeed.jsp",
]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

# ═══════════════════════════════════════════════
# PIPELINE SETTINGS
# ═══════════════════════════════════════════════

# State file tracks processed GUIDs to prevent duplicates
# Path must align with GitHub Workflow 'Commit' step
STATE_FILE = os.getenv("STATE_FILE", "data/blogger_processed.json")

MAX_STATE_SIZE = 1500
MAX_PER_FEED = 5
MAX_POSTS_PER_RUN = 5
CVE_FETCH_HOURS = 24
CVE_MAX_RESULTS = 20
WEEKLY_CVE_HOURS = 168
WEEKLY_TOP_N = 10
DEEP_DIVE_MIN_EPSS = 0.40
DEEP_DIVE_MIN_CVSS = 9.0
READING_SPEED_WPM = 200
HTTP_TIMEOUT = 30
PUBLISH_RETRY_MAX = 3
PUBLISH_RETRY_DELAY = 10

# ═══════════════════════════════════════════════
# HTML DESIGN TOKENS (UI APEX v5.4)
# ═══════════════════════════════════════════════

COLORS = {
    "bg_dark": "#0d1117",
    "bg_card": "#161b22",
    "bg_accent": "#1c2333",
    "text": "#e6edf3",
    "text_muted": "#8b949e",
    "accent": "#00d4aa",
    "accent_dark": "#00b894",
    "cyber_blue": "#3b82f6",
    "cyber_purple": "#8b5cf6",
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#16a34a",
    "border": "#30363d",
    "white": "#ffffff",
}

FONTS = {
    "heading": "'Segoe UI', 'Helvetica Neue', Arial, sans-serif",
    "body": "'Segoe UI', 'Helvetica Neue', Arial, sans-serif",
    "mono": "'Consolas', 'Monaco', 'Courier New', monospace",
}

# ═══════════════════════════════════════════════
# MITRE ATT&CK REFERENCE TECHNIQUES
# ═══════════════════════════════════════════════

MITRE_ATTACK_TECHNIQUES = [
    {"external_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    {"external_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
    {"external_id": "T1059.001", "name": "PowerShell", "tactic": "execution"},
    {"external_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
    {"external_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    {"external_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
    {"external_id": "T1078", "name": "Valid Accounts", "tactic": "persistence"},
    {"external_id": "T1021", "name": "Remote Services", "tactic": "lateral-movement"},
    {"external_id": "T1053", "name": "Scheduled Task/Job", "tactic": "persistence"},
    {"external_id": "T1003", "name": "OS Credential Dumping", "tactic": "credential-access"},
]

# Baseline SOC coverage (claimed detections)
DETECTED_TECHNIQUES = {"T1059", "T1059.001", "T1105"}
