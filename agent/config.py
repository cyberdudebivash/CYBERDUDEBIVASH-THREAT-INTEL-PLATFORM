#!/usr/bin/env python3
"""
config.py — CYBERDUDEBIVASH® SENTINEL APEX v46.0 COMMAND CORTEX
Founder & CEO — CyberDudeBivash Pvt. Ltd.

Central configuration for Sentinel APEX platform.
All platform-wide constants, paths, and operational settings
must be defined here to prevent runtime failures.
"""

# ============================================================
# PLATFORM IDENTITY
# ============================================================

VERSION = "46.0"
CODENAME = "COMMAND CORTEX"
AUTHORITY = "CYBERDUDEBIVASH OFFICIAL AUTHORITY"
PLATFORM_NAME = "CYBERDUDEBIVASH SENTINEL APEX"

# ============================================================
# CORE PATHS
# ============================================================

DATA_DIR = "data"

# Threat Intelligence Storage
STIX_DIR = f"{DATA_DIR}/stix"
MANIFEST_FILE = f"{STIX_DIR}/feed_manifest.json"

# Sovereign registry
SOVEREIGN_DIR = f"{DATA_DIR}/sovereign"
TENANT_REGISTRY = f"{SOVEREIGN_DIR}/tenants.json"

# Revenue tracking
REVENUE_DIR = f"{DATA_DIR}/revenue"
REVENUE_LOG = f"{REVENUE_DIR}/transaction_log.json"

# Product Factory output
PRODUCT_DIR = f"{DATA_DIR}/products"

# ============================================================
# SECURITY & VAULTING
# ============================================================

ENCRYPTION_ENABLED = True

VAULT_DIR = f"{DATA_DIR}/vault"
VAULT_LOG = f"{VAULT_DIR}/vault_manifest.json"

# ============================================================
# NETWORK & IOC FILTERING
# ============================================================

# Private IP ranges used by enrichment engine
PRIVATE_IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
]

# IOC validation thresholds
MAX_IOC_PER_REPORT = 500
MIN_CONFIDENCE_SCORE = 0.5

# ============================================================
# API SERVER SETTINGS
# ============================================================

API_HOST = "0.0.0.0"
API_PORT = 8000
DEBUG_MODE = False

# Rate limiting (future SaaS gateway)
API_RATE_LIMIT = 1000

# ============================================================
# BILLING & SUBSCRIPTION TIERS
# ============================================================

TIERS = {
    "community": {
        "price": 0.0,
        "limit": 10
    },
    "pro": {
        "price": 49.0,
        "limit": 1000
    },
    "enterprise": {
        "price": 499.0,
        "limit": 0  # Unlimited
    }
}

# ============================================================
# PRODUCT FACTORY SETTINGS
# ============================================================

PRODUCT_TYPES = [
    "detection_pack",
    "ioc_bundle",
    "soc_playbook",
    "premium_report"
]

DEFAULT_PRODUCT_RETENTION_DAYS = 365

# ============================================================
# BLOGGER / INTEL PUBLISHING
# ============================================================

BLOG_PLATFORM = "blogger"
BLOG_AUTHOR = AUTHORITY

# Sentinel Threat Bulletin template version
BULLETIN_TEMPLATE = "SENTINEL_INTEL_V4"

# ============================================================
# SYSTEM SAFETY
# ============================================================

# Prevent accidental deletion
PROTECT_CORE_DATA = True

# Platform node identifier
NODE_ID = "CDB-GOC-01"

# ============================================================
# RUNTIME VALIDATION
# ============================================================

REQUIRED_DIRECTORIES = [
    DATA_DIR,
    STIX_DIR,
    SOVEREIGN_DIR,
    REVENUE_DIR,
    PRODUCT_DIR,
    VAULT_DIR
]
