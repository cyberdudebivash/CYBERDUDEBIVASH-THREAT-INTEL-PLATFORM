#!/usr/bin/env python3
"""
config.py — CYBERDUDEBIVASH® SENTINEL APEX v46.0 COMMAND CORTEX
Founder & CEO — CyberDudeBivash Pvt. Ltd.
"""

VERSION = "46.0"
CODENAME = "COMMAND CORTEX"
AUTHORITY = "CYBERDUDEBIVASH OFFICIAL AUTHORITY"

# Core Paths
DATA_DIR = "data"
SOVEREIGN_DIR = f"{DATA_DIR}/sovereign"
REVENUE_LOG = f"{DATA_DIR}/revenue/transaction_log.json"
TENANT_REGISTRY = f"{SOVEREIGN_DIR}/tenants.json"
PRODUCT_DIR = f"{DATA_DIR}/products"

# Security & Vaulting
ENCRYPTION_ENABLED = True
VAULT_DIR = f"{DATA_DIR}/vault"
VAULT_LOG = f"{VAULT_DIR}/vault_manifest.json"

# API Settings
API_HOST = "0.0.0.0"
API_PORT = 8000
DEBUG_MODE = False

# Billing Tiers
TIERS = {
    "community": {"price": 0.0, "limit": 10},
    "pro": {"price": 49.0, "limit": 1000},
    "enterprise": {"price": 499.0, "limit": 0} # Unlimited
}