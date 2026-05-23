#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Page Presence Validator
v161.3 -- Stage 5.9.4 -- Added MSSP/Partner/Demo/Global/Compliance pages (v161.x)

Validates that all required enterprise trust and monetization pages exist.
Non-blocking: always exits 0.
"""
from pathlib import Path
import sys

REPO = Path(__file__).parent.parent

REQUIRED_PAGES = [
    # Core commercial/trust pages
    ("sla.html",                        "SLA commitment page (P1-005)"),
    ("pricing.html",                    "Commercial pricing tiers (P2-002)"),
    ("terms.html",                      "Terms of Service (P1-005)"),
    ("api-docs.html",                   "API reference documentation (P2-001)"),
    ("docs/index.html",                 "Enterprise documentation hub (P2-005)"),
    (".well-known/security.txt",        "Responsible disclosure policy (P1-005)"),
    # Business development & go-to-market pages (v161.x)
    ("mssp.html",                       "MSSP Partner Program page (B1-001)"),
    ("partner.html",                    "Global Partner & Reseller Program (B1-002)"),
    ("demo.html",                       "Live Demo Booking page (B1-003)"),
    ("global-deployment.html",          "International Deployment Guide (B1-004)"),
    ("compliance.html",                 "Compliance & Certifications page (B1-005)"),
    # Pipeline infrastructure
    ("scripts/manifest_repair.py",      "Manifest URL repair engine (P1-004)"),
    ("scripts/openapi_generator.py",    "OpenAPI spec generator (P2-001)"),
    ("scripts/cloudflare_api_gateway.js", "Cloudflare API gateway (P0-003)"),
]

ok = 0
missing = 0
for rel_path, description in REQUIRED_PAGES:
    full = REPO / rel_path
    if full.exists():
        size = full.stat().st_size
        print(f"  [OK]      {rel_path} ({size:,} bytes) -- {description}")
        ok += 1
    else:
        print(f"  [MISSING] {rel_path} -- {description}")
        missing += 1

print(f"\nEnterprise page audit: {ok} present / {missing} missing")
if missing == 0:
    print("ALL ENTERPRISE ASSETS VERIFIED -- platform is commercially equipped")
else:
    print(f"WARNING: {missing} asset(s) missing -- check deployment")

sys.exit(0)  # Non-blocking
