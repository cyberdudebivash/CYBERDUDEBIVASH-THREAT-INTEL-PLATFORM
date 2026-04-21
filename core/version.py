"""
CYBERDUDEBIVASH® SENTINEL APEX — Centralized Version Management
================================================================
SINGLE SOURCE OF TRUTH for all version information.
Reads from config/version.json via core.utils.version.

Usage:
    from core.version import VERSION, CODENAME, VERSION_FULL

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

from core.utils.version import (
    get_version as _get_cfg,
    platform_version as _pv,
    platform_full as _pf,
    api_gateway_string as _ag,
)

# ══════════════════════════════════════════════════════════════════════════════
# VERSION DEFINITION — loaded from config/version.json (single source of truth)
# ══════════════════════════════════════════════════════════════════════════════

_V = _get_cfg()

VERSION: str = _pv()
CODENAME: str = str(_V.get("codename") or "Apex Stability")
RELEASE_DATE: str = str(_V.get("release_date") or "2026-04-21")
RELEASE_TYPE: str = str(_V.get("release_type") or "enterprise")

# Derived values
try:
    _parts = [int(x) for x in VERSION.split(".")]
    VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH = (_parts + [0, 0, 0])[:3]
except Exception:
    VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH = 134, 0, 0

VERSION_SHORT: str = f"v{VERSION_MAJOR}.{VERSION_MINOR}"
VERSION_DISPLAY: str = f"v{VERSION}"
VERSION_FULL: str = _pf()
API_GATEWAY: str = _ag()

VERSION_INFO = {
    "version": VERSION,
    "codename": CODENAME,
    "release_date": RELEASE_DATE,
    "display": VERSION_DISPLAY,
    "full": VERSION_FULL,
    "schema_version": str(_V.get("schema_version", "v134.0")),
    "api_version": "v1",
    "stix_version": "2.1",
    "ioc_engine_version": str(_V.get("components", {}).get("ioc_engine", "6.0")),
    "platform": "CYBERDUDEBIVASH® SENTINEL APEX",
}

# Version history for compatibility checks (informational only)
VERSION_HISTORY = [
    {"version": VERSION,   "codename": CODENAME,              "type": "enterprise", "date": RELEASE_DATE},
    {"version": "131.0.0", "codename": "REVENUE ENGINE",       "type": "enterprise", "date": "2026-04"},
    {"version": "124.0.0", "codename": "GLOBAL DOMINATION",    "type": "enterprise", "date": "2026-04"},
    {"version": "47.0.0",  "codename": "COMMAND CENTER",       "type": "enterprise", "date": "2026-03"},
    {"version": "46.0.0",  "codename": "VANGUARD",             "type": "enterprise", "date": "2026-03"},
    {"version": "45.0.0",  "codename": "BUG HUNTER",           "type": "enterprise", "date": "2026-03"},
    {"version": "39.0.0",  "codename": "NEXUS INTELLIGENCE",   "type": "enterprise", "date": "2026-03"},
    {"version": "29.0.0",  "codename": "APEX SCALE",           "type": "enterprise", "date": "2026-03"},
    {"version": "28.0.0",  "codename": "FORTRESS",             "type": "hardening",  "date": "2026-03"},
    {"version": "27.0.0",  "codename": "ENTERPRISE",           "type": "feature",    "date": "2026-02"},
    {"version": "26.0.0",  "codename": "SYNC FIX",             "type": "bugfix",     "date": "2026-02"},
    {"version": "25.0.0",  "codename": "CTEM",                 "type": "feature",    "date": "2026-02"},
    {"version": "24.0.0",  "codename": "ULTRA",                "type": "feature",    "date": "2026-01"},
]


def get_version() -> str:
    """Get current version string"""
    return VERSION


def get_version_info() -> dict:
    """Get complete version info dict"""
    return VERSION_INFO.copy()


def check_version_compatibility(required_version: str) -> bool:
    """Check if current version meets minimum requirement"""
    req_parts = [int(x) for x in required_version.split(".")]
    cur_parts = [VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH]
    for req, cur in zip(req_parts, cur_parts):
        if cur > req:
            return True
        if cur < req:
            return False
    return True


if __name__ == "__main__":  # pragma: no cover
    print(f"CYBERDUDEBIVASH® {VERSION_FULL}")
    print(f"Codename: {CODENAME}")
    print(f"Release Type: {RELEASE_TYPE}")
    print(f"API Gateway: {API_GATEWAY}")
