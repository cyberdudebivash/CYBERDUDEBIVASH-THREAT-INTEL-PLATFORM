"""
CYBERDUDEBIVASH® SENTINEL APEX — Centralized Version Management
================================================================
SINGLE SOURCE OF TRUTH for all version information.

Usage:
    from core.version import VERSION, CODENAME
    
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

# ══════════════════════════════════════════════════════════════════════════════
# VERSION DEFINITION — EDIT ONLY HERE
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "46.0.0"
CODENAME = "ULTRA INTEL"
RELEASE_DATE = "2026-03"
RELEASE_TYPE = "enterprise"

# Derived values
VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH = [int(x) for x in VERSION.split(".")]
VERSION_SHORT = f"v{VERSION_MAJOR}.{VERSION_MINOR}"
VERSION_DISPLAY = f"v{VERSION} ULTRA"
VERSION_FULL = f"SENTINEL APEX {VERSION_DISPLAY}"

VERSION_INFO = {
    "version": VERSION,
    "codename": CODENAME,
    "release_date": RELEASE_DATE,
    "display": VERSION_DISPLAY,
    "full": VERSION_FULL,
}

# Version history for compatibility checks
VERSION_HISTORY = [
    {"version": "46.0.0", "codename": "ULTRA INTEL", "type": "enterprise", "date": "2026-03"},
    {"version": "45.0.0", "codename": "BUG HUNTER", "type": "enterprise", "date": "2026-03"},
    {"version": "39.0.0", "codename": "NEXUS INTELLIGENCE", "type": "enterprise", "date": "2026-03"},
    {"version": "29.0.0", "codename": "APEX SCALE", "type": "enterprise", "date": "2026-03"},
    {"version": "28.0.0", "codename": "FORTRESS", "type": "hardening", "date": "2026-03"},
    {"version": "27.0.0", "codename": "ENTERPRISE", "type": "feature", "date": "2026-02"},
    {"version": "26.0.0", "codename": "SYNC FIX", "type": "bugfix", "date": "2026-02"},
    {"version": "25.0.0", "codename": "CTEM", "type": "feature", "date": "2026-02"},
    {"version": "24.0.0", "codename": "ULTRA", "type": "feature", "date": "2026-01"},
]


def get_version():
    """Get current version string"""
    return VERSION


def get_version_info():
    """Get complete version info dict"""
    return VERSION_INFO.copy()


def check_version_compatibility(required_version: str) -> bool:
    """Check if current version meets minimum requirement"""
    req_parts = [int(x) for x in required_version.split(".")]
    cur_parts = [VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH]
    
    for req, cur in zip(req_parts, cur_parts):
        if cur > req:
            return True
        elif cur < req:
            return False
    return True


if __name__ == "__main__":
    print(f"CYBERDUDEBIVASH® {VERSION_FULL}")
    print(f"Codename: {CODENAME}")
    print(f"Release Type: {RELEASE_TYPE}")
