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

VERSION = "28.0.0"
CODENAME = "FORTRESS"
RELEASE_DATE = "2026-03"
RELEASE_TYPE = "hardening"

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

def get_version(): return VERSION

if __name__ == "__main__":
    print(f"CYBERDUDEBIVASH® {VERSION_FULL}")
    print(f"Codename: {CODENAME}")
