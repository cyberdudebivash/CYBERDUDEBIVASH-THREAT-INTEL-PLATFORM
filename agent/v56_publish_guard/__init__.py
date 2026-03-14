"""
CYBERDUDEBIVASH® SENTINEL APEX v56.0 — Publish Guard
=====================================================
Production stability patch for Blogger API publishing:
  - Rate limiter (8s between posts, max 6/min)
  - Retry handler (429/5xx with exponential backoff, 5 attempts)
  - Manifest-first write (intel→manifest→publish)
  - Failed publish queue (data/pending_publish.json)

ADDITIVE MODULE — Does NOT modify any existing modules directly.
Patches are applied via monkey-patch in sentinel_blogger.py's process_entry().

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

V56_VERSION = "56.0.0"
V56_CODENAME = "PUBLISH GUARD"
