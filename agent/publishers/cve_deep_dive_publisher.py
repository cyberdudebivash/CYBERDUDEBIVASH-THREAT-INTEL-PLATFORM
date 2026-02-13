"""
CVE Deep-Dive Publisher — Publishes individual authority-grade CVE reports.
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import logging
from typing import Dict

from agent.blogger_auth import get_blogger_service
from agent.blogger_client import publish_post
from agent.formatter.cdb_cve_deep_dive import format_cve_deep_dive
from agent.config import BLOG_ID, BRAND

logger = logging.getLogger("CDB-DEEPDIVE")


def publish_cve_deep_dive(
    cve: Dict,
    blog_id: str = "",
    author: str = "",
    site_url: str = "",
) -> Dict:
    """Publish a single CVE deep-dive as a standalone post."""

    blog_id = blog_id or BLOG_ID
    author = author or "CyberDudeBivash Threat Intelligence Team"
    site_url = site_url or BRAND["website"]

    service = get_blogger_service()
    cve_id = cve.get("id", "Unknown-CVE")
    severity = (cve.get("severity") or "Unknown").upper()

    title = f"{cve_id} — {severity} Vulnerability Deep Dive | CyberDudeBivash Threat Intel"

    content = format_cve_deep_dive(
        cve=cve,
        author=author,
        site_url=site_url,
    )

    result = publish_post(
        service=service,
        blog_id=blog_id,
        title=title,
        content=content,
        labels=[
            "CVE", "Deep Dive", "Threat Intelligence",
            "CyberDudeBivash", cve_id, severity,
        ],
        is_draft=False,
    )

    logger.info(f"Deep dive published: {cve_id} → {result.get('url')}")
    return result
