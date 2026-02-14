"""
CDB-SENTINEL Weekly CVE Mega-Report Orchestrator v3.0
Fetches, ranks, formats, and publishes the weekly top-exploited CVE report.
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import os
import logging
from dotenv import load_dotenv

from agent.intel.cve_feed import fetch_recent_cves
from agent.intel.kev_feed import fetch_kev_catalog
from agent.analysis.weekly_cve_ranker import rank_weekly_cves
from agent.formatter.cdb_weekly_cve_report import format_weekly_cve_report
from agent.blogger_auth import get_blogger_service
from agent.blogger_client import publish_post
from agent.config import BLOG_ID, BRAND, WEEKLY_CVE_HOURS, WEEKLY_TOP_N

logger = logging.getLogger("CDB-WEEKLY")

load_dotenv()


def run():
    """Execute the weekly CVE mega-report pipeline."""
    blog_id = os.getenv("BLOG_ID") or BLOG_ID
    author = os.getenv("AUTHOR_NAME", "CyberDudeBivash Threat Intelligence Team")
    site_url = os.getenv("SITE_URL", BRAND["website"])

    if not blog_id:
        raise RuntimeError("BLOG_ID not set")

    logger.info("Starting weekly CVE mega-report pipeline")

    service = get_blogger_service()

    # Fetch 7-day intelligence
    cves = fetch_recent_cves(hours=WEEKLY_CVE_HOURS, max_results=50)
    kev_items = fetch_kev_catalog()

    # Rank CVEs
    ranked = rank_weekly_cves(cves=cves, kev_items=kev_items, top_n=WEEKLY_TOP_N)
    logger.info(f"Ranked {len(ranked)} CVEs for weekly report")

    # Format report
    content = format_weekly_cve_report(
        ranked_cves=ranked,
        author=author,
        site_url=site_url,
    )

    # Publish
    result = publish_post(
        service=service,
        blog_id=blog_id,
        title="Weekly Top Exploited CVEs — Cyber Threat Intelligence Mega-Report | CyberDudeBivash",
        content=content,
        labels=["Weekly Report", "CVE", "Threat Intelligence", "CyberDudeBivash", "2026"],
        is_draft=False,
    )

    logger.info(f"✅ Weekly report published: {result.get('url')}")
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run()
