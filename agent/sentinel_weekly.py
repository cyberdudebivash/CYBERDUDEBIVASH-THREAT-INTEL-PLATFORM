"""
CDB-SENTINEL Weekly CVE Mega-Report Orchestrator
FINAL • PRODUCTION • CI SAFE
"""

import os
from dotenv import load_dotenv

from agent.intel.cve_feed import fetch_recent_cves
from agent.intel.kev_feed import fetch_kev_catalog
from agent.analysis.weekly_cve_ranker import rank_weekly_cves
from agent.formatter.cdb_weekly_cve_report import format_weekly_cve_report
from agent.blogger_auth import get_blogger_service
from agent.blogger_client import publish_post


# =================================================
# ENVIRONMENT
# =================================================

load_dotenv()

BLOG_ID = os.getenv("BLOGGER_BLOG_ID")
AUTHOR_NAME = os.getenv("AUTHOR_NAME", "CyberDudeBivash Threat Intelligence Team")
SITE_URL = os.getenv("SITE_URL", "")

if not BLOG_ID:
    raise RuntimeError("❌ BLOGGER_BLOG_ID not set")


# =================================================
# WEEKLY ORCHESTRATOR
# =================================================

def run():
    service = get_blogger_service()

    # ------------------------------
    # FETCH 7-DAY INTELLIGENCE
    # ------------------------------

    cves = fetch_recent_cves(hours=168, max_results=50)
    kev_items = fetch_kev_catalog()

    # ------------------------------
    # RANK CVES
    # ------------------------------

    ranked_cves = rank_weekly_cves(
        cves=cves,
        kev_items=kev_items,
        top_n=10,
    )

    # ------------------------------
    # FORMAT REPORT
    # ------------------------------

    content = format_weekly_cve_report(
        ranked_cves=ranked_cves,
        author=AUTHOR_NAME,
        site_url=SITE_URL,
    )

    # ------------------------------
    # PUBLISH
    # ------------------------------

    result = publish_post(
        service=service,
        blog_id=BLOG_ID,
        title="Weekly Top Exploited CVEs – Cyber Threat Intelligence Mega-Report",
        content=content,
        labels=[
            "Weekly Report",
            "CVE",
            "Threat Intelligence",
            "CyberDudeBivash",
        ],
        is_draft=False,
    )

    print("✅ Weekly CVE mega-report published")
    print("🔗 Blog URL:", result.get("url"))


# =================================================
# ENTRYPOINT
# =================================================

if __name__ == "__main__":
    run()
