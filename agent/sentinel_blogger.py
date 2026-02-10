"""
CDB-SENTINEL Blogger Orchestrator
FINAL • PRODUCTION • FULL PIPELINE
"""

import os
from dotenv import load_dotenv

from agent.blogger_auth import get_blogger_service
from agent.blogger_client import publish_post
from agent.formatter.cdb_template import format_daily_threat_report

from agent.intel.cve_feed import fetch_recent_cves
from agent.intel.kev_feed import fetch_kev_catalog
from agent.intel.malware_feed import fetch_malware_activity

from agent.analysis.attack_coverage import analyze_attack_coverage
from agent.analysis.cve_deep_dive_selector import select_cves_for_deep_dive
from agent.publishers.cve_deep_dive_publisher import publish_cve_deep_dive

from agent.intel.ioc_export import export_stix_bundle, export_misp_event


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
# MAIN ORCHESTRATOR
# =================================================

def run():
    service = get_blogger_service()

    # ------------------------------
    # FETCH INTELLIGENCE
    # ------------------------------

    cves = fetch_recent_cves(hours=24, max_results=10)
    kev_items = fetch_kev_catalog()

    try:
        malware_items = fetch_malware_activity()
    except Exception:
        print("⚠️ MalwareBazaar API unavailable")
        malware_items = []

    # ------------------------------
    # ATT&CK COVERAGE
    # ------------------------------

    # FIX: Add missing attack_techniques parameter (was causing TypeError)
    coverage_gaps = analyze_attack_coverage(
        cves=cves,
        malware_items=malware_items,
        attack_techniques=[]  # Empty list - function requires 3 parameters
    )

    # ------------------------------
    # DAILY REPORT
    # ------------------------------

    content = format_daily_threat_report(
        cves=cves,
        kev_items=kev_items,
        malware_items=malware_items,
        coverage_gaps=coverage_gaps,
        author=AUTHOR_NAME,
        site_url=SITE_URL,
    )

    result = publish_post(
        service=service,
        blog_id=BLOG_ID,
        title="Daily Cyber Threat Intelligence Report",
        content=content,
        labels=[
            "Threat Intelligence",
            "CyberDudeBivash",
            "Daily Report",
        ],
        is_draft=False,
    )

    print("✅ Daily threat report published")
    print("🔗 Blog URL:", result.get("url"))

    # ------------------------------
    # IOC EXPORTS
    # ------------------------------

    export_stix_bundle(cves, malware_items)
    export_misp_event(cves, malware_items)

    print("📦 STIX & MISP exports completed")

    # ------------------------------
    # AUTO CVE DEEP DIVES
    # ------------------------------

    deep_dive_cves = select_cves_for_deep_dive(
        cves=cves,
        kev_items=kev_items,
    )

    for cve in deep_dive_cves:
        publish_cve_deep_dive(
            cve=cve,
            blog_id=BLOG_ID,
            author=AUTHOR_NAME,
            site_url=SITE_URL,
        )
        print(f"📝 CVE deep dive published: {cve.get('id')}")

    print("✅ Threat report + CVE deep dives completed")


# =================================================
# ENTRYPOINT
# =================================================

if __name__ == "__main__":
    run()
