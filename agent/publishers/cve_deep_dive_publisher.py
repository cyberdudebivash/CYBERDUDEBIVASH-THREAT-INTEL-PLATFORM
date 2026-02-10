"""
Standalone CVE Deep-Dive Publisher
FINAL • PRODUCTION • BLOGGER SAFE
"""

from agent.blogger_auth import get_blogger_service
from agent.blogger_client import publish_post
from agent.formatter.cdb_cve_deep_dive import format_cve_deep_dive


def publish_cve_deep_dive(
    cve: dict,
    blog_id: str,
    author: str,
    site_url: str,
):
    """
    Publish a single CVE deep-dive as a standalone post.
    """

    service = get_blogger_service()

    cve_id = cve.get("id", "Unknown-CVE")
    title = f"{cve_id} – Cyber Threat Intelligence Deep Dive"

    content = format_cve_deep_dive(
        cve=cve,
        author=author,
        site_url=site_url,
    )

    return publish_post(
        service=service,
        blog_id=blog_id,
        title=title,
        content=content,
        labels=[
            "CVE",
            "Threat Intelligence",
            "CyberDudeBivash",
            cve_id,
        ],
        is_draft=False,
    )
