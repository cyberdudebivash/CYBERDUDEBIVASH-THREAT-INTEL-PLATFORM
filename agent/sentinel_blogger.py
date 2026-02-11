#!/usr/bin/env python3
"""
CDB-SENTINEL-BLOGGER v2.9 – CyberDudeBivash Automated Premium Threat Intel Publisher
Author: Bivash Kumar Nayak (CyberDudeBivash)
Last Updated: February 11, 2026 – Priority fix for unique/relevant images per incident
"""

# ... (keep your existing imports, config, auth, fetch, publish, main – unchanged from last version)

# Only update the version and logging message for generate_premium_report
def generate_premium_report(intel_items):
    from .content.blog_post_generator import generate_full_post_content

    intel_items.sort(key=lambda x: x['published'], reverse=True)
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    title = f"CyberDudeBivash Premium Threat Intel Report – {today} | Zero-Days • Breaches • Malware"
    content = generate_full_post_content(intel_items)
    logger.info("Premium report generated with **unique & relevant images per incident**")
    return title, content

# ... (rest of file unchanged)
