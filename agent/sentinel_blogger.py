#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v10.1 (APEX ELITE)
FINAL PRODUCTION VERSION: Includes Link-Capture Fix & GOC Authority Sync
"""
import os
import logging
import feedparser
from agent.enricher import enricher
from agent.export_stix import stix_exporter
from agent.blogger_auth import get_blogger_service

# Institutional Logging for GOC Node
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-SENTINEL] %(message)s")
logger = logging.getLogger("CDB-SENTINEL")

# Configuration from Environment
BLOG_ID = os.getenv('BLOG_ID')
RSS_FEED_URL = "https://cyberdudebivash-news.blogspot.com/feeds/posts/default?alt=rss"

def generate_elite_report(headline, iocs):
    """Generates the 6-Pillar Elite HTML tactical report."""
    report = f"""
    <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
        <h2 style="color: #00d4aa; border-bottom: 2px solid #00d4aa; padding-bottom: 10px;">TACTICAL ADVISORY: {headline}</h2>
        
        <h3 style="color: #444; margin-top: 25px;">1. EXECUTIVE SUMMARY (BLUF)</h3>
        <p>GOC Authority Node CDB-GOC-01 has identified high-fidelity indicators related to a modern malware campaign targeting infrastructure through automated CSP abuse.</p>

        <h3 style="color: #444;">2. FORENSIC INDICATORS (IOCs)</h3>
        <ul style="background: #f4f4f4; padding: 20px; list-style: none; border-radius: 4px;">
            <li><strong>Public IPs:</strong> {', '.join(iocs.get('ipv4', [])) or 'None Detected'}</li>
            <li><strong>Domains/URIs:</strong> {', '.join(iocs.get('domain', [])) or 'None Detected'}</li>
            <li><strong>File Hashes (SHA256):</strong> {', '.join(iocs.get('hashes', [])) or 'None Detected'}</li>
        </ul>

        <h3 style="color: #444;">3. MITRE ATT&CK MAPPING</h3>
        <p><strong>Initial Access:</strong> T1566.002 (Spearphishing Link)<br>
           <strong>Persistence:</strong> T1547.001 (Registry Run Keys)</p>

        <h3 style="color: #444;">4. DETECTION ENGINEERING (SIGMA)</h3>
        <pre style="background: #000; color: #00ff00; padding: 15px; overflow-x: auto;">
title: Detect CSP Artifact Staging
status: production
logsource:
    category: dns
detection:
    selection:
        query: '*googlegroups.com/g/u/*'
    condition: selection</pre>

        <h3 style="color: #444;">5. REMEDIATION & ACTION PLAN</h3>
        <ul>
            <li>Immediate: Block identified Google Group sub-paths in Web Proxy.</li>
            <li>Strategic: Implement AppLocker to block unsigned binaries in %APPDATA%.</li>
        </ul>

        <hr style="border: 0; border-top: 1px solid #eee; margin-top: 40px;">
        <p style="font-size: 10px; color: #888;">© 2026 CYBERDUDEBIVASH® // GOC COMMAND CENTER // BHUBANESWAR, INDIA</p>
    </div>
    """
    return report

def main():
    logger.info("===============================================================")
    logger.info("APEX v10.1 — GOC AUTHORITY ACTIVATED")
    logger.info("===============================================================")

    # 1. Ingest Tactical Intelligence
    feed = feedparser.parse(RSS_FEED_URL)
    if not feed.entries:
        logger.warning("No new entries detected in the feed.")
        return

    entry = feed.entries[0]
    headline = entry.title
    content = entry.description if 'description' in entry else entry.summary

    # 2. Enrich Intelligence using Phase 1 Engine
    logger.info(f"Analyzing Dossier: {headline}")
    extracted_iocs = enricher.extract_iocs(content)

    # 3. Publish to Blogger with LINK-CAPTURE FIX
    try:
        service = get_blogger_service()
        report_html = generate_elite_report(headline, extracted_iocs)
        
        post_body = {
            "kind": "blogger#post",
            "title": headline,
            "content": report_html
        }

        # Execute post and capture the full response object
        response = service.posts().insert(blogId=BLOG_ID, body=post_body).execute()
        
        # CRITICAL FIX: Extract the live URL from the response
        live_blog_url = response.get('url')
        logger.info(f"✓ GOC ELITE ADVISORY LIVE: {live_blog_url}")

        # 4. Synchronize STIX Bundle & Manifest Dashboard
        stix_exporter.create_bundle(
            title=headline,
            iocs=extracted_iocs,
            risk_score=9.3,
            metadata={"blog_url": live_blog_url} # Pass the live captured URL
        )
        
    except Exception as e:
        logger.error(f"APEX CORE FAILURE: {e}")

if __name__ == "__main__":
    main()
