#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v6.0 APEX (Geospatial Edition)
Orchestrator: Ingestion -> Enrichment -> STIX 2.1 Mapping -> Global Dispatch.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone

import feedparser

# Path resolution for Enterprise Environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Platform Module Imports
from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE,
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY, VT_API_KEY
)
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter # v6.0 Geospatial Exporter
from agent.notifier import send_sentinel_alert

# Global Operational Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("CDB-SENTINEL-APEX")

def _calculate_cdb_risk_score(headline: str, corpus: str, iocs: dict) -> float:
    """Enterprise Risk Scoring Algorithm v6.0."""
    score = 5.0
    critical_terms = ["ransomware", "zero-day", "critical", "exploit", "cve-2026"]
    for term in critical_terms:
        if term in (headline + corpus).lower():
            score += 1.5
    
    ioc_count = sum(len(v) for v in iocs.values())
    if ioc_count > 10: score += 1.0
    if ioc_count > 25: score += 2.0
    
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nCYBERDUDEBIVASH SENTINEL APEX v6.0 — GOC ACTIVE\n" + "="*60)

    try:
        # 1. State/Ingestion Cycle
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        with open(STATE_FILE, "r") as f:
            state_data = json.load(f)
            processed = set(state_data[-MAX_STATE_SIZE:]) if isinstance(state_data, list) else set()

        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid") or entry.get("link", "")
                if guid in processed: continue
                intel_items.append({
                    "title": entry.get("title", "Advisory Node"),
                    "link": entry.get("link", ""),
                    "summary": entry.get("summary", entry.get("description", ""))
                })
                processed.add(guid)
        
        if not intel_items:
            logger.info("System Standby: No new geospatial vectors detected.")
            # Critical Fix: Still update manifest to ensure map remains synced
            stix_exporter.update_manifest()
            return

        # 2. Intelligence Triage & Enrichment
        corpus = " ".join([i['summary'] for i in intel_items])
        extracted_iocs = enricher.extract_iocs(corpus)
        threat_category = enricher.categorize_threat(extracted_iocs)
        
        # Build the Enriched Metadata for STIX 2.1 Location Mapping
        enriched_metadata = {}
        for ioc_type, values in extracted_iocs.items():
            for val in values:
                # Geo-IP Context
                context = enricher_pro.get_ip_context(val) if ioc_type == "ipv4" else {"location": "N/A", "isp": "N/A", "country_code": None}
                # Reputation Sweeps
                reputation = vt_lookup.get_reputation(val, ioc_type)
                enriched_metadata[val] = {**context, "reputation": reputation}
        
        # 3. Branding & Scoring
        headline = generate_headline(intel_items)
        risk_score = _calculate_cdb_risk_score(headline, corpus, extracted_iocs)
        threat_map_html = visualizer.generate_heat_map(enriched_metadata)
        
        # 4. Content Assembly (Enterprise UI)
        stix_id = f"CDB-APEX-{int(time.time())}"
        full_html = generate_full_post_content(
            intel_items, 
            iocs=extracted_iocs, 
            pro_data=enriched_metadata, 
            map_html=threat_map_html,
            stix_id=stix_id
        )
        
        # 5. Global Dispatch (Blogger API)
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "title": f"[{threat_category}] {headline} (Score: {risk_score}/10)",
                    "content": full_html,
                    "labels": ["CDB-Sentinel", "STIX-2.1", "Geospatial-Intel", "VT-Verified"]
                }).execute()
                post_url = post.get("url")
                break
            except Exception as e:
                logger.error(f"Dispatch attempt {attempt} failed: {e}")
                time.sleep(PUBLISH_RETRY_DELAY * attempt)

        if post_url:
            logger.info(f"✓ APEX REPORT DISPATCHED: {post_url}")
            # Update State
            with open(STATE_FILE, "w") as f: json.dump(list(processed), f)
            
            # THE CORE UPGRADE: Create STIX Bundle with Geospatial Metadata
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata)
            
            # Send Final Alert
            send_sentinel_alert(headline, risk_score, post_url)

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}")
        raise

if __name__ == "__main__":
    main()
