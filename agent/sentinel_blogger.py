#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.0 (BEAST MODE)
Orchestrator: Ingestion -> MITRE Mapping -> Enrichment -> Global Dispatch.
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
    MAX_PER_FEED, PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY
)
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

# --- NEW BEAST MODE MODULE: MITRE MAPPER ---
class MITREMapper:
    def __init__(self):
        self.mapping_db = {
            "phishing": {"id": "T1566", "tactic": "Initial Access"},
            "credential": {"id": "T1556", "tactic": "Credential Access"},
            "c2": {"id": "T1071", "tactic": "Command and Control"},
            "beacon": {"id": "T1071.004", "tactic": "Command and Control"},
            "ransomware": {"id": "T1486", "tactic": "Impact"},
            "exploit": {"id": "T1203", "tactic": "Execution"},
            "obfuscation": {"id": "T1027", "tactic": "Defense Evasion"},
            "exfiltration": {"id": "T1041", "tactic": "Exfiltration"}
        }

    def map_threat(self, corpus: str) -> list:
        matches = []
        corpus_lower = corpus.lower()
        for keyword, meta in self.mapping_db.items():
            if keyword in corpus_lower:
                matches.append(meta)
        return [dict(t) for t in {tuple(d.items()) for d in matches}]

mitre_engine = MITREMapper()

# --- ORCHESTRATION LOGIC ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] CDB-APEX — %(message)s")
logger = logging.getLogger("CDB-SENTINEL-APEX")

def _calculate_cdb_risk_score(headline: str, corpus: str, iocs: dict, mitre_context: list) -> float:
    score = 5.0
    # Increase score based on MITRE tactic severity
    for tech in mitre_context:
        if tech['tactic'] in ["Impact", "Exfiltration", "Initial Access"]:
            score += 1.0
    
    ioc_count = sum(len(v) for v in iocs.values())
    if ioc_count > 15: score += 2.0
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nCYBERDUDEBIVASH SENTINEL APEX v7.0 — BEAST MODE ACTIVE\n" + "="*60)

    try:
        # 1. State/Ingestion Cycle
        if not os.path.exists(STATE_FILE):
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f: json.dump([], f)
        
        with open(STATE_FILE, "r") as f:
            state_data = json.load(f)
            processed = set(state_data[-MAX_STATE_SIZE:])

        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid") or entry.get("link", "")
                if guid in processed: continue
                intel_items.append({
                    "title": entry.get("title", "Threat Node"),
                    "link": entry.get("link", ""),
                    "summary": entry.get("summary", entry.get("description", ""))
                })
                processed.add(guid)
        
        if not intel_items:
            logger.info("System Standby: No new threat vectors detected.")
            stix_exporter.update_manifest() # Keep manifest healthy
            return

        # 2. BEAST MODE: MITRE Mapping & Enrichment
        corpus = " ".join([i['summary'] for i in intel_items])
        mitre_context = mitre_engine.map_threat(corpus)
        logger.info(f"✓ MITRE ATT&CK Mapping Complete: {len(mitre_context)} Techniques Identified.")

        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {}
        for ioc_type, values in extracted_iocs.items():
            for val in values:
                context = enricher_pro.get_ip_context(val) if ioc_type == "ipv4" else {"country_code": None}
                reputation = vt_lookup.get_reputation(val, ioc_type)
                enriched_metadata[val] = {**context, "reputation": reputation}
        
        # 3. Intelligence Assembly
        headline = generate_headline(intel_items)
        risk_score = _calculate_cdb_risk_score(headline, corpus, extracted_iocs, mitre_context)
        threat_map_html = visualizer.generate_heat_map(enriched_metadata)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 4. Content Generation (Enhanced with MITRE Context)
        full_html = generate_full_post_content(
            intel_items, 
            iocs=extracted_iocs, 
            pro_data=enriched_metadata, 
            map_html=threat_map_html,
            stix_id=stix_id,
            mitre_data=mitre_context # New Parameter
        )
        
        # 5. Global Dispatch
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "title": f"[v7.0] {headline} (Risk: {risk_score}/10)",
                    "content": full_html,
                    "labels": ["Sentinel-Apex", "MITRE-ATT&CK", "STIX-2.1", "Enterprise-Intel"]
                }).execute()
                post_url = post.get("url")
                break
            except Exception as e:
                logger.error(f"Dispatch Fail (Attempt {attempt}): {e}")
                time.sleep(PUBLISH_RETRY_DELAY * attempt)

        if post_url:
            logger.info(f"✓ ENTERPRISE ADVISORY LIVE: {post_url}")
            with open(STATE_FILE, "w") as f: json.dump(list(processed), f)
            
            # THE CORE SYNC: STIX Bundle with MITRE & Geo Metadata
            stix_exporter.create_bundle(
                headline, 
                extracted_iocs, 
                risk_score, 
                enriched_metadata,
                mitre_data=mitre_context 
            )
            send_sentinel_alert(headline, risk_score, post_url)

    except Exception as e:
        logger.critical(f"APEX BEAST MODE CRASH: {e}")
        raise

if __name__ == "__main__":
    main()
