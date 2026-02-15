#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.4 (FINAL PRODUCTION)
Integrated: Ingestion -> MITRE -> Enrichment -> PDF Gen -> TLP/Diamond Model -> Dispatch.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone

import feedparser
from fpdf import FPDF

# Ensure paths match repository structure
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Platform Module Imports
from agent.blogger_auth import get_blogger_service
from agent.config import (
    BLOG_ID, RSS_FEEDS, MAX_STATE_SIZE, MAX_PER_FEED,
    PUBLISH_RETRY_MAX, PUBLISH_RETRY_DELAY
)
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

# Verified State File Path from Repository History
STATE_FILE = "data/blogger_processed.json"

# Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-APEX] %(message)s")
logger = logging.getLogger("CDB-MAIN")

# --- BEAST MODE ENGINES ---
class MITREMapper:
    """Maps keywords to MITRE ATT&CK techniques."""
    def __init__(self):
        self.db = {
            "phishing": {"id": "T1566", "tactic": "Initial Access"},
            "credential": {"id": "T1556", "tactic": "Credential Access"},
            "c2": {"id": "T1071", "tactic": "Command and Control"},
            "ransomware": {"id": "T1486", "tactic": "Impact"},
            "exfiltration": {"id": "T1041", "tactic": "Exfiltration"}
        }

    def map_threat(self, text):
        matches = []
        for k, v in self.db.items():
            if k in text.lower():
                matches.append(v)
        return [dict(t) for t in {tuple(d.items()) for d in matches}]

class CDBWhitepaper(FPDF):
    """Generates professional Enterprise Advisories in PDF format."""
    def create_report(self, headline, risk, iocs, mitre, filename):
        self.add_page()
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, f"CDB SENTINEL ADVISORY: {headline}", ln=True)
        self.set_font("Arial", "", 10)
        self.cell(0, 10, f"Risk Level: {risk}/10 | TLP: {'AMBER' if risk >= 7.0 else 'CLEAR'}", ln=True)
        
        output_dir = "data/whitepapers"
        os.makedirs(output_dir, exist_ok=True)
        self.output(os.path.join(output_dir, filename))

# Initialization
mitre_engine = MITREMapper()
pdf_engine = CDBWhitepaper()

def _calculate_cdb_risk_score(headline, corpus, iocs, mitre_context):
    """Dynamic risk scoring based on tactical severity."""
    score = 6.0
    if any(m['tactic'] in ["Impact", "Initial Access"] for m in mitre_context):
        score += 2.0
    if len(iocs.get('ipv4', [])) > 10:
        score += 1.5
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nCYBERDUDEBIVASH SENTINEL APEX v7.4 — BEAST MODE RUN\n" + "="*60)
    
    try:
        # 1. Ingestion & State Management
        if not os.path.exists("data"): os.makedirs("data")
        processed = set(json.load(open(STATE_FILE))[-MAX_STATE_SIZE:]) if os.path.exists(STATE_FILE) else set()
        
        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid", entry.link)
                if guid not in processed:
                    intel_items.append({
                        "title": entry.title, 
                        "link": entry.link, 
                        "summary": entry.get("summary", entry.get("description", ""))
                    })
                    processed.add(guid)
        
        if not intel_items:
            logger.info("No new threat vectors detected. Updating manifest.")
            stix_exporter.update_manifest()
            return

        # 2. Intelligence Triage & Enrichment
        corpus = " ".join([i['summary'] for i in intel_items])
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {
            v: {**enricher_pro.get_ip_context(v), "reputation": vt_lookup.get_reputation(v, "ipv4")} 
            for v in extracted_iocs.get('ipv4', [])
        }
        
        # 3. Report Assembly (v7.4 Enhanced)
        headline = generate_headline(intel_items)
        risk_score = _calculate_cdb_risk_score(headline, corpus, extracted_iocs, mitre_context)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # Call signature synchronized with v7.4 content engine
        full_html = generate_full_post_content(
            intel_items, 
            extracted_iocs, 
            enriched_metadata, 
            visualizer.generate_heat_map(enriched_metadata), 
            stix_id, 
            mitre_data=mitre_context,
            risk_score=risk_score # Critical for TLP marking
        )
        
        # 4. Authenticated Dispatch
        service = get_blogger_service()
        post = service.posts().insert(blogId=os.environ.get('BLOG_ID'), body={
            "title": f"[v7.4] {headline} ({'🚨 HIGH' if risk_score >= 7.5 else '🛡️ INFO'})",
            "content": full_html,
            "labels": ["Sentinel-Apex", "MITRE-ATT&CK", "Diamond-Model"]
        }).execute()

        if post.get("url"):
            logger.info(f"✓ REPORT PUBLISHED: {post['url']}")
            # Update persistence file
            json.dump(list(processed), open(STATE_FILE, "w"))
            
            # 5. Asset Generation & Alerts
            if risk_score >= 7.0:
                pdf_engine.create_report(headline, risk_score, extracted_iocs, mitre_context, f"{stix_id}.pdf")
            
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata, mitre_data=mitre_context)
            send_sentinel_alert(headline, risk_score, post['url'], mitre_data=mitre_context)

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}")
        raise

if __name__ == "__main__":
    main()
