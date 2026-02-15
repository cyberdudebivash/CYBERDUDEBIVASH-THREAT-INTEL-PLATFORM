#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.5
Enterprise Orchestrator: Advanced TTP Correlation & Detection Synthesis.
"""
import os, sys, json, logging, time
from datetime import datetime, timezone
import feedparser
from fpdf import FPDF

# System Path Alignment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Platform Imports
from agent.blogger_auth import get_blogger_service
from agent.config import BLOG_ID, RSS_FEEDS, STATE_FILE, MAX_STATE_SIZE, MAX_PER_FEED
from agent.content.blog_post_generator import generate_full_post_content, generate_headline
from agent.enricher import enricher
from agent.enricher_pro import enricher_pro
from agent.integrations.vt_lookup import vt_lookup
from agent.visualizer import visualizer
from agent.export_stix import stix_exporter
from agent.notifier import send_sentinel_alert

# Global Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-APEX] %(message)s")
logger = logging.getLogger("CDB-MAIN")

class MITREMapper:
    """Enterprise-grade TTP Correlation Engine."""
    def __init__(self):
        # Expanded database for Microsoft/Google level reporting
        self.db = {
            "phishing": {"id": "T1566", "technique": "Phishing", "tactic": "Initial Access"},
            "credential": {"id": "T1552", "technique": "Unsecured Credentials", "tactic": "Credential Access"},
            "c2": {"id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
            "scanning": {"id": "T1595", "technique": "Active Scanning", "tactic": "Reconnaissance"},
            "obfuscation": {"id": "T1027", "technique": "Obfuscated Files or Information", "tactic": "Defense Evasion"}
        }

    def map_threat(self, text):
        """Maps content to full MITRE ATT&CK metadata."""
        matches = []
        text_lower = text.lower()
        for key, metadata in self.db.items():
            if key in text_lower:
                matches.append(metadata)
        # Deduplicate results
        return [dict(t) for t in {tuple(d.items()) for d in matches}]

class CDBWhitepaper(FPDF):
    """Refactored PDF engine to resolve v7.4.1 deprecation warnings."""
    def create_report(self, headline, risk, iocs, mitre, filename):
        self.add_page()
        self.set_font("helvetica", "B", 16) # Resolved font substitution
        self.cell(0, 10, f"CDB ADVISORY: {headline}", new_x="LMARGIN", new_y="NEXT")
        
        self.set_font("helvetica", "", 10)
        self.cell(0, 10, f"Severity: {risk}/10 | Classification: {'TLP:AMBER' if risk >= 7.0 else 'TLP:CLEAR'}", new_x="LMARGIN", new_y="NEXT")
        
        output_dir = "data/whitepapers"
        os.makedirs(output_dir, exist_ok=True)
        self.output(os.path.join(output_dir, filename))

# Core Engine Initialization
mitre_engine = MITREMapper()
pdf_engine = CDBWhitepaper()

def _calculate_enterprise_risk(mitre_context, iocs):
    """Standardized Risk Calculation for Enterprise Reporting."""
    score = 5.5
    if mitre_context: score += 2.0
    if iocs.get('ipv4') or iocs.get('domain'): score += 1.5
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nAPEX v7.5 — ENTERPRISE REFACTOR ACTIVE\n" + "="*60)
    try:
        # 1. Stateless Ingestion
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
            logger.info("No new intelligence nodes. Syncing dashboard only.")
            stix_exporter.update_manifest(); return

        # 2. Intelligence Triage & Correlation
        headline = generate_headline(intel_items)
        corpus = " ".join([i['summary'] for i in intel_items])
        
        # Enterprise Fix: Now returns full ID/Name/Tactic objects
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {
            v: {**enricher_pro.get_ip_context(v), "reputation": vt_lookup.get_reputation(v, "ipv4")} 
            for v in extracted_iocs.get('ipv4', [])
        }
        
        risk_score = _calculate_enterprise_risk(mitre_context, extracted_iocs)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 3. World-Class Content Generation
        full_html = generate_full_post_content(
            intel_items, 
            extracted_iocs, 
            enriched_metadata, 
            visualizer.generate_heat_map(enriched_metadata), 
            stix_id, 
            mitre_data=mitre_context, # Now fully populated
            risk_score=risk_score
        )
        
        # 4. Authenticated Dispatch
        service = get_blogger_service()
        post = service.posts().insert(
            blogId=os.environ.get('BLOG_ID', BLOG_ID), 
            body={
                "title": f"[v7.5 Advisory] {headline}", 
                "content": full_html,
                "labels": ["Enterprise-Advisory", "MITRE-ATT&CK", "Sentinel-APEX"]
            }
        ).execute()

        if post.get("url"):
            # Update Persistence
            json.dump(list(processed), open(STATE_FILE, "w"))
            
            # 5. Asset Generation & Alerts
            if risk_score >= 7.0:
                pdf_engine.create_report(headline, risk_score, extracted_iocs, mitre_context, f"{stix_id}.pdf")
            
            # Final Sync
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata, mitre_data=mitre_context)
            send_sentinel_alert(headline, risk_score, post['url'], mitre_data=mitre_context)
            logger.info(f"✓ V7.5 ENTERPRISE ADVISORY LIVE: {post['url']}")

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__":
    main()
