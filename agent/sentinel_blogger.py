#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.5.2
Final Enterprise Orchestrator: Deep-Dive Intelligence Triage & Attribution.
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

# Global Logging Configuration
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] CDB-APEX: %(message)s"
)
logger = logging.getLogger("CDB-MAIN")

class MITREMapper:
    """Enterprise-grade TTP Correlation Engine."""
    def __init__(self):
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
        # Deduplicate results using tuple conversion
        return [dict(t) for t in {tuple(d.items()) for d in matches}]

class CDBWhitepaper(FPDF):
    """Refactored PDF engine to resolve deprecation warnings."""
    def create_report(self, headline, risk, iocs, mitre, filename):
        self.add_page()
        self.set_font("helvetica", "B", 16)
        self.cell(0, 10, f"CDB ADVISORY: {headline}", new_x="LMARGIN", new_y="NEXT")
        
        self.set_font("helvetica", "", 10)
        status = f"Severity: {risk}/10 | Classification: {'TLP:AMBER' if risk >= 7.0 else 'TLP:CLEAR'}"
        self.cell(0, 10, status, new_x="LMARGIN", new_y="NEXT")
        
        output_dir = "data/whitepapers"
        os.makedirs(output_dir, exist_ok=True)
        self.output(os.path.join(output_dir, filename))

mitre_engine = MITREMapper()
pdf_engine = CDBWhitepaper()

def _calculate_enterprise_risk(mitre_context, iocs):
    """Dynamic risk scoring for v7.5.2."""
    score = 5.5
    if mitre_context: score += 2.0
    if iocs.get('ipv4') or iocs.get('domain'): score += 1.5
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nAPEX v7.5.2 — DEEP-DIVE PRODUCTION ACTIVE\n" + "="*60)
    try:
        if not os.path.exists("data"): os.makedirs("data")
        processed = set(json.load(open(STATE_FILE))[-MAX_STATE_SIZE:]) if os.path.exists(STATE_FILE) else set()
        
        intel_items = []
        for url in RSS_FEEDS:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_PER_FEED]:
                guid = entry.get("guid", entry.link)
                if guid not in processed:
                    # Capturing full summary for Deep-Dive Section 2
                    intel_items.append({
                        "title": entry.title, 
                        "link": entry.link, 
                        "summary": entry.get("summary", entry.get("description", "No detail available."))
                    })
                    processed.add(guid)
        
        if not intel_items:
            logger.info("No new intelligence found. Syncing manifest.")
            stix_exporter.update_manifest(); return

        # 2. Advanced Triage & Enrichment
        headline = generate_headline(intel_items)
        corpus = " ".join([i['summary'] for i in intel_items])
        
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        
        # Enrichment with VT Analyst Insights
        enriched_metadata = {
            v: vt_lookup.get_reputation(v, "ipv4" if enricher.is_ip(v) else "domain") 
            for v in (extracted_iocs.get('ipv4', []) + extracted_iocs.get('domain', []))
        }
        
        risk_score = _calculate_enterprise_risk(mitre_context, extracted_iocs)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 3. Enterprise Content Generation
        full_html = generate_full_post_content(
            intel_items, extracted_iocs, enriched_metadata, 
            visualizer.generate_heat_map(enriched_metadata), 
            stix_id, mitre_data=mitre_context, risk_score=risk_score
        )
        
        # 4. Authenticated Dispatch
        service = get_blogger_service()
        post = service.posts().insert(
            blogId=os.environ.get('BLOG_ID', BLOG_ID), 
            body={
                "title": f"[v7.5.2 Advisory] {headline}", 
                "content": full_html,
                "labels": ["Enterprise-Advisory", "MITRE-Mapping", "Contextual-Attribution"]
            }
        ).execute()

        if post.get("url"):
            json.dump(list(processed), open(STATE_FILE, "w"))
            
            # 5. Global Asset Sync
            if risk_score >= 7.0:
                pdf_engine.create_report(headline, risk_score, extracted_iocs, mitre_context, f"{stix_id}.pdf")
            
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata, mitre_data=mitre_context)
            send_sentinel_alert(headline, risk_score, post['url'], mitre_data=mitre_context)
            logger.info(f"✓ ENTERPRISE ADVISORY DISPATCHED: {post['url']}")

    except Exception as e:
        logger.critical(f"APEX CORE FAILURE: {e}"); raise

if __name__ == "__main__":
    main()
