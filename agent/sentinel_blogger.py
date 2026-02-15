#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash v7.2 (BEAST MODE + PDF GEN)
Orchestrator: Ingestion -> MITRE Mapping -> Enrichment -> PDF Generation -> Dispatch.
"""
import os
import sys
import json
import logging
import time
from datetime import datetime, timezone

import feedparser
from fpdf import FPDF # Requires: pip install fpdf2

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

# --- MODULE: MITRE MAPPER ---
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

# --- MODULE: PDF GENERATOR (v7.2) ---
class CDBWhitepaper(FPDF):
    def header(self):
        # Professional Dark Theme Background
        self.set_fill_color(10, 10, 10)
        self.rect(0, 0, 210, 297, 'F')
        
        # Neon Teal Header
        self.set_font('Arial', 'B', 22)
        self.set_text_color(0, 212, 170)
        self.cell(0, 15, 'CDB SENTINEL APEX', ln=True, align='L')
        
        self.set_font('Arial', 'B', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, 'CYBERDUDEBIVASH PVT. LTD. | ENTERPRISE THREAT ADVISORY', ln=True, align='L')
        self.ln(10)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_text_color(0, 212, 170)
        self.cell(0, 10, f">> {title}", ln=True)
        self.ln(4)

    def create_report(self, headline, risk_score, iocs, mitre_data, filename):
        self.add_page()
        self.set_text_color(240, 240, 240)
        
        # Section 1: BLUF
        self.chapter_title("EXECUTIVE SUMMARY (BLUF)")
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 6, f"THREAT IDENTIFIED: {headline}\nCRITICAL RISK SCORE: {risk_score}/10\nSTATUS: ACTIVE TRIAGE / GOC MONITORED")
        self.ln(8)

        # Section 2: MITRE Tactics
        if mitre_data:
            self.chapter_title("TACTICAL ATTRIBUTION (MITRE ATT&CK)")
            for tech in mitre_data:
                self.set_font('Arial', 'B', 9)
                self.set_text_color(0, 212, 170)
                self.cell(30, 6, f"ID: {tech['id']}", border=0)
                self.set_text_color(200, 200, 200)
                self.cell(0, 6, f"Tactic: {tech['tactic']}", ln=True)
            self.ln(8)

        # Section 3: Forensic Indicators
        self.chapter_title("FORENSIC INDICATORS (IOCs)")
        self.set_font('Courier', '', 9)
        self.set_text_color(150, 150, 150)
        for ioc_type, values in iocs.items():
            if values:
                self.set_font('Courier', 'B', 9)
                self.cell(0, 6, f"[{ioc_type.upper()}]", ln=True)
                self.set_font('Courier', '', 9)
                for val in values:
                    self.cell(0, 5, f" > {val}", ln=True)
        
        # Save to localized repository path
        output_dir = "data/whitepapers"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        self.output(output_path)
        return output_path

# --- CORE ORCHESTRATION ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] CDB-APEX — %(message)s")
logger = logging.getLogger("CDB-SENTINEL-APEX")
mitre_engine = MITREMapper()
pdf_engine = CDBWhitepaper()

def _calculate_cdb_risk_score(headline: str, corpus: str, iocs: dict, mitre_context: list) -> float:
    score = 5.0
    for tech in mitre_context:
        if tech['tactic'] in ["Impact", "Exfiltration", "Initial Access"]: score += 1.0
    ioc_count = sum(len(v) for v in iocs.values())
    if ioc_count > 15: score += 2.0
    return min(10.0, score)

def main():
    logger.info("="*60 + "\nCYBERDUDEBIVASH SENTINEL APEX v7.2 — PDF ENGINE ACTIVE\n" + "="*60)

    try:
        # 1. State/Ingestion
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
            stix_exporter.update_manifest()
            return

        # 2. Enrichment & Mapping
        corpus = " ".join([i['summary'] for i in intel_items])
        mitre_context = mitre_engine.map_threat(corpus)
        extracted_iocs = enricher.extract_iocs(corpus)
        enriched_metadata = {}
        for ioc_type, values in extracted_iocs.items():
            for val in values:
                context = enricher_pro.get_ip_context(val) if ioc_type == "ipv4" else {"country_code": None}
                reputation = vt_lookup.get_reputation(val, ioc_type)
                enriched_metadata[val] = {**context, "reputation": reputation}
        
        # 3. Intelligence Triage
        headline = generate_headline(intel_items)
        risk_score = _calculate_cdb_risk_score(headline, corpus, extracted_iocs, mitre_context)
        threat_map_html = visualizer.generate_heat_map(enriched_metadata)
        stix_id = f"CDB-APEX-{int(time.time())}"
        
        # 4. Content Generation
        full_html = generate_full_post_content(
            intel_items, 
            iocs=extracted_iocs, 
            pro_data=enriched_metadata, 
            map_html=threat_map_html,
            stix_id=stix_id,
            mitre_data=mitre_context
        )
        
        # 5. Global Dispatch
        service = get_blogger_service()
        post_url = None
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                post = service.posts().insert(blogId=BLOG_ID, body={
                    "title": f"[v7.2] {headline} (Risk: {risk_score}/10)",
                    "content": full_html,
                    "labels": ["Sentinel-Apex", "MITRE-ATT&CK", "Whitepaper-Available"]
                }).execute()
                post_url = post.get("url")
                break
            except Exception as e:
                logger.error(f"Dispatch Fail: {e}")
                time.sleep(PUBLISH_RETRY_DELAY * attempt)

        if post_url:
            logger.info(f"✓ ENTERPRISE ADVISORY LIVE: {post_url}")
            with open(STATE_FILE, "w") as f: json.dump(list(processed), f)
            
            # --- NEW v7.2 ACTION: Generate Enterprise Whitepaper PDF ---
            if risk_score >= 7.0:
                pdf_filename = f"CDB-ADVISORY-{int(time.time())}.pdf"
                pdf_path = pdf_engine.create_report(headline, risk_score, extracted_iocs, mitre_context, pdf_filename)
                logger.info(f"✓ PDF WHITEPAPER CREATED: {pdf_path}")

            # STIX 2.1 Sync
            stix_exporter.create_bundle(headline, extracted_iocs, risk_score, enriched_metadata, mitre_data=mitre_context)
            send_sentinel_alert(headline, risk_score, post_url)

    except Exception as e:
        logger.critical(f"APEX BEAST MODE CRASH: {e}")
        raise

if __name__ == "__main__":
    main()
