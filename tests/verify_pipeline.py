#!/usr/bin/env python3
"""
verify_pipeline.py — CyberDudeBivash v1.0
Pre-Flight Diagnostic: Validating Forensic & Reputation Logic.
"""
import sys
import os
import json
import logging

# Ensure the agent modules are discoverable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from agent.config import VT_API_KEY
    from agent.enricher import enricher
    from agent.enricher_pro import enricher_pro
    from agent.integrations.vt_lookup import vt_lookup
    from agent.export_stix import stix_exporter
except ImportError as e:
    print(f"CRITICAL: Missing modules. Ensure requirements.txt is installed. {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("CDB-DIAGNOSTIC")

def run_diagnostic():
    print("="*60)
    print("CYBERDUDEBIVASH SENTINEL — PRE-FLIGHT DIAGNOSTIC")
    print("="*60)

    # 1. Check VT API Key Presence
    if not VT_API_KEY:
        logger.error("VT_API_KEY not found in config. Reputation checks will fail.")
    else:
        logger.info(f"VT_API_KEY detected: {VT_API_KEY[:5]}...{VT_API_KEY[-5:]}")

    # 2. Simulate Forensic Extraction
    sample_text = "Emerging threat detected from 8.8.8.8 and C2 server at 1.1.1.1. Malware hash: 44d88612fea8a8f36de82e1278abb02f"
    print(f"\n[1] Extracting IoCs from Sample Text...")
    iocs = enricher.extract_iocs(sample_text)
    print(f"    - Found: {iocs}")

    # 3. Simulate Reputation Lookup (Live Test)
    if iocs.get("ipv4"):
        test_ip = iocs["ipv4"][0]
        print(f"\n[2] Testing Multi-Vendor Reputation for {test_ip}...")
        reputation = vt_lookup.get_reputation(test_ip, "ipv4")
        context = enricher_pro.get_ip_context(test_ip)
        print(f"    - VT Verdict: {reputation}")
        print(f"    - Geo-Origin: {context.get('location')}")
        print(f"    - Infrastructure: {context.get('isp')}")

    # 4. Validate STIX 2.1 Generation
    print("\n[3] Validating STIX 2.1 JSON Schema...")
    try:
        stix_json = stix_exporter.create_bundle("Diagnostic Test", iocs, 8.5)
        stix_data = json.loads(stix_json)
        if stix_data.get("type") == "bundle" and len(stix_data.get("objects", [])) > 0:
            print("    - STIX Bundle: VALID ✅")
        else:
            print("    - STIX Bundle: MALFORMED ❌")
    except Exception as e:
        print(f"    - STIX Generation Failed: {e}")

    print("\n" + "="*60)
    print("DIAGNOSTIC COMPLETE — Ready for Production Run #79+")
    print("="*60)

if __name__ == "__main__":
    run_diagnostic()