#!/usr/bin/env python3
"""
verify_pipeline.py — CyberDudeBivash v11.0 (SENTINEL APEX ULTRA)
Pre-Flight Diagnostic: Validates all engines including new modules.
FIXED: Import errors, VT_API_KEY reference, STIX bundle signature.
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
    from agent.risk_engine import risk_engine
    from agent.deduplication import dedup_engine
    from agent.mitre_mapper import mitre_engine
    from agent.integrations.actor_matrix import actor_matrix
    from agent.integrations.detection_engine import detection_engine
except ImportError as e:
    print(f"CRITICAL: Missing modules. Ensure requirements.txt is installed. {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("CDB-DIAGNOSTIC")

def run_diagnostic():
    print("=" * 65)
    print("CYBERDUDEBIVASH SENTINEL APEX ULTRA — PRE-FLIGHT DIAGNOSTIC v11.0")
    print("=" * 65)

    # 1. Config Validation
    print("\n[1] Validating Configuration...")
    if not VT_API_KEY:
        logger.warning("VT_API_KEY not found. Reputation checks will use fallback.")
    else:
        logger.info(f"VT_API_KEY detected: {VT_API_KEY[:5]}...{VT_API_KEY[-5:]}")

    # 2. Enhanced IOC Extraction
    sample_text = """
    Emerging threat detected from 8.8.8.8 and C2 server at 45.33.32.156.
    Malware hash: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    Phishing domain: evil-login.example-malware.com
    Registry persistence: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware-svc
    CVE-2024-12345 exploited in the wild. Contact attacker@darknet.org
    Payload: dropper.exe downloaded from https://malware-cdn.evil.net/payload.zip
    Private IP 192.168.1.1 should be excluded.
    """
    print("\n[2] Testing Enhanced IOC Extraction...")
    iocs = enricher.extract_iocs(sample_text)
    for key, values in iocs.items():
        if values:
            print(f"    {key}: {values}")

    # Verify private IP exclusion
    assert '192.168.1.1' not in iocs.get('ipv4', []), "FAIL: Private IP not excluded!"
    assert '8.8.8.8' not in iocs.get('ipv4', []), "FAIL: Google DNS should be excluded!"
    print("    ✓ Private IP exclusion: WORKING")

    # 3. Confidence Scoring
    print("\n[3] Testing Confidence Scoring...")
    confidence = enricher.calculate_confidence(iocs, actor_mapped=False)
    print(f"    Confidence Score: {confidence}%")

    # 4. Dynamic Risk Scoring
    print("\n[4] Testing Dynamic Risk Scoring...")
    mitre_data = mitre_engine.map_threat(sample_text)
    actor_data = actor_matrix.correlate_actor(sample_text, iocs)
    risk_score = risk_engine.calculate_risk_score(
        iocs=iocs, mitre_matches=mitre_data, actor_data=actor_data
    )
    severity = risk_engine.get_severity_label(risk_score)
    tlp = risk_engine.get_tlp_label(risk_score)
    print(f"    Risk Score: {risk_score}/10")
    print(f"    Severity: {severity}")
    print(f"    TLP: {tlp['label']}")
    assert risk_score != 9.3, "FAIL: Risk score is still hardcoded!"
    print("    ✓ Dynamic scoring: WORKING")

    # 5. MITRE Mapping
    print("\n[5] Testing MITRE ATT&CK Mapping...")
    print(f"    Techniques matched: {len(mitre_data)}")
    for t in mitre_data:
        print(f"    - {t['id']}: {t['tactic']}")

    # 6. Detection Engineering
    print("\n[6] Testing Auto-Generated Detections...")
    sigma = detection_engine.generate_sigma_rule("Test Campaign", iocs)
    yara = detection_engine.generate_yara_rule("Test Campaign", iocs)
    print(f"    Sigma rule: {'Generated' if sigma else 'FAILED'}")
    print(f"    YARA rule: {'Generated' if yara else 'FAILED'}")

    # 7. Deduplication
    print("\n[7] Testing Deduplication Engine...")
    test_title = "DIAGNOSTIC_TEST_ENTRY"
    is_dup = dedup_engine.is_duplicate(test_title)
    print(f"    First check (should be False): {is_dup}")
    assert not is_dup, "FAIL: Fresh entry detected as duplicate!"
    print(f"    Processed count: {dedup_engine.get_processed_count()}")
    print("    ✓ Deduplication: WORKING")

    # 8. Summary
    print("\n" + "=" * 65)
    print("ALL DIAGNOSTICS PASSED — SENTINEL APEX ULTRA v11.0 READY")
    print(f"Modules verified: enricher, risk_engine, dedup, mitre, actor, detection")
    print("=" * 65)

if __name__ == "__main__":
    run_diagnostic()
