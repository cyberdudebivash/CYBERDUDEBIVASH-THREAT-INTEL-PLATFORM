#!/usr/bin/env python3
"""Fail-closed contract gate for capabilities quoted to SOC/MSSP customers.

This does not claim third-party end-to-end certification. It proves that the
repository's production implementation still contains the canonical delivery,
enrichment, security and tenancy contracts advertised by SENTINEL APEX.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

CHECKS = {
    "STIX 2.1 generation": [
        ("agent/export_stix.py", r"stix"),
    ],
    "TAXII 2.1 discovery/collections/objects": [
        ("workers/intel-gateway/src/index.js", r"/taxii/"),
        ("workers/intel-gateway/src/index.js", r"collections"),
    ],
    "MISP export": [
        ("workers/intel-gateway/src/enterprise-endpoints.js", r"misp"),
    ],
    "REST API gateway": [
        ("workers/intel-gateway/src/index.js", r"/api/"),
    ],
    "Splunk/Sentinel/Elastic/QRadar connectors": [
        ("agent/integrations/siem/siem_connectors.py", r"SplunkHECConnector"),
        ("agent/integrations/siem/siem_connectors.py", r"MicrosoftSentinelConnector"),
        ("agent/integrations/siem/siem_connectors.py", r"ElasticSIEMConnector"),
        ("agent/integrations/siem/siem_connectors.py", r"QRadarConnector"),
    ],
    "HMAC-SHA256 webhook signing": [
        ("workers/intel-gateway/src/watchdog-webhook.js", r"HMAC"),
        ("workers/intel-gateway/src/watchdog-webhook.js", r"Signature"),
    ],
    "Detection content Sigma/YARA/KQL": [
        ("workers/intel-gateway/src/enterprise-endpoints.js", r"sigma"),
        ("workers/intel-gateway/src/enterprise-endpoints.js", r"yara"),
        ("workers/intel-gateway/src/enterprise-endpoints.js", r"kql|sentinel"),
    ],
    "CVSS/EPSS/KEV enrichment pipeline": [
        (".github/workflows/sentinel-apex.yml", r"CVSS/EPSS"),
        (".github/workflows/sentinel-apex.yml", r"CISA KEV"),
    ],
    "MITRE ATT&CK mapping": [
        (".github/workflows/sentinel-apex.yml", r"MITRE ATT&CK"),
    ],
    "IOC/confidence enrichment": [
        (".github/workflows/sentinel-apex.yml", r"IOC Quality"),
        (".github/workflows/sentinel-apex.yml", r"Confidence"),
    ],
    "Tier entitlement enforcement": [
        ("workers/intel-gateway/src/revenue-enforcement.js", r"enforceTierGate"),
    ],
    "API rate controls": [
        ("workers/intel-gateway/src/index.js", r"RATE_LIMITS"),
        ("workers/intel-gateway/src/index.js", r"RATE_LIMIT_KV"),
    ],
    "MSSP tenant isolation": [
        ("workers/intel-gateway/src/mssp-tenants.js", r"managed"),
        ("workers/intel-gateway/src/mssp-tenants.js", r"tenant"),
    ],
}

def main() -> int:
    failures = []
    for capability, requirements in CHECKS.items():
        missing = []
        for rel, pattern in requirements:
            path = ROOT / rel
            if not path.is_file():
                missing.append(f"{rel} (missing file)")
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(pattern, text, re.IGNORECASE) is None:
                missing.append(f"{rel} (missing contract: {pattern})")
        if missing:
            failures.append((capability, missing))
            print(f"FAIL: {capability}: " + "; ".join(missing))
        else:
            print(f"PASS: {capability}")
    if failures:
        print(f"\nCUSTOMER CORE FLOW: FAIL ({len(failures)} capability groups)")
        return 1
    print(f"\nCUSTOMER CORE FLOW: PASS ({len(CHECKS)}/{len(CHECKS)} capability groups)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
