"""
CYBERDUDEBIVASH® SENTINEL APEX v60.0 — Incident Intelligence Engine
====================================================================
Converts threat intelligence records into structured security incidents.
Correlates IOCs, maps MITRE ATT&CK, assigns severity, and generates
incident records for SOC consumption.

Input:  data/stix/feed_manifest.json
Output: data/incidents/incidents.json

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [INCIDENT-ENGINE] %(levelname)s %(message)s")
logger = logging.getLogger("v60_incident_engine")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"
OUTPUT_DIR = BASE_DIR / "data" / "incidents"
OUTPUT_FILE = OUTPUT_DIR / "incidents.json"

SEVERITY_MAP = {
    (9, 11): "CRITICAL",
    (7, 9):  "HIGH",
    (4, 7):  "MEDIUM",
    (0, 4):  "LOW",
}

ASSET_CATEGORIES = {
    "cloud": ["aws", "azure", "gcp", "s3", "blob", "cloud", "saas"],
    "network": ["firewall", "router", "vpn", "proxy", "dns", "ssl", "tls"],
    "endpoint": ["windows", "linux", "macos", "workstation", "laptop", "server"],
    "identity": ["active directory", "ldap", "sso", "oauth", "credential", "password", "mfa"],
    "application": ["web", "api", "database", "sql", "apache", "nginx", "iis"],
    "iot_ics": ["ics", "scada", "plc", "ot", "iot", "siemens", "schneider", "trane"],
    "mobile": ["android", "ios", "mobile", "apk", "app store"],
    "email": ["phishing", "email", "smtp", "spear", "bec"],
}

def classify_severity(risk_score: float) -> str:
    for (low, high), label in SEVERITY_MAP.items():
        if low <= risk_score < high:
            return label
    return "CRITICAL" if risk_score >= 9 else "LOW"

def identify_affected_assets(title: str, content: str = "") -> List[str]:
    combined = (title + " " + content).lower()
    assets = []
    for category, keywords in ASSET_CATEGORIES.items():
        if any(kw in combined for kw in keywords):
            assets.append(category)
    return assets or ["general_infrastructure"]

def generate_incident_id(title: str, timestamp: str) -> str:
    raw = f"{title}:{timestamp}"
    return f"INC-{hashlib.sha256(raw.encode()).hexdigest()[:12].upper()}"

def correlate_incidents(intel_records: List[Dict]) -> List[Dict]:
    """Convert threat intelligence records into structured incidents."""
    incidents = []
    seen_titles = set()

    for record in intel_records:
        title = record.get("title", "")
        if not title or title in seen_titles:
            continue
        seen_titles.add(title)

        risk_score = record.get("risk_score", 0)
        timestamp = record.get("timestamp", datetime.now(timezone.utc).isoformat())
        mitre = record.get("mitre_tactics", [])
        actor = record.get("actor_tag", "UNC-CDB-UNKNOWN")
        confidence = record.get("confidence_score", record.get("confidence", 50))
        source_url = record.get("source_url", "")
        ioc_counts = record.get("ioc_counts", {})

        total_iocs = sum(
            v if isinstance(v, int) else len(v) if isinstance(v, list) else 0
            for v in ioc_counts.values()
        )

        severity = classify_severity(risk_score)
        affected = identify_affected_assets(title, source_url)
        incident_id = generate_incident_id(title, timestamp)

        incident = {
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "risk_score": risk_score,
            "confidence": round(float(confidence), 1),
            "threat_actor": actor,
            "mitre_techniques": mitre,
            "affected_assets": affected,
            "ioc_count": total_iocs,
            "ioc_breakdown": ioc_counts,
            "source_url": source_url,
            "stix_id": record.get("stix_id", ""),
            "kev_present": record.get("kev_present", False),
            "cvss_score": record.get("cvss_score"),
            "epss_score": record.get("epss_score"),
            "tlp_label": record.get("tlp_label", "TLP:CLEAR"),
            "status": "NEW",
            "created_at": timestamp,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        incidents.append(incident)

    incidents.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return incidents


def run():
    """Execute the Incident Intelligence Engine."""
    logger.info("=" * 60)
    logger.info("  SENTINEL APEX v60.0 — Incident Intelligence Engine")
    logger.info("=" * 60)

    if not MANIFEST_PATH.exists():
        logger.error(f"Manifest not found: {MANIFEST_PATH}")
        return {"status": "error", "incidents": 0}

    with open(MANIFEST_PATH) as f:
        data = json.load(f)
    records = data if isinstance(data, list) else data.get("entries", [])
    logger.info(f"Loaded {len(records)} intel records")

    incidents = correlate_incidents(records)

    critical = sum(1 for i in incidents if i["severity"] == "CRITICAL")
    high = sum(1 for i in incidents if i["severity"] == "HIGH")
    actors = len(set(i["threat_actor"] for i in incidents))

    output = {
        "engine": "v60_incident_engine",
        "version": "60.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_incidents": len(incidents),
        "severity_breakdown": {
            "CRITICAL": critical,
            "HIGH": high,
            "MEDIUM": sum(1 for i in incidents if i["severity"] == "MEDIUM"),
            "LOW": sum(1 for i in incidents if i["severity"] == "LOW"),
        },
        "unique_actors": actors,
        "incidents": incidents,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    logger.info(f"✅ {len(incidents)} incidents generated (CRIT:{critical} HIGH:{high} Actors:{actors})")
    logger.info(f"   Output: {OUTPUT_FILE}")
    return output


if __name__ == "__main__":
    result = run()
    print(json.dumps({"incidents": result["total_incidents"], "status": "OK"}, indent=2))
