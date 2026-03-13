"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Bug Hunter Data Models
==============================================================
SQLModel-based schemas for recon persistence.
Isolated from core Sentinel APEX data layer.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

logger = logging.getLogger("CDB-BH-MODELS")

# ══════════════════════════════════════════════════════════════
# DATA DIRECTORY
# ══════════════════════════════════════════════════════════════

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "bughunter")


def _ensure_dirs():
    for sub in ["scans", "reports", "exports", "logs"]:
        path = os.path.join(_DATA_DIR, sub)
        os.makedirs(path, exist_ok=True)


# ══════════════════════════════════════════════════════════════
# SCAN RECORD
# ══════════════════════════════════════════════════════════════

class BugHunterScan:
    """Represents a completed recon scan session."""

    def __init__(self, domain: str, scan_id: Optional[str] = None):
        self.scan_id = scan_id or f"BH-{int(datetime.now(timezone.utc).timestamp())}"
        self.domain = domain
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.status = "INITIALIZED"
        self.critical_count = 0
        self.subdomains: List[str] = []
        self.live_hosts: List[Dict] = []
        self.api_endpoints: List[str] = []
        self.findings: List[Dict] = []
        self.assets: List[Dict] = []
        self.duration_seconds: float = 0.0

    def add_finding(self, finding: Dict[str, Any]):
        finding["scan_id"] = self.scan_id
        finding["detected_at"] = datetime.now(timezone.utc).isoformat()
        self.findings.append(finding)
        if finding.get("severity") == "CRITICAL":
            self.critical_count += 1

    def add_asset(self, hostname: str, ip: Optional[str] = None,
                  technologies: Optional[List[str]] = None):
        self.assets.append({
            "hostname": hostname,
            "ip_address": ip,
            "technologies": technologies or [],
            "last_seen": datetime.now(timezone.utc).isoformat(),
        })

    def finalize(self, status: str = "COMPLETED", duration: float = 0.0):
        self.status = status
        self.duration_seconds = duration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "domain": self.domain,
            "timestamp": self.timestamp,
            "status": self.status,
            "critical_count": self.critical_count,
            "subdomain_count": len(self.subdomains),
            "live_host_count": len(self.live_hosts),
            "api_endpoint_count": len(self.api_endpoints),
            "finding_count": len(self.findings),
            "asset_count": len(self.assets),
            "duration_seconds": self.duration_seconds,
            "findings": self.findings,
            "assets": self.assets,
        }

    def save(self):
        """Persist scan results to JSON file in data/bughunter/scans/."""
        _ensure_dirs()
        filename = f"{self.scan_id}_{self.domain.replace('.', '_')}.json"
        filepath = os.path.join(_DATA_DIR, "scans", filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, default=str)
            logger.info(f"[BH-SAVE] Scan persisted: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"[BH-SAVE] Failed to persist scan: {e}")
            return None


# ══════════════════════════════════════════════════════════════
# VULNERABILITY FINDING
# ══════════════════════════════════════════════════════════════

class BugHunterFinding:
    """Standardized vulnerability finding record."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2,
        "INFO": 1,
    }

    def __init__(self, finding_type: str, target: str, severity: str = "HIGH",
                 evidence: Optional[str] = None, impact: Optional[str] = None):
        self.type = finding_type
        self.target = target
        self.severity = severity.upper()
        self.evidence = evidence
        self.impact = impact or self._default_impact()
        self.detected_at = datetime.now(timezone.utc).isoformat()

    def _default_impact(self) -> str:
        impacts = {
            "BOLA": "Unauthorized access to user-specific data via IDOR",
            "CLOUD_LEAK": "Sensitive data exposure in misconfigured cloud storage",
            "SUBDOMAIN_TAKEOVER": "Domain hijacking via dangling CNAME records",
            "OPEN_PORT": "Exposed service increasing attack surface",
            "SECRET_LEAK": "Hardcoded credentials or API keys in client-side code",
        }
        return impacts.get(self.type, "Security vulnerability detected")

    @property
    def risk_weight(self) -> int:
        return self.SEVERITY_WEIGHTS.get(self.severity, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "target": self.target,
            "severity": self.severity,
            "evidence": self.evidence,
            "impact": self.impact,
            "risk_weight": self.risk_weight,
            "detected_at": self.detected_at,
        }

    def to_stix_indicator(self) -> Dict[str, Any]:
        """Convert to a STIX 2.1–compatible indicator stub for Sentinel APEX."""
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "name": f"CDB-BH-{self.type}: {self.target}",
            "description": self.impact,
            "pattern_type": "stix",
            "pattern": f"[domain-name:value = '{self.target}']",
            "valid_from": self.detected_at,
            "labels": [self.severity.lower(), "bug-hunter"],
            "created_by_ref": "identity--cyberdudebivash-sentinel-apex",
            "confidence": self.risk_weight * 10,
        }
