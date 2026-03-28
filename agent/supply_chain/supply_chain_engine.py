"""
CYBERDUDEBIVASH® SENTINEL APEX — SUPPLY CHAIN SECURITY ENGINE v1.0
Dependency monitoring, CVE matching, CI/CD security analysis.
"""
import re, logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-SUPPLY-CHAIN")

KNOWN_COMPROMISED_PACKAGES = [
    "event-stream", "flatmap-stream", "ua-parser-js", "coa", "rc",
    "node-ipc", "colors", "faker", "xz-utils", "polyfill.io",
    "bootstrap-sass", "rest-client", "jquery-ujs", "tzinfo",
]

RISKY_DEPENDENCY_PATTERNS = [
    r"typosquat",
    r"install\s+script",
    r"postinstall",
    r"preinstall",
    r"curl.*sh",
    r"wget.*sh",
    r"eval\(",
]


class SupplyChainEngine:
    """Monitors dependencies and detects supply chain threats."""

    def __init__(self):
        self.scans_done = 0

    def scan_advisory_for_supply_chain(self, advisory: Dict) -> Dict:
        """Detect supply chain indicators in a threat advisory."""
        text = f"{advisory.get('title','')} {advisory.get('summary','')}".lower()
        ttps = advisory.get("mitre_techniques", [])

        indicators = []
        risk_level = "LOW"

        # TTP-based detection
        if "T1195" in ttps:
            indicators.append({"type": "TTP", "value": "T1195 — Supply Chain Compromise detected"})
            risk_level = "CRITICAL"
        if "T1199" in ttps:
            indicators.append({"type": "TTP", "value": "T1199 — Trusted Relationship abuse"})
            risk_level = "HIGH" if risk_level == "LOW" else risk_level

        # Text-based detection
        for pkg in KNOWN_COMPROMISED_PACKAGES:
            if pkg in text:
                indicators.append({"type": "COMPROMISED_PACKAGE", "value": pkg})
                risk_level = "CRITICAL"

        supply_chain_keywords = [
            "supply chain", "dependency", "package", "npm", "pypi", "rubygems",
            "maven", "nuget", "third-party", "vendor", "open source", "sbom",
        ]
        keyword_hits = [kw for kw in supply_chain_keywords if kw in text]
        if keyword_hits:
            indicators.append({"type": "KEYWORDS", "value": keyword_hits})
            if risk_level == "LOW":
                risk_level = "MEDIUM"

        is_supply_chain = len(indicators) > 0
        self.scans_done += 1

        return {
            "advisory_id":           advisory.get("stix_id", ""),
            "is_supply_chain_threat": is_supply_chain,
            "risk_level":            risk_level,
            "indicators":            indicators,
            "affected_ecosystems":   self._detect_ecosystems(text),
            "remediation_steps": [
                "Run SCA scan on all repositories",
                "Pin dependency versions in lockfiles",
                "Enable dependency review in CI/CD",
                "Subscribe to package security advisories",
                "Implement SBOM generation in build pipeline",
            ] if is_supply_chain else [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def _detect_ecosystems(self, text: str) -> List[str]:
        ecosystem_map = {
            "npm": ["npm", "node_modules", "package.json"],
            "pypi": ["pypi", "pip", "requirements.txt", "setup.py"],
            "maven": ["maven", "pom.xml", "gradle"],
            "rubygems": ["gem", "gemfile", "rubygems"],
            "nuget": ["nuget", ".csproj", "packages.config"],
        }
        return [eco for eco, kws in ecosystem_map.items() if any(k in text for k in kws)]

    def get_stats(self) -> Dict:
        return {"scans_done": self.scans_done, "engine": "SupplyChainEngine v1.0"}
