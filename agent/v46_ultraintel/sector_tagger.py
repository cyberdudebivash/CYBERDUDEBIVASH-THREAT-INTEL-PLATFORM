#!/usr/bin/env python3
"""
sector_tagger.py — CyberDudeBivash v46.0 (SENTINEL APEX ULTRA INTEL)
28-sector industry impact classification engine.
Uses title/CVE/keyword signals to tag affected industry verticals.

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("CDB-SECTOR-TAGGER-V46")

# ── 28-SECTOR TAXONOMY with keywords ────────────────────────────────────────
SECTOR_DEFINITIONS: Dict[str, Dict] = {
    "Healthcare": {
        "icon": "🏥",
        "keywords": ["hospital", "healthcare", "medical", "patient", "ehr", "hipaa",
                     "clinical", "pharmacy", "health system", "medicare", "medicat",
                     "medical device", "biosig", "epic systems"],
        "priority": "CRITICAL",
    },
    "Finance": {
        "icon": "🏦",
        "keywords": ["bank", "financial", "fintech", "payment", "swift", "trading",
                     "stock", "forex", "cryptocurrency", "bitcoin", "wallet",
                     "credit card", "atm", "pos terminal", "fastcash", "carbanak",
                     "sap", "s/4hana", "sap hana", "erp finance"],
        "priority": "CRITICAL",
    },
    "Critical Infrastructure": {
        "icon": "⚡",
        "keywords": ["critical infrastructure", "power grid", "utility", "water treatment",
                     "oil", "gas", "pipeline", "energy sector", "scada", "ics",
                     "operational technology", "ot environment", "industrial control",
                     "electricity", "nuclear", "dam"],
        "priority": "CRITICAL",
    },
    "Government": {
        "icon": "🏛️",
        "keywords": ["government", "federal", "ministry", "department of", "nato",
                     "military", "defense contractor", "intelligence agency", "dhs",
                     "cisa", "senate", "parliament", "election", "voting system"],
        "priority": "HIGH",
    },
    "Defense": {
        "icon": "🛡️",
        "keywords": ["defense", "military", "aerospace", "contractor", "weapon",
                     "dod", "pentagon", "navy", "army", "air force", "missile"],
        "priority": "HIGH",
    },
    "Technology": {
        "icon": "💻",
        "keywords": ["software", "saas", "cloud provider", "tech company", "platform",
                     "developer", "api", "github", "npm", "pypi", "open source",
                     "microsoft", "google", "apple", "amazon", "meta", "adobe"],
        "priority": "HIGH",
    },
    "Telecommunications": {
        "icon": "📡",
        "keywords": ["telecom", "telecommunications", "carrier", "5g", "network provider",
                     "isp", "mobile network", "cell tower", "wireline"],
        "priority": "HIGH",
    },
    "Education": {
        "icon": "🎓",
        "keywords": ["university", "school", "college", "education", "academic",
                     "student", "k-12", "campus", "learning management"],
        "priority": "MEDIUM",
    },
    "Retail & E-Commerce": {
        "icon": "🛒",
        "keywords": ["retail", "e-commerce", "ecommerce", "shop", "store", "shopify",
                     "woocommerce", "magento", "payment gateway", "pos"],
        "priority": "MEDIUM",
    },
    "Manufacturing": {
        "icon": "🏭",
        "keywords": ["manufacturing", "factory", "production", "industrial",
                     "scada", "plc", "industrial iot", "supply chain manufacturing"],
        "priority": "HIGH",
    },
    "Legal & Professional Services": {
        "icon": "⚖️",
        "keywords": ["law firm", "legal", "attorney", "accountant", "consulting",
                     "professional services", "compliance"],
        "priority": "MEDIUM",
    },
    "Media & Entertainment": {
        "icon": "📺",
        "keywords": ["media", "news", "broadcasting", "entertainment", "streaming",
                     "game", "gaming", "studio"],
        "priority": "MEDIUM",
    },
    "Transportation & Logistics": {
        "icon": "🚢",
        "keywords": ["aviation", "airline", "maritime", "shipping", "logistics",
                     "freight", "port", "rail", "transportation"],
        "priority": "HIGH",
    },
    "Hospitality & Travel": {
        "icon": "🏨",
        "keywords": ["hotel", "hospitality", "travel", "reservation", "booking",
                     "resort", "restaurant chain"],
        "priority": "MEDIUM",
    },
    "Insurance": {
        "icon": "📋",
        "keywords": ["insurance", "insurer", "actuarial", "underwriting", "claims"],
        "priority": "MEDIUM",
    },
    "Pharmaceutical": {
        "icon": "💊",
        "keywords": ["pharma", "pharmaceutical", "drug", "biotech", "clinical trial",
                     "fda", "research laboratory"],
        "priority": "HIGH",
    },
    "Research & Academia": {
        "icon": "🔬",
        "keywords": ["research", "laboratory", "think tank", "academic research",
                     "ngo", "nonprofit", "foundation"],
        "priority": "MEDIUM",
    },
    "Web Applications": {
        "icon": "🌐",
        "keywords": ["web application", "web app", "cms", "wordpress", "drupal",
                     "joomla", "django", "ruby on rails", "php application",
                     "expressjs", "nextjs", "web portal"],
        "priority": "MEDIUM",
    },
    "IoT / Embedded": {
        "icon": "📱",
        "keywords": ["iot", "embedded", "router", "modem", "smart device",
                     "firmware", "ip camera", "nas", "network device", "set-top box",
                     "android tv", "tenda", "utt hiper", "d-link", "tp-link", "zyxel"],
        "priority": "MEDIUM",
    },
    "Cloud & Virtualization": {
        "icon": "☁️",
        "keywords": ["cloud", "aws", "azure", "gcp", "kubernetes", "docker",
                     "container", "vm", "virtual machine", "hypervisor", "saas platform"],
        "priority": "HIGH",
    },
    "MSP / MSSP": {
        "icon": "🔧",
        "keywords": ["managed service", "msp", "mssp", "remote monitoring",
                     "rmm", "beyondtrust", "connectwise", "kaseya", "solarwinds"],
        "priority": "CRITICAL",
    },
    "Open Source Software": {
        "icon": "🔓",
        "keywords": ["open source", "npm package", "pypi", "github", "gitlab",
                     "imagemagick", "389-ds", "openssl", "apache", "nginx", "linux",
                     "hummerrisk", "pimcore", "muyucms", "datalinkdc"],
        "priority": "MEDIUM",
    },
    "Document Management": {
        "icon": "📁",
        "keywords": ["document management", "file management", "cms document",
                     "itsourcecode", "sourcecodester"],
        "priority": "LOW",
    },
    "Security Tools": {
        "icon": "🔒",
        "keywords": ["security tool", "siem", "edr", "antivirus", "firewall",
                     "vpn", "soc", "crowdstrike", "sentinel", "splunk", "qradar"],
        "priority": "HIGH",
    },
    "Database": {
        "icon": "🗄️",
        "keywords": ["database", "sql server", "mysql", "postgresql", "mongodb",
                     "redis", "elasticsearch", "oracle db", "sqlite"],
        "priority": "HIGH",
    },
    "Email & Collaboration": {
        "icon": "📧",
        "keywords": ["email", "outlook", "exchange", "sharepoint", "teams",
                     "slack", "office365", "mail server", "smtp"],
        "priority": "HIGH",
    },
    "Identity & Access": {
        "icon": "🔑",
        "keywords": ["identity", "iam", "okta", "active directory", "ldap",
                     "sso", "oauth", "saml", "mfa", "privilege escalation",
                     "authentication bypass"],
        "priority": "CRITICAL",
    },
    "Supply Chain": {
        "icon": "🔗",
        "keywords": ["supply chain", "third party", "vendor", "upstream",
                     "build pipeline", "ci/cd", "devops", "software supply"],
        "priority": "CRITICAL",
    },
}

# Priority ordering for display (top 3)
_PRIORITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class SectorTaggerV46:
    """
    28-sector industry impact tagger.
    Analyzes item title + CVE description + MITRE tactics to tag affected sectors.
    Returns top 3 most-relevant sectors with confidence scores.
    """

    def __init__(self):
        self._sectors = SECTOR_DEFINITIONS

    def _build_corpus(self, item: Dict) -> str:
        parts = [
            item.get("title", ""),
            str(item.get("extended_metrics", {}).get("description", "")),
            item.get("feed_source", ""),
            " ".join(item.get("mitre_tactics", [])),
        ]
        return " ".join(parts).lower()

    def tag_sectors(self, item: Dict) -> List[Dict]:
        """
        Tag item with affected sectors.
        Returns list of dicts sorted by relevance score (max 5).
        """
        corpus = self._build_corpus(item)
        scores: List[Tuple[str, float, Dict]] = []

        for sector_name, sector_def in self._sectors.items():
            score = 0.0
            for kw in sector_def["keywords"]:
                if kw in corpus:
                    # Longer keyword = more specific = higher score
                    score += 1.0 + (len(kw) / 20.0)
            if score > 0:
                scores.append((sector_name, score, sector_def))

        # Sort by score descending, then by priority
        scores.sort(key=lambda x: (x[1], _PRIORITY_ORDER.get(x[2]["priority"], 0)), reverse=True)

        result = []
        for sector_name, score, sector_def in scores[:5]:
            result.append({
                "sector": sector_name,
                "icon": sector_def["icon"],
                "priority": sector_def["priority"],
                "confidence": round(min(score / 5.0, 1.0), 2),
            })

        # Fallback: no match → Web Applications (generic)
        if not result:
            fallback = self._sectors["Web Applications"]
            result = [{
                "sector": "Web Applications",
                "icon": fallback["icon"],
                "priority": fallback["priority"],
                "confidence": 0.1,
            }]

        return result

    def enrich_item(self, item: Dict) -> Dict:
        """Enrich manifest item with sector_tags field."""
        item["sector_tags"] = self.tag_sectors(item)
        return item

    def batch_enrich(self, items: List[Dict]) -> List[Dict]:
        """Batch enrich a list of manifest items."""
        enriched = []
        for item in items:
            try:
                enriched.append(self.enrich_item(item))
            except Exception as e:
                logger.warning(f"Sector tagging failed for item: {e}")
                item.setdefault("sector_tags", [])
                enriched.append(item)
        return enriched


sector_tagger_v46 = SectorTaggerV46()
