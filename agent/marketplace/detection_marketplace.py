#!/usr/bin/env python3
"""
detection_marketplace.py — CYBERDUDEBIVASH® SENTINEL APEX v24.0
Detection Rule Marketplace Module.

Non-Breaking Addition: Standalone marketplace catalog module.
Manages, packages, and prices detection rule packs for sale.

Features:
    - Detection pack catalog management
    - Industry-specific rule bundles
    - Pack versioning and signing
    - Revenue tracking per pack
    - Gumroad integration for product listing

Author: CyberDudeBivash Pvt. Ltd.
"""

import json
import os
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger("CDB-Marketplace")
VERSION = "1.0.0"

CATALOG_PATH = "data/marketplace/catalog.json"
PACKS_DIR    = "data/marketplace/packs"


class DetectionPack:
    """Represents a packaged detection rule bundle for sale."""

    def __init__(
        self,
        pack_id: str,
        name: str,
        description: str,
        price_usd: float,
        tier: str = "PRO",
        industry: Optional[str] = None,
    ):
        self.pack_id     = pack_id
        self.name        = name
        self.description = description
        self.price_usd   = price_usd
        self.tier        = tier
        self.industry    = industry
        self.rules       = {
            "sigma":    [],
            "yara":     [],
            "kql":      [],
            "spl":      [],
            "suricata": [],
            "eql":      [],
        }
        self.metadata = {
            "version":      "1.0.0",
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "updated_at":   datetime.now(timezone.utc).isoformat(),
            "rule_count":   0,
            "downloads":    0,
            "rating":       0.0,
            "reviews":      0,
            "tags":         [],
            "cve_coverage": [],
            "mitre_coverage": [],
        }

    def add_sigma_rule(self, rule: str, rule_id: Optional[str] = None):
        self.rules["sigma"].append({"id": rule_id or f"sigma-{len(self.rules['sigma'])+1}", "content": rule})
        self._update_count()

    def add_yara_rule(self, rule: str, rule_name: Optional[str] = None):
        self.rules["yara"].append({"name": rule_name or f"yara_{len(self.rules['yara'])+1}", "content": rule})
        self._update_count()

    def add_kql_query(self, query: str, description: str = ""):
        self.rules["kql"].append({"description": description, "query": query})
        self._update_count()

    def add_spl_query(self, query: str, description: str = ""):
        self.rules["spl"].append({"description": description, "query": query})
        self._update_count()

    def add_suricata_rule(self, rule: str, rule_id: Optional[str] = None):
        self.rules["suricata"].append({"id": rule_id, "content": rule})
        self._update_count()

    def _update_count(self):
        self.metadata["rule_count"] = sum(len(v) for v in self.rules.values())
        self.metadata["updated_at"] = datetime.now(timezone.utc).isoformat()

    def compute_hash(self) -> str:
        content = json.dumps(self.rules, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_catalog_entry(self) -> Dict:
        return {
            "pack_id":        self.pack_id,
            "name":           self.name,
            "description":    self.description,
            "price_usd":      self.price_usd,
            "tier":           self.tier,
            "industry":       self.industry,
            "rule_count":     self.metadata["rule_count"],
            "rule_types":     {k: len(v) for k, v in self.rules.items() if v},
            "tags":           self.metadata.get("tags", []),
            "cve_coverage":   self.metadata.get("cve_coverage", []),
            "mitre_coverage": self.metadata.get("mitre_coverage", []),
            "version":        self.metadata["version"],
            "downloads":      self.metadata["downloads"],
            "rating":         self.metadata["rating"],
            "reviews":        self.metadata["reviews"],
            "created_at":     self.metadata["created_at"],
            "updated_at":     self.metadata["updated_at"],
            "hash":           self.compute_hash(),
        }

    def export_pack(self, output_dir: str = PACKS_DIR) -> str:
        """Export pack as a signed JSON file."""
        os.makedirs(output_dir, exist_ok=True)
        pack_data = {
            "pack_metadata": self.to_catalog_entry(),
            "rules":         self.rules,
            "signature":     self.compute_hash(),
            "platform":      "CYBERDUDEBIVASH SENTINEL APEX",
            "exported_at":   datetime.now(timezone.utc).isoformat(),
        }
        path = os.path.join(output_dir, f"{self.pack_id}.json")
        with open(path, "w") as f:
            json.dump(pack_data, f, indent=2)
        logger.info(f"Detection pack exported: {path}")
        return path


class DetectionMarketplace:
    """
    Manages the CDB detection rule marketplace catalog.

    Provides:
    - Pack registration and versioning
    - Catalog management
    - Revenue tracking
    - Industry-specific bundles
    """

    # Pre-built marketplace catalog
    BUILT_IN_PACKS = [
        {
            "pack_id":     "cdb-ransomware-defense",
            "name":        "CDB Ransomware Defense Pack",
            "description": "Production-ready detection rules for LockBit, ALPHV/BlackCat, Cl0p, Akira, Royal, and 10+ other active ransomware families. Includes Sigma, YARA, KQL, SPL, and Suricata rules.",
            "price_usd":   29.00,
            "tier":        "PRO",
            "industry":    "all",
            "tags":        ["ransomware", "lockbit", "alphv", "blackcat", "cl0p", "defense"],
            "rule_types":  {"sigma": 25, "yara": 18, "kql": 20, "spl": 20, "suricata": 15},
            "rule_count":  98,
            "mitre_coverage": ["T1486", "T1490", "T1491", "T1489", "T1562"],
        },
        {
            "pack_id":     "cdb-apt-nation-state",
            "name":        "CDB APT / Nation-State Hunting Pack",
            "description": "Elite detection rules for APT28, APT29, APT41, Lazarus Group, Volt Typhoon, Salt Typhoon, and Sandworm. Includes behavioral hunting queries for Sentinel/Splunk/Elastic.",
            "price_usd":   49.00,
            "tier":        "PRO",
            "industry":    "government,critical_infrastructure",
            "tags":        ["apt", "nation-state", "espionage", "apt28", "apt29", "lazarus", "hunting"],
            "rule_types":  {"sigma": 35, "kql": 30, "spl": 30, "eql": 15, "suricata": 10},
            "rule_count":  120,
            "mitre_coverage": ["T1566", "T1059", "T1105", "T1078", "T1021"],
        },
        {
            "pack_id":     "cdb-supply-chain-detection",
            "name":        "CDB Supply Chain Attack Detection Pack",
            "description": "Detect compromised packages, build pipeline poisoning, dependency confusion, and software supply chain attacks. Covers npm, PyPI, GitHub Actions, CI/CD threats.",
            "price_usd":   39.00,
            "tier":        "PRO",
            "industry":    "technology",
            "tags":        ["supply-chain", "npm", "pypi", "cicd", "github-actions", "solarwinds-like"],
            "rule_types":  {"sigma": 20, "yara": 12, "kql": 18, "spl": 18, "suricata": 8},
            "rule_count":  76,
            "mitre_coverage": ["T1195", "T1072", "T1554", "T1601"],
        },
        {
            "pack_id":     "cdb-healthcare-bundle",
            "name":        "CDB Healthcare Security Bundle",
            "description": "HIPAA-aligned detection rules for healthcare organizations. Covers medical device attacks, EHR system threats, healthcare ransomware, and patient data exfiltration.",
            "price_usd":   79.00,
            "tier":        "ENTERPRISE",
            "industry":    "healthcare",
            "tags":        ["healthcare", "hipaa", "ehr", "medical-device", "ransomware"],
            "rule_types":  {"sigma": 40, "yara": 20, "kql": 35, "spl": 35, "suricata": 20},
            "rule_count":  150,
            "mitre_coverage": ["T1486", "T1078", "T1566", "T1021", "T1041"],
        },
        {
            "pack_id":     "cdb-financial-fraud",
            "name":        "CDB Financial Fraud & Banking Threat Pack",
            "description": "Detection rules for banking trojans, SWIFT attacks, ATM malware, business email compromise (BEC), wire fraud, and financial sector APT campaigns.",
            "price_usd":   79.00,
            "tier":        "ENTERPRISE",
            "industry":    "financial",
            "tags":        ["banking", "bec", "swift", "fraud", "atm-malware", "financial"],
            "rule_types":  {"sigma": 38, "yara": 22, "kql": 32, "spl": 32, "suricata": 18},
            "rule_count":  142,
            "mitre_coverage": ["T1566", "T1059", "T1041", "T1078", "T1486"],
        },
        {
            "pack_id":     "cdb-cloud-kubernetes",
            "name":        "CDB Cloud & Kubernetes Security Pack",
            "description": "Cloud-native detection for AWS, Azure, GCP threats. Kubernetes attack detection, container escape, cryptomining, IAM abuse, and cloud data exfiltration rules.",
            "price_usd":   49.00,
            "tier":        "PRO",
            "industry":    "technology",
            "tags":        ["cloud", "kubernetes", "aws", "azure", "gcp", "containers", "cryptomining"],
            "rule_types":  {"sigma": 30, "kql": 28, "spl": 28, "eql": 12},
            "rule_count":  98,
            "mitre_coverage": ["T1078", "T1190", "T1496", "T1552", "T1619"],
        },
        {
            "pack_id":     "cdb-zero-day-response",
            "name":        "CDB Zero-Day Rapid Response Kit",
            "description": "Instantly deployable detection rules generated within hours of new critical CVEs. Monthly updates for the latest 0-days. Includes hunting queries and threat context.",
            "price_usd":   99.00,
            "tier":        "ENTERPRISE",
            "industry":    "all",
            "tags":        ["zero-day", "rapid-response", "cve", "vulnerability", "patch"],
            "rule_types":  {"sigma": 50, "yara": 30, "kql": 45, "spl": 45, "suricata": 25},
            "rule_count":  195,
            "mitre_coverage": ["T1190", "T1203", "T1068", "T1211", "T1212"],
        },
        {
            "pack_id":     "cdb-ics-scada",
            "name":        "CDB ICS/SCADA Critical Infrastructure Pack",
            "description": "OT/ICS security detection for power grids, water treatment, oil & gas, and manufacturing. Covers Modbus, DNP3, IEC 61850, PROFINET protocol anomalies.",
            "price_usd":   199.00,
            "tier":        "ENTERPRISE",
            "industry":    "critical_infrastructure",
            "tags":        ["ics", "scada", "ot", "critical-infrastructure", "modbus", "industrial"],
            "rule_types":  {"sigma": 45, "yara": 25, "suricata": 40},
            "rule_count":  110,
            "mitre_coverage": ["T0800", "T0802", "T0803", "T0804", "T0840"],
        },
        {
            "pack_id":     "cdb-mobile-android",
            "name":        "CDB Mobile Threat Intelligence Pack",
            "description": "Detection and IOC rules for mobile malware, banking trojans (Cerberus, Anubis, Flubot), spyware, and Android-based enterprise threats.",
            "price_usd":   35.00,
            "tier":        "PRO",
            "industry":    "all",
            "tags":        ["mobile", "android", "banking-trojan", "spyware", "cerberus"],
            "rule_types":  {"yara": 30, "sigma": 15, "suricata": 20},
            "rule_count":  65,
            "mitre_coverage": ["T1406", "T1417", "T1421", "T1516", "T1582"],
        },
        {
            "pack_id":     "cdb-weekly-threat-pack",
            "name":        "CDB Weekly Threat Intelligence Pack (Subscription)",
            "description": "Weekly-updated detection rules generated from the live CDB pipeline. Auto-generated Sigma, YARA, KQL rules for the top 10 threats of the week.",
            "price_usd":   19.00,
            "tier":        "PRO",
            "industry":    "all",
            "tags":        ["weekly", "subscription", "auto-updated", "current-threats"],
            "rule_types":  {"sigma": 10, "yara": 5, "kql": 10, "spl": 10, "suricata": 5},
            "rule_count":  40,
            "mitre_coverage": [],
            "subscription": True,
            "update_frequency": "weekly",
        },
    ]

    def __init__(self, catalog_path: str = CATALOG_PATH):
        self.catalog_path = catalog_path
        os.makedirs(os.path.dirname(catalog_path), exist_ok=True)
        os.makedirs(PACKS_DIR, exist_ok=True)

    def get_catalog(self) -> List[Dict]:
        """Get the full marketplace catalog."""
        if os.path.exists(self.catalog_path):
            try:
                with open(self.catalog_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return self.BUILT_IN_PACKS

    def save_catalog(self, catalog: List[Dict]):
        """Save catalog to disk."""
        with open(self.catalog_path, "w") as f:
            json.dump(catalog, f, indent=2)

    def initialize_catalog(self) -> str:
        """Initialize catalog with built-in packs."""
        catalog = [{
            **pack,
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "updated_at":   datetime.now(timezone.utc).isoformat(),
            "downloads":    pack.get("downloads", 0),
            "rating":       pack.get("rating", 0.0),
            "reviews":      pack.get("reviews", 0),
            "available":    True,
            "gumroad_url":  f"https://cyberdudebivash.gumroad.com/{pack['pack_id']}",
        } for pack in self.BUILT_IN_PACKS]

        self.save_catalog(catalog)
        logger.info(f"Marketplace catalog initialized: {len(catalog)} packs")
        return self.catalog_path

    def get_pack_by_id(self, pack_id: str) -> Optional[Dict]:
        """Get a specific pack by ID."""
        return next((p for p in self.get_catalog() if p.get("pack_id") == pack_id), None)

    def get_packs_by_industry(self, industry: str) -> List[Dict]:
        """Get packs relevant to a specific industry."""
        all_packs = self.get_catalog()
        return [
            p for p in all_packs
            if industry.lower() in (p.get("industry") or "").lower() or (p.get("industry") or "") == "all"
        ]

    def get_packs_by_tier(self, tier: str) -> List[Dict]:
        """Get packs available at a specific tier."""
        return [p for p in self.get_catalog() if p.get("tier", "").upper() == tier.upper()]

    def get_revenue_summary(self) -> Dict:
        """Calculate revenue potential from the marketplace catalog."""
        catalog = self.get_catalog()
        total_one_time = sum(p["price_usd"] * p.get("downloads", 0) for p in catalog if not p.get("subscription"))
        subscriptions  = [p for p in catalog if p.get("subscription")]
        sub_mrr        = sum(p["price_usd"] * p.get("downloads", 0) for p in subscriptions)

        return {
            "total_packs":         len(catalog),
            "pro_packs":           len([p for p in catalog if p.get("tier") == "PRO"]),
            "enterprise_packs":    len([p for p in catalog if p.get("tier") == "ENTERPRISE"]),
            "subscription_packs":  len(subscriptions),
            "price_range":         {
                "min": min(p["price_usd"] for p in catalog),
                "max": max(p["price_usd"] for p in catalog),
                "avg": round(sum(p["price_usd"] for p in catalog) / len(catalog), 2),
            },
            "total_one_time_revenue": total_one_time,
            "subscription_mrr":       sub_mrr,
            "catalog_path":           self.catalog_path,
            "generated_at":           datetime.now(timezone.utc).isoformat(),
        }

    def generate_catalog_html(self) -> str:
        """Generate a marketplace HTML page for the platform website."""
        catalog = self.get_catalog()
        os.makedirs("data/marketplace", exist_ok=True)

        pack_cards = ""
        for pack in catalog:
            tier_color = "#00d4aa" if pack.get("tier") == "PRO" else "#8b5cf6"
            rule_types = pack.get("rule_types", {})
            rule_summary = " | ".join(f"{k.upper()}: {v}" for k, v in rule_types.items() if v)
            tags_html = "".join(f'<span style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:4px;font-size:0.7rem;margin:2px;">{t}</span>' for t in pack.get("tags", [])[:5])

            pack_cards += f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;padding:24px;margin-bottom:16px;">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">
    <div>
      <span style="background:{tier_color}22;color:{tier_color};padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;">{pack.get('tier','')}</span>
      {'<span style="background:#f59e0b22;color:#f59e0b;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;margin-left:6px;">SUBSCRIPTION</span>' if pack.get('subscription') else ''}
    </div>
    <div style="font-size:1.5rem;font-weight:700;color:#00d4aa;">${pack['price_usd']:.0f}{'<span style="font-size:0.8rem;color:#64748b;">/mo</span>' if pack.get('subscription') else ''}</div>
  </div>
  <h3 style="color:#e2e8f0;margin-bottom:8px;">{pack['name']}</h3>
  <p style="color:#94a3b8;font-size:0.9rem;margin-bottom:12px;">{pack['description'][:200]}...</p>
  <div style="color:#64748b;font-size:0.8rem;margin-bottom:12px;">📋 {pack.get('rule_count',0)} rules | {rule_summary}</div>
  <div style="margin-bottom:16px;">{tags_html}</div>
  <a href="{pack.get('gumroad_url','https://cyberdudebivash.gumroad.com')}" target="_blank" style="display:inline-block;background:{tier_color};color:#000;font-weight:700;padding:10px 24px;border-radius:8px;text-decoration:none;font-size:0.9rem;">Get Pack →</a>
</div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Detection Rule Marketplace — CyberDudeBivash SENTINEL APEX</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
body {{ background:#06080d; color:#cbd5e1; font-family:'Inter',sans-serif; max-width:900px; margin:0 auto; padding:20px; }}
</style>
</head>
<body>
<div style="text-align:center;padding:40px 20px;border-bottom:1px solid #1e293b;margin-bottom:40px;">
  <div style="color:#00d4aa;font-size:1.1rem;font-weight:700;">Shield CYBERDUDEBIVASH® SENTINEL APEX</div>
  <h1 style="font-size:2.2rem;color:#e2e8f0;margin:12px 0;">Detection Rule Marketplace</h1>
  <p style="color:#64748b;">Production-ready detection rules for SIEM, EDR, and NDR platforms.</p>
  <p style="color:#64748b;">Sigma · YARA · KQL · SPL · Suricata · EQL</p>
</div>
{pack_cards}
<div style="text-align:center;padding:40px;color:#475569;font-size:0.8rem;">
  <p>CYBERDUDEBIVASH® SENTINEL APEX · <a href="https://intel.cyberdudebivash.com" style="color:#00d4aa;">intel.cyberdudebivash.com</a></p>
  <p>Enterprise licensing: <a href="mailto:bivash@cyberdudebivash.com" style="color:#00d4aa;">bivash@cyberdudebivash.com</a></p>
</div>
</body>
</html>"""

        html_path = "data/marketplace/marketplace.html"
        with open(html_path, "w") as f:
            f.write(html)

        return html_path


if __name__ == "__main__":
    marketplace = DetectionMarketplace()
    catalog_path = marketplace.initialize_catalog()
    print(f"Marketplace initialized: {catalog_path}")

    summary = marketplace.get_revenue_summary()
    print(f"Total packs: {summary['total_packs']}")
    print(f"Price range: ${summary['price_range']['min']} - ${summary['price_range']['max']}")

    html_path = marketplace.generate_catalog_html()
    print(f"Marketplace HTML: {html_path}")
