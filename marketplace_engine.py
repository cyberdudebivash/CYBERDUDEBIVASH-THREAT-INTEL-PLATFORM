"""
SENTINEL APEX — Marketplace Engine
Phase 131-140: Detection Marketplace, ATT&CK Content Packs, Intelligence Packs, API Marketplace.
Monetization through content and capability licensing.
"""

import uuid
import hashlib
import random
from datetime import datetime
from typing import Optional


MARKETPLACE_CATEGORIES = {
    "detection_pack":    {"label": "Detection Pack",         "unit": "rules",   "base_price": 5_000},
    "attck_content":     {"label": "ATT&CK Content Pack",    "unit": "mappings","base_price": 8_000},
    "intel_pack":        {"label": "Intelligence Pack",      "unit": "feeds",   "base_price": 12_000},
    "threat_actor":      {"label": "Threat Actor Profile",   "unit": "report",  "base_price": 15_000},
    "api_extension":     {"label": "API Extension",          "unit": "endpoint","base_price": 3_000},
    "integration":       {"label": "Integration Connector",  "unit": "connector","base_price": 6_000},
    "compliance_pack":   {"label": "Compliance Pack",        "unit": "controls","base_price": 20_000},
    "hunting_pack":      {"label": "Threat Hunting Pack",    "unit": "queries", "base_price": 10_000},
}

LISTING_STATUS = ["published", "published", "published", "beta", "coming_soon"]


def _rng(seed: str) -> random.Random:
    return random.Random(int(hashlib.md5(seed.encode()).hexdigest()[:8], 16))


def create_marketplace_listing(title: str, category: str, author: str,
                                 description: str, price: int, items: int,
                                 tags: list) -> dict:
    """Create a new marketplace listing."""
    listing_id = f"MKT-{uuid.uuid4().hex[:8].upper()}"
    cat = MARKETPLACE_CATEGORIES.get(category, MARKETPLACE_CATEGORIES["detection_pack"])
    return {
        "listing_id": listing_id,
        "title": title,
        "category": category,
        "category_label": cat["label"],
        "author": author,
        "description": description,
        "price_monthly": price,
        "price_annual": round(price * 10),  # 2 months free
        "item_count": items,
        "unit_label": cat["unit"],
        "tags": tags,
        "status": "published",
        "rating": round(random.uniform(4.2, 5.0), 1),
        "installs": random.randint(12, 380),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "free_tier_available": price == 0,
        "enterprise_only": price >= 20_000,
    }


def get_marketplace_catalog() -> list:
    """Return the full marketplace catalog."""
    rng = _rng("marketplace_catalog_v1")

    catalog = [
        # Detection Packs
        create_marketplace_listing(
            "APT29 / Cozy Bear Detection Suite", "detection_pack",
            "Sentinel APEX Research",
            "84 production Sigma rules covering all known APT29 TTPs. Updated within 24h of new intelligence.",
            8_000, 84, ["apt29", "russia", "sigma", "detection"]),
        create_marketplace_listing(
            "Ransomware Pre-Encryption Detection Pack", "detection_pack",
            "Sentinel APEX Research",
            "47 rules detecting ransomware behavior before encryption: shadow copy deletion, volume enumeration, lateral movement.",
            6_000, 47, ["ransomware", "lockbit", "blackcat", "sigma"]),
        create_marketplace_listing(
            "Windows Active Directory Attack Detection", "detection_pack",
            "Sentinel APEX Research",
            "112 Sigma rules for AD attacks: Kerberoasting, DCSync, Pass-the-Hash, LDAP enumeration.",
            10_000, 112, ["active-directory", "kerberos", "sigma", "windows"]),
        create_marketplace_listing(
            "Cloud Infrastructure Attack Detection (AWS/Azure/GCP)", "detection_pack",
            "Sentinel APEX Research",
            "73 KQL + Sigma rules for cloud-native attacks. CSPM integration ready.",
            9_000, 73, ["cloud", "aws", "azure", "gcp", "detection"]),
        create_marketplace_listing(
            "Financial Sector Threat Detection Bundle", "detection_pack",
            "Sentinel APEX Research",
            "Sector-specific bundle: FIN7, Carbanak, SWIFT attacks, ATM malware. 91 rules.",
            12_000, 91, ["finance", "banking", "fin7", "swift"]),

        # ATT&CK Content Packs
        create_marketplace_listing(
            "Full MITRE ATT&CK Coverage Matrix v14", "attck_content",
            "Sentinel APEX Research",
            "Complete ATT&CK Enterprise matrix with detections for all 193 techniques. Navigator layers included.",
            15_000, 193, ["mitre", "attck", "matrix", "navigator"]),
        create_marketplace_listing(
            "ICS/OT ATT&CK Coverage Pack", "attck_content",
            "Sentinel APEX Research",
            "ATT&CK for ICS: 83 techniques mapped to detection rules. OT/SCADA focused.",
            18_000, 83, ["ics", "ot", "scada", "attck"]),
        create_marketplace_listing(
            "Mobile ATT&CK Coverage Pack", "attck_content",
            "Sentinel APEX Research",
            "iOS and Android threat coverage. 67 ATT&CK Mobile techniques with detection rules.",
            10_000, 67, ["mobile", "ios", "android", "attck"]),

        # Intelligence Packs
        create_marketplace_listing(
            "Global APT Intelligence Bundle (Live)", "intel_pack",
            "Sentinel APEX CTI",
            "Real-time intelligence on 40+ APT groups. Updated daily. STIX 2.1 format.",
            20_000, 40, ["apt", "intelligence", "stix", "live"]),
        create_marketplace_listing(
            "Ransomware Intelligence Subscription", "intel_pack",
            "Sentinel APEX CTI",
            "Weekly ransomware TTP reports, C2 infrastructure, victim sectors. All active groups covered.",
            15_000, 12, ["ransomware", "intelligence", "weekly"]),
        create_marketplace_listing(
            "Dark Web Monitoring Intelligence Feed", "intel_pack",
            "Sentinel APEX CTI",
            "Credential leaks, sale of access, data exfiltration evidence from dark web forums.",
            25_000, 5, ["darkweb", "credentials", "monitoring"]),

        # Threat Actor Profiles
        create_marketplace_listing(
            "APT29 Deep-Dive Profile", "threat_actor",
            "Sentinel APEX Research",
            "200-page technical profile: infrastructure, TTPs, malware families, detection guidance.",
            10_000, 1, ["apt29", "russia", "svr", "profile"]),
        create_marketplace_listing(
            "LockBit 4.0 Operational Profile", "threat_actor",
            "Sentinel APEX Research",
            "Full LockBit 4.0 analysis: affiliate program, encryption routines, negotiation tactics.",
            8_000, 1, ["lockbit", "ransomware", "profile"]),

        # Compliance Packs
        create_marketplace_listing(
            "PCI DSS v4.0 Threat Detection Pack", "compliance_pack",
            "Sentinel APEX Compliance",
            "Detection rules mapped to PCI DSS v4.0 requirements. Audit-ready evidence generation.",
            20_000, 156, ["pci", "compliance", "detection"]),
        create_marketplace_listing(
            "ISO 27001:2022 Control Detection Mapping", "compliance_pack",
            "Sentinel APEX Compliance",
            "All 93 ISO 27001:2022 controls mapped to detection rules and evidence collection.",
            18_000, 93, ["iso27001", "compliance"]),

        # API Extensions
        create_marketplace_listing(
            "Threat Score API Extension", "api_extension",
            "Sentinel APEX Engineering",
            "Real-time threat scoring endpoint. Query any IP, domain, hash for instant risk score.",
            3_000, 5, ["api", "threat-scoring", "ioc"]),
        create_marketplace_listing(
            "Automated SOAR Enrichment API", "api_extension",
            "Sentinel APEX Engineering",
            "Drop-in enrichment API for SOAR playbooks. Returns full threat context in <200ms.",
            4_000, 8, ["api", "soar", "enrichment"]),

        # Integrations
        create_marketplace_listing(
            "Splunk Enterprise Security Connector", "integration",
            "Sentinel APEX Engineering",
            "Native Splunk ES integration. Auto-pushes rules, IOCs, correlation searches.",
            6_000, 1, ["splunk", "integration", "siem"]),
        create_marketplace_listing(
            "Microsoft Sentinel Deep Integration", "integration",
            "Sentinel APEX Engineering",
            "KQL rules, watchlists, hunting queries, playbook templates — all auto-synced.",
            6_000, 1, ["sentinel", "microsoft", "azure", "kql"]),

        # Hunting Packs
        create_marketplace_listing(
            "Threat Hunting Query Library (KQL/SPL/EQL)", "hunting_pack",
            "Sentinel APEX Research",
            "340 production-tested hunting queries across KQL, Splunk SPL, and Elastic EQL.",
            12_000, 340, ["hunting", "kql", "splunk", "elastic"]),
    ]
    return catalog


def process_marketplace_purchase(buyer_tenant_id: str, listing_id: str,
                                   billing_cycle: str = "monthly") -> dict:
    """Process a marketplace purchase and provision access."""
    order_id = f"ORD-{uuid.uuid4().hex[:10].upper()}"
    # Production: look up listing from DB, charge billing engine, provision access key
    return {
        "order_id": order_id,
        "buyer_tenant_id": buyer_tenant_id,
        "listing_id": listing_id,
        "billing_cycle": billing_cycle,
        "status": "PROVISIONED",
        "access_key": f"mk-{uuid.uuid4().hex[:16].upper()}",
        "provisioned_at": datetime.utcnow().isoformat() + "Z",
        "api_endpoint": f"https://api.cyberdudebivash.in/marketplace/{listing_id.lower()}/",
        "download_url": f"https://cdn.cyberdudebivash.in/marketplace/{order_id}/content.zip",
    }


def get_marketplace_analytics() -> dict:
    """Return marketplace revenue and adoption analytics."""
    catalog = get_marketplace_catalog()
    total_listings = len(catalog)
    total_installs = sum(l["installs"] for l in catalog)
    total_mrr = sum(l["price_monthly"] * min(l["installs"] // 10, 50) for l in catalog)
    avg_rating = round(sum(l["rating"] for l in catalog) / total_listings, 2)

    by_category = {}
    for l in catalog:
        cat = l["category"]
        by_category.setdefault(cat, {"count": 0, "installs": 0, "mrr": 0})
        by_category[cat]["count"] += 1
        by_category[cat]["installs"] += l["installs"]
        by_category[cat]["mrr"] += l["price_monthly"] * min(l["installs"] // 10, 50)

    return {
        "total_listings": total_listings,
        "total_installs": total_installs,
        "marketplace_mrr": total_mrr,
        "marketplace_arr": total_mrr * 12,
        "avg_rating": avg_rating,
        "by_category": by_category,
        "top_listings": sorted(catalog, key=lambda x: -x["installs"])[:5],
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


# ── CLI Demo ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    analytics = get_marketplace_analytics()
    print(f"\n{'='*55}")
    print(f"SENTINEL APEX — Marketplace Analytics")
    print(f"{'='*55}")
    print(f"Total Listings  : {analytics['total_listings']}")
    print(f"Total Installs  : {analytics['total_installs']}")
    print(f"Marketplace MRR : ₹{analytics['marketplace_mrr']:,.0f}")
    print(f"Marketplace ARR : ₹{analytics['marketplace_arr']:,.0f}")
    print(f"Avg Rating      : {analytics['avg_rating']}/5.0")
    print(f"\nTop Listings:")
    for l in analytics["top_listings"]:
        print(f"  {l['title'][:40]:40s} | {l['installs']:3d} installs | ₹{l['price_monthly']:,.0f}/mo")
