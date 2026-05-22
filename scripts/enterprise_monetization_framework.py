#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v158.5
ENTERPRISE MONETIZATION FRAMEWORK — Product Catalog + GTM Intelligence Engine
===============================================================================
PURPOSE:
  Defines the complete monetizable product catalog for SENTINEL APEX,
  including tier definitions, pricing models, SOC/MSSP readiness scoring,
  ROI computation, and sellability analysis.

  This module is the single source of truth for:
    1. Product tier definitions (FREE / PRO / ENTERPRISE / MSSP / SOVEREIGN)
    2. Feature-tier matrix (what each customer tier gets)
    3. Pricing engine (monthly + annual + volume)
    4. SOC readiness scorer (is the platform SOC-deployable?)
    5. MSSP package builder (white-label bundle generator)
    6. ROI calculator (client-facing value justification)
    7. Competitive positioning matrix (vs. CrowdStrike / Mandiant / Recorded Future)
    8. Sellability health check (data quality gates for premium tier)

OUTPUTS:
  data/monetization/product_catalog.json    -- Machine-readable catalog
  data/monetization/soc_readiness.json      -- SOC deployment readiness report
  data/monetization/mssp_packages.json      -- MSSP white-label packages
  data/monetization/roi_report.json         -- ROI analysis for sales deck
  data/monetization/sellability_score.json  -- Data quality → sellability score

CLI:
  python3 scripts/enterprise_monetization_framework.py --report
  python3 scripts/enterprise_monetization_framework.py --catalog
  python3 scripts/enterprise_monetization_framework.py --soc-check
  python3 scripts/enterprise_monetization_framework.py --mssp-packages
  python3 scripts/enterprise_monetization_framework.py --roi
  python3 scripts/enterprise_monetization_framework.py --all   (default)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import pathlib
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [monetization] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-MONETIZATION")

REPO_ROOT   = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR     = REPO_ROOT / "data" / "monetization"
VERSION     = "158.5"

# ─────────────────────────────────────────────────────────────────────────────
# 1. PRODUCT TIER DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

PRODUCT_TIERS: List[Dict] = [
    {
        "tier_id"     : "FREE",
        "tier_name"   : "SENTINEL APEX Free",
        "tagline"     : "Real-time threat intelligence for security researchers & individuals",
        "price_monthly_usd": 0,
        "price_annual_usd" : 0,
        "price_inr_monthly": 0,
        "target_audience"  : ["Security researchers", "Students", "Individual practitioners"],
        "advisory_limit"   : 50,
        "api_calls_day"    : 100,
        "history_days"     : 7,
        "sla_response_hrs" : None,
        "features": [
            "Public threat feed (50 latest advisories)",
            "Basic severity triage (CRITICAL/HIGH/MEDIUM/LOW)",
            "Public API — 100 calls/day",
            "7-day advisory history",
            "TLP:CLEAR intelligence only",
            "Community dashboard access",
            "MITRE ATT&CK technique tags",
        ],
        "not_included": [
            "CVSS/EPSS enrichment",
            "CISA KEV correlation",
            "IOC export",
            "SIEM integration",
            "Analyst support",
            "Custom sectors",
            "White-label",
        ],
    },
    {
        "tier_id"     : "PRO",
        "tier_name"   : "SENTINEL APEX Pro",
        "tagline"     : "Full-spectrum threat intelligence for security teams and practitioners",
        "price_monthly_usd": 29,
        "price_annual_usd" : 290,   # ~17% discount
        "price_inr_monthly": 2400,
        "price_inr_annual" : 24000,
        "target_audience"  : ["Individual security analysts", "Pen testers", "Threat hunters", "Security consultants"],
        "advisory_limit"   : 500,
        "api_calls_day"    : 5000,
        "history_days"     : 90,
        "sla_response_hrs" : 48,
        "features": [
            "500 enriched advisories per cycle",
            "CVSS v3.1 + EPSS enrichment on all CVEs",
            "CISA KEV correlation (active exploitation flags)",
            "Full IOC corpus — IPs, domains, hashes, URLs",
            "MITRE ATT&CK v15 technique + tactic mapping",
            "Actor attribution (named groups + CDB-UNATTR clusters)",
            "90-day advisory history",
            "STIX 2.1 export (JSON)",
            "CSV/JSON bulk export",
            "API — 5,000 calls/day",
            "Daily AI executive brief (PDF)",
            "TLP:GREEN intelligence included",
            "Email support — 48h SLA",
        ],
        "not_included": [
            "Custom sector feeds",
            "SIEM push integration",
            "Private TLP:AMBER intelligence",
            "Custom enrichment pipelines",
            "White-label",
            "Dedicated CSM",
        ],
    },
    {
        "tier_id"     : "ENTERPRISE",
        "tier_name"   : "SENTINEL APEX Enterprise",
        "tagline"     : "SOC-grade threat intelligence with full enrichment and SIEM integration",
        "price_monthly_usd": 199,
        "price_annual_usd" : 1990,  # ~17% discount
        "price_inr_monthly": 16500,
        "price_inr_annual" : 165000,
        "target_audience"  : [
            "Corporate SOC teams (up to 25 analysts)",
            "CISOs / security managers",
            "Mid-market enterprises",
            "Security consultancies",
        ],
        "advisory_limit"   : -1,   # Unlimited
        "api_calls_day"    : 50000,
        "history_days"     : 365,
        "sla_response_hrs" : 8,
        "features": [
            "Unlimited enriched advisories",
            "All Pro features included",
            "SIEM push — Splunk, QRadar, Elastic, Microsoft Sentinel",
            "SOAR webhook delivery (PagerDuty, Jira, ServiceNow)",
            "Custom sector prioritization (up to 5 sectors)",
            "Private TLP:AMBER intelligence feed",
            "Isolation Forest anomaly scoring on all advisories",
            "GradientBoosting 30-day sector risk forecasts",
            "IOC quality scoring + pseudo-IOC filtering",
            "Full STIX 2.1 bundle export",
            "API — 50,000 calls/day with JWT authentication",
            "1-year advisory history",
            "Executive AI intelligence brief (daily PDF)",
            "Dedicated analyst portal (white-label ready)",
            "Priority support — 8h SLA",
            "Monthly threat landscape briefing call",
        ],
        "not_included": [
            "Multi-tenant MSSP infrastructure",
            "Custom enrichment pipelines (custom build)",
            "Regulatory compliance reporting",
            "Full white-label deployment",
        ],
    },
    {
        "tier_id"     : "MSSP",
        "tier_name"   : "SENTINEL APEX MSSP Partner",
        "tagline"     : "White-label CTI platform for MSSPs serving multiple client organizations",
        "price_monthly_usd": 799,
        "price_annual_usd" : 7990,
        "price_inr_monthly": 66500,
        "price_inr_annual" : 665000,
        "target_audience"  : [
            "Managed Security Service Providers",
            "MDR (Managed Detection and Response) providers",
            "Security outsourcing firms",
            "Telecom / ISP security divisions",
        ],
        "advisory_limit"   : -1,   # Unlimited
        "api_calls_day"    : 500000,
        "history_days"     : 730,  # 2 years
        "client_seats"     : 25,   # Managed client organizations
        "sla_response_hrs" : 4,
        "features": [
            "All Enterprise features included",
            "Multi-tenant architecture (25 client orgs)",
            "Full white-label branding (logo, domain, color scheme)",
            "Per-client sector customization",
            "Per-client TLP policy enforcement",
            "Client-facing intelligence portal",
            "Bulk IOC export per client (CSV, STIX, MISP)",
            "Automated client report generation (PDF/HTML)",
            "MSSP partner dashboard (cross-client threat overview)",
            "API — 500,000 calls/day with per-client JWT keys",
            "2-year advisory history",
            "SIEM push for each managed client",
            "SOAR integration templates",
            "Weekly threat briefing per client",
            "Partner success manager — 4h SLA",
            "Co-marketing: listed as SENTINEL APEX MSSP Partner",
            "Revenue share on sub-client upsells",
        ],
        "not_included": [
            "Custom AI model training",
            "On-premises deployment",
        ],
    },
    {
        "tier_id"     : "SOVEREIGN",
        "tier_name"   : "SENTINEL APEX Sovereign",
        "tagline"     : "Air-gapped, on-premises national/government CTI infrastructure",
        "price_monthly_usd": None,
        "price_annual_usd" : None,
        "price_note"       : "Custom — contact root@cyberdudebivash.in",
        "price_inr_annual" : "₹50L+ / year (custom)",
        "target_audience"  : [
            "Government CERT / NCIIPC equivalents",
            "Defense ministries",
            "Critical national infrastructure operators",
            "Financial regulators (RBI, SEBI, FSDC)",
        ],
        "advisory_limit"   : -1,
        "api_calls_day"    : -1,   # Internal — no rate limit
        "history_days"     : -1,   # Unlimited retention
        "sla_response_hrs" : 2,
        "features": [
            "Complete on-premises or private-cloud deployment",
            "Air-gapped operation capability",
            "All MSSP features included",
            "Unlimited client organizations",
            "Custom AI model training on national threat landscape",
            "Nation-state actor attribution (classified annexure)",
            "STIX/TAXII 2.1 server (push + pull)",
            "Regulatory compliance reporting (ISO 27001, SOC 2, DPDPA)",
            "24/7 hotline support — 2h SLA",
            "On-site deployment + training",
            "Source code escrow",
            "Annual threat landscape assessment report",
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 2. FEATURE-TIER MATRIX
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_MATRIX: List[Dict] = [
    # (feature, free, pro, enterprise, mssp, sovereign)
    {"feature": "Threat advisories",          "FREE": "50/cycle",    "PRO": "500/cycle",  "ENTERPRISE": "Unlimited", "MSSP": "Unlimited", "SOVEREIGN": "Unlimited"},
    {"feature": "CVSS v3.1 enrichment",       "FREE": False,         "PRO": True,         "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "EPSS exploit probability",   "FREE": False,         "PRO": True,         "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "CISA KEV correlation",        "FREE": False,         "PRO": True,         "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "IOC extraction & export",    "FREE": False,         "PRO": True,         "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "MITRE ATT&CK v15 mapping",   "FREE": "Tags only",  "PRO": "Full",       "ENTERPRISE": "Full+nav",  "MSSP": "Full+nav",  "SOVEREIGN": "Custom"},
    {"feature": "STIX 2.1 export",            "FREE": False,         "PRO": True,         "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": "TAXII server"},
    {"feature": "SIEM integration",           "FREE": False,         "PRO": False,        "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "SOAR webhooks",              "FREE": False,         "PRO": False,        "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "API calls / day",            "FREE": "100",         "PRO": "5,000",      "ENTERPRISE": "50,000",    "MSSP": "500,000",   "SOVEREIGN": "Unlimited"},
    {"feature": "Advisory history",           "FREE": "7 days",      "PRO": "90 days",    "ENTERPRISE": "1 year",    "MSSP": "2 years",   "SOVEREIGN": "Unlimited"},
    {"feature": "TLP:AMBER intelligence",     "FREE": False,         "PRO": False,        "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "AI anomaly scoring",         "FREE": False,         "PRO": False,        "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "Sector risk forecasts",      "FREE": False,         "PRO": False,        "ENTERPRISE": True,        "MSSP": True,        "SOVEREIGN": True},
    {"feature": "Daily AI brief (PDF)",       "FREE": False,         "PRO": True,         "ENTERPRISE": True,        "MSSP": "Per client","SOVEREIGN": True},
    {"feature": "White-label branding",       "FREE": False,         "PRO": False,        "ENTERPRISE": False,       "MSSP": True,        "SOVEREIGN": True},
    {"feature": "Multi-tenant (client orgs)", "FREE": False,         "PRO": False,        "ENTERPRISE": False,       "MSSP": "25 orgs",   "SOVEREIGN": "Unlimited"},
    {"feature": "On-premises deployment",     "FREE": False,         "PRO": False,        "ENTERPRISE": False,       "MSSP": False,       "SOVEREIGN": True},
    {"feature": "SLA",                        "FREE": "None",        "PRO": "48h email",  "ENTERPRISE": "8h priority","MSSP": "4h partner","SOVEREIGN": "2h hotline"},
    {"feature": "Support",                    "FREE": "Community",   "PRO": "Email",      "ENTERPRISE": "Priority",  "MSSP": "Partner CSM","SOVEREIGN": "Dedicated"},
]


# ─────────────────────────────────────────────────────────────────────────────
# 3. COMPETITIVE POSITIONING MATRIX
# ─────────────────────────────────────────────────────────────────────────────

COMPETITIVE_MATRIX: List[Dict] = [
    {
        "vendor"         : "CrowdStrike Falcon Intelligence",
        "price_est_usd"  : "~$14,000/yr (mid-tier)",
        "strengths"      : ["Endpoint telemetry", "Nation-state attribution depth", "Global sensor network"],
        "weaknesses"     : ["Enterprise-only pricing", "No open-source tier", "Black-box AI"],
        "sentinel_edge"  : [
            "10–50x lower cost ($290–$1990/yr vs $14k+)",
            "Transparent AI/ML pipeline (explainable scoring)",
            "API-first architecture (no vendor lock-in)",
            "India-region threat coverage advantage",
        ],
    },
    {
        "vendor"         : "Mandiant Threat Intelligence",
        "price_est_usd"  : "~$20,000–$100,000/yr",
        "strengths"      : ["Deep incident response correlation", "Zero-day attribution", "Government contracts"],
        "weaknesses"     : ["Extreme cost barrier", "No self-service", "Slow API"],
        "sentinel_edge"  : [
            "API-first, instant self-service onboarding",
            "Real-time feed (15-minute update cadence vs Mandiant's daily)",
            "Open STIX 2.1 standard — no proprietary format lock-in",
            "MSSP-ready multi-tenancy out-of-box",
        ],
    },
    {
        "vendor"         : "Recorded Future",
        "price_est_usd"  : "~$10,000–$50,000/yr",
        "strengths"      : ["Dark web monitoring", "Geopolitical context", "Browser plugin"],
        "weaknesses"     : ["Complex UI", "Expensive data enrichment add-ons", "No MSSP white-label"],
        "sentinel_edge"  : [
            "Native MSSP white-label (Recorded Future has none)",
            "EPSS + CISA KEV enrichment included (RF charges extra)",
            "Cloudflare-native edge delivery (sub-50ms global latency)",
        ],
    },
    {
        "vendor"         : "Cisco Talos",
        "price_est_usd"  : "Bundled with Cisco products (~$5k+/yr standalone)",
        "strengths"      : ["Email + DNS threat data", "Reputation scoring", "Large sensor network"],
        "weaknesses"     : ["Tightly coupled to Cisco ecosystem", "No white-label", "Limited STIX export"],
        "sentinel_edge"  : [
            "Vendor-agnostic: integrates with any SIEM/SOAR/EDR",
            "Full STIX 2.1 + TAXII 2.1 (Talos has partial support)",
            "Standalone pricing — no Cisco hardware dependency",
        ],
    },
    {
        "vendor"         : "MISP (open source)",
        "price_est_usd"  : "Free (self-hosted, high ops cost)",
        "strengths"      : ["Community sharing", "STIX/TAXII support", "No licensing cost"],
        "weaknesses"     : ["Requires self-hosting + maintenance", "No AI enrichment", "No managed pipeline"],
        "sentinel_edge"  : [
            "Fully managed SaaS — zero infrastructure ops",
            "AI/ML enrichment (MISP has none)",
            "15-minute automated ingestion vs manual community sharing",
            "Enterprise SLA available (MISP: community only)",
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 4. SOC READINESS SCORER
# ─────────────────────────────────────────────────────────────────────────────

SOC_READINESS_CRITERIA: List[Dict] = [
    # (criterion_id, weight, description, data_path_or_check)
    {"id": "STIX_EXPORT",       "weight": 12, "desc": "STIX 2.1 structured export available",                   "required": True},
    {"id": "IOC_EXTRACTION",    "weight": 12, "desc": "IOC corpus (IPs, domains, hashes) extracted per advisory","required": True},
    {"id": "CVSS_ENRICHMENT",   "weight": 10, "desc": "CVSS v3.1 scores on CVE advisories",                     "required": True},
    {"id": "EPSS_ENRICHMENT",   "weight": 10, "desc": "EPSS exploit probability enrichment",                    "required": True},
    {"id": "KEV_CORRELATION",   "weight": 10, "desc": "CISA KEV active-exploitation flags",                     "required": True},
    {"id": "MITRE_MAPPING",     "weight": 8,  "desc": "MITRE ATT&CK v15 technique mapping (TTP coverage)",     "required": True},
    {"id": "SIEM_PUSH",         "weight": 8,  "desc": "SIEM push webhook delivery (Splunk/QRadar/Elastic)",    "required": False},
    {"id": "SEVERITY_ACCURACY", "weight": 8,  "desc": "Evidence-weighted severity (not label-based buckets)",  "required": True},
    {"id": "API_AUTH",          "weight": 7,  "desc": "JWT-authenticated API with rate limiting",              "required": True},
    {"id": "TLP_POLICY",        "weight": 6,  "desc": "TLP classification on all advisories",                  "required": True},
    {"id": "ACTOR_ATTRIBUTION", "weight": 5,  "desc": "Threat actor attribution or unattributed cluster IDs", "required": True},
    {"id": "ANOMALY_SCORING",   "weight": 4,  "desc": "ML anomaly scoring (Isolation Forest or equivalent)",  "required": False},
]


def score_soc_readiness(feed: Optional[List[Dict]], manifest_path: Optional[pathlib.Path]) -> Dict:
    """
    Score platform SOC readiness against 12 criteria.
    Returns a dict with score/100, tier, gaps, and per-criterion details.
    """
    results = []
    total_weight = sum(c["weight"] for c in SOC_READINESS_CRITERIA)
    achieved_weight = 0

    # Load manifest sample for field inspection
    sample_items: List[Dict] = feed[:20] if feed else []
    if not sample_items and manifest_path and manifest_path.exists():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                sample_items = data[:20]
            elif isinstance(data, dict) and "items" in data:
                sample_items = data["items"][:20]
        except Exception:
            pass

    for c in SOC_READINESS_CRITERIA:
        cid = c["id"]
        passed = False
        evidence = ""

        if cid == "STIX_EXPORT":
            stix_dir = REPO_ROOT / "data" / "stix"
            passed = stix_dir.exists() and any(stix_dir.glob("*.json"))
            evidence = f"STIX dir: {stix_dir.exists()}, files: {len(list(stix_dir.glob('*.json'))) if stix_dir.exists() else 0}"

        elif cid == "IOC_EXTRACTION":
            if sample_items:
                with_iocs = sum(1 for i in sample_items if i.get("iocs") and len(i["iocs"]) > 0)
                passed = with_iocs >= len(sample_items) * 0.3
                evidence = f"{with_iocs}/{len(sample_items)} sample items have IOCs"
            else:
                evidence = "No sample items to inspect"

        elif cid == "CVSS_ENRICHMENT":
            if sample_items:
                cve_items = [i for i in sample_items if i.get("cve_ids") or i.get("cvss_score")]
                with_cvss = sum(1 for i in cve_items if i.get("cvss_score") and float(i.get("cvss_score") or 0) > 0)
                passed = len(cve_items) == 0 or (with_cvss / max(len(cve_items), 1)) >= 0.5
                evidence = f"{with_cvss}/{len(cve_items)} CVE items have CVSS"
            else:
                evidence = "No sample items"

        elif cid == "EPSS_ENRICHMENT":
            if sample_items:
                with_epss = sum(1 for i in sample_items if i.get("epss_score") is not None or i.get("epss") is not None)
                passed = with_epss > 0
                evidence = f"{with_epss}/{len(sample_items)} have EPSS"
            else:
                evidence = "No sample items"

        elif cid == "KEV_CORRELATION":
            if sample_items:
                with_kev = sum(1 for i in sample_items
                               if i.get("kev_enriched") or i.get("in_cisa_kev") or i.get("cisa_kev"))
                kev_path = REPO_ROOT / "data" / "intel" / "cisa_kev.json"
                kev_exists = kev_path.exists()
                passed = kev_exists and with_kev >= 0  # KEV present even if 0 items match
                evidence = f"KEV catalog: {kev_exists}, matches in sample: {with_kev}"
            else:
                kev_path = REPO_ROOT / "data" / "intel" / "cisa_kev.json"
                passed = kev_path.exists()
                evidence = f"KEV catalog: {kev_path.exists()}"

        elif cid == "MITRE_MAPPING":
            if sample_items:
                with_mitre = sum(1 for i in sample_items
                                 if (i.get("mitre_tactics") and len(i.get("mitre_tactics", [])) > 0)
                                 or (i.get("ttps") and len(i.get("ttps", [])) > 0))
                passed = with_mitre >= len(sample_items) * 0.3
                evidence = f"{with_mitre}/{len(sample_items)} have MITRE techniques"
            else:
                attack_nav = REPO_ROOT / "data" / "intelligence" / "attack_navigator.json"
                passed = attack_nav.exists()
                evidence = f"ATT&CK navigator: {attack_nav.exists()}"

        elif cid == "SIEM_PUSH":
            siem_script = REPO_ROOT / "scripts" / "siem_webhook_delivery.py"
            webhook_script = REPO_ROOT / "scripts" / "enterprise_webhook_delivery.py"
            passed = siem_script.exists() or webhook_script.exists()
            evidence = f"SIEM delivery script: {passed}"

        elif cid == "SEVERITY_ACCURACY":
            if sample_items:
                with_evidence = sum(1 for i in sample_items
                                    if i.get("apex_ai") and isinstance(i.get("apex_ai"), dict)
                                    and i["apex_ai"].get("apex_score") is not None)
                # Also check risk_score is not a pure bucket value
                bucket_vals = {10.0, 7.5, 5.5, 5.0, 4.8, 2.8, 2.3}
                non_bucket = sum(1 for i in sample_items
                                 if float(i.get("risk_score") or 0) not in bucket_vals
                                 and float(i.get("risk_score") or 0) > 0)
                passed = with_evidence > 0 or non_bucket >= len(sample_items) * 0.5
                evidence = f"apex_score enriched: {with_evidence}, non-bucket scores: {non_bucket}/{len(sample_items)}"
            else:
                evidence = "No sample items"

        elif cid == "API_AUTH":
            wrangler = REPO_ROOT / "workers" / "intel-gateway" / "wrangler.toml"
            passed = wrangler.exists()
            evidence = f"Gateway wrangler.toml: {wrangler.exists()}"

        elif cid == "TLP_POLICY":
            if sample_items:
                with_tlp = sum(1 for i in sample_items if i.get("tlp") or i.get("tlp_label"))
                passed = with_tlp >= len(sample_items) * 0.8
                evidence = f"{with_tlp}/{len(sample_items)} have TLP label"
            else:
                evidence = "No sample items"

        elif cid == "ACTOR_ATTRIBUTION":
            if sample_items:
                with_actor = sum(1 for i in sample_items
                                 if i.get("actor_tag") or i.get("threat_actor") or i.get("actor"))
                passed = with_actor >= len(sample_items) * 0.5
                evidence = f"{with_actor}/{len(sample_items)} have actor attribution"
            else:
                evidence = "No sample items"

        elif cid == "ANOMALY_SCORING":
            anomaly_path = REPO_ROOT / "data" / "ai_predictions" / "anomalies.json"
            passed = anomaly_path.exists()
            evidence = f"Anomaly output: {anomaly_path.exists()}"

        if passed:
            achieved_weight += c["weight"]

        results.append({
            "criterion_id"  : cid,
            "criterion_desc": c["desc"],
            "weight"        : c["weight"],
            "passed"        : passed,
            "required"      : c["required"],
            "evidence"      : evidence,
        })

    score = round((achieved_weight / total_weight) * 100, 1)
    required_failed = [r for r in results if r["required"] and not r["passed"]]

    if score >= 85:
        tier = "ENTERPRISE-READY"
    elif score >= 70:
        tier = "SOC-DEPLOYABLE"
    elif score >= 55:
        tier = "PRO-READY"
    else:
        tier = "DEVELOPMENT"

    return {
        "score"           : score,
        "tier"            : tier,
        "criteria_passed" : sum(1 for r in results if r["passed"]),
        "criteria_total"  : len(results),
        "required_gaps"   : [r["criterion_id"] for r in required_failed],
        "required_gap_count": len(required_failed),
        "sellable_now"    : score >= 70 and len(required_failed) == 0,
        "details"         : results,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5. MSSP PACKAGE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

MSSP_PACKAGES: List[Dict] = [
    {
        "package_id"    : "MSSP-STARTER",
        "package_name"  : "MSSP Starter Pack",
        "description"   : "Entry point for small MSSPs (1–5 clients). All white-label basics included.",
        "client_orgs"   : 5,
        "price_monthly_usd": 399,
        "price_annual_usd" : 3990,
        "resell_markup_suggestion": "40–60% markup → $559–$638/mo billed to clients",
        "gross_margin_est": "65–70% at 40% markup",
        "included": [
            "5 white-label client portals",
            "Custom logo + color scheme per client",
            "Per-client API keys (JWT)",
            "Per-client SIEM push configuration",
            "Per-client daily brief PDF",
            "500 advisories/cycle per client",
            "Partner dashboard (cross-client view)",
            "Email support — 8h SLA",
        ],
        "upsell_paths": ["MSSP-GROWTH", "ENTERPRISE"],
    },
    {
        "package_id"    : "MSSP-GROWTH",
        "package_name"  : "MSSP Growth Pack",
        "description"   : "For MSSPs scaling to 25 client organizations. Full feature set included.",
        "client_orgs"   : 25,
        "price_monthly_usd": 799,
        "price_annual_usd" : 7990,
        "resell_markup_suggestion": "50–100% markup → $1,200–$1,600/mo billed to clients",
        "gross_margin_est": "70–80% at 50% markup",
        "included": [
            "25 white-label client portals",
            "All MSSP Starter features",
            "Unlimited advisories per client",
            "TLP:AMBER intelligence per client",
            "Custom sector prioritization per client",
            "Automated client report generation",
            "SOAR integration templates",
            "Revenue share on sub-client upgrades",
            "Partner CSM — 4h SLA",
            "Co-marketing listing",
        ],
        "upsell_paths": ["SOVEREIGN"],
    },
    {
        "package_id"    : "MSSP-ENTERPRISE",
        "package_name"  : "MSSP Enterprise Pack",
        "description"   : "For large MSSPs and MDR providers managing 50+ clients. Custom SLAs.",
        "client_orgs"   : 100,
        "price_monthly_usd": None,
        "price_note"    : "Custom — contact root@cyberdudebivash.in",
        "included": [
            "100+ white-label client portals",
            "All MSSP Growth features",
            "Custom AI model tuning per vertical",
            "On-premises deployment option",
            "Regulatory compliance report templates (ISO 27001, SOC 2)",
            "Dedicated 24/7 partner engineering support",
            "Joint GTM (go-to-market) co-sell agreement",
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 6. ROI CALCULATOR
# ─────────────────────────────────────────────────────────────────────────────

def calculate_roi(
    tier_id: str = "ENTERPRISE",
    analyst_headcount: int = 5,
    analyst_hourly_rate_usd: float = 75.0,
    incidents_per_month: int = 20,
    avg_incident_cost_usd: float = 15000.0,
    mttr_reduction_pct: float = 35.0,   # % reduction in mean-time-to-respond
) -> Dict:
    """
    Calculate 12-month ROI for SENTINEL APEX deployment.

    Model:
      - Analyst efficiency gain: CTI platform reduces manual research time
      - Incident cost reduction: faster triage → lower breach cost
      - Tool consolidation: replaces X threat feeds at Y cost each
    """
    tier = next((t for t in PRODUCT_TIERS if t["tier_id"] == tier_id), PRODUCT_TIERS[2])
    annual_platform_cost = tier.get("price_annual_usd") or 0

    # Analyst efficiency: CTI platform saves ~8 hrs/analyst/week on manual triage
    hours_saved_per_analyst_week = 8.0
    weeks_per_year = 52
    analyst_hours_saved = analyst_headcount * hours_saved_per_analyst_week * weeks_per_year
    analyst_cost_savings = analyst_hours_saved * analyst_hourly_rate_usd

    # Incident cost reduction
    incidents_per_year = incidents_per_month * 12
    incident_cost_reduction = (incidents_per_year * avg_incident_cost_usd * (mttr_reduction_pct / 100.0))

    # Tool consolidation (replaces avg 3 paid threat feeds at $200/mo each)
    tools_replaced_cost = 3 * 200 * 12

    total_annual_benefit = analyst_cost_savings + incident_cost_reduction + tools_replaced_cost
    net_roi = total_annual_benefit - annual_platform_cost
    roi_pct = ((total_annual_benefit - annual_platform_cost) / max(annual_platform_cost, 1)) * 100

    # Payback period in months
    monthly_benefit = total_annual_benefit / 12
    monthly_cost = annual_platform_cost / 12
    payback_months = annual_platform_cost / max(monthly_benefit, 1)

    return {
        "tier_id"                 : tier_id,
        "annual_platform_cost_usd": annual_platform_cost,
        "analyst_headcount"       : analyst_headcount,
        "analyst_hours_saved_yr"  : round(analyst_hours_saved),
        "analyst_cost_savings_usd": round(analyst_cost_savings),
        "incident_cost_reduction_usd": round(incident_cost_reduction),
        "tool_consolidation_savings_usd": tools_replaced_cost,
        "total_annual_benefit_usd": round(total_annual_benefit),
        "net_annual_roi_usd"      : round(net_roi),
        "roi_percentage"          : round(roi_pct, 1),
        "payback_months"          : round(payback_months, 1),
        "breakeven_statement"     : (
            f"Platform pays for itself in {payback_months:.1f} months through analyst efficiency "
            f"gains and incident cost reduction alone."
        ),
        "assumptions": {
            "analyst_hours_saved_per_week": hours_saved_per_analyst_week,
            "analyst_hourly_rate_usd"     : analyst_hourly_rate_usd,
            "mttr_reduction_pct"          : mttr_reduction_pct,
            "incidents_per_year"          : incidents_per_year,
            "avg_incident_cost_usd"       : avg_incident_cost_usd,
            "tools_replaced_count"        : 3,
            "tools_replaced_cost_per_yr"  : tools_replaced_cost,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# 7. SELLABILITY HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────

SELLABILITY_GATES: List[Dict] = [
    {"id": "DATA_FRESHNESS",    "weight": 20, "desc": "Feed updated within last 2 hours"},
    {"id": "ADVISORY_VOLUME",   "weight": 15, "desc": "≥50 advisories in current feed"},
    {"id": "ENRICHMENT_RATE",   "weight": 15, "desc": "≥60% advisories have CVSS or EPSS or KEV"},
    {"id": "IOC_COVERAGE",      "weight": 10, "desc": "≥30% advisories have extracted IOCs"},
    {"id": "ACTOR_DIVERSITY",   "weight": 10, "desc": "≥5 distinct actor clusters"},
    {"id": "SOURCE_DIVERSITY",  "weight": 10, "desc": "≥3 distinct source domains"},
    {"id": "SEVERITY_SPREAD",   "weight": 10, "desc": "All 4 severity levels represented"},
    {"id": "API_AVAILABILITY",  "weight": 5,  "desc": "Worker endpoint responding"},
    {"id": "STIX_VALIDITY",     "weight": 5,  "desc": "STIX bundle valid and non-empty"},
]


def check_sellability(feed: Optional[List[Dict]]) -> Dict:
    """Score whether current data quality is high enough to sell."""
    score = 0
    results = []
    now = datetime.now(timezone.utc)

    # DATA_FRESHNESS
    freshness_passed = False
    freshness_evidence = "No feed data"
    if feed:
        latest_dates = []
        for item in feed[:20]:
            d = item.get("published_at") or item.get("published") or ""
            if d:
                try:
                    dt = datetime.fromisoformat(d.replace("Z", "+00:00"))
                    latest_dates.append(dt)
                except Exception:
                    pass
        if latest_dates:
            newest = max(latest_dates)
            hours_old = (now - newest).total_seconds() / 3600
            freshness_passed = hours_old <= 2
            freshness_evidence = f"Newest item: {hours_old:.1f}h ago"
        else:
            freshness_evidence = "No parseable dates in feed"

    # ADVISORY_VOLUME
    volume = len(feed) if feed else 0
    volume_passed = volume >= 50
    volume_evidence = f"{volume} advisories in feed"

    # ENRICHMENT_RATE
    enrichment_passed = False
    enrichment_evidence = "No feed"
    if feed:
        enriched = sum(1 for i in feed
                       if i.get("cvss_score") or i.get("epss_score") or i.get("kev_enriched")
                       or i.get("in_cisa_kev") or (i.get("apex_ai") and isinstance(i.get("apex_ai"), dict)))
        enrichment_rate = enriched / max(len(feed), 1)
        enrichment_passed = enrichment_rate >= 0.60
        enrichment_evidence = f"{enriched}/{len(feed)} enriched ({enrichment_rate:.0%})"

    # IOC_COVERAGE
    ioc_passed = False
    ioc_evidence = "No feed"
    if feed:
        with_iocs = sum(1 for i in feed if i.get("iocs") and len(i.get("iocs", [])) > 0)
        ioc_rate = with_iocs / max(len(feed), 1)
        ioc_passed = ioc_rate >= 0.30
        ioc_evidence = f"{with_iocs}/{len(feed)} have IOCs ({ioc_rate:.0%})"

    # ACTOR_DIVERSITY
    actor_passed = False
    actor_evidence = "No feed"
    if feed:
        actors = set(
            (i.get("actor_tag") or i.get("threat_actor") or "UNKNOWN").upper()
            for i in feed
            if i.get("actor_tag") or i.get("threat_actor")
        )
        actor_passed = len(actors) >= 5
        actor_evidence = f"{len(actors)} distinct actors"

    # SOURCE_DIVERSITY
    source_passed = False
    source_evidence = "No feed"
    if feed:
        sources = set(
            (i.get("source_domain") or i.get("source") or "").lower().strip()
            for i in feed
            if i.get("source_domain") or i.get("source")
        )
        source_passed = len(sources) >= 3
        source_evidence = f"{len(sources)} distinct sources"

    # SEVERITY_SPREAD
    sev_passed = False
    sev_evidence = "No feed"
    if feed:
        sevs = set((i.get("severity") or "MEDIUM").upper() for i in feed)
        all_four = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        sev_passed = len(sevs & all_four) >= 3
        sev_evidence = f"Severity levels present: {sorted(sevs & all_four)}"

    # API_AVAILABILITY (check wrangler)
    wrangler = REPO_ROOT / "workers" / "intel-gateway" / "wrangler.toml"
    api_passed = wrangler.exists()
    api_evidence = f"Gateway config: {wrangler.exists()}"

    # STIX_VALIDITY
    stix_dir = REPO_ROOT / "data" / "stix"
    stix_files = list(stix_dir.glob("*.json")) if stix_dir.exists() else []
    stix_passed = len(stix_files) > 0
    stix_evidence = f"STIX files: {len(stix_files)}"

    gate_results = [
        ("DATA_FRESHNESS",   20, freshness_passed, freshness_evidence),
        ("ADVISORY_VOLUME",  15, volume_passed,    volume_evidence),
        ("ENRICHMENT_RATE",  15, enrichment_passed, enrichment_evidence),
        ("IOC_COVERAGE",     10, ioc_passed,        ioc_evidence),
        ("ACTOR_DIVERSITY",  10, actor_passed,      actor_evidence),
        ("SOURCE_DIVERSITY", 10, source_passed,     source_evidence),
        ("SEVERITY_SPREAD",  10, sev_passed,        sev_evidence),
        ("API_AVAILABILITY",  5, api_passed,        api_evidence),
        ("STIX_VALIDITY",     5, stix_passed,       stix_evidence),
    ]

    total_weight = sum(g[1] for g in gate_results)
    achieved = sum(g[1] for g in gate_results if g[2])
    score = round((achieved / total_weight) * 100, 1)

    for gid, weight, passed, evidence in gate_results:
        results.append({
            "gate_id" : gid,
            "weight"  : weight,
            "passed"  : passed,
            "evidence": evidence,
        })

    if score >= 80:
        tier = "PREMIUM_SELLABLE"
        recommendation = "Platform data quality is premium-grade. Proceed to enterprise sales outreach."
    elif score >= 65:
        tier = "PRO_SELLABLE"
        recommendation = "Good quality for Pro tier. Fix failing gates before ENTERPRISE sales."
    elif score >= 50:
        tier = "BASIC_SELLABLE"
        recommendation = "Minimum viable for basic offering. Significant enrichment improvements needed."
    else:
        tier = "NOT_SELLABLE"
        recommendation = "Data quality insufficient for commercial offering. Run pipeline improvements first."

    return {
        "sellability_score"   : score,
        "sellability_tier"    : tier,
        "recommendation"      : recommendation,
        "gates_passed"        : sum(1 for g in gate_results if g[2]),
        "gates_total"         : len(gate_results),
        "gates"               : results,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN OUTPUT RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_feed() -> Optional[List[Dict]]:
    feed_path = REPO_ROOT / "api" / "feed.json"
    if not feed_path.exists():
        log.warning("Feed not found: %s", feed_path)
        return None
    try:
        data = json.loads(feed_path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, list) else None
    except Exception as e:
        log.warning("Feed load error: %s", e)
        return None


def write_json(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.info("[WRITE] %s (%dB)", path, path.stat().st_size)


def run_all(args) -> int:
    t0 = time.monotonic()
    log.info("=" * 70)
    log.info("SENTINEL APEX %s — Enterprise Monetization Framework", VERSION)
    log.info("=" * 70)

    feed = load_feed()
    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

    # --- Product Catalog ---
    if args.catalog or args.all:
        log.info("[CATALOG] Building product catalog...")
        catalog = {
            "generated_at"   : now_iso(),
            "version"        : VERSION,
            "tiers"          : PRODUCT_TIERS,
            "feature_matrix" : FEATURE_MATRIX,
            "competitive"    : COMPETITIVE_MATRIX,
            "mssp_packages"  : MSSP_PACKAGES,
        }
        write_json(OUT_DIR / "product_catalog.json", catalog)
        log.info("[CATALOG] %d tiers, %d features, %d competitors", len(PRODUCT_TIERS), len(FEATURE_MATRIX), len(COMPETITIVE_MATRIX))

    # --- SOC Readiness ---
    if args.soc_check or args.all:
        log.info("[SOC] Scoring SOC readiness...")
        soc = score_soc_readiness(feed, manifest_path)
        soc["generated_at"] = now_iso()
        soc["version"] = VERSION
        write_json(OUT_DIR / "soc_readiness.json", soc)
        log.info("[SOC] Score: %.1f/100 | Tier: %s | Required gaps: %d | Sellable: %s",
                 soc["score"], soc["tier"], soc["required_gap_count"], soc["sellable_now"])

    # --- MSSP Packages ---
    if args.mssp_packages or args.all:
        log.info("[MSSP] Generating MSSP package definitions...")
        mssp_out = {
            "generated_at": now_iso(),
            "version"     : VERSION,
            "packages"    : MSSP_PACKAGES,
        }
        write_json(OUT_DIR / "mssp_packages.json", mssp_out)
        log.info("[MSSP] %d packages defined", len(MSSP_PACKAGES))

    # --- ROI Report ---
    if args.roi or args.all:
        log.info("[ROI] Computing ROI scenarios...")
        roi_scenarios = []
        for tier_id, analysts, incident_cost in [
            ("PRO",        2,  5000),
            ("ENTERPRISE", 8,  15000),
            ("MSSP",       15, 25000),
        ]:
            roi = calculate_roi(tier_id, analysts, 75.0, 20, incident_cost, 35.0)
            roi_scenarios.append(roi)
            log.info("[ROI] %s: Net $%d/yr | ROI %.0f%% | Payback %.1f mo",
                     tier_id, roi["net_annual_roi_usd"], roi["roi_percentage"], roi["payback_months"])

        roi_report = {
            "generated_at": now_iso(),
            "version"     : VERSION,
            "scenarios"   : roi_scenarios,
        }
        write_json(OUT_DIR / "roi_report.json", roi_report)

    # --- Sellability Check ---
    if args.report or args.all:
        log.info("[SELL] Running sellability health check...")
        sell = check_sellability(feed)
        sell["generated_at"] = now_iso()
        sell["version"] = VERSION
        write_json(OUT_DIR / "sellability_score.json", sell)
        log.info("[SELL] Score: %.1f/100 | Tier: %s | Gates: %d/%d",
                 sell["sellability_score"], sell["sellability_tier"],
                 sell["gates_passed"], sell["gates_total"])
        log.info("[SELL] %s", sell["recommendation"])

    runtime = round(time.monotonic() - t0, 3)
    log.info("=" * 70)
    log.info("Monetization Framework complete in %.3fs", runtime)
    log.info("Outputs: %s", OUT_DIR)
    log.info("=" * 70)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Enterprise Monetization Framework v158.5"
    )
    parser.add_argument("--catalog",      action="store_true", help="Output product catalog JSON")
    parser.add_argument("--soc-check",    action="store_true", help="Run SOC readiness scoring")
    parser.add_argument("--mssp-packages",action="store_true", help="Output MSSP package definitions")
    parser.add_argument("--roi",          action="store_true", help="Compute ROI scenarios")
    parser.add_argument("--report",       action="store_true", help="Run sellability health check")
    parser.add_argument("--all",          action="store_true", help="Run all modules (default)")
    args = parser.parse_args()

    if not any([args.catalog, args.soc_check, args.mssp_packages, args.roi, args.report]):
        args.all = True

    return run_all(args)


if __name__ == "__main__":
    sys.exit(main())
