#!/usr/bin/env python3
"""
scripts/p38_shared_validators.py
P38.0 Shared Certification Framework — Canonical Validator Library

This module is the Single Source of Truth for all certification-level
validation logic.  Every P-layer certification script that needs field-
coverage measurement, gate construction, or feed-type detection MUST
import from here rather than re-implementing the logic inline.

REUSE MAP (Phase 0 audit finding):
  - _field_pct / _gate were duplicated in p36 and p37 cert scripts.
    This module canonicalises them.  p36/p37 are NOT modified (backward
    compatibility preserved per CLAUDE.md).  Future P-layers (P38+)
    import from here.

  - score_item()      → intelligence_quality_governor.score_item
  - compute_confidence() → apex_confidence_engine.compute_confidence
    Both are called by reference, never re-implemented.

ARCHITECTURE DECISION RECORD — ADR-P38-001
  Decision : Introduce shared validator library rather than continuing
             to inline validation logic in each cert script.
  Rationale: Phase 0 audit found _field_pct re-defined independently
             in p36 and p37.  As the platform grows to P40+, each new
             cert script would diverge further, creating maintenance
             and regression risk.
  Approach : Additive — existing p36/p37 scripts are NOT modified.
             New scripts import from this module.
  Risk      : LOW — this module exposes pure functions with no side
             effects and no external dependencies beyond stdlib.
"""
from __future__ import annotations
import json
import pathlib
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# FEED REGISTRY — canonical feed definitions
# Source of truth for feed purpose / type / owner / required fields.
# ---------------------------------------------------------------------------
FEED_REGISTRY: Dict[str, Dict] = {
    "root": {
        "path": ROOT / "feed.json",
        "label": "Root Snapshot Feed",
        "purpose": "Stale CI snapshot; consumed by legacy cert scripts (p36). NOT the live production feed.",
        "feed_type": "SNAPSHOT",
        "owner": "CI pipeline",
        "consumer": ["p36_production_certification.py"],
        "required_fields": ["id", "title", "severity"],
        "enrichment_expected": False,
        "commercial_use": False,
        "deprecated": False,
    },
    "live": {
        "path": ROOT / "api" / "feed.json",
        "label": "Live Production CVE Feed",
        "purpose": "Primary production feed enriched by enrich_cvss_epss_batch.py. CVE-dominant (NVD). "
                   "Consumed by p37 cert and API endpoints.",
        "feed_type": "CVE_FEED",
        "owner": "enrich_cvss_epss_batch.py",
        "consumer": ["p37_production_certification.py", "/api/v1/p37/*", "/api/v1/p36/*"],
        "required_fields": ["id", "title", "severity", "cvss_score", "epss", "confidence"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "research": {
        "path": ROOT / "data" / "feed.json",
        "label": "Aggregate Research Feed",
        "purpose": "Broad threat intelligence feed including APT, malware, campaigns. IOC-rich. "
                   "Not CVE-primary; actor attribution expected.",
        "feed_type": "BROAD_THREAT_INTEL",
        "owner": "research pipeline",
        "consumer": ["p36_production_certification.py (G06 fallback)"],
        "required_fields": ["id", "title", "severity"],
        "enrichment_expected": False,
        "commercial_use": False,
        "deprecated": False,
    },
    "baseline": {
        "path": ROOT / "api" / "feed.baseline.json",
        "label": "Commercial Baseline Tier Feed",
        "purpose": "Widest enriched dataset for baseline tier subscribers. 491 items.",
        "feed_type": "COMMERCIAL_CVE",
        "owner": "commercial tier pipeline",
        "consumer": ["billing.py", "api/feed.baseline.json endpoint"],
        "required_fields": ["id", "title", "severity", "cvss_score", "confidence"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "gold": {
        "path": ROOT / "api" / "feed.gold.json",
        "label": "Commercial Gold Tier Feed",
        "purpose": "Premium enriched dataset for gold tier. 260 curated high-signal items.",
        "feed_type": "COMMERCIAL_CVE",
        "owner": "commercial tier pipeline",
        "consumer": ["billing.py"],
        "required_fields": ["id", "title", "severity", "cvss_score", "epss", "confidence"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "silver": {
        "path": ROOT / "api" / "feed.silver.json",
        "label": "Commercial Silver Tier Feed",
        "purpose": "Mid-tier enriched feed. 397 items.",
        "feed_type": "COMMERCIAL_CVE",
        "owner": "commercial tier pipeline",
        "consumer": ["billing.py"],
        "required_fields": ["id", "title", "severity", "cvss_score", "confidence"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "standard": {
        "path": ROOT / "api" / "feed.standard.json",
        "label": "Commercial Standard Tier Feed",
        "purpose": "Entry-level commercial feed. 491 items, same count as baseline with reduced enrichment.",
        "feed_type": "COMMERCIAL_CVE",
        "owner": "commercial tier pipeline",
        "consumer": ["billing.py"],
        "required_fields": ["id", "title", "severity", "cvss_score", "confidence"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "executive": {
        "path": ROOT / "api" / "feed.executive.json",
        "label": "Executive Intelligence Feed",
        "purpose": "Curated executive-grade summary feed. 220 items. Confidence not required per format.",
        "feed_type": "EXECUTIVE",
        "owner": "executive report pipeline",
        "consumer": ["executive dashboard"],
        "required_fields": ["id", "title", "severity"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "trial": {
        "path": ROOT / "api" / "feed.trial.json",
        "label": "Trial / Demo Feed",
        "purpose": "10-item sampled feed for product trials. Not enrichment-complete by design.",
        "feed_type": "TRIAL",
        "owner": "commercial tier pipeline",
        "consumer": ["billing.py", "trial signup flow"],
        "required_fields": ["id", "title", "severity"],
        "enrichment_expected": False,
        "commercial_use": True,
        "deprecated": False,
    },
    "enterprise": {
        "path": ROOT / "api" / "feed_enterprise.json",
        "label": "Enterprise Dedicated Feed",
        "purpose": "23-item high-fidelity enterprise feed. Full enrichment mandatory.",
        "feed_type": "ENTERPRISE",
        "owner": "enterprise tier pipeline",
        "consumer": ["enterprise portal"],
        "required_fields": ["id", "title", "severity", "cvss_score", "epss", "confidence", "iocs"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "mssp": {
        "path": ROOT / "api" / "feed_mssp.json",
        "label": "MSSP Feed",
        "purpose": "58-item MSSP-grade feed matching live feed with MSSP-specific enrichment.",
        "feed_type": "MSSP",
        "owner": "MSSP tier pipeline",
        "consumer": ["MSSP portal"],
        "required_fields": ["id", "title", "severity", "cvss_score", "confidence"],
        "enrichment_expected": True,
        "commercial_use": True,
        "deprecated": False,
    },
    "public": {
        "path": ROOT / "api" / "feed_public.json",
        "label": "Public API Feed",
        "purpose": "58-item public-facing feed. No paywall. Subset of live feed.",
        "feed_type": "PUBLIC",
        "owner": "public API",
        "consumer": ["/api/feed_public.json endpoint"],
        "required_fields": ["id", "title", "severity"],
        "enrichment_expected": True,
        "commercial_use": False,
        "deprecated": False,
    },
}

# ---------------------------------------------------------------------------
# FEED TYPE THRESHOLDS — context-aware validation rules
# ---------------------------------------------------------------------------
FEED_TYPE_RULES: Dict[str, Dict] = {
    "CVE_FEED": {
        "cvss_min_pct": 50.0,
        "epss_min_pct": 30.0,
        "cve_min_pct": 50.0,
        "dominance_max_pct": 98.0,   # NVD concentration acceptable
        "distinct_sources_min": 1,
        "actor_min_pct": 0.0,        # CVE feeds rarely have actor tags
        "description": "NVD-primary CVE feeds tolerate source concentration and lack of actor attribution",
    },
    "BROAD_THREAT_INTEL": {
        "cvss_min_pct": 20.0,
        "epss_min_pct": 0.0,
        "cve_min_pct": 0.0,
        "dominance_max_pct": 75.0,
        "distinct_sources_min": 3,
        "actor_min_pct": 20.0,
        "description": "Broad threat intel feeds require source diversity and actor attribution",
    },
    "COMMERCIAL_CVE": {
        "cvss_min_pct": 50.0,
        "epss_min_pct": 30.0,
        "cve_min_pct": 30.0,
        "dominance_max_pct": 90.0,
        "distinct_sources_min": 2,
        "actor_min_pct": 0.0,
        "description": "Commercial CVE feeds require enrichment; source diversity is encouraged",
    },
    "ENTERPRISE": {
        "cvss_min_pct": 80.0,
        "epss_min_pct": 50.0,
        "cve_min_pct": 50.0,
        "dominance_max_pct": 85.0,
        "distinct_sources_min": 2,
        "actor_min_pct": 10.0,
        "description": "Enterprise feeds require high enrichment and some actor attribution",
    },
    "MSSP": {
        "cvss_min_pct": 60.0,
        "epss_min_pct": 30.0,
        "cve_min_pct": 30.0,
        "dominance_max_pct": 90.0,
        "distinct_sources_min": 2,
        "actor_min_pct": 5.0,
        "description": "MSSP feeds require solid enrichment for managed detection",
    },
    "EXECUTIVE": {
        "cvss_min_pct": 50.0,
        "epss_min_pct": 20.0,
        "cve_min_pct": 20.0,
        "dominance_max_pct": 95.0,
        "distinct_sources_min": 1,
        "actor_min_pct": 0.0,
        "description": "Executive feeds are curated summaries; enrichment thresholds relaxed",
    },
    "TRIAL": {
        "cvss_min_pct": 0.0,
        "epss_min_pct": 0.0,
        "cve_min_pct": 0.0,
        "dominance_max_pct": 100.0,
        "distinct_sources_min": 1,
        "actor_min_pct": 0.0,
        "description": "Trial feeds are demo samples; no enrichment guarantees",
    },
    "SNAPSHOT": {
        "cvss_min_pct": 0.0,
        "epss_min_pct": 0.0,
        "cve_min_pct": 0.0,
        "dominance_max_pct": 100.0,
        "distinct_sources_min": 1,
        "actor_min_pct": 0.0,
        "description": "Snapshot feeds are CI artifacts; validated for structure only",
    },
    "PUBLIC": {
        "cvss_min_pct": 40.0,
        "epss_min_pct": 20.0,
        "cve_min_pct": 20.0,
        "dominance_max_pct": 95.0,
        "distinct_sources_min": 1,
        "actor_min_pct": 0.0,
        "description": "Public API feeds require basic enrichment; commercial completeness not required",
    },
}

# ---------------------------------------------------------------------------
# CANONICAL SCHEMA REGISTRY — field definitions
# This is the Single Source of Truth for every known feed field.
# Fields are grouped by domain.
# ---------------------------------------------------------------------------
SCHEMA_REGISTRY: Dict[str, Dict] = {
    # ── Identity ────────────────────────────────────────────────────────────
    "id":              {"required": True,  "type": "str",   "domain": "identity",    "nullable": False,  "version_introduced": "v1.0"},
    "title":           {"required": True,  "type": "str",   "domain": "identity",    "nullable": False,  "version_introduced": "v1.0"},
    "severity":        {"required": True,  "type": "str",   "domain": "identity",    "nullable": False,  "version_introduced": "v1.0"},
    "description":     {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v1.0"},
    "source":          {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v1.0"},
    "feed_source":     {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v2.0"},
    "source_url":      {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v1.0"},
    "published_at":    {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v1.0"},
    "timestamp":       {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v1.0"},
    "processed_at":    {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v2.0"},
    "schema_version":  {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v3.0"},
    "status":          {"required": False, "type": "str",   "domain": "identity",    "nullable": True,   "version_introduced": "v2.0"},
    "is_published":    {"required": False, "type": "bool",  "domain": "identity",    "nullable": True,   "version_introduced": "v2.0"},
    "is_new":          {"required": False, "type": "bool",  "domain": "identity",    "nullable": True,   "version_introduced": "v2.0"},
    # ── Vulnerability ────────────────────────────────────────────────────────
    "cve_id":          {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v1.0"},
    "cve_ids":         {"required": False, "type": "list",  "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "cves":            {"required": False, "type": "list",  "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0", "deprecated": True, "replacement": "cve_ids"},
    "cvss_score":      {"required": False, "type": "float", "domain": "vulnerability","nullable": True,  "version_introduced": "v1.0"},
    "cvss_vector":     {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "cvss_source":     {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "cvss_estimated":  {"required": False, "type": "bool",  "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "epss":            {"required": False, "type": "float", "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "epss_score":      {"required": False, "type": "float", "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0", "deprecated": True, "replacement": "epss"},
    "epss_normalized": {"required": False, "type": "float", "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "kev":             {"required": False, "type": "bool",  "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "kev_confirmed":   {"required": False, "type": "bool",  "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "kev_date":        {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "kev_due":         {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "kev_name":        {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "kev_action":      {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "kev_product":     {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "kev_present":     {"required": False, "type": "bool",  "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "nvd_status":      {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "nvd_checked_at":  {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "nvd_disclosure":  {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "vuln_class":      {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "exploit_maturity":{"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "exploit_count":   {"required": False, "type": "int",   "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "exploit_refs":    {"required": False, "type": "list",  "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "poc_github_count":{"required": False, "type": "int",   "domain": "vulnerability","nullable": True,  "version_introduced": "v3.0"},
    "metasploit_available":{"required": False, "type": "bool","domain": "vulnerability","nullable": True,"version_introduced": "v3.0"},
    "attack_vector":   {"required": False, "type": "str",   "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    "affected_products":{"required": False, "type": "list", "domain": "vulnerability","nullable": True,  "version_introduced": "v2.0"},
    # ── Actor / Attribution ───────────────────────────────────────────────────
    "actor_tag":       {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v2.0", "note": "canonical actor field"},
    "actor":           {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v1.0", "deprecated": True, "replacement": "actor_tag"},
    "actor_name":      {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v2.0"},
    "actor_display_name":{"required": False,"type": "str",  "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "actor_aliases":   {"required": False, "type": "list",  "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "actor_code":      {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v2.0"},
    "actor_type":      {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v2.0"},
    "actor_country":   {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v2.0"},
    "actor_region":    {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "actor_motivation":{"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v2.0"},
    "actor_sectors":   {"required": False, "type": "list",  "domain": "actor",       "nullable": True,  "version_introduced": "v2.0"},
    "actor_threat_level":{"required": False,"type": "str",  "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "actor_ttps":      {"required": False, "type": "list",  "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "actor_malware":   {"required": False, "type": "list",  "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "actor_mitre_id":  {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "actor_confidence_label":{"required": False,"type": "str","domain": "actor",     "nullable": True,  "version_introduced": "v3.0"},
    "verified_actor":  {"required": False, "type": "bool",  "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "attribution_status":{"required": False,"type": "str",  "domain": "actor",       "nullable": True,  "version_introduced": "v3.0"},
    "attribution_assessment":{"required": False,"type": "dict","domain": "actor",    "nullable": True,  "version_introduced": "v3.0"},
    # ── Confidence / Trust ───────────────────────────────────────────────────
    "confidence":      {"required": False, "type": "float", "domain": "confidence",  "nullable": True,  "version_introduced": "v1.0"},
    "confidence_score":{"required": False, "type": "float", "domain": "confidence",  "nullable": True,  "version_introduced": "v2.0", "deprecated": True, "replacement": "confidence"},
    "confidence_score_v2":{"required": False,"type": "float","domain": "confidence", "nullable": True,  "version_introduced": "v3.0"},
    "confidence_label":{"required": False, "type": "str",   "domain": "confidence",  "nullable": True,  "version_introduced": "v2.0"},
    "confidence_rationale":{"required": False,"type": "str","domain": "confidence",  "nullable": True,  "version_introduced": "v3.0"},
    "confidence_reason":{"required": False,"type": "str",   "domain": "confidence",  "nullable": True,  "version_introduced": "v3.0"},
    "confidence_factors":{"required": False,"type": "dict", "domain": "confidence",  "nullable": True,  "version_introduced": "v3.0"},
    "confidence_engine_version":{"required": False,"type": "str","domain": "confidence","nullable": True,"version_introduced": "v3.0"},
    "confidence_enriched_at":{"required": False,"type": "str","domain": "confidence","nullable": True,  "version_introduced": "v3.0"},
    "source_trust_score":{"required": False,"type": "float","domain": "confidence",  "nullable": True,  "version_introduced": "v3.0"},
    "source_reliability":{"required": False,"type": "str",  "domain": "confidence",  "nullable": True,  "version_introduced": "v2.0"},
    "source_quality":  {"required": False, "type": "str",   "domain": "confidence",  "nullable": True,  "version_introduced": "v2.0"},
    "corroboration_score":{"required": False,"type": "float","domain": "confidence", "nullable": True,  "version_introduced": "v3.0"},
    "corroboration_strength":{"required": False,"type": "str","domain": "confidence","nullable": True,  "version_introduced": "v3.0"},
    "corroboration_count":{"required": False,"type": "int", "domain": "confidence",  "nullable": True,  "version_introduced": "v3.0"},
    "corroborating_sources":{"required": False,"type": "list","domain": "confidence","nullable": True,  "version_introduced": "v3.0"},
    "corroboration_sources":{"required": False,"type": "list","domain": "confidence","nullable": True,  "version_introduced": "v3.0", "deprecated": True, "replacement": "corroborating_sources"},
    "ioc_confidence":  {"required": False, "type": "float", "domain": "confidence",  "nullable": True,  "version_introduced": "v3.0"},
    # ── IOC / Indicators ─────────────────────────────────────────────────────
    "iocs":            {"required": False, "type": "list",  "domain": "ioc",         "nullable": True,  "version_introduced": "v1.0"},
    "iocs_by_type":    {"required": False, "type": "dict",  "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_types":       {"required": False, "type": "list",  "domain": "ioc",         "nullable": True,  "version_introduced": "v2.0"},
    "ioc_count":       {"required": False, "type": "int",   "domain": "ioc",         "nullable": True,  "version_introduced": "v2.0"},
    "ioc_counts":      {"required": False, "type": "dict",  "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "real_ioc_count":  {"required": False, "type": "int",   "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "indicator_count": {"required": False, "type": "int",   "domain": "ioc",         "nullable": True,  "version_introduced": "v2.0"},
    "ioc_quality":     {"required": False, "type": "str",   "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_quality_label":{"required": False,"type": "str",   "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_quality_score":{"required": False,"type": "float", "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_threat_level":{"required": False, "type": "str",   "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_fp_removed":  {"required": False, "type": "int",   "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_note":        {"required": False, "type": "str",   "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_paywall":     {"required": False, "type": "bool",  "domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    "ioc_extraction_meta":{"required": False,"type": "dict","domain": "ioc",         "nullable": True,  "version_introduced": "v3.0"},
    # ── Detection / MITRE ────────────────────────────────────────────────────
    "ttps":            {"required": False, "type": "list",  "domain": "detection",   "nullable": True,  "version_introduced": "v1.0"},
    "ttp_count":       {"required": False, "type": "int",   "domain": "detection",   "nullable": True,  "version_introduced": "v2.0"},
    "ttp_quality":     {"required": False, "type": "str",   "domain": "detection",   "nullable": True,  "version_introduced": "v3.0"},
    "mitre_tactics":   {"required": False, "type": "list",  "domain": "detection",   "nullable": True,  "version_introduced": "v2.0"},
    "attck_techniques":{"required": False, "type": "list",  "domain": "detection",   "nullable": True,  "version_introduced": "v2.0"},
    "attck_technique_ids":{"required": False,"type": "list","domain": "detection",   "nullable": True,  "version_introduced": "v3.0"},
    "attck_notes":     {"required": False, "type": "str",   "domain": "detection",   "nullable": True,  "version_introduced": "v3.0"},
    "attck_verification":{"required": False,"type": "str",  "domain": "detection",   "nullable": True,  "version_introduced": "v3.0"},
    "kill_chain_phase":{"required": False, "type": "str",   "domain": "detection",   "nullable": True,  "version_introduced": "v2.0"},
    "kill_chain_phases":{"required": False,"type": "list",  "domain": "detection",   "nullable": True,  "version_introduced": "v2.0"},
    "sigma_rule":      {"required": False, "type": "str",   "domain": "detection",   "nullable": True,  "version_introduced": "v2.0"},
    "suricata_rule":   {"required": False, "type": "str",   "domain": "detection",   "nullable": True,  "version_introduced": "v2.0"},
    "kql_query":       {"required": False, "type": "str",   "domain": "detection",   "nullable": True,  "version_introduced": "v3.0"},
    "detection_generated_at":{"required": False,"type": "str","domain": "detection", "nullable": True,  "version_introduced": "v3.0"},
    "detection_production_ready":{"required": False,"type": "bool","domain": "detection","nullable": True,"version_introduced": "v3.0"},
    "detection_quality_status":{"required": False,"type": "str","domain": "detection","nullable": True,  "version_introduced": "v3.0"},
    "detection_rules_production_ready":{"required": False,"type": "bool","domain": "detection","nullable": True,"version_introduced": "v3.0"},
    "detection_rules_total":{"required": False,"type": "int","domain": "detection",  "nullable": True,  "version_introduced": "v3.0"},
    # ── Intelligence Quality ─────────────────────────────────────────────────
    "intelligence_grade":{"required": False,"type": "str",  "domain": "quality",     "nullable": True,  "version_introduced": "v2.0"},
    "iq_score":        {"required": False, "type": "float", "domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    "iq_breakdown":    {"required": False, "type": "dict",  "domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    "enrichment_score":{"required": False, "type": "float", "domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    "report_quality":  {"required": False, "type": "str",   "domain": "quality",     "nullable": True,  "version_introduced": "v2.0"},
    "grade_notes":     {"required": False, "type": "list",  "domain": "quality",     "nullable": True,  "version_introduced": "v2.0"},
    "grade_notes_v2":  {"required": False, "type": "list",  "domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    "graded_at":       {"required": False, "type": "str",   "domain": "quality",     "nullable": True,  "version_introduced": "v2.0"},
    "graded_at_v2":    {"required": False, "type": "str",   "domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    "grade_engine_version":{"required": False,"type": "str","domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    "validation_status":{"required": False,"type": "str",   "domain": "quality",     "nullable": True,  "version_introduced": "v2.0"},
    "verification_status":{"required": False,"type": "str", "domain": "quality",     "nullable": True,  "version_introduced": "v2.0"},
    "analyst_verdict": {"required": False, "type": "str",   "domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    "publication_decision":{"required": False,"type": "str","domain": "quality",     "nullable": True,  "version_introduced": "v3.0"},
    # ── Risk / Scoring ────────────────────────────────────────────────────────
    "risk_score":      {"required": False, "type": "float", "domain": "risk",        "nullable": True,  "version_introduced": "v1.0"},
    "risk_score_reasoning":{"required": False,"type": "str","domain": "risk",        "nullable": True,  "version_introduced": "v3.0"},
    "threat_level":    {"required": False, "type": "str",   "domain": "risk",        "nullable": True,  "version_introduced": "v1.0"},
    "threat_priority": {"required": False, "type": "str",   "domain": "risk",        "nullable": True,  "version_introduced": "v2.0"},
    "threat_category": {"required": False, "type": "str",   "domain": "risk",        "nullable": True,  "version_introduced": "v1.0"},
    "threat_type":     {"required": False, "type": "str",   "domain": "risk",        "nullable": True,  "version_introduced": "v1.0"},
    "sla_priority":    {"required": False, "type": "str",   "domain": "risk",        "nullable": True,  "version_introduced": "v2.0"},
    "recommended_sla_action":{"required": False,"type": "str","domain": "risk",      "nullable": True,  "version_introduced": "v3.0"},
    "action_deadline_hours":{"required": False,"type": "int","domain": "risk",       "nullable": True,  "version_introduced": "v3.0"},
    # ── Evidence ─────────────────────────────────────────────────────────────
    "evidence_chain":  {"required": False, "type": "list",  "domain": "evidence",    "nullable": True,  "version_introduced": "v2.0"},
    "evidence_count":  {"required": False, "type": "int",   "domain": "evidence",    "nullable": True,  "version_introduced": "v2.0"},
    "evidence_ledger": {"required": False, "type": "dict",  "domain": "evidence",    "nullable": True,  "version_introduced": "v3.0"},
    "sources_reporting":{"required": False,"type": "list",  "domain": "evidence",    "nullable": True,  "version_introduced": "v2.0"},
    # ── Commercial / Tiers ───────────────────────────────────────────────────
    "allowed_content_tier":{"required": False,"type": "str","domain": "commercial",  "nullable": True,  "version_introduced": "v2.0"},
    "cti_tier":        {"required": False, "type": "str",   "domain": "commercial",  "nullable": True,  "version_introduced": "v3.0"},
    "premium_eligible":{"required": False, "type": "bool",  "domain": "commercial",  "nullable": True,  "version_introduced": "v2.0"},
    "enterprise_eligible":{"required": False,"type": "bool","domain": "commercial",  "nullable": True,  "version_introduced": "v3.0"},
    "mssp_eligible":   {"required": False, "type": "bool",  "domain": "commercial",  "nullable": True,  "version_introduced": "v3.0"},
    "revenue_opportunities":{"required": False,"type": "list","domain": "commercial","nullable": True,  "version_introduced": "v3.0"},
    "pdf_available":   {"required": False, "type": "bool",  "domain": "commercial",  "nullable": True,  "version_introduced": "v2.0"},
    "pdf_url":         {"required": False, "type": "str",   "domain": "commercial",  "nullable": True,  "version_introduced": "v2.0"},
    "report_url":      {"required": False, "type": "str",   "domain": "commercial",  "nullable": True,  "version_introduced": "v1.0"},
    "blog_url":        {"required": False, "type": "str",   "domain": "commercial",  "nullable": True,  "version_introduced": "v2.0"},
    "internal_report_url":{"required": False,"type": "str", "domain": "commercial",  "nullable": True,  "version_introduced": "v2.0"},
    # ── Governance / Meta ────────────────────────────────────────────────────
    "_enriched_at":    {"required": False, "type": "str",   "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_enriched_by":    {"required": False, "type": "str",   "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_governance_rules":{"required": False,"type": "list",  "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_kev_marked_at":  {"required": False, "type": "str",   "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_kev_source":     {"required": False, "type": "str",   "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_quality_hardened_at":{"required": False,"type": "str","domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_quality_version":{"required": False, "type": "str",   "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_risk_micro_adj": {"required": False, "type": "float", "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "_score_details":  {"required": False, "type": "dict",  "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "governed_at":     {"required": False, "type": "str",   "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "governor_audit_log":{"required": False,"type": "list", "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    "governor_version":{"required": False, "type": "str",   "domain": "governance",  "nullable": True,  "version_introduced": "v3.0"},
    # ── Campaign / Context ───────────────────────────────────────────────────
    "campaign_id":     {"required": False, "type": "str",   "domain": "campaign",    "nullable": True,  "version_introduced": "v2.0"},
    "campaign_name":   {"required": False, "type": "str",   "domain": "campaign",    "nullable": True,  "version_introduced": "v2.0"},
    "campaign_status": {"required": False, "type": "str",   "domain": "campaign",    "nullable": True,  "version_introduced": "v3.0"},
    "tags":            {"required": False, "type": "list",  "domain": "campaign",    "nullable": True,  "version_introduced": "v1.0"},
    "tlp":             {"required": False, "type": "str",   "domain": "campaign",    "nullable": True,  "version_introduced": "v1.0"},
    "stix_id":         {"required": False, "type": "str",   "domain": "campaign",    "nullable": True,  "version_introduced": "v2.0"},
    "research_based":  {"required": False, "type": "bool",  "domain": "campaign",    "nullable": True,  "version_introduced": "v3.0"},
    "intelligence_age_days":{"required": False,"type": "int","domain": "campaign",   "nullable": True,  "version_introduced": "v3.0"},
    # ── Previously undocumented fields (discovered by G23 schema drift audit) ─
    "actor_id":        {"required": False, "type": "str",   "domain": "actor",       "nullable": True,  "version_introduced": "v3.1", "note": "internal actor ID used by attribution pipeline"},
    "ioc_enforced":    {"required": False, "type": "bool",  "domain": "ioc",         "nullable": True,  "version_introduced": "v3.1"},
    "ioc_enforced_at": {"required": False, "type": "str",   "domain": "ioc",         "nullable": True,  "version_introduced": "v3.1"},
    "published":       {"required": False, "type": "bool",  "domain": "identity",    "nullable": True,  "version_introduced": "v3.1", "note": "boolean publication flag (distinct from is_published which is also bool)"},
    # ── APEX / AI ────────────────────────────────────────────────────────────
    "apex":            {"required": False, "type": "dict",  "domain": "apex",        "nullable": True,  "version_introduced": "v2.0"},
    "apex_ai":         {"required": False, "type": "dict",  "domain": "apex",        "nullable": True,  "version_introduced": "v3.0"},
    "apex_ai_score":   {"required": False, "type": "float", "domain": "apex",        "nullable": True,  "version_introduced": "v3.0"},
    "apex_ai_summary": {"required": False, "type": "str",   "domain": "apex",        "nullable": True,  "version_introduced": "v3.0"},
}

# ---------------------------------------------------------------------------
# CANONICAL GATE BUILDER — replaces duplicated _gate() in p36/p37
# ---------------------------------------------------------------------------
def gate(
    gate_id: str,
    label: str,
    severity: str,
    status: bool,
    detail: str,
) -> Dict:
    """Build a standard certification gate result dict.
    Canonical implementation: replaces _gate() in p36 and _gate() in p37.
    New P-layer cert scripts MUST call this function.
    """
    return {
        "gate_id": gate_id,
        "label": label,
        "severity": severity,
        "status": "PASS" if status else ("FAIL_BLOCKER" if severity == "BLOCKER" else "FAIL_WARNING"),
        "detail": detail,
    }

# ---------------------------------------------------------------------------
# CANONICAL FIELD-COVERAGE MEASUREMENT — replaces duplicated _field_pct / _pct
# ---------------------------------------------------------------------------
def field_pct(
    items: List[Dict],
    key: str,
    check: Optional[Callable[[Dict], bool]] = None,
) -> float:
    """Measure what percentage of items have a non-empty value for `key`.
    Canonical implementation: replaces _field_pct() in p36 and _pct() in p37.
    New P-layer cert scripts MUST call this function.

    Args:
        items: Feed item list.
        key:   Field name to check.
        check: Optional custom predicate; defaults to bool(item.get(key)).
    Returns:
        Percentage [0.0–100.0].
    """
    if not items:
        return 0.0
    if check is None:
        check = lambda x: bool(x.get(key))
    return 100.0 * sum(1 for x in items if check(x)) / len(items)

# ---------------------------------------------------------------------------
# FEED LOADER — canonical feed loading with fallback chain
# ---------------------------------------------------------------------------
def load_feed(feed_key: str = "live") -> Tuple[List[Dict], str]:
    """Load a registered feed by key.
    Returns (items, path_used).
    """
    reg = FEED_REGISTRY.get(feed_key)
    if not reg:
        raise KeyError(f"Feed key '{feed_key}' not in FEED_REGISTRY")
    path = reg["path"]
    try:
        raw = json.loads(path.read_bytes())
        items = raw if isinstance(raw, list) else raw.get("items", raw.get("data", []))
        return items, str(path)
    except Exception as e:
        raise RuntimeError(f"Cannot load feed '{feed_key}' from {path}: {e}") from e

def load_feed_safe(feed_key: str = "live") -> Tuple[List[Dict], str]:
    """Like load_feed but returns ([], "") on any error."""
    try:
        return load_feed(feed_key)
    except Exception:
        return [], ""

def load_json_safe(path: pathlib.Path) -> Optional[Dict]:
    """Load any JSON file; return None on failure."""
    try:
        return json.loads(path.read_bytes())
    except Exception:
        return None

# ---------------------------------------------------------------------------
# FEED TYPE DETECTOR
# ---------------------------------------------------------------------------
def detect_feed_type(items: List[Dict]) -> str:
    """Classify a feed as CVE_FEED, BROAD_THREAT_INTEL, or UNKNOWN.
    Uses the top source name heuristic from P37 Phase 0 audit.
    """
    if not items:
        return "UNKNOWN"
    from collections import Counter
    sources = Counter(
        x.get("source") or x.get("feed_source", "unknown") for x in items
    )
    top_src = sources.most_common(1)[0][0].lower() if sources else ""
    cve_keywords = ("nvd_cve", "cve", "nvd", "mitre_cve", "nist")
    if any(k in top_src for k in cve_keywords):
        return "CVE_FEED"
    return "BROAD_THREAT_INTEL"

# ---------------------------------------------------------------------------
# FIELD COVERAGE AUDIT — produces a coverage dict for every registered field
# ---------------------------------------------------------------------------
def audit_field_coverage(items: List[Dict], key_fields: Optional[List[str]] = None) -> Dict[str, float]:
    """Return coverage percentage for each field in key_fields (or all schema fields)."""
    fields = key_fields or list(SCHEMA_REGISTRY.keys())
    return {f: field_pct(items, f) for f in fields}

# ---------------------------------------------------------------------------
# ENRICHMENT COVERAGE SUMMARY
# ---------------------------------------------------------------------------
def enrichment_summary(items: List[Dict]) -> Dict:
    """Summarise enrichment status across the canonical enrichment fields."""
    return {
        "cvss_pct":   round(field_pct(items, "cvss_score",  lambda x: bool(x.get("cvss_score")  and float(x.get("cvss_score",  0)) > 0)), 1),
        "epss_pct":   round(field_pct(items, "epss",        lambda x: x.get("epss")  is not None and x.get("epss")  != ""), 1),
        "kev_pct":    round(field_pct(items, "kev",         lambda x: bool(x.get("kev") or x.get("kev_confirmed"))), 1),
        "conf_pct":   round(field_pct(items, "confidence",  lambda x: x.get("confidence") is not None and x.get("confidence") != ""), 1),
        "actor_pct":  round(field_pct(items, "actor_tag",   lambda x: bool((x.get("actor_tag") or x.get("actor") or x.get("threat_actor") or "").strip())), 1),
        "ioc_pct":    round(field_pct(items, "iocs",        lambda x: bool(x.get("iocs") and len(x["iocs"]) > 0)), 1),
        "ttp_pct":    round(field_pct(items, "ttps",        lambda x: (x.get("ttps") and len(x["ttps"]) > 0) or bool(x.get("mitre_tactics"))), 1),
        "sigma_pct":  round(field_pct(items, "sigma_rule",  lambda x: bool(x.get("sigma_rule"))), 1),
        "desc_pct":   round(field_pct(items, "description", lambda x: len(x.get("description", "")) >= 50), 1),
        "cve_ids_pct":round(field_pct(items, "cve_ids",     lambda x: bool(x.get("cve_ids") and len(x["cve_ids"]) > 0) or bool(x.get("cve_id"))), 1),
    }

# ---------------------------------------------------------------------------
# SOURCE DIVERSITY — feed-type-aware
# ---------------------------------------------------------------------------
def source_diversity(items: List[Dict]) -> Dict:
    """Compute source diversity metrics."""
    from collections import Counter
    if not items:
        return {"distinct": 0, "top_dominance_pct": 0.0, "sources": {}}
    n = len(items)
    sources = Counter(x.get("source") or x.get("feed_source", "unknown") for x in items)
    top_dom = 100.0 * sources.most_common(1)[0][1] / n if sources else 0.0
    return {
        "distinct": len(sources),
        "top_dominance_pct": round(top_dom, 1),
        "sources": dict(sources.most_common(10)),
    }

# ---------------------------------------------------------------------------
# SCHEMA DRIFT DETECTOR
# ---------------------------------------------------------------------------
def detect_schema_drift(items: List[Dict]) -> Dict:
    """Find fields in the feed that are NOT in the canonical schema registry."""
    if not items:
        return {"unknown_fields": [], "deprecated_fields": [], "drift_count": 0}
    observed: set = set()
    for it in items:
        observed.update(it.keys())
    known = set(SCHEMA_REGISTRY.keys())
    unknown = sorted(observed - known)
    deprecated = sorted(
        f for f in observed & known
        if SCHEMA_REGISTRY[f].get("deprecated", False)
    )
    return {
        "unknown_fields": unknown,
        "deprecated_fields": deprecated,
        "drift_count": len(unknown),
        "deprecated_count": len(deprecated),
    }
