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
import hashlib
import json
import pathlib
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
# Reused, not re-implemented, per this module's own REUSE MAP convention
# above: anti_hallucination_engine.py's PSEUDO_IOC check already knows
# which reference/vendor/CVE-tracker domains and CVE-ID shapes are not
# real indicators of compromise -- is_pseudo_ioc() below calls these same
# compiled patterns rather than duplicating the detection logic.
from anti_hallucination_engine import (  # noqa: E402
    REFERENCE_URL_PATTERNS as _AHE_REFERENCE_URL_PATTERNS,
    CVE_RE as _AHE_CVE_RE,
)

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
    # v184.4 FIX: gold/silver/standard/executive paths updated to match
    # scripts/generate_tiered_feeds.py's private-staging output location
    # (they used to write to api/feed.*.json, which was PUBLIC in this git
    # repo -- see LEGACY_COMPONENTS.md for the full retirement history).
    "gold": {
        "path": ROOT / "data" / "premium_staging" / "feed.gold.json",
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
        "path": ROOT / "data" / "premium_staging" / "feed.silver.json",
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
        "path": ROOT / "data" / "premium_staging" / "feed.standard.json",
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
        "path": ROOT / "data" / "premium_staging" / "feed.executive.json",
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
    # ── Exposure Intelligence (commercial source connectors) ─────────────────
    # Written by scripts/exposure_intel_enricher.py from the commercially
    # licensed, free-registration sources (Shodan/Censys/ZoomEye/FOFA/
    # BinaryEdge/Netlas/CriminalIP/Onyphe). Absent unless a credential is
    # configured -- the enricher is a no-op without one -- hence nullable
    # and not required. Registered here so an activated source does not
    # register as schema drift in p38's live-feed drift gate.
    "exposure_intel":  {"required": False, "type": "dict",  "domain": "exposure",    "nullable": True,  "version_introduced": "v3.1"},
    "exposure_hosts_total":{"required": False,"type": "int","domain": "exposure",    "nullable": True,  "version_introduced": "v3.1"},
    "exposure_sources_count":{"required": False,"type": "int","domain": "exposure",  "nullable": True,  "version_introduced": "v3.1"},
    "exposure_queried_at":{"required": False,"type": "str", "domain": "exposure",    "nullable": True,  "version_introduced": "v3.1"},

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
# CANONICAL CERTIFICATION FEED RESOLVER
#
# Single entry point for every production certification/quality script to
# resolve the feed it should measure, replacing each script independently
# deciding between data/feed.json (stale snapshot) and api/feed.json (live).
# Phase 1 (PR #219) found p33 silently measuring the stale "root" feed;
# Phase 2 generalises the fix so no sibling script can repeat it.
# ---------------------------------------------------------------------------
DEFAULT_FRESHNESS_TOLERANCE_HOURS = 48.0


class StaleFeedError(RuntimeError):
    """Raised when the canonical certification feed is missing or unreadable.
    Callers must NOT catch this to silently fall back to a different,
    possibly-stale dataset -- that is exactly the Phase 1 regression class."""


@dataclass
class CertificationFeed:
    key: str
    path: pathlib.Path
    items: List[Dict]
    item_count: int
    generated_at: Optional[str]
    age_hours: Optional[float]
    is_fresh: Optional[bool]
    schema_version: Optional[str]
    fingerprint: str


def _feed_fingerprint(items: List[Dict]) -> str:
    """Deterministic short fingerprint of a feed's id set (drift detection)."""
    ids = sorted(str(i.get("id", "")) for i in items if isinstance(i, dict))
    return hashlib.sha256("|".join(ids).encode("utf-8", errors="replace")).hexdigest()[:16]


def get_certification_feed(
    feed_key: str = "live",
    *,
    freshness_tolerance_hours: float = DEFAULT_FRESHNESS_TOLERANCE_HOURS,
) -> CertificationFeed:
    """Canonical resolver for every production certification/quality script.

    Contract:
      - feed_key defaults to "live" (api/feed.json) -- the real production
        feed. Scripts that intentionally measure a different registered
        feed (e.g. a commercial tier) must pass that key explicitly and
        document why in their own header.
      - Explicit failure (StaleFeedError) if the canonical feed file is
        missing or unreadable -- never a silent fallback to a different
        dataset (that silent-fallback pattern is the Phase 1 defect class).
      - Exposes generated_at / age_hours / is_fresh / schema_version /
        item_count / fingerprint so callers can block or downgrade
        certification on stale or drifted input instead of certifying it
        as if it were live.
    """
    reg = FEED_REGISTRY.get(feed_key)
    if not reg:
        raise KeyError(f"Feed key '{feed_key}' not in FEED_REGISTRY")
    path = reg["path"]
    if not path.exists():
        raise StaleFeedError(
            f"Canonical feed '{feed_key}' not found at {path} -- "
            "refusing silent fallback to a different dataset."
        )
    try:
        raw = json.loads(path.read_bytes())
    except Exception as e:
        raise StaleFeedError(f"Canonical feed '{feed_key}' at {path} is unreadable: {e}") from e

    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.get("items", raw.get("data", raw.get("advisories", [])))
    else:
        items = None
    if not isinstance(items, list):
        raise StaleFeedError(
            f"Canonical feed '{feed_key}' at {path} has unexpected root type "
            f"{type(raw).__name__} -- expected a list or a dict with items/data/advisories."
        )

    generated_at = raw.get("generated_at") or raw.get("generatedAt") if isinstance(raw, dict) else None
    if not generated_at:
        candidates = [
            it.get("processed_at") or it.get("timestamp") or it.get("published_at")
            for it in items if isinstance(it, dict)
        ]
        candidates = [c for c in candidates if c]
        generated_at = max(candidates) if candidates else None

    age_hours: Optional[float] = None
    is_fresh: Optional[bool] = None
    if generated_at:
        try:
            dt = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
            is_fresh = age_hours <= freshness_tolerance_hours
        except Exception:
            age_hours, is_fresh = None, None

    schema_version = raw.get("schema_version") if isinstance(raw, dict) else None
    if not schema_version and items:
        schema_version = next(
            (it.get("schema_version") for it in items
             if isinstance(it, dict) and it.get("schema_version")),
            None,
        )

    return CertificationFeed(
        key=feed_key,
        path=path,
        items=items,
        item_count=len(items),
        generated_at=generated_at,
        age_hours=round(age_hours, 2) if age_hours is not None else None,
        is_fresh=is_fresh,
        schema_version=schema_version,
        fingerprint=_feed_fingerprint(items),
    )


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
# REPORT/SOURCE URL CONTRACT — Single Source of Truth
#
# report_url  = CYBERDUDEBIVASH-owned published intelligence report location.
# source_url  = external evidence / advisory location (GitHub Advisories,
#               vendor blogs, etc.).  These are NEVER interchangeable:
#               report_url must never be set to an external source_url as a
#               "better than empty" fallback (P0 regression class — see
#               scripts/sync_report_urls.py history).
#
# Canonical definition, matching validate_repo.py V10/V11 and
# manifest_url_repair.py's existing guards: a report_url is "owned" if it is
# a relative /reports/... path, or an absolute https:// URL whose host is a
# CYBERDUDEBIVASH-owned domain.  OWNED_HOST_MARKER intentionally matches by
# substring (not exact host) because the platform legitimately publishes
# reports across multiple cyberdudebivash.com subdomains (intel., reports.,
# etc.) — do not narrow this to one hardcoded domain.
# ---------------------------------------------------------------------------
OWNED_HOST_MARKER = "cyberdudebivash"


def is_owned_report_url(url: Optional[str]) -> bool:
    """True if `url` is a CYBERDUDEBIVASH-owned report location (relative
    /reports/... path, or absolute https:// URL on an owned domain)."""
    if not url or not isinstance(url, str):
        return False
    if url.startswith("/reports/"):
        return True
    if url.startswith("https://") and OWNED_HOST_MARKER in url:
        return True
    return False


def is_external_report_url(url: Optional[str]) -> bool:
    """True if `url` is a non-empty http(s) URL that is NOT CYBERDUDEBIVASH-owned
    (i.e. it points at an external source and must never populate report_url)."""
    if not url or not isinstance(url, str):
        return False
    return url.startswith("http") and OWNED_HOST_MARKER not in url


# ---------------------------------------------------------------------------
# CURRENT-VS-LEGACY FIELD ACCESSORS
#
# p33_production_certification.py already established the correct pattern
# (current field first, deprecated field as fallback -- never the reverse)
# independently in four places (G07, G18's _enrich(), G22, G23). Phase 2
# found the identical stale-field defect in six sibling scripts (p27-p32,
# p36) still checking ONLY the deprecated pair. These accessors are that
# proven pattern extracted once, so every certification script agrees on
# exactly one definition instead of re-deriving (or forgetting) it.
# ---------------------------------------------------------------------------
def has_mitre_coverage(item: Dict) -> bool:
    """True if `item` carries MITRE ATT&CK data under either the current
    fields (attck_technique_ids/attck_techniques) or the deprecated pair
    (mitre_tactics/ttps) kept as a fallback per the Deprecation Instead of
    Deletion policy -- never the deprecated pair alone."""
    return bool(
        item.get("attck_technique_ids") or item.get("attck_techniques")
        or item.get("mitre_tactics") or item.get("ttps")
    )


# Report categories where a MITRE ATT&CK technique mapping AND a real IOC
# are plausible -- the content describes a concrete technical vulnerability
# or attacker behavior. Shared between attck_eligible() and
# is_ioc_eligible() since both ask the same underlying question ("does
# this content have a technical/behavioral hook to extract from"). Pure
# commentary/news pieces with no CVE, no vuln_class, and no attack-relevant
# threat_type are NOT eligible for either: forcing a mapping or an
# indicator onto them would be fabrication, not coverage (the mandate
# explicitly allows 0 ATT&CK/0 IOC for news when evidence doesn't support
# one -- that is a correct outcome, not a defect to paper over).
_TECHNICAL_THREAT_TYPES = {
    "cve", "vulnerability", "ransomware", "malware", "threat intel",
    "threat intelligence", "phishing-url", "phishing", "kev",
    "oss-advisory", "data breach", "remote code execution",
    "web application attack", "malicious url", "cloud security",
    "ics/ot", "supply chain", "zero-day", "zero day", "botnet",
}


def attck_eligible(item: Dict) -> bool:
    """True if `item` is of a report type/content class where a MITRE
    ATT&CK technique mapping is plausible. Mirrors is_detection_eligible's
    role for detection coverage: the point is to report
    eligible-vs-mapped, never raw-items-vs-mapped, since an ineligible item
    correctly has 0 techniques."""
    if get_cve_ids(item):
        return True
    if item.get("vuln_class"):
        return True
    tt = str(item.get("threat_type") or "").strip().lower()
    return tt in _TECHNICAL_THREAT_TYPES


def attck_mapping_state(item: Dict) -> str:
    """Evidence-bound schema state for `item`'s ATT&CK mapping:
      NOT_ELIGIBLE -- content class has no plausible technique mapping
      UNMAPPED     -- eligible, but no technique present (0 is honest here)
      LEGACY_ONLY  -- technique(s) present only in the deprecated
                      mitre_tactics/ttps fields, not the current schema
      MAPPED       -- technique(s) present in the current
                      attck_technique_ids/attck_techniques fields
    This is the field-schema dimension only -- it does not independently
    verify per-technique evidence quality (OBSERVED/REPORTED/INFERRED),
    which lives on each technique entry's own verification_status/
    confidence field where the producing engine supplies one (e.g.
    attack_mapping_validator.py's verification_status, or
    apex_mitre_attack_engine.py's confidence)."""
    if not attck_eligible(item):
        return "NOT_ELIGIBLE"
    if item.get("attck_technique_ids") or item.get("attck_techniques"):
        return "MAPPED"
    if item.get("mitre_tactics") or item.get("ttps"):
        return "LEGACY_ONLY"
    return "UNMAPPED"


def attck_coverage_summary(items: List[Dict]) -> Dict:
    """Numerator+denominator ATT&CK coverage breakdown -- never a bare
    percentage. Reports eligible/mapped/legacy_only/unmapped/not_eligible
    counts so a reader can see both the honest eligible-item coverage rate
    AND how much of that coverage rests on the deprecated field pair
    rather than the current schema."""
    total = len(items)
    counts: Dict[str, int] = {"NOT_ELIGIBLE": 0, "UNMAPPED": 0, "LEGACY_ONLY": 0, "MAPPED": 0}
    for it in items:
        counts[attck_mapping_state(it)] += 1
    eligible_total = total - counts["NOT_ELIGIBLE"]
    covered_any = counts["MAPPED"] + counts["LEGACY_ONLY"]
    return {
        "total_items": total,
        "eligible_items": eligible_total,
        "not_eligible_items": counts["NOT_ELIGIBLE"],
        "covered_items_any_field": covered_any,
        "covered_items_current_schema": counts["MAPPED"],
        "covered_items_legacy_field_only": counts["LEGACY_ONLY"],
        "unmapped_eligible_items": counts["UNMAPPED"],
        "eligible_coverage_pct": round(covered_any / eligible_total * 100, 1) if eligible_total else 0.0,
        "current_schema_coverage_pct": round(counts["MAPPED"] / eligible_total * 100, 1) if eligible_total else 0.0,
    }


def is_pseudo_ioc(ioc_value: str, item: Optional[Dict] = None) -> bool:
    """True if `ioc_value` is a reference identifier masquerading as an
    indicator of compromise, not a real IOC:
      - a bare CVE ID (a vulnerability reference, not an indicator)
      - a known vendor/NVD/CISA/threat-intel-blog reference URL (reuses
        anti_hallucination_engine.py's REFERENCE_URL_PATTERNS/CVE_RE)
      - (when `item` is given) identical to the item's OWN source_url --
        an article can never be malicious infrastructure it is reporting
        on, regardless of which domain hosts it, so this catches the same
        violation class for domains outside the fixed reference-URL list.
        Confirmed present in live data: 175/500 api/feed.json items (35%)
        had an IOC whose value was exactly their own source_url (mostly
        cvefeed.io CVE-detail pages reported as "url"-type indicators).
    Does NOT flag a URL just because it matches an item's source_url when
    that item is itself a URL-flagging feed (OpenPhish/URLhaus), where the
    "source" and the malicious indicator are legitimately the same URL --
    those items set iocs directly during ingestion from the value being
    reported on, not as a fallback padding pattern, so this function is
    intentionally scoped to reference-identifier detection, not a blanket
    "matches source_url" rule applied without that context."""
    if not ioc_value:
        return False
    v = str(ioc_value).strip()
    if _AHE_CVE_RE.match(v):
        return True
    if _AHE_REFERENCE_URL_PATTERNS.search(v):
        return True
    if item:
        src = str(item.get("source_url") or "").strip()
        tt = str(item.get("threat_type") or "").strip().upper()
        if src and v.rstrip("/") == src.rstrip("/") and tt not in ("PHISHING-URL", "MALWARE-URL", "MALICIOUS URL"):
            return True
    return False


def is_ioc_eligible(item: Dict) -> bool:
    """True if `item` is of a report type/content class where a real IOC
    (IP/domain/URL/hash distinct from the item's own reference link) is
    plausibly extractable. Mirrors attck_eligible/is_detection_eligible:
    the point is to report eligible-vs-populated, never
    raw-items-vs-populated, since a pure commentary/news item correctly
    has 0 IOCs."""
    if get_cve_ids(item):
        return True
    tt = str(item.get("threat_type") or "").strip().lower()
    return tt in _TECHNICAL_THREAT_TYPES


def ioc_coverage_summary(items: List[Dict]) -> Dict:
    """Numerator+denominator IOC coverage breakdown -- never a bare
    percentage. Separates genuinely populated IOCs from pseudo-IOCs (a
    reference URL or CVE ID counted as if it were a real indicator), so a
    reader can see both the honest eligible-item coverage rate AND how
    much of the raw ioc_count is inflated by non-indicator values."""
    total = len(items)
    eligible = 0
    real_covered = 0
    pseudo_only = 0
    for it in items:
        if not is_ioc_eligible(it):
            continue
        eligible += 1
        iocs = it.get("iocs") or []
        real = [i for i in iocs if not is_pseudo_ioc(i.get("value", ""), it)]
        if real:
            real_covered += 1
        elif iocs:
            pseudo_only += 1
    return {
        "total_items": total,
        "eligible_items": eligible,
        "not_eligible_items": total - eligible,
        "covered_items_real_ioc": real_covered,
        "items_pseudo_ioc_only": pseudo_only,
        "unmapped_eligible_items": eligible - real_covered - pseudo_only,
        "eligible_coverage_pct": round(real_covered / eligible * 100, 1) if eligible else 0.0,
    }


def has_source_url(item: Dict) -> bool:
    """True if `item` has a usable source_url (the actual link) -- distinct
    from `source`, which is only a short display label."""
    su = item.get("source_url")
    return bool(su and isinstance(su, str) and su.strip())


def get_detection_rules_total(item: Dict) -> int:
    """Current detection_rules_total (int-coerced defensively -- observed as
    both int and string in real data), falling back to the legacy
    detection_bundle field, and -- Phase 4.1 mandate Section 12 fix -- as a
    final fallback, a count of the CURRENT per-item rule fields
    detection_bundle_injector.py actually writes (sigma_rule, kql_query,
    suricata_rule, yara_rule).

    Root cause (confirmed by direct inspection of the live feed, not
    assumed): detection_rules_total/detection_bundle exist on ZERO items in
    the current feed, while sigma_rule/kql_query/suricata_rule carry real
    content on 86 -- exactly the "0.0% detection coverage" figure reported
    everywhere upstream of this accessor all session was this field-name
    drift, not an absence of detection content. This is the exact class of
    defect Section 12 names explicitly ("detection_rules, detection_rules_
    total, detection_bundle, sigma_rules, detections, detection_pack, or
    current equivalents... never silently count the same rule twice").
    Counts distinct rule TYPES present (0-4), never the same rule twice."""
    val = item.get("detection_rules_total")
    if val is None:
        val = item.get("detection_bundle")
    if val is not None:
        try:
            return int(val)
        except (TypeError, ValueError):
            pass
    return sum(1 for k in ("sigma_rule", "kql_query", "suricata_rule", "yara_rule") if item.get(k))


def has_detection_rules(item: Dict) -> bool:
    return get_detection_rules_total(item) > 0


def is_detection_eligible(item: Dict) -> bool:
    """True if `item` is of a report type where a detection artifact is
    plausibly applicable -- CVE-referenced or vuln_class-classified content
    (the two signals confirmed, by direct inspection of the live feed
    during the Phase 2 detection-coverage investigation, to exactly track
    which items the existing detection_bundle_injector.py generator treats
    as in-scope). Generic/news/non-operational items (no CVE, no vuln
    class) are not expected to carry a rule, so counting them in a coverage
    denominator understates real coverage -- see mandate: report both
    eligible_detection_items and items_with_valid_detection, never a
    raw over-total-feed percentage alone."""
    if get_cve_ids(item):
        return True
    if item.get("vuln_class"):
        return True
    return False


# ---------------------------------------------------------------------------
# CANONICAL SCHEMA ACCESSORS (Phase 4.1 mandate Section 27) -- "central
# helpers... do not scatter fallback logic across 40 scripts." Each accessor
# below is the SINGLE place cve-id / ioc-count / confidence-scale fallback
# logic lives; new code should call these instead of re-deriving field
# fallbacks inline (matching this module's own existing REUSE MAP doctrine).
# Canonical-vs-legacy field decisions are read from SCHEMA_REGISTRY above
# (cve_ids canonical, cves deprecated->cve_ids; confidence canonical,
# confidence_score deprecated->confidence) -- these accessors do not
# redecide that, they implement it once.
# ---------------------------------------------------------------------------

def get_cve_ids(item: Dict) -> List[str]:
    """Canonical CVE-identifier accessor. cve_ids (list) and cves (list,
    SCHEMA_REGISTRY-deprecated alias of cve_ids) are merged with the
    singular cve_id, de-duplicated (case-insensitive, output upper-cased),
    order preserved, list-first then singular. Never raises; a malformed
    or absent field simply contributes nothing."""
    ids: List[str] = []
    seen: set = set()
    for key in ("cve_ids", "cves"):
        raw = item.get(key)
        if isinstance(raw, list):
            for v in raw:
                s = str(v).strip().upper()
                if s and s not in seen:
                    seen.add(s)
                    ids.append(s)
    single = item.get("cve_id")
    if single:
        s = str(single).strip().upper()
        if s and s not in seen:
            seen.add(s)
            ids.append(s)
    return ids


def get_ioc_count(item: Dict) -> int:
    """Canonical IOC-count accessor. Mandate Section 25: never trust a
    persisted count that can drift from the actual IOC collection -- when
    an `iocs` array is present, its length is authoritative regardless of
    what any stored count field says. Only falls back to a stored count
    (ioc_count, then real_ioc_count, then the deprecated indicator_count)
    for the leaner schemas that carry no iocs array at all."""
    iocs = item.get("iocs")
    if isinstance(iocs, list):
        return len(iocs)
    for key in ("ioc_count", "real_ioc_count", "indicator_count"):
        v = item.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
            return int(v)
    return 0


def get_confidence_normalized(item: Dict) -> Optional[float]:
    """Canonical confidence accessor, normalized to [0.0, 1.0]. Reproduces
    the scale-detection + validity logic p25_enterprise_trust_gate.py's G2
    gate uses (the fix for the "803% average confidence" cross-producer
    scale-mismatch bug: some producers write confidence as a 0-1 fraction,
    others as a 0-100 percentage). Returns None -- never a clamped guess --
    for an absent, non-numeric, non-finite (NaN/Infinity), or out-of-
    [0,100]-range value; callers that must distinguish "absent" from
    "present but invalid" should inspect item.get("confidence") directly."""
    v = item.get("confidence")
    if v is None:
        v = item.get("confidence_score")  # SCHEMA_REGISTRY-deprecated alias
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if not (v == v) or v in (float("inf"), float("-inf")) or not (0.0 <= v <= 100.0):
        return None
    return v / 100.0 if v > 1.0 else v


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
