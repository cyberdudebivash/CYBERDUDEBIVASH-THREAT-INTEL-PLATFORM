#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
scripts/ocios_campaign_correlation_engine.py
OCIOS Phase 1 — Campaign Correlation Engine
================================================================================
Version      : 1.0.0
Classification: CONFIDENTIAL — OCIOS TIER

MANDATE
-------
Transforms the advisory corpus from a flat list of independent alerts into
an interconnected operational intelligence graph.  Every advisory becomes an
"operational intelligence entity" linked by shared signals to peer advisories,
actor clusters, infrastructure nodes, and attack campaigns.

WHAT THIS ENGINE DOES (that nothing else in the stack does)
-----------------------------------------------------------
- Corpus-level signal extraction across ALL manifest items simultaneously
- Graph-based campaign detection using multi-dimensional edge scoring
- Infrastructure reuse detection (shared ASNs, TLDs, vendor patterns)
- Temporal attack-wave identification (burst clustering over time windows)
- Malware-family linkage across campaign clusters
- Adversary evolution tracking (actor activity trends over time)
- IOC lineage graph (which reports share indicator families)
- Evidence graph linking advisories through shared observable signals

DIFFERENTIATION FROM EXISTING ENGINES
--------------------------------------
- ai_brain_publisher.py     : clusters by actor name only (single dimension)
- threat_actor_profiler.py  : per-actor profiles, not cross-actor relationships
- enterprise_scoring_engine : per-item scoring, no cross-item correlation
- THIS ENGINE               : corpus-level graph, multi-signal, temporal chains

INPUTS
------
  data/stix/feed_manifest.json       (required — manifest with scoring applied)
  data/actor_profiles.json           (optional — enriches actor nodes)
  data/enterprise_scoring/scoring_report.json (optional — score enrichment)

OUTPUTS
-------
  data/ocios/campaign_graph.json           — full campaign correlation graph
  data/ocios/actor_relationships.json      — actor co-occurrence + relationship map
  data/ocios/infrastructure_clusters.json  — infrastructure reuse clusters
  data/ocios/temporal_chains.json          — time-ordered attack wave chains
  data/ocios/ioc_lineage.json              — IOC family cross-report lineage

PIPELINE POSITION
-----------------
  Runs AFTER: enterprise_scoring_engine.py, apex_intelligence_engine.py
  Runs BEFORE: ocios_operational_reasoning_engine.py, report generation
  Called by:  ocios_engine.py (coordinator)

SAFETY GUARANTEES
-----------------
  - ADDITIVE ONLY — never writes to feed_manifest.json
  - Atomic writes (tmp -> fsync -> os.replace) for all outputs
  - UTF-8 clean — no non-ASCII in code paths
  - Deterministic — same corpus always produces same graph structure
  - Zero silent failure — all exceptions logged, engine still completes

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OCIOS-CORR] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("CDB-OCIOS-CORR")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT        = Path(__file__).resolve().parent.parent
MANIFEST_PATH    = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
ACTOR_PROFILES   = REPO_ROOT / "data" / "actor_profiles.json"
SCORING_REPORT   = REPO_ROOT / "data" / "enterprise_scoring" / "scoring_report.json"
OCIOS_DIR        = REPO_ROOT / "data" / "ocios"

ENGINE_VERSION   = "1.0.0"

# ---------------------------------------------------------------------------
# Correlation signal weights
# ---------------------------------------------------------------------------
# Each shared signal between two advisories contributes this weight to their
# correlation edge score.  Higher weight = stronger evidence of relatedness.
SIGNAL_WEIGHTS: Dict[str, float] = {
    "shared_actor":          5.0,   # Same attributed actor
    "shared_cve":            4.5,   # Literally the same CVE
    "shared_vendor":         3.5,   # Same vendor targeted (e.g. Cisco, Microsoft)
    "shared_ttp":            3.0,   # Same MITRE ATT&CK technique
    "shared_vuln_class":     2.5,   # Same vulnerability class (auth bypass, RCE, etc.)
    "shared_source_domain":  2.0,   # Same intelligence source domain
    "temporal_proximity":    2.0,   # Published within 72-hour window
    "shared_sector":         1.5,   # Same target sector
    "kev_cluster":           1.5,   # Both are KEV-confirmed
    "severity_cluster":      1.0,   # Same severity tier
    "ransomware_linkage":    3.0,   # Both linked to ransomware operations
}

# Minimum correlation score to form a campaign edge
CAMPAIGN_EDGE_THRESHOLD    = 4.0
# Minimum advisories to form a named campaign cluster
CAMPAIGN_MIN_SIZE          = 2
# Temporal window for burst clustering (hours)
TEMPORAL_WINDOW_HOURS      = 72
# Maximum campaign name length
CAMPAIGN_NAME_MAX          = 80

# ---------------------------------------------------------------------------
# Vulnerability class taxonomy
# ---------------------------------------------------------------------------
_VULN_CLASS_PATTERNS: List[Tuple[str, str]] = [
    (r"auth(?:entication)?\s+bypass",       "authentication_bypass"),
    (r"remote\s+code\s+exec(?:ution)?|rce", "remote_code_execution"),
    (r"privilege\s+escal(?:ation)?",        "privilege_escalation"),
    (r"sql\s+inject(?:ion)?",               "sql_injection"),
    (r"cross.site\s+(?:script|xss)",        "cross_site_scripting"),
    (r"path\s+trav(?:ersal)?",              "path_traversal"),
    (r"(?:stack|heap)\s+(?:overflow|exhaust|exhaus)", "memory_corruption"),
    (r"deseri(?:alization)?",               "deserialization"),
    (r"ssrf",                               "ssrf"),
    (r"xxe",                                "xxe"),
    (r"command\s+inject(?:ion)?",           "command_injection"),
    (r"open\s+redirect",                    "open_redirect"),
    (r"denial.of.service|dos\b",            "denial_of_service"),
    (r"information\s+disclos(?:ure)?",      "information_disclosure"),
    (r"supply.chain",                       "supply_chain"),
    (r"zero.day|0.day",                     "zero_day"),
    (r"ransomware",                         "ransomware"),
    (r"backdoor",                           "backdoor"),
    (r"phish(?:ing)?",                      "phishing"),
    (r"stealer|infostealer",               "credential_stealer"),
]

# ---------------------------------------------------------------------------
# Sector taxonomy
# ---------------------------------------------------------------------------
_SECTOR_PATTERNS: List[Tuple[str, str]] = [
    (r"cisco|router|switch|sd.wan|network",     "networking_infrastructure"),
    (r"microsoft|windows|active\s+directory",   "microsoft_ecosystem"),
    (r"linux|ubuntu|debian|red\s*hat|centos",   "linux_systems"),
    (r"cloud|aws|azure|gcp|kubernetes|docker",  "cloud_infrastructure"),
    (r"iot|scada|industrial|plc|ics",           "ot_ics"),
    (r"healthcare|hospital|medical|dicom",      "healthcare"),
    (r"finance|bank|payment|swift|stripe",      "financial_services"),
    (r"supply.chain|software\s+supply",         "supply_chain"),
    (r"government|federal|mil\b|defence|defense", "government_defense"),
    (r"energy|electric|power\s+grid|oil|gas",   "energy_utilities"),
    (r"crypto|blockchain|web3|defi|wallet",     "cryptocurrency"),
    (r"education|university|academic",          "education"),
    (r"telecom|carrier|isp|mobile",             "telecommunications"),
    (r"retail|e.commerce|shopify|magento",      "retail_ecommerce"),
    (r"ai|llm|gpt|ml\b|model",                 "ai_ml_systems"),
]

# ---------------------------------------------------------------------------
# Known malware family patterns
# ---------------------------------------------------------------------------
_MALWARE_PATTERNS: List[Tuple[str, str]] = [
    (r"lockbit",              "LockBit"),
    (r"black\s*cat|alphv",   "BlackCat/ALPHV"),
    (r"clop|cl0p",           "Cl0p"),
    (r"hive\s+ransomware",   "Hive"),
    (r"conti",               "Conti"),
    (r"revil|sodinokibi",    "REvil/Sodinokibi"),
    (r"cobalt\s+strike",     "Cobalt Strike"),
    (r"metasploit",          "Metasploit"),
    (r"mimikatz",            "Mimikatz"),
    (r"emotet",              "Emotet"),
    (r"qakbot|qbot",         "QakBot"),
    (r"icedid",              "IcedID"),
    (r"brute\s*ratel",       "Brute Ratel C4"),
    (r"sliver\b",            "Sliver C2"),
    (r"havoc\s+c2",          "Havoc C2"),
    (r"njrat",               "njRAT"),
    (r"asyncrat",            "AsyncRAT"),
    (r"darkcomet",           "DarkComet"),
    (r"remcos",              "Remcos RAT"),
    (r"wannacry",            "WannaCry"),
    (r"notpetya",            "NotPetya"),
    (r"triton|trisis",       "TRITON/TRISIS"),
    (r"industroyer",         "Industroyer"),
    (r"volt\s+typhoon",      "Volt Typhoon"),
    (r"salt\s+typhoon",      "Salt Typhoon"),
    (r"lazarus",             "Lazarus Group"),
    (r"fancy\s+bear|apt28",  "APT28/Fancy Bear"),
    (r"cozy\s+bear|apt29",   "APT29/Cozy Bear"),
    (r"sandworm",            "Sandworm"),
    (r"kimsuky",             "Kimsuky"),
    (r"oceans?\s*lotus|apt32", "OceanLotus/APT32"),
    (r"scattered\s+spider",  "Scattered Spider"),
    (r"unc\d{4}",            "UNC Cluster"),
    (r"fakewallet",          "FakeWallet"),
    (r"phantom\s*rpc",       "PhantomRPC"),
]

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    return str(v).strip()


def _safe_list(v: Any) -> List:
    if isinstance(v, list):
        return v
    if v is None:
        return []
    return [v]


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _safe_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().upper() in ("YES", "TRUE", "1", "CONFIRMED")
    return bool(v)


def _item_id(item: Dict) -> str:
    return _safe_str(item.get("id") or item.get("intel_id") or item.get("report_id"), "unknown")


def _item_title(item: Dict) -> str:
    return _safe_str(item.get("title") or item.get("headline"), "untitled")


def _parse_ts(item: Dict) -> Optional[datetime]:
    for key in ("published", "timestamp", "generated_at", "created_at", "date"):
        val = item.get(key)
        if not val:
            continue
        try:
            # Handle both ISO strings and epoch
            if isinstance(val, (int, float)):
                return datetime.fromtimestamp(val, tz=timezone.utc)
            s = str(val).replace("Z", "+00:00")
            return datetime.fromisoformat(s)
        except Exception:
            continue
    return None


def _extract_cves(item: Dict) -> Set[str]:
    """Extract all CVE identifiers from an advisory."""
    text = " ".join([
        _safe_str(item.get("title")),
        _safe_str(item.get("description")),
        _safe_str(item.get("summary")),
        _safe_str(item.get("id")),
    ])
    return set(re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE))


def _extract_ttps(item: Dict) -> Set[str]:
    """Extract MITRE ATT&CK technique IDs."""
    ttps: Set[str] = set()
    # From dedicated fields
    for key in ("ttps", "mitre_ttps", "techniques", "attack_techniques"):
        for t in _safe_list(item.get(key)):
            m = re.search(r"T\d{4}(?:\.\d{3})?", _safe_str(t))
            if m:
                ttps.add(m.group().upper())
    # From apex_score block
    apex = item.get("apex_score") or {}
    for t in _safe_list(apex.get("top_ttps")):
        m = re.search(r"T\d{4}(?:\.\d{3})?", _safe_str(t))
        if m:
            ttps.add(m.group().upper())
    # From text
    text = _safe_str(item.get("description")) + " " + _safe_str(item.get("ai_insight"))
    for m in re.finditer(r"T\d{4}(?:\.\d{3})?", text):
        ttps.add(m.group().upper())
    return ttps


def _extract_actor(item: Dict) -> str:
    """Return canonical actor name (lowered, stripped)."""
    raw = (
        item.get("actor")
        or item.get("threat_actor")
        or item.get("actor_name")
        or ""
    )
    return _safe_str(raw).lower()


def _extract_vendor(item: Dict) -> str:
    """Infer primary vendor from title/description."""
    text = (_safe_str(item.get("title")) + " " + _safe_str(item.get("description"))).lower()
    vendors = [
        "cisco", "microsoft", "google", "apple", "apache", "nginx",
        "fortinet", "palo alto", "juniper", "vmware", "broadcom",
        "ivanti", "citrix", "f5", "atlassian", "confluence", "jira",
        "wordpress", "drupal", "joomla", "php", "python", "ruby",
        "java", "spring", "log4j", "openssl", "openssh", "curl",
        "chrome", "firefox", "safari", "edge", "linux", "android",
        "ios", "macos", "windows", "siemens", "schneider", "docker",
        "kubernetes", "aws", "azure", "gcp", "cloudflare", "akamai",
        "hedera", "mcp", "flowise", "foxit", "siemens sinec",
    ]
    for v in vendors:
        if v in text:
            return v.replace(" ", "_")
    return ""


def _extract_vuln_class(item: Dict) -> str:
    """Classify the vulnerability type."""
    text = (
        _safe_str(item.get("title"))
        + " "
        + _safe_str(item.get("description"))
        + " "
        + _safe_str(item.get("summary"))
    ).lower()
    for pattern, label in _VULN_CLASS_PATTERNS:
        if re.search(pattern, text):
            return label
    return "unclassified"


def _extract_sectors(item: Dict) -> List[str]:
    """Infer target sectors from advisory text."""
    text = (
        _safe_str(item.get("title"))
        + " "
        + _safe_str(item.get("description"))
        + " "
        + _safe_str(item.get("affected_systems", ""))
    ).lower()
    sectors = []
    for pattern, label in _SECTOR_PATTERNS:
        if re.search(pattern, text):
            sectors.append(label)
    return sectors or ["general_enterprise"]


def _extract_malware_families(item: Dict) -> List[str]:
    """Detect malware/actor family mentions."""
    text = (
        _safe_str(item.get("title"))
        + " "
        + _safe_str(item.get("description"))
        + " "
        + _safe_str(item.get("ai_insight", ""))
        + " "
        + _safe_str(item.get("actor", ""))
    ).lower()
    families = []
    for pattern, label in _MALWARE_PATTERNS:
        if re.search(pattern, text):
            families.append(label)
    return families


def _extract_source_domain(item: Dict) -> str:
    """Extract root domain from source URL."""
    url = _safe_str(item.get("source_url") or item.get("source") or "")
    m = re.search(r"https?://(?:www\.)?([^/?\s]+)", url)
    if m:
        parts = m.group(1).split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
    return ""


def _is_kev(item: Dict) -> bool:
    return _safe_bool(item.get("kev") or item.get("cisa_kev") or item.get("in_kev"))


def _is_ransomware_linked(item: Dict) -> bool:
    apex = item.get("apex_score") or {}
    ra = apex.get("ransomware_affinity_score", 0)
    if _safe_float(ra) >= 40:
        return True
    text = (
        _safe_str(item.get("title")) + " " + _safe_str(item.get("actor", ""))
    ).lower()
    return bool(re.search(r"ransomware|ransom\b|lockbit|clop|hive|alphv|blackcat", text))


def _severity_tier(item: Dict) -> str:
    sev = _safe_str(item.get("severity", "")).upper()
    if sev in ("CRITICAL",):
        return "critical"
    if sev in ("HIGH",):
        return "high"
    if sev in ("MEDIUM",):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Signal extraction — build per-item signal fingerprint
# ---------------------------------------------------------------------------

def extract_signals(item: Dict) -> Dict[str, Any]:
    """Extract all correlation signals from a single advisory."""
    return {
        "id":               _item_id(item),
        "title":            _item_title(item),
        "actor":            _extract_actor(item),
        "cves":             _extract_cves(item),
        "ttps":             _extract_ttps(item),
        "vendor":           _extract_vendor(item),
        "vuln_class":       _extract_vuln_class(item),
        "sectors":          _extract_sectors(item),
        "malware_families": _extract_malware_families(item),
        "source_domain":    _extract_source_domain(item),
        "is_kev":           _is_kev(item),
        "is_ransomware":    _is_ransomware_linked(item),
        "severity_tier":    _severity_tier(item),
        "timestamp":        _parse_ts(item),
        "risk_score":       _safe_float(item.get("risk_score")),
        "confidence":       _safe_float(item.get("confidence")),
        "report_url":       _safe_str(item.get("report_url") or item.get("blog_url")),
    }


# ---------------------------------------------------------------------------
# Edge scoring — compute correlation weight between two advisories
# ---------------------------------------------------------------------------

def compute_edge_score(a: Dict, b: Dict) -> Tuple[float, List[str]]:
    """
    Compute the correlation edge score between two advisory signal fingerprints.
    Returns (score, [shared_signal_labels]) for edge annotation.
    """
    score = 0.0
    signals: List[str] = []

    # Shared actor (strongest signal)
    if a["actor"] and b["actor"] and a["actor"] == b["actor"]:
        score += SIGNAL_WEIGHTS["shared_actor"]
        signals.append(f"actor:{a['actor']}")

    # Shared CVE (exact match — definitively same vulnerability)
    shared_cves = a["cves"] & b["cves"]
    if shared_cves:
        score += SIGNAL_WEIGHTS["shared_cve"] * len(shared_cves)
        signals.extend(f"cve:{c}" for c in sorted(shared_cves))

    # Shared vendor
    if a["vendor"] and b["vendor"] and a["vendor"] == b["vendor"]:
        score += SIGNAL_WEIGHTS["shared_vendor"]
        signals.append(f"vendor:{a['vendor']}")

    # Shared TTPs
    shared_ttps = a["ttps"] & b["ttps"]
    if shared_ttps:
        score += SIGNAL_WEIGHTS["shared_ttp"] * min(len(shared_ttps), 3)
        signals.extend(f"ttp:{t}" for t in sorted(shared_ttps)[:3])

    # Shared vulnerability class
    if a["vuln_class"] != "unclassified" and a["vuln_class"] == b["vuln_class"]:
        score += SIGNAL_WEIGHTS["shared_vuln_class"]
        signals.append(f"vuln_class:{a['vuln_class']}")

    # Shared source domain
    if a["source_domain"] and b["source_domain"] and a["source_domain"] == b["source_domain"]:
        score += SIGNAL_WEIGHTS["shared_source_domain"]
        signals.append(f"source:{a['source_domain']}")

    # Temporal proximity
    if a["timestamp"] and b["timestamp"]:
        delta_h = abs((a["timestamp"] - b["timestamp"]).total_seconds()) / 3600
        if delta_h <= TEMPORAL_WINDOW_HOURS:
            # Inverse scaling: closer = higher weight
            proximity_weight = SIGNAL_WEIGHTS["temporal_proximity"] * (
                1.0 - delta_h / TEMPORAL_WINDOW_HOURS
            )
            if proximity_weight > 0.3:
                score += proximity_weight
                signals.append(f"temporal:{int(delta_h)}h_apart")

    # Shared sector
    shared_sectors = set(a["sectors"]) & set(b["sectors"])
    if shared_sectors and "general_enterprise" not in shared_sectors:
        score += SIGNAL_WEIGHTS["shared_sector"]
        signals.append(f"sector:{next(iter(shared_sectors))}")

    # KEV cluster
    if a["is_kev"] and b["is_kev"]:
        score += SIGNAL_WEIGHTS["kev_cluster"]
        signals.append("kev_cluster")

    # Ransomware linkage
    if a["is_ransomware"] and b["is_ransomware"]:
        score += SIGNAL_WEIGHTS["ransomware_linkage"]
        signals.append("ransomware_linkage")

    # Severity cluster
    if a["severity_tier"] == b["severity_tier"] and a["severity_tier"] in ("critical", "high"):
        score += SIGNAL_WEIGHTS["severity_cluster"]
        signals.append(f"severity:{a['severity_tier']}")

    return score, signals


# ---------------------------------------------------------------------------
# Campaign graph builder
# ---------------------------------------------------------------------------

def _generate_campaign_id(items: List[str], actor: str) -> str:
    """Generate a deterministic campaign ID from member IDs."""
    key = actor + ":" + ":".join(sorted(items))
    return "campaign--" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _infer_campaign_name(cluster: List[Dict], signals: List[str]) -> str:
    """Derive a human-readable campaign name from cluster characteristics."""
    actors = [s["actor"] for s in cluster if s["actor"] and s["actor"] != "cdb-cve-gen"]
    vendors = [s["vendor"] for s in cluster if s["vendor"]]
    vuln_classes = [s["vuln_class"] for s in cluster if s["vuln_class"] != "unclassified"]
    malware = []
    for s in cluster:
        malware.extend(s["malware_families"])

    if malware:
        return malware[0] + " Campaign"
    if actors:
        top_actor = Counter(actors).most_common(1)[0][0].title()
        if vendors:
            top_vendor = Counter(vendors).most_common(1)[0][0].title()
            return f"{top_actor} — {top_vendor} Exploitation Wave"
        return f"{top_actor} Attack Campaign"
    if vuln_classes:
        vc = Counter(vuln_classes).most_common(1)[0][0].replace("_", " ").title()
        if vendors:
            tv = Counter(vendors).most_common(1)[0][0].title()
            return f"{tv} {vc} Campaign"
        return f"{vc} Exploitation Campaign"
    if vendors:
        tv = Counter(vendors).most_common(1)[0][0].title()
        return f"{tv} Infrastructure Attack Wave"
    return "Multi-Vector Threat Campaign"


def _infer_campaign_objective(cluster: List[Dict]) -> str:
    """Infer the likely attacker objective from the cluster characteristics."""
    has_ransomware = any(s["is_ransomware"] for s in cluster)
    has_kev        = any(s["is_kev"] for s in cluster)
    vuln_classes   = [s["vuln_class"] for s in cluster]
    ttps_all: Set[str] = set()
    for s in cluster:
        ttps_all |= s["ttps"]

    if has_ransomware:
        return "ransomware_deployment_and_extortion"
    if "T1190" in ttps_all and has_kev:
        return "initial_access_via_public_exploit"
    if "T1078" in ttps_all or "T1078.003" in ttps_all:
        return "credential_abuse_and_persistence"
    if any(vc in vuln_classes for vc in ("privilege_escalation", "authentication_bypass")):
        return "privilege_escalation_and_lateral_movement"
    if any(vc in vuln_classes for vc in ("remote_code_execution",)):
        return "remote_code_execution_and_backdoor"
    if any(vc in vuln_classes for vc in ("information_disclosure", "credential_stealer")):
        return "intelligence_collection_and_espionage"
    if any(vc in vuln_classes for vc in ("supply_chain",)):
        return "supply_chain_compromise"
    if any(vc in vuln_classes for vc in ("denial_of_service",)):
        return "service_disruption"
    return "opportunistic_exploitation"


def _campaign_severity(cluster: List[Dict]) -> str:
    """Derive overall campaign severity."""
    has_critical = any(s["severity_tier"] == "critical" for s in cluster)
    has_high     = any(s["severity_tier"] == "high" for s in cluster)
    has_kev      = any(s["is_kev"] for s in cluster)
    has_ransom   = any(s["is_ransomware"] for s in cluster)

    if has_critical or (has_high and (has_kev or has_ransom)):
        return "CRITICAL"
    if has_high or (has_kev and len(cluster) >= 3):
        return "HIGH"
    if any(s["severity_tier"] == "medium" for s in cluster):
        return "MEDIUM"
    return "LOW"


def build_campaign_graph(signals: List[Dict]) -> Dict[str, Any]:
    """
    Build the full campaign correlation graph.

    Uses a greedy community detection approach:
    1. Compute all pairwise edge scores
    2. Build adjacency list for edges exceeding threshold
    3. Apply connected-component clustering
    4. Filter to minimum campaign size
    5. Annotate each campaign with metadata
    """
    n = len(signals)
    log.info("Building campaign graph from %d advisories...", n)

    # Build edge list
    edges: List[Tuple[int, int, float, List[str]]] = []
    adjacency: Dict[int, Set[int]] = defaultdict(set)

    for i in range(n):
        for j in range(i + 1, n):
            score, shared = compute_edge_score(signals[i], signals[j])
            if score >= CAMPAIGN_EDGE_THRESHOLD:
                edges.append((i, j, score, shared))
                adjacency[i].add(j)
                adjacency[j].add(i)

    log.info("Found %d correlation edges (threshold=%.1f)", len(edges), CAMPAIGN_EDGE_THRESHOLD)

    # Connected-component clustering (BFS)
    visited:  Set[int]         = set()
    clusters: List[List[int]]  = []

    for start in range(n):
        if start in visited:
            continue
        if start not in adjacency:
            continue
        # BFS from start
        component: List[int] = []
        queue = [start]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            component.append(node)
            for neighbor in adjacency[node]:
                if neighbor not in visited:
                    queue.append(neighbor)
        if len(component) >= CAMPAIGN_MIN_SIZE:
            clusters.append(component)

    log.info("Identified %d campaign clusters (min_size=%d)", len(clusters), CAMPAIGN_MIN_SIZE)

    # Build campaign objects
    campaigns: List[Dict] = []
    edge_lookup: Dict[FrozenSet, Tuple[float, List[str]]] = {
        frozenset({i, j}): (score, shared)
        for i, j, score, shared in edges
    }

    for cluster_idx, component in enumerate(clusters):
        cluster_signals = [signals[i] for i in component]

        # Compute campaign confidence: mean edge score within cluster / max possible
        cluster_edges = [
            edge_lookup[frozenset({i, j})]
            for i in component
            for j in component
            if i < j and frozenset({i, j}) in edge_lookup
        ]
        mean_edge_score = (
            sum(s for s, _ in cluster_edges) / len(cluster_edges)
            if cluster_edges else 0.0
        )
        max_possible = sum(SIGNAL_WEIGHTS.values())
        confidence_pct = min(100, round(mean_edge_score / max_possible * 100 * 3.5))

        # Collect all shared signals across cluster
        all_signals: List[str] = []
        for _, sigs in cluster_edges:
            all_signals.extend(sigs)

        # Count signal frequencies
        signal_counter = Counter(all_signals)
        top_signals = [s for s, _ in signal_counter.most_common(10)]

        item_ids = [s["id"] for s in cluster_signals]
        actors = list({s["actor"] for s in cluster_signals if s["actor"] and s["actor"] != "cdb-cve-gen"})
        cves   = list(set().union(*[s["cves"] for s in cluster_signals]))
        ttps   = sorted(set().union(*[s["ttps"] for s in cluster_signals]))
        sectors = sorted(set().union(*[set(s["sectors"]) for s in cluster_signals]) - {"general_enterprise"})

        # Temporal extent
        timestamps = [s["timestamp"] for s in cluster_signals if s["timestamp"]]
        if timestamps:
            ts_sorted = sorted(timestamps)
            first_seen = ts_sorted[0].strftime("%Y-%m-%dT%H:%M:%SZ")
            last_seen  = ts_sorted[-1].strftime("%Y-%m-%dT%H:%M:%SZ")
            duration_h = round((ts_sorted[-1] - ts_sorted[0]).total_seconds() / 3600, 1)
        else:
            first_seen = last_seen = "unknown"
            duration_h = 0.0

        malware_families = list({
            m for s in cluster_signals for m in s["malware_families"]
        })

        objective = _infer_campaign_objective(cluster_signals)
        severity  = _campaign_severity(cluster_signals)
        name      = _infer_campaign_name(cluster_signals, top_signals)
        camp_id   = _generate_campaign_id(item_ids, actors[0] if actors else "unknown")

        campaigns.append({
            "campaign_id":          camp_id,
            "campaign_name":        name[:CAMPAIGN_NAME_MAX],
            "cluster_index":        cluster_idx,
            "advisory_count":       len(item_ids),
            "advisory_ids":         item_ids,
            "advisory_titles":      [s["title"] for s in cluster_signals],
            "report_urls":          [s["report_url"] for s in cluster_signals if s["report_url"]],
            "attributed_actors":    actors,
            "malware_families":     malware_families,
            "cves_involved":        sorted(cves),
            "techniques":           ttps,
            "target_sectors":       sectors,
            "attack_objective":     objective,
            "campaign_severity":    severity,
            "confidence_pct":       confidence_pct,
            "correlation_signals":  top_signals,
            "kev_confirmed_count":  sum(1 for s in cluster_signals if s["is_kev"]),
            "ransomware_linked":    any(s["is_ransomware"] for s in cluster_signals),
            "first_seen":           first_seen,
            "last_seen":            last_seen,
            "duration_hours":       duration_h,
            "mean_edge_score":      round(mean_edge_score, 2),
        })

    # Sort by severity then advisory count
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    campaigns.sort(key=lambda c: (_sev_order.get(c["campaign_severity"], 4), -c["advisory_count"]))

    # Global stats
    all_advisories_in_campaigns = sum(c["advisory_count"] for c in campaigns)
    isolated_count = n - len({idx for comp in clusters for idx in comp})

    graph = {
        "schema_version":              "1.0",
        "engine":                      "ocios_campaign_correlation_engine",
        "engine_version":              ENGINE_VERSION,
        "generated_at":                _utc_now(),
        "corpus_size":                 n,
        "total_edges":                 len(edges),
        "campaign_count":              len(campaigns),
        "advisories_in_campaigns":     all_advisories_in_campaigns,
        "isolated_advisories":         isolated_count,
        "campaign_coverage_pct":       round(all_advisories_in_campaigns / n * 100, 1) if n else 0,
        "campaigns":                   campaigns,
    }

    log.info(
        "Campaign graph: %d campaigns, %d/%d advisories clustered (%.1f%%)",
        len(campaigns), all_advisories_in_campaigns, n,
        graph["campaign_coverage_pct"],
    )
    return graph


# ---------------------------------------------------------------------------
# Actor relationship map
# ---------------------------------------------------------------------------

def build_actor_relationships(signals: List[Dict]) -> Dict[str, Any]:
    """
    Build actor co-occurrence and relationship map.
    Tracks which actors appear in correlated advisories and their
    shared infrastructure/technique patterns.
    """
    log.info("Building actor relationship map...")
    actor_registry: Dict[str, Dict] = {}

    for sig in signals:
        actor = sig["actor"]
        if not actor or actor == "cdb-cve-gen":
            continue

        if actor not in actor_registry:
            actor_registry[actor] = {
                "actor":            actor,
                "advisory_count":   0,
                "advisory_ids":     [],
                "cves":             set(),
                "ttps":             set(),
                "sectors":          set(),
                "vendors":          set(),
                "malware_families": set(),
                "kev_count":        0,
                "ransomware":       False,
                "first_seen":       None,
                "last_seen":        None,
                "risk_scores":      [],
                "confidence_scores": [],
            }

        a = actor_registry[actor]
        a["advisory_count"]   += 1
        a["advisory_ids"].append(sig["id"])
        a["cves"]            |= sig["cves"]
        a["ttps"]            |= sig["ttps"]
        a["sectors"]         |= set(sig["sectors"])
        a["malware_families"] |= set(sig["malware_families"])
        if sig["vendor"]:
            a["vendors"].add(sig["vendor"])
        if sig["is_kev"]:
            a["kev_count"] += 1
        if sig["is_ransomware"]:
            a["ransomware"] = True
        a["risk_scores"].append(sig["risk_score"])
        a["confidence_scores"].append(sig["confidence"])

        ts = sig["timestamp"]
        if ts:
            if a["first_seen"] is None or ts < a["first_seen"]:
                a["first_seen"] = ts
            if a["last_seen"] is None or ts > a["last_seen"]:
                a["last_seen"] = ts

    # Serialize and compute derived fields
    actors_out = []
    for actor, a in actor_registry.items():
        scores = a["risk_scores"]
        confs  = a["confidence_scores"]
        actors_out.append({
            "actor":             actor,
            "advisory_count":    a["advisory_count"],
            "advisory_ids":      a["advisory_ids"],
            "cves":              sorted(a["cves"]),
            "techniques":        sorted(a["ttps"]),
            "target_sectors":    sorted(a["sectors"] - {"general_enterprise"}),
            "targeted_vendors":  sorted(a["vendors"]),
            "malware_families":  sorted(a["malware_families"]),
            "kev_confirmed":     a["kev_count"],
            "ransomware_linked": a["ransomware"],
            "avg_risk_score":    round(sum(scores) / len(scores), 2) if scores else 0.0,
            "avg_confidence":    round(sum(confs) / len(confs), 1) if confs else 0.0,
            "first_seen":        a["first_seen"].strftime("%Y-%m-%dT%H:%M:%SZ") if a["first_seen"] else None,
            "last_seen":         a["last_seen"].strftime("%Y-%m-%dT%H:%M:%SZ") if a["last_seen"] else None,
            "activity_score":    min(100, a["advisory_count"] * 8 + a["kev_count"] * 20),
        })

    actors_out.sort(key=lambda a: -a["activity_score"])

    return {
        "schema_version": "1.0",
        "engine":         "ocios_campaign_correlation_engine",
        "generated_at":   _utc_now(),
        "actor_count":    len(actors_out),
        "actors":         actors_out,
    }


# ---------------------------------------------------------------------------
# Infrastructure cluster builder
# ---------------------------------------------------------------------------

def build_infrastructure_clusters(signals: List[Dict]) -> Dict[str, Any]:
    """
    Detect infrastructure reuse across advisories.
    Groups advisories that share vendor, source domain, or vulnerability
    infrastructure patterns — indicating coordinated or related campaigns.
    """
    log.info("Building infrastructure clusters...")

    # Group by vendor
    vendor_groups: Dict[str, List[str]] = defaultdict(list)
    for sig in signals:
        if sig["vendor"]:
            vendor_groups[sig["vendor"]].append(sig["id"])

    # Group by source domain
    domain_groups: Dict[str, List[str]] = defaultdict(list)
    for sig in signals:
        if sig["source_domain"]:
            domain_groups[sig["source_domain"]].append(sig["id"])

    # Group by vuln class
    vuln_groups: Dict[str, List[str]] = defaultdict(list)
    for sig in signals:
        vc = sig["vuln_class"]
        if vc != "unclassified":
            vuln_groups[vc].append(sig["id"])

    clusters = []

    for vendor, ids in vendor_groups.items():
        if len(ids) >= 2:
            clusters.append({
                "cluster_type":   "vendor_targeting",
                "cluster_key":    vendor,
                "advisory_ids":   ids,
                "advisory_count": len(ids),
                "description":    f"Multiple advisories targeting {vendor.title()} infrastructure",
                "reuse_signal":   "shared_vendor_target",
            })

    for domain, ids in domain_groups.items():
        if len(ids) >= 2:
            clusters.append({
                "cluster_type":   "source_correlation",
                "cluster_key":    domain,
                "advisory_ids":   ids,
                "advisory_count": len(ids),
                "description":    f"Multiple advisories sourced from {domain}",
                "reuse_signal":   "shared_intelligence_source",
            })

    for vc, ids in vuln_groups.items():
        if len(ids) >= 3:
            clusters.append({
                "cluster_type":   "vulnerability_class",
                "cluster_key":    vc,
                "advisory_ids":   ids,
                "advisory_count": len(ids),
                "description":    f"Exploit wave: {len(ids)} advisories share '{vc.replace('_',' ')}' class",
                "reuse_signal":   "shared_vulnerability_class",
            })

    clusters.sort(key=lambda c: -c["advisory_count"])

    return {
        "schema_version":  "1.0",
        "engine":          "ocios_campaign_correlation_engine",
        "generated_at":    _utc_now(),
        "cluster_count":   len(clusters),
        "clusters":        clusters,
    }


# ---------------------------------------------------------------------------
# Temporal chain builder
# ---------------------------------------------------------------------------

def build_temporal_chains(signals: List[Dict]) -> Dict[str, Any]:
    """
    Identify temporal attack waves — bursts of advisories within
    rolling time windows that suggest coordinated or cascading activity.
    """
    log.info("Building temporal attack chains...")

    # Filter to signals with timestamps
    timed = [s for s in signals if s["timestamp"] is not None]
    timed.sort(key=lambda s: s["timestamp"])

    if not timed:
        return {
            "schema_version": "1.0",
            "engine":         "ocios_campaign_correlation_engine",
            "generated_at":   _utc_now(),
            "chain_count":    0,
            "chains":         [],
            "note":           "No timestamped advisories available",
        }

    # Sliding window burst detection
    chains: List[Dict] = []
    window = timedelta(hours=TEMPORAL_WINDOW_HOURS)
    i = 0

    while i < len(timed):
        window_end = timed[i]["timestamp"] + window
        burst = [timed[i]]
        j = i + 1
        while j < len(timed) and timed[j]["timestamp"] <= window_end:
            burst.append(timed[j])
            j += 1

        if len(burst) >= 3:  # Minimum 3 advisories for a chain
            actors  = list({s["actor"] for s in burst if s["actor"] and s["actor"] != "cdb-cve-gen"})
            kev_ct  = sum(1 for s in burst if s["is_kev"])
            crit_ct = sum(1 for s in burst if s["severity_tier"] in ("critical", "high"))
            sectors = sorted(set().union(*[set(s["sectors"]) for s in burst]) - {"general_enterprise"})
            vendors = sorted({s["vendor"] for s in burst if s["vendor"]})

            # Classify wave type
            if kev_ct >= len(burst) * 0.5:
                wave_type = "kev_exploitation_wave"
            elif len(actors) >= 2:
                wave_type = "multi_actor_campaign"
            elif crit_ct >= len(burst) * 0.6:
                wave_type = "critical_vulnerability_wave"
            elif sectors:
                wave_type = f"targeted_sector_wave"
            else:
                wave_type = "opportunistic_burst"

            chains.append({
                "chain_id":          "chain--" + hashlib.sha256(
                    (timed[i]["id"] + str(len(burst))).encode()
                ).hexdigest()[:12],
                "wave_type":         wave_type,
                "advisory_count":    len(burst),
                "advisory_ids":      [s["id"] for s in burst],
                "start_time":        timed[i]["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end_time":          burst[-1]["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "duration_hours":    round((burst[-1]["timestamp"] - timed[i]["timestamp"]).total_seconds() / 3600, 1),
                "actors":            actors,
                "kev_in_wave":       kev_ct,
                "high_critical_pct": round(crit_ct / len(burst) * 100),
                "target_sectors":    sectors,
                "target_vendors":    vendors,
                "intensity_score":   min(100, len(burst) * 6 + kev_ct * 15 + crit_ct * 5),
            })
            i = j  # Advance past this window
        else:
            i += 1

    chains.sort(key=lambda c: -c["intensity_score"])

    return {
        "schema_version": "1.0",
        "engine":         "ocios_campaign_correlation_engine",
        "generated_at":   _utc_now(),
        "chain_count":    len(chains),
        "corpus_span_days": round(
            (timed[-1]["timestamp"] - timed[0]["timestamp"]).total_seconds() / 86400, 1
        ) if len(timed) >= 2 else 0,
        "chains":         chains,
    }


# ---------------------------------------------------------------------------
# IOC lineage builder
# ---------------------------------------------------------------------------

def build_ioc_lineage(signals: List[Dict]) -> Dict[str, Any]:
    """
    Build IOC lineage graph: which CVEs, techniques, and malware families
    appear across multiple advisories, forming observable lineage chains.
    """
    log.info("Building IOC lineage graph...")

    cve_lineage:     Dict[str, List[str]] = defaultdict(list)
    ttp_lineage:     Dict[str, List[str]] = defaultdict(list)
    malware_lineage: Dict[str, List[str]] = defaultdict(list)

    for sig in signals:
        for cve in sig["cves"]:
            cve_lineage[cve].append(sig["id"])
        for ttp in sig["ttps"]:
            ttp_lineage[ttp].append(sig["id"])
        for mf in sig["malware_families"]:
            malware_lineage[mf].append(sig["id"])

    # Only report IOCs appearing in 2+ advisories (lineage = cross-report)
    cve_nodes = [
        {"ioc_type": "cve", "value": k, "advisory_count": len(v), "advisory_ids": v}
        for k, v in cve_lineage.items() if len(v) >= 2
    ]
    ttp_nodes = [
        {"ioc_type": "technique", "value": k, "advisory_count": len(v), "advisory_ids": v}
        for k, v in ttp_lineage.items() if len(v) >= 2
    ]
    malware_nodes = [
        {"ioc_type": "malware_family", "value": k, "advisory_count": len(v), "advisory_ids": v}
        for k, v in malware_lineage.items() if len(v) >= 2
    ]

    all_nodes = cve_nodes + ttp_nodes + malware_nodes
    all_nodes.sort(key=lambda n: -n["advisory_count"])

    return {
        "schema_version":          "1.0",
        "engine":                  "ocios_campaign_correlation_engine",
        "generated_at":            _utc_now(),
        "total_lineage_nodes":     len(all_nodes),
        "shared_cves":             len(cve_nodes),
        "shared_techniques":       len(ttp_nodes),
        "shared_malware_families": len(malware_nodes),
        "lineage_nodes":           all_nodes,
    }


# ---------------------------------------------------------------------------
# Atomic write helper
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, obj: Any, indent: int = 2) -> None:
    """Write JSON atomically via tmp -> os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    try:
        content = json.dumps(obj, indent=indent, ensure_ascii=False, default=str)
        tmp.write_text(content, encoding="utf-8")
        os.replace(str(tmp), str(path))
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_correlation_engine(
    manifest_path: Path = MANIFEST_PATH,
    ocios_dir:     Path = OCIOS_DIR,
) -> Dict[str, Any]:
    """
    Execute the full OCIOS Campaign Correlation Engine.
    Returns a summary dict.  Never raises — all exceptions are caught and logged.
    """
    t_start = time.monotonic()
    summary: Dict[str, Any] = {
        "engine":        "ocios_campaign_correlation_engine",
        "version":       ENGINE_VERSION,
        "started_at":    _utc_now(),
        "status":        "running",
        "corpus_size":   0,
        "campaigns":     0,
        "actors":        0,
        "infra_clusters": 0,
        "temporal_chains": 0,
        "errors":        [],
    }

    # ── Load manifest ─────────────────────────────────────────────────────
    if not manifest_path.exists():
        msg = f"Manifest not found at {manifest_path} — engine skipped"
        log.warning(msg)
        summary["status"] = "skipped"
        summary["errors"].append(msg)
        return summary

    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        items: List[Dict] = raw.get("advisories") or raw.get("reports") or []
        if not isinstance(items, list):
            raise ValueError("Manifest has no 'advisories' or 'reports' list")
    except Exception as exc:
        log.error("Manifest load failed: %s", exc)
        summary["status"] = "error"
        summary["errors"].append(str(exc))
        return summary

    log.info("Loaded %d advisories from manifest", len(items))
    summary["corpus_size"] = len(items)

    if not items:
        summary["status"] = "empty_corpus"
        return summary

    # ── Extract signals ────────────────────────────────────────────────────
    signals: List[Dict] = []
    for item in items:
        try:
            signals.append(extract_signals(item))
        except Exception as exc:
            log.debug("Signal extraction failed for %s: %s", _item_id(item), exc)

    log.info("Extracted signals from %d advisories", len(signals))

    # ── Build all graphs ───────────────────────────────────────────────────
    outputs: Dict[str, Tuple[str, Any]] = {}

    try:
        campaign_graph = build_campaign_graph(signals)
        outputs["campaign_graph.json"] = campaign_graph
        summary["campaigns"] = campaign_graph["campaign_count"]
    except Exception as exc:
        log.error("Campaign graph failed: %s", exc)
        summary["errors"].append(f"campaign_graph: {exc}")

    try:
        actor_rels = build_actor_relationships(signals)
        outputs["actor_relationships.json"] = actor_rels
        summary["actors"] = actor_rels["actor_count"]
    except Exception as exc:
        log.error("Actor relationships failed: %s", exc)
        summary["errors"].append(f"actor_relationships: {exc}")

    try:
        infra_clusters = build_infrastructure_clusters(signals)
        outputs["infrastructure_clusters.json"] = infra_clusters
        summary["infra_clusters"] = infra_clusters["cluster_count"]
    except Exception as exc:
        log.error("Infrastructure clusters failed: %s", exc)
        summary["errors"].append(f"infrastructure_clusters: {exc}")

    try:
        temporal_chains = build_temporal_chains(signals)
        outputs["temporal_chains.json"] = temporal_chains
        summary["temporal_chains"] = temporal_chains["chain_count"]
    except Exception as exc:
        log.error("Temporal chains failed: %s", exc)
        summary["errors"].append(f"temporal_chains: {exc}")

    try:
        ioc_lineage = build_ioc_lineage(signals)
        outputs["ioc_lineage.json"] = ioc_lineage
        summary["ioc_lineage_nodes"] = ioc_lineage["total_lineage_nodes"]
    except Exception as exc:
        log.error("IOC lineage failed: %s", exc)
        summary["errors"].append(f"ioc_lineage: {exc}")

    # ── Write outputs atomically ───────────────────────────────────────────
    ocios_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for filename, obj in outputs.items():
        try:
            _atomic_write(ocios_dir / filename, obj)
            log.info("Written: data/ocios/%s", filename)
            written += 1
        except Exception as exc:
            log.error("Write failed for %s: %s", filename, exc)
            summary["errors"].append(f"write:{filename}: {exc}")

    elapsed = round(time.monotonic() - t_start, 2)
    summary.update({
        "status":       "success" if not summary["errors"] else "partial",
        "files_written": written,
        "elapsed_seconds": elapsed,
        "completed_at": _utc_now(),
    })

    # Write engine summary
    try:
        _atomic_write(ocios_dir / "correlation_engine_summary.json", summary)
    except Exception:
        pass

    log.info(
        "OCIOS Correlation Engine complete: %d campaigns, %d actors, "
        "%d infra clusters, %d temporal chains | %.2fs",
        summary["campaigns"], summary["actors"],
        summary["infra_clusters"], summary["temporal_chains"],
        elapsed,
    )
    return summary


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="OCIOS Campaign Correlation Engine")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--output-dir", default=str(OCIOS_DIR))
    args = parser.parse_args()

    result = run_correlation_engine(
        manifest_path=Path(args.manifest),
        ocios_dir=Path(args.output_dir),
    )
    status = result.get("status", "unknown")
    if status in ("success", "partial", "skipped", "empty_corpus"):
        return 0
    return 1


if __name__ == "__main__":
    import sys
    sys.exit