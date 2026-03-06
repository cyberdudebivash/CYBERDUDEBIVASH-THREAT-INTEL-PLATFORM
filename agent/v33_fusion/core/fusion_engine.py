#!/usr/bin/env python3
"""
fusion_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v33.0 (FUSION DOMINANCE)
===========================================================================
The Intelligence Fusion Engine — connects isolated threat signals into
correlated intelligence context using entity extraction, relationship
mapping, confidence scoring, and narrative generation.

This is the SINGLE ARCHITECTURE UPGRADE that transforms Sentinel from a
threat feed into a cyber intelligence company product.

Pipeline:
    Raw Signal → Normalize → Extract Entities → Resolve → Map Relationships
    → Score Confidence → Build Context → Generate Intelligence Report

Non-Breaking: Reads from existing feed_manifest.json and STIX bundles.
Writes to isolated data/fusion/ directory. Zero impact on existing pipeline.

Author: CyberDudeBivash Pvt. Ltd. — SENTINEL APEX GOC
"""

import os
import re
import json
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("CDB-FusionEngine")

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

FUSION_DATA_DIR = os.environ.get("FUSION_DATA_DIR", "data/fusion")
MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
STIX_DIR = os.environ.get("STIX_DIR", "data/stix")

# Entity type constants
class EntityType(Enum):
    CVE = "cve"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    INFRASTRUCTURE = "infrastructure"
    SECTOR = "sector"
    IOC = "ioc"
    TECHNIQUE = "technique"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    TOOL = "tool"
    COUNTRY = "country"

class RelationshipType(Enum):
    EXPLOITS = "exploits"
    USES = "uses"
    ATTRIBUTED_TO = "attributed_to"
    TARGETS = "targets"
    DELIVERS = "delivers"
    INDICATES = "indicates"
    PART_OF = "part_of"
    HOSTED_ON = "hosted_on"
    COMMUNICATES_WITH = "communicates_with"
    DROPS = "drops"
    VARIANT_OF = "variant_of"
    ASSOCIATED_WITH = "associated_with"
    MITIGATED_BY = "mitigated_by"


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class FusionEntity:
    """Extracted and resolved entity from threat intelligence signals."""
    entity_id: str
    entity_type: EntityType
    canonical_name: str
    aliases: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    first_seen: str = ""
    last_seen: str = ""
    source_signals: List[str] = field(default_factory=list)
    mention_count: int = 0

    def to_dict(self) -> Dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "canonical_name": self.canonical_name,
            "aliases": self.aliases,
            "properties": self.properties,
            "confidence": round(self.confidence, 3),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source_signals": self.source_signals[-10:],
            "mention_count": self.mention_count,
        }


@dataclass
class FusionRelationship:
    """Mapped relationship between two entities."""
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    confidence: float = 0.5
    evidence: List[str] = field(default_factory=list)
    first_observed: str = ""
    last_observed: str = ""

    def to_dict(self) -> Dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship_type.value,
            "confidence": round(self.confidence, 3),
            "evidence_count": len(self.evidence),
            "first_observed": self.first_observed,
            "last_observed": self.last_observed,
        }


@dataclass
class FusionContext:
    """Complete fused intelligence context for a threat signal."""
    context_id: str
    title: str
    summary: str
    risk_score: float
    entities: List[FusionEntity]
    relationships: List[FusionRelationship]
    attack_chain: List[str]
    recommended_actions: List[str]
    detection_signatures: List[str]
    intelligence_level: str  # tactical, operational, strategic
    confidence: float
    timestamp: str
    source_report_ids: List[str]

    def to_dict(self) -> Dict:
        return {
            "context_id": self.context_id,
            "title": self.title,
            "summary": self.summary,
            "risk_score": round(self.risk_score, 2),
            "entities": [e.to_dict() for e in self.entities],
            "relationships": [r.to_dict() for r in self.relationships],
            "attack_chain": self.attack_chain,
            "recommended_actions": self.recommended_actions,
            "detection_signatures": self.detection_signatures,
            "intelligence_level": self.intelligence_level,
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp,
            "source_report_ids": self.source_report_ids,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL NORMALIZER
# ═══════════════════════════════════════════════════════════════════════════════

class SignalNormalizer:
    """Normalizes raw threat signals into canonical schema."""

    # CVE regex pattern
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    # IP address patterns
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b'
    )

    # Domain patterns (simplified, production-grade)
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|info|biz|xyz|top|cc|ru|cn|tk|ml|ga|cf|pw|onion)\b'
    )

    # Hash patterns
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

    # MITRE ATT&CK pattern
    MITRE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')

    @staticmethod
    def normalize_manifest_entry(entry: Dict) -> Dict:
        """Normalize a feed_manifest.json entry into canonical signal format.
        Handles actual Sentinel APEX manifest schema:
        - actor_tag (not actor_id)
        - ioc_counts (not iocs) — IOC values are in STIX bundles
        - mitre_tactics contains technique IDs (T1xxx)
        - CVEs extracted from title
        """
        title = entry.get("title", "Unknown Signal")
        stix_file = entry.get("stix_file", "")

        # Extract CVEs from title
        cve_ids = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE)))

        # Resolve confidence (can be 0-100 or 0-1)
        raw_conf = entry.get("confidence_score", entry.get("confidence", 50))
        confidence = raw_conf / 100.0 if isinstance(raw_conf, (int, float)) and raw_conf > 1 else float(raw_conf or 0.5)

        # Extract IOCs from STIX bundle if available
        iocs = SignalNormalizer._extract_iocs_from_stix(stix_file)

        # Actor from actor_tag field
        actor_id = entry.get("actor_tag", entry.get("actor_id", ""))

        # MITRE techniques (stored in mitre_tactics field as T-codes)
        mitre_techniques = entry.get("mitre_tactics", entry.get("mitre_techniques", []))

        # Sectors from entry or detect from title
        sectors = entry.get("sectors", [])

        return {
            "signal_id": stix_file or f"sig-{hashlib.md5(json.dumps(entry, default=str).encode()).hexdigest()[:12]}",
            "title": title,
            "source_url": entry.get("source_url", entry.get("blog_url", "")),
            "risk_score": entry.get("risk_score", 0),
            "iocs": iocs,
            "ioc_counts": entry.get("ioc_counts", {}),
            "mitre_tactics": [],
            "mitre_techniques": mitre_techniques,
            "tlp": entry.get("tlp_label", entry.get("tlp", "TLP:CLEAR")),
            "published": entry.get("timestamp", entry.get("published", entry.get("generated_at", ""))),
            "actor_id": actor_id,
            "actor_aliases": entry.get("actor_aliases", []),
            "sectors": sectors,
            "confidence": confidence,
            "category": entry.get("category", entry.get("severity", "general")),
            "cve_ids": cve_ids,
            "cvss_score": entry.get("cvss_score"),
            "epss_score": entry.get("epss_score"),
            "kev_present": entry.get("kev_present", False),
            "raw": entry,
        }

    @staticmethod
    def _extract_iocs_from_stix(stix_file: str) -> Dict[str, List[str]]:
        """Extract IOC values from STIX bundle file."""
        iocs: Dict[str, List[str]] = {"ips": [], "domains": [], "urls": [], "hashes": [], "files": []}
        if not stix_file:
            return iocs

        stix_path = os.path.join(STIX_DIR, stix_file)
        if not os.path.exists(stix_path):
            return iocs

        try:
            with open(stix_path, 'r') as f:
                bundle = json.load(f)

            for obj in bundle.get("objects", []):
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    name = obj.get("name", "")

                    # Extract IP addresses
                    ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
                    if ip_match:
                        iocs["ips"].append(ip_match.group(1))

                    # Extract domains
                    domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
                    if domain_match:
                        iocs["domains"].append(domain_match.group(1))

                    # Extract URLs
                    url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
                    if url_match:
                        iocs["urls"].append(url_match.group(1))

                    # Extract hashes
                    hash_match = re.search(r"file:hashes\.'([^']+)'\s*=\s*'([^']+)'", pattern)
                    if hash_match:
                        iocs["hashes"].append(hash_match.group(2))

                    # Extract filenames from name field
                    if "Malicious File:" in name:
                        fname = name.replace("Malicious File:", "").strip()
                        if fname:
                            iocs["files"].append(fname)
        except Exception:
            pass

        return iocs

    @classmethod
    def extract_iocs_from_text(cls, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from freeform text."""
        return {
            "cves": list(set(cls.CVE_PATTERN.findall(text))),
            "ipv4": list(set(cls.IPV4_PATTERN.findall(text))),
            "domains": list(set(cls.DOMAIN_PATTERN.findall(text))),
            "md5": list(set(cls.MD5_PATTERN.findall(text))),
            "sha1": list(set(cls.SHA1_PATTERN.findall(text))),
            "sha256": list(set(cls.SHA256_PATTERN.findall(text))),
            "techniques": list(set(cls.MITRE_PATTERN.findall(text))),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# ENTITY EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

class EntityExtractor:
    """Extracts typed entities from normalized signals."""

    # Known actor database (expandable via actor_registry.py integration)
    KNOWN_ACTORS = {
        "apt-28": {"canonical": "APT-28", "aliases": ["Fancy Bear", "Sofacy", "Strontium", "Forest Blizzard"]},
        "apt-29": {"canonical": "APT-29", "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes"]},
        "apt-41": {"canonical": "APT-41", "aliases": ["Winnti", "Barium", "Double Dragon"]},
        "lazarus": {"canonical": "Lazarus Group", "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet"]},
        "scattered-spider": {"canonical": "Scattered Spider", "aliases": ["UNC3944", "Octo Tempest", "0ktapus"]},
        "lockbit": {"canonical": "LockBit", "aliases": ["LockBit 3.0", "LockBit Black"]},
        "blackcat": {"canonical": "BlackCat", "aliases": ["ALPHV", "Noberus"]},
        "cl0p": {"canonical": "Cl0p", "aliases": ["TA505", "FIN11"]},
        "kimsuky": {"canonical": "Kimsuky", "aliases": ["Thallium", "Velvet Chollima", "Emerald Sleet"]},
        "turla": {"canonical": "Turla", "aliases": ["Snake", "Venomous Bear", "Secret Blizzard"]},
        "sandworm": {"canonical": "Sandworm", "aliases": ["Voodoo Bear", "Seashell Blizzard", "IRIDIUM"]},
        "fin7": {"canonical": "FIN7", "aliases": ["Carbanak", "Navigator Group"]},
        "conti": {"canonical": "Conti", "aliases": ["Wizard Spider", "Gold Ulrick"]},
        "revil": {"canonical": "REvil", "aliases": ["Sodinokibi", "Gold Southfield"]},
        "volt-typhoon": {"canonical": "Volt Typhoon", "aliases": ["Vanguard Panda", "Bronze Silhouette"]},
        "salt-typhoon": {"canonical": "Salt Typhoon", "aliases": ["GhostEmperor", "FamousSparrow"]},
    }

    # Sector keywords mapping
    SECTOR_KEYWORDS = {
        "finance": ["bank", "finance", "financial", "payment", "credit", "trading", "investment", "fintech"],
        "healthcare": ["health", "hospital", "medical", "pharma", "patient", "clinical", "biotech"],
        "government": ["government", "federal", "state", "municipal", "agency", "defense", "military", "diplomatic"],
        "energy": ["energy", "oil", "gas", "power", "utility", "grid", "nuclear", "electric", "pipeline"],
        "technology": ["tech", "software", "cloud", "saas", "platform", "semiconductor", "chip"],
        "telecom": ["telecom", "mobile", "wireless", "carrier", "5g", "isp", "broadband"],
        "education": ["university", "school", "education", "academic", "college", "student"],
        "manufacturing": ["manufacturing", "industrial", "factory", "supply chain", "ics", "scada", "ot"],
        "retail": ["retail", "ecommerce", "e-commerce", "shopping", "merchant", "consumer"],
        "transportation": ["transport", "aviation", "airline", "railway", "shipping", "logistics"],
        "critical_infrastructure": ["critical infrastructure", "water", "dam", "bridge", "ics", "scada"],
    }

    # Malware family patterns
    MALWARE_KEYWORDS = [
        "ransomware", "trojan", "wiper", "backdoor", "rootkit", "keylogger",
        "stealer", "loader", "dropper", "botnet", "rat", "infostealer",
        "cryptominer", "spyware", "worm", "exploit kit",
    ]

    def extract_entities(self, signal: Dict) -> List[FusionEntity]:
        """Extract all entity types from a normalized signal."""
        entities = []
        signal_id = signal.get("signal_id", "unknown")
        timestamp = signal.get("published", datetime.now(timezone.utc).isoformat())
        title_lower = signal.get("title", "").lower()
        full_text = f"{signal.get('title', '')} {json.dumps(signal.get('iocs', {}))}"

        # Extract CVEs
        cve_ids = signal.get("cve_ids", [])
        text_cves = SignalNormalizer.CVE_PATTERN.findall(full_text)
        all_cves = list(set(cve_ids + [c.upper() for c in text_cves]))
        for cve in all_cves:
            eid = f"vuln--{cve.lower()}"
            entities.append(FusionEntity(
                entity_id=eid,
                entity_type=EntityType.CVE,
                canonical_name=cve.upper(),
                confidence=0.95,
                first_seen=timestamp,
                last_seen=timestamp,
                source_signals=[signal_id],
                mention_count=1,
            ))

        # Extract threat actors
        actor_id = signal.get("actor_id", "")
        actor_aliases = signal.get("actor_aliases", [])
        if actor_id:
            canonical, aliases = self._resolve_actor(actor_id, actor_aliases, title_lower)
            eid = f"actor--{hashlib.md5(canonical.lower().encode()).hexdigest()[:12]}"
            entities.append(FusionEntity(
                entity_id=eid,
                entity_type=EntityType.THREAT_ACTOR,
                canonical_name=canonical,
                aliases=aliases,
                confidence=0.8,
                first_seen=timestamp,
                last_seen=timestamp,
                source_signals=[signal_id],
                mention_count=1,
                properties={"origin": signal.get("raw", {}).get("actor_origin", "unknown")},
            ))

        # Extract sectors
        sectors = signal.get("sectors", [])
        detected_sectors = self._detect_sectors(title_lower)
        all_sectors = list(set(sectors + detected_sectors))
        for sector in all_sectors:
            eid = f"sector--{hashlib.md5(sector.lower().encode()).hexdigest()[:10]}"
            entities.append(FusionEntity(
                entity_id=eid,
                entity_type=EntityType.SECTOR,
                canonical_name=sector.title(),
                confidence=0.7,
                first_seen=timestamp,
                last_seen=timestamp,
                source_signals=[signal_id],
                mention_count=1,
            ))

        # Extract IOCs as entities
        iocs = signal.get("iocs", {})
        for ioc_type, ioc_list in iocs.items():
            if isinstance(ioc_list, list):
                for ioc_val in ioc_list[:50]:  # Cap per-signal IOC extraction
                    eid = f"ioc--{hashlib.md5(f'{ioc_type}:{ioc_val}'.encode()).hexdigest()[:12]}"
                    entities.append(FusionEntity(
                        entity_id=eid,
                        entity_type=EntityType.IOC,
                        canonical_name=str(ioc_val),
                        properties={"ioc_type": ioc_type},
                        confidence=0.85,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        source_signals=[signal_id],
                        mention_count=1,
                    ))

        # Extract MITRE techniques
        techniques = signal.get("mitre_techniques", [])
        for tech in techniques:
            eid = f"technique--{tech}"
            entities.append(FusionEntity(
                entity_id=eid,
                entity_type=EntityType.TECHNIQUE,
                canonical_name=tech,
                confidence=0.9,
                first_seen=timestamp,
                last_seen=timestamp,
                source_signals=[signal_id],
                mention_count=1,
            ))

        # Detect malware references in title
        for kw in self.MALWARE_KEYWORDS:
            if kw in title_lower:
                # Try to extract malware name from context
                malware_name = self._extract_malware_name(signal.get("title", ""), kw)
                if malware_name:
                    eid = f"malware--{hashlib.md5(malware_name.lower().encode()).hexdigest()[:12]}"
                    entities.append(FusionEntity(
                        entity_id=eid,
                        entity_type=EntityType.MALWARE,
                        canonical_name=malware_name,
                        properties={"malware_type": kw},
                        confidence=0.7,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        source_signals=[signal_id],
                        mention_count=1,
                    ))
                break

        return entities

    def _resolve_actor(self, actor_id: str, aliases: List[str], title: str) -> Tuple[str, List[str]]:
        """Resolve actor to canonical name and aliases."""
        check_strings = [actor_id.lower()] + [a.lower() for a in aliases] + [title]
        for key, info in self.KNOWN_ACTORS.items():
            for s in check_strings:
                if key in s or info["canonical"].lower() in s:
                    return info["canonical"], info["aliases"]
                for alias in info["aliases"]:
                    if alias.lower() in s:
                        return info["canonical"], info["aliases"]
        # Return as-is if not found in known DB
        canonical = actor_id if actor_id else (aliases[0] if aliases else "Unknown Actor")
        return canonical, aliases

    def _detect_sectors(self, text: str) -> List[str]:
        """Detect targeted sectors from text."""
        detected = []
        for sector, keywords in self.SECTOR_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    detected.append(sector)
                    break
        return detected

    def _extract_malware_name(self, title: str, keyword: str) -> Optional[str]:
        """Attempt to extract specific malware family name from title."""
        # Look for capitalized words near the keyword
        words = title.split()
        for i, word in enumerate(words):
            clean = re.sub(r'[^a-zA-Z0-9\-]', '', word)
            if clean.lower() == keyword:
                # Check surrounding words for proper nouns
                for j in range(max(0, i - 3), min(len(words), i + 3)):
                    candidate = re.sub(r'[^a-zA-Z0-9\-]', '', words[j])
                    if candidate and candidate[0].isupper() and candidate.lower() != keyword:
                        return candidate
        return title.split(":")[0].strip()[:60] if ":" in title else None


# ═══════════════════════════════════════════════════════════════════════════════
# RELATIONSHIP MAPPER
# ═══════════════════════════════════════════════════════════════════════════════

class RelationshipMapper:
    """Maps relationships between extracted entities within and across signals."""

    def map_intra_signal(self, entities: List[FusionEntity], signal: Dict) -> List[FusionRelationship]:
        """Map relationships between entities within a single signal."""
        relationships = []
        signal_id = signal.get("signal_id", "")
        timestamp = signal.get("published", datetime.now(timezone.utc).isoformat())

        # Group entities by type
        by_type: Dict[EntityType, List[FusionEntity]] = defaultdict(list)
        for entity in entities:
            by_type[entity.entity_type].append(entity)

        # Actor → CVE (exploits)
        for actor in by_type.get(EntityType.THREAT_ACTOR, []):
            for cve in by_type.get(EntityType.CVE, []):
                relationships.append(FusionRelationship(
                    source_id=actor.entity_id,
                    target_id=cve.entity_id,
                    relationship_type=RelationshipType.EXPLOITS,
                    confidence=min(actor.confidence, cve.confidence) * 0.9,
                    evidence=[signal_id],
                    first_observed=timestamp,
                    last_observed=timestamp,
                ))

        # Actor → Sector (targets)
        for actor in by_type.get(EntityType.THREAT_ACTOR, []):
            for sector in by_type.get(EntityType.SECTOR, []):
                relationships.append(FusionRelationship(
                    source_id=actor.entity_id,
                    target_id=sector.entity_id,
                    relationship_type=RelationshipType.TARGETS,
                    confidence=min(actor.confidence, sector.confidence) * 0.85,
                    evidence=[signal_id],
                    first_observed=timestamp,
                    last_observed=timestamp,
                ))

        # Actor → Malware (uses)
        for actor in by_type.get(EntityType.THREAT_ACTOR, []):
            for malware in by_type.get(EntityType.MALWARE, []):
                relationships.append(FusionRelationship(
                    source_id=actor.entity_id,
                    target_id=malware.entity_id,
                    relationship_type=RelationshipType.USES,
                    confidence=min(actor.confidence, malware.confidence) * 0.8,
                    evidence=[signal_id],
                    first_observed=timestamp,
                    last_observed=timestamp,
                ))

        # Actor → Technique (uses)
        for actor in by_type.get(EntityType.THREAT_ACTOR, []):
            for technique in by_type.get(EntityType.TECHNIQUE, []):
                relationships.append(FusionRelationship(
                    source_id=actor.entity_id,
                    target_id=technique.entity_id,
                    relationship_type=RelationshipType.USES,
                    confidence=min(actor.confidence, technique.confidence) * 0.85,
                    evidence=[signal_id],
                    first_observed=timestamp,
                    last_observed=timestamp,
                ))

        # Malware → IOC (indicates)
        for malware in by_type.get(EntityType.MALWARE, []):
            for ioc in by_type.get(EntityType.IOC, []):
                relationships.append(FusionRelationship(
                    source_id=malware.entity_id,
                    target_id=ioc.entity_id,
                    relationship_type=RelationshipType.INDICATES,
                    confidence=min(malware.confidence, ioc.confidence) * 0.75,
                    evidence=[signal_id],
                    first_observed=timestamp,
                    last_observed=timestamp,
                ))

        # CVE → Technique (associated)
        for cve in by_type.get(EntityType.CVE, []):
            for technique in by_type.get(EntityType.TECHNIQUE, []):
                relationships.append(FusionRelationship(
                    source_id=cve.entity_id,
                    target_id=technique.entity_id,
                    relationship_type=RelationshipType.ASSOCIATED_WITH,
                    confidence=min(cve.confidence, technique.confidence) * 0.7,
                    evidence=[signal_id],
                    first_observed=timestamp,
                    last_observed=timestamp,
                ))

        return relationships


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIDENCE SCORER
# ═══════════════════════════════════════════════════════════════════════════════

class ConfidenceScorer:
    """Multi-signal confidence aggregation engine."""

    # Source reliability weights
    SOURCE_WEIGHTS = {
        "cisa": 0.95, "nvd": 0.95, "mandiant": 0.9, "crowdstrike": 0.9,
        "microsoft": 0.85, "google": 0.85, "unit42": 0.85, "sophos": 0.8,
        "kaspersky": 0.8, "trendmicro": 0.8, "recorded_future": 0.85,
        "bleepingcomputer": 0.7, "hackernews": 0.7, "securityweek": 0.7,
        "threatpost": 0.7, "darkweb": 0.5, "unknown": 0.4,
    }

    @classmethod
    def aggregate_confidence(cls, confidences: List[float], source_urls: List[str] = None) -> float:
        """Aggregate confidence scores from multiple signals."""
        if not confidences:
            return 0.0

        # Base: weighted average with diminishing returns for repeated signals
        n = len(confidences)
        weighted = sum(c * (1.0 / (i + 1)) for i, c in enumerate(sorted(confidences, reverse=True)))
        harmonic_n = sum(1.0 / (i + 1) for i in range(n))
        base = weighted / harmonic_n

        # Source diversity bonus (up to +0.1)
        diversity_bonus = 0.0
        if source_urls:
            unique_sources = set()
            for url in source_urls:
                for source_name in cls.SOURCE_WEIGHTS:
                    if source_name in url.lower():
                        unique_sources.add(source_name)
                        break
            diversity_bonus = min(0.1, len(unique_sources) * 0.02)

        # Multi-signal corroboration bonus (up to +0.15)
        corroboration = min(0.15, (n - 1) * 0.03)

        return min(1.0, base + diversity_bonus + corroboration)


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT CONTEXT BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatContextBuilder:
    """Builds fused intelligence context from entities and relationships."""

    @staticmethod
    def build_context(
        entities: List[FusionEntity],
        relationships: List[FusionRelationship],
        source_signals: List[Dict],
    ) -> FusionContext:
        """Build complete intelligence context."""
        now = datetime.now(timezone.utc).isoformat()

        # Determine primary threat focus
        actors = [e for e in entities if e.entity_type == EntityType.THREAT_ACTOR]
        cves = [e for e in entities if e.entity_type == EntityType.CVE]
        sectors = [e for e in entities if e.entity_type == EntityType.SECTOR]
        techniques = [e for e in entities if e.entity_type == EntityType.TECHNIQUE]
        malware = [e for e in entities if e.entity_type == EntityType.MALWARE]

        # Build title
        if actors and cves:
            title = f"{actors[0].canonical_name} exploiting {cves[0].canonical_name}"
            if sectors:
                title += f" targeting {sectors[0].canonical_name}"
        elif cves:
            title = f"Active exploitation of {', '.join(c.canonical_name for c in cves[:3])}"
        elif actors:
            title = f"Campaign activity by {actors[0].canonical_name}"
        else:
            title = source_signals[0].get("title", "Threat Intelligence Fusion Report") if source_signals else "Threat Context"

        # Build summary
        summary_parts = []
        if actors:
            actor_names = ", ".join(a.canonical_name for a in actors[:3])
            summary_parts.append(f"Threat actor(s) {actor_names} identified")
        if cves:
            cve_names = ", ".join(c.canonical_name for c in cves[:5])
            summary_parts.append(f"exploiting vulnerabilities {cve_names}")
        if sectors:
            sector_names = ", ".join(s.canonical_name for s in sectors[:3])
            summary_parts.append(f"targeting {sector_names} sector(s)")
        if techniques:
            tech_names = ", ".join(t.canonical_name for t in techniques[:5])
            summary_parts.append(f"using techniques {tech_names}")

        summary = ". ".join(summary_parts) + "." if summary_parts else "Fused intelligence context generated."

        # Calculate composite risk score
        signal_risks = [s.get("risk_score", 5.0) for s in source_signals]
        avg_risk = sum(signal_risks) / len(signal_risks) if signal_risks else 5.0
        # Boost risk for multi-entity correlation
        entity_boost = min(2.0, len(set(e.entity_type for e in entities)) * 0.3)
        risk_score = min(10.0, avg_risk + entity_boost)

        # Build attack chain
        attack_chain = []
        if cves:
            attack_chain.append(f"Initial Access via {cves[0].canonical_name}")
        if techniques:
            for t in techniques[:5]:
                attack_chain.append(f"Technique: {t.canonical_name}")
        if malware:
            attack_chain.append(f"Payload: {malware[0].canonical_name}")

        # Recommended actions
        actions = []
        if cves:
            actions.append(f"Patch {', '.join(c.canonical_name for c in cves[:3])} immediately")
        if actors:
            actions.append(f"Hunt for {actors[0].canonical_name} TTPs in environment")
        actions.append("Review IOCs against SIEM/EDR telemetry")
        actions.append("Update detection rules with provided signatures")
        if risk_score >= 8.0:
            actions.append("Escalate to SOC Tier 2/3 for immediate response")

        # Determine intelligence level
        if actors and cves and sectors:
            intel_level = "strategic"
        elif actors or (cves and len(cves) > 2):
            intel_level = "operational"
        else:
            intel_level = "tactical"

        # Aggregate confidence
        entity_confidences = [e.confidence for e in entities]
        confidence = ConfidenceScorer.aggregate_confidence(entity_confidences)

        context_id = f"ctx-{hashlib.md5(f'{title}:{now}'.encode()).hexdigest()[:12]}"

        return FusionContext(
            context_id=context_id,
            title=title,
            summary=summary,
            risk_score=risk_score,
            entities=entities,
            relationships=relationships,
            attack_chain=attack_chain,
            recommended_actions=actions,
            detection_signatures=[],  # Populated by DetectionForge
            intelligence_level=intel_level,
            confidence=confidence,
            timestamp=now,
            source_report_ids=[s.get("signal_id", "") for s in source_signals],
        )


# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE FUSION ENGINE (MAIN ORCHESTRATOR)
# ═══════════════════════════════════════════════════════════════════════════════

class IntelligenceFusionEngine:
    """
    Main fusion engine orchestrator.
    Reads existing STIX manifest data, runs the full fusion pipeline,
    and outputs correlated intelligence to data/fusion/.
    """

    def __init__(
        self,
        manifest_path: str = MANIFEST_PATH,
        output_dir: str = FUSION_DATA_DIR,
    ):
        self.manifest_path = manifest_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.normalizer = SignalNormalizer()
        self.extractor = EntityExtractor()
        self.mapper = RelationshipMapper()
        self.context_builder = ThreatContextBuilder()

        # Global entity store (in-memory knowledge graph)
        self.entity_store: Dict[str, FusionEntity] = {}
        self.relationship_store: List[FusionRelationship] = []
        self.fusion_contexts: List[FusionContext] = []

        # Stats
        self._stats = {
            "signals_processed": 0,
            "entities_extracted": 0,
            "relationships_mapped": 0,
            "contexts_generated": 0,
        }

    def load_manifest(self) -> List[Dict]:
        """Load existing feed manifest."""
        if not os.path.exists(self.manifest_path):
            logger.warning(f"Manifest not found: {self.manifest_path}")
            return []
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
            entries = data if isinstance(data, list) else data.get("entries", [])
            logger.info(f"Loaded {len(entries)} manifest entries")
            return entries
        except Exception as e:
            logger.error(f"Failed to load manifest: {e}")
            return []

    def _merge_entity(self, entity: FusionEntity) -> FusionEntity:
        """Merge entity into global store (dedup + confidence aggregation)."""
        if entity.entity_id in self.entity_store:
            existing = self.entity_store[entity.entity_id]
            existing.mention_count += 1
            existing.last_seen = entity.last_seen
            existing.source_signals.extend(entity.source_signals)
            existing.aliases = list(set(existing.aliases + entity.aliases))
            existing.confidence = ConfidenceScorer.aggregate_confidence(
                [existing.confidence, entity.confidence]
            )
            existing.properties.update(entity.properties)
            return existing
        else:
            self.entity_store[entity.entity_id] = entity
            return entity

    def _merge_relationship(self, rel: FusionRelationship):
        """Merge relationship (boost confidence on repeated observations)."""
        for existing in self.relationship_store:
            if (existing.source_id == rel.source_id and
                existing.target_id == rel.target_id and
                existing.relationship_type == rel.relationship_type):
                existing.evidence.extend(rel.evidence)
                existing.last_observed = rel.last_observed
                existing.confidence = min(1.0, existing.confidence + 0.05)
                return
        self.relationship_store.append(rel)

    def run_fusion(self, max_signals: int = 500, window_hours: int = 168) -> Dict:
        """
        Execute the full fusion pipeline.

        Args:
            max_signals: Maximum number of recent signals to process
            window_hours: Lookback window in hours (default: 7 days)

        Returns:
            Fusion report summary
        """
        logger.info("=" * 60)
        logger.info("SENTINEL APEX v33.0 — INTELLIGENCE FUSION ENGINE")
        logger.info("=" * 60)

        # 1. Load and normalize signals
        raw_entries = self.load_manifest()
        if not raw_entries:
            return {"status": "no_data", "message": "No manifest entries found"}

        # Filter to window
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        recent = [e for e in raw_entries if e.get("published", "") >= cutoff]
        if not recent:
            recent = raw_entries[-max_signals:]  # Fallback to most recent
        else:
            recent = recent[-max_signals:]

        signals = [self.normalizer.normalize_manifest_entry(e) for e in recent]
        self._stats["signals_processed"] = len(signals)
        logger.info(f"Normalized {len(signals)} signals")

        # 2. Extract entities from all signals
        all_entities = []
        all_relationships = []
        for signal in signals:
            entities = self.extractor.extract_entities(signal)
            for entity in entities:
                merged = self._merge_entity(entity)
                all_entities.append(merged)

            # Map intra-signal relationships
            rels = self.mapper.map_intra_signal(entities, signal)
            for rel in rels:
                self._merge_relationship(rel)
                all_relationships.append(rel)

        self._stats["entities_extracted"] = len(self.entity_store)
        self._stats["relationships_mapped"] = len(self.relationship_store)
        logger.info(f"Extracted {len(self.entity_store)} unique entities, {len(self.relationship_store)} relationships")

        # 3. Build fusion contexts (group by actor or campaign)
        contexts = self._build_contextual_groups(signals)
        self._stats["contexts_generated"] = len(contexts)
        self.fusion_contexts = contexts

        # 4. Save outputs
        self._save_fusion_output()

        # 5. Try to populate graph (optional, non-breaking)
        self._populate_graph()

        report = {
            "status": "success",
            "version": "33.0.0",
            "codename": "FUSION DOMINANCE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stats": self._stats,
            "entity_breakdown": dict(Counter(e.entity_type.value for e in self.entity_store.values())),
            "top_actors": [
                e.to_dict() for e in sorted(
                    [e for e in self.entity_store.values() if e.entity_type == EntityType.THREAT_ACTOR],
                    key=lambda x: x.mention_count, reverse=True
                )[:10]
            ],
            "top_cves": [
                e.to_dict() for e in sorted(
                    [e for e in self.entity_store.values() if e.entity_type == EntityType.CVE],
                    key=lambda x: x.mention_count, reverse=True
                )[:10]
            ],
            "top_sectors": [
                e.to_dict() for e in sorted(
                    [e for e in self.entity_store.values() if e.entity_type == EntityType.SECTOR],
                    key=lambda x: x.mention_count, reverse=True
                )[:10]
            ],
            "fusion_contexts": len(contexts),
        }

        logger.info(f"Fusion complete: {self._stats}")
        return report

    def _build_contextual_groups(self, signals: List[Dict]) -> List[FusionContext]:
        """Group signals into contextual intelligence reports."""
        contexts = []

        # Group by actor
        actor_signals: Dict[str, List[Dict]] = defaultdict(list)
        ungrouped = []
        for signal in signals:
            if signal.get("actor_id"):
                actor_key = signal["actor_id"].lower()
                actor_signals[actor_key].append(signal)
            else:
                ungrouped.append(signal)

        # Build context per actor group
        for actor_key, group_signals in actor_signals.items():
            group_entities = []
            group_rels = []
            for s in group_signals:
                entities = self.extractor.extract_entities(s)
                group_entities.extend(entities)
                rels = self.mapper.map_intra_signal(entities, s)
                group_rels.extend(rels)

            if group_entities:
                ctx = self.context_builder.build_context(group_entities, group_rels, group_signals)
                contexts.append(ctx)

        # Build contexts for ungrouped signals (batch by time window)
        if ungrouped:
            batch_size = 10
            for i in range(0, len(ungrouped), batch_size):
                batch = ungrouped[i:i + batch_size]
                batch_entities = []
                batch_rels = []
                for s in batch:
                    entities = self.extractor.extract_entities(s)
                    batch_entities.extend(entities)
                    rels = self.mapper.map_intra_signal(entities, s)
                    batch_rels.extend(rels)

                if batch_entities:
                    ctx = self.context_builder.build_context(batch_entities, batch_rels, batch)
                    contexts.append(ctx)

        return contexts

    def _save_fusion_output(self):
        """Save all fusion outputs to data/fusion/."""
        # Save entity store
        entities_path = os.path.join(self.output_dir, "entity_store.json")
        with open(entities_path, 'w') as f:
            json.dump(
                {eid: e.to_dict() for eid, e in self.entity_store.items()},
                f, indent=2, default=str
            )

        # Save relationships
        rels_path = os.path.join(self.output_dir, "relationship_store.json")
        with open(rels_path, 'w') as f:
            json.dump(
                [r.to_dict() for r in self.relationship_store],
                f, indent=2, default=str
            )

        # Save fusion contexts
        contexts_path = os.path.join(self.output_dir, "fusion_contexts.json")
        with open(contexts_path, 'w') as f:
            json.dump(
                [ctx.to_dict() for ctx in self.fusion_contexts],
                f, indent=2, default=str
            )

        # Save fusion summary
        summary_path = os.path.join(self.output_dir, "fusion_summary.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "version": "33.0.0",
                "last_run": datetime.now(timezone.utc).isoformat(),
                "stats": self._stats,
                "entity_count": len(self.entity_store),
                "relationship_count": len(self.relationship_store),
                "context_count": len(self.fusion_contexts),
            }, f, indent=2)

        logger.info(f"Fusion outputs saved to {self.output_dir}")

    def _populate_graph(self):
        """Populate the v29 graph backend (optional, non-breaking)."""
        try:
            from agent.v29.graph import get_client, Node, Edge
            client = get_client()

            for eid, entity in self.entity_store.items():
                client.add_node(Node(
                    id=eid,
                    label=entity.entity_type.value,
                    properties={
                        "name": entity.canonical_name,
                        "confidence": entity.confidence,
                        "mention_count": entity.mention_count,
                    }
                ))

            for rel in self.relationship_store:
                client.add_edge(Edge(
                    source_id=rel.source_id,
                    target_id=rel.target_id,
                    relationship=rel.relationship_type.value,
                    properties={"confidence": rel.confidence}
                ))

            health = client.health_check()
            logger.info(f"Graph populated: {health}")
        except Exception as e:
            logger.debug(f"Graph population skipped (optional): {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL THREAT INDEX
# ═══════════════════════════════════════════════════════════════════════════════

class GlobalThreatIndex:
    """
    Calculates the CyberDudeBivash Global Threat Index — a daily composite
    cyber risk score that media, enterprises, and SOCs can reference.
    """

    def __init__(self, manifest_path: str = MANIFEST_PATH):
        self.manifest_path = manifest_path

    def calculate(self, window_hours: int = 24) -> Dict:
        """Calculate current global threat index."""
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
        except Exception:
            return {"index": 5.0, "status": "insufficient_data"}

        entries = data if isinstance(data, list) else data.get("entries", [])
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        recent = [e for e in entries if e.get("published", "") >= cutoff]
        if not recent:
            recent = entries[-50:]

        # Component scores
        risk_scores = [e.get("risk_score", 5.0) for e in recent]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 5.0

        # Severity distribution
        critical_count = sum(1 for r in risk_scores if r >= 9.0)
        high_count = sum(1 for r in risk_scores if 7.0 <= r < 9.0)
        severity_factor = min(2.0, (critical_count * 0.3 + high_count * 0.1))

        # Volume factor (normalized)
        volume_factor = min(1.0, len(recent) / 50.0)

        # Unique actor count
        actors = set(e.get("actor_id", "") for e in recent if e.get("actor_id"))
        actor_factor = min(1.0, len(actors) * 0.15)

        # CVE exploitation factor
        cve_entries = [e for e in recent if e.get("cve_ids")]
        cve_factor = min(1.0, len(cve_entries) / max(1, len(recent)))

        # Composite index (0-10 scale)
        composite = (
            avg_risk * 0.4 +
            severity_factor * 1.5 +
            volume_factor * 1.0 +
            actor_factor * 1.5 +
            cve_factor * 1.0
        )
        index = min(10.0, max(0.0, composite))

        # Determine level
        if index >= 8.5:
            level = "CRITICAL"
        elif index >= 7.0:
            level = "HIGH"
        elif index >= 5.0:
            level = "ELEVATED"
        elif index >= 3.0:
            level = "GUARDED"
        else:
            level = "LOW"

        return {
            "index": round(index, 1),
            "level": level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "window_hours": window_hours,
            "signals_analyzed": len(recent),
            "components": {
                "avg_risk_score": round(avg_risk, 2),
                "severity_factor": round(severity_factor, 2),
                "volume_factor": round(volume_factor, 2),
                "actor_diversity": round(actor_factor, 2),
                "cve_exploitation": round(cve_factor, 2),
            },
            "critical_threats": critical_count,
            "high_threats": high_count,
            "active_actors": len(actors),
            "brand": "CyberDudeBivash Global Threat Index",
            "platform": "SENTINEL APEX v33.0",
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """CLI entry point for running the fusion engine."""
    logging.basicConfig(
        level=logging.INFO,
        format="[FUSION-ENGINE] %(asctime)s — %(levelname)s — %(message)s"
    )

    logger.info("Initializing SENTINEL APEX v33.0 — FUSION DOMINANCE")

    engine = IntelligenceFusionEngine()
    result = engine.run_fusion(max_signals=500, window_hours=168)

    # Also calculate Global Threat Index
    gti = GlobalThreatIndex()
    threat_index = gti.calculate(window_hours=24)

    # Save threat index
    index_path = os.path.join(FUSION_DATA_DIR, "global_threat_index.json")
    with open(index_path, 'w') as f:
        json.dump(threat_index, f, indent=2)

    logger.info(f"GLOBAL THREAT INDEX: {threat_index['index']}/10 ({threat_index['level']})")
    logger.info(f"Fusion complete: {result.get('stats', {})}")

    # Print summary
    print(json.dumps({
        "fusion_report": result,
        "global_threat_index": threat_index,
    }, indent=2, default=str))

    return result


if __name__ == "__main__":
    main()
