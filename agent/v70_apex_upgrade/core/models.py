"""
SENTINEL APEX v70 — Structured Threat Data Models
===================================================
Converts flat JSON into relational entities with graph-ready relationships.
Entities: Threat, IOC, CVE, Actor, Campaign, Advisory
All models are serializable, hashable, and STIX 2.1 compatible.
"""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score >= 0.1:
            return cls.LOW
        return cls.INFO


class IOCType(Enum):
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    EMAIL = "email-addr"
    MD5 = "file:hashes.MD5"
    SHA1 = "file:hashes.SHA-1"
    SHA256 = "file:hashes.SHA-256"
    FILENAME = "file:name"
    REGISTRY = "windows-registry-key"
    CVE = "vulnerability"
    UNKNOWN = "unknown"


class ThreatType(Enum):
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    INTRUSION_SET = "intrusion-set"
    TOOL = "tool"
    ATTACK_PATTERN = "attack-pattern"
    INDICATOR = "indicator"
    GENERIC = "threat-report"


class ConfidenceLevel(Enum):
    CONFIRMED = "confirmed"      # 85-100
    HIGH = "high"                # 65-84
    MODERATE = "moderate"        # 40-64
    LOW = "low"                  # 15-39
    UNVERIFIED = "unverified"    # 0-14

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        if score >= 85:
            return cls.CONFIRMED
        elif score >= 65:
            return cls.HIGH
        elif score >= 40:
            return cls.MODERATE
        elif score >= 15:
            return cls.LOW
        return cls.UNVERIFIED


# ---------------------------------------------------------------------------
# IOC Entity
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """Indicator of Compromise with type inference and dedup hash."""
    value: str
    ioc_type: IOCType = IOCType.UNKNOWN
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def __post_init__(self):
        if self.ioc_type == IOCType.UNKNOWN:
            self.ioc_type = self._infer_type()
        if not self.first_seen:
            self.first_seen = datetime.now(timezone.utc).isoformat()
        if not self.last_seen:
            self.last_seen = self.first_seen

    def _infer_type(self) -> IOCType:
        v = self.value.strip()
        if re.match(r"^CVE-\d{4}-\d{4,}$", v, re.IGNORECASE):
            return IOCType.CVE
        if re.match(r"^[a-f0-9]{64}$", v, re.IGNORECASE):
            return IOCType.SHA256
        if re.match(r"^[a-f0-9]{40}$", v, re.IGNORECASE):
            return IOCType.SHA1
        if re.match(r"^[a-f0-9]{32}$", v, re.IGNORECASE):
            return IOCType.MD5
        if re.match(r"^https?://", v, re.IGNORECASE):
            return IOCType.URL
        if re.match(r"^[^@]+@[^@]+\.[^@]+$", v):
            return IOCType.EMAIL
        if re.match(
            r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$",
            v,
        ):
            return IOCType.IPV4
        if ":" in v and re.match(r"^[0-9a-f:]+$", v, re.IGNORECASE):
            return IOCType.IPV6
        if re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$", v, re.IGNORECASE):
            return IOCType.DOMAIN
        return IOCType.UNKNOWN

    @property
    def dedup_key(self) -> str:
        return hashlib.sha256(
            f"{self.ioc_type.value}:{self.value.lower().strip()}".encode()
        ).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
            "tags": self.tags,
            "confidence": self.confidence,
            "dedup_key": self.dedup_key,
        }


# ---------------------------------------------------------------------------
# CVE Entity
# ---------------------------------------------------------------------------

@dataclass
class CVERecord:
    """CVE with enrichment fields for CVSS, EPSS, KEV status."""
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    kev_status: bool = False
    kev_date_added: str = ""
    exploit_available: bool = False
    exploit_sources: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_date: str = ""
    last_modified: str = ""
    severity: Severity = Severity.INFO

    def __post_init__(self):
        if self.cvss_score > 0:
            self.severity = Severity.from_cvss(self.cvss_score)

    @property
    def dedup_key(self) -> str:
        return self.cve_id.upper().strip()

    def compute_composite_score(self) -> float:
        """Weighted composite: CVSS(40%) + EPSS(25%) + KEV(20%) + Exploit(15%)."""
        cvss_norm = min(self.cvss_score / 10.0, 1.0)
        epss_norm = min(self.epss_score, 1.0)
        kev_val = 1.0 if self.kev_status else 0.0
        exploit_val = 1.0 if self.exploit_available else 0.0
        return round(
            (cvss_norm * 0.40 + epss_norm * 0.25 + kev_val * 0.20 + exploit_val * 0.15) * 100,
            2,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "kev_status": self.kev_status,
            "kev_date_added": self.kev_date_added,
            "exploit_available": self.exploit_available,
            "exploit_sources": self.exploit_sources,
            "cwe_ids": self.cwe_ids,
            "affected_products": self.affected_products,
            "severity": self.severity.value,
            "composite_score": self.compute_composite_score(),
            "published_date": self.published_date,
            "last_modified": self.last_modified,
        }


# ---------------------------------------------------------------------------
# Threat Actor Entity
# ---------------------------------------------------------------------------

@dataclass
class ThreatActor:
    """Threat actor / intrusion set with attribution data."""
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    motivation: str = ""  # financial, espionage, hacktivism, destruction
    sophistication: str = ""  # nation-state, advanced, intermediate, novice
    origin_country: str = ""
    target_sectors: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK IDs
    associated_malware: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 0.0

    @property
    def dedup_key(self) -> str:
        canon = self.name.lower().strip().replace(" ", "_")
        return hashlib.sha256(canon.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Campaign Entity
# ---------------------------------------------------------------------------

@dataclass
class Campaign:
    """Linked set of threat activities with common objective."""
    campaign_id: str = ""
    name: str = ""
    description: str = ""
    threat_actors: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    malware_used: List[str] = field(default_factory=list)
    cves_exploited: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)  # IOC dedup keys
    first_seen: str = ""
    last_seen: str = ""
    status: str = "active"  # active, inactive, historic

    def __post_init__(self):
        if not self.campaign_id:
            self.campaign_id = f"campaign--{uuid.uuid4()}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Advisory (unified threat entry — replaces flat manifest item)
# ---------------------------------------------------------------------------

@dataclass
class Advisory:
    """
    Unified threat advisory — the core entity in the manifest.
    Replaces the flat JSON structure with a relational model.
    Backward-compatible: to_legacy_dict() produces the old format.
    """
    advisory_id: str = ""
    title: str = ""
    summary: str = ""
    source_url: str = ""
    source_name: str = ""
    published_date: str = ""
    ingested_date: str = ""
    threat_type: ThreatType = ThreatType.GENERIC
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.UNVERIFIED

    # Linked entities (by dedup_key / ID)
    cves: List[str] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Enrichment
    attack_chain: List[str] = field(default_factory=list)  # Kill-chain phases
    affected_products: List[str] = field(default_factory=list)
    affected_sectors: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Scoring
    threat_score: float = 0.0
    risk_level: str = ""

    # AI-generated fields
    ai_summary: str = ""
    ai_cluster_id: str = ""
    ai_classification: str = ""

    # Correlation
    related_advisories: List[str] = field(default_factory=list)
    correlation_keys: List[str] = field(default_factory=list)

    # STIX
    stix_id: str = ""
    stix_bundle_ref: str = ""

    # Blog
    blog_post_url: str = ""
    blog_post_id: str = ""

    def __post_init__(self):
        if not self.advisory_id:
            self.advisory_id = f"advisory--{uuid.uuid4()}"
        if not self.ingested_date:
            self.ingested_date = datetime.now(timezone.utc).isoformat()
        if self.confidence > 0:
            self.confidence_level = ConfidenceLevel.from_score(self.confidence)
        if not self.stix_id:
            self.stix_id = f"report--{uuid.uuid4()}"

    @property
    def dedup_key(self) -> str:
        """Content-based dedup: hash of title + source + CVEs."""
        raw = f"{self.title.lower().strip()}|{self.source_url.strip()}|{'|'.join(sorted(self.cves))}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def to_dict(self) -> Dict[str, Any]:
        """Full structured representation."""
        d = {
            "advisory_id": self.advisory_id,
            "dedup_key": self.dedup_key,
            "title": self.title,
            "summary": self.summary,
            "source_url": self.source_url,
            "source_name": self.source_name,
            "published_date": self.published_date,
            "ingested_date": self.ingested_date,
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "cves": self.cves,
            "iocs": [ioc.to_dict() if isinstance(ioc, IOC) else ioc for ioc in self.iocs],
            "actors": self.actors,
            "campaigns": self.campaigns,
            "mitre_techniques": self.mitre_techniques,
            "attack_chain": self.attack_chain,
            "affected_products": self.affected_products,
            "affected_sectors": self.affected_sectors,
            "tags": self.tags,
            "threat_score": self.threat_score,
            "risk_level": self.risk_level,
            "ai_summary": self.ai_summary,
            "ai_cluster_id": self.ai_cluster_id,
            "ai_classification": self.ai_classification,
            "related_advisories": self.related_advisories,
            "correlation_keys": self.correlation_keys,
            "stix_id": self.stix_id,
            "stix_bundle_ref": self.stix_bundle_ref,
            "blog_post_url": self.blog_post_url,
            "blog_post_id": self.blog_post_id,
        }
        return d

    def to_legacy_dict(self) -> Dict[str, Any]:
        """Backward-compatible flat format for existing dashboard."""
        return {
            "title": self.title,
            "description": self.summary or self.ai_summary,
            "source": self.source_name,
            "link": self.source_url,
            "published": self.published_date,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "cves": self.cves,
            "iocs": [
                ioc.value if isinstance(ioc, IOC) else (ioc.get("value", str(ioc)) if isinstance(ioc, dict) else str(ioc))
                for ioc in self.iocs
            ],
            "threat_score": self.threat_score,
            "threat_type": self.threat_type.value,
            "mitre_techniques": self.mitre_techniques,
            "actors": self.actors,
            "tags": self.tags,
            # v70 enrichment fields (additive — existing dashboard ignores unknown keys)
            "advisory_id": self.advisory_id,
            "dedup_key": self.dedup_key,
            "confidence_level": self.confidence_level.value,
            "risk_level": self.risk_level,
            "ai_summary": self.ai_summary,
            "ai_cluster_id": self.ai_cluster_id,
            "related_advisories": self.related_advisories,
            "attack_chain": self.attack_chain,
            "blog_post_url": self.blog_post_url,
        }


# ---------------------------------------------------------------------------
# Manifest (the top-level container — versioned, validated)
# ---------------------------------------------------------------------------

@dataclass
class Manifest:
    """Versioned manifest container with metadata and advisory list."""
    version: str = "70.0"
    schema_version: str = "2.0"
    generated_at: str = ""
    generator: str = "SENTINEL_APEX_v70"
    total_advisories: int = 0
    total_cves: int = 0
    total_iocs: int = 0
    advisories: List[Dict[str, Any]] = field(default_factory=list)
    cve_index: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    actor_index: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    campaign_index: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "generator": self.generator,
            "total_advisories": self.total_advisories,
            "total_cves": self.total_cves,
            "total_iocs": self.total_iocs,
            "advisories": self.advisories,
            "cve_index": self.cve_index,
            "actor_index": self.actor_index,
            "campaign_index": self.campaign_index,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ---------------------------------------------------------------------------
# Factory: Convert legacy flat items → Advisory
# ---------------------------------------------------------------------------

def advisory_from_legacy(item: Dict[str, Any]) -> Advisory:
    """Convert a legacy flat manifest item into a structured Advisory."""
    # Infer threat type
    threat_type = ThreatType.GENERIC
    cves = item.get("cves", [])
    title_lower = (item.get("title", "") or "").lower()
    if cves:
        threat_type = ThreatType.VULNERABILITY
    elif "malware" in title_lower or "ransomware" in title_lower:
        threat_type = ThreatType.MALWARE
    elif "campaign" in title_lower or "apt" in title_lower:
        threat_type = ThreatType.CAMPAIGN

    # Build IOCs
    raw_iocs = item.get("iocs", [])
    iocs = []
    for raw in raw_iocs:
        if isinstance(raw, str):
            iocs.append(IOC(value=raw, source=item.get("source", "")))
        elif isinstance(raw, dict):
            iocs.append(IOC(
                value=raw.get("value", ""),
                ioc_type=IOCType(raw.get("type", "unknown")),
                source=raw.get("source", item.get("source", "")),
            ))

    # Severity
    sev_str = (item.get("severity", "") or "").lower()
    severity = Severity.INFO
    for s in Severity:
        if s.value == sev_str:
            severity = s
            break

    return Advisory(
        advisory_id=item.get("advisory_id", ""),
        title=item.get("title", ""),
        summary=item.get("description", "") or item.get("summary", ""),
        source_url=item.get("link", "") or item.get("source_url", ""),
        source_name=item.get("source", "") or item.get("source_name", ""),
        published_date=item.get("published", "") or item.get("published_date", ""),
        threat_type=threat_type,
        severity=severity,
        confidence=float(item.get("confidence", 0)),
        cves=cves,
        iocs=iocs,
        actors=item.get("actors", []),
        mitre_techniques=item.get("mitre_techniques", []),
        tags=item.get("tags", []),
        threat_score=float(item.get("threat_score", 0)),
        blog_post_url=item.get("blog_post_url", ""),
        blog_post_id=item.get("blog_post_id", ""),
    )
