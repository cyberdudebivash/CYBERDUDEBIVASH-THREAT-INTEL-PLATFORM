"""
sdk/sentinel_sdk/models.py — CYBERDUDEBIVASH® Sentinel APEX Python SDK
Typed data models for all API response schemas.
Pure dataclasses — no external dependencies required.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────
# Advisory / Threat Intel
# ─────────────────────────────────────────────

@dataclass
class AdvisoryItem:
    """A single threat intelligence advisory from the Sentinel APEX feed."""
    stix_id:          str
    title:            str
    severity:         str
    risk_score:       float
    timestamp:        str
    blog_url:         str
    source_url:       str
    tlp_label:        str
    confidence_score: float
    threat_type:      str
    feed_source:      str
    kev_present:      bool
    cvss_score:       Optional[float] = None
    epss_score:       Optional[float] = None
    mitre_tactics:    List[str] = field(default_factory=list)
    iocs:             Dict[str, Any] = field(default_factory=dict)
    ai_summary:       Optional[str] = None
    recommendations:  List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AdvisoryItem":
        return cls(
            stix_id          = d.get("stix_id", ""),
            title            = d.get("title", ""),
            severity         = d.get("severity", ""),
            risk_score       = float(d.get("risk_score", 0)),
            timestamp        = d.get("timestamp", ""),
            blog_url         = d.get("blog_url", ""),
            source_url       = d.get("source_url", ""),
            tlp_label        = d.get("tlp_label", ""),
            confidence_score = float(d.get("confidence_score", 0)),
            threat_type      = d.get("threat_type", ""),
            feed_source      = d.get("feed_source", ""),
            kev_present      = bool(d.get("kev_present", False)),
            cvss_score       = d.get("cvss_score"),
            epss_score       = d.get("epss_score"),
            mitre_tactics    = d.get("mitre_tactics") or [],
            iocs             = d.get("iocs") or {},
            ai_summary       = d.get("ai_summary"),
            recommendations  = d.get("recommendations") or [],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stix_id":          self.stix_id,
            "title":            self.title,
            "severity":         self.severity,
            "risk_score":       self.risk_score,
            "timestamp":        self.timestamp,
            "blog_url":         self.blog_url,
            "source_url":       self.source_url,
            "tlp_label":        self.tlp_label,
            "confidence_score": self.confidence_score,
            "threat_type":      self.threat_type,
            "feed_source":      self.feed_source,
            "kev_present":      self.kev_present,
            "cvss_score":       self.cvss_score,
            "epss_score":       self.epss_score,
            "mitre_tactics":    self.mitre_tactics,
            "iocs":             self.iocs,
            "ai_summary":       self.ai_summary,
            "recommendations":  self.recommendations,
        }

    @property
    def is_critical(self) -> bool:
        return self.severity.upper() == "CRITICAL"

    @property
    def is_high_epss(self) -> bool:
        return (self.epss_score or 0) > 0.5


# ─────────────────────────────────────────────
# API Key / Auth
# ─────────────────────────────────────────────

@dataclass
class ApiKeyInfo:
    """API key metadata returned by key provisioning and introspection."""
    key:        str
    tier:       str
    owner:      str
    label:      str
    created_at: str
    expires_at: Optional[str] = None
    usage_today: int = 0
    daily_limit: int = 0
    is_active:  bool = True

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ApiKeyInfo":
        return cls(
            key         = d.get("key", ""),
            tier        = d.get("tier", ""),
            owner       = d.get("owner", ""),
            label       = d.get("label", ""),
            created_at  = d.get("created_at", ""),
            expires_at  = d.get("expires_at"),
            usage_today = int(d.get("usage_today", 0)),
            daily_limit = int(d.get("daily_limit", 0)),
            is_active   = bool(d.get("is_active", True)),
        )

    @property
    def usage_pct(self) -> float:
        if not self.daily_limit:
            return 0.0
        return round(self.usage_today / self.daily_limit * 100, 1)


# ─────────────────────────────────────────────
# Feed Metadata
# ─────────────────────────────────────────────

@dataclass
class FeedMetadata:
    """Feed-level metadata from the advisories list endpoint."""
    total:         int
    returned:      int
    page:          int
    tier:          str
    feed_version:  str
    last_updated:  str
    critical_count: int = 0
    high_count:    int = 0
    kev_count:     int = 0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FeedMetadata":
        meta = d.get("meta", d)
        return cls(
            total         = int(meta.get("total", 0)),
            returned      = int(meta.get("returned", 0)),
            page          = int(meta.get("page", 1)),
            tier          = meta.get("tier", ""),
            feed_version  = meta.get("feed_version", ""),
            last_updated  = meta.get("last_updated", ""),
            critical_count = int(meta.get("critical_count", 0)),
            high_count    = int(meta.get("high_count", 0)),
            kev_count     = int(meta.get("kev_count", 0)),
        )


# ─────────────────────────────────────────────
# Health / Status
# ─────────────────────────────────────────────

@dataclass
class HealthStatus:
    """Platform health status."""
    status:         str
    platform:       str
    version:        str
    components:     Dict[str, str] = field(default_factory=dict)
    uptime_s:       float = 0.0
    pipeline_ok:    bool = True

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HealthStatus":
        return cls(
            status      = d.get("status", "unknown"),
            platform    = d.get("platform", ""),
            version     = d.get("version", ""),
            components  = d.get("components", {}),
            uptime_s    = float(d.get("uptime_s", 0)),
            pipeline_ok = d.get("pipeline_ok", True),
        )

    @property
    def is_healthy(self) -> bool:
        return self.status in ("ok", "healthy", "degraded")


# ─────────────────────────────────────────────
# STIX Export
# ─────────────────────────────────────────────

@dataclass
class StixBundle:
    """STIX 2.1 bundle returned by export endpoints."""
    type:     str
    id:       str
    objects:  List[Dict[str, Any]] = field(default_factory=list)
    spec_version: str = "2.1"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StixBundle":
        return cls(
            type         = d.get("type", "bundle"),
            id           = d.get("id", ""),
            objects      = d.get("objects", []),
            spec_version = d.get("spec_version", "2.1"),
        )

    @property
    def object_count(self) -> int:
        return len(self.objects)


# ─────────────────────────────────────────────
# Paginated response wrapper
# ─────────────────────────────────────────────

@dataclass
class Page:
    """Generic paginated result container."""
    items:    List[Any]
    metadata: FeedMetadata
    raw:      Dict[str, Any] = field(default_factory=dict)

    @property
    def has_more(self) -> bool:
        return self.metadata.returned < self.metadata.total
