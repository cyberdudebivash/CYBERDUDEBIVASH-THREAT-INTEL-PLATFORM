"""
core/ingestion/normalizer.py — CYBERDUDEBIVASH® SENTINEL APEX v134.0
Schema normalizer: maps heterogeneous RawIntelItem → unified IntelItem.

Unified schema (IntelItem) is the canonical format consumed by:
  - AI enrichment engine
  - Detection rule generator
  - STIX export
  - Dashboard feed
  - Storage layer

Design:
  - Type-dispatched normalization via registry pattern
  - Lossy-safe: unknown fields go into `extra` dict
  - Validates required fields; drops items that fail validation
  - Adds normalized_at timestamp and pipeline_version tag
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .sources.base import RawIntelItem, SourceType

logger = logging.getLogger("sentinel.ingestion.normalizer")

_PIPELINE_VERSION = "100.0.0"


# ─────────────────────────────────────────────
# Unified Intel Schema
# ─────────────────────────────────────────────

@dataclass
class IntelItem:
    """
    Canonical threat intelligence item.
    All sources map into this schema before downstream processing.
    """
    # ── Identity ─────────────────────────────────
    intel_id:       str                         # Globally unique: source_id:raw_id
    source_id:      str                         # Originating source
    source_type:    str                         # SourceType value string
    raw_id:         str                         # Source-native primary key
    content_hash:   str                         # For deduplication reference

    # ── Classification ────────────────────────────
    intel_type:     str                         # cve | malware | ip | indicator | kev
    title:          str                         # Human-readable short title
    description:    str                         # Full description / summary
    severity:       str                         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    base_score:     float                       # Numeric severity (0–10)

    # ── Temporal ─────────────────────────────────
    fetched_at:     float                       # Unix timestamp from source fetch
    normalized_at:  float = field(default_factory=time.time)
    published_at:   Optional[str] = None        # ISO8601 string from source

    # ── Threat context ────────────────────────────
    tags:           List[str] = field(default_factory=list)
    iocs:           Dict[str, Any] = field(default_factory=dict)
    threat_actors:  List[str] = field(default_factory=list)
    malware_family: str = ""
    cve_id:         Optional[str] = None
    cvss_v3:        Dict[str, Any] = field(default_factory=dict)
    epss_score:     Optional[float] = None
    epss_percentile: Optional[float] = None
    actively_exploited: bool = False
    cisa_kev:       bool = False

    # ── Attribution / geo ─────────────────────────
    country_code:   str = ""
    isp:            str = ""

    # ── Pipeline ─────────────────────────────────
    pipeline_version: str = _PIPELINE_VERSION
    extra:          Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intel_id":          self.intel_id,
            "source_id":         self.source_id,
            "source_type":       self.source_type,
            "raw_id":            self.raw_id,
            "content_hash":      self.content_hash,
            "intel_type":        self.intel_type,
            "title":             self.title,
            "description":       self.description,
            "severity":          self.severity,
            "base_score":        self.base_score,
            "fetched_at":        self.fetched_at,
            "normalized_at":     self.normalized_at,
            "published_at":      self.published_at,
            "tags":              self.tags,
            "iocs":              self.iocs,
            "threat_actors":     self.threat_actors,
            "malware_family":    self.malware_family,
            "cve_id":            self.cve_id,
            "cvss_v3":           self.cvss_v3,
            "epss_score":        self.epss_score,
            "epss_percentile":   self.epss_percentile,
            "actively_exploited": self.actively_exploited,
            "cisa_kev":          self.cisa_kev,
            "country_code":      self.country_code,
            "isp":               self.isp,
            "pipeline_version":  self.pipeline_version,
            "extra":             self.extra,
        }


# ─────────────────────────────────────────────
# Normalizer Registry
# ─────────────────────────────────────────────

_NormalizerFn = Callable[[RawIntelItem], Optional[IntelItem]]
_REGISTRY: Dict[str, _NormalizerFn] = {}


def _register(source_type: SourceType):
    """Decorator: register a normalizer function for a source type."""
    def decorator(fn: _NormalizerFn) -> _NormalizerFn:
        _REGISTRY[source_type.value] = fn
        return fn
    return decorator


# ─────────────────────────────────────────────
# Type-Specific Normalizers
# ─────────────────────────────────────────────

@_register(SourceType.CVE)
def _normalize_cve(item: RawIntelItem) -> Optional[IntelItem]:
    d = item.raw_data
    cve_id = d.get("cve_id") or item.raw_id
    desc   = d.get("description", "")
    score  = float(d.get("base_score") or 0)
    sev    = _canonicalize_severity(d.get("severity", ""), score)

    return IntelItem(
        intel_id       = f"{item.source_id}:{cve_id}",
        source_id      = item.source_id,
        source_type    = item.source_type.value,
        raw_id         = item.raw_id,
        content_hash   = item.content_hash,
        intel_type     = "cve",
        title          = f"{cve_id}: {desc[:80]}{'…' if len(desc)>80 else ''}",
        description    = desc,
        severity       = sev,
        base_score     = score,
        fetched_at     = item.fetched_at,
        published_at   = d.get("published"),
        tags           = _build_cve_tags(d),
        iocs           = {"cve_id": cve_id, "cpes": d.get("affected_cpes", [])[:10]},
        cve_id         = cve_id,
        cvss_v3        = d.get("cvss_v3", {}),
        epss_score     = d.get("epss_score"),
        epss_percentile = d.get("epss_percentile"),
        actively_exploited = d.get("actively_exploited", False),
        cisa_kev       = item.source_id == "cisa_kev",
        extra          = {
            "cwes":        d.get("cwes", []),
            "references":  d.get("references", [])[:5],
            "vuln_status": d.get("vulnStatus", ""),
            "cvss_v2":     d.get("cvss_v2", {}),
        },
    )


@_register(SourceType.KEV)
def _normalize_kev(item: RawIntelItem) -> Optional[IntelItem]:
    d = item.raw_data
    cve_id = d.get("cve_id") or item.raw_id
    vendor = d.get("vendor_project", "")
    product = d.get("product", "")
    vuln_name = d.get("vulnerability_name", "")

    title = f"[KEV] {cve_id}: {vuln_name or vendor+' '+product}"
    desc  = d.get("short_description", "") or d.get("required_action", "")

    return IntelItem(
        intel_id       = f"cisa_kev:{cve_id}",
        source_id      = item.source_id,
        source_type    = item.source_type.value,
        raw_id         = item.raw_id,
        content_hash   = item.content_hash,
        intel_type     = "kev",
        title          = title[:200],
        description    = desc,
        severity       = "CRITICAL",
        base_score     = float(d.get("base_score", 9.0)),
        fetched_at     = item.fetched_at,
        published_at   = d.get("date_added"),
        tags           = ["kev", "actively-exploited", "cisa-mandate", "patch-required"],
        iocs           = {"cve_id": cve_id},
        cve_id         = cve_id,
        actively_exploited = True,
        cisa_kev       = True,
        extra          = {
            "vendor_project":  vendor,
            "product":         product,
            "due_date":        d.get("due_date", ""),
            "required_action": d.get("required_action", ""),
            "known_ransomware": d.get("known_ransomware", "Unknown"),
            "notes":           d.get("notes", ""),
        },
    )


@_register(SourceType.MALWARE)
def _normalize_malware(item: RawIntelItem) -> Optional[IntelItem]:
    d = item.raw_data
    sha256 = d.get("sha256") or item.raw_id
    sig    = d.get("signature") or d.get("malware_family", "")
    fname  = d.get("file_name", "")
    ftype  = d.get("file_type", "")
    tags   = list(d.get("tags") or [])

    title = f"[Malware] {sig or fname or sha256[:16]}"
    desc  = (
        f"File: {fname} | Type: {ftype} | Family: {sig or 'Unknown'} | "
        f"Tags: {', '.join(tags[:5]) if tags else 'none'}"
    )

    iocs: Dict[str, Any] = {
        "sha256":    sha256,
        "md5":       d.get("md5", ""),
        "sha1":      d.get("sha1", ""),
        "filename":  fname,
        "c2_urls":   d.get("c2_urls", []),
    }

    return IntelItem(
        intel_id      = f"malwarebazaar:{sha256}",
        source_id     = item.source_id,
        source_type   = item.source_type.value,
        raw_id        = item.raw_id,
        content_hash  = item.content_hash,
        intel_type    = "malware",
        title         = title,
        description   = desc,
        severity      = d.get("severity", "MEDIUM"),
        base_score    = float(d.get("base_score", 5.0)),
        fetched_at    = item.fetched_at,
        published_at  = d.get("first_seen"),
        tags          = tags[:20],
        iocs          = iocs,
        malware_family = sig,
        extra         = {
            "file_size":    d.get("file_size", 0),
            "mime_type":    d.get("mime_type", ""),
            "reporter":     d.get("reporter", ""),
            "yara_hits":    d.get("yara_hits", []),
            "vendor_intel": d.get("vendor_intel", {}),
            "origin_country": d.get("origin_country", ""),
        },
    )


@_register(SourceType.IP_THREAT)
def _normalize_ip(item: RawIntelItem) -> Optional[IntelItem]:
    d = item.raw_data
    ip         = d.get("ip_address") or item.raw_id
    isp        = d.get("isp", "")
    country    = d.get("country_code", "")
    confidence = int(d.get("abuse_confidence_score", 0))
    categories = d.get("abuse_categories", [])

    title = f"[IP Threat] {ip} — {isp or country} (confidence: {confidence}%)"
    desc  = (
        f"Abusive IP {ip} from {country}/{isp}. "
        f"Confidence: {confidence}%. Reports: {d.get('total_reports', 0)}. "
        f"Abuse types: {', '.join(categories[:5]) if categories else 'unknown'}."
    )

    return IntelItem(
        intel_id      = f"abuseipdb:{ip}",
        source_id     = item.source_id,
        source_type   = item.source_type.value,
        raw_id        = item.raw_id,
        content_hash  = item.content_hash,
        intel_type    = "ip_threat",
        title         = title,
        description   = desc,
        severity      = d.get("severity", "MEDIUM"),
        base_score    = float(d.get("base_score", 5.0)),
        fetched_at    = item.fetched_at,
        published_at  = d.get("last_reported_at"),
        tags          = [c.lower().replace(" ", "-") for c in categories[:10]],
        iocs          = {
            "ip":          ip,
            "country":     country,
            "isp":         isp,
            "is_tor":      d.get("is_tor", False),
        },
        country_code  = country,
        isp           = isp,
        extra         = {
            "total_reports":      d.get("total_reports", 0),
            "distinct_users":     d.get("num_distinct_users", 0),
            "is_tor":             d.get("is_tor", False),
            "is_public":          d.get("is_public", True),
            "abuse_confidence":   confidence,
            "recent_reports":     d.get("recent_reports", [])[:5],
        },
    )


# Fallback for generic source types
@_register(SourceType.GENERIC)
@_register(SourceType.INDICATOR)
@_register(SourceType.THREAT_ACTOR)
def _normalize_generic(item: RawIntelItem) -> Optional[IntelItem]:
    d = item.raw_data
    return IntelItem(
        intel_id      = f"{item.source_id}:{item.raw_id}",
        source_id     = item.source_id,
        source_type   = item.source_type.value,
        raw_id        = item.raw_id,
        content_hash  = item.content_hash,
        intel_type    = item.source_type.value,
        title         = d.get("title", "") or f"{item.source_id}:{item.raw_id}",
        description   = d.get("description", "") or str(d)[:500],
        severity      = _canonicalize_severity(d.get("severity", ""), float(d.get("base_score", 0))),
        base_score    = float(d.get("base_score", 0)),
        fetched_at    = item.fetched_at,
        extra         = d,
    )


# ─────────────────────────────────────────────
# Main Normalizer Class
# ─────────────────────────────────────────────

class Normalizer:
    """
    Dispatches RawIntelItem → IntelItem using the type-registered normalizer.
    Validates output and logs failures without raising.
    """

    def normalize(self, item: RawIntelItem) -> Optional[IntelItem]:
        fn = _REGISTRY.get(item.source_type.value)
        if not fn:
            # Try GENERIC fallback
            fn = _REGISTRY.get(SourceType.GENERIC.value)

        if not fn:
            logger.warning("normalizer_no_fn source_type=%s", item.source_type.value)
            return None

        try:
            normalized = fn(item)
            if normalized and self._validate(normalized):
                return normalized
            logger.warning("normalizer_validation_failed raw_id=%s", item.raw_id)
            return None
        except Exception as exc:
            logger.error("normalizer_error source=%s raw_id=%s err=%s",
                         item.source_id, item.raw_id, exc, exc_info=True)
            return None

    def normalize_batch(
        self, items: List[RawIntelItem]
    ) -> tuple[List[IntelItem], int]:
        """
        Normalize a batch.
        Returns (normalized_items, error_count).
        """
        results: List[IntelItem] = []
        errors = 0
        for item in items:
            norm = self.normalize(item)
            if norm:
                results.append(norm)
            else:
                errors += 1
        return results, errors

    @staticmethod
    def _validate(item: IntelItem) -> bool:
        if not item.intel_id:
            return False
        if not item.title:
            return False
        if item.base_score < 0 or item.base_score > 10:
            return False
        return True


# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def _canonicalize_severity(severity: str, score: float) -> str:
    """Map source-specific severity strings + CVSS score to canonical enum."""
    s = severity.upper().strip()
    canonical_map = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW":      "LOW",
        "NONE":     "INFO",
        "INFO":     "INFO",
        "INFORMATIONAL": "INFO",
    }
    if s in canonical_map:
        return canonical_map[s]
    # Fall back to CVSS score banding
    if score >= 9.0:   return "CRITICAL"
    if score >= 7.0:   return "HIGH"
    if score >= 4.0:   return "MEDIUM"
    if score >= 0.1:   return "LOW"
    return "INFO"


def _build_cve_tags(d: Dict[str, Any]) -> List[str]:
    tags = ["cve"]
    if d.get("epss_score", 0.0) >= 0.7:
        tags.append("high-epss")
    if d.get("kev_present") or d.get("kev_due_date"):
        tags.append("kev")
        tags.append("actively-exploited")
    if d.get("base_score", 0.0) >= 9.0:
        tags.append("critical-cvss")
    cwes = d.get("cwe_ids", []) or []
    for cwe in cwes[:3]:
        tags.append(cwe.lower().replace(" ", "-"))
    return list(dict.fromkeys(tags))  # deduplicate, preserve order


def _build_malware_tags(d: Dict[str, Any]) -> List[str]:
    """Build tag list for malware/indicator items."""
    tags = ["malware"]
    sig = d.get("signature", "").lower()
    if sig:
        tags.append(sig.replace(" ", "-")[:40])
    for t in d.get("tags", [])[:5]:
        tags.append(str(t).lower().replace(" ", "-")[:30])
    if d.get("c2_urls"):
        tags.append("c2")
    return list(dict.fromkeys(tags))


def _build_ip_tags(d: Dict[str, Any]) -> List[str]:
    """Build tag list for IP threat items."""
    tags = ["ip-threat"]
    abuse_types = d.get("abuse_types", [])
    for at in abuse_types[:3]:
        tags.append(str(at).lower().replace(" ", "-")[:30])
    confidence = d.get("abuse_confidence_score", 0)
    if confidence >= 90:
        tags.append("high-confidence")
    return list(dict.fromkeys(tags))
