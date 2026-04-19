"""
CYBERDUDEBIVASH SENTINEL APEX v123.0.0
IOC Enrichment Graph Engine

Production-grade threat intelligence graph engine providing:
  - Multi-source OSINT IOC enrichment (VirusTotal, AbuseIPDB, Shodan, URLhaus,
    ThreatFox, AlienVault OTX)
  - Pure Python dict-based adjacency graph (no networkx dependency)
  - PageRank-like authority scoring
  - STIX 2.1 bundle export
  - BFS graph traversal for relationship discovery
  - Campaign correlation and actor attribution
  - Thread-safe operations with RLock
  - JSON persistence
  - Community feed sharing (Phase 6 network effect)

Usage:
    from core.intelligence.enrichment_graph import graph
    print(graph.stats())
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional requests import — graceful degradation
# ---------------------------------------------------------------------------
try:
    import requests as _requests

    _REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _requests = None  # type: ignore[assignment]
    _REQUESTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("sentinel_apex.intelligence.enrichment_graph")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# TypedDict-compatible classes (stdlib only; TypedDict from typing >= 3.8)
# ---------------------------------------------------------------------------
try:
    from typing import TypedDict  # Python 3.8+
except ImportError:  # pragma: no cover
    from typing_extensions import TypedDict  # type: ignore[no-redef]


class IOCNode(TypedDict):
    """Represents a single Indicator of Compromise node in the graph."""

    id: str
    type: str           # IP | DOMAIN | HASH | URL | EMAIL | CVE | ACTOR | CAMPAIGN | MALWARE_FAMILY
    value: str          # normalised raw value
    first_seen: str     # ISO-8601
    last_seen: str      # ISO-8601
    confidence: int     # 0-100
    source_count: int
    sources: List[str]
    tags: List[str]
    enrichment: Dict[str, Any]


class IOCEdge(TypedDict):
    """Represents a directed relationship between two IOC nodes."""

    source_id: str
    target_id: str
    type: str           # RESOLVES_TO | COMMUNICATES_WITH | HOSTS | ATTRIBUTED_TO | PART_OF | SHARES_INFRASTRUCTURE | DROPS | EXPLOITS
    weight: float       # 0.0-1.0
    first_seen: str     # ISO-8601
    evidence: List[str]


class EnrichmentResult(TypedDict):
    """Return value from enrich_ioc()."""

    node_id: str
    ioc_value: str
    ioc_type: str
    sources_queried: List[str]
    sources_responded: List[str]
    enriched_node: IOCNode
    raw_responses: Dict[str, Any]
    elapsed_seconds: float


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NODE_TYPES = frozenset(
    {"IP", "DOMAIN", "HASH", "URL", "EMAIL", "CVE", "ACTOR", "CAMPAIGN", "MALWARE_FAMILY"}
)

EDGE_TYPES = frozenset(
    {
        "RESOLVES_TO",
        "COMMUNICATES_WITH",
        "HOSTS",
        "ATTRIBUTED_TO",
        "PART_OF",
        "SHARES_INFRASTRUCTURE",
        "DROPS",
        "EXPLOITS",
    }
)

# Per-source trust weights used in confidence calculation
SOURCE_TRUST = {
    "virustotal": 0.95,
    "abuseipdb": 0.85,
    "urlhaus": 0.90,
    "threatfox": 0.88,
    "otx": 0.80,
    "shodan": 0.70,
}

# Per-domain rate limit: (max_calls, window_seconds)
RATE_LIMITS: Dict[str, Tuple[int, int]] = {
    "www.virustotal.com": (4, 60),
    "api.abuseipdb.com": (10, 60),
    "api.shodan.io": (1, 1),
    "urlhaus-api.abuse.ch": (20, 60),
    "threatfox-api.abuse.ch": (10, 60),
    "otx.alienvault.com": (10, 60),
}

_HTTP_TIMEOUT = 5  # seconds
_HTTP_RETRIES = 2


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Token-bucket rate limiter keyed by domain.

    Tracks call timestamps per domain and blocks (sleeps) when the
    configured rate is exceeded.  Thread-safe via per-domain locks.
    """

    def __init__(self) -> None:
        self._locks: Dict[str, threading.Lock] = {}
        self._history: Dict[str, deque] = {}
        self._meta_lock = threading.Lock()

    def _ensure_domain(self, domain: str) -> None:
        with self._meta_lock:
            if domain not in self._locks:
                self._locks[domain] = threading.Lock()
                self._history[domain] = deque()

    def acquire(self, domain: str) -> None:
        """Block until the rate limit for *domain* allows another call."""
        self._ensure_domain(domain)
        max_calls, window = RATE_LIMITS.get(domain, (30, 60))
        with self._locks[domain]:
            now = time.monotonic()
            history = self._history[domain]
            # Purge timestamps older than window
            while history and now - history[0] >= window:
                history.popleft()
            if len(history) >= max_calls:
                sleep_for = window - (now - history[0]) + 0.05
                logger.debug("Rate limit hit for %s — sleeping %.2fs", domain, sleep_for)
                time.sleep(max(0.0, sleep_for))
                # Re-purge after sleep
                now = time.monotonic()
                while history and now - history[0] >= window:
                    history.popleft()
            history.append(time.monotonic())


_rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = _HTTP_TIMEOUT,
    retries: int = _HTTP_RETRIES,
) -> Optional[Dict[str, Any]]:
    """Perform a GET request with retries, rate limiting, and graceful errors.

    Returns the parsed JSON body on success, or None on failure.
    """
    if not _REQUESTS_AVAILABLE:
        logger.warning("requests library not available — skipping HTTP call to %s", url)
        return None
    from urllib.parse import urlparse

    domain = urlparse(url).netloc
    _rate_limiter.acquire(domain)

    for attempt in range(1, retries + 1):
        try:
            resp = _requests.get(url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "10"))
                logger.warning("429 from %s — waiting %ds", domain, retry_after)
                time.sleep(retry_after)
                continue
            if resp.status_code in (401, 403):
                logger.warning("Auth error %d from %s", resp.status_code, domain)
                return None
            logger.debug("HTTP %d from %s (attempt %d)", resp.status_code, domain, attempt)
        except Exception as exc:  # noqa: BLE001
            logger.debug("HTTP error on %s attempt %d: %s", url, attempt, exc)
            if attempt < retries:
                time.sleep(1.5 ** attempt)
    return None


def _http_post(
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = _HTTP_TIMEOUT,
    retries: int = _HTTP_RETRIES,
) -> Optional[Dict[str, Any]]:
    """Perform a POST request with retries and graceful errors."""
    if not _REQUESTS_AVAILABLE:
        return None
    from urllib.parse import urlparse

    domain = urlparse(url).netloc
    _rate_limiter.acquire(domain)

    for attempt in range(1, retries + 1):
        try:
            resp = _requests.post(url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            logger.debug("HTTP POST %d from %s (attempt %d)", resp.status_code, domain, attempt)
        except Exception as exc:  # noqa: BLE001
            logger.debug("HTTP POST error on %s attempt %d: %s", url, attempt, exc)
            if attempt < retries:
                time.sleep(1.5 ** attempt)
    return None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_node_id(ioc_type: str, value: str) -> str:
    """Deterministically derive a stable node ID from type+value."""
    digest = hashlib.sha256(f"{ioc_type.upper()}:{value.lower()}".encode()).hexdigest()[:16]
    return f"{ioc_type.upper()}:{digest}"


def _normalize_value(value: str) -> str:
    """Strip whitespace and lower-case the IOC value."""
    return value.strip().lower()


def _infer_ioc_type(value: str) -> str:
    """Best-effort IOC type inference from value shape."""
    v = value.strip()
    # IPv4
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "IP"
    # IPv6
    if re.match(r"^[0-9a-fA-F:]{2,39}$", v) and ":" in v:
        return "IP"
    # CVE
    if re.match(r"^CVE-\d{4}-\d+$", v, re.IGNORECASE):
        return "CVE"
    # Hash — MD5/SHA1/SHA256
    if re.match(r"^[0-9a-fA-F]{32}$", v):
        return "HASH"
    if re.match(r"^[0-9a-fA-F]{40}$", v):
        return "HASH"
    if re.match(r"^[0-9a-fA-F]{64}$", v):
        return "HASH"
    # URL
    if re.match(r"^https?://", v, re.IGNORECASE):
        return "URL"
    # Email
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "EMAIL"
    # Domain (fallback)
    if "." in v and not v.startswith("/"):
        return "DOMAIN"
    return "DOMAIN"


# ---------------------------------------------------------------------------
# OSINT source adapters
# ---------------------------------------------------------------------------


class _VirusTotalAdapter:
    """Thin wrapper around the VirusTotal v3 public API."""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self) -> None:
        self.key = os.environ.get("VT_API_KEY", "")

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.key}

    def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query VT for IP reputation data."""
        if not self.key:
            return None
        return _http_get(f"{self.BASE}/ip_addresses/{ip}", headers=self._headers())

    def query_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query VT for domain reputation data."""
        if not self.key:
            return None
        return _http_get(f"{self.BASE}/domains/{domain}", headers=self._headers())

    def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query VT for file hash reputation data."""
        if not self.key:
            return None
        return _http_get(f"{self.BASE}/files/{file_hash}", headers=self._headers())

    def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query VT for URL reputation data (URL-safe base64 encoded)."""
        if not self.key:
            return None
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return _http_get(f"{self.BASE}/urls/{url_id}", headers=self._headers())

    def extract_verdict(self, data: Optional[Dict[str, Any]]) -> Tuple[bool, int, int]:
        """Return (is_malicious, malicious_count, total_engines) from VT response."""
        if not data:
            return False, 0, 0
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        return malicious > 0, malicious, total


class _AbuseIPDBAdapter:
    """Thin wrapper around the AbuseIPDB v2 API."""

    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self) -> None:
        self.key = os.environ.get("ABUSEIPDB_KEY", "")

    def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB for IP confidence score."""
        if not self.key:
            return None
        return _http_get(
            f"{self.BASE}/check",
            headers={"Key": self.key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
        )

    def extract_verdict(self, data: Optional[Dict[str, Any]]) -> Tuple[bool, int]:
        """Return (is_malicious, abuse_confidence_score) from AbuseIPDB response."""
        if not data:
            return False, 0
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        return score >= 25, score


class _ShodanAdapter:
    """Thin wrapper around the Shodan InternetDB (free) and REST API."""

    BASE_FREE = "https://internetdb.shodan.io"
    BASE_REST = "https://api.shodan.io"

    def __init__(self) -> None:
        self.key = os.environ.get("SHODAN_KEY", "")

    def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query Shodan for open ports, vulnerabilities, and tags on an IP."""
        # internetdb is free and doesn't require a key
        data = _http_get(f"{self.BASE_FREE}/{ip}")
        if data:
            return data
        if self.key:
            return _http_get(
                f"{self.BASE_REST}/shodan/host/{ip}",
                params={"key": self.key},
            )
        return None

    def extract_tags(self, data: Optional[Dict[str, Any]]) -> List[str]:
        """Extract Shodan tags/vulns from response."""
        if not data:
            return []
        tags: List[str] = list(data.get("tags", []))
        vulns: List[str] = list(data.get("vulns", []))
        return tags + vulns


class _URLhausAdapter:
    """Thin wrapper around the abuse.ch URLhaus API (free, no key)."""

    BASE = "https://urlhaus-api.abuse.ch/v1"

    def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Look up a URL in URLhaus."""
        return _http_post(f"{self.BASE}/url/", payload={"url": url})

    def query_host(self, host: str) -> Optional[Dict[str, Any]]:
        """Look up a host (IP or domain) in URLhaus."""
        return _http_post(f"{self.BASE}/host/", payload={"host": host})

    def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Look up a payload hash in URLhaus."""
        key = "md5_hash" if len(file_hash) == 32 else "sha256_hash"
        return _http_post(f"{self.BASE}/payload/", payload={key: file_hash})

    def extract_verdict(self, data: Optional[Dict[str, Any]]) -> bool:
        """Return True if URLhaus considers this IOC malicious."""
        if not data:
            return False
        return data.get("query_status") in ("is_malware", "detected")


class _ThreatFoxAdapter:
    """Thin wrapper around the abuse.ch ThreatFox API (free, no key)."""

    BASE = "https://threatfox-api.abuse.ch/api/v1"

    def query_ioc(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Search ThreatFox for any IOC type."""
        return _http_post(self.BASE, payload={"query": "search_ioc", "search_term": ioc_value})

    def extract_verdict(self, data: Optional[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """Return (is_malicious, [malware_names]) from ThreatFox response."""
        if not data or data.get("query_status") != "ok":
            return False, []
        iocs = data.get("data", []) or []
        malware_names = [i.get("malware", "") for i in iocs if i.get("malware")]
        return bool(iocs), malware_names


class _OTXAdapter:
    """Thin wrapper around the AlienVault OTX API."""

    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self) -> None:
        self.key = os.environ.get("OTX_API_KEY", "")

    def _headers(self) -> Dict[str, str]:
        return {"X-OTX-API-KEY": self.key}

    def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query OTX for IP indicators."""
        if not self.key:
            return None
        return _http_get(
            f"{self.BASE}/indicators/IPv4/{ip}/general",
            headers=self._headers(),
        )

    def query_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query OTX for domain indicators."""
        if not self.key:
            return None
        return _http_get(
            f"{self.BASE}/indicators/domain/{domain}/general",
            headers=self._headers(),
        )

    def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query OTX for file hash indicators."""
        if not self.key:
            return None
        return _http_get(
            f"{self.BASE}/indicators/file/{file_hash}/general",
            headers=self._headers(),
        )

    def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query OTX for URL indicators."""
        if not self.key:
            return None
        return _http_get(
            f"{self.BASE}/indicators/url/{url}/general",
            headers=self._headers(),
        )

    def extract_verdict(self, data: Optional[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """Return (is_malicious, pulse_names) from OTX response."""
        if not data:
            return False, []
        pulses = data.get("pulse_info", {}).get("pulses", [])
        names = [p.get("name", "") for p in pulses if p.get("name")]
        return bool(pulses), names


# ---------------------------------------------------------------------------
# Main graph engine
# ---------------------------------------------------------------------------


class IOCEnrichmentGraph:
    """Production IOC Enrichment Graph Engine for CYBERDUDEBIVASH SENTINEL APEX.

    Maintains a pure-Python adjacency graph of IOC nodes and edges,
    providing multi-source enrichment, correlation, authority scoring,
    STIX 2.1 export, and community feed sharing.

    Thread-safety: all public methods acquire an RLock before mutating state.
    """

    def __init__(self, graph_path: Optional[str] = None) -> None:
        """Initialise the graph engine, optionally loading a persisted graph.

        Args:
            graph_path: Optional filesystem path to a JSON-serialised graph.
                        If provided and the file exists, it is loaded on init.
        """
        self._lock = threading.RLock()
        # {node_id: IOCNode}
        self._nodes: Dict[str, IOCNode] = {}
        # {node_id: {neighbour_id: IOCEdge}}  — directed adjacency list
        self._adj: Dict[str, Dict[str, IOCEdge]] = {}
        # Reverse adjacency for in-degree lookups
        self._radj: Dict[str, Dict[str, IOCEdge]] = {}

        # Source adapters
        self._vt = _VirusTotalAdapter()
        self._abuse = _AbuseIPDBAdapter()
        self._shodan = _ShodanAdapter()
        self._urlhaus = _URLhausAdapter()
        self._threatfox = _ThreatFoxAdapter()
        self._otx = _OTXAdapter()

        self._graph_path = graph_path
        if graph_path and os.path.isfile(graph_path):
            try:
                self.load(graph_path)
                logger.info("Loaded graph from %s", graph_path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not load graph from %s: %s", graph_path, exc)

        logger.info("IOCEnrichmentGraph initialised — %d nodes", len(self._nodes))

    # ------------------------------------------------------------------
    # Core graph mutation
    # ------------------------------------------------------------------

    def add_ioc(
        self,
        value: str,
        ioc_type: Optional[str] = None,
        source: str = "manual",
        confidence: int = 50,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Add an IOC node to the graph, deduplicating by normalised value.

        If the node already exists its metadata is updated (last_seen,
        source_count, sources, confidence averaged, tags merged).

        Args:
            value:      Raw IOC value (IP, domain, hash, URL, etc.).
            ioc_type:   One of NODE_TYPES.  Auto-inferred if not supplied.
            source:     Human-readable source label (e.g. "virustotal").
            confidence: Analyst confidence 0-100.
            tags:       Optional list of free-text tags.

        Returns:
            Stable node_id string.
        """
        norm_value = _normalize_value(value)
        resolved_type = (ioc_type or _infer_ioc_type(value)).upper()
        if resolved_type not in NODE_TYPES:
            resolved_type = "DOMAIN"
        node_id = _make_node_id(resolved_type, norm_value)
        now = _now_iso()
        tags = tags or []

        with self._lock:
            if node_id in self._nodes:
                node = self._nodes[node_id]
                node["last_seen"] = now
                node["source_count"] += 1
                if source not in node["sources"]:
                    node["sources"].append(source)
                # Average confidence
                node["confidence"] = (node["confidence"] + confidence) // 2
                for t in tags:
                    if t not in node["tags"]:
                        node["tags"].append(t)
                logger.debug("Updated existing node %s", node_id)
            else:
                self._nodes[node_id] = IOCNode(
                    id=node_id,
                    type=resolved_type,
                    value=norm_value,
                    first_seen=now,
                    last_seen=now,
                    confidence=confidence,
                    source_count=1,
                    sources=[source],
                    tags=list(tags),
                    enrichment={},
                )
                self._adj[node_id] = {}
                self._radj[node_id] = {}
                logger.debug("Added new node %s (%s)", node_id, norm_value)

        return node_id

    def link_iocs(
        self,
        ioc_a: str,
        ioc_b: str,
        edge_type: str = "COMMUNICATES_WITH",
        weight: float = 0.5,
        evidence: Optional[List[str]] = None,
    ) -> None:
        """Create a directed relationship between two IOC node IDs.

        If either node ID does not exist in the graph the call is silently
        ignored with a warning.  Duplicate edges update weight and evidence.

        Args:
            ioc_a:     Source node ID.
            ioc_b:     Target node ID.
            edge_type: One of EDGE_TYPES.
            weight:    Relationship confidence weight 0.0-1.0.
            evidence:  List of evidence strings supporting this link.
        """
        edge_type = edge_type.upper()
        if edge_type not in EDGE_TYPES:
            logger.warning("Unknown edge type '%s' — defaulting to COMMUNICATES_WITH", edge_type)
            edge_type = "COMMUNICATES_WITH"
        weight = max(0.0, min(1.0, weight))
        evidence = evidence or []

        with self._lock:
            if ioc_a not in self._nodes:
                logger.warning("link_iocs: source node %s not found", ioc_a)
                return
            if ioc_b not in self._nodes:
                logger.warning("link_iocs: target node %s not found", ioc_b)
                return

            now = _now_iso()
            if ioc_b in self._adj[ioc_a]:
                # Update existing edge
                existing = self._adj[ioc_a][ioc_b]
                existing["weight"] = max(existing["weight"], weight)
                for e in evidence:
                    if e not in existing["evidence"]:
                        existing["evidence"].append(e)
            else:
                edge = IOCEdge(
                    source_id=ioc_a,
                    target_id=ioc_b,
                    type=edge_type,
                    weight=weight,
                    first_seen=now,
                    evidence=list(evidence),
                )
                self._adj[ioc_a][ioc_b] = edge
                self._radj[ioc_b][ioc_a] = edge
                logger.debug("Linked %s -[%s]-> %s", ioc_a, edge_type, ioc_b)

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def enrich_ioc(self, ioc_value: str, ioc_type: Optional[str] = None) -> EnrichmentResult:
        """Enrich a single IOC against all configured OSINT sources.

        Queries VirusTotal, AbuseIPDB, Shodan, URLhaus, ThreatFox, and OTX
        concurrently (via threads).  Missing API keys cause graceful skip.
        Results are merged into the graph node and returned.

        Args:
            ioc_value: The raw IOC value.
            ioc_type:  Override type inference (optional).

        Returns:
            EnrichmentResult dict containing enriched node and raw responses.
        """
        t_start = time.monotonic()
        norm_value = _normalize_value(ioc_value)
        resolved_type = (ioc_type or _infer_ioc_type(ioc_value)).upper()
        if resolved_type not in NODE_TYPES:
            resolved_type = "DOMAIN"

        # Ensure node exists
        node_id = self.add_ioc(norm_value, resolved_type, source="enrichment_engine", confidence=0)

        sources_queried: List[str] = []
        sources_responded: List[str] = []
        raw_responses: Dict[str, Any] = {}
        aggregated_tags: List[str] = []
        confidence_components: List[Tuple[float, float]] = []  # (score 0-1, trust_weight)

        # ---- Thread worker ----
        def _call(name: str, fn, *args):  # type: ignore[no-untyped-def]
            result = None
            try:
                result = fn(*args)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Enrichment source %s error: %s", name, exc)
            return name, result

        tasks = []

        if resolved_type == "IP":
            if self._vt.key:
                tasks.append(("virustotal", self._vt.query_ip, norm_value))
            if self._abuse.key:
                tasks.append(("abuseipdb", self._abuse.query_ip, norm_value))
            tasks.append(("shodan", self._shodan.query_ip, norm_value))
            tasks.append(("urlhaus", self._urlhaus.query_host, norm_value))
            tasks.append(("threatfox", self._threatfox.query_ioc, norm_value))
            if self._otx.key:
                tasks.append(("otx", self._otx.query_ip, norm_value))

        elif resolved_type == "DOMAIN":
            if self._vt.key:
                tasks.append(("virustotal", self._vt.query_domain, norm_value))
            tasks.append(("urlhaus", self._urlhaus.query_host, norm_value))
            tasks.append(("threatfox", self._threatfox.query_ioc, norm_value))
            if self._otx.key:
                tasks.append(("otx", self._otx.query_domain, norm_value))

        elif resolved_type == "HASH":
            if self._vt.key:
                tasks.append(("virustotal", self._vt.query_hash, norm_value))
            tasks.append(("urlhaus", self._urlhaus.query_hash, norm_value))
            tasks.append(("threatfox", self._threatfox.query_ioc, norm_value))
            if self._otx.key:
                tasks.append(("otx", self._otx.query_hash, norm_value))

        elif resolved_type == "URL":
            if self._vt.key:
                tasks.append(("virustotal", self._vt.query_url, norm_value))
            tasks.append(("urlhaus", self._urlhaus.query_url, norm_value))
            tasks.append(("threatfox", self._threatfox.query_ioc, norm_value))
            if self._otx.key:
                tasks.append(("otx", self._otx.query_url, norm_value))

        else:
            # EMAIL / CVE / ACTOR / CAMPAIGN / MALWARE_FAMILY — ThreatFox + OTX only
            tasks.append(("threatfox", self._threatfox.query_ioc, norm_value))
            if self._otx.key:
                tasks.append(("otx", self._otx.query_ip, norm_value))  # best effort

        # Execute tasks in parallel threads
        results: Dict[str, Any] = {}
        threads = []
        result_lock = threading.Lock()

        def worker(name: str, fn, args: tuple) -> None:  # type: ignore[no-untyped-def]
            nm, res = _call(name, fn, *args)
            with result_lock:
                results[nm] = res

        for name, fn, *args in tasks:
            sources_queried.append(name)
            t = threading.Thread(target=worker, args=(name, fn, tuple(args)), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=_HTTP_TIMEOUT + 1)

        # Process results
        for name, data in results.items():
            raw_responses[name] = data
            if data is None:
                continue
            sources_responded.append(name)

            if name == "virustotal":
                is_mal, mal_count, total = self._vt.extract_verdict(data)
                if total > 0:
                    confidence_components.append((mal_count / total, SOURCE_TRUST["virustotal"]))
                if is_mal:
                    aggregated_tags.append("malicious:virustotal")

            elif name == "abuseipdb":
                is_mal, score = self._abuse.extract_verdict(data)
                confidence_components.append((score / 100.0, SOURCE_TRUST["abuseipdb"]))
                if is_mal:
                    aggregated_tags.append("malicious:abuseipdb")

            elif name == "shodan":
                tags = self._shodan.extract_tags(data)
                aggregated_tags.extend(tags)
                ports = data.get("ports", [])
                if ports:
                    aggregated_tags.append(f"open_ports:{','.join(str(p) for p in ports[:5])}")

            elif name == "urlhaus":
                is_mal = self._urlhaus.extract_verdict(data)
                if is_mal:
                    confidence_components.append((1.0, SOURCE_TRUST["urlhaus"]))
                    aggregated_tags.append("malicious:urlhaus")

            elif name == "threatfox":
                is_mal, malware_names = self._threatfox.extract_verdict(data)
                if is_mal:
                    confidence_components.append((1.0, SOURCE_TRUST["threatfox"]))
                    aggregated_tags.extend(f"malware:{m}" for m in malware_names[:3])
                    aggregated_tags.append("malicious:threatfox")

            elif name == "otx":
                is_mal, pulse_names = self._otx.extract_verdict(data)
                if is_mal:
                    confidence_components.append((1.0, SOURCE_TRUST["otx"]))
                    aggregated_tags.append("malicious:otx")

        # Compute composite confidence
        if confidence_components:
            weighted_sum = sum(score * trust for score, trust in confidence_components)
            weight_total = sum(trust for _, trust in confidence_components)
            final_confidence = int((weighted_sum / weight_total) * 100)
        else:
            final_confidence = 0

        # Update node with enrichment data
        with self._lock:
            if node_id in self._nodes:
                node = self._nodes[node_id]
                node["confidence"] = final_confidence
                node["last_seen"] = _now_iso()
                for tag in aggregated_tags:
                    if tag not in node["tags"]:
                        node["tags"].append(tag)
                node["enrichment"] = {
                    "sources_queried": sources_queried,
                    "sources_responded": sources_responded,
                    "enriched_at": _now_iso(),
                    "raw_summary": {
                        s: bool(d) for s, d in raw_responses.items()
                    },
                }
                enriched_node = dict(node)  # type: ignore[arg-type]
            else:
                enriched_node = {}  # type: ignore[assignment]

        elapsed = time.monotonic() - t_start
        logger.info(
            "Enriched %s (%s) — confidence=%d, sources=%d/%d, elapsed=%.2fs",
            norm_value,
            resolved_type,
            final_confidence,
            len(sources_responded),
            len(sources_queried),
            elapsed,
        )

        return EnrichmentResult(
            node_id=node_id,
            ioc_value=norm_value,
            ioc_type=resolved_type,
            sources_queried=sources_queried,
            sources_responded=sources_responded,
            enriched_node=enriched_node,  # type: ignore[arg-type]
            raw_responses=raw_responses,
            elapsed_seconds=round(elapsed, 3),
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_ioc(self, ioc_value: str) -> Dict[str, Any]:
        """Query multiple sources and return an aggregated maliciousness verdict.

        Confidence = weighted average of per-source maliciousness scores,
        using SOURCE_TRUST weights.

        Args:
            ioc_value: The raw IOC value to validate.

        Returns:
            Dict with keys: valid (bool), malicious_count (int),
            total_sources (int), confidence (int 0-100), verdicts (dict).
        """
        result = self.enrich_ioc(ioc_value)
        verdicts: Dict[str, Any] = {}
        malicious_count = 0
        total_sources = len(result["sources_responded"])

        for source in result["sources_responded"]:
            data = result["raw_responses"].get(source)
            is_mal = False

            if source == "virustotal":
                is_mal, _, _ = self._vt.extract_verdict(data)
            elif source == "abuseipdb":
                is_mal, score = self._abuse.extract_verdict(data)
            elif source == "urlhaus":
                is_mal = self._urlhaus.extract_verdict(data)
            elif source == "threatfox":
                is_mal, _ = self._threatfox.extract_verdict(data)
            elif source == "otx":
                is_mal, _ = self._otx.extract_verdict(data)

            verdicts[source] = {"malicious": is_mal}
            if is_mal:
                malicious_count += 1

        confidence = result["enriched_node"].get("confidence", 0)
        valid = malicious_count == 0

        return {
            "valid": valid,
            "malicious_count": malicious_count,
            "total_sources": total_sources,
            "confidence": confidence,
            "verdicts": verdicts,
        }

    # ------------------------------------------------------------------
    # Graph analytics
    # ------------------------------------------------------------------

    def find_related(self, ioc_value: str, depth: int = 2) -> List[Dict[str, Any]]:
        """BFS traversal to find all IOC nodes related to the given value.

        Traverses both outgoing and incoming edges up to *depth* hops.

        Args:
            ioc_value: The IOC value to start from.
            depth:     Maximum traversal depth (default 2).

        Returns:
            List of node dicts for all related IOCs (excluding origin).
        """
        norm_value = _normalize_value(ioc_value)
        with self._lock:
            # Find matching node
            start_ids = [
                nid for nid, n in self._nodes.items() if n["value"] == norm_value
            ]
            if not start_ids:
                logger.warning("find_related: no node found for '%s'", ioc_value)
                return []

            visited: set = set(start_ids)
            queue: deque = deque()
            for sid in start_ids:
                queue.append((sid, 0))

            related: List[Dict[str, Any]] = []

            while queue:
                node_id, current_depth = queue.popleft()
                if current_depth >= depth:
                    continue
                # Forward edges
                for neighbour_id in self._adj.get(node_id, {}):
                    if neighbour_id not in visited:
                        visited.add(neighbour_id)
                        if neighbour_id in self._nodes:
                            related.append(dict(self._nodes[neighbour_id]))
                        queue.append((neighbour_id, current_depth + 1))
                # Reverse edges
                for neighbour_id in self._radj.get(node_id, {}):
                    if neighbour_id not in visited:
                        visited.add(neighbour_id)
                        if neighbour_id in self._nodes:
                            related.append(dict(self._nodes[neighbour_id]))
                        queue.append((neighbour_id, current_depth + 1))

        logger.debug("find_related('%s', depth=%d) => %d nodes", ioc_value, depth, len(related))
        return related

    def authority_score(self, node_id: str) -> float:
        """Compute a PageRank-like authority score for a node.

        Nodes referenced by many high-confidence sources score higher.
        Uses a simplified iterative authority propagation (5 iterations).

        Args:
            node_id: The ID of the node to score.

        Returns:
            Authority score in range [0.0, 1.0].
        """
        with self._lock:
            if node_id not in self._nodes:
                return 0.0

            n = len(self._nodes)
            if n == 0:
                return 0.0

            # Initialise scores
            scores = {nid: 1.0 / n for nid in self._nodes}

            damping = 0.85
            for _ in range(5):
                new_scores: Dict[str, float] = {}
                for nid in self._nodes:
                    # Sum of weighted contributions from predecessors
                    in_score = 0.0
                    for pred_id, edge in self._radj.get(nid, {}).items():
                        out_degree = len(self._adj.get(pred_id, {}))
                        if out_degree > 0:
                            in_score += scores[pred_id] * edge["weight"] / out_degree
                    new_scores[nid] = (1 - damping) / n + damping * in_score
                scores = new_scores

            raw = scores.get(node_id, 0.0)
            # Normalise to [0, 1]
            max_score = max(scores.values()) if scores else 1.0
            return round(raw / max_score, 4) if max_score > 0 else 0.0

    def correlate_campaign(self, iocs: List[str]) -> Dict[str, Any]:
        """Find shared infrastructure among a list of IOC values and group into a campaign.

        Shared infrastructure is detected by finding nodes connected to two or
        more of the supplied IOCs within depth-1 traversal.

        Args:
            iocs: List of IOC value strings.

        Returns:
            Dict with keys: campaign_id, ioc_count, shared_infrastructure (list),
            member_nodes (list), created_at (ISO-8601).
        """
        with self._lock:
            # Resolve IOC values to node IDs
            norm_to_id: Dict[str, str] = {
                n["value"]: nid for nid, n in self._nodes.items()
            }
            member_ids: List[str] = []
            for v in iocs:
                nv = _normalize_value(v)
                if nv in norm_to_id:
                    member_ids.append(norm_to_id[nv])

            if not member_ids:
                return {
                    "campaign_id": None,
                    "ioc_count": 0,
                    "shared_infrastructure": [],
                    "member_nodes": [],
                    "created_at": _now_iso(),
                }

            # Find neighbours for each member
            neighbour_sets: List[set] = []
            for mid in member_ids:
                neighbours = set(self._adj.get(mid, {}).keys()) | set(
                    self._radj.get(mid, {}).keys()
                )
                neighbour_sets.append(neighbours)

            # Shared = nodes appearing as neighbours for >= 2 members
            shared: Dict[str, int] = {}
            for ns in neighbour_sets:
                for nid in ns:
                    shared[nid] = shared.get(nid, 0) + 1
            shared_infra = [nid for nid, count in shared.items() if count >= 2]

            campaign_id = f"CAMPAIGN:{uuid.uuid4().hex[:12].upper()}"

            # Create campaign node
            cid = self.add_ioc(campaign_id, "CAMPAIGN", source="correlate_campaign", confidence=60)
            for mid in member_ids:
                self.link_iocs(mid, cid, "PART_OF", weight=0.8, evidence=["campaign_correlation"])
            for infra_id in shared_infra:
                self.link_iocs(infra_id, cid, "PART_OF", weight=0.7, evidence=["shared_infra"])

            logger.info(
                "Campaign %s created: %d members, %d shared infra",
                campaign_id,
                len(member_ids),
                len(shared_infra),
            )
            return {
                "campaign_id": cid,
                "campaign_value": campaign_id,
                "ioc_count": len(member_ids),
                "shared_infrastructure": [
                    dict(self._nodes[nid]) for nid in shared_infra if nid in self._nodes
                ],
                "member_nodes": [
                    dict(self._nodes[nid]) for nid in member_ids if nid in self._nodes
                ],
                "created_at": _now_iso(),
            }

    def get_actor_attribution(self, ioc: str) -> Dict[str, Any]:
        """Traverse the graph from an IOC to find probable actor attribution.

        Follows ATTRIBUTED_TO and PART_OF edges up to depth 3 looking for
        ACTOR-type nodes.

        Args:
            ioc: IOC value string.

        Returns:
            Dict with keys: ioc_value, attributed_actors (list), confidence,
            attribution_path (list of node IDs).
        """
        norm = _normalize_value(ioc)
        with self._lock:
            start_ids = [nid for nid, n in self._nodes.items() if n["value"] == norm]
            if not start_ids:
                return {
                    "ioc_value": ioc,
                    "attributed_actors": [],
                    "confidence": 0,
                    "attribution_path": [],
                }

            actor_nodes: List[Dict[str, Any]] = []
            visited: set = set()
            path: List[str] = []

            def dfs(node_id: str, depth: int) -> None:
                if depth > 3 or node_id in visited:
                    return
                visited.add(node_id)
                path.append(node_id)
                node = self._nodes.get(node_id)
                if node and node["type"] == "ACTOR":
                    actor_nodes.append(dict(node))
                # Follow attribution and campaign edges
                for neighbour_id, edge in self._adj.get(node_id, {}).items():
                    if edge["type"] in ("ATTRIBUTED_TO", "PART_OF"):
                        dfs(neighbour_id, depth + 1)
                # Reverse: who targets this node
                for neighbour_id, edge in self._radj.get(node_id, {}).items():
                    if edge["type"] == "ATTRIBUTED_TO":
                        dfs(neighbour_id, depth + 1)

            for sid in start_ids:
                dfs(sid, 0)

            avg_confidence = (
                int(sum(a["confidence"] for a in actor_nodes) / len(actor_nodes))
                if actor_nodes
                else 0
            )

        return {
            "ioc_value": ioc,
            "attributed_actors": actor_nodes,
            "confidence": avg_confidence,
            "attribution_path": path,
        }

    # ------------------------------------------------------------------
    # STIX 2.1 export
    # ------------------------------------------------------------------

    def export_stix_bundle(self, node_ids: List[str]) -> Dict[str, Any]:
        """Export a subgraph as a STIX 2.1 bundle.

        Maps IOC node types to STIX 2.1 SCO/SDO types:
          IP -> ipv4-addr / ipv6-addr
          DOMAIN -> domain-name
          HASH -> file (with hashes dict)
          URL -> url
          EMAIL -> email-addr
          CVE -> vulnerability
          ACTOR -> threat-actor
          CAMPAIGN -> campaign
          MALWARE_FAMILY -> malware

        Edge relationships are exported as STIX relationship objects.

        Args:
            node_ids: List of node IDs to include in the bundle.

        Returns:
            STIX 2.1 bundle dict ready for JSON serialisation.
        """
        stix_objects: List[Dict[str, Any]] = []
        stix_id_map: Dict[str, str] = {}  # node_id -> stix_id

        _TYPE_MAP = {
            "IP": "ipv4-addr",
            "DOMAIN": "domain-name",
            "HASH": "file",
            "URL": "url",
            "EMAIL": "email-addr",
            "CVE": "vulnerability",
            "ACTOR": "threat-actor",
            "CAMPAIGN": "campaign",
            "MALWARE_FAMILY": "malware",
        }

        with self._lock:
            valid_ids = [nid for nid in node_ids if nid in self._nodes]

            for nid in valid_ids:
                node = self._nodes[nid]
                stix_type = _TYPE_MAP.get(node["type"], "indicator")
                stix_id = f"{stix_type}--{uuid.uuid4()}"
                stix_id_map[nid] = stix_id
                now = _now_iso()

                obj: Dict[str, Any] = {
                    "type": stix_type,
                    "id": stix_id,
                    "spec_version": "2.1",
                    "created": node["first_seen"],
                    "modified": node["last_seen"],
                }

                if stix_type == "ipv4-addr":
                    obj["value"] = node["value"]
                elif stix_type == "domain-name":
                    obj["value"] = node["value"]
                elif stix_type == "url":
                    obj["value"] = node["value"]
                elif stix_type == "email-addr":
                    obj["value"] = node["value"]
                elif stix_type == "file":
                    h = node["value"]
                    hash_key = (
                        "MD5" if len(h) == 32 else "SHA-1" if len(h) == 40 else "SHA-256"
                    )
                    obj["hashes"] = {hash_key: h}
                elif stix_type == "vulnerability":
                    obj["name"] = node["value"]
                elif stix_type in ("threat-actor", "campaign", "malware"):
                    obj["name"] = node["value"]
                    if stix_type == "malware":
                        obj["is_family"] = True

                # Add labels from tags
                if node["tags"]:
                    obj["labels"] = node["tags"][:10]

                stix_objects.append(obj)

            # Add relationship objects
            for src_id in valid_ids:
                for tgt_id, edge in self._adj.get(src_id, {}).items():
                    if tgt_id in stix_id_map:
                        rel_type = edge["type"].lower().replace("_", "-")
                        rel = {
                            "type": "relationship",
                            "id": f"relationship--{uuid.uuid4()}",
                            "spec_version": "2.1",
                            "created": edge["first_seen"],
                            "modified": edge["first_seen"],
                            "relationship_type": rel_type,
                            "source_ref": stix_id_map[src_id],
                            "target_ref": stix_id_map[tgt_id],
                            "confidence": int(edge["weight"] * 100),
                        }
                        if edge["evidence"]:
                            rel["description"] = "; ".join(edge["evidence"][:5])
                        stix_objects.append(rel)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": stix_objects,
        }
        logger.info("Exported STIX bundle: %d objects", len(stix_objects))
        return bundle

    # ------------------------------------------------------------------
    # Phase 6 — Network Effect / Community Sharing
    # ------------------------------------------------------------------

    def merge_external_graph(self, external_graph_data: Dict[str, Any]) -> int:
        """Merge intelligence from another SENTINEL APEX instance.

        Nodes are deduplicated by value+type.  Edges are created or updated.
        Enrichment data is deep-merged (external data does not overwrite local
        data if local confidence is higher).

        Args:
            external_graph_data: Dict as produced by save() or export_shared_feed().

        Returns:
            Number of new nodes merged.
        """
        ext_nodes: Dict[str, Any] = external_graph_data.get("nodes", {})
        ext_edges: List[Any] = external_graph_data.get("edges", [])
        merged_count = 0

        for _nid, node_data in ext_nodes.items():
            value = node_data.get("value", "")
            ioc_type = node_data.get("type", "DOMAIN")
            source = node_data.get("sources", ["external"])[0]
            confidence = node_data.get("confidence", 0)
            tags = node_data.get("tags", [])
            new_id = self.add_ioc(value, ioc_type, source=source, confidence=confidence, tags=tags)
            with self._lock:
                if new_id in self._nodes:
                    # Deep-merge enrichment — prefer local if higher confidence
                    local_node = self._nodes[new_id]
                    ext_enrichment = node_data.get("enrichment", {})
                    for k, v in ext_enrichment.items():
                        if k not in local_node["enrichment"]:
                            local_node["enrichment"][k] = v
            merged_count += 1

        for edge_data in ext_edges:
            src_val = edge_data.get("source_value", "")
            tgt_val = edge_data.get("target_value", "")
            src_type = edge_data.get("source_type", "DOMAIN")
            tgt_type = edge_data.get("target_type", "DOMAIN")
            if src_val and tgt_val:
                src_id = self.add_ioc(src_val, src_type, source="external_merge", confidence=30)
                tgt_id = self.add_ioc(tgt_val, tgt_type, source="external_merge", confidence=30)
                self.link_iocs(
                    src_id,
                    tgt_id,
                    edge_data.get("type", "COMMUNICATES_WITH"),
                    edge_data.get("weight", 0.5),
                    edge_data.get("evidence", ["external_merge"]),
                )

        logger.info("Merged %d nodes from external graph", merged_count)
        return merged_count

    def export_shared_feed(self) -> Dict[str, Any]:
        """Export anonymised IOCs suitable for community sharing.

        Only exports nodes with confidence >= 60 and at least 2 sources.
        Actor/Campaign nodes are excluded to prevent OPSEC disclosure.
        Raw enrichment data is stripped; only tags and confidence are shared.

        Returns:
            Dict with keys: version, exported_at, nodes (list), edges (list).
        """
        with self._lock:
            export_nodes = []
            exportable_ids: set = set()
            for nid, node in self._nodes.items():
                if node["type"] in ("ACTOR", "CAMPAIGN"):
                    continue
                if node["confidence"] < 60:
                    continue
                if node["source_count"] < 2:
                    continue
                exportable_ids.add(nid)
                export_nodes.append(
                    {
                        "value": node["value"],
                        "type": node["type"],
                        "confidence": node["confidence"],
                        "tags": node["tags"],
                        "first_seen": node["first_seen"],
                        "last_seen": node["last_seen"],
                        "source_count": node["source_count"],
                    }
                )

            export_edges = []
            for src_id in exportable_ids:
                for tgt_id, edge in self._adj.get(src_id, {}).items():
                    if tgt_id in exportable_ids:
                        src_node = self._nodes[src_id]
                        tgt_node = self._nodes[tgt_id]
                        export_edges.append(
                            {
                                "source_value": src_node["value"],
                                "source_type": src_node["type"],
                                "target_value": tgt_node["value"],
                                "target_type": tgt_node["type"],
                                "type": edge["type"],
                                "weight": edge["weight"],
                                "evidence": edge["evidence"],
                            }
                        )

        feed = {
            "version": "123.0.0",
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "exported_at": _now_iso(),
            "nodes": export_nodes,
            "edges": export_edges,
        }
        logger.info(
            "Exported shared feed: %d nodes, %d edges", len(export_nodes), len(export_edges)
        )
        return feed

    def import_community_feed(self, feed_data: Dict[str, Any]) -> int:
        """Ingest community-shared intelligence from a feed dict.

        Nodes receive a 10-point confidence penalty (community-sourced data
        is less trusted than direct enrichment) and are tagged with
        "source:community_feed".

        Args:
            feed_data: Dict as produced by export_shared_feed().

        Returns:
            Number of nodes imported.
        """
        imported = 0
        for node_data in feed_data.get("nodes", []):
            value = node_data.get("value", "")
            ioc_type = node_data.get("type", "DOMAIN")
            confidence = max(0, node_data.get("confidence", 50) - 10)
            tags = node_data.get("tags", []) + ["source:community_feed"]
            if value:
                self.add_ioc(value, ioc_type, source="community_feed", confidence=confidence, tags=tags)
                imported += 1

        for edge_data in feed_data.get("edges", []):
            src_val = edge_data.get("source_value", "")
            tgt_val = edge_data.get("target_value", "")
            if src_val and tgt_val:
                src_id = self.add_ioc(src_val, edge_data.get("source_type", "DOMAIN"), source="community_feed", confidence=40)
                tgt_id = self.add_ioc(tgt_val, edge_data.get("target_type", "DOMAIN"), source="community_feed", confidence=40)
                self.link_iocs(
                    src_id,
                    tgt_id,
                    edge_data.get("type", "COMMUNICATES_WITH"),
                    edge_data.get("weight", 0.4),
                    edge_data.get("evidence", []) + ["community_feed"],
                )

        logger.info("Imported %d nodes from community feed", imported)
        return imported

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """Serialise the full graph to a JSON file.

        Acquires the graph lock for the duration of serialisation to ensure
        a consistent snapshot.

        Args:
            path: Filesystem path for the output JSON file.
        """
        with self._lock:
            # Build edge list from adjacency
            edges: List[Dict[str, Any]] = []
            for src_id, neighbours in self._adj.items():
                for tgt_id, edge in neighbours.items():
                    edges.append(dict(edge))

            payload = {
                "version": "123.0.0",
                "saved_at": _now_iso(),
                "nodes": {nid: dict(n) for nid, n in self._nodes.items()},
                "edges": edges,
            }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

        logger.info("Graph saved to %s (%d nodes)", path, len(payload["nodes"]))

    def load(self, path: str) -> None:
        """Load a JSON-serialised graph, merging with any existing state.

        Existing nodes are preserved.  Loaded nodes are upserted; loaded
        edges are added if not already present.

        Args:
            path: Filesystem path to the JSON file.
        """
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)

        nodes_data: Dict[str, Any] = payload.get("nodes", {})
        edges_data: List[Any] = payload.get("edges", [])

        with self._lock:
            for nid, node_data in nodes_data.items():
                if nid not in self._nodes:
                    self._nodes[nid] = node_data  # type: ignore[assignment]
                    self._adj.setdefault(nid, {})
                    self._radj.setdefault(nid, {})

            for edge_data in edges_data:
                src = edge_data.get("source_id", "")
                tgt = edge_data.get("target_id", "")
                if src in self._nodes and tgt in self._nodes:
                    self._adj[src].setdefault(tgt, edge_data)  # type: ignore[arg-type]
                    self._radj[tgt].setdefault(src, edge_data)  # type: ignore[arg-type]

        logger.info("Graph loaded from %s: %d nodes", path, len(nodes_data))

    # ------------------------------------------------------------------
    # R2 Export Snapshot
    # ------------------------------------------------------------------

    def export_snapshot(self) -> Dict[str, Any]:
        """Return a Worker-consumable snapshot of the current graph state.

        Produces the flat node/edge lists expected by handleIntelGraph and
        handleIntelRelations in the Cloudflare Worker.  Thread-safe.

        Returns:
            Dict with keys:
              nodes            — list of node dicts (id, type, value, confidence,
                                 source, authority_score, threat_level)
              edges            — list of edge dicts (source, target, relation, weight)
              node_count       — int
              edge_count       — int
              high_confidence_nodes — count of nodes with confidence >= 75
        """
        with self._lock:
            node_ids = list(self._nodes.keys())
            adj_snapshot = {k: dict(v) for k, v in self._adj.items()}

        nodes = []
        for nid in node_ids:
            nd = self._nodes[nid]
            # authority_score is a computed method — call outside the lock is safe (reads only)
            try:
                auth = self.authority_score(nid)
            except Exception:
                auth = 0.0
            # threat_level is derived from enrichment data if present
            enrichment = nd.get("enrichment", {})
            threat_level = (
                enrichment.get("threat_level")
                or enrichment.get("abuse_confidence_level")
                or ("high" if nd.get("confidence", 0) >= 80 else
                    "medium" if nd.get("confidence", 0) >= 50 else "low")
            )
            nodes.append({
                "id":            nid,
                "type":          nd.get("type", "unknown"),
                "value":         nd.get("value", nid),
                "confidence":    nd.get("confidence", 0),
                "source":        (nd.get("sources") or ["unknown"])[0],
                "sources":       nd.get("sources", []),
                "authority_score": round(auth, 4),
                "threat_level":  str(threat_level).lower(),
                "first_seen":    nd.get("first_seen", ""),
                "last_seen":     nd.get("last_seen", ""),
                "tags":          nd.get("tags", []),
            })

        edges = []
        for src_id, neighbours in adj_snapshot.items():
            for tgt_id, edge in neighbours.items():
                edges.append({
                    "source":   src_id,
                    "target":   tgt_id,
                    "relation": edge.get("relation_type", "related_to"),
                    "weight":   edge.get("weight", 1.0),
                })

        high_conf = sum(1 for nd in nodes if nd.get("confidence", 0) >= 75)

        return {
            "nodes":                nodes,
            "edges":                edges,
            "node_count":           len(nodes),
            "edge_count":           len(edges),
            "high_confidence_nodes": high_conf,
        }

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return a summary statistics dict describing the current graph state.

        Returns:
            Dict with keys: node_count, edge_count, node_type_breakdown,
            avg_confidence, high_confidence_nodes, sources_active,
            requests_available (bool), graph_path.
        """
        with self._lock:
            node_count = len(self._nodes)
            edge_count = sum(len(v) for v in self._adj.values())

            type_breakdown: Dict[str, int] = {}
            total_conf = 0
            high_conf = 0
            for node in self._nodes.values():
                t = node["type"]
                type_breakdown[t] = type_breakdown.get(t, 0) + 1
                total_conf += node["confidence"]
                if node["confidence"] >= 75:
                    high_conf += 1

            avg_conf = round(total_conf / node_count, 1) if node_count else 0.0

            active_sources: List[str] = []
            if self._vt.key:
                active_sources.append("virustotal")
            if self._abuse.key:
                active_sources.append("abuseipdb")
            if self._shodan.key:
                active_sources.append("shodan")
            active_sources.extend(["urlhaus", "threatfox"])  # always available
            if self._otx.key:
                active_sources.append("otx")

        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "node_type_breakdown": type_breakdown,
            "avg_confidence": avg_conf,
            "high_confidence_nodes": high_conf,
            "sources_active": active_sources,
            "requests_available": _REQUESTS_AVAILABLE,
            "graph_path": self._graph_path,
            "platform": "CYBERDUDEBIVASH SENTINEL APEX v123.0.0",
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

graph = IOCEnrichmentGraph()
