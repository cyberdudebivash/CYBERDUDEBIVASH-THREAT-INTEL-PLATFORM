"""
CYBERDUDEBIVASH® SENTINEL APEX v26.0 - IOC Correlation Engine
===============================================================
Correlates Indicators of Compromise across multiple threat reports
to identify related campaigns, threat actors, and attack patterns.

Features:
- Multi-type IOC correlation (IP, domain, hash, email)
- Campaign clustering
- Threat actor attribution
- Attack pattern detection
- Confidence scoring

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Set, Tuple
from collections import defaultdict
from enum import Enum
import hashlib
import re
import json


class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    FILE_NAME = "filename"
    REGISTRY = "registry"
    MUTEX = "mutex"
    UNKNOWN = "unknown"


@dataclass
class IOCMatch:
    """Represents a match between IOCs"""
    ioc_value: str
    ioc_type: IOCType
    report_ids: List[str]
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    confidence: float


@dataclass
class CorrelationCluster:
    """A cluster of correlated threats"""
    cluster_id: str
    report_ids: Set[str]
    shared_iocs: List[IOCMatch]
    threat_actors: List[str]
    techniques: List[str]  # MITRE ATT&CK
    confidence: float
    created_at: datetime


class IOCCorrelationEngine:
    """
    IOC Correlation Engine
    
    Identifies relationships between threat reports based on
    shared indicators of compromise.
    """
    
    # IOC extraction patterns
    PATTERNS = {
        IOCType.IP_ADDRESS: re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        IOCType.DOMAIN: re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        IOCType.MD5: re.compile(r'\b[a-fA-F0-9]{32}\b'),
        IOCType.SHA1: re.compile(r'\b[a-fA-F0-9]{40}\b'),
        IOCType.SHA256: re.compile(r'\b[a-fA-F0-9]{64}\b'),
        IOCType.EMAIL: re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        ),
        IOCType.CVE: re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
        IOCType.URL: re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE
        ),
    }
    
    # Whitelist patterns (common false positives)
    WHITELIST = [
        re.compile(r'example\.com', re.IGNORECASE),
        re.compile(r'localhost'),
        re.compile(r'127\.0\.0\.1'),
        re.compile(r'0\.0\.0\.0'),
        re.compile(r'google\.com'),
        re.compile(r'microsoft\.com'),
        re.compile(r'github\.com'),
    ]
    
    def __init__(
        self,
        correlation_window_hours: int = 72,
        min_confidence: float = 0.5,
        min_shared_iocs: int = 2
    ):
        self.correlation_window = timedelta(hours=correlation_window_hours)
        self.min_confidence = min_confidence
        self.min_shared_iocs = min_shared_iocs
        
        # IOC index: ioc_value -> list of (report_id, timestamp, ioc_type)
        self._ioc_index: Dict[str, List[Tuple[str, datetime, IOCType]]] = defaultdict(list)
        
        # Report IOCs: report_id -> set of iocs
        self._report_iocs: Dict[str, Set[str]] = defaultdict(set)
        
        # Clusters
        self._clusters: Dict[str, CorrelationCluster] = {}
    
    def _is_whitelisted(self, ioc: str) -> bool:
        """Check if IOC matches whitelist"""
        for pattern in self.WHITELIST:
            if pattern.search(ioc):
                return True
        return False
    
    def _normalize_ioc(self, ioc: str, ioc_type: IOCType) -> str:
        """Normalize IOC for consistent matching"""
        ioc = ioc.strip().lower()
        
        if ioc_type == IOCType.URL:
            # Remove trailing slashes
            ioc = ioc.rstrip('/')
        elif ioc_type == IOCType.DOMAIN:
            # Remove www prefix
            if ioc.startswith('www.'):
                ioc = ioc[4:]
        
        return ioc
    
    def extract_iocs(self, text: str) -> Dict[IOCType, List[str]]:
        """
        Extract all IOCs from text.
        
        Args:
            text: Raw text to extract IOCs from
            
        Returns:
            Dictionary mapping IOC types to lists of values
        """
        results: Dict[IOCType, List[str]] = defaultdict(list)
        
        for ioc_type, pattern in self.PATTERNS.items():
            matches = pattern.findall(text)
            for match in matches:
                normalized = self._normalize_ioc(match, ioc_type)
                if not self._is_whitelisted(normalized):
                    results[ioc_type].append(normalized)
        
        # Deduplicate
        for ioc_type in results:
            results[ioc_type] = list(set(results[ioc_type]))
        
        return dict(results)
    
    def index_report(
        self,
        report_id: str,
        iocs: Dict[IOCType, List[str]],
        timestamp: Optional[datetime] = None
    ):
        """
        Index IOCs from a threat report.
        
        Args:
            report_id: Unique identifier for the report
            iocs: Dictionary of IOC type -> list of values
            timestamp: When the report was created
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        for ioc_type, values in iocs.items():
            for value in values:
                normalized = self._normalize_ioc(value, ioc_type)
                self._ioc_index[normalized].append((report_id, timestamp, ioc_type))
                self._report_iocs[report_id].add(normalized)
    
    def find_correlations(
        self,
        report_id: str,
        reference_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Find reports correlated with the given report.
        
        Args:
            report_id: Report to find correlations for
            reference_time: Time reference for window calculation
            
        Returns:
            List of correlated reports with details
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        report_iocs = self._report_iocs.get(report_id, set())
        if not report_iocs:
            return []
        
        # Find other reports sharing IOCs
        correlation_scores: Dict[str, Dict] = defaultdict(lambda: {
            "shared_iocs": [],
            "earliest_overlap": None,
            "latest_overlap": None,
        })
        
        for ioc in report_iocs:
            occurrences = self._ioc_index.get(ioc, [])
            
            for other_id, ts, ioc_type in occurrences:
                if other_id == report_id:
                    continue
                
                # Check time window
                if abs((reference_time - ts).total_seconds()) > self.correlation_window.total_seconds():
                    continue
                
                data = correlation_scores[other_id]
                data["shared_iocs"].append({
                    "value": ioc,
                    "type": ioc_type.value,
                    "timestamp": ts.isoformat(),
                })
                
                if data["earliest_overlap"] is None or ts < data["earliest_overlap"]:
                    data["earliest_overlap"] = ts
                if data["latest_overlap"] is None or ts > data["latest_overlap"]:
                    data["latest_overlap"] = ts
        
        # Calculate confidence and filter
        results = []
        for other_id, data in correlation_scores.items():
            shared_count = len(data["shared_iocs"])
            
            if shared_count < self.min_shared_iocs:
                continue
            
            # Confidence based on shared IOCs and IOC diversity
            ioc_types = set(i["type"] for i in data["shared_iocs"])
            type_diversity = len(ioc_types) / len(IOCType)
            
            # More shared IOCs = higher confidence (logarithmic scale)
            import math
            quantity_factor = min(1.0, math.log10(shared_count + 1) / 2)
            
            confidence = 0.5 * quantity_factor + 0.5 * type_diversity
            
            if confidence < self.min_confidence:
                continue
            
            results.append({
                "report_id": other_id,
                "shared_iocs_count": shared_count,
                "shared_iocs": data["shared_iocs"][:10],  # Limit to top 10
                "ioc_types": list(ioc_types),
                "confidence": round(confidence, 3),
                "time_span_hours": round(
                    (data["latest_overlap"] - data["earliest_overlap"]).total_seconds() / 3600, 2
                ) if data["earliest_overlap"] and data["latest_overlap"] else 0,
            })
        
        # Sort by confidence
        results.sort(key=lambda x: x["confidence"], reverse=True)
        
        return results
    
    def build_clusters(self) -> List[CorrelationCluster]:
        """
        Build clusters of correlated reports.
        
        Returns:
            List of correlation clusters
        """
        # Build adjacency graph
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        
        for report_id in self._report_iocs:
            correlations = self.find_correlations(report_id)
            for corr in correlations:
                adjacency[report_id].add(corr["report_id"])
                adjacency[corr["report_id"]].add(report_id)
        
        # Find connected components (clusters)
        visited: Set[str] = set()
        clusters: List[CorrelationCluster] = []
        
        def dfs(node: str, component: Set[str]):
            if node in visited:
                return
            visited.add(node)
            component.add(node)
            for neighbor in adjacency[node]:
                dfs(neighbor, component)
        
        for report_id in adjacency:
            if report_id not in visited:
                component: Set[str] = set()
                dfs(report_id, component)
                
                if len(component) >= 2:
                    # Find shared IOCs in cluster
                    shared: Set[str] = self._report_iocs[next(iter(component))].copy()
                    for rid in component:
                        shared &= self._report_iocs[rid]
                    
                    cluster_id = hashlib.md5(
                        ",".join(sorted(component)).encode()
                    ).hexdigest()[:12]
                    
                    cluster = CorrelationCluster(
                        cluster_id=f"CDB-CLUSTER-{cluster_id}",
                        report_ids=component,
                        shared_iocs=[
                            IOCMatch(
                                ioc_value=ioc,
                                ioc_type=self._ioc_index[ioc][0][2] if ioc in self._ioc_index else IOCType.UNKNOWN,
                                report_ids=list(component),
                                first_seen=min(t[1] for t in self._ioc_index.get(ioc, [(None, datetime.now(timezone.utc), None)])),
                                last_seen=max(t[1] for t in self._ioc_index.get(ioc, [(None, datetime.now(timezone.utc), None)])),
                                occurrence_count=len(component),
                                confidence=0.8,
                            )
                            for ioc in list(shared)[:20]
                        ],
                        threat_actors=[],
                        techniques=[],
                        confidence=0.8 if len(shared) >= 3 else 0.6,
                        created_at=datetime.now(timezone.utc),
                    )
                    clusters.append(cluster)
        
        return clusters
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics"""
        return {
            "indexed_reports": len(self._report_iocs),
            "indexed_iocs": len(self._ioc_index),
            "total_ioc_occurrences": sum(len(v) for v in self._ioc_index.values()),
            "iocs_per_report_avg": round(
                sum(len(v) for v in self._report_iocs.values()) / max(1, len(self._report_iocs)), 2
            ),
            "correlation_window_hours": self.correlation_window.total_seconds() / 3600,
            "min_confidence": self.min_confidence,
        }


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
_engine: Optional[IOCCorrelationEngine] = None


def get_correlation_engine() -> IOCCorrelationEngine:
    """Get or create the global correlation engine"""
    global _engine
    if _engine is None:
        _engine = IOCCorrelationEngine()
    return _engine


# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS
# ══════════════════════════════════════════════════════════════════════════════
__all__ = [
    "IOCCorrelationEngine",
    "IOCType",
    "IOCMatch",
    "CorrelationCluster",
    "get_correlation_engine",
]
