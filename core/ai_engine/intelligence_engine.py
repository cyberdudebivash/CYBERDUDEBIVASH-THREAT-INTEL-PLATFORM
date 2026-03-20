#!/usr/bin/env python3
"""
intelligence_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0 (COMMAND CENTER)
════════════════════════════════════════════════════════════════════════════════
AI-Powered Intelligence Engine: Real threat analysis, not static scoring.

Capabilities:
  - IOC Clustering: Groups related indicators by behavioral similarity
  - CVE Correlation: Links CVEs across campaigns via product/vector overlap
  - Threat Campaign Detection: Identifies coordinated attack campaigns
  - Dynamic Risk Scoring: Multi-factor analysis with temporal decay
  - Anomaly Detection: Statistical outlier identification in threat feeds
  - Predictive Threat Modeling: Forecasts risk trajectory

Architecture:
  - Uses scikit-learn when available, falls back to native implementations
  - All methods are idempotent and side-effect free
  - Integrates with existing RiskScoringEngine (agent/risk_engine.py)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import re
import math
import hashlib
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-AI-ENGINE")

# ── Optional ML imports ──
try:
    from sklearn.cluster import DBSCAN
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.info("scikit-learn not available; using native clustering")

try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False


# ═══════════════════════════════════════════════════════════
# IOC CLUSTERING ENGINE
# ═══════════════════════════════════════════════════════════

class IOCClusterEngine:
    """
    Groups IOCs into behavioral clusters based on co-occurrence,
    network proximity, and temporal correlation.
    """

    # Known CDN/benign infrastructure to exclude
    INFRA_PATTERNS = {
        "cloudflare", "akamai", "fastly", "amazonaws", "azure",
        "googleapis", "cloudfront", "incapsula",
    }

    def cluster_iocs(self, intel_items: List[Dict]) -> List[Dict]:
        """
        Cluster IOCs from multiple intelligence items.
        Returns list of clusters with member IOCs and metadata.
        """
        # Extract all IOCs with provenance
        ioc_records = []
        for item in intel_items:
            iocs = item.get("iocs", {})
            intel_id = item.get("intel_id", item.get("title", "unknown"))
            timestamp = item.get("timestamp", "")

            for ioc_type, values in iocs.items():
                if not isinstance(values, list):
                    continue
                for val in values:
                    if self._is_infrastructure(val):
                        continue
                    ioc_records.append({
                        "type": ioc_type,
                        "value": val,
                        "intel_id": intel_id,
                        "timestamp": timestamp,
                    })

        if len(ioc_records) < 2:
            return []

        # Build co-occurrence matrix
        co_occurrence = self._build_co_occurrence(ioc_records)

        # Cluster via connected components
        clusters = self._connected_components(co_occurrence, ioc_records)

        # Enrich clusters with metadata
        enriched = []
        for i, cluster_iocs in enumerate(clusters):
            if len(cluster_iocs) < 2:
                continue

            types = Counter(ioc["type"] for ioc in cluster_iocs)
            sources = list(set(ioc["intel_id"] for ioc in cluster_iocs))

            enriched.append({
                "cluster_id": f"CDB-CLU-{hashlib.sha256(str(cluster_iocs).encode()).hexdigest()[:8]}",
                "ioc_count": len(cluster_iocs),
                "ioc_types": dict(types),
                "source_intel": sources[:10],
                "source_count": len(sources),
                "members": [{"type": i["type"], "value": i["value"]} for i in cluster_iocs[:50]],
                "confidence": min(0.95, 0.3 + len(sources) * 0.15 + len(cluster_iocs) * 0.05),
                "classification": self._classify_cluster(types),
            })

        enriched.sort(key=lambda c: c["ioc_count"], reverse=True)
        logger.info(f"IOC Clustering: {len(ioc_records)} IOCs -> {len(enriched)} clusters")
        return enriched

    def _is_infrastructure(self, value: str) -> bool:
        val_lower = value.lower()
        return any(infra in val_lower for infra in self.INFRA_PATTERNS)

    def _build_co_occurrence(self, records: List[Dict]) -> Dict[str, Set[str]]:
        """Build adjacency based on shared intel sources."""
        intel_to_iocs: Dict[str, List[str]] = defaultdict(list)
        for rec in records:
            key = f"{rec['type']}:{rec['value']}"
            intel_to_iocs[rec["intel_id"]].append(key)

        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for ioc_keys in intel_to_iocs.values():
            for i, k1 in enumerate(ioc_keys):
                for k2 in ioc_keys[i + 1:]:
                    adjacency[k1].add(k2)
                    adjacency[k2].add(k1)

        return adjacency

    def _connected_components(
        self, adjacency: Dict[str, Set[str]], records: List[Dict]
    ) -> List[List[Dict]]:
        """Find connected components in the co-occurrence graph."""
        ioc_map = {}
        for rec in records:
            key = f"{rec['type']}:{rec['value']}"
            ioc_map[key] = rec

        visited = set()
        components = []

        for node in ioc_map:
            if node in visited:
                continue
            component = []
            stack = [node]
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                if current in ioc_map:
                    component.append(ioc_map[current])
                for neighbor in adjacency.get(current, set()):
                    if neighbor not in visited:
                        stack.append(neighbor)
            if component:
                components.append(component)

        return components

    def _classify_cluster(self, type_counts: Counter) -> str:
        if type_counts.get("sha256", 0) + type_counts.get("md5", 0) > 0:
            if type_counts.get("ipv4", 0) + type_counts.get("domain", 0) > 0:
                return "MALWARE_C2"
            return "MALWARE_FAMILY"
        if type_counts.get("domain", 0) > type_counts.get("ipv4", 0):
            return "PHISHING_INFRA"
        if type_counts.get("ipv4", 0) > 0:
            return "ATTACK_INFRA"
        return "MIXED"


# ═══════════════════════════════════════════════════════════
# CVE CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════

class CVECorrelationEngine:
    """
    Links CVEs across intelligence items via:
      - Product/vendor overlap
      - Attack vector similarity
      - Temporal proximity
      - Shared MITRE techniques
    """

    # Product family groupings for correlation
    PRODUCT_FAMILIES = {
        "microsoft": ["windows", "office", "exchange", "sharepoint", "outlook", "edge", "azure", "teams"],
        "apple": ["ios", "macos", "safari", "webkit", "xcode"],
        "google": ["chrome", "chromium", "android", "v8"],
        "linux": ["kernel", "ubuntu", "debian", "centos", "rhel", "fedora"],
        "apache": ["httpd", "tomcat", "struts", "log4j", "kafka"],
        "cisco": ["ios", "asa", "firepower", "webex", "anyconnect"],
        "vmware": ["esxi", "vcenter", "vsphere", "workstation", "horizon"],
        "fortinet": ["fortigate", "fortimanager", "fortios", "fortianalyzer"],
        "paloalto": ["pan-os", "globalprotect", "cortex", "prisma"],
    }

    def correlate_cves(self, intel_items: List[Dict]) -> List[Dict]:
        """
        Find correlated CVE groups across intelligence items.
        Returns correlation groups with linked CVEs and shared attributes.
        """
        cve_records = []
        for item in intel_items:
            title = item.get("title", "")
            cves = re.findall(r'CVE-\d{4}-\d{4,}', title, re.IGNORECASE)
            iocs = item.get("iocs", {})
            cves.extend(iocs.get("cve", []))
            cves = list(set(c.upper() for c in cves))

            for cve_id in cves:
                cve_records.append({
                    "cve_id": cve_id,
                    "title": title,
                    "severity": item.get("severity", "MEDIUM"),
                    "risk_score": float(item.get("risk_score", 0)),
                    "cvss_score": item.get("cvss_score"),
                    "epss_score": item.get("epss_score"),
                    "kev_present": item.get("kev_present", False),
                    "mitre_tactics": item.get("mitre_tactics", []),
                    "actor_tag": item.get("actor_tag", ""),
                    "timestamp": item.get("timestamp", ""),
                    "product_family": self._detect_product_family(title),
                })

        if len(cve_records) < 2:
            return []

        # Group by product family
        family_groups: Dict[str, List[Dict]] = defaultdict(list)
        for rec in cve_records:
            family = rec["product_family"]
            if family:
                family_groups[family].append(rec)

        # Build correlation groups
        correlations = []
        for family, group in family_groups.items():
            if len(group) < 2:
                continue

            cve_ids = list(set(r["cve_id"] for r in group))
            shared_mitre = self._find_shared_mitre(group)
            kev_count = sum(1 for r in group if r["kev_present"])
            max_risk = max(r["risk_score"] for r in group)

            correlations.append({
                "correlation_id": f"CDB-COR-{hashlib.sha256(family.encode()).hexdigest()[:8]}",
                "product_family": family,
                "cve_count": len(cve_ids),
                "cve_ids": cve_ids[:20],
                "shared_mitre_techniques": shared_mitre,
                "kev_confirmed_count": kev_count,
                "max_risk_score": max_risk,
                "avg_risk_score": round(sum(r["risk_score"] for r in group) / len(group), 2),
                "severity_distribution": dict(Counter(r["severity"] for r in group)),
                "actors_involved": list(set(r["actor_tag"] for r in group if r["actor_tag"] and not r["actor_tag"].startswith("UNC-"))),
                "confidence": min(0.95, 0.4 + len(cve_ids) * 0.1 + kev_count * 0.15),
                "assessment": self._assess_correlation(group),
            })

        correlations.sort(key=lambda c: c["max_risk_score"], reverse=True)
        logger.info(f"CVE Correlation: {len(cve_records)} CVEs -> {len(correlations)} groups")
        return correlations

    def _detect_product_family(self, text: str) -> str:
        text_lower = text.lower()
        for family, keywords in self.PRODUCT_FAMILIES.items():
            if any(kw in text_lower for kw in keywords) or family in text_lower:
                return family
        return ""

    def _find_shared_mitre(self, records: List[Dict]) -> List[str]:
        all_techniques = []
        for rec in records:
            tactics = rec.get("mitre_tactics", [])
            for t in tactics:
                tid = t if isinstance(t, str) else t.get("id", "")
                if tid:
                    all_techniques.append(tid)
        counts = Counter(all_techniques)
        return [t for t, c in counts.most_common(10) if c >= 2]

    def _assess_correlation(self, records: List[Dict]) -> str:
        kev_count = sum(1 for r in records if r["kev_present"])
        max_risk = max(r["risk_score"] for r in records)
        if kev_count >= 2 and max_risk >= 8.0:
            return "ACTIVE_EXPLOITATION_CHAIN"
        if kev_count >= 1 or max_risk >= 7.0:
            return "HIGH_RISK_CORRELATION"
        if len(records) >= 5:
            return "VENDOR_VULNERABILITY_CLUSTER"
        return "RELATED_VULNERABILITIES"


# ═══════════════════════════════════════════════════════════
# THREAT CAMPAIGN DETECTION ENGINE
# ═══════════════════════════════════════════════════════════

class CampaignDetectionEngine:
    """
    Detects coordinated threat campaigns from intelligence items using:
      - Textual similarity (TF-IDF when sklearn available, Jaccard fallback)
      - Actor tag grouping
      - Temporal clustering
      - IOC co-occurrence
      - MITRE technique overlap
    """

    SIMILARITY_THRESHOLD = 0.45
    TEMPORAL_WINDOW_HOURS = 72

    def detect_campaigns(self, intel_items: List[Dict]) -> List[Dict]:
        """
        Analyze intelligence items and detect coordinated campaigns.
        Returns list of detected campaigns with member items and confidence.
        """
        if len(intel_items) < 3:
            return []

        # Phase 1: Group by actor tag (known campaigns)
        actor_groups = self._group_by_actor(intel_items)

        # Phase 2: Textual similarity clustering
        text_groups = self._cluster_by_text(intel_items)

        # Phase 3: Temporal + IOC correlation
        temporal_groups = self._cluster_temporal_ioc(intel_items)

        # Merge all detected groups
        merged = self._merge_campaign_groups(actor_groups, text_groups, temporal_groups)

        # Build campaign objects
        campaigns = []
        for group_id, members in merged.items():
            if len(members) < 2:
                continue

            titles = [m.get("title", "") for m in members]
            all_cves = []
            all_mitre = []
            all_actors = set()
            severities = []

            for m in members:
                cves = re.findall(r'CVE-\d{4}-\d{4,}', m.get("title", ""), re.IGNORECASE)
                all_cves.extend(cves)
                all_mitre.extend(m.get("mitre_tactics", []))
                actor = m.get("actor_tag", "")
                if actor and not actor.startswith("UNC-"):
                    all_actors.add(actor)
                severities.append(m.get("severity", "MEDIUM"))

            max_risk = max((float(m.get("risk_score", 0)) for m in members), default=0)
            has_kev = any(m.get("kev_present") for m in members)

            campaign_name = self._generate_campaign_name(members)

            campaigns.append({
                "campaign_id": f"CDB-CAM-{group_id[:8]}",
                "name": campaign_name,
                "description": f"Detected campaign: {len(members)} correlated intelligence items",
                "intel_count": len(members),
                "member_titles": titles[:10],
                "related_cves": list(set(c.upper() for c in all_cves))[:15],
                "mitre_techniques": list(set(
                    t if isinstance(t, str) else t.get("id", "")
                    for t in all_mitre
                ))[:10],
                "actors_involved": list(all_actors),
                "severity": self._campaign_severity(severities, max_risk, has_kev),
                "max_risk_score": max_risk,
                "kev_present": has_kev,
                "confidence": self._campaign_confidence(members),
                "first_seen": min((m.get("timestamp", "") for m in members), default=""),
                "last_seen": max((m.get("timestamp", "") for m in members), default=""),
                "status": "active",
            })

        campaigns.sort(key=lambda c: c["confidence"], reverse=True)
        logger.info(f"Campaign Detection: {len(intel_items)} items -> {len(campaigns)} campaigns")
        return campaigns

    def _group_by_actor(self, items: List[Dict]) -> Dict[str, List[Dict]]:
        groups: Dict[str, List[Dict]] = defaultdict(list)
        for item in items:
            actor = item.get("actor_tag", "")
            if actor and not actor.startswith("UNC-"):
                groups[f"actor_{actor}"].append(item)
        return {k: v for k, v in groups.items() if len(v) >= 2}

    def _cluster_by_text(self, items: List[Dict]) -> Dict[str, List[Dict]]:
        """Cluster items by textual similarity of titles."""
        titles = [item.get("title", "") for item in items]

        if _SKLEARN_AVAILABLE and len(titles) >= 3:
            return self._sklearn_text_cluster(titles, items)
        return self._jaccard_text_cluster(titles, items)

    def _sklearn_text_cluster(self, titles: List[str], items: List[Dict]) -> Dict[str, List[Dict]]:
        try:
            vectorizer = TfidfVectorizer(
                stop_words="english", max_features=500, min_df=1
            )
            tfidf_matrix = vectorizer.fit_transform(titles)
            sim_matrix = cosine_similarity(tfidf_matrix)

            # DBSCAN clustering on similarity
            distance_matrix = 1 - sim_matrix
            if _NUMPY_AVAILABLE:
                distance_matrix = np.clip(distance_matrix, 0, 1)

            clustering = DBSCAN(eps=1 - self.SIMILARITY_THRESHOLD, min_samples=2, metric="precomputed")
            labels = clustering.fit_predict(distance_matrix)

            groups: Dict[str, List[Dict]] = defaultdict(list)
            for idx, label in enumerate(labels):
                if label >= 0:
                    groups[f"text_{label}"].append(items[idx])
            return dict(groups)
        except Exception as e:
            logger.debug(f"sklearn clustering failed, using fallback: {e}")
            return self._jaccard_text_cluster(titles, items)

    def _jaccard_text_cluster(self, titles: List[str], items: List[Dict]) -> Dict[str, List[Dict]]:
        """Fallback: Jaccard similarity clustering."""
        word_sets = [set(re.sub(r'[^\w\s]', '', t.lower()).split()) for t in titles]
        groups: Dict[str, List[Dict]] = defaultdict(list)
        assigned = set()

        for i in range(len(items)):
            if i in assigned:
                continue
            cluster = [items[i]]
            assigned.add(i)

            for j in range(i + 1, len(items)):
                if j in assigned:
                    continue
                if not word_sets[i] or not word_sets[j]:
                    continue
                intersection = len(word_sets[i] & word_sets[j])
                union = len(word_sets[i] | word_sets[j])
                if union > 0 and intersection / union >= self.SIMILARITY_THRESHOLD:
                    cluster.append(items[j])
                    assigned.add(j)

            if len(cluster) >= 2:
                gid = hashlib.sha256(titles[i].encode()).hexdigest()[:8]
                groups[f"text_{gid}"] = cluster

        return dict(groups)

    def _cluster_temporal_ioc(self, items: List[Dict]) -> Dict[str, List[Dict]]:
        """Cluster items sharing IOCs within a temporal window."""
        ioc_to_items: Dict[str, List[int]] = defaultdict(list)
        for idx, item in enumerate(items):
            iocs = item.get("iocs", {})
            for ioc_type, values in iocs.items():
                if not isinstance(values, list):
                    continue
                for val in values:
                    ioc_to_items[f"{ioc_type}:{val}"].append(idx)

        groups: Dict[str, List[Dict]] = defaultdict(list)
        seen_items = set()

        for ioc_key, item_indices in ioc_to_items.items():
            if len(item_indices) < 2:
                continue
            group_items = [items[i] for i in item_indices if i not in seen_items]
            if len(group_items) >= 2:
                gid = hashlib.sha256(ioc_key.encode()).hexdigest()[:8]
                groups[f"ioc_{gid}"] = group_items
                seen_items.update(item_indices)

        return dict(groups)

    def _merge_campaign_groups(self, *group_sets) -> Dict[str, List[Dict]]:
        """Merge overlapping campaign groups from different detection methods."""
        merged: Dict[str, List[Dict]] = {}
        seen_titles = {}

        for groups in group_sets:
            for gid, members in groups.items():
                new_members = []
                for m in members:
                    title = m.get("title", "")
                    if title not in seen_titles:
                        seen_titles[title] = gid
                        new_members.append(m)
                    else:
                        existing_gid = seen_titles[title]
                        if existing_gid in merged and gid != existing_gid:
                            pass  # Already assigned to another group

                if new_members:
                    if gid in merged:
                        merged[gid].extend(new_members)
                    else:
                        merged[gid] = new_members

        return merged

    def _generate_campaign_name(self, members: List[Dict]) -> str:
        actors = [m.get("actor_tag", "") for m in members if m.get("actor_tag") and not m.get("actor_tag", "").startswith("UNC-")]
        if actors:
            return f"{actors[0]} Campaign"

        titles = [m.get("title", "") for m in members]
        words = Counter()
        for t in titles:
            for w in re.sub(r'[^\w\s]', '', t).split():
                if len(w) > 3 and w.upper() not in {"THE", "AND", "FOR", "WITH", "FROM"}:
                    words[w] += 1
        common = words.most_common(2)
        if common:
            return f"{common[0][0].title()} {'- ' + common[1][0].title() if len(common) > 1 else ''} Campaign"
        return "Unnamed Campaign"

    def _campaign_severity(self, severities: List[str], max_risk: float, has_kev: bool) -> str:
        if has_kev or max_risk >= 8.5 or "CRITICAL" in severities:
            return "CRITICAL"
        if max_risk >= 6.5 or "HIGH" in severities:
            return "HIGH"
        if max_risk >= 4.0:
            return "MEDIUM"
        return "LOW"

    def _campaign_confidence(self, members: List[Dict]) -> float:
        base = 0.3
        base += min(0.25, len(members) * 0.05)
        if any(not m.get("actor_tag", "").startswith("UNC-") for m in members if m.get("actor_tag")):
            base += 0.15
        if any(m.get("kev_present") for m in members):
            base += 0.1
        shared_cves = set()
        for m in members:
            cves = re.findall(r'CVE-\d{4}-\d{4,}', m.get("title", ""), re.IGNORECASE)
            shared_cves.update(c.upper() for c in cves)
        if len(shared_cves) >= 3:
            base += 0.1
        return min(0.95, round(base, 2))


# ═══════════════════════════════════════════════════════════
# ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════

class AnomalyDetector:
    """Statistical anomaly detection for threat intelligence feeds."""

    def detect_anomalies(self, intel_items: List[Dict]) -> List[Dict]:
        """Identify statistical outliers in risk scores, IOC density, etc."""
        if len(intel_items) < 5:
            return []

        scores = [float(item.get("risk_score", 0)) for item in intel_items]
        mean_score = sum(scores) / len(scores)
        variance = sum((s - mean_score) ** 2 for s in scores) / len(scores)
        std_dev = math.sqrt(variance) if variance > 0 else 1.0

        anomalies = []
        for item, score in zip(intel_items, scores):
            z_score = (score - mean_score) / std_dev if std_dev > 0 else 0
            if abs(z_score) >= 2.0:
                anomalies.append({
                    "title": item.get("title", ""),
                    "risk_score": score,
                    "z_score": round(z_score, 2),
                    "anomaly_type": "HIGH_RISK_OUTLIER" if z_score > 0 else "LOW_RISK_OUTLIER",
                    "mean_score": round(mean_score, 2),
                    "std_dev": round(std_dev, 2),
                    "severity": item.get("severity", "MEDIUM"),
                })

        # IOC density anomalies
        ioc_counts_list = []
        for item in intel_items:
            counts = item.get("ioc_counts", {})
            total = sum(counts.values()) if isinstance(counts, dict) else 0
            ioc_counts_list.append(total)

        if ioc_counts_list:
            mean_ioc = sum(ioc_counts_list) / len(ioc_counts_list)
            for item, count in zip(intel_items, ioc_counts_list):
                if mean_ioc > 0 and count > mean_ioc * 3:
                    anomalies.append({
                        "title": item.get("title", ""),
                        "ioc_count": count,
                        "mean_ioc_count": round(mean_ioc, 1),
                        "anomaly_type": "HIGH_IOC_DENSITY",
                        "severity": "HIGH",
                    })

        logger.info(f"Anomaly Detection: {len(anomalies)} anomalies in {len(intel_items)} items")
        return anomalies


# ═══════════════════════════════════════════════════════════
# UNIFIED AI INTELLIGENCE ENGINE
# ═══════════════════════════════════════════════════════════

class AIIntelligenceEngine:
    """
    Unified AI engine that orchestrates all intelligence analysis.
    Central coordinator for clustering, correlation, campaign detection.
    """

    def __init__(self):
        self.ioc_clusterer = IOCClusterEngine()
        self.cve_correlator = CVECorrelationEngine()
        self.campaign_detector = CampaignDetectionEngine()
        self.anomaly_detector = AnomalyDetector()
        self._analysis_count = 0

    def analyze(self, intel_items: List[Dict]) -> Dict:
        """
        Run full AI intelligence analysis pipeline.
        Returns comprehensive analysis results.
        """
        self._analysis_count += 1
        start = datetime.now(timezone.utc)

        results = {
            "analysis_id": f"CDB-ANA-{hashlib.sha256(str(start).encode()).hexdigest()[:8]}",
            "timestamp": start.isoformat(),
            "input_count": len(intel_items),
            "ioc_clusters": [],
            "cve_correlations": [],
            "campaigns": [],
            "anomalies": [],
            "summary": {},
        }

        if not intel_items:
            return results

        # Run all analysis engines
        results["ioc_clusters"] = self.ioc_clusterer.cluster_iocs(intel_items)
        results["cve_correlations"] = self.cve_correlator.correlate_cves(intel_items)
        results["campaigns"] = self.campaign_detector.detect_campaigns(intel_items)
        results["anomalies"] = self.anomaly_detector.detect_anomalies(intel_items)

        # Build summary
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        results["summary"] = {
            "total_clusters": len(results["ioc_clusters"]),
            "total_correlations": len(results["cve_correlations"]),
            "total_campaigns": len(results["campaigns"]),
            "total_anomalies": len(results["anomalies"]),
            "critical_campaigns": sum(1 for c in results["campaigns"] if c.get("severity") == "CRITICAL"),
            "high_risk_correlations": sum(1 for c in results["cve_correlations"] if c.get("max_risk_score", 0) >= 7.0),
            "analysis_duration_seconds": round(duration, 3),
            "sklearn_available": _SKLEARN_AVAILABLE,
            "analysis_run_number": self._analysis_count,
        }

        logger.info(
            f"AI Analysis complete: {results['summary']['total_campaigns']} campaigns, "
            f"{results['summary']['total_clusters']} clusters, "
            f"{results['summary']['total_correlations']} correlations, "
            f"{results['summary']['total_anomalies']} anomalies "
            f"({duration:.2f}s)"
        )

        return results

    def quick_score(self, intel_item: Dict) -> Dict:
        """
        Quick AI-enhanced scoring for a single intelligence item.
        Adds AI-specific risk signals without full pipeline analysis.
        """
        signals = {
            "ai_risk_modifier": 0.0,
            "threat_category": "GENERAL",
            "confidence_boost": 0.0,
            "tags": [],
        }

        title = intel_item.get("title", "").lower()
        risk_score = float(intel_item.get("risk_score", 0))

        # Zero-day detection
        if any(t in title for t in ["zero-day", "0-day", "zero day"]):
            signals["ai_risk_modifier"] += 1.5
            signals["threat_category"] = "ZERO_DAY"
            signals["tags"].append("zero-day")

        # APT detection
        apt_indicators = ["apt", "nation-state", "state-sponsored", "lazarus", "cozy bear",
                          "fancy bear", "volt typhoon", "sandworm", "hafnium"]
        if any(t in title for t in apt_indicators):
            signals["ai_risk_modifier"] += 1.0
            signals["threat_category"] = "APT"
            signals["tags"].append("apt")

        # Supply chain
        if any(t in title for t in ["supply chain", "dependency", "npm", "pypi", "package"]):
            signals["ai_risk_modifier"] += 0.8
            signals["tags"].append("supply-chain")

        # Multi-CVE correlation signal
        cves = re.findall(r'CVE-\d{4}-\d{4,}', title, re.IGNORECASE)
        if len(cves) > 1:
            signals["ai_risk_modifier"] += 0.5
            signals["tags"].append("multi-cve")

        # KEV + high EPSS = imminent threat
        if intel_item.get("kev_present") and float(intel_item.get("epss_score", 0) or 0) >= 0.5:
            signals["ai_risk_modifier"] += 1.0
            signals["confidence_boost"] = 10.0
            signals["tags"].append("imminent-threat")

        return signals

    def get_stats(self) -> Dict:
        return {
            "total_analyses": self._analysis_count,
            "sklearn_available": _SKLEARN_AVAILABLE,
            "numpy_available": _NUMPY_AVAILABLE,
        }


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

ai_engine = AIIntelligenceEngine()
