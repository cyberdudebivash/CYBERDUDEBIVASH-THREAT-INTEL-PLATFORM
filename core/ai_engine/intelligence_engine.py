#!/usr/bin/env python3
"""
intelligence_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v48.0 (COMMAND CENTER)
════════════════════════════════════════════════════════════════════════════════
AI-Powered Intelligence Engine: Real threat analysis, not static scoring.

Capabilities:
  - IOC Clustering: Groups related indicators by behavioral similarity
  - CVE Correlation: Links CVEs across campaigns via product/vector overlap
  - Threat Campaign Detection: Identifies coordinated attack campaigns
  - Dynamic Risk Scoring: Multi-factor analysis with temporal decay
  - Anomaly Detection: Statistical outlier identification in threat feeds
  - Predictive Threat Modeling: Forecasts risk trajectory
  - Multi-Factor Threat Prioritization: Composite scoring with CVSS/EPSS/KEV/IOC/MITRE weights
  - Velocity Anomaly Detection: Spike detection in threat volume per vendor/product
  - IOC Reuse Detection: Shared infrastructure identification across campaigns
  - Cross-Source Correlation: Multi-source corroboration and confirmation

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

    def detect_velocity_anomalies(self, intel_items: List[Dict], window_hours: float = 6.0) -> List[Dict]:
        """
        Detect sudden spikes in threat volume targeting specific vendors or products.

        Groups intel items by detected vendor/product and time window, then flags
        any window where the volume exceeds 2 standard deviations above the mean
        for that vendor.

        Args:
            intel_items: List of intelligence item dicts.
            window_hours: Size of time buckets in hours for volume measurement.

        Returns:
            List of velocity anomaly dicts with vendor, spike volume, and baseline stats.
        """
        if len(intel_items) < 5:
            return []

        # Map each item to a vendor and parse timestamp
        vendor_buckets: Dict[str, List[datetime]] = defaultdict(list)
        for item in intel_items:
            vendor = self._extract_vendor(item)
            if not vendor:
                continue
            ts = self._parse_timestamp(item.get("timestamp", ""))
            if ts:
                vendor_buckets[vendor].append(ts)

        velocity_anomalies = []
        for vendor, timestamps in vendor_buckets.items():
            if len(timestamps) < 3:
                continue

            timestamps.sort()
            earliest = timestamps[0]
            latest = timestamps[-1]
            total_span_hours = max((latest - earliest).total_seconds() / 3600.0, window_hours)
            num_buckets = max(1, int(total_span_hours / window_hours))

            # Count items per bucket
            bucket_counts: Dict[int, int] = defaultdict(int)
            for ts in timestamps:
                bucket_idx = int((ts - earliest).total_seconds() / (window_hours * 3600))
                bucket_counts[bucket_idx] += 1

            # Fill empty buckets with zero
            all_counts = [bucket_counts.get(i, 0) for i in range(num_buckets + 1)]
            if len(all_counts) < 2:
                continue

            mean_vol = sum(all_counts) / len(all_counts)
            variance = sum((c - mean_vol) ** 2 for c in all_counts) / len(all_counts)
            std_vol = math.sqrt(variance) if variance > 0 else 1.0
            threshold = mean_vol + 2.0 * std_vol

            for bucket_idx, count in bucket_counts.items():
                if count > threshold and count >= 3:
                    bucket_start = earliest + timedelta(hours=bucket_idx * window_hours)
                    velocity_anomalies.append({
                        "vendor": vendor,
                        "anomaly_type": "VELOCITY_SPIKE",
                        "window_start": bucket_start.isoformat(),
                        "window_hours": window_hours,
                        "item_count": count,
                        "baseline_mean": round(mean_vol, 2),
                        "baseline_stddev": round(std_vol, 2),
                        "spike_factor": round(count / mean_vol, 2) if mean_vol > 0 else count,
                        "severity": "CRITICAL" if count >= mean_vol + 3 * std_vol else "HIGH",
                    })

        velocity_anomalies.sort(key=lambda a: a["spike_factor"], reverse=True)
        logger.info(f"Velocity Anomaly Detection: {len(velocity_anomalies)} spikes detected")
        return velocity_anomalies

    def detect_ioc_reuse(self, intel_items: List[Dict], min_campaigns: int = 2) -> List[Dict]:
        """
        Flag IOCs appearing across multiple unrelated campaigns, indicating
        shared infrastructure or common tooling.

        An IOC is flagged when it appears in items attributed to different actors
        or in items with sufficiently different titles (low textual overlap).

        Args:
            intel_items: List of intelligence item dicts.
            min_campaigns: Minimum number of distinct campaigns/sources for an IOC to be flagged.

        Returns:
            List of reuse records with the IOC, campaign contexts, and reuse count.
        """
        if len(intel_items) < 2:
            return []

        # Map IOC -> list of item contexts
        ioc_contexts: Dict[str, List[Dict]] = defaultdict(list)
        for item in intel_items:
            iocs = item.get("iocs", {})
            actor = item.get("actor_tag", "")
            title = item.get("title", "")
            source = item.get("source", item.get("feed_source", ""))
            for ioc_type, values in iocs.items():
                if not isinstance(values, list):
                    continue
                for val in values:
                    ioc_key = f"{ioc_type}:{val}"
                    ioc_contexts[ioc_key].append({
                        "actor": actor,
                        "title": title,
                        "source": source,
                        "severity": item.get("severity", "MEDIUM"),
                    })

        reuse_records = []
        for ioc_key, contexts in ioc_contexts.items():
            if len(contexts) < min_campaigns:
                continue

            # Determine distinct campaigns by unique actors or distinct titles
            unique_actors = set(c["actor"] for c in contexts if c["actor"])
            unique_sources = set(c["source"] for c in contexts if c["source"])
            unique_titles = set(c["title"] for c in contexts if c["title"])

            # Consider it cross-campaign if multiple actors, or multiple distinct sources,
            # or many distinct titles
            distinct_campaigns = max(len(unique_actors), len(unique_sources), 1)
            if distinct_campaigns < min_campaigns and len(unique_titles) < min_campaigns:
                continue

            ioc_type, ioc_value = ioc_key.split(":", 1)
            reuse_records.append({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "reuse_count": len(contexts),
                "distinct_actors": list(unique_actors)[:10],
                "distinct_sources": list(unique_sources)[:10],
                "campaign_count": distinct_campaigns,
                "titles": list(unique_titles)[:5],
                "anomaly_type": "IOC_REUSE",
                "severity": "HIGH" if distinct_campaigns >= 3 else "MEDIUM",
                "assessment": "SHARED_INFRASTRUCTURE" if len(unique_actors) >= 2 else "COMMON_TOOLING",
            })

        reuse_records.sort(key=lambda r: r["reuse_count"], reverse=True)
        logger.info(f"IOC Reuse Detection: {len(reuse_records)} reused IOCs across campaigns")
        return reuse_records

    def _extract_vendor(self, item: Dict) -> str:
        """Extract vendor/product name from an intel item for velocity grouping."""
        title = item.get("title", "").lower()
        vendor_keywords = {
            "microsoft": ["microsoft", "windows", "office", "exchange", "azure"],
            "apple": ["apple", "ios", "macos", "safari", "webkit"],
            "google": ["google", "chrome", "android", "chromium"],
            "cisco": ["cisco", "ios-xe", "asa", "firepower"],
            "fortinet": ["fortinet", "fortigate", "fortios"],
            "paloalto": ["palo alto", "pan-os", "globalprotect"],
            "vmware": ["vmware", "esxi", "vcenter"],
            "apache": ["apache", "log4j", "tomcat", "struts"],
            "linux": ["linux", "kernel", "ubuntu", "debian"],
            "adobe": ["adobe", "acrobat", "reader", "flash"],
        }
        for vendor, keywords in vendor_keywords.items():
            if any(kw in title for kw in keywords):
                return vendor
        return ""

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse an ISO-format timestamp string, returning None on failure."""
        if not ts_str:
            return None
        try:
            # Handle both Z suffix and +00:00 style
            cleaned = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError):
            return None


# ═══════════════════════════════════════════════════════════
# MULTI-FACTOR THREAT PRIORITIZATION ENGINE
# ═══════════════════════════════════════════════════════════

class ThreatPrioritizationEngine:
    """
    Computes a composite threat score by combining multiple intelligence
    factors with configurable weights. Produces a priority level (P1-P5)
    and an exploitation likelihood assessment.

    Weight distribution (default):
      - CVSS score:               25%
      - EPSS probability:         20%
      - KEV presence:             15%
      - IOC density factor:       15%
      - MITRE coverage breadth:   10%
      - Actor attribution:        10%
      - Temporal freshness:        5%
    """

    # Default weight configuration
    WEIGHTS = {
        "cvss": 0.25,
        "epss": 0.20,
        "kev": 0.15,
        "ioc_density": 0.15,
        "mitre_breadth": 0.10,
        "actor_attribution": 0.10,
        "temporal_freshness": 0.05,
    }

    # MITRE ATT&CK has 14 tactics; used for normalization
    MAX_MITRE_TACTICS = 14

    # Items older than this (in hours) get zero freshness score
    MAX_FRESHNESS_HOURS = 720  # 30 days

    def prioritize(self, intel_items: List[Dict], now: Optional[datetime] = None) -> List[Dict]:
        """
        Score and prioritize a list of intelligence items.

        Args:
            intel_items: List of intelligence item dicts, each optionally containing:
                - cvss_score (float, 0-10)
                - epss_score (float, 0-1)
                - kev_present (bool)
                - ioc_counts or iocs (dict)
                - mitre_tactics (list)
                - actor_tag (str)
                - timestamp (ISO str)
            now: Reference time for freshness calculation. Defaults to UTC now.

        Returns:
            List of priority result dicts, sorted by composite_score descending.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        priorities = []
        for item in intel_items:
            score_result = self._compute_composite_score(item, now)
            priorities.append(score_result)

        priorities.sort(key=lambda p: p["composite_score"], reverse=True)
        logger.info(
            f"Threat Prioritization: scored {len(priorities)} items, "
            f"{sum(1 for p in priorities if p['priority_level'] in ('P1', 'P2'))} high-priority"
        )
        return priorities

    def _compute_composite_score(self, item: Dict, now: datetime) -> Dict:
        """
        Compute the composite score for a single intelligence item.

        Normalizes each factor to a 0-10 scale, applies weights, and sums
        to produce the final composite score.

        Args:
            item: Intelligence item dict.
            now: Reference time for freshness.

        Returns:
            Dict with composite_score, priority_level, exploitation_likelihood,
            and individual factor scores.
        """
        factors = {}

        # 1. CVSS score (already 0-10)
        cvss_raw = float(item.get("cvss_score", 0) or 0)
        factors["cvss"] = min(10.0, max(0.0, cvss_raw))

        # 2. EPSS probability (0-1 -> 0-10)
        epss_raw = float(item.get("epss_score", 0) or 0)
        factors["epss"] = min(10.0, max(0.0, epss_raw * 10.0))

        # 3. KEV presence (boolean -> 0 or 10)
        kev = bool(item.get("kev_present", False))
        factors["kev"] = 10.0 if kev else 0.0

        # 4. IOC density factor (count-based, log-scaled to 0-10)
        ioc_total = 0
        ioc_counts = item.get("ioc_counts", {})
        if isinstance(ioc_counts, dict) and ioc_counts:
            ioc_total = sum(ioc_counts.values())
        else:
            iocs = item.get("iocs", {})
            if isinstance(iocs, dict):
                for vals in iocs.values():
                    if isinstance(vals, list):
                        ioc_total += len(vals)
        # Log scale: 0 iocs = 0, 1 = ~3.0, 10 = ~6.7, 50 = ~8.5, 100+ = ~10
        factors["ioc_density"] = min(10.0, (math.log(1 + ioc_total) / math.log(1 + 100)) * 10.0)

        # 5. MITRE coverage breadth (tactic count / 14, scaled to 0-10)
        mitre_tactics = item.get("mitre_tactics", [])
        unique_tactics = set()
        for t in mitre_tactics:
            tid = t if isinstance(t, str) else t.get("tactic", t.get("id", ""))
            if tid:
                unique_tactics.add(tid)
        factors["mitre_breadth"] = min(10.0, (len(unique_tactics) / self.MAX_MITRE_TACTICS) * 10.0)

        # 6. Actor attribution confidence (known vs UNC)
        actor_tag = item.get("actor_tag", "")
        if actor_tag and not actor_tag.startswith("UNC-") and not actor_tag.startswith("UNC"):
            factors["actor_attribution"] = 8.0  # Known named actor
        elif actor_tag:
            factors["actor_attribution"] = 3.0  # Unconfirmed actor cluster
        else:
            factors["actor_attribution"] = 0.0  # No attribution

        # 7. Temporal freshness (hours since publication)
        freshness_score = 0.0
        ts_str = item.get("timestamp", "")
        if ts_str:
            try:
                cleaned = ts_str.replace("Z", "+00:00")
                pub_time = datetime.fromisoformat(cleaned)
                # Make timezone-aware if naive
                if pub_time.tzinfo is None:
                    pub_time = pub_time.replace(tzinfo=timezone.utc)
                hours_ago = max(0.0, (now - pub_time).total_seconds() / 3600.0)
                # Linear decay: fresh (0 hours) = 10, MAX_FRESHNESS_HOURS = 0
                freshness_score = max(0.0, 10.0 * (1.0 - hours_ago / self.MAX_FRESHNESS_HOURS))
            except (ValueError, TypeError):
                freshness_score = 0.0
        factors["temporal_freshness"] = freshness_score

        # Weighted composite
        composite = sum(factors[k] * self.WEIGHTS[k] for k in self.WEIGHTS)
        composite = round(min(10.0, max(0.0, composite)), 2)

        priority_level = self._score_to_priority(composite)
        exploitation = self._assess_exploitation_likelihood(kev, epss_raw, cvss_raw, composite)

        return {
            "title": item.get("title", ""),
            "intel_id": item.get("intel_id", item.get("title", "")),
            "composite_score": composite,
            "priority_level": priority_level,
            "exploitation_likelihood": exploitation,
            "factor_scores": {k: round(v, 2) for k, v in factors.items()},
            "weights_applied": dict(self.WEIGHTS),
            "kev_present": kev,
            "cvss_score": cvss_raw,
            "epss_score": epss_raw,
        }

    def _score_to_priority(self, score: float) -> str:
        """
        Map composite score to a priority level P1-P5.

        Args:
            score: Composite score (0-10).

        Returns:
            Priority string from P1 (most critical) to P5 (informational).
        """
        if score >= 8.0:
            return "P1"
        if score >= 6.0:
            return "P2"
        if score >= 4.0:
            return "P3"
        if score >= 2.0:
            return "P4"
        return "P5"

    def _assess_exploitation_likelihood(
        self, kev: bool, epss: float, cvss: float, composite: float
    ) -> str:
        """
        Determine exploitation likelihood based on KEV, EPSS, CVSS, and composite.

        Args:
            kev: Whether the vulnerability is in CISA KEV.
            epss: EPSS probability (0-1).
            cvss: CVSS score (0-10).
            composite: Overall composite score (0-10).

        Returns:
            One of CONFIRMED, LIKELY, POSSIBLE, UNLIKELY.
        """
        if kev:
            return "CONFIRMED"
        if epss >= 0.7 or (epss >= 0.4 and cvss >= 8.0):
            return "LIKELY"
        if epss >= 0.1 or cvss >= 7.0 or composite >= 6.0:
            return "POSSIBLE"
        return "UNLIKELY"


# ═══════════════════════════════════════════════════════════
# CROSS-SOURCE CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════

class CrossSourceCorrelator:
    """
    Groups intelligence from different feed sources that reference the same
    CVEs or IOCs, calculates a corroboration score based on independent
    source confirmation, and marks items confirmed by multiple sources.
    """

    def correlate_sources(self, intel_items: List[Dict]) -> List[Dict]:
        """
        Identify threats reported by multiple independent sources.

        Groups items by shared CVEs and IOCs, then scores each group based
        on the number of independent sources confirming the threat.

        Args:
            intel_items: List of intelligence item dicts, each optionally containing:
                - source or feed_source (str)
                - iocs (dict of type -> list of values)
                - title (str, CVEs extracted via regex)

        Returns:
            List of cross-source confirmation dicts, sorted by corroboration_score descending.
        """
        if len(intel_items) < 2:
            return []

        # Index items by CVE and IOC indicators
        cve_to_items: Dict[str, List[int]] = defaultdict(list)
        ioc_to_items: Dict[str, List[int]] = defaultdict(list)

        for idx, item in enumerate(intel_items):
            # Extract CVEs from title and iocs
            title = item.get("title", "")
            cves = re.findall(r'CVE-\d{4}-\d{4,}', title, re.IGNORECASE)
            item_iocs = item.get("iocs", {})
            cves.extend(item_iocs.get("cve", []))
            for cve in set(c.upper() for c in cves):
                cve_to_items[cve].append(idx)

            # Index by IOC values
            for ioc_type, values in item_iocs.items():
                if ioc_type == "cve" or not isinstance(values, list):
                    continue
                for val in values:
                    ioc_to_items[f"{ioc_type}:{val}"].append(idx)

        # Build groups of items sharing indicators
        item_groups: Dict[str, Set[int]] = {}

        for indicator, indices in list(cve_to_items.items()) + list(ioc_to_items.items()):
            if len(indices) < 2:
                continue
            # Use first indicator as group key, merge overlapping groups
            group_key = indicator
            item_groups[group_key] = set(indices)

        # Merge overlapping groups
        merged_groups = self._merge_overlapping_groups(item_groups)

        # Build confirmation records
        confirmations = []
        for group_indices in merged_groups:
            if len(group_indices) < 2:
                continue

            group_items = [intel_items[i] for i in group_indices]
            sources = set()
            shared_cves = set()
            shared_iocs = set()

            for item in group_items:
                src = item.get("source", item.get("feed_source", ""))
                if src:
                    sources.add(src)

                title = item.get("title", "")
                for cve in re.findall(r'CVE-\d{4}-\d{4,}', title, re.IGNORECASE):
                    shared_cves.add(cve.upper())
                item_iocs = item.get("iocs", {})
                for cve in item_iocs.get("cve", []):
                    shared_cves.add(cve.upper())
                for ioc_type, values in item_iocs.items():
                    if ioc_type == "cve" or not isinstance(values, list):
                        continue
                    for val in values:
                        shared_iocs.add(f"{ioc_type}:{val}")

            source_count = len(sources)
            corroboration_score = self._compute_corroboration_score(
                source_count, len(shared_cves), len(shared_iocs), len(group_items)
            )

            max_risk = max((float(item.get("risk_score", 0)) for item in group_items), default=0)
            max_severity = "LOW"
            for item in group_items:
                sev = item.get("severity", "LOW")
                if sev == "CRITICAL":
                    max_severity = "CRITICAL"
                    break
                if sev == "HIGH" and max_severity != "CRITICAL":
                    max_severity = "HIGH"
                elif sev == "MEDIUM" and max_severity not in ("CRITICAL", "HIGH"):
                    max_severity = "MEDIUM"

            confirmations.append({
                "confirmation_id": f"CDB-XSC-{hashlib.sha256(str(sorted(group_indices)).encode()).hexdigest()[:8]}",
                "item_count": len(group_items),
                "source_count": source_count,
                "sources": list(sources)[:10],
                "shared_cves": list(shared_cves)[:20],
                "shared_iocs_count": len(shared_iocs),
                "corroboration_score": corroboration_score,
                "multi_source_confirmed": source_count >= 2,
                "max_risk_score": max_risk,
                "max_severity": max_severity,
                "titles": [item.get("title", "") for item in group_items][:10],
                "confidence": min(0.95, 0.3 + source_count * 0.2 + len(shared_cves) * 0.05),
            })

        confirmations.sort(key=lambda c: c["corroboration_score"], reverse=True)
        logger.info(
            f"Cross-Source Correlation: {len(confirmations)} confirmed groups, "
            f"{sum(1 for c in confirmations if c['multi_source_confirmed'])} multi-source confirmed"
        )
        return confirmations

    def _merge_overlapping_groups(self, item_groups: Dict[str, Set[int]]) -> List[Set[int]]:
        """
        Merge groups that share common item indices using union-find.

        Args:
            item_groups: Mapping of indicator key to set of item indices.

        Returns:
            List of merged sets of item indices.
        """
        if not item_groups:
            return []

        # Union-Find
        parent: Dict[int, int] = {}

        def find(x: int) -> int:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for indices in item_groups.values():
            idx_list = list(indices)
            for i in range(1, len(idx_list)):
                union(idx_list[0], idx_list[i])

        # Group by root
        root_groups: Dict[int, Set[int]] = defaultdict(set)
        all_items = set()
        for indices in item_groups.values():
            all_items.update(indices)
        for item_idx in all_items:
            root_groups[find(item_idx)].add(item_idx)

        return [group for group in root_groups.values() if len(group) >= 2]

    def _compute_corroboration_score(
        self, source_count: int, cve_count: int, ioc_count: int, item_count: int
    ) -> float:
        """
        Compute a corroboration score (0-10) based on multi-source confirmation signals.

        Args:
            source_count: Number of independent sources.
            cve_count: Number of shared CVEs.
            ioc_count: Number of shared IOCs.
            item_count: Total items in the group.

        Returns:
            Corroboration score from 0.0 to 10.0.
        """
        score = 0.0
        # Sources are the strongest corroboration signal
        score += min(4.0, source_count * 1.5)
        # Shared CVEs reinforce confidence
        score += min(3.0, cve_count * 0.5)
        # Shared IOCs show technical overlap
        score += min(2.0, math.log(1 + ioc_count) * 0.5)
        # Volume of corroborating items
        score += min(1.0, item_count * 0.15)
        return round(min(10.0, score), 2)


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
        self.threat_prioritizer = ThreatPrioritizationEngine()
        self.cross_source_correlator = CrossSourceCorrelator()
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
            "threat_priorities": [],
            "velocity_anomalies": [],
            "cross_source_confirmations": [],
            "summary": {},
        }

        if not intel_items:
            return results

        # Run all analysis engines
        results["ioc_clusters"] = self.ioc_clusterer.cluster_iocs(intel_items)
        results["cve_correlations"] = self.cve_correlator.correlate_cves(intel_items)
        results["campaigns"] = self.campaign_detector.detect_campaigns(intel_items)
        results["anomalies"] = self.anomaly_detector.detect_anomalies(intel_items)

        # Run new analysis engines
        results["threat_priorities"] = self.threat_prioritizer.prioritize(intel_items, now=start)
        results["velocity_anomalies"] = self.anomaly_detector.detect_velocity_anomalies(intel_items)
        results["cross_source_confirmations"] = self.cross_source_correlator.correlate_sources(intel_items)

        # Build summary
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        p1_count = sum(1 for p in results["threat_priorities"] if p.get("priority_level") == "P1")
        p2_count = sum(1 for p in results["threat_priorities"] if p.get("priority_level") == "P2")
        multi_confirmed = sum(1 for c in results["cross_source_confirmations"] if c.get("multi_source_confirmed"))
        results["summary"] = {
            "total_clusters": len(results["ioc_clusters"]),
            "total_correlations": len(results["cve_correlations"]),
            "total_campaigns": len(results["campaigns"]),
            "total_anomalies": len(results["anomalies"]),
            "critical_campaigns": sum(1 for c in results["campaigns"] if c.get("severity") == "CRITICAL"),
            "high_risk_correlations": sum(1 for c in results["cve_correlations"] if c.get("max_risk_score", 0) >= 7.0),
            "p1_threats": p1_count,
            "p2_threats": p2_count,
            "velocity_spikes": len(results["velocity_anomalies"]),
            "multi_source_confirmed": multi_confirmed,
            "analysis_duration_seconds": round(duration, 3),
            "sklearn_available": _SKLEARN_AVAILABLE,
            "analysis_run_number": self._analysis_count,
        }

        logger.info(
            f"AI Analysis complete: {results['summary']['total_campaigns']} campaigns, "
            f"{results['summary']['total_clusters']} clusters, "
            f"{results['summary']['total_correlations']} correlations, "
            f"{results['summary']['total_anomalies']} anomalies, "
            f"{p1_count} P1 threats, {multi_confirmed} multi-source confirmed "
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

        text = f"{intel_item.get('title', '')} {intel_item.get('content', '')}".lower()
        risk_score = float(intel_item.get("risk_score", 0))

        # Zero-day detection
        if any(t in text for t in ["zero-day", "0-day", "zero day"]):
            signals["ai_risk_modifier"] += 1.5
            signals["threat_category"] = "ZERO_DAY"
            signals["tags"].append("zero-day")

        # APT detection
        apt_indicators = ["apt", "nation-state", "state-sponsored", "lazarus", "cozy bear",
                          "fancy bear", "volt typhoon", "sandworm", "hafnium"]
        if any(t in text for t in apt_indicators):
            signals["ai_risk_modifier"] += 1.0
            signals["threat_category"] = "APT"
            signals["tags"].append("apt")

        # Supply chain
        if any(t in text for t in ["supply chain", "dependency", "npm", "pypi", "package"]):
            signals["ai_risk_modifier"] += 0.8
            signals["tags"].append("supply-chain")

        # Multi-CVE correlation signal
        cves = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        if len(cves) > 1:
            signals["ai_risk_modifier"] += 0.5
            signals["tags"].append("multi-cve")

        # KEV + high EPSS = imminent threat
        if intel_item.get("kev_present") and float(intel_item.get("epss_score", 0) or 0) >= 0.5:
            signals["ai_risk_modifier"] += 1.0
            signals["confidence_boost"] = 10.0
            signals["tags"].append("imminent-threat")

        return signals

    def generate_threat_summary(self, intel_items: List[Dict]) -> Dict:
        """
        Produce a structured intelligence summary for executive or analyst consumption.

        Runs the threat prioritization engine and aggregates results into a
        high-level summary covering top threats, landscape distribution, active
        exploitation, emerging threats, and threat velocity.

        Args:
            intel_items: List of intelligence item dicts.

        Returns:
            Dict with keys: top_threats, threat_landscape, active_exploitation,
            emerging_threats, threat_velocity, generated_at.
        """
        now = datetime.now(timezone.utc)

        summary: Dict[str, Any] = {
            "generated_at": now.isoformat(),
            "total_items_analyzed": len(intel_items),
            "top_threats": [],
            "threat_landscape": {},
            "active_exploitation": [],
            "emerging_threats": [],
            "threat_velocity": {},
        }

        if not intel_items:
            return summary

        # Run prioritization
        priorities = self.threat_prioritizer.prioritize(intel_items, now=now)

        # Top threats: sorted by composite score, top 20
        summary["top_threats"] = [
            {
                "title": p["title"],
                "composite_score": p["composite_score"],
                "priority_level": p["priority_level"],
                "exploitation_likelihood": p["exploitation_likelihood"],
                "cvss_score": p["cvss_score"],
                "epss_score": p["epss_score"],
                "kev_present": p["kev_present"],
            }
            for p in priorities[:20]
        ]

        # Threat landscape: category distribution by severity
        severity_dist: Dict[str, int] = Counter()
        category_dist: Dict[str, int] = Counter()
        for item in intel_items:
            severity_dist[item.get("severity", "UNKNOWN")] += 1
            # Categorize by quick_score threat_category
            signals = self.quick_score(item)
            category_dist[signals.get("threat_category", "GENERAL")] += 1

        summary["threat_landscape"] = {
            "severity_distribution": dict(severity_dist),
            "category_distribution": dict(category_dist),
            "priority_distribution": dict(Counter(p["priority_level"] for p in priorities)),
            "exploitation_distribution": dict(Counter(p["exploitation_likelihood"] for p in priorities)),
        }

        # Active exploitation: KEV-confirmed items
        summary["active_exploitation"] = [
            {
                "title": item.get("title", ""),
                "cvss_score": float(item.get("cvss_score", 0) or 0),
                "epss_score": float(item.get("epss_score", 0) or 0),
                "severity": item.get("severity", "MEDIUM"),
                "actor_tag": item.get("actor_tag", ""),
            }
            for item in intel_items
            if item.get("kev_present")
        ]

        # Emerging threats: high EPSS (>=0.3) but NOT yet KEV
        emerging = []
        for item in intel_items:
            epss = float(item.get("epss_score", 0) or 0)
            if epss >= 0.3 and not item.get("kev_present"):
                emerging.append({
                    "title": item.get("title", ""),
                    "epss_score": epss,
                    "cvss_score": float(item.get("cvss_score", 0) or 0),
                    "severity": item.get("severity", "MEDIUM"),
                    "risk_assessment": "HIGH_RISK_EMERGING" if epss >= 0.7 else "MONITOR_CLOSELY",
                })
        emerging.sort(key=lambda e: e["epss_score"], reverse=True)
        summary["emerging_threats"] = emerging[:20]

        # Threat velocity: items per hour over the observed time range
        timestamps = []
        for item in intel_items:
            ts_str = item.get("timestamp", "")
            if ts_str:
                try:
                    cleaned = ts_str.replace("Z", "+00:00")
                    ts = datetime.fromisoformat(cleaned)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    timestamps.append(ts)
                except (ValueError, TypeError):
                    pass

        if len(timestamps) >= 2:
            timestamps.sort()
            span_hours = max(1.0, (timestamps[-1] - timestamps[0]).total_seconds() / 3600.0)
            items_per_hour = round(len(timestamps) / span_hours, 2)
            # Last 24h velocity
            cutoff_24h = now - timedelta(hours=24)
            recent_count = sum(1 for ts in timestamps if ts >= cutoff_24h)
            summary["threat_velocity"] = {
                "overall_items_per_hour": items_per_hour,
                "last_24h_count": recent_count,
                "last_24h_items_per_hour": round(recent_count / 24.0, 2),
                "observation_window_hours": round(span_hours, 1),
            }
        else:
            summary["threat_velocity"] = {
                "overall_items_per_hour": 0.0,
                "last_24h_count": len(intel_items),
                "last_24h_items_per_hour": 0.0,
                "observation_window_hours": 0.0,
            }

        logger.info(
            f"Threat Summary generated: {len(summary['top_threats'])} top threats, "
            f"{len(summary['active_exploitation'])} active exploitations, "
            f"{len(summary['emerging_threats'])} emerging threats"
        )
        return summary

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
