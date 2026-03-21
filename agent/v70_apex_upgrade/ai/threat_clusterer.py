"""
SENTINEL APEX v70 — Threat Clustering Engine (AI-Powered)
===========================================================
Groups related advisories into clusters using:
1. TF-IDF vectorization of advisory text
2. DBSCAN clustering (density-based, no preset k)
3. Cluster labeling via top-term extraction

Falls back to deterministic CVE/tag grouping if sklearn unavailable.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..core.models import Advisory

logger = logging.getLogger("sentinel.ai.clusterer")

# ML imports with graceful fallback
_ML_AVAILABLE = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    _ML_AVAILABLE = True
except ImportError:
    logger.warning("sklearn not available — using rule-based clustering")


class ThreatClusterer:
    """
    AI-powered threat clustering engine.
    Groups related advisories by semantic similarity.
    """

    def __init__(
        self,
        eps: float = 0.45,
        min_samples: int = 2,
        max_features: int = 3000,
    ):
        self.eps = eps
        self.min_samples = min_samples
        self.max_features = max_features
        self._clusters: Dict[str, List[str]] = {}
        self._cluster_labels: Dict[str, str] = {}

    @property
    def clusters(self) -> Dict[str, List[str]]:
        return dict(self._clusters)

    @property
    def cluster_labels(self) -> Dict[str, str]:
        return dict(self._cluster_labels)

    def cluster(self, advisories: List[Advisory]) -> List[Advisory]:
        """
        Cluster advisories and assign cluster IDs.
        Returns updated advisories with ai_cluster_id set.
        """
        if len(advisories) < 2:
            return advisories

        if _ML_AVAILABLE:
            return self._ml_cluster(advisories)
        else:
            return self._rule_cluster(advisories)

    def _ml_cluster(self, advisories: List[Advisory]) -> List[Advisory]:
        """ML-based clustering using TF-IDF + DBSCAN."""
        # Build text corpus
        texts = []
        for adv in advisories:
            text = f"{adv.title} {adv.summary} {' '.join(adv.cves)} {' '.join(adv.tags)} {' '.join(adv.actors)}"
            texts.append(text)

        try:
            # TF-IDF vectorization
            vectorizer = TfidfVectorizer(
                max_features=self.max_features,
                ngram_range=(1, 2),
                stop_words="english",
                sublinear_tf=True,
            )
            tfidf_matrix = vectorizer.fit_transform(texts)

            # Compute cosine distance matrix (clip negatives from floating point)
            cosine_dist = np.clip(1 - cosine_similarity(tfidf_matrix), 0, 2)

            # DBSCAN clustering
            clustering = DBSCAN(
                eps=self.eps,
                min_samples=self.min_samples,
                metric="precomputed",
            )
            labels = clustering.fit_predict(cosine_dist)

            # Assign cluster IDs
            self._clusters = defaultdict(list)
            for idx, label in enumerate(labels):
                if label == -1:
                    # Noise point — assign to singleton cluster
                    cluster_id = f"cluster_singleton_{idx}"
                else:
                    cluster_id = f"cluster_{label}"

                advisories[idx].ai_cluster_id = cluster_id
                self._clusters[cluster_id].append(advisories[idx].advisory_id)

            # Generate cluster labels from top TF-IDF terms
            feature_names = vectorizer.get_feature_names_out()
            for cluster_id, adv_ids in self._clusters.items():
                if cluster_id.startswith("cluster_singleton"):
                    continue
                # Get indices for this cluster
                cluster_indices = [
                    idx for idx, adv in enumerate(advisories)
                    if adv.ai_cluster_id == cluster_id
                ]
                if cluster_indices:
                    # Mean TF-IDF vector for cluster
                    cluster_vectors = tfidf_matrix[cluster_indices]
                    mean_vector = np.asarray(cluster_vectors.mean(axis=0)).flatten()
                    top_indices = mean_vector.argsort()[-5:][::-1]
                    top_terms = [feature_names[i] for i in top_indices if mean_vector[i] > 0]
                    self._cluster_labels[cluster_id] = " | ".join(top_terms[:3])

            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            n_noise = list(labels).count(-1)
            logger.info(
                f"ML clustering: {n_clusters} clusters found, "
                f"{n_noise} singletons, {len(advisories)} total"
            )

        except Exception as e:
            logger.error(f"ML clustering failed, falling back to rules: {e}")
            return self._rule_cluster(advisories)

        return advisories

    def _rule_cluster(self, advisories: List[Advisory]) -> List[Advisory]:
        """
        Rule-based clustering fallback.
        Groups by: shared CVEs → shared actors → shared tags.
        """
        self._clusters = defaultdict(list)
        assigned = set()
        cluster_counter = 0

        # Group by shared CVEs
        cve_groups: Dict[str, List[int]] = defaultdict(list)
        for idx, adv in enumerate(advisories):
            for cve in adv.cves:
                cve_groups[cve.upper()].append(idx)

        for cve, indices in cve_groups.items():
            if len(indices) >= 2:
                cluster_id = f"cluster_cve_{cluster_counter}"
                cluster_counter += 1
                for idx in indices:
                    if idx not in assigned:
                        advisories[idx].ai_cluster_id = cluster_id
                        self._clusters[cluster_id].append(advisories[idx].advisory_id)
                        assigned.add(idx)
                self._cluster_labels[cluster_id] = f"CVE: {cve}"

        # Group by shared actors
        actor_groups: Dict[str, List[int]] = defaultdict(list)
        for idx, adv in enumerate(advisories):
            if idx in assigned:
                continue
            for actor in adv.actors:
                actor_groups[actor.lower()].append(idx)

        for actor, indices in actor_groups.items():
            if len(indices) >= 2:
                cluster_id = f"cluster_actor_{cluster_counter}"
                cluster_counter += 1
                for idx in indices:
                    if idx not in assigned:
                        advisories[idx].ai_cluster_id = cluster_id
                        self._clusters[cluster_id].append(advisories[idx].advisory_id)
                        assigned.add(idx)
                self._cluster_labels[cluster_id] = f"Actor: {actor}"

        # Remaining → singleton
        for idx, adv in enumerate(advisories):
            if idx not in assigned:
                cluster_id = f"cluster_singleton_{idx}"
                adv.ai_cluster_id = cluster_id
                self._clusters[cluster_id].append(adv.advisory_id)

        logger.info(f"Rule-based clustering: {cluster_counter} clusters, {len(advisories)} total")
        return advisories

    def get_cluster_summary(self) -> List[Dict[str, Any]]:
        """Return cluster summary for dashboard/API consumption."""
        summary = []
        for cluster_id, adv_ids in self._clusters.items():
            if cluster_id.startswith("cluster_singleton"):
                continue
            summary.append({
                "cluster_id": cluster_id,
                "label": self._cluster_labels.get(cluster_id, "Unlabeled"),
                "advisory_count": len(adv_ids),
                "advisory_ids": adv_ids,
            })
        return sorted(summary, key=lambda x: x["advisory_count"], reverse=True)
