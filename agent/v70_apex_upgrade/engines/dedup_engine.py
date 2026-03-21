"""
SENTINEL APEX v70 — Deduplication Engine
==========================================
Multi-strategy dedup:
1. Exact match (same dedup_key)
2. CVE overlap (>50% CVE intersection)
3. Title similarity (fuzzy, >85% match)
4. URL dedup (same source URL)

Merges intelligently: keeps highest-confidence, most-enriched version.
"""

import hashlib
import logging
import re
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.models import Advisory, advisory_from_legacy

logger = logging.getLogger("sentinel.dedup_engine")


class DedupEngine:
    """
    Production deduplication engine for threat advisories.
    Detects duplicates across multiple dimensions and merges intelligently.
    """

    def __init__(
        self,
        title_similarity_threshold: float = 0.85,
        cve_overlap_threshold: float = 0.50,
    ):
        self.title_threshold = title_similarity_threshold
        self.cve_threshold = cve_overlap_threshold
        self._stats = {"total_input": 0, "duplicates_found": 0, "merged": 0}

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    @staticmethod
    def _normalize_title(title: str) -> str:
        """Normalize title for comparison."""
        t = title.lower().strip()
        t = re.sub(r"[^\w\s]", "", t)
        t = re.sub(r"\s+", " ", t)
        return t

    @staticmethod
    def _title_similarity(a: str, b: str) -> float:
        """Compute title similarity ratio."""
        na = DedupEngine._normalize_title(a)
        nb = DedupEngine._normalize_title(b)
        if not na or not nb:
            return 0.0
        return SequenceMatcher(None, na, nb).ratio()

    @staticmethod
    def _cve_overlap(cves_a: List[str], cves_b: List[str]) -> float:
        """Compute CVE overlap ratio (Jaccard index)."""
        if not cves_a and not cves_b:
            return 0.0
        set_a = set(c.upper() for c in cves_a)
        set_b = set(c.upper() for c in cves_b)
        if not set_a and not set_b:
            return 0.0
        intersection = set_a & set_b
        union = set_a | set_b
        return len(intersection) / len(union) if union else 0.0

    def _merge_advisories(self, primary: Advisory, duplicate: Advisory) -> Advisory:
        """
        Merge duplicate into primary, keeping the best data from each.
        Primary = higher confidence or more enriched version.
        """
        # Keep the one with higher confidence as base
        if duplicate.confidence > primary.confidence:
            primary, duplicate = duplicate, primary

        # Merge CVEs (union)
        all_cves = list(set(primary.cves + duplicate.cves))
        primary.cves = all_cves

        # Merge IOCs (union by value)
        existing_values = set()
        merged_iocs = []
        for ioc in primary.iocs + duplicate.iocs:
            val = ioc.value if hasattr(ioc, 'value') else str(ioc)
            if val not in existing_values:
                existing_values.add(val)
                merged_iocs.append(ioc)
        primary.iocs = merged_iocs

        # Merge actors (union)
        primary.actors = list(set(primary.actors + duplicate.actors))

        # Merge MITRE techniques (union)
        primary.mitre_techniques = list(set(primary.mitre_techniques + duplicate.mitre_techniques))

        # Merge tags (union)
        primary.tags = list(set(primary.tags + duplicate.tags))

        # Take highest threat score
        primary.threat_score = max(primary.threat_score, duplicate.threat_score)

        # Use best summary
        if not primary.summary and duplicate.summary:
            primary.summary = duplicate.summary
        elif duplicate.summary and len(duplicate.summary) > len(primary.summary):
            primary.summary = duplicate.summary

        # Use best AI summary
        if not primary.ai_summary and duplicate.ai_summary:
            primary.ai_summary = duplicate.ai_summary

        # Track relationship
        if duplicate.advisory_id and duplicate.advisory_id not in primary.related_advisories:
            primary.related_advisories.append(duplicate.advisory_id)

        # Merge attack chain
        primary.attack_chain = list(set(primary.attack_chain + duplicate.attack_chain))

        # Merge affected products
        primary.affected_products = list(set(primary.affected_products + duplicate.affected_products))

        # Blog: keep the one with a blog post
        if not primary.blog_post_url and duplicate.blog_post_url:
            primary.blog_post_url = duplicate.blog_post_url
            primary.blog_post_id = duplicate.blog_post_id

        self._stats["merged"] += 1
        return primary

    def deduplicate(
        self,
        advisories: List[Advisory],
    ) -> List[Advisory]:
        """
        Main dedup pipeline. Returns deduplicated advisory list.
        
        Strategy order:
        1. Exact dedup_key match → merge
        2. URL dedup → merge
        3. CVE overlap > threshold → merge
        4. Title similarity > threshold → merge
        """
        self._stats = {"total_input": len(advisories), "duplicates_found": 0, "merged": 0}

        if not advisories:
            return []

        # Phase 1: Group by dedup_key
        key_groups: Dict[str, List[int]] = defaultdict(list)
        for idx, adv in enumerate(advisories):
            key_groups[adv.dedup_key].append(idx)

        # Merge exact dupes
        merged_indices: Set[int] = set()
        result_map: Dict[int, Advisory] = {}

        for dk, indices in key_groups.items():
            if len(indices) > 1:
                self._stats["duplicates_found"] += len(indices) - 1
                primary = advisories[indices[0]]
                for dup_idx in indices[1:]:
                    primary = self._merge_advisories(primary, advisories[dup_idx])
                    merged_indices.add(dup_idx)
                result_map[indices[0]] = primary
            else:
                result_map[indices[0]] = advisories[indices[0]]

        # Phase 2: URL dedup on remaining
        url_groups: Dict[str, List[int]] = defaultdict(list)
        for idx in result_map:
            url = result_map[idx].source_url.strip().lower()
            if url:
                url_groups[url].append(idx)

        for url, indices in url_groups.items():
            if len(indices) > 1:
                self._stats["duplicates_found"] += len(indices) - 1
                primary_idx = indices[0]
                for dup_idx in indices[1:]:
                    result_map[primary_idx] = self._merge_advisories(
                        result_map[primary_idx], result_map[dup_idx]
                    )
                    del result_map[dup_idx]

        # Phase 3: CVE overlap on remaining (O(n²) but bounded by manifest size)
        remaining = list(result_map.keys())
        cve_merged: Set[int] = set()
        for i in range(len(remaining)):
            if remaining[i] in cve_merged:
                continue
            adv_i = result_map[remaining[i]]
            if not adv_i.cves:
                continue
            for j in range(i + 1, len(remaining)):
                if remaining[j] in cve_merged:
                    continue
                adv_j = result_map[remaining[j]]
                if not adv_j.cves:
                    continue
                overlap = self._cve_overlap(adv_i.cves, adv_j.cves)
                if overlap >= self.cve_threshold:
                    self._stats["duplicates_found"] += 1
                    result_map[remaining[i]] = self._merge_advisories(adv_i, adv_j)
                    adv_i = result_map[remaining[i]]
                    cve_merged.add(remaining[j])

        for idx in cve_merged:
            if idx in result_map:
                del result_map[idx]

        # Phase 4: Title similarity on remaining
        remaining = list(result_map.keys())
        title_merged: Set[int] = set()
        for i in range(len(remaining)):
            if remaining[i] in title_merged:
                continue
            adv_i = result_map[remaining[i]]
            for j in range(i + 1, len(remaining)):
                if remaining[j] in title_merged:
                    continue
                adv_j = result_map[remaining[j]]
                sim = self._title_similarity(adv_i.title, adv_j.title)
                if sim >= self.title_threshold:
                    self._stats["duplicates_found"] += 1
                    result_map[remaining[i]] = self._merge_advisories(adv_i, adv_j)
                    adv_i = result_map[remaining[i]]
                    title_merged.add(remaining[j])

        for idx in title_merged:
            if idx in result_map:
                del result_map[idx]

        deduped = list(result_map.values())

        logger.info(
            f"Dedup complete: {self._stats['total_input']} → {len(deduped)} "
            f"({self._stats['duplicates_found']} duplicates found, "
            f"{self._stats['merged']} merges)"
        )
        return deduped


def deduplicate_advisories(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convenience function: dedup a list of legacy advisory dicts.
    Returns deduplicated legacy dicts (backward-compatible).
    """
    advisories = [advisory_from_legacy(item) for item in items]
    engine = DedupEngine()
    deduped = engine.deduplicate(advisories)
    return [a.to_legacy_dict() for a in deduped]
