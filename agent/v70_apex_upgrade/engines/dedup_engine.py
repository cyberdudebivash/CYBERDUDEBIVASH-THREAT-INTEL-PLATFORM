"""
SENTINEL APEX v70.3 — Optimized Deduplication Engine
======================================================
Performance fix: replaces O(n²) title similarity with:
1. Exact dedup_key match (O(n) hash lookup)
2. URL dedup (O(n) hash lookup)
3. CVE-set overlap (O(n) inverted index, only checks pairs sharing CVEs)
4. Title similarity ONLY on short candidate lists from CVE/URL groups

Target: 15.86s → <2s for 400 items.
"""

import hashlib
import logging
import re
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any, Dict, List, Set

from ..core.models import Advisory

logger = logging.getLogger("sentinel.dedup_engine")


class DedupEngine:
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
        t = title.lower().strip()
        t = re.sub(r"[^\w\s]", "", t)
        t = re.sub(r"\s+", " ", t)
        return t

    @staticmethod
    def _title_hash(title: str) -> str:
        """Fast title fingerprint for pre-grouping."""
        norm = DedupEngine._normalize_title(title)
        # Take first 6 words as fingerprint (catches most CVE-title dupes)
        words = norm.split()[:6]
        return " ".join(words)

    def _merge(self, primary: Advisory, dup: Advisory) -> Advisory:
        if dup.confidence > primary.confidence:
            primary, dup = dup, primary
        primary.cves = list(set(primary.cves + dup.cves))
        existing_ioc_vals = set()
        merged_iocs = []
        for ioc in primary.iocs + dup.iocs:
            val = ioc.value if hasattr(ioc, 'value') else str(ioc)
            if val not in existing_ioc_vals:
                existing_ioc_vals.add(val)
                merged_iocs.append(ioc)
        primary.iocs = merged_iocs
        primary.actors = list(set(primary.actors + dup.actors))
        primary.mitre_techniques = list(set(primary.mitre_techniques + dup.mitre_techniques))
        primary.tags = list(set(primary.tags + dup.tags))
        primary.threat_score = max(primary.threat_score, dup.threat_score)
        if not primary.summary and dup.summary:
            primary.summary = dup.summary
        elif dup.summary and len(dup.summary) > len(primary.summary):
            primary.summary = dup.summary
        if not primary.ai_summary and dup.ai_summary:
            primary.ai_summary = dup.ai_summary
        if dup.advisory_id and dup.advisory_id not in primary.related_advisories:
            primary.related_advisories.append(dup.advisory_id)
        primary.attack_chain = list(set(primary.attack_chain + dup.attack_chain))
        primary.affected_products = list(set(primary.affected_products + dup.affected_products))
        if not primary.blog_post_url and dup.blog_post_url:
            primary.blog_post_url = dup.blog_post_url
            primary.blog_post_id = dup.blog_post_id
        self._stats["merged"] += 1
        return primary

    def deduplicate(self, advisories: List[Advisory]) -> List[Advisory]:
        self._stats = {"total_input": len(advisories), "duplicates_found": 0, "merged": 0}
        if len(advisories) < 2:
            return advisories

        # Phase 1: Exact dedup_key — O(n) hash grouping
        key_map: Dict[str, int] = {}  # dedup_key → first index
        merged_indices: Set[int] = set()
        advs = list(advisories)

        for idx, adv in enumerate(advs):
            dk = adv.dedup_key
            if dk in key_map:
                first_idx = key_map[dk]
                advs[first_idx] = self._merge(advs[first_idx], adv)
                merged_indices.add(idx)
                self._stats["duplicates_found"] += 1
            else:
                key_map[dk] = idx

        # Phase 2: URL dedup — O(n) hash grouping
        url_map: Dict[str, int] = {}
        for idx, adv in enumerate(advs):
            if idx in merged_indices:
                continue
            url = adv.source_url.strip().lower()
            if not url:
                continue
            if url in url_map:
                first_idx = url_map[url]
                if first_idx not in merged_indices:
                    advs[first_idx] = self._merge(advs[first_idx], adv)
                    merged_indices.add(idx)
                    self._stats["duplicates_found"] += 1
            else:
                url_map[url] = idx

        # Phase 3: CVE overlap — inverted index (only check pairs sharing CVEs)
        cve_to_indices: Dict[str, List[int]] = defaultdict(list)
        for idx, adv in enumerate(advs):
            if idx in merged_indices or not adv.cves:
                continue
            for cve in adv.cves:
                cve_to_indices[cve.upper()].append(idx)

        checked_pairs: Set[tuple] = set()
        for cve, indices in cve_to_indices.items():
            if len(indices) < 2:
                continue
            for i in range(len(indices)):
                for j in range(i + 1, len(indices)):
                    a, b = indices[i], indices[j]
                    if a in merged_indices or b in merged_indices:
                        continue
                    pair = (min(a, b), max(a, b))
                    if pair in checked_pairs:
                        continue
                    checked_pairs.add(pair)
                    # Check CVE overlap
                    set_a = set(c.upper() for c in advs[a].cves)
                    set_b = set(c.upper() for c in advs[b].cves)
                    intersection = set_a & set_b
                    union = set_a | set_b
                    if union and len(intersection) / len(union) >= self.cve_threshold:
                        advs[a] = self._merge(advs[a], advs[b])
                        merged_indices.add(b)
                        self._stats["duplicates_found"] += 1

        # Phase 4: Title fingerprint dedup — O(n) pre-grouping
        # Only run similarity check within groups that share the same title prefix
        title_groups: Dict[str, List[int]] = defaultdict(list)
        for idx, adv in enumerate(advs):
            if idx in merged_indices:
                continue
            fp = self._title_hash(adv.title)
            title_groups[fp].append(idx)

        for fp, indices in title_groups.items():
            if len(indices) < 2:
                continue
            # Within-group pairwise check (groups are small, typically 2-3 items)
            for i in range(len(indices)):
                if indices[i] in merged_indices:
                    continue
                for j in range(i + 1, len(indices)):
                    if indices[j] in merged_indices:
                        continue
                    na = self._normalize_title(advs[indices[i]].title)
                    nb = self._normalize_title(advs[indices[j]].title)
                    if SequenceMatcher(None, na, nb).ratio() >= self.title_threshold:
                        advs[indices[i]] = self._merge(advs[indices[i]], advs[indices[j]])
                        merged_indices.add(indices[j])
                        self._stats["duplicates_found"] += 1

        result = [adv for idx, adv in enumerate(advs) if idx not in merged_indices]

        logger.info(
            f"Dedup complete: {self._stats['total_input']} -> {len(result)} "
            f"({self._stats['duplicates_found']} duplicates, {self._stats['merged']} merges)"
        )
        return result


def deduplicate_advisories(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    from ..core.models import advisory_from_legacy
    advisories = [advisory_from_legacy(item) for item in items]
    engine = DedupEngine()
    deduped = engine.deduplicate(advisories)
    return [a.to_legacy_dict() for a in deduped]
