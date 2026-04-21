#!/usr/bin/env python3
"""
campaign_clusterer.py — CYBERDUDEBIVASH® SENTINEL APEX v134.0.0
════════════════════════════════════════════════════════════════════════════════
Campaign Grouping Engine

Groups related threat intel items into campaigns using DBSCAN clustering
on TTP similarity, IOC overlap, temporal proximity, and actor attribution.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger("CDB-CAMPAIGN-CLUSTERER")

# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

# DBSCAN parameters — tune for intel item density
DBSCAN_EPS = 0.40          # max distance for neighbourhood (1 - similarity)
DBSCAN_MIN_SAMPLES = 2     # min items to form a core point

# Similarity weight distribution (must sum to 1.0)
W_TTP = 0.35
W_IOC = 0.25
W_TEMPORAL = 0.15
W_ACTOR = 0.15
W_KEYWORD = 0.10

MAX_TEMPORAL_HOURS = 168.0  # 7 days — beyond this, temporal score = 0

THREAT_LEVEL_MAP = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# Campaign name vocabulary
_TACTICS = ["PHANTOM", "SHADOW", "STEALTH", "SILENT", "GHOST", "DARK", "COVERT", "VOID"]
_THEMES = ["EXFIL", "RANSOM", "ESPIONAGE", "WIPER", "SUPPLY-CHAIN", "EXPLOIT", "PIVOT", "PERSIST"]
_SECTORS = {
    "healthcare": "HEALTH", "finance": "FINSERV", "energy": "ENERGY",
    "government": "GOV", "defense": "DEFENSE", "education": "EDU",
    "retail": "RETAIL", "manufacturing": "MFG", "technology": "TECH",
    "telecom": "TELECOM", "transportation": "TRANSIT",
}


# ════════════════════════════════════════════════════════════════════════════════
# HELPER UTILITIES
# ════════════════════════════════════════════════════════════════════════════════

def _to_set(value: Any) -> Set[str]:
    """Normalise a list/string/set to a lowercase set of strings."""
    if isinstance(value, (list, tuple)):
        return {str(v).lower().strip() for v in value if v}
    if isinstance(value, set):
        return {str(v).lower().strip() for v in value}
    if isinstance(value, str) and value:
        return {s.lower().strip() for s in value.replace(";", ",").split(",") if s.strip()}
    return set()


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _parse_dt(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    try:
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except Exception:
        return None


def _item_date(item: dict) -> Optional[datetime]:
    for key in ("disclosure_date", "published_date", "created_at", "date", "timestamp"):
        dt = _parse_dt(item.get(key))
        if dt:
            return dt
    return None


def _item_ttps(item: dict) -> Set[str]:
    return _to_set(item.get("ttps", item.get("techniques", item.get("mitre_techniques", []))))


def _item_iocs(item: dict) -> Set[str]:
    return _to_set(item.get("iocs", item.get("indicators", [])))


def _item_actor(item: dict) -> str:
    return str(item.get("actor", item.get("threat_actor", "unknown"))).lower().strip()


def _item_keywords(item: dict) -> Set[str]:
    """Extract keywords from title + description + tags."""
    parts = []
    for key in ("title", "name", "description", "summary", "tags", "keywords"):
        v = item.get(key, "")
        if isinstance(v, list):
            parts.extend(v)
        elif v:
            parts.append(str(v))
    text = " ".join(parts).lower()
    # Simple tokenisation — alphanumeric tokens ≥ 4 chars
    tokens = {t for t in text.split() if len(t) >= 4 and t.isalnum()}
    return tokens


def _item_sector(item: dict) -> str:
    return str(item.get("sector", item.get("industry", "unknown"))).lower().strip()


def _severity_int(item: dict) -> int:
    raw = str(item.get("severity", item.get("risk_level", "low"))).lower()
    m = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0}
    for k, v in m.items():
        if k in raw:
            return v
    cvss = float(item.get("cvss_score", item.get("cvss", 0.0)) or 0.0)
    if cvss >= 9.0: return 4
    if cvss >= 7.0: return 3
    if cvss >= 4.0: return 2
    if cvss > 0.0: return 1
    return 1


def _stable_id(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:12].upper()


# ════════════════════════════════════════════════════════════════════════════════
# CAMPAIGN CLUSTERER
# ════════════════════════════════════════════════════════════════════════════════

class CampaignClusterer:
    """
    Groups related threat intel items into campaigns using DBSCAN clustering
    on TTP similarity, IOC overlap, temporal proximity, and actor attribution.

    Thread-safe. Stateless per call (no persistent model needed).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._total_clustered = 0
        self._total_campaigns = 0
        logger.info("CampaignClusterer initialised (DBSCAN eps=%.2f, min_samples=%d)",
                    DBSCAN_EPS, DBSCAN_MIN_SAMPLES)

    # ── similarity ────────────────────────────────────────────────────────────

    def compute_similarity(self, item_a: dict, item_b: dict) -> float:
        """
        Multi-factor similarity score [0.0, 1.0].
        Factors: TTP Jaccard, IOC overlap, temporal proximity, actor match, keyword overlap.
        """
        # TTP Jaccard
        ttp_sim = _jaccard(_item_ttps(item_a), _item_ttps(item_b))

        # IOC overlap
        ioc_sim = _jaccard(_item_iocs(item_a), _item_iocs(item_b))

        # Temporal proximity — exponential decay over MAX_TEMPORAL_HOURS
        dt_a = _item_date(item_a)
        dt_b = _item_date(item_b)
        if dt_a and dt_b:
            hours_diff = abs((dt_a - dt_b).total_seconds()) / 3600.0
            temporal_sim = math.exp(-hours_diff / (MAX_TEMPORAL_HOURS / 3.0))
        else:
            temporal_sim = 0.50  # unknown → neutral

        # Actor similarity
        actor_a = _item_actor(item_a)
        actor_b = _item_actor(item_b)
        if actor_a == actor_b and actor_a not in ("unknown", ""):
            actor_sim = 1.0
        elif actor_a != "unknown" and actor_b != "unknown":
            # Partial match (e.g. "apt28" vs "apt28-subgroup")
            actor_sim = 0.60 if (actor_a in actor_b or actor_b in actor_a) else 0.0
        else:
            actor_sim = 0.25  # unknown actor → weak link

        # Keyword overlap
        kw_sim = _jaccard(_item_keywords(item_a), _item_keywords(item_b))

        score = (
            W_TTP * ttp_sim
            + W_IOC * ioc_sim
            + W_TEMPORAL * temporal_sim
            + W_ACTOR * actor_sim
            + W_KEYWORD * kw_sim
        )
        return round(min(1.0, max(0.0, score)), 6)

    # ── clustering core ───────────────────────────────────────────────────────

    def _build_distance_matrix(self, items: List[dict]) -> np.ndarray:
        n = len(items)
        dist = np.zeros((n, n), dtype=np.float64)
        for i in range(n):
            for j in range(i + 1, n):
                sim = self.compute_similarity(items[i], items[j])
                d = 1.0 - sim
                dist[i, j] = d
                dist[j, i] = d
        return dist

    def cluster(self, items: List[dict]) -> List[dict]:
        """
        DBSCAN clustering on pairwise similarity matrix.
        Returns list of campaign dicts.
        """
        if not items:
            return []

        if len(items) == 1:
            return [self._make_campaign([items[0]], campaign_index=0)]

        try:
            from sklearn.cluster import DBSCAN
        except ImportError as exc:
            logger.error("scikit-learn not available: %s", exc)
            return [self._make_campaign(items, campaign_index=0)]

        dist_matrix = self._build_distance_matrix(items)

        with self._lock:
            db = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES, metric="precomputed")
            labels = db.fit_predict(dist_matrix)

        campaigns: List[dict] = []
        label_to_indices: Dict[int, List[int]] = defaultdict(list)
        for idx, lbl in enumerate(labels):
            label_to_indices[lbl].append(idx)

        for lbl, indices in sorted(label_to_indices.items()):
            cluster_items = [items[i] for i in indices]
            if lbl == -1:
                # Noise — each item gets its own singleton campaign
                for i, singleton in enumerate(cluster_items):
                    camp = self._make_campaign([singleton], campaign_index=len(campaigns))
                    camp["is_singleton"] = True
                    campaigns.append(camp)
            else:
                camp = self._make_campaign(cluster_items, campaign_index=lbl)
                campaigns.append(camp)

        with self._lock:
            self._total_clustered += len(items)
            self._total_campaigns += len([c for c in campaigns if not c.get("is_singleton")])

        logger.info("cluster(): %d items → %d campaigns (%d singletons)",
                    len(items),
                    sum(1 for c in campaigns if not c.get("is_singleton")),
                    sum(1 for c in campaigns if c.get("is_singleton")))
        return campaigns

    # ── campaign construction ─────────────────────────────────────────────────

    def _make_campaign(self, items: List[dict], campaign_index: int) -> dict:
        """Build a campaign dict from a cluster of items."""
        all_ttps: Counter = Counter()
        all_iocs: Counter = Counter()
        actors: Counter = Counter()
        sectors: Counter = Counter()
        severities = []
        dates = []

        for item in items:
            for t in _item_ttps(item):
                all_ttps[t] += 1
            for i in _item_iocs(item):
                all_iocs[i] += 1
            actor = _item_actor(item)
            if actor not in ("unknown", ""):
                actors[actor] += 1
            sector = _item_sector(item)
            if sector not in ("unknown", ""):
                sectors[sector] += 1
            severities.append(_severity_int(item))
            dt = _item_date(item)
            if dt:
                dates.append(dt)

        # Centroid item = most connected (highest avg similarity to others)
        centroid_item = items[0]
        if len(items) > 2:
            avg_sims = []
            for i, item_i in enumerate(items):
                sims = [self.compute_similarity(item_i, item_j)
                        for j, item_j in enumerate(items) if i != j]
                avg_sims.append(np.mean(sims) if sims else 0.0)
            centroid_item = items[int(np.argmax(avg_sims))]

        common_ttps = [t for t, _ in all_ttps.most_common(10)]
        shared_iocs = [i for i, cnt in all_iocs.items() if cnt >= max(1, len(items) // 2)]
        actor_hypothesis = actors.most_common(1)[0][0] if actors else "unknown"
        primary_sector = sectors.most_common(1)[0][0] if sectors else "unknown"
        threat_level_int = max(severities) if severities else 1
        threat_level = THREAT_LEVEL_MAP.get(threat_level_int, "medium")
        confidence = min(0.95, 0.40 + 0.10 * min(len(items), 6))

        start_date = min(dates).isoformat() if dates else None
        end_date = max(dates).isoformat() if dates else None

        # Stable campaign_id from content fingerprint
        fingerprint = json.dumps({
            "ttps": common_ttps[:5],
            "actor": actor_hypothesis,
            "sector": primary_sector,
            "index": campaign_index,
        }, sort_keys=True)
        campaign_id = "CAMP-" + _stable_id(fingerprint)

        camp: dict = {
            "campaign_id": campaign_id,
            "items": items,
            "item_count": len(items),
            "centroid_item": centroid_item,
            "common_ttps": common_ttps,
            "shared_iocs": shared_iocs,
            "actor_hypothesis": actor_hypothesis,
            "primary_sector": primary_sector,
            "confidence": round(confidence, 4),
            "start_date": start_date,
            "end_date": end_date,
            "threat_level": threat_level,
            "threat_level_int": threat_level_int,
            "is_singleton": False,
        }
        camp["campaign_name"] = self.name_campaign(camp)
        return camp

    # ── naming ────────────────────────────────────────────────────────────────

    def name_campaign(self, cluster: dict) -> str:
        """Generate a human-readable campaign name from cluster characteristics."""
        actor = str(cluster.get("actor_hypothesis", "")).upper()
        sector = cluster.get("primary_sector", "")
        ttps = cluster.get("common_ttps", [])
        threat_level = str(cluster.get("threat_level", "medium")).upper()
        now_ym = datetime.now(tz=timezone.utc).strftime("%Y-%m")

        # Pick tactic word from actor
        tactic = "PHANTOM"
        for t in _TACTICS:
            if t[:3].lower() in actor.lower():
                tactic = t
                break
        else:
            # Hash-based deterministic pick
            h = int(_stable_id(actor + "".join(ttps[:2])), 16)
            tactic = _TACTICS[h % len(_TACTICS)]

        # Pick theme from TTPs
        theme = "EXPLOIT"
        ttp_str = " ".join(ttps).upper()
        if "T1486" in ttp_str or "RANSOM" in ttp_str:
            theme = "RANSOM"
        elif "T1041" in ttp_str or "EXFIL" in ttp_str or "T1048" in ttp_str:
            theme = "EXFIL"
        elif "T1195" in ttp_str or "SUPPLY" in ttp_str:
            theme = "SUPPLY-CHAIN"
        elif "T1059" in ttp_str or "T1204" in ttp_str:
            theme = "EXPLOIT"
        elif "T1071" in ttp_str or "C2" in ttp_str:
            theme = "PERSIST"
        else:
            h2 = int(_stable_id("".join(ttps[:3]) + threat_level), 16)
            theme = _THEMES[h2 % len(_THEMES)]

        # Sector suffix
        sector_tag = _SECTORS.get(sector.lower(), "MULTI")

        return f"{tactic}-{theme}-{sector_tag}-{now_ym}"

    # ── merge ─────────────────────────────────────────────────────────────────

    def merge_clusters(self, cluster_a: dict, cluster_b: dict) -> dict:
        """Merge two campaigns when new linking evidence is found."""
        combined_items = cluster_a.get("items", []) + cluster_b.get("items", [])
        # Rebuild campaign from merged item pool
        merged = self._make_campaign(combined_items, campaign_index=0)
        # Preserve the older campaign_id for traceability
        merged["campaign_id"] = cluster_a["campaign_id"]
        merged["merged_from"] = [cluster_a["campaign_id"], cluster_b["campaign_id"]]
        merged["confidence"] = round(
            min(0.98, (cluster_a.get("confidence", 0.5) + cluster_b.get("confidence", 0.5)) / 2 + 0.05),
            4,
        )
        logger.info("Merged campaigns %s + %s → %s (%d items)",
                    cluster_a["campaign_id"], cluster_b["campaign_id"],
                    merged["campaign_id"], len(combined_items))
        return merged

    # ── find campaign for item ────────────────────────────────────────────────

    def find_campaign_for_item(self, item: dict, existing_campaigns: List[dict]) -> Optional[str]:
        """
        Given a new item, find the best-matching existing campaign.
        Returns campaign_id if similarity to campaign centroid exceeds threshold, else None.
        """
        MATCH_THRESHOLD = 0.45
        best_id: Optional[str] = None
        best_score = 0.0

        for camp in existing_campaigns:
            centroid = camp.get("centroid_item")
            if centroid is None:
                items = camp.get("items", [])
                if not items:
                    continue
                centroid = items[0]
            sim = self.compute_similarity(item, centroid)
            # Boost score if IOC overlap with shared_iocs
            shared = set(camp.get("shared_iocs", []))
            item_iocs = _item_iocs(item)
            if shared & item_iocs:
                sim = min(1.0, sim + 0.15)
            if sim > best_score:
                best_score = sim
                best_id = camp["campaign_id"]

        if best_score >= MATCH_THRESHOLD:
            logger.debug("Item matched campaign %s (score=%.4f)", best_id, best_score)
            return best_id
        return None

    # ── incremental evolution ─────────────────────────────────────────────────

    def evolve_campaigns(self, existing: List[dict], new_items: List[dict]) -> List[dict]:
        """
        Incremental update: assign new items to existing campaigns or create new ones.
        Returns updated campaign list.
        """
        campaigns = [dict(c) for c in existing]  # shallow copy for safety
        unassigned = []

        for item in new_items:
            cid = self.find_campaign_for_item(item, campaigns)
            if cid:
                # Append to existing campaign
                for camp in campaigns:
                    if camp["campaign_id"] == cid:
                        camp["items"] = camp.get("items", []) + [item]
                        camp["item_count"] = len(camp["items"])
                        # Refresh campaign metadata
                        refreshed = self._make_campaign(camp["items"], campaign_index=0)
                        refreshed["campaign_id"] = cid
                        camp.update(refreshed)
                        break
            else:
                unassigned.append(item)

        # Cluster unassigned items into new campaigns
        if unassigned:
            new_camps = self.cluster(unassigned)
            campaigns.extend(new_camps)
            logger.info("evolve_campaigns: %d new items → %d assigned, %d new campaigns",
                        len(new_items), len(new_items) - len(unassigned), len(new_camps))

        return campaigns

    # ── STIX export ───────────────────────────────────────────────────────────

    def export_as_stix_campaigns(self, campaigns: List[dict]) -> List[dict]:
        """
        Export each campaign as a STIX 2.1 Campaign object dict.
        Does not require the stix2 library — produces raw dicts.
        """
        stix_objects = []
        for camp in campaigns:
            obj: dict = {
                "type": "campaign",
                "spec_version": "2.1",
                "id": f"campaign--{str(uuid.uuid5(uuid.NAMESPACE_DNS, camp['campaign_id']))}",
                "created": datetime.now(tz=timezone.utc).isoformat(),
                "modified": datetime.now(tz=timezone.utc).isoformat(),
                "name": camp.get("campaign_name", camp["campaign_id"]),
                "description": (
                    f"Threat campaign {camp['campaign_id']} "
                    f"with {camp.get('item_count', 0)} intelligence items. "
                    f"Actor hypothesis: {camp.get('actor_hypothesis', 'unknown')}. "
                    f"Threat level: {camp.get('threat_level', 'unknown')}."
                ),
                "first_seen": camp.get("start_date"),
                "last_seen": camp.get("end_date"),
                "objective": ", ".join(camp.get("common_ttps", [])[:5]),
                "confidence": int(camp.get("confidence", 0.5) * 100),
                "labels": [camp.get("threat_level", "unknown")],
                "x_cdb_campaign_id": camp["campaign_id"],
                "x_cdb_shared_iocs": camp.get("shared_iocs", [])[:20],
                "x_cdb_item_count": camp.get("item_count", 0),
                "x_cdb_primary_sector": camp.get("primary_sector", "unknown"),
            }
            stix_objects.append(obj)
        return stix_objects

    # ── diagnostics ───────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            return {
                "module": "CampaignClusterer",
                "version": "v134.0.0",
                "algorithm": "DBSCAN",
                "dbscan_eps": DBSCAN_EPS,
                "dbscan_min_samples": DBSCAN_MIN_SAMPLES,
                "similarity_weights": {
                    "ttp": W_TTP, "ioc": W_IOC, "temporal": W_TEMPORAL,
                    "actor": W_ACTOR, "keyword": W_KEYWORD,
                },
                "total_items_clustered": self._total_clustered,
                "total_multi_item_campaigns": self._total_campaigns,
            }


# ════════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(name)s | %(levelname)s | %(message)s")
    cc = CampaignClusterer()

    feed = [
        {"id": "1", "ttps": ["T1190", "T1059"], "iocs": ["evil.com", "1.2.3.4"],
         "actor": "APT28", "sector": "healthcare", "severity": "high",
         "disclosure_date": "2026-04-01"},
        {"id": "2", "ttps": ["T1190", "T1059", "T1486"], "iocs": ["evil.com", "5.6.7.8"],
         "actor": "APT28", "sector": "healthcare", "severity": "critical",
         "disclosure_date": "2026-04-02"},
        {"id": "3", "ttps": ["T1195"], "iocs": ["supply.evil.net"],
         "actor": "Lazarus", "sector": "finance", "severity": "high",
         "disclosure_date": "2026-04-10"},
        {"id": "4", "ttps": ["T1041"], "iocs": ["data-exfil.ru"],
         "actor": "unknown", "sector": "energy", "severity": "medium",
         "disclosure_date": "2026-04-12"},
    ]

    campaigns = cc.cluster(feed)
    print(f"Campaigns: {len(campaigns)}")
    for camp in campaigns:
        print(f"  {camp['campaign_id']} | {camp['campaign_name']} | "
              f"items={camp['item_count']} | level={camp['threat_level']}")

    stix = cc.export_as_stix_campaigns(campaigns)
    print(f"STIX objects: {len(stix)}")
    print(json.dumps(cc.stats(), indent=2))
