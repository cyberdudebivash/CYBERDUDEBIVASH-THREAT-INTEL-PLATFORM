#!/usr/bin/env python3
"""
campaign_tracker.py — CyberDudeBivash SENTINEL APEX v17.0
ADVERSARY CAMPAIGN LIFECYCLE TRACKER

Tracks threat actor campaigns across multiple intel items:
  - Links related CVEs/incidents to campaign clusters
  - Detects campaign recurrence (same actor, recurring TTPs)
  - Computes campaign intensity score
  - Maintains campaign timeline for dashboard display

NON-BREAKING: Pure additive layer. Reads existing STIX manifests.
Persists campaign data to data/campaign_tracker.json.
"""

import json
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict

logger = logging.getLogger("CDB-CAMPAIGN-TRACKER")

CAMPAIGN_DB_PATH = "data/campaign_tracker.json"
MANIFEST_PATH = "data/stix/feed_manifest.json"
MAX_CAMPAIGNS = 200  # Rolling history


class CampaignTracker:
    """
    Tracks adversary campaigns across intel items.
    Groups related threats by actor tag and TTP similarity.
    """

    def __init__(self):
        self._campaigns: Dict = {}
        self._load()

    def record_campaign_activity(
        self,
        actor_tag: str,
        headline: str,
        risk_score: float,
        mitre_tactics: List[str],
        cve_ids: List[str],
        bundle_id: str,
        published_at: Optional[str] = None,
    ) -> str:
        """
        Record a new intel item as campaign activity.
        Links it to an existing campaign or creates a new one.

        Returns: campaign_id for this activity.
        """
        campaign_id = self._find_or_create_campaign(actor_tag, mitre_tactics)
        ts = published_at or datetime.now(timezone.utc).isoformat()

        activity = {
            "bundle_id": bundle_id,
            "headline": headline[:120],
            "risk_score": risk_score,
            "tactics": mitre_tactics,
            "cve_ids": cve_ids,
            "recorded_at": ts,
        }

        campaign = self._campaigns[campaign_id]
        campaign["activities"].append(activity)
        campaign["last_seen"] = ts
        campaign["activity_count"] = len(campaign["activities"])

        # Update max risk score seen in campaign
        if risk_score > campaign.get("max_risk_score", 0):
            campaign["max_risk_score"] = risk_score

        # Accumulate all TTPs seen
        for tactic in mitre_tactics:
            if tactic not in campaign.get("all_tactics", []):
                campaign.setdefault("all_tactics", []).append(tactic)

        # Compute intensity score
        campaign["intensity_score"] = self._compute_intensity(campaign)

        self._persist()

        logger.debug(
            f"📌 Campaign activity recorded | "
            f"Campaign: {campaign_id} | Actor: {actor_tag} | "
            f"Activities: {campaign['activity_count']}"
        )

        return campaign_id

    def get_active_campaigns(self, days: int = 30) -> List[Dict]:
        """Return campaigns with activity in the last N days, sorted by intensity."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        active = []
        for campaign_id, campaign in self._campaigns.items():
            last_seen_str = campaign.get("last_seen", "")
            if not last_seen_str:
                continue
            try:
                last_seen = datetime.fromisoformat(
                    last_seen_str.replace("Z", "+00:00")
                )
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                if last_seen >= cutoff:
                    active.append({"campaign_id": campaign_id, **campaign})
            except Exception:
                continue
        return sorted(active, key=lambda x: x.get("intensity_score", 0), reverse=True)

    def get_campaign_summary(self) -> Dict:
        """Return high-level campaign dashboard data."""
        now = datetime.now(timezone.utc)
        active_30d = self.get_active_campaigns(30)
        active_7d = self.get_active_campaigns(7)

        # Actor frequency
        actor_counts: Dict[str, int] = defaultdict(int)
        for c in active_30d:
            actor = c.get("actor_tag", "Unknown")
            actor_counts[actor] += c.get("activity_count", 1)

        top_actors = sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "summary_at": now.isoformat(),
            "total_campaigns_tracked": len(self._campaigns),
            "active_campaigns_30d": len(active_30d),
            "active_campaigns_7d": len(active_7d),
            "top_actors_30d": [
                {"actor": actor, "activity_count": count}
                for actor, count in top_actors
            ],
            "highest_intensity_campaign": (
                active_30d[0].get("campaign_id") if active_30d else None
            ),
        }

    def _find_or_create_campaign(self, actor_tag: str, tactics: List[str]) -> str:
        """
        Find an existing campaign for this actor/tactic combination,
        or create a new campaign cluster.
        """
        # Try to match to an existing open campaign for this actor
        for campaign_id, campaign in self._campaigns.items():
            if campaign.get("actor_tag") != actor_tag:
                continue
            # Check TTP overlap (>= 1 shared tactic = same campaign cluster)
            existing_tactics = set(campaign.get("all_tactics", []))
            new_tactics = set(tactics)
            if existing_tactics & new_tactics:
                # Check recency — don't merge campaigns that are >90 days apart
                last_seen_str = campaign.get("last_seen", "")
                if last_seen_str:
                    try:
                        last_seen = datetime.fromisoformat(
                            last_seen_str.replace("Z", "+00:00")
                        )
                        if last_seen.tzinfo is None:
                            last_seen = last_seen.replace(tzinfo=timezone.utc)
                        if (datetime.now(timezone.utc) - last_seen).days <= 90:
                            return campaign_id
                    except Exception:
                        pass

        # Create new campaign
        campaign_id = f"CDB-CAMP-{int(datetime.now(timezone.utc).timestamp())}-{actor_tag[:8]}"
        self._campaigns[campaign_id] = {
            "campaign_id": campaign_id,
            "actor_tag": actor_tag,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "activities": [],
            "all_tactics": list(tactics),
            "activity_count": 0,
            "max_risk_score": 0.0,
            "intensity_score": 0.0,
        }

        # Prune if over limit
        if len(self._campaigns) > MAX_CAMPAIGNS:
            oldest_key = min(
                self._campaigns.keys(),
                key=lambda k: self._campaigns[k].get("last_seen", "")
            )
            del self._campaigns[oldest_key]

        logger.info(f"🆕 New campaign cluster created: {campaign_id} | Actor: {actor_tag}")
        return campaign_id

    def _compute_intensity(self, campaign: Dict) -> float:
        """
        Compute campaign intensity score (0.0 - 10.0).
        Based on: activity count, max risk score, tactic breadth, recency.
        """
        activity_count = campaign.get("activity_count", 0)
        max_risk = campaign.get("max_risk_score", 0.0)
        tactic_count = len(campaign.get("all_tactics", []))

        # Recency boost
        last_seen_str = campaign.get("last_seen", "")
        recency_boost = 0.0
        if last_seen_str:
            try:
                last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                days_ago = (datetime.now(timezone.utc) - last_seen).days
                if days_ago <= 3:
                    recency_boost = 2.0
                elif days_ago <= 7:
                    recency_boost = 1.0
            except Exception:
                pass

        intensity = (
            min(activity_count * 0.5, 3.0) +  # Up to 3 pts for volume
            max_risk * 0.4 +                   # Up to 4 pts for risk severity
            min(tactic_count * 0.2, 1.5) +     # Up to 1.5 pts for TTP breadth
            recency_boost                       # Up to 2 pts for recency
        )
        return round(min(intensity, 10.0), 2)

    def _load(self):
        if os.path.exists(CAMPAIGN_DB_PATH):
            try:
                with open(CAMPAIGN_DB_PATH, "r") as f:
                    self._campaigns = json.load(f)
            except Exception as e:
                logger.warning(f"Campaign DB load failed: {e}")
                self._campaigns = {}

    def _persist(self):
        try:
            os.makedirs("data", exist_ok=True)
            with open(CAMPAIGN_DB_PATH, "w") as f:
                json.dump(self._campaigns, f, indent=2)
        except Exception as e:
            logger.warning(f"Campaign DB persist failed: {e}")


# Singleton instance
campaign_tracker = CampaignTracker()
