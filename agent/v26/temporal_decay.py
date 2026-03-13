"""
CYBERDUDEBIVASH® SENTINEL APEX v26.0 - Temporal Decay Engine
==============================================================
Implements time-based relevance decay for threat scores.

Older threats become less relevant over time, allowing SOC teams
to focus on the most current and pressing threats.

Algorithm:
    decayed_score = original_score * decay_factor
    decay_factor = max(MIN_FACTOR, 2^(-age_days / half_life))

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
import math
import json


@dataclass
class TemporalDecayConfig:
    """Configuration for temporal decay calculations"""
    half_life_days: float = 30.0        # Score halves every 30 days
    min_decay_factor: float = 0.3       # Never decay below 30%
    max_age_days: int = 365             # Maximum age considered
    boost_recent_hours: int = 24        # Boost threats < 24h old
    boost_factor: float = 1.1           # 10% boost for recent


class TemporalDecayEngine:
    """
    Temporal Decay Engine for Threat Scoring
    
    Applies time-based decay to threat scores, making older
    threats less prominent in rankings and dashboards.
    """
    
    def __init__(self, config: Optional[TemporalDecayConfig] = None):
        self.config = config or TemporalDecayConfig()
    
    def calculate_decay_factor(
        self,
        threat_timestamp: datetime,
        reference_time: Optional[datetime] = None
    ) -> float:
        """
        Calculate decay factor based on age.
        
        Args:
            threat_timestamp: When the threat was first observed
            reference_time: Current time (defaults to now)
            
        Returns:
            Decay factor between min_decay_factor and 1.0
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        # Ensure both timestamps are timezone-aware
        if threat_timestamp.tzinfo is None:
            threat_timestamp = threat_timestamp.replace(tzinfo=timezone.utc)
        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)
        
        # Calculate age
        age = reference_time - threat_timestamp
        age_days = max(0, age.total_seconds() / 86400)
        
        # Cap at maximum age
        if age_days > self.config.max_age_days:
            return self.config.min_decay_factor
        
        # Boost recent threats
        age_hours = age.total_seconds() / 3600
        if age_hours < self.config.boost_recent_hours:
            return min(1.0, self.config.boost_factor)
        
        # Calculate exponential decay
        # decay = 2^(-age / half_life)
        decay = math.pow(2, -age_days / self.config.half_life_days)
        
        # Apply minimum threshold
        return max(self.config.min_decay_factor, decay)
    
    def apply_decay(
        self,
        original_score: float,
        threat_timestamp: datetime,
        reference_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Apply temporal decay to a threat score.
        
        Args:
            original_score: Original CVSS/risk score
            threat_timestamp: When threat was observed
            reference_time: Current time reference
            
        Returns:
            Dict with decayed_score, decay_factor, age_days
        """
        decay_factor = self.calculate_decay_factor(threat_timestamp, reference_time)
        decayed_score = round(original_score * decay_factor, 2)
        
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        
        age = reference_time - threat_timestamp
        age_days = age.total_seconds() / 86400
        
        return {
            "original_score": original_score,
            "decayed_score": decayed_score,
            "decay_factor": round(decay_factor, 4),
            "age_days": round(age_days, 2),
            "is_recent": age_days < 1,
            "is_stale": age_days > self.config.half_life_days,
            "decay_applied": decay_factor < 1.0,
        }
    
    def rank_by_decayed_score(
        self,
        threats: List[Dict[str, Any]],
        score_key: str = "risk_score",
        timestamp_key: str = "timestamp",
        reference_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Rank threats by their temporally-decayed scores.
        
        Args:
            threats: List of threat dictionaries
            score_key: Key containing the score
            timestamp_key: Key containing the timestamp
            reference_time: Reference time for decay calculation
            
        Returns:
            Threats sorted by decayed score (highest first)
        """
        ranked = []
        
        for threat in threats:
            score = threat.get(score_key, 0)
            ts_raw = threat.get(timestamp_key)
            
            # Parse timestamp
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                except ValueError:
                    ts = datetime.now(timezone.utc)
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                ts = datetime.now(timezone.utc)
            
            decay_result = self.apply_decay(score, ts, reference_time)
            
            ranked.append({
                **threat,
                "_decay_info": decay_result,
                "_effective_score": decay_result["decayed_score"],
            })
        
        # Sort by effective score (descending)
        ranked.sort(key=lambda x: x["_effective_score"], reverse=True)
        
        return ranked
    
    def get_decay_summary(
        self,
        threats: List[Dict[str, Any]],
        timestamp_key: str = "timestamp"
    ) -> Dict[str, Any]:
        """
        Generate summary statistics for decay analysis.
        
        Returns distribution of threats by age and decay status.
        """
        now = datetime.now(timezone.utc)
        
        summary = {
            "total": len(threats),
            "recent_24h": 0,
            "recent_7d": 0,
            "aged_30d_plus": 0,
            "stale_90d_plus": 0,
            "avg_age_days": 0,
            "avg_decay_factor": 0,
        }
        
        total_age = 0
        total_decay = 0
        
        for threat in threats:
            ts_raw = threat.get(timestamp_key)
            
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                except ValueError:
                    continue
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                continue
            
            age = now - ts
            age_days = age.total_seconds() / 86400
            decay_factor = self.calculate_decay_factor(ts, now)
            
            total_age += age_days
            total_decay += decay_factor
            
            if age_days < 1:
                summary["recent_24h"] += 1
            if age_days < 7:
                summary["recent_7d"] += 1
            if age_days >= 30:
                summary["aged_30d_plus"] += 1
            if age_days >= 90:
                summary["stale_90d_plus"] += 1
        
        if len(threats) > 0:
            summary["avg_age_days"] = round(total_age / len(threats), 2)
            summary["avg_decay_factor"] = round(total_decay / len(threats), 4)
        
        return summary


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON INSTANCE
# ══════════════════════════════════════════════════════════════════════════════
_engine: Optional[TemporalDecayEngine] = None


def get_decay_engine() -> TemporalDecayEngine:
    """Get or create the global temporal decay engine"""
    global _engine
    if _engine is None:
        _engine = TemporalDecayEngine()
    return _engine


def apply_temporal_decay(
    score: float,
    timestamp: datetime,
    reference: Optional[datetime] = None
) -> Dict[str, Any]:
    """Convenience function to apply decay"""
    return get_decay_engine().apply_decay(score, timestamp, reference)


# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS
# ══════════════════════════════════════════════════════════════════════════════
__all__ = [
    "TemporalDecayEngine",
    "TemporalDecayConfig",
    "get_decay_engine",
    "apply_temporal_decay",
]
