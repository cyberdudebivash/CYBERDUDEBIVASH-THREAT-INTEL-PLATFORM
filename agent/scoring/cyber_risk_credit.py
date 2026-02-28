"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
Cyber-Risk Credit Score Engine
==============================

FICO-like Credit Scoring for Cybersecurity Posture

Features:
- 300-850 score range (FICO-aligned)
- Multi-dimensional risk analysis
- Temporal decay modeling
- Asset-context weighting
- Industry benchmarking
- Momentum tracking

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from datetime import datetime, timedelta
import math
import hashlib
import json

# =============================================================================
# ENUMS & TYPES
# =============================================================================

class CreditTier(Enum):
    """Credit Score Tiers"""
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"
    CRITICAL = "CRITICAL"


class RiskLevel(Enum):
    """Associated Risk Levels"""
    MINIMAL = "MINIMAL"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrendDirection(Enum):
    """Score Trend Direction"""
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DECLINING = "DECLINING"
    VOLATILE = "VOLATILE"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AssetContext:
    """Asset Context for Score Calculation"""
    asset_id: str
    asset_type: str = "endpoint"
    criticality: str = "medium"  # crown_jewel, critical, high, medium, low
    data_classification: str = "internal"  # top_secret, secret, confidential, internal, public
    exposure_zone: str = "internal"  # internet_facing, dmz, internal, restricted, air_gapped
    compliance_scope: List[str] = field(default_factory=list)
    business_unit: str = "default"
    owner: str = ""


@dataclass
class VulnerabilityData:
    """Vulnerability Data for Scoring"""
    cve_id: str
    cvss_score: float
    epss_score: float = 0.0
    kev_listed: bool = False
    published_date: Optional[datetime] = None
    remediation_status: str = "open"  # open, in_progress, mitigated, accepted
    affected_assets: int = 1


@dataclass
class HistoricalIncident:
    """Historical Incident Data"""
    incident_id: str
    incident_type: str  # breach, malware, phishing, dos, insider
    severity: str  # critical, high, medium, low
    occurred_date: datetime
    resolved_date: Optional[datetime] = None
    root_cause: str = ""
    impact_score: float = 0.0


@dataclass
class CreditScoreResult:
    """Complete Credit Score Result"""
    # Core Score
    score: int
    tier: CreditTier
    risk_level: RiskLevel
    
    # Factor Breakdown
    exposure_score: float
    velocity_score: float
    impact_score: float
    resilience_score: float
    historical_score: float
    
    # Context
    asset_context: Optional[AssetContext]
    industry_benchmark: int
    industry_delta: int
    
    # Trends
    trend_direction: TrendDirection
    momentum: float  # -100 to +100
    score_7d_change: int
    score_30d_change: int
    
    # Recommendations
    primary_risk_factor: str
    remediation_uplift: int  # Potential score improvement
    top_actions: List[Dict[str, Any]]
    
    # Metadata
    calculation_timestamp: str
    confidence_level: float
    data_quality_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "tier": self.tier.value,
            "risk_level": self.risk_level.value,
            "factors": {
                "exposure": round(self.exposure_score, 2),
                "velocity": round(self.velocity_score, 2),
                "impact": round(self.impact_score, 2),
                "resilience": round(self.resilience_score, 2),
                "historical": round(self.historical_score, 2),
            },
            "benchmarking": {
                "industry_benchmark": self.industry_benchmark,
                "industry_delta": self.industry_delta,
                "position": "ABOVE" if self.industry_delta > 0 else "BELOW" if self.industry_delta < 0 else "AT",
            },
            "trends": {
                "direction": self.trend_direction.value,
                "momentum": round(self.momentum, 1),
                "change_7d": self.score_7d_change,
                "change_30d": self.score_30d_change,
            },
            "recommendations": {
                "primary_risk_factor": self.primary_risk_factor,
                "remediation_uplift": self.remediation_uplift,
                "top_actions": self.top_actions,
            },
            "metadata": {
                "timestamp": self.calculation_timestamp,
                "confidence": round(self.confidence_level, 2),
                "data_quality": round(self.data_quality_score, 2),
            },
        }


# =============================================================================
# CREDIT SCORE ENGINE
# =============================================================================

class CyberRiskCreditEngine:
    """
    Enterprise Cyber-Risk Credit Score Engine
    
    Calculates FICO-like credit scores (300-850) based on:
    - Exposure Factor (30%): Current vulnerability exposure
    - Velocity Factor (20%): Rate of vulnerability accumulation
    - Impact Factor (25%): Potential business impact
    - Resilience Factor (15%): Recovery and patch velocity
    - Historical Factor (10%): Past incident history
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Credit Score Engine"""
        self.config = config or self._default_config()
        self.min_score = self.config.get("min_score", 300)
        self.max_score = self.config.get("max_score", 850)
        self.score_range = self.max_score - self.min_score
        
        # Factor Weights
        self.weights = self.config.get("weights", {
            "exposure_factor": 0.30,
            "velocity_factor": 0.20,
            "impact_factor": 0.25,
            "resilience_factor": 0.15,
            "historical_factor": 0.10,
        })
        
        # Tier Thresholds
        self.tiers = self.config.get("tiers", {
            "EXCELLENT": {"min": 750, "max": 850},
            "GOOD": {"min": 670, "max": 749},
            "FAIR": {"min": 580, "max": 669},
            "POOR": {"min": 450, "max": 579},
            "CRITICAL": {"min": 300, "max": 449},
        })
        
        # Industry Benchmarks
        self.industry_benchmarks = self.config.get("industry_benchmarks", {
            "technology": 680,
            "financial_services": 720,
            "healthcare": 650,
            "retail": 640,
            "manufacturing": 660,
            "government": 700,
            "education": 620,
            "energy": 690,
            "default": 650,
        })
        
        # Decay Settings
        self.decay_half_life = self.config.get("decay_half_life_days", 30)
        
        # Score History (in-memory cache)
        self._score_history: Dict[str, List[Dict[str, Any]]] = {}
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            "min_score": 300,
            "max_score": 850,
            "decay_half_life_days": 30,
            "weights": {
                "exposure_factor": 0.30,
                "velocity_factor": 0.20,
                "impact_factor": 0.25,
                "resilience_factor": 0.15,
                "historical_factor": 0.10,
            },
        }
    
    # =========================================================================
    # FACTOR CALCULATIONS
    # =========================================================================
    
    def _calculate_exposure_factor(
        self,
        vulnerabilities: List[VulnerabilityData],
        asset_context: Optional[AssetContext] = None
    ) -> float:
        """
        Calculate Exposure Factor (0-1, where 1 is best)
        
        Based on current vulnerability exposure weighted by severity,
        EPSS scores, and KEV status.
        """
        if not vulnerabilities:
            return 1.0  # No vulnerabilities = perfect exposure score
        
        # Calculate weighted vulnerability score
        total_weight = 0.0
        weighted_risk = 0.0
        
        for vuln in vulnerabilities:
            if vuln.remediation_status in ("mitigated", "accepted"):
                continue  # Skip remediated vulns
            
            # Base weight from CVSS
            weight = vuln.cvss_score / 10.0
            
            # EPSS multiplier
            epss_multiplier = 1.0 + (vuln.epss_score * 2.0)
            
            # KEV multiplier
            kev_multiplier = 2.0 if vuln.kev_listed else 1.0
            
            # Age decay
            age_multiplier = 1.0
            if vuln.published_date:
                days_old = (datetime.utcnow() - vuln.published_date).days
                age_multiplier = self._apply_decay(days_old)
            
            # Asset count impact
            asset_multiplier = min(math.log2(vuln.affected_assets + 1) / 5.0, 2.0)
            
            risk = weight * epss_multiplier * kev_multiplier * age_multiplier * asset_multiplier
            weighted_risk += risk
            total_weight += 1.0
        
        if total_weight == 0:
            return 1.0
        
        # Normalize to 0-1 range (inverse - higher risk = lower score)
        avg_risk = weighted_risk / total_weight
        
        # Apply asset context multipliers
        if asset_context:
            zone_mult = self._get_zone_multiplier(asset_context.exposure_zone)
            crit_mult = self._get_criticality_multiplier(asset_context.criticality)
            avg_risk *= zone_mult * crit_mult
        
        # Convert to score factor (0-1, where 1 is best)
        exposure_factor = max(0.0, 1.0 - (avg_risk / 5.0))
        
        return min(1.0, exposure_factor)
    
    def _calculate_velocity_factor(
        self,
        vulnerabilities: List[VulnerabilityData],
        lookback_days: int = 90
    ) -> float:
        """
        Calculate Velocity Factor (0-1, where 1 is best)
        
        Based on rate of new vulnerability accumulation.
        Faster accumulation = lower score.
        """
        if not vulnerabilities:
            return 1.0
        
        now = datetime.utcnow()
        cutoff = now - timedelta(days=lookback_days)
        
        # Count vulns by time period
        recent_30d = 0
        recent_60d = 0
        recent_90d = 0
        
        for vuln in vulnerabilities:
            if vuln.published_date:
                age = (now - vuln.published_date).days
                if age <= 30:
                    recent_30d += 1
                if age <= 60:
                    recent_60d += 1
                if age <= 90:
                    recent_90d += 1
        
        # Calculate acceleration (is it getting worse?)
        period_1 = recent_30d
        period_2 = recent_60d - recent_30d
        period_3 = recent_90d - recent_60d
        
        # Acceleration factor (-1 to +1)
        if period_2 + period_3 > 0:
            acceleration = (period_1 - period_3) / max(period_2 + period_3, 1)
        else:
            acceleration = 0
        
        # Normalize velocity
        monthly_rate = recent_30d
        
        # Base velocity score
        if monthly_rate == 0:
            velocity_score = 1.0
        elif monthly_rate <= 5:
            velocity_score = 0.9
        elif monthly_rate <= 10:
            velocity_score = 0.7
        elif monthly_rate <= 25:
            velocity_score = 0.5
        elif monthly_rate <= 50:
            velocity_score = 0.3
        else:
            velocity_score = 0.1
        
        # Adjust for acceleration
        velocity_score -= acceleration * 0.1
        
        return max(0.0, min(1.0, velocity_score))
    
    def _calculate_impact_factor(
        self,
        vulnerabilities: List[VulnerabilityData],
        asset_context: Optional[AssetContext] = None
    ) -> float:
        """
        Calculate Impact Factor (0-1, where 1 is best)
        
        Based on potential business impact of current exposures.
        """
        if not vulnerabilities:
            return 1.0
        
        # Get critical/high vulns affecting crown jewels
        critical_exposure = 0.0
        
        for vuln in vulnerabilities:
            if vuln.remediation_status in ("mitigated", "accepted"):
                continue
            
            if vuln.cvss_score >= 9.0:
                critical_exposure += 3.0
            elif vuln.cvss_score >= 7.0:
                critical_exposure += 2.0
            elif vuln.cvss_score >= 4.0:
                critical_exposure += 1.0
            
            if vuln.kev_listed:
                critical_exposure += 2.0
        
        # Apply asset context
        if asset_context:
            data_mult = self._get_data_classification_multiplier(
                asset_context.data_classification
            )
            critical_exposure *= data_mult
            
            # Compliance impact
            compliance_mult = self._get_compliance_multiplier(
                asset_context.compliance_scope
            )
            critical_exposure *= compliance_mult
        
        # Normalize to 0-1 (inverse)
        impact_score = max(0.0, 1.0 - (critical_exposure / 50.0))
        
        return min(1.0, impact_score)
    
    def _calculate_resilience_factor(
        self,
        vulnerabilities: List[VulnerabilityData],
        mttr_hours: Optional[float] = None
    ) -> float:
        """
        Calculate Resilience Factor (0-1, where 1 is best)
        
        Based on remediation velocity and patch adoption rate.
        """
        if not vulnerabilities:
            return 0.8  # Baseline if no data
        
        # Calculate remediation rate
        total_vulns = len(vulnerabilities)
        remediated = sum(
            1 for v in vulnerabilities
            if v.remediation_status in ("mitigated", "accepted")
        )
        
        remediation_rate = remediated / total_vulns if total_vulns > 0 else 0
        
        # Factor in MTTR
        mttr_factor = 1.0
        if mttr_hours is not None:
            if mttr_hours <= 24:
                mttr_factor = 1.0
            elif mttr_hours <= 72:
                mttr_factor = 0.9
            elif mttr_hours <= 168:
                mttr_factor = 0.7
            elif mttr_hours <= 720:
                mttr_factor = 0.5
            else:
                mttr_factor = 0.3
        
        # Calculate age of open vulns (penalty for old unpatched vulns)
        old_vuln_penalty = 0.0
        for vuln in vulnerabilities:
            if vuln.remediation_status == "open" and vuln.published_date:
                age_days = (datetime.utcnow() - vuln.published_date).days
                if age_days > 90:
                    old_vuln_penalty += 0.05
                elif age_days > 30:
                    old_vuln_penalty += 0.02
        
        resilience_score = (remediation_rate * 0.6 + mttr_factor * 0.4) - old_vuln_penalty
        
        return max(0.0, min(1.0, resilience_score))
    
    def _calculate_historical_factor(
        self,
        incidents: List[HistoricalIncident],
        lookback_years: int = 3
    ) -> float:
        """
        Calculate Historical Factor (0-1, where 1 is best)
        
        Based on past incident history with time decay.
        """
        if not incidents:
            return 0.9  # Good score if no incidents
        
        now = datetime.utcnow()
        cutoff = now - timedelta(days=lookback_years * 365)
        
        # Filter to lookback period
        relevant_incidents = [
            inc for inc in incidents
            if inc.occurred_date >= cutoff
        ]
        
        if not relevant_incidents:
            return 0.9
        
        # Calculate weighted incident score
        incident_score = 0.0
        
        severity_weights = {
            "critical": 5.0,
            "high": 3.0,
            "medium": 1.5,
            "low": 0.5,
        }
        
        type_weights = {
            "breach": 2.0,
            "malware": 1.5,
            "phishing": 1.0,
            "dos": 1.2,
            "insider": 1.8,
        }
        
        for incident in relevant_incidents:
            # Base weight
            weight = severity_weights.get(incident.severity, 1.0)
            weight *= type_weights.get(incident.incident_type, 1.0)
            
            # Time decay
            days_ago = (now - incident.occurred_date).days
            decay = self._apply_decay(days_ago, half_life=365)
            
            # Resolution bonus
            resolution_factor = 0.7 if incident.resolved_date else 1.0
            
            incident_score += weight * decay * resolution_factor
        
        # Normalize to 0-1 (inverse)
        historical_score = max(0.0, 1.0 - (incident_score / 20.0))
        
        return min(1.0, historical_score)
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _apply_decay(self, days: int, half_life: Optional[int] = None) -> float:
        """Apply exponential decay"""
        half_life = half_life or self.decay_half_life
        return math.exp(-0.693 * days / half_life)
    
    def _get_zone_multiplier(self, zone: str) -> float:
        """Get exposure zone multiplier"""
        multipliers = {
            "internet_facing": 1.8,
            "dmz": 1.4,
            "internal": 1.0,
            "restricted": 0.7,
            "air_gapped": 0.3,
        }
        return multipliers.get(zone, 1.0)
    
    def _get_criticality_multiplier(self, criticality: str) -> float:
        """Get asset criticality multiplier"""
        multipliers = {
            "crown_jewel": 2.0,
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8,
        }
        return multipliers.get(criticality, 1.0)
    
    def _get_data_classification_multiplier(self, classification: str) -> float:
        """Get data classification multiplier"""
        multipliers = {
            "top_secret": 2.5,
            "secret": 2.0,
            "confidential": 1.5,
            "internal": 1.0,
            "public": 0.5,
        }
        return multipliers.get(classification, 1.0)
    
    def _get_compliance_multiplier(self, compliance_scope: List[str]) -> float:
        """Get compliance scope multiplier"""
        if not compliance_scope:
            return 0.8
        
        compliance_weights = {
            "PCI_DSS": 1.4,
            "HIPAA": 1.4,
            "SOX": 1.3,
            "GDPR": 1.2,
            "SOC2": 1.1,
        }
        
        max_weight = max(
            compliance_weights.get(c, 1.0)
            for c in compliance_scope
        )
        return max_weight
    
    def _get_tier(self, score: int) -> CreditTier:
        """Determine credit tier from score"""
        for tier_name, thresholds in self.tiers.items():
            if thresholds["min"] <= score <= thresholds["max"]:
                return CreditTier[tier_name]
        return CreditTier.CRITICAL
    
    def _get_risk_level(self, tier: CreditTier) -> RiskLevel:
        """Map tier to risk level"""
        mapping = {
            CreditTier.EXCELLENT: RiskLevel.MINIMAL,
            CreditTier.GOOD: RiskLevel.LOW,
            CreditTier.FAIR: RiskLevel.MODERATE,
            CreditTier.POOR: RiskLevel.HIGH,
            CreditTier.CRITICAL: RiskLevel.CRITICAL,
        }
        return mapping.get(tier, RiskLevel.CRITICAL)
    
    def _calculate_trend(
        self,
        entity_id: str,
        current_score: int
    ) -> Tuple[TrendDirection, float, int, int]:
        """Calculate score trend and momentum"""
        history = self._score_history.get(entity_id, [])
        
        if len(history) < 2:
            return TrendDirection.STABLE, 0.0, 0, 0
        
        now = datetime.utcnow()
        
        # Get scores from 7 and 30 days ago
        score_7d = None
        score_30d = None
        
        for entry in reversed(history):
            entry_time = datetime.fromisoformat(entry["timestamp"])
            age = (now - entry_time).days
            
            if age >= 7 and score_7d is None:
                score_7d = entry["score"]
            if age >= 30 and score_30d is None:
                score_30d = entry["score"]
                break
        
        score_7d = score_7d or current_score
        score_30d = score_30d or current_score
        
        change_7d = current_score - score_7d
        change_30d = current_score - score_30d
        
        # Calculate momentum (-100 to +100)
        momentum = (change_7d * 2.0) + (change_30d * 1.0)
        momentum = max(-100, min(100, momentum))
        
        # Determine direction
        if abs(change_30d) <= 10:
            if abs(change_7d) > 20:
                direction = TrendDirection.VOLATILE
            else:
                direction = TrendDirection.STABLE
        elif change_30d > 0:
            direction = TrendDirection.IMPROVING
        else:
            direction = TrendDirection.DECLINING
        
        return direction, momentum, change_7d, change_30d
    
    def _identify_primary_risk(
        self,
        factors: Dict[str, float]
    ) -> Tuple[str, int, List[Dict[str, Any]]]:
        """Identify primary risk factor and remediation opportunities"""
        
        # Find lowest scoring factor
        sorted_factors = sorted(factors.items(), key=lambda x: x[1])
        primary_factor = sorted_factors[0][0]
        primary_score = sorted_factors[0][1]
        
        # Calculate remediation uplift potential
        # If we improved the worst factor to average, how much would score improve?
        avg_factor = sum(factors.values()) / len(factors)
        improvement_potential = (avg_factor - primary_score) * self.weights.get(primary_factor, 0.2)
        uplift = int(improvement_potential * self.score_range)
        
        # Generate top actions
        actions = self._generate_remediation_actions(primary_factor, primary_score)
        
        return primary_factor.replace("_", " ").title(), uplift, actions
    
    def _generate_remediation_actions(
        self,
        factor: str,
        score: float
    ) -> List[Dict[str, Any]]:
        """Generate remediation actions based on risk factor"""
        
        actions = []
        
        if factor == "exposure_factor":
            actions = [
                {
                    "action": "Remediate KEV-listed vulnerabilities",
                    "priority": "P0",
                    "estimated_uplift": 15,
                },
                {
                    "action": "Patch critical CVSS 9.0+ vulnerabilities",
                    "priority": "P0",
                    "estimated_uplift": 20,
                },
                {
                    "action": "Address internet-facing asset vulnerabilities",
                    "priority": "P1",
                    "estimated_uplift": 10,
                },
            ]
        elif factor == "velocity_factor":
            actions = [
                {
                    "action": "Implement automated patch management",
                    "priority": "P1",
                    "estimated_uplift": 25,
                },
                {
                    "action": "Reduce vulnerability scan-to-patch cycle time",
                    "priority": "P2",
                    "estimated_uplift": 15,
                },
            ]
        elif factor == "impact_factor":
            actions = [
                {
                    "action": "Segment crown jewel assets",
                    "priority": "P1",
                    "estimated_uplift": 20,
                },
                {
                    "action": "Implement compensating controls",
                    "priority": "P1",
                    "estimated_uplift": 15,
                },
            ]
        elif factor == "resilience_factor":
            actions = [
                {
                    "action": "Reduce Mean Time to Remediate (MTTR)",
                    "priority": "P1",
                    "estimated_uplift": 20,
                },
                {
                    "action": "Clear vulnerability remediation backlog",
                    "priority": "P2",
                    "estimated_uplift": 15,
                },
            ]
        elif factor == "historical_factor":
            actions = [
                {
                    "action": "Conduct root cause analysis on past incidents",
                    "priority": "P2",
                    "estimated_uplift": 10,
                },
                {
                    "action": "Implement lessons-learned controls",
                    "priority": "P2",
                    "estimated_uplift": 15,
                },
            ]
        
        return actions[:3]
    
    def _calculate_data_quality(
        self,
        vulnerabilities: List[VulnerabilityData],
        incidents: List[HistoricalIncident]
    ) -> float:
        """Calculate data quality score"""
        quality = 0.5  # Base
        
        # Vuln data completeness
        if vulnerabilities:
            with_dates = sum(1 for v in vulnerabilities if v.published_date)
            with_epss = sum(1 for v in vulnerabilities if v.epss_score > 0)
            quality += 0.2 * (with_dates / len(vulnerabilities))
            quality += 0.1 * (with_epss / len(vulnerabilities))
        
        # Incident data completeness
        if incidents:
            resolved = sum(1 for i in incidents if i.resolved_date)
            quality += 0.2 * (resolved / len(incidents))
        
        return min(1.0, quality)
    
    # =========================================================================
    # MAIN CALCULATION
    # =========================================================================
    
    def calculate_score(
        self,
        entity_id: str,
        vulnerabilities: List[VulnerabilityData],
        incidents: Optional[List[HistoricalIncident]] = None,
        asset_context: Optional[AssetContext] = None,
        mttr_hours: Optional[float] = None,
        industry: str = "default"
    ) -> CreditScoreResult:
        """
        Calculate comprehensive Cyber-Risk Credit Score
        
        Args:
            entity_id: Unique identifier for the entity (org, asset, etc.)
            vulnerabilities: List of current vulnerabilities
            incidents: Historical incident data
            asset_context: Asset context for weighting
            mttr_hours: Mean Time to Remediate in hours
            industry: Industry for benchmarking
            
        Returns:
            CreditScoreResult with complete analysis
        """
        incidents = incidents or []
        
        # Calculate individual factors
        exposure_score = self._calculate_exposure_factor(vulnerabilities, asset_context)
        velocity_score = self._calculate_velocity_factor(vulnerabilities)
        impact_score = self._calculate_impact_factor(vulnerabilities, asset_context)
        resilience_score = self._calculate_resilience_factor(vulnerabilities, mttr_hours)
        historical_score = self._calculate_historical_factor(incidents)
        
        factors = {
            "exposure_factor": exposure_score,
            "velocity_factor": velocity_score,
            "impact_factor": impact_score,
            "resilience_factor": resilience_score,
            "historical_factor": historical_score,
        }
        
        # Calculate weighted composite score
        weighted_score = sum(
            factors[k] * self.weights[k]
            for k in factors
        )
        
        # Convert to 300-850 range
        raw_score = self.min_score + (weighted_score * self.score_range)
        final_score = int(round(raw_score))
        final_score = max(self.min_score, min(self.max_score, final_score))
        
        # Determine tier and risk level
        tier = self._get_tier(final_score)
        risk_level = self._get_risk_level(tier)
        
        # Get industry benchmark
        benchmark = self.industry_benchmarks.get(industry, self.industry_benchmarks["default"])
        delta = final_score - benchmark
        
        # Calculate trends
        trend, momentum, change_7d, change_30d = self._calculate_trend(entity_id, final_score)
        
        # Identify risks and remediation
        primary_risk, uplift, actions = self._identify_primary_risk(factors)
        
        # Data quality
        data_quality = self._calculate_data_quality(vulnerabilities, incidents)
        
        # Confidence level based on data quality and volume
        confidence = min(1.0, data_quality * (0.5 + 0.5 * min(len(vulnerabilities) / 100, 1.0)))
        
        # Store in history
        self._update_history(entity_id, final_score)
        
        return CreditScoreResult(
            score=final_score,
            tier=tier,
            risk_level=risk_level,
            exposure_score=exposure_score,
            velocity_score=velocity_score,
            impact_score=impact_score,
            resilience_score=resilience_score,
            historical_score=historical_score,
            asset_context=asset_context,
            industry_benchmark=benchmark,
            industry_delta=delta,
            trend_direction=trend,
            momentum=momentum,
            score_7d_change=change_7d,
            score_30d_change=change_30d,
            primary_risk_factor=primary_risk,
            remediation_uplift=uplift,
            top_actions=actions,
            calculation_timestamp=datetime.utcnow().isoformat(),
            confidence_level=confidence,
            data_quality_score=data_quality,
        )
    
    def _update_history(self, entity_id: str, score: int):
        """Update score history for trend tracking"""
        if entity_id not in self._score_history:
            self._score_history[entity_id] = []
        
        self._score_history[entity_id].append({
            "timestamp": datetime.utcnow().isoformat(),
            "score": score,
        })
        
        # Keep last 365 days
        cutoff = datetime.utcnow() - timedelta(days=365)
        self._score_history[entity_id] = [
            entry for entry in self._score_history[entity_id]
            if datetime.fromisoformat(entry["timestamp"]) > cutoff
        ][-365:]  # Max 365 entries
    
    def get_history(
        self,
        entity_id: str,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get score history for an entity"""
        history = self._score_history.get(entity_id, [])
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        return [
            entry for entry in history
            if datetime.fromisoformat(entry["timestamp"]) > cutoff
        ]


# =============================================================================
# FACTORY & EXPORTS
# =============================================================================

# Global engine instance
_credit_engine: Optional[CyberRiskCreditEngine] = None


def get_credit_engine(config: Optional[Dict[str, Any]] = None) -> CyberRiskCreditEngine:
    """Get or create the credit score engine instance"""
    global _credit_engine
    if _credit_engine is None or config is not None:
        _credit_engine = CyberRiskCreditEngine(config)
    return _credit_engine


def calculate_credit_score(
    entity_id: str,
    vulnerabilities: List[Dict[str, Any]],
    incidents: Optional[List[Dict[str, Any]]] = None,
    asset_context: Optional[Dict[str, Any]] = None,
    mttr_hours: Optional[float] = None,
    industry: str = "default"
) -> Dict[str, Any]:
    """
    Convenience function to calculate credit score from dict inputs
    
    Returns dict-formatted result for API responses
    """
    engine = get_credit_engine()
    
    # Convert vuln dicts to dataclass
    vuln_list = [
        VulnerabilityData(
            cve_id=v.get("cve_id", "UNKNOWN"),
            cvss_score=v.get("cvss_score", 0.0),
            epss_score=v.get("epss_score", 0.0),
            kev_listed=v.get("kev_listed", False),
            published_date=datetime.fromisoformat(v["published_date"]) if v.get("published_date") else None,
            remediation_status=v.get("remediation_status", "open"),
            affected_assets=v.get("affected_assets", 1),
        )
        for v in vulnerabilities
    ]
    
    # Convert incident dicts
    incident_list = []
    if incidents:
        incident_list = [
            HistoricalIncident(
                incident_id=i.get("incident_id", ""),
                incident_type=i.get("incident_type", ""),
                severity=i.get("severity", "medium"),
                occurred_date=datetime.fromisoformat(i["occurred_date"]),
                resolved_date=datetime.fromisoformat(i["resolved_date"]) if i.get("resolved_date") else None,
            )
            for i in incidents
        ]
    
    # Convert asset context
    ctx = None
    if asset_context:
        ctx = AssetContext(
            asset_id=asset_context.get("asset_id", "default"),
            asset_type=asset_context.get("asset_type", "endpoint"),
            criticality=asset_context.get("criticality", "medium"),
            data_classification=asset_context.get("data_classification", "internal"),
            exposure_zone=asset_context.get("exposure_zone", "internal"),
            compliance_scope=asset_context.get("compliance_scope", []),
        )
    
    result = engine.calculate_score(
        entity_id=entity_id,
        vulnerabilities=vuln_list,
        incidents=incident_list,
        asset_context=ctx,
        mttr_hours=mttr_hours,
        industry=industry,
    )
    
    return result.to_dict()


# Singleton exports
credit_engine = get_credit_engine()

__all__ = [
    "CyberRiskCreditEngine",
    "CreditScoreResult",
    "VulnerabilityData",
    "HistoricalIncident",
    "AssetContext",
    "CreditTier",
    "RiskLevel",
    "TrendDirection",
    "get_credit_engine",
    "calculate_credit_score",
    "credit_engine",
]
