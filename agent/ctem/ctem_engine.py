"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
CTEM Engine
===========

Continuous Threat Exposure Management (CTEM) Engine
Gartner 5-Phase Framework Implementation

Phases:
1. SCOPING - Define attack surface
2. DISCOVERY - Identify exposures  
3. PRIORITIZATION - Risk-based ranking (P0-P4)
4. VALIDATION - Exploitability testing
5. MOBILIZATION - Remediation workflow

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from datetime import datetime, timedelta
import uuid
import hashlib
import json

# =============================================================================
# ENUMS
# =============================================================================

class CTEMPhase(Enum):
    """CTEM Lifecycle Phases"""
    SCOPING = "SCOPING"
    DISCOVERY = "DISCOVERY"
    PRIORITIZATION = "PRIORITIZATION"
    VALIDATION = "VALIDATION"
    MOBILIZATION = "MOBILIZATION"


class ExposureStatus(Enum):
    """Exposure Lifecycle Status"""
    NEW = "NEW"
    CONFIRMED = "CONFIRMED"
    IN_REMEDIATION = "IN_REMEDIATION"
    MITIGATED = "MITIGATED"
    ACCEPTED = "ACCEPTED"
    DEFERRED = "DEFERRED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class RemediationPriority(Enum):
    """Remediation Priority Levels"""
    P0 = "P0"  # Critical - 24 hours
    P1 = "P1"  # High - 72 hours
    P2 = "P2"  # Medium - 7 days
    P3 = "P3"  # Low - 30 days
    P4 = "P4"  # Informational - 90 days


class ValidationResult(Enum):
    """Validation Test Results"""
    NOT_TESTED = "NOT_TESTED"
    EXPLOITABLE = "EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    PARTIALLY_EXPLOITABLE = "PARTIALLY_EXPLOITABLE"
    BLOCKED_BY_CONTROL = "BLOCKED_BY_CONTROL"


class AssetType(Enum):
    """Asset Types for Scoping"""
    ENDPOINT = "ENDPOINT"
    SERVER = "SERVER"
    WEB_APP = "WEB_APP"
    API = "API"
    DATABASE = "DATABASE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    IOT_DEVICE = "IOT_DEVICE"
    CONTAINER = "CONTAINER"
    IDENTITY = "IDENTITY"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CTEMScope:
    """CTEM Scope Definition"""
    scope_id: str
    name: str
    description: str = ""
    
    # Asset targeting
    asset_types: List[AssetType] = field(default_factory=list)
    asset_tags: List[str] = field(default_factory=list)
    business_units: List[str] = field(default_factory=list)
    
    # Compliance focus
    compliance_frameworks: List[str] = field(default_factory=list)
    
    # Risk parameters
    criticality_threshold: str = "medium"  # low, medium, high, critical
    exposure_zones: List[str] = field(default_factory=lambda: ["internet_facing", "dmz"])
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    owner: str = ""
    active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "name": self.name,
            "description": self.description,
            "asset_types": [at.value for at in self.asset_types],
            "asset_tags": self.asset_tags,
            "business_units": self.business_units,
            "compliance_frameworks": self.compliance_frameworks,
            "criticality_threshold": self.criticality_threshold,
            "exposure_zones": self.exposure_zones,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "owner": self.owner,
            "active": self.active,
        }


@dataclass
class Exposure:
    """Individual Exposure Record"""
    exposure_id: str
    scope_id: str
    
    # Exposure details
    exposure_type: str  # vulnerability, misconfiguration, credential, certificate, etc.
    title: str
    description: str = ""
    
    # Technical details
    cve_id: Optional[str] = None
    cwes: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    epss_score: float = 0.0
    kev_listed: bool = False
    
    # Asset info
    affected_assets: List[str] = field(default_factory=list)
    asset_count: int = 1
    
    # Risk scoring
    risk_score: float = 0.0
    priority: RemediationPriority = RemediationPriority.P3
    
    # Status tracking
    status: ExposureStatus = ExposureStatus.NEW
    validation_result: ValidationResult = ValidationResult.NOT_TESTED
    
    # Dates
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    sla_deadline: Optional[str] = None
    resolved_at: Optional[str] = None
    
    # Assignment
    assignee: str = ""
    team: str = ""
    
    # Remediation
    remediation_notes: str = ""
    compensating_controls: List[str] = field(default_factory=list)
    
    # MITRE mapping
    mitre_techniques: List[str] = field(default_factory=list)
    kill_chain_phase: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "exposure_id": self.exposure_id,
            "scope_id": self.scope_id,
            "exposure_type": self.exposure_type,
            "title": self.title,
            "description": self.description,
            "technical": {
                "cve_id": self.cve_id,
                "cwes": self.cwes,
                "cvss_score": self.cvss_score,
                "cvss_vector": self.cvss_vector,
                "epss_score": self.epss_score,
                "kev_listed": self.kev_listed,
            },
            "assets": {
                "affected": self.affected_assets[:10],  # Truncate for response
                "count": self.asset_count,
            },
            "risk": {
                "score": round(self.risk_score, 2),
                "priority": self.priority.value,
            },
            "status": self.status.value,
            "validation": self.validation_result.value,
            "dates": {
                "discovered": self.discovered_at,
                "sla_deadline": self.sla_deadline,
                "resolved": self.resolved_at,
            },
            "assignment": {
                "assignee": self.assignee,
                "team": self.team,
            },
            "mitre": {
                "techniques": self.mitre_techniques,
                "kill_chain_phase": self.kill_chain_phase,
            },
        }


@dataclass
class RemediationTask:
    """Remediation Task"""
    task_id: str
    exposure_id: str
    
    # Task details
    title: str
    description: str = ""
    task_type: str = "patch"  # patch, config, code_fix, compensating_control
    
    # Status
    status: str = "pending"  # pending, in_progress, completed, blocked, deferred
    
    # Assignment
    assignee: str = ""
    team: str = ""
    
    # Timeline
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    due_date: Optional[str] = None
    
    # Effort
    estimated_hours: float = 0.0
    actual_hours: float = 0.0
    
    # Verification
    requires_verification: bool = True
    verified: bool = False
    verified_by: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "exposure_id": self.exposure_id,
            "title": self.title,
            "description": self.description,
            "task_type": self.task_type,
            "status": self.status,
            "assignment": {
                "assignee": self.assignee,
                "team": self.team,
            },
            "timeline": {
                "created": self.created_at,
                "started": self.started_at,
                "completed": self.completed_at,
                "due": self.due_date,
            },
            "effort": {
                "estimated_hours": self.estimated_hours,
                "actual_hours": self.actual_hours,
            },
            "verification": {
                "required": self.requires_verification,
                "verified": self.verified,
                "verified_by": self.verified_by,
            },
        }


@dataclass
class CTEMMetrics:
    """CTEM Performance Metrics"""
    # Discovery Metrics
    total_exposures: int = 0
    new_exposures_24h: int = 0
    new_exposures_7d: int = 0
    new_exposures_30d: int = 0
    
    # Priority Distribution
    p0_count: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0
    p4_count: int = 0
    
    # Status Distribution
    open_exposures: int = 0
    in_remediation: int = 0
    mitigated: int = 0
    accepted: int = 0
    
    # SLA Metrics
    sla_compliance_rate: float = 0.0
    breached_slas: int = 0
    at_risk_slas: int = 0
    
    # Performance Metrics
    mttd_hours: float = 0.0  # Mean Time to Detect
    mttr_hours: float = 0.0  # Mean Time to Remediate
    remediation_velocity: float = 0.0  # Exposures closed per day
    
    # Risk Metrics
    total_risk_score: float = 0.0
    average_risk_score: float = 0.0
    risk_reduction_30d: float = 0.0
    
    # Backlog
    backlog_age_p95: float = 0.0  # 95th percentile age in days
    overdue_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "discovery": {
                "total": self.total_exposures,
                "new_24h": self.new_exposures_24h,
                "new_7d": self.new_exposures_7d,
                "new_30d": self.new_exposures_30d,
            },
            "priority_distribution": {
                "P0": self.p0_count,
                "P1": self.p1_count,
                "P2": self.p2_count,
                "P3": self.p3_count,
                "P4": self.p4_count,
            },
            "status_distribution": {
                "open": self.open_exposures,
                "in_remediation": self.in_remediation,
                "mitigated": self.mitigated,
                "accepted": self.accepted,
            },
            "sla": {
                "compliance_rate": round(self.sla_compliance_rate * 100, 1),
                "breached": self.breached_slas,
                "at_risk": self.at_risk_slas,
            },
            "performance": {
                "mttd_hours": round(self.mttd_hours, 1),
                "mttr_hours": round(self.mttr_hours, 1),
                "remediation_velocity": round(self.remediation_velocity, 2),
            },
            "risk": {
                "total_score": round(self.total_risk_score, 1),
                "average_score": round(self.average_risk_score, 2),
                "reduction_30d_percent": round(self.risk_reduction_30d * 100, 1),
            },
            "backlog": {
                "age_p95_days": round(self.backlog_age_p95, 1),
                "overdue": self.overdue_count,
            },
        }


# =============================================================================
# CTEM ENGINE
# =============================================================================

class CTEMEngine:
    """
    Continuous Threat Exposure Management Engine
    
    Implements the Gartner CTEM 5-phase framework:
    1. Scoping - Define what's in scope
    2. Discovery - Find exposures
    3. Prioritization - Risk-based ranking
    4. Validation - Test exploitability
    5. Mobilization - Remediation workflow
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        
        # SLA definitions (hours)
        self.sla_hours = self.config.get("sla_hours", {
            "P0": 24,
            "P1": 72,
            "P2": 168,    # 7 days
            "P3": 720,    # 30 days
            "P4": 2160,   # 90 days
        })
        
        # Priority calculation thresholds
        self.priority_thresholds = self.config.get("priority_thresholds", {
            "P0": {"cvss_min": 9.0, "epss_min": 0.7, "kev": True},
            "P1": {"cvss_min": 7.0, "epss_min": 0.4},
            "P2": {"cvss_min": 4.0, "epss_min": 0.1},
            "P3": {"cvss_min": 0.1, "epss_min": 0.01},
            "P4": {"cvss_min": 0.0, "epss_min": 0.0},
        })
        
        # Compliance weights
        self.compliance_weights = self.config.get("compliance_weights", {
            "PCI_DSS": 1.4,
            "HIPAA": 1.4,
            "SOX": 1.3,
            "GDPR": 1.2,
            "SOC2": 1.1,
            "ISO27001": 1.1,
            "NIST_CSF": 1.0,
        })
        
        # Data stores (in-memory for now)
        self._scopes: Dict[str, CTEMScope] = {}
        self._exposures: Dict[str, Exposure] = {}
        self._tasks: Dict[str, RemediationTask] = {}
        self._metrics_history: List[Dict[str, Any]] = []
    
    def _default_config(self) -> Dict[str, Any]:
        return {
            "sla_hours": {
                "P0": 24,
                "P1": 72,
                "P2": 168,
                "P3": 720,
                "P4": 2160,
            },
        }
    
    # =========================================================================
    # PHASE 1: SCOPING
    # =========================================================================
    
    def create_scope(
        self,
        name: str,
        asset_types: Optional[List[str]] = None,
        business_units: Optional[List[str]] = None,
        compliance_frameworks: Optional[List[str]] = None,
        exposure_zones: Optional[List[str]] = None,
        **kwargs
    ) -> CTEMScope:
        """
        Create a new CTEM scope
        
        Args:
            name: Scope name
            asset_types: Types of assets to include
            business_units: Business units to scope
            compliance_frameworks: Compliance frameworks in scope
            exposure_zones: Network zones to focus on
            
        Returns:
            CTEMScope object
        """
        scope_id = f"scope-{uuid.uuid4().hex[:12]}"
        
        # Convert string asset types to enum
        asset_type_enums = []
        if asset_types:
            for at in asset_types:
                try:
                    asset_type_enums.append(AssetType[at.upper()])
                except KeyError:
                    pass
        
        scope = CTEMScope(
            scope_id=scope_id,
            name=name,
            asset_types=asset_type_enums or [AssetType.ENDPOINT, AssetType.SERVER],
            business_units=business_units or [],
            compliance_frameworks=compliance_frameworks or [],
            exposure_zones=exposure_zones or ["internet_facing", "dmz"],
            description=kwargs.get("description", ""),
            owner=kwargs.get("owner", ""),
        )
        
        self._scopes[scope_id] = scope
        return scope
    
    def get_scope(self, scope_id: str) -> Optional[CTEMScope]:
        """Get scope by ID"""
        return self._scopes.get(scope_id)
    
    def list_scopes(self, active_only: bool = True) -> List[CTEMScope]:
        """List all scopes"""
        scopes = list(self._scopes.values())
        if active_only:
            scopes = [s for s in scopes if s.active]
        return scopes
    
    # =========================================================================
    # PHASE 2: DISCOVERY
    # =========================================================================
    
    def discover_exposure(
        self,
        scope_id: str,
        exposure_type: str,
        title: str,
        cvss_score: float = 0.0,
        epss_score: float = 0.0,
        kev_listed: bool = False,
        affected_assets: Optional[List[str]] = None,
        **kwargs
    ) -> Exposure:
        """
        Record a discovered exposure
        
        Args:
            scope_id: Parent scope ID
            exposure_type: Type (vulnerability, misconfiguration, etc.)
            title: Exposure title
            cvss_score: CVSS base score
            epss_score: EPSS probability
            kev_listed: Is it in CISA KEV
            affected_assets: List of affected asset IDs
            
        Returns:
            Exposure object with calculated priority
        """
        exposure_id = f"exp-{uuid.uuid4().hex[:12]}"
        
        exposure = Exposure(
            exposure_id=exposure_id,
            scope_id=scope_id,
            exposure_type=exposure_type,
            title=title,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_listed=kev_listed,
            affected_assets=affected_assets or [],
            asset_count=len(affected_assets) if affected_assets else 1,
            cve_id=kwargs.get("cve_id"),
            description=kwargs.get("description", ""),
            cvss_vector=kwargs.get("cvss_vector", ""),
            cwes=kwargs.get("cwes", []),
            mitre_techniques=kwargs.get("mitre_techniques", []),
            kill_chain_phase=kwargs.get("kill_chain_phase", ""),
        )
        
        # Phase 3: Prioritize
        exposure = self._prioritize_exposure(exposure)
        
        self._exposures[exposure_id] = exposure
        return exposure
    
    def bulk_discover(
        self,
        scope_id: str,
        exposures_data: List[Dict[str, Any]]
    ) -> List[Exposure]:
        """
        Bulk import exposures
        
        Args:
            scope_id: Parent scope ID
            exposures_data: List of exposure dictionaries
            
        Returns:
            List of created Exposure objects
        """
        results = []
        for data in exposures_data:
            exposure = self.discover_exposure(
                scope_id=scope_id,
                exposure_type=data.get("exposure_type", "vulnerability"),
                title=data.get("title", "Unknown"),
                cvss_score=data.get("cvss_score", 0.0),
                epss_score=data.get("epss_score", 0.0),
                kev_listed=data.get("kev_listed", False),
                affected_assets=data.get("affected_assets"),
                **{k: v for k, v in data.items() if k not in [
                    "exposure_type", "title", "cvss_score", "epss_score",
                    "kev_listed", "affected_assets"
                ]}
            )
            results.append(exposure)
        return results
    
    # =========================================================================
    # PHASE 3: PRIORITIZATION
    # =========================================================================
    
    def _prioritize_exposure(self, exposure: Exposure) -> Exposure:
        """
        Calculate priority and risk score for an exposure
        
        Uses CVSS, EPSS, KEV, and contextual factors
        """
        # Calculate base risk score
        risk_score = self._calculate_risk_score(exposure)
        exposure.risk_score = risk_score
        
        # Determine priority
        priority = self._determine_priority(exposure)
        exposure.priority = priority
        
        # Set SLA deadline
        sla_hours = self.sla_hours.get(priority.value, 720)
        deadline = datetime.utcnow() + timedelta(hours=sla_hours)
        exposure.sla_deadline = deadline.isoformat()
        
        return exposure
    
    def _calculate_risk_score(self, exposure: Exposure) -> float:
        """Calculate composite risk score (0-10)"""
        # Base from CVSS
        cvss_component = exposure.cvss_score * 0.4
        
        # EPSS component (scaled to 0-10)
        epss_component = (exposure.epss_score * 10) * 0.3
        
        # KEV boost
        kev_component = 3.0 if exposure.kev_listed else 0.0
        kev_weight = 0.2
        
        # Asset count impact
        asset_multiplier = min(1.0 + (exposure.asset_count / 100), 2.0)
        asset_weight = 0.1
        
        # Calculate score
        base_score = (
            cvss_component +
            epss_component +
            (kev_component * kev_weight) +
            (asset_multiplier * asset_weight * 10)
        )
        
        # Compliance multiplier
        scope = self._scopes.get(exposure.scope_id)
        if scope and scope.compliance_frameworks:
            max_compliance_weight = max(
                self.compliance_weights.get(f, 1.0)
                for f in scope.compliance_frameworks
            )
            base_score *= max_compliance_weight
        
        return min(10.0, max(0.0, base_score))
    
    def _determine_priority(self, exposure: Exposure) -> RemediationPriority:
        """Determine remediation priority based on thresholds"""
        cvss = exposure.cvss_score
        epss = exposure.epss_score
        kev = exposure.kev_listed
        
        # P0: Critical
        p0_thresh = self.priority_thresholds["P0"]
        if kev or (cvss >= p0_thresh["cvss_min"] and epss >= p0_thresh["epss_min"]):
            return RemediationPriority.P0
        
        # P1: High
        p1_thresh = self.priority_thresholds["P1"]
        if cvss >= p1_thresh["cvss_min"] or epss >= p1_thresh["epss_min"]:
            return RemediationPriority.P1
        
        # P2: Medium
        p2_thresh = self.priority_thresholds["P2"]
        if cvss >= p2_thresh["cvss_min"] or epss >= p2_thresh["epss_min"]:
            return RemediationPriority.P2
        
        # P3: Low
        p3_thresh = self.priority_thresholds["P3"]
        if cvss >= p3_thresh["cvss_min"]:
            return RemediationPriority.P3
        
        return RemediationPriority.P4
    
    def reprioritize_all(self, scope_id: Optional[str] = None) -> int:
        """
        Recalculate priorities for all exposures
        
        Returns:
            Number of exposures updated
        """
        count = 0
        for exp_id, exposure in self._exposures.items():
            if scope_id and exposure.scope_id != scope_id:
                continue
            
            if exposure.status in (ExposureStatus.MITIGATED, ExposureStatus.FALSE_POSITIVE):
                continue
            
            self._prioritize_exposure(exposure)
            count += 1
        
        return count
    
    # =========================================================================
    # PHASE 4: VALIDATION
    # =========================================================================
    
    def validate_exposure(
        self,
        exposure_id: str,
        result: str,
        notes: str = "",
        tested_by: str = ""
    ) -> Exposure:
        """
        Record validation test result
        
        Args:
            exposure_id: Exposure to validate
            result: Validation result (exploitable, not_exploitable, etc.)
            notes: Additional notes
            tested_by: Who performed the test
            
        Returns:
            Updated Exposure
        """
        exposure = self._exposures.get(exposure_id)
        if not exposure:
            raise ValueError(f"Exposure not found: {exposure_id}")
        
        # Update validation
        try:
            exposure.validation_result = ValidationResult[result.upper()]
        except KeyError:
            exposure.validation_result = ValidationResult.NOT_TESTED
        
        # Update status
        if exposure.status == ExposureStatus.NEW:
            exposure.status = ExposureStatus.CONFIRMED
        
        # Adjust priority based on validation
        if exposure.validation_result == ValidationResult.NOT_EXPLOITABLE:
            # Lower priority if not actually exploitable
            if exposure.priority in (RemediationPriority.P0, RemediationPriority.P1):
                exposure.priority = RemediationPriority.P2
        elif exposure.validation_result == ValidationResult.BLOCKED_BY_CONTROL:
            # Lower priority if compensating controls work
            exposure.compensating_controls.append(notes)
            exposure.priority = RemediationPriority.P3
        elif exposure.validation_result == ValidationResult.EXPLOITABLE:
            # Boost priority if confirmed exploitable
            if exposure.priority in (RemediationPriority.P2, RemediationPriority.P3):
                exposure.priority = RemediationPriority.P1
        
        return exposure
    
    # =========================================================================
    # PHASE 5: MOBILIZATION
    # =========================================================================
    
    def create_remediation_task(
        self,
        exposure_id: str,
        title: str,
        task_type: str = "patch",
        assignee: str = "",
        team: str = "",
        estimated_hours: float = 0.0
    ) -> RemediationTask:
        """
        Create a remediation task for an exposure
        
        Args:
            exposure_id: Parent exposure
            title: Task title
            task_type: Type of remediation
            assignee: Assigned person
            team: Responsible team
            estimated_hours: Effort estimate
            
        Returns:
            RemediationTask object
        """
        exposure = self._exposures.get(exposure_id)
        if not exposure:
            raise ValueError(f"Exposure not found: {exposure_id}")
        
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        
        task = RemediationTask(
            task_id=task_id,
            exposure_id=exposure_id,
            title=title,
            task_type=task_type,
            assignee=assignee,
            team=team,
            estimated_hours=estimated_hours,
            due_date=exposure.sla_deadline,
        )
        
        # Update exposure status
        if exposure.status in (ExposureStatus.NEW, ExposureStatus.CONFIRMED):
            exposure.status = ExposureStatus.IN_REMEDIATION
        
        exposure.assignee = assignee
        exposure.team = team
        
        self._tasks[task_id] = task
        return task
    
    def update_task_status(
        self,
        task_id: str,
        status: str,
        actual_hours: Optional[float] = None,
        notes: str = ""
    ) -> RemediationTask:
        """Update remediation task status"""
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        
        task.status = status
        
        if status == "in_progress" and not task.started_at:
            task.started_at = datetime.utcnow().isoformat()
        elif status == "completed":
            task.completed_at = datetime.utcnow().isoformat()
            if actual_hours:
                task.actual_hours = actual_hours
            
            # Update exposure
            exposure = self._exposures.get(task.exposure_id)
            if exposure:
                exposure.status = ExposureStatus.MITIGATED
                exposure.resolved_at = datetime.utcnow().isoformat()
                exposure.remediation_notes = notes
        
        return task
    
    def get_exposure(self, exposure_id: str) -> Optional[Exposure]:
        """Get exposure by ID"""
        return self._exposures.get(exposure_id)
    
    def list_exposures(
        self,
        scope_id: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        limit: int = 100
    ) -> List[Exposure]:
        """List exposures with optional filters"""
        exposures = list(self._exposures.values())
        
        if scope_id:
            exposures = [e for e in exposures if e.scope_id == scope_id]
        
        if status:
            try:
                status_enum = ExposureStatus[status.upper()]
                exposures = [e for e in exposures if e.status == status_enum]
            except KeyError:
                pass
        
        if priority:
            try:
                priority_enum = RemediationPriority[priority.upper()]
                exposures = [e for e in exposures if e.priority == priority_enum]
            except KeyError:
                pass
        
        # Sort by risk score (descending)
        exposures.sort(key=lambda e: e.risk_score, reverse=True)
        
        return exposures[:limit]
    
    # =========================================================================
    # METRICS & REPORTING
    # =========================================================================
    
    def calculate_metrics(self, scope_id: Optional[str] = None) -> CTEMMetrics:
        """Calculate comprehensive CTEM metrics"""
        exposures = self.list_exposures(scope_id=scope_id, limit=10000)
        
        if not exposures:
            return CTEMMetrics()
        
        now = datetime.utcnow()
        
        # Basic counts
        total = len(exposures)
        
        # Time-based counts
        new_24h = sum(1 for e in exposures if (now - datetime.fromisoformat(e.discovered_at)).total_seconds() < 86400)
        new_7d = sum(1 for e in exposures if (now - datetime.fromisoformat(e.discovered_at)).days < 7)
        new_30d = sum(1 for e in exposures if (now - datetime.fromisoformat(e.discovered_at)).days < 30)
        
        # Priority distribution
        p0 = sum(1 for e in exposures if e.priority == RemediationPriority.P0)
        p1 = sum(1 for e in exposures if e.priority == RemediationPriority.P1)
        p2 = sum(1 for e in exposures if e.priority == RemediationPriority.P2)
        p3 = sum(1 for e in exposures if e.priority == RemediationPriority.P3)
        p4 = sum(1 for e in exposures if e.priority == RemediationPriority.P4)
        
        # Status distribution
        open_exp = sum(1 for e in exposures if e.status in (ExposureStatus.NEW, ExposureStatus.CONFIRMED))
        in_rem = sum(1 for e in exposures if e.status == ExposureStatus.IN_REMEDIATION)
        mitigated = sum(1 for e in exposures if e.status == ExposureStatus.MITIGATED)
        accepted = sum(1 for e in exposures if e.status == ExposureStatus.ACCEPTED)
        
        # SLA metrics
        breached = 0
        at_risk = 0
        compliant = 0
        
        for exp in exposures:
            if exp.status in (ExposureStatus.MITIGATED, ExposureStatus.ACCEPTED, ExposureStatus.FALSE_POSITIVE):
                if exp.resolved_at and exp.sla_deadline:
                    if datetime.fromisoformat(exp.resolved_at) <= datetime.fromisoformat(exp.sla_deadline):
                        compliant += 1
                    else:
                        breached += 1
            elif exp.sla_deadline:
                deadline = datetime.fromisoformat(exp.sla_deadline)
                if now > deadline:
                    breached += 1
                elif (deadline - now).total_seconds() < 86400:  # Within 24 hours
                    at_risk += 1
        
        total_with_sla = breached + compliant + at_risk + open_exp
        sla_compliance = compliant / total_with_sla if total_with_sla > 0 else 0.0
        
        # Performance metrics
        resolved = [e for e in exposures if e.resolved_at]
        mttr_hours = 0.0
        if resolved:
            total_hours = sum(
                (datetime.fromisoformat(e.resolved_at) - datetime.fromisoformat(e.discovered_at)).total_seconds() / 3600
                for e in resolved
            )
            mttr_hours = total_hours / len(resolved)
        
        # Remediation velocity (last 30 days)
        resolved_30d = sum(
            1 for e in resolved
            if (now - datetime.fromisoformat(e.resolved_at)).days < 30
        )
        velocity = resolved_30d / 30.0
        
        # Risk metrics
        total_risk = sum(e.risk_score for e in exposures if e.status not in (ExposureStatus.MITIGATED, ExposureStatus.FALSE_POSITIVE))
        avg_risk = total_risk / max(1, open_exp + in_rem)
        
        # Backlog age
        open_ages = []
        for e in exposures:
            if e.status not in (ExposureStatus.MITIGATED, ExposureStatus.ACCEPTED, ExposureStatus.FALSE_POSITIVE):
                age = (now - datetime.fromisoformat(e.discovered_at)).days
                open_ages.append(age)
        
        backlog_p95 = 0.0
        if open_ages:
            open_ages.sort()
            p95_idx = int(len(open_ages) * 0.95)
            backlog_p95 = open_ages[min(p95_idx, len(open_ages) - 1)]
        
        return CTEMMetrics(
            total_exposures=total,
            new_exposures_24h=new_24h,
            new_exposures_7d=new_7d,
            new_exposures_30d=new_30d,
            p0_count=p0,
            p1_count=p1,
            p2_count=p2,
            p3_count=p3,
            p4_count=p4,
            open_exposures=open_exp,
            in_remediation=in_rem,
            mitigated=mitigated,
            accepted=accepted,
            sla_compliance_rate=sla_compliance,
            breached_slas=breached,
            at_risk_slas=at_risk,
            mttd_hours=0.0,  # Would need scan data
            mttr_hours=mttr_hours,
            remediation_velocity=velocity,
            total_risk_score=total_risk,
            average_risk_score=avg_risk,
            risk_reduction_30d=0.0,  # Would need historical data
            backlog_age_p95=backlog_p95,
            overdue_count=breached,
        )
    
    def get_sla_breaches(
        self,
        scope_id: Optional[str] = None,
        include_at_risk: bool = True
    ) -> List[Dict[str, Any]]:
        """Get list of SLA breaches and at-risk exposures"""
        exposures = self.list_exposures(scope_id=scope_id, limit=10000)
        now = datetime.utcnow()
        
        results = []
        
        for exp in exposures:
            if exp.status in (ExposureStatus.MITIGATED, ExposureStatus.ACCEPTED, ExposureStatus.FALSE_POSITIVE):
                continue
            
            if not exp.sla_deadline:
                continue
            
            deadline = datetime.fromisoformat(exp.sla_deadline)
            
            if now > deadline:
                # Breached
                overdue_hours = (now - deadline).total_seconds() / 3600
                results.append({
                    "exposure_id": exp.exposure_id,
                    "title": exp.title,
                    "priority": exp.priority.value,
                    "status": "BREACHED",
                    "overdue_hours": round(overdue_hours, 1),
                    "escalation_level": self._get_escalation_level(overdue_hours, exp.priority),
                })
            elif include_at_risk and (deadline - now).total_seconds() < 86400:
                # At risk (within 24 hours)
                remaining_hours = (deadline - now).total_seconds() / 3600
                results.append({
                    "exposure_id": exp.exposure_id,
                    "title": exp.title,
                    "priority": exp.priority.value,
                    "status": "AT_RISK",
                    "remaining_hours": round(remaining_hours, 1),
                    "escalation_level": 0,
                })
        
        # Sort by severity (breached first, then by overdue time)
        results.sort(key=lambda x: (x["status"] != "BREACHED", -x.get("overdue_hours", 0)))
        
        return results
    
    def _get_escalation_level(self, overdue_hours: float, priority: RemediationPriority) -> int:
        """Determine escalation level based on how overdue"""
        sla = self.sla_hours.get(priority.value, 720)
        
        if overdue_hours > sla * 1.5:
            return 3  # Critical escalation
        elif overdue_hours > sla * 1.0:
            return 2  # Second escalation
        elif overdue_hours > sla * 0.5:
            return 1  # First escalation
        
        return 0
    
    def generate_executive_summary(
        self,
        scope_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate executive summary report"""
        metrics = self.calculate_metrics(scope_id)
        sla_breaches = self.get_sla_breaches(scope_id)
        
        # Risk rating
        avg_risk = metrics.average_risk_score
        if avg_risk >= 8.0:
            risk_rating = "CRITICAL"
        elif avg_risk >= 6.0:
            risk_rating = "HIGH"
        elif avg_risk >= 4.0:
            risk_rating = "MEDIUM"
        elif avg_risk >= 2.0:
            risk_rating = "LOW"
        else:
            risk_rating = "MINIMAL"
        
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "scope_id": scope_id or "ALL",
            "risk_posture": {
                "rating": risk_rating,
                "score": round(avg_risk, 1),
                "total_risk": round(metrics.total_risk_score, 1),
            },
            "exposure_summary": {
                "total": metrics.total_exposures,
                "critical_high": metrics.p0_count + metrics.p1_count,
                "medium_low": metrics.p2_count + metrics.p3_count + metrics.p4_count,
                "open": metrics.open_exposures,
                "in_remediation": metrics.in_remediation,
            },
            "sla_performance": {
                "compliance_rate": f"{metrics.sla_compliance_rate * 100:.1f}%",
                "breached": metrics.breached_slas,
                "at_risk": metrics.at_risk_slas,
            },
            "remediation_performance": {
                "mttr_hours": round(metrics.mttr_hours, 1),
                "velocity_per_day": round(metrics.remediation_velocity, 2),
                "backlog_age_days": round(metrics.backlog_age_p95, 1),
            },
            "top_sla_breaches": sla_breaches[:5],
            "recommendations": self._generate_recommendations(metrics),
        }
    
    def _generate_recommendations(self, metrics: CTEMMetrics) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if metrics.p0_count > 0:
            recommendations.append(f"URGENT: Address {metrics.p0_count} P0 critical exposures within 24 hours")
        
        if metrics.breached_slas > 5:
            recommendations.append(f"SLA Review: {metrics.breached_slas} breached SLAs require immediate attention")
        
        if metrics.mttr_hours > 168:
            recommendations.append(f"Process Improvement: MTTR of {metrics.mttr_hours:.0f} hours exceeds 7-day target")
        
        if metrics.backlog_age_p95 > 30:
            recommendations.append(f"Backlog Management: 5% of exposures older than {metrics.backlog_age_p95:.0f} days")
        
        if metrics.sla_compliance_rate < 0.8:
            recommendations.append(f"Resource Allocation: SLA compliance at {metrics.sla_compliance_rate*100:.0f}% - consider additional resources")
        
        if not recommendations:
            recommendations.append("Maintain current operational tempo - metrics within acceptable ranges")
        
        return recommendations


# =============================================================================
# FACTORY & EXPORTS
# =============================================================================

_ctem_engine: Optional[CTEMEngine] = None


def get_ctem_engine(config: Optional[Dict[str, Any]] = None) -> CTEMEngine:
    """Get or create CTEM engine instance"""
    global _ctem_engine
    if _ctem_engine is None or config is not None:
        _ctem_engine = CTEMEngine(config)
    return _ctem_engine


def run_ctem_discovery(
    scope_id: str,
    vulnerabilities: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Run CTEM discovery phase on vulnerability data
    
    Convenience function for API usage
    """
    engine = get_ctem_engine()
    
    exposures = engine.bulk_discover(scope_id, vulnerabilities)
    return [e.to_dict() for e in exposures]


# Singleton export
ctem_engine = get_ctem_engine()

__all__ = [
    "CTEMEngine",
    "CTEMScope",
    "Exposure",
    "RemediationTask",
    "CTEMMetrics",
    "CTEMPhase",
    "ExposureStatus",
    "RemediationPriority",
    "ValidationResult",
    "AssetType",
    "get_ctem_engine",
    "run_ctem_discovery",
    "ctem_engine",
]
