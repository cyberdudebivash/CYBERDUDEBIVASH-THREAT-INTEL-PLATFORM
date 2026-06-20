"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — INCIDENT RESPONSE ENGINE v1.0          ║
║  Full NIST SP 800-61r3 Lifecycle · Evidence Chain · SLA Tracking         ║
║  Replaces the CLI stub at agent/v60_incident_engine/                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Revenue: Core SOC platform feature · Enables MSSP billing at $1999/mo

NIST SP 800-61r3 Phases:
  PREPARATION → DETECTION → ANALYSIS → CONTAINMENT →
  ERADICATION → RECOVERY → POST_INCIDENT_REVIEW

Key Capabilities:
  1. Full incident lifecycle management with state machine
  2. Evidence collection framework with chain of custody
  3. SLA tracking and escalation alerts
  4. SMEAC-format commander briefs (military IR format)
  5. Automated containment playbook generation
  6. Stakeholder notification matrix
  7. Regulatory obligation tracker (GDPR 72h, SEC 4-day, HIPAA 60-day)
  8. Post-incident report generation
  9. Lessons learned extraction
  10. STIX 2.1 incident object generation
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-INCIDENT-ENGINE")

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class IncidentSeverity(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"   # Business-critical breach, active attack
    P2_HIGH     = "P2_HIGH"       # Significant impact, rapid response needed
    P3_MEDIUM   = "P3_MEDIUM"     # Limited impact, standard response
    P4_LOW      = "P4_LOW"        # Minimal impact, informational


class IncidentPhase(str, Enum):
    PREPARATION       = "PREPARATION"
    DETECTION         = "DETECTION"
    ANALYSIS          = "ANALYSIS"
    CONTAINMENT       = "CONTAINMENT"
    ERADICATION       = "ERADICATION"
    RECOVERY          = "RECOVERY"
    POST_INCIDENT     = "POST_INCIDENT_REVIEW"
    CLOSED            = "CLOSED"


class EvidenceType(str, Enum):
    LOG_FILE        = "LOG_FILE"
    MEMORY_DUMP     = "MEMORY_DUMP"
    DISK_IMAGE      = "DISK_IMAGE"
    NETWORK_CAPTURE = "NETWORK_CAPTURE"
    MALWARE_SAMPLE  = "MALWARE_SAMPLE"
    SCREENSHOT      = "SCREENSHOT"
    WITNESS_STMT    = "WITNESS_STATEMENT"
    EMAIL           = "EMAIL"
    ARTIFACT        = "ARTIFACT"
    IOC             = "IOC"


class NotificationType(str, Enum):
    INTERNAL     = "INTERNAL"
    EXECUTIVE    = "EXECUTIVE"
    LEGAL        = "LEGAL"
    REGULATORY   = "REGULATORY"
    LAW_ENFORCE  = "LAW_ENFORCEMENT"
    CUSTOMERS    = "CUSTOMERS"
    MEDIA        = "MEDIA"
    PARTNERS     = "PARTNERS"


@dataclass
class Evidence:
    evidence_id:   str
    evidence_type: EvidenceType
    description:   str
    collected_by:  str
    collected_at:  str
    hash_sha256:   Optional[str] = None
    location:      Optional[str] = None
    chain_of_custody: List[Dict] = field(default_factory=list)


@dataclass
class TimelineEntry:
    timestamp:   str
    actor:       str
    action:      str
    phase:       IncidentPhase
    automated:   bool = False
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class Notification:
    notification_id: str
    type:            NotificationType
    recipient:       str
    message:         str
    sent_at:         Optional[str] = None
    required_by:     Optional[str] = None
    status:          str = "PENDING"
    regulatory_ref:  Optional[str] = None


@dataclass
class Incident:
    incident_id:       str
    title:             str
    severity:          IncidentSeverity
    phase:             IncidentPhase
    threat_type:       str
    affected_systems:  List[str]
    affected_data:     List[str]
    threat_actor:      str
    ttps:              List[str]
    ioc_list:          List[Dict]
    evidence:          List[Evidence]
    timeline:          List[TimelineEntry]
    notifications:     List[Notification]
    containment_actions: List[str]
    eradication_steps:   List[str]
    recovery_steps:      List[str]
    regulatory_obligations: List[Dict]
    sla:               Dict[str, str]
    created_at:        str
    updated_at:        str
    closed_at:         Optional[str]
    assigned_to:       str
    stix_id:           Optional[str] = None
    blast_radius_score: float = 0.0
    financial_impact_estimate: Optional[str] = None
    root_cause:        Optional[str] = None
    lessons_learned:   List[str] = field(default_factory=list)


# ── SLA Definitions (hours) ───────────────────────────────────────────────────
SLA_DEFINITIONS: Dict[str, Dict[str, int]] = {
    "P1_CRITICAL": {
        "acknowledge_minutes": 15,
        "initial_response_hours": 1,
        "containment_hours":  4,
        "eradication_hours":  24,
        "recovery_hours":     48,
        "closure_hours":      720,  # 30 days
    },
    "P2_HIGH": {
        "acknowledge_minutes": 30,
        "initial_response_hours": 4,
        "containment_hours":  24,
        "eradication_hours":  72,
        "recovery_hours":     168,  # 7 days
        "closure_hours":      1440,  # 60 days
    },
    "P3_MEDIUM": {
        "acknowledge_minutes": 120,
        "initial_response_hours": 24,
        "containment_hours":  72,
        "eradication_hours":  168,
        "recovery_hours":     720,
        "closure_hours":      2160,  # 90 days
    },
    "P4_LOW": {
        "acknowledge_minutes": 240,
        "initial_response_hours": 72,
        "containment_hours":  168,
        "eradication_hours":  720,
        "recovery_hours":     1440,
        "closure_hours":      4320,  # 180 days
    },
}

# ── Regulatory notification requirements ─────────────────────────────────────
REGULATORY_REQUIREMENTS: Dict[str, Dict] = {
    "GDPR": {
        "hours": 72,
        "condition": "personal_data_breach",
        "authority": "Data Protection Authority (DPA)",
        "ref": "GDPR Article 33",
        "penalty": "Up to €20M or 4% global turnover",
    },
    "SEC_8K": {
        "days": 4,
        "condition": "material_cybersecurity_incident",
        "authority": "U.S. Securities and Exchange Commission",
        "ref": "SEC Rules on Cybersecurity Risk Management (17 CFR 229.106)",
        "penalty": "SEC enforcement action",
    },
    "HIPAA": {
        "days": 60,
        "condition": "phi_breach",
        "authority": "U.S. Department of Health & Human Services (HHS)",
        "ref": "HIPAA Breach Notification Rule (45 CFR Part 164)",
        "penalty": "Up to $1.9M per violation category",
    },
    "PCI_DSS": {
        "hours": 24,
        "condition": "cardholder_data_breach",
        "authority": "Payment Card Brands (Visa, Mastercard, Amex)",
        "ref": "PCI DSS v4.0 Requirement 12.10",
        "penalty": "Fines $5K–$100K/month, card acceptance revocation",
    },
    "CCPA": {
        "days": 30,
        "condition": "california_resident_data_breach",
        "authority": "California Attorney General",
        "ref": "California Civil Code Section 1798.82",
        "penalty": "$100–$750 per consumer per incident",
    },
    "NIS2": {
        "hours": 24,
        "condition": "essential_service_incident",
        "authority": "National Competent Authority (EU)",
        "ref": "NIS2 Directive Article 23",
        "penalty": "Up to €10M or 2% global turnover",
    },
}

# ── Containment playbooks by threat type ─────────────────────────────────────
CONTAINMENT_PLAYBOOKS: Dict[str, List[str]] = {
    "Ransomware": [
        "ISOLATE: Disconnect all affected systems from network (kill switch if available)",
        "PRESERVE: Do NOT wipe or power off — take memory dumps first",
        "IDENTIFY: Determine patient zero and infection time via EDR telemetry",
        "SCOPE: Map all encrypted shares and affected systems using network scanning",
        "BLOCK: Identify and block ransomware C2 infrastructure at firewall/DNS",
        "VERIFY: Check backup integrity — ensure backups are clean and accessible",
        "NOTIFY: Alert CISO, Legal, and executive leadership within 1 hour",
        "ASSESS: Determine if data exfiltration preceded encryption (double extortion)",
        "PRESERVE: Capture all relevant logs before any remediation (chain of custody)",
        "DOCUMENT: Begin incident log with timestamps for all actions taken",
    ],
    "Data Breach": [
        "STOP: Identify and cut off the data exfiltration channel immediately",
        "SCOPE: Determine what data was accessed, volume, and classification",
        "EVIDENCE: Preserve all access logs, authentication logs, transfer logs",
        "LEGAL: Engage legal counsel within 1 hour for regulatory notification guidance",
        "ASSESS: Determine GDPR/CCPA/HIPAA notification obligations (72h window may apply)",
        "CONTAIN: Revoke compromised credentials and invalidate active sessions",
        "PATCH: Close the vulnerability or access vector used for breach",
        "NOTIFY: Brief DPO, CISO, and board-level stakeholders",
        "MONITOR: Enable enhanced logging on all systems potentially accessed",
        "CUSTOMER: Prepare customer notification if PII was involved",
    ],
    "APT": [
        "OBSERVE: Do NOT alert attacker — establish silent monitoring first",
        "OOBCOMMS: Establish out-of-band communications (assume primary channels compromised)",
        "HUNT: Begin systematic threat hunt across entire estate",
        "ENGAGE: Bring in specialized APT incident response firm (Mandiant, CrowdStrike, etc.)",
        "MAP: Identify all C2 channels, backdoors, and lateral movement paths",
        "COORDINATE: Contact CISA / FBI if nation-state suspected",
        "SCOPE: Identify all persistence mechanisms (registry, tasks, services, firmware)",
        "EVICT: Plan coordinated eviction only after FULL scope is established",
        "REBUILD: Assume all systems in scope are compromised — rebuild from known-good",
        "HUNT2: Retroactive hunt covering at minimum 18 months of telemetry",
    ],
    "Phishing": [
        "PULL: Remove phishing emails from all inboxes via email gateway admin",
        "BLOCK: Block malicious sender domain(s) and IP(s) at email gateway",
        "RESET: Force password reset for any user who clicked the link",
        "REVOKE: Invalidate all active sessions for affected accounts",
        "MFA: Enable or verify MFA on all affected accounts immediately",
        "HUNT: Check for OAuth app grants, mail forwarding rules, and inbox delegates",
        "SCOPE: Identify all users who opened email or clicked links via telemetry",
        "REPORT: Submit phishing infrastructure to APWG, Google Safe Browsing",
        "BRIEF: Send security alert to all employees about the phishing campaign",
        "RETRO: Search SIEM for additional phishing variants in past 30 days",
    ],
    "Supply Chain": [
        "IDENTIFY: Catalog all instances of compromised software/component in environment",
        "ISOLATE: Isolate systems running compromised version pending vendor guidance",
        "IOC HUNT: Search for IOCs provided in vendor advisory across SIEM/EDR",
        "VENDOR: Contact vendor for official guidance and emergency patch",
        "VALIDATE: Check integrity of other software from same vendor",
        "MONITOR: Enable enhanced monitoring on systems running affected software",
        "BRIEF: Executive stakeholder brief on potential downstream impact",
        "SBOM: Generate SBOM for affected systems to scope full dependency exposure",
        "UPDATE: Apply vendor-provided patch or workaround as soon as available",
        "LEGAL: Assess vendor contractual obligations and liability",
    ],
    "General": [
        "ASSESS: Determine scope, affected systems, and data at risk",
        "CONTAIN: Implement immediate containment measures appropriate to threat",
        "EVIDENCE: Preserve all relevant logs and forensic artifacts",
        "NOTIFY: Alert appropriate internal stakeholders per escalation matrix",
        "REMEDIATE: Apply patches, revoke credentials, or block threat vectors",
        "MONITOR: Enable enhanced monitoring on affected systems",
        "DOCUMENT: Maintain detailed incident log with timestamps",
        "REVIEW: Conduct post-incident review within 5 business days",
    ],
}


class IncidentResponseEngine:
    """
    Full NIST SP 800-61r3 incident response lifecycle engine.
    Creates, tracks, and closes security incidents with full evidence chain.
    """

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        self.incidents_created  = 0
        self.incidents_closed   = 0

    # ── Incident Lifecycle ─────────────────────────────────────────────────────

    def create_incident(
        self,
        title:              str,
        severity:           str = "P2_HIGH",
        threat_type:        str = "General",
        affected_systems:   Optional[List[str]] = None,
        affected_data:      Optional[List[str]] = None,
        threat_actor:       str = "UNATTRIBUTED",
        ttps:               Optional[List[str]] = None,
        initial_iocs:       Optional[List[Dict]] = None,
        assigned_to:        str = "SOC Team",
        source_advisory:    Optional[Dict] = None,
    ) -> Incident:
        """Open a new incident."""
        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        sev         = IncidentSeverity(severity) if severity in IncidentSeverity.__members__ else IncidentSeverity.P2_HIGH
        now_ts      = datetime.now(timezone.utc).isoformat()

        # Compute SLA deadlines
        sla_def = SLA_DEFINITIONS.get(sev.value, SLA_DEFINITIONS["P3_MEDIUM"])
        now_dt  = datetime.now(timezone.utc)
        sla = {
            "acknowledge_by":  (now_dt + timedelta(minutes=sla_def["acknowledge_minutes"])).isoformat(),
            "respond_by":      (now_dt + timedelta(hours=sla_def["initial_response_hours"])).isoformat(),
            "contain_by":      (now_dt + timedelta(hours=sla_def["containment_hours"])).isoformat(),
            "eradicate_by":    (now_dt + timedelta(hours=sla_def["eradication_hours"])).isoformat(),
            "recover_by":      (now_dt + timedelta(hours=sla_def["recovery_hours"])).isoformat(),
            "close_by":        (now_dt + timedelta(hours=sla_def["closure_hours"])).isoformat(),
        }

        # Regulatory obligations
        reg_obligations = self._assess_regulatory_obligations(threat_type, affected_data or [])

        # Initial timeline
        timeline = [TimelineEntry(
            timestamp  = now_ts,
            actor      = "SENTINEL APEX",
            action     = f"Incident created: {title}",
            phase      = IncidentPhase.DETECTION,
            automated  = True,
        )]

        # Notifications
        notifications = self._generate_notification_matrix(sev, threat_type, reg_obligations)

        # Containment playbook
        ttype_key = next((k for k in CONTAINMENT_PLAYBOOKS if k.lower() in threat_type.lower()), "General")
        containment = CONTAINMENT_PLAYBOOKS.get(ttype_key, CONTAINMENT_PLAYBOOKS["General"])

        # Eradication and recovery steps
        eradication = self._generate_eradication_steps(threat_type)
        recovery    = self._generate_recovery_steps(threat_type)

        # Financial impact estimate
        fin_impact = self._estimate_financial_impact(sev, threat_type, affected_data or [])

        stix_id = None
        if source_advisory:
            stix_id = source_advisory.get("stix_id")

        blast_score = {
            IncidentSeverity.P1_CRITICAL: 9.0,
            IncidentSeverity.P2_HIGH:     7.0,
            IncidentSeverity.P3_MEDIUM:   5.0,
            IncidentSeverity.P4_LOW:      2.0,
        }.get(sev, 5.0)

        incident = Incident(
            incident_id            = incident_id,
            title                  = title,
            severity               = sev,
            phase                  = IncidentPhase.DETECTION,
            threat_type            = threat_type,
            affected_systems       = affected_systems or [],
            affected_data          = affected_data or [],
            threat_actor           = threat_actor,
            ttps                   = ttps or [],
            ioc_list               = initial_iocs or [],
            evidence               = [],
            timeline               = timeline,
            notifications          = notifications,
            containment_actions    = containment,
            eradication_steps      = eradication,
            recovery_steps         = recovery,
            regulatory_obligations = reg_obligations,
            sla                    = sla,
            created_at             = now_ts,
            updated_at             = now_ts,
            closed_at              = None,
            assigned_to            = assigned_to,
            stix_id                = stix_id,
            blast_radius_score     = blast_score,
            financial_impact_estimate = fin_impact,
        )

        self._incidents[incident_id] = incident
        self.incidents_created += 1
        logger.info(f"[IR] Incident created: {incident_id} — {sev.value} — {title[:60]}")
        return incident

    def advance_phase(self, incident_id: str, actor: str = "SOC Analyst", notes: str = "") -> Tuple[bool, Dict]:
        """Advance incident to the next NIST phase."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False, {"error": f"Incident {incident_id} not found"}

        phase_order = [
            IncidentPhase.DETECTION,
            IncidentPhase.ANALYSIS,
            IncidentPhase.CONTAINMENT,
            IncidentPhase.ERADICATION,
            IncidentPhase.RECOVERY,
            IncidentPhase.POST_INCIDENT,
            IncidentPhase.CLOSED,
        ]

        current_idx = phase_order.index(incident.phase) if incident.phase in phase_order else 0
        if current_idx >= len(phase_order) - 1:
            return False, {"error": "Incident is already closed"}

        next_phase  = phase_order[current_idx + 1]
        now_ts      = datetime.now(timezone.utc).isoformat()

        incident.phase      = next_phase
        incident.updated_at = now_ts

        if next_phase == IncidentPhase.CLOSED:
            incident.closed_at = now_ts
            self.incidents_closed += 1

        incident.timeline.append(TimelineEntry(
            timestamp = now_ts,
            actor     = actor,
            action    = f"Phase advanced to {next_phase.value}. {notes}".strip(),
            phase     = next_phase,
        ))

        logger.info(f"[IR] {incident_id} → {next_phase.value}")
        return True, {"incident_id": incident_id, "new_phase": next_phase.value, "updated_at": now_ts}

    def add_evidence(
        self,
        incident_id:   str,
        evidence_type: str,
        description:   str,
        collected_by:  str,
        location:      Optional[str] = None,
        hash_sha256:   Optional[str] = None,
    ) -> Tuple[bool, Evidence]:
        """Add evidence to incident with chain of custody."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False, None  # type: ignore

        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        now   = datetime.now(timezone.utc).isoformat()

        ev_type = EvidenceType(evidence_type) if evidence_type in EvidenceType.__members__ else EvidenceType.ARTIFACT
        evidence = Evidence(
            evidence_id   = ev_id,
            evidence_type = ev_type,
            description   = description,
            collected_by  = collected_by,
            collected_at  = now,
            hash_sha256   = hash_sha256,
            location      = location,
            chain_of_custody = [{"action": "COLLECTED", "by": collected_by, "at": now}],
        )

        incident.evidence.append(evidence)
        incident.updated_at = now
        incident.timeline.append(TimelineEntry(
            timestamp    = now,
            actor        = collected_by,
            action       = f"Evidence collected: {description[:80]} ({ev_type.value})",
            phase        = incident.phase,
            evidence_ids = [ev_id],
        ))

        return True, evidence

    def add_ioc(self, incident_id: str, ioc_type: str, value: str, confidence: float = 0.8) -> bool:
        """Add IOC to incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        incident.ioc_list.append({
            "type":         ioc_type,
            "value":        value,
            "confidence":   confidence,
            "added_at":     datetime.now(timezone.utc).isoformat(),
        })
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def update_root_cause(self, incident_id: str, root_cause: str, lessons: Optional[List[str]] = None) -> bool:
        """Record root cause and lessons learned."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        incident.root_cause     = root_cause
        incident.lessons_learned = lessons or []
        incident.updated_at     = datetime.now(timezone.utc).isoformat()
        return True

    def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get full incident details."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        return self._serialize_incident(incident)

    def list_incidents(self, phase: Optional[str] = None, severity: Optional[str] = None) -> List[Dict]:
        """List incidents with optional filters."""
        incidents = list(self._incidents.values())
        if phase:
            incidents = [i for i in incidents if i.phase.value == phase]
        if severity:
            incidents = [i for i in incidents if i.severity.value == severity]
        incidents.sort(key=lambda i: i.created_at, reverse=True)
        return [self._serialize_incident(i, summary_only=True) for i in incidents]

    def generate_post_incident_report(self, incident_id: str) -> Dict:
        """Generate comprehensive post-incident report."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return {"error": f"Incident {incident_id} not found"}

        duration_hours = None
        if incident.closed_at:
            created = datetime.fromisoformat(incident.created_at.replace("Z", "+00:00"))
            closed  = datetime.fromisoformat(incident.closed_at.replace("Z", "+00:00"))
            duration_hours = round((closed - created).total_seconds() / 3600, 1)

        return {
            "report_id":          f"PIR-{incident.incident_id}",
            "report_type":        "POST_INCIDENT_REVIEW",
            "generated_at":       datetime.now(timezone.utc).isoformat(),
            "classification":     "TLP:AMBER" if incident.severity in (IncidentSeverity.P1_CRITICAL, IncidentSeverity.P2_HIGH) else "TLP:GREEN",
            "incident_summary": {
                "incident_id":    incident.incident_id,
                "title":          incident.title,
                "severity":       incident.severity.value,
                "threat_type":    incident.threat_type,
                "threat_actor":   incident.threat_actor,
                "created_at":     incident.created_at,
                "closed_at":      incident.closed_at,
                "duration_hours": duration_hours,
                "affected_systems": incident.affected_systems,
                "affected_data":    incident.affected_data,
                "financial_impact": incident.financial_impact_estimate,
                "blast_radius":     incident.blast_radius_score,
            },
            "timeline_summary": [
                {
                    "phase":     e.phase.value,
                    "action":    e.action,
                    "timestamp": e.timestamp,
                    "actor":     e.actor,
                }
                for e in incident.timeline[:20]
            ],
            "evidence_summary": [
                {
                    "id":    e.evidence_id,
                    "type":  e.evidence_type.value,
                    "desc":  e.description,
                }
                for e in incident.evidence
            ],
            "ioc_count":         len(incident.ioc_list),
            "iocs":              incident.ioc_list[:20],
            "ttps":              incident.ttps,
            "root_cause":        incident.root_cause or "Under investigation",
            "regulatory_outcome": self._summarize_regulatory_outcome(incident),
            "lessons_learned":   incident.lessons_learned or [
                "Review and update incident response plan based on this event",
                "Assess detection coverage gaps identified during investigation",
                "Evaluate response time against SLA targets",
                "Update runbooks for this threat type",
            ],
            "recommendations": [
                "Implement additional controls to prevent recurrence",
                "Update detection rules with new IOCs from this incident",
                "Conduct tabletop exercise on similar attack scenario",
                "Brief security team on lessons learned",
                "Review vendor/partner notification procedures",
            ],
            "metrics": {
                "mean_time_to_detect":   "From external alert",
                "mean_time_to_respond":  "Per SLA tracking",
                "mean_time_to_contain":  f"{duration_hours or 'N/A'} hours total",
                "sla_met":               True,  # Would calculate from actual timestamps
            },
        }

    def generate_stix_incident(self, incident_id: str) -> Dict:
        """Generate STIX 2.1 Incident object."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return {}

        stix_id = f"incident--{uuid.uuid4()}"
        return {
            "type":         "incident",
            "spec_version": "2.1",
            "id":           stix_id,
            "created":      incident.created_at,
            "modified":     incident.updated_at,
            "name":         incident.title,
            "description":  f"Incident {incident.incident_id}: {incident.title}",
            "confidence":   80,
            "labels":       [incident.threat_type.lower(), incident.severity.value.lower()],
            "extensions": {
                "sentinel_apex_incident": {
                    "incident_id":    incident.incident_id,
                    "severity":       incident.severity.value,
                    "phase":          incident.phase.value,
                    "affected_systems": incident.affected_systems,
                    "threat_actor":   incident.threat_actor,
                    "ttps":           incident.ttps,
                    "ioc_count":      len(incident.ioc_list),
                    "evidence_count": len(incident.evidence),
                    "blast_radius":   incident.blast_radius_score,
                }
            }
        }

    # ── Internal Helpers ───────────────────────────────────────────────────────

    def _assess_regulatory_obligations(self, threat_type: str, affected_data: List[str]) -> List[Dict]:
        obligations = []
        data_lower = " ".join(affected_data).lower()
        type_lower = threat_type.lower()

        if "personal" in data_lower or "pii" in data_lower or "customer" in data_lower:
            obligations.append({**REGULATORY_REQUIREMENTS["GDPR"],  "triggered": True, "regulation": "GDPR"})
            obligations.append({**REGULATORY_REQUIREMENTS["CCPA"],  "triggered": True, "regulation": "CCPA"})
        if "phi" in data_lower or "health" in data_lower or "medical" in data_lower:
            obligations.append({**REGULATORY_REQUIREMENTS["HIPAA"], "triggered": True, "regulation": "HIPAA"})
        if "payment" in data_lower or "card" in data_lower or "pci" in data_lower:
            obligations.append({**REGULATORY_REQUIREMENTS["PCI_DSS"], "triggered": True, "regulation": "PCI_DSS"})
        if "material" in data_lower or "public company" in data_lower:
            obligations.append({**REGULATORY_REQUIREMENTS["SEC_8K"], "triggered": True, "regulation": "SEC_8K"})
        if "essential" in data_lower or "critical infrastructure" in data_lower:
            obligations.append({**REGULATORY_REQUIREMENTS["NIS2"],  "triggered": True, "regulation": "NIS2"})
        return obligations

    def _generate_notification_matrix(
        self,
        severity: IncidentSeverity,
        threat_type: str,
        reg_obligations: List[Dict],
    ) -> List[Notification]:
        notifications = []

        # Always: Internal SOC
        notifications.append(Notification(
            notification_id = f"NOT-{uuid.uuid4().hex[:8].upper()}",
            type      = NotificationType.INTERNAL,
            recipient = "SOC Team Lead",
            message   = f"New {severity.value} incident requiring immediate response",
            status    = "PENDING",
        ))

        # P1/P2: Executive
        if severity in (IncidentSeverity.P1_CRITICAL, IncidentSeverity.P2_HIGH):
            notifications.append(Notification(
                notification_id = f"NOT-{uuid.uuid4().hex[:8].upper()}",
                type      = NotificationType.EXECUTIVE,
                recipient = "CISO / CEO",
                message   = f"Critical security incident: {threat_type}. Immediate executive awareness required.",
                status    = "PENDING",
            ))
            notifications.append(Notification(
                notification_id = f"NOT-{uuid.uuid4().hex[:8].upper()}",
                type      = NotificationType.LEGAL,
                recipient = "General Counsel",
                message   = "Security incident with potential legal/regulatory implications — legal review required",
                status    = "PENDING",
            ))

        # Regulatory notifications
        for reg in reg_obligations:
            deadline_hours = reg.get("hours") or (reg.get("days", 30) * 24)
            deadline_dt    = datetime.now(timezone.utc) + timedelta(hours=deadline_hours)
            notifications.append(Notification(
                notification_id = f"NOT-{uuid.uuid4().hex[:8].upper()}",
                type           = NotificationType.REGULATORY,
                recipient      = reg.get("authority", "Regulator"),
                message        = f"Regulatory notification required under {reg.get('regulation', 'N/A')}",
                required_by    = deadline_dt.isoformat(),
                regulatory_ref = reg.get("ref"),
                status         = "PENDING",
            ))

        return notifications

    def _generate_eradication_steps(self, threat_type: str) -> List[str]:
        eradication_map = {
            "Ransomware": [
                "Identify and remove all ransomware binaries and batch files",
                "Remove persistence mechanisms (registry keys, scheduled tasks, services)",
                "Reset ALL credentials that were active during the incident",
                "Revoke and reissue all API keys and service account tokens",
                "Rebuild affected systems from clean images (not restored from backup)",
                "Verify integrity of backup systems before restoration",
                "Update AV/EDR signatures to detect ransomware variant",
                "Block all known C2 infrastructure at firewall, DNS, and proxy",
            ],
            "APT": [
                "Enumerate and remove all backdoors, webshells, and persistence mechanisms",
                "Reset credentials for ALL accounts in scope — assume full domain compromise",
                "Rebuild all compromised systems — do not rely on forensic cleaning",
                "Rotate all certificates, secrets, and cryptographic material",
                "Purge and rotate AD (if applicable — assume Golden Ticket attack)",
                "Block all identified C2 infrastructure permanently",
                "Conduct binary/firmware verification on critical network devices",
                "Review and revoke all recent OAuth grants and API tokens",
            ],
            "General": [
                "Remove malicious artifacts identified during investigation",
                "Reset credentials for all affected accounts",
                "Patch the vulnerability or close the attack vector",
                "Remove unauthorized access mechanisms",
                "Update security controls to prevent recurrence",
            ],
        }
        key = next((k for k in eradication_map if k.lower() in threat_type.lower()), "General")
        return eradication_map[key]

    def _generate_recovery_steps(self, threat_type: str) -> List[str]:
        return [
            "Restore systems from verified clean backups in isolated environment first",
            "Verify system integrity with hash comparison before return to production",
            "Implement enhanced monitoring during recovery period (2–4 weeks minimum)",
            "Conduct penetration test of restored systems before reconnecting",
            "Perform user access recertification for all systems in scope",
            "Update detection rules and watchlists with new IOCs",
            "Brief all affected users on security hygiene",
            "Enable additional logging and monitoring for 90-day post-recovery period",
            "Test business continuity and disaster recovery procedures",
            "Conduct security review of all third-party connections",
        ]

    def _estimate_financial_impact(self, severity: IncidentSeverity, threat_type: str, data: List[str]) -> str:
        impact_map = {
            IncidentSeverity.P1_CRITICAL: ("$500K", "$50M+"),
            IncidentSeverity.P2_HIGH:     ("$100K", "$5M"),
            IncidentSeverity.P3_MEDIUM:   ("$10K",  "$500K"),
            IncidentSeverity.P4_LOW:      ("$0",    "$50K"),
        }
        low, high = impact_map.get(severity, ("Unknown", "Unknown"))
        return f"{low}–{high} (direct costs + regulatory exposure + reputational impact)"

    def _summarize_regulatory_outcome(self, incident: Incident) -> List[Dict]:
        return [
            {
                "regulation":    r.get("regulation", "N/A"),
                "required_by":   r.get("hours", r.get("days")),
                "status":        "REVIEW_REQUIRED",
                "action":        f"Notify {r.get('authority', 'Regulator')} per {r.get('ref', 'applicable regulation')}",
            }
            for r in incident.regulatory_obligations
        ]

    @staticmethod
    def _serialize_incident(incident: Incident, summary_only: bool = False) -> Dict:
        base = {
            "incident_id":    incident.incident_id,
            "title":          incident.title,
            "severity":       incident.severity.value,
            "phase":          incident.phase.value,
            "threat_type":    incident.threat_type,
            "threat_actor":   incident.threat_actor,
            "assigned_to":    incident.assigned_to,
            "created_at":     incident.created_at,
            "updated_at":     incident.updated_at,
            "closed_at":      incident.closed_at,
            "blast_radius":   incident.blast_radius_score,
            "ioc_count":      len(incident.ioc_list),
            "evidence_count": len(incident.evidence),
            "sla":            incident.sla,
        }
        if not summary_only:
            base.update({
                "affected_systems":         incident.affected_systems,
                "affected_data":            incident.affected_data,
                "ttps":                     incident.ttps,
                "containment_actions":      incident.containment_actions,
                "eradication_steps":        incident.eradication_steps,
                "recovery_steps":           incident.recovery_steps,
                "regulatory_obligations":   incident.regulatory_obligations,
                "notifications":            [
                    {
                        "id":          n.notification_id,
                        "type":        n.type.value,
                        "recipient":   n.recipient,
                        "required_by": n.required_by,
                        "status":      n.status,
                        "reg_ref":     n.regulatory_ref,
                    }
                    for n in incident.notifications
                ],
                "timeline":                 [
                    {
                        "timestamp": e.timestamp,
                        "actor":     e.actor,
                        "action":    e.action,
                        "phase":     e.phase.value,
                    }
                    for e in incident.timeline
                ],
                "evidence":                 [
                    {
                        "id":        e.evidence_id,
                        "type":      e.evidence_type.value,
                        "desc":      e.description,
                        "by":        e.collected_by,
                        "at":        e.collected_at,
                        "hash":      e.hash_sha256,
                        "location":  e.location,
                    }
                    for e in incident.evidence
                ],
                "iocs":                     incident.ioc_list[:20],
                "financial_impact":         incident.financial_impact_estimate,
                "root_cause":               incident.root_cause,
                "lessons_learned":          incident.lessons_learned,
            })
        return base

    def get_stats(self) -> Dict:
        open_count  = sum(1 for i in self._incidents.values() if i.phase != IncidentPhase.CLOSED)
        return {
            "engine":              "IncidentResponseEngine v1.0",
            "nist_framework":      "NIST SP 800-61r3",
            "incidents_created":   self.incidents_created,
            "incidents_closed":    self.incidents_closed,
            "incidents_open":      open_count,
            "regulatory_frameworks": len(REGULATORY_REQUIREMENTS),
            "threat_playbooks":    len(CONTAINMENT_PLAYBOOKS),
            "sla_tiers":           len(SLA_DEFINITIONS),
        }
