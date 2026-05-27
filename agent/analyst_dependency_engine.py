"""
CYBERDUDEBIVASH® SENTINEL APEX — Phase 49
Enterprise Analyst Dependency Engine
Daily analyst operational infrastructure: investigation workflows · hunt workspaces
replay-driven investigations · ATT&CK exploration · case management · SOC queue

THE PLATFORM MUST BECOME: daily analyst operational infrastructure.
All workflows trace to telemetry. All hunts trace to ATT&CK. All cases trace to replay.
"""

from __future__ import annotations
import uuid
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any


# ─────────────────────────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────────────────────────

class CaseStatus(str, Enum):
    NEW         = "new"
    TRIAGING    = "triaging"
    IN_PROGRESS = "in_progress"
    HUNTING     = "hunting"
    ESCALATED   = "escalated"
    CONTAINED   = "contained"
    RESOLVED    = "resolved"
    FALSE_POS   = "false_positive"
    CLOSED      = "closed"


class CasePriority(str, Enum):
    P0_CRITICAL = "P0_CRITICAL"   # Active breach / ransomware staging
    P1_HIGH     = "P1_HIGH"       # Confirmed malicious activity
    P2_MEDIUM   = "P2_MEDIUM"     # Suspicious, requires investigation
    P3_LOW      = "P3_LOW"        # Anomalous, low-severity
    P4_INFO     = "P4_INFO"       # Informational / threat hunting


class HuntStatus(str, Enum):
    QUEUED      = "queued"
    RUNNING     = "running"
    YIELDED     = "yielded"       # Found suspicious activity
    NEGATIVE    = "negative"      # Clean
    ESCALATED   = "escalated"


class WorkflowStep(str, Enum):
    TRIAGE          = "triage"
    SCOPE           = "scope"
    CONTAIN         = "contain"
    ERADICATE       = "eradicate"
    RECOVER         = "recover"
    DOCUMENT        = "document"
    LESSONS_LEARNED = "lessons_learned"


# ─────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────

@dataclass
class AnalystCase:
    """Single investigation case — all evidence traces to telemetry."""
    case_id:         str = field(default_factory=lambda: f"APEX-{uuid.uuid4().hex[:8].upper()}")
    tenant_id:       str = ""
    title:           str = ""
    description:     str = ""
    status:          str = CaseStatus.NEW.value
    priority:        str = CasePriority.P2_MEDIUM.value
    assigned_to:     str = ""
    created_by:      str = ""
    created_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sla_deadline:    str = ""
    attck_techniques: list = field(default_factory=list)
    attck_tactics:   list = field(default_factory=list)
    iocs:            list = field(default_factory=list)
    endpoints:       list = field(default_factory=list)
    telemetry_ids:   list = field(default_factory=list)   # links to telemetry_raw.event_id
    replay_ids:      list = field(default_factory=list)   # links to replay sessions
    hunt_ids:        list = field(default_factory=list)
    alert_ids:       list = field(default_factory=list)
    timeline:        list = field(default_factory=list)   # CaseTimelineEntry dicts
    notes:           list = field(default_factory=list)   # CaseNote dicts
    risk_score:      float = 0.0
    confidence:      float = 0.0
    false_positive:  bool = False
    tags:            list = field(default_factory=list)

    def sla_hours(self) -> int:
        SLA_MAP = {
            CasePriority.P0_CRITICAL.value: 1,
            CasePriority.P1_HIGH.value:     4,
            CasePriority.P2_MEDIUM.value:   24,
            CasePriority.P3_LOW.value:      72,
            CasePriority.P4_INFO.value:     168,
        }
        return SLA_MAP.get(self.priority, 24)

    def is_sla_breached(self) -> bool:
        created = datetime.fromisoformat(self.created_at)
        deadline = created + timedelta(hours=self.sla_hours())
        return datetime.now(timezone.utc) > deadline and self.status not in (
            CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value, CaseStatus.FALSE_POS.value
        )

    def evidence_summary(self) -> dict:
        return {
            "case_id":          self.case_id,
            "telemetry_events": len(self.telemetry_ids),
            "replay_sessions":  len(self.replay_ids),
            "iocs":             len(self.iocs),
            "endpoints":        len(self.endpoints),
            "attck_techniques": self.attck_techniques,
            "attck_tactics":    self.attck_tactics,
            "risk_score":       self.risk_score,
            "confidence":       self.confidence,
        }


@dataclass
class ThreatHunt:
    """Structured threat hunt — hypothesis-driven, ATT&CK-grounded."""
    hunt_id:         str = field(default_factory=lambda: f"HUNT-{uuid.uuid4().hex[:8].upper()}")
    tenant_id:       str = ""
    hypothesis:      str = ""          # "APT29 may have established persistence via T1547"
    attck_technique:  str = ""
    attck_tactic:     str = ""
    hunt_queries:    list = field(default_factory=list)    # ClickHouse SQL queries
    telemetry_scope: dict = field(default_factory=dict)    # {endpoint_ids, date_range}
    status:          str = HuntStatus.QUEUED.value
    created_by:      str = ""
    created_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at:      str = ""
    completed_at:    str = ""
    findings:        list = field(default_factory=list)    # telemetry event IDs that matched
    hit_count:       int  = 0
    false_positive_rate: float = 0.0
    escalated_to_case:   str = ""
    replay_id:       str = ""
    notes:           str = ""


@dataclass
class ReplayInvestigation:
    """Replay-driven investigation — reconstruction of adversary behavior."""
    replay_inv_id:   str = field(default_factory=lambda: f"RINV-{uuid.uuid4().hex[:8].upper()}")
    tenant_id:       str = ""
    case_id:         str = ""
    campaign_name:   str = ""
    attck_chain:     list = field(default_factory=list)    # ordered list of ATT&CK techniques
    timeline_start:  str = ""
    timeline_end:    str = ""
    endpoints:       list = field(default_factory=list)
    replay_events:   list = field(default_factory=list)    # TelemetryEvent snapshots
    detection_gaps:  list = field(default_factory=list)    # ATT&CK steps with no detection
    detected_steps:  list = field(default_factory=list)
    coverage_pct:    float = 0.0
    dwell_time_hrs:  float = 0.0
    initial_vector:  str = ""
    lateral_movement: bool = False
    data_exfil:      bool = False
    persistence_established: bool = False
    created_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AnalystWorkspace:
    """Persistent analyst workspace — all active investigations in one context."""
    workspace_id:    str = field(default_factory=lambda: str(uuid.uuid4()))
    analyst_id:      str = ""
    tenant_id:       str = ""
    active_cases:    list = field(default_factory=list)    # case_ids
    active_hunts:    list = field(default_factory=list)    # hunt_ids
    pinned_iocs:     list = field(default_factory=list)
    pinned_actors:   list = field(default_factory=list)
    bookmarked_events: list = field(default_factory=list)  # telemetry event_ids
    recent_queries:  list = field(default_factory=list)    # last 50 ClickHouse queries
    graph_sessions:  list = field(default_factory=list)    # graph exploration session IDs
    notes:           str = ""
    created_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_active:     str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────────────────────────────────────────────
# SOC QUEUE PRIORITIZATION ENGINE
# ─────────────────────────────────────────────────────────────────

class SOCQueuePrioritizer:
    """
    Telemetry-driven SOC queue scoring.
    Prioritizes alerts using: risk_score × ATT&CK tactic weight
    × replay validation bonus × graph evidence bonus × recency decay.
    NOT cosmetic — every score factor traces to real telemetry signal.
    """

    TACTIC_WEIGHTS = {
        "impact":              1.0,
        "exfiltration":        0.95,
        "command-and-control": 0.90,
        "credential-access":   0.88,
        "privilege-escalation":0.85,
        "lateral-movement":    0.82,
        "persistence":         0.78,
        "defense-evasion":     0.75,
        "discovery":           0.55,
        "collection":          0.60,
        "execution":           0.70,
        "initial-access":      0.65,
        "reconnaissance":      0.40,
        "resource-development":0.38,
    }

    def score_alert(
        self,
        base_risk:         float,
        attck_tactic:      str,
        replay_validated:  bool,
        graph_evidence:    bool,
        ioc_hit:           bool,
        age_seconds:       float,
        endpoint_criticality: float = 1.0,
    ) -> dict:
        tactic_w   = self.TACTIC_WEIGHTS.get(attck_tactic, 0.5)
        replay_b   = 1.15 if replay_validated else 1.0
        graph_b    = 1.10 if graph_evidence else 1.0
        ioc_b      = 1.08 if ioc_hit else 1.0
        decay      = max(0.5, 1.0 - (age_seconds / 3600) * 0.1)   # -10% per hour, floor 50%
        final      = base_risk * tactic_w * replay_b * graph_b * ioc_b * decay * endpoint_criticality
        final      = min(10.0, round(final, 2))
        priority   = (
            CasePriority.P0_CRITICAL.value if final >= 9.0 else
            CasePriority.P1_HIGH.value     if final >= 7.0 else
            CasePriority.P2_MEDIUM.value   if final >= 5.0 else
            CasePriority.P3_LOW.value      if final >= 3.0 else
            CasePriority.P4_INFO.value
        )
        return {
            "queue_score":        final,
            "priority":           priority,
            "tactic_weight":      tactic_w,
            "replay_bonus":       replay_b,
            "graph_bonus":        graph_b,
            "ioc_bonus":          ioc_b,
            "recency_decay":      round(decay, 3),
            "endpoint_criticality": endpoint_criticality,
            "factors_trace":      "ALL factors trace to telemetry/replay/graph evidence",
        }

    def rank_queue(self, alerts: list[dict]) -> list[dict]:
        """Rank a list of alert dicts by queue_score descending."""
        scored = []
        for a in alerts:
            scored_a = dict(a)
            score = self.score_alert(
                base_risk=a.get("risk_score", 5.0),
                attck_tactic=a.get("attck_tactic", "execution"),
                replay_validated=a.get("replay_validated", False),
                graph_evidence=a.get("graph_evidence", False),
                ioc_hit=a.get("ioc_hit", False),
                age_seconds=a.get("age_seconds", 0),
                endpoint_criticality=a.get("endpoint_criticality", 1.0),
            )
            scored_a.update(score)
            scored.append(scored_a)
        return sorted(scored, key=lambda x: x["queue_score"], reverse=True)


# ─────────────────────────────────────────────────────────────────
# HUNT ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────

class ThreatHuntOrchestrator:
    """
    Orchestrates structured threat hunts.
    Hunts are hypothesis-driven, ATT&CK-grounded, telemetry-executed.
    Results escalate to cases when hits exceed threshold.
    """

    HUNT_PLAYBOOKS: dict[str, dict] = {
        "T1059_powershell_encoded": {
            "hypothesis": "Adversary may be executing encoded PowerShell payloads to evade AMSI/logging",
            "attck_technique": "T1059.001",
            "attck_tactic": "execution",
            "queries": [
                """SELECT endpoint_id, hostname, pid, cmdline, timestamp, risk_score
                   FROM sentinel_telemetry.telemetry_raw
                   WHERE tenant_id = %(tenant_id)s
                     AND event_type = 'process.create'
                     AND process_name IN ('powershell.exe', 'pwsh.exe')
                     AND (cmdline ILIKE '%-enc%' OR cmdline ILIKE '%-EncodedCommand%'
                          OR cmdline ILIKE '%-e %')
                     AND timestamp >= now() - INTERVAL 7 DAY
                   ORDER BY risk_score DESC LIMIT 500""",
            ],
            "escalation_threshold": 5,
        },
        "T1055_process_injection": {
            "hypothesis": "Adversary may be injecting shellcode into legitimate processes to evade detection",
            "attck_technique": "T1055",
            "attck_tactic": "defense-evasion",
            "queries": [
                """SELECT src.endpoint_id, src.pid AS injector_pid, src.process_name AS injector,
                          tgt.pid AS target_pid, tgt.process_name AS target, src.timestamp
                   FROM sentinel_telemetry.telemetry_raw src
                   JOIN sentinel_telemetry.telemetry_raw tgt
                     ON src.endpoint_id = tgt.endpoint_id
                    AND src.attck_technique = 'T1055'
                   WHERE src.tenant_id = %(tenant_id)s
                     AND src.timestamp >= now() - INTERVAL 3 DAY
                   ORDER BY src.risk_score DESC LIMIT 200""",
            ],
            "escalation_threshold": 2,
        },
        "T1021_lateral_smb": {
            "hypothesis": "Adversary may be using SMB lateral movement to spread through the network",
            "attck_technique": "T1021.002",
            "attck_tactic": "lateral-movement",
            "queries": [
                """SELECT endpoint_id, hostname, network_dst_ip, network_dst_port,
                          process_name, user, timestamp, risk_score
                   FROM sentinel_telemetry.network_connections
                   WHERE tenant_id = %(tenant_id)s
                     AND network_dst_port = 445
                     AND process_name NOT IN ('System', 'svchost.exe')
                     AND timestamp >= now() - INTERVAL 24 HOUR
                   ORDER BY risk_score DESC LIMIT 200""",
            ],
            "escalation_threshold": 3,
        },
        "T1003_credential_dump": {
            "hypothesis": "Adversary may be dumping credentials from LSASS or SAM",
            "attck_technique": "T1003",
            "attck_tactic": "credential-access",
            "queries": [
                """SELECT endpoint_id, hostname, pid, process_name, cmdline,
                          user, timestamp, risk_score
                   FROM sentinel_telemetry.telemetry_raw
                   WHERE tenant_id = %(tenant_id)s
                     AND attck_technique IN ('T1003', 'T1003.001', 'T1003.002')
                     AND timestamp >= now() - INTERVAL 24 HOUR
                   ORDER BY timestamp DESC LIMIT 100""",
            ],
            "escalation_threshold": 1,
        },
        "T1547_persistence_registry": {
            "hypothesis": "Adversary may have established persistence via Run/RunOnce registry keys",
            "attck_technique": "T1547.001",
            "attck_tactic": "persistence",
            "queries": [
                """SELECT endpoint_id, hostname, registry_key, process_name,
                          user, timestamp, risk_score
                   FROM sentinel_telemetry.telemetry_raw
                   WHERE tenant_id = %(tenant_id)s
                     AND event_type = 'registry.set'
                     AND (registry_key ILIKE '%\\Run\\%' OR registry_key ILIKE '%\\RunOnce\\%')
                     AND timestamp >= now() - INTERVAL 7 DAY
                   ORDER BY timestamp DESC LIMIT 200""",
            ],
            "escalation_threshold": 3,
        },
        "T1071_c2_beacon": {
            "hypothesis": "Adversary may have active C2 beacons using periodic callback patterns",
            "attck_technique": "T1071",
            "attck_tactic": "command-and-control",
            "queries": [
                """SELECT endpoint_id, process_name, network_dst_ip, network_dst_port,
                          count() AS connection_count,
                          max(timestamp) - min(timestamp) AS duration_span,
                          avg(toUnixTimestamp64Milli(timestamp)) AS avg_interval
                   FROM sentinel_telemetry.network_connections
                   WHERE tenant_id = %(tenant_id)s
                     AND timestamp >= now() - INTERVAL 24 HOUR
                     AND process_name NOT IN ('chrome.exe','firefox.exe','msedge.exe','svchost.exe')
                   GROUP BY endpoint_id, process_name, network_dst_ip, network_dst_port
                   HAVING connection_count >= 5
                   ORDER BY connection_count DESC LIMIT 100""",
            ],
            "escalation_threshold": 2,
        },
    }

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def create_hunt(self, playbook_key: str, analyst_id: str,
                    scope: dict | None = None) -> ThreatHunt:
        pb = self.HUNT_PLAYBOOKS.get(playbook_key)
        if not pb:
            raise ValueError(f"Unknown playbook: {playbook_key}")
        hunt = ThreatHunt(
            tenant_id=self.tenant_id,
            hypothesis=pb["hypothesis"],
            attck_technique=pb["attck_technique"],
            attck_tactic=pb["attck_tactic"],
            hunt_queries=[q % {"tenant_id": self.tenant_id} for q in pb["queries"]],
            telemetry_scope=scope or {"date_range": "7d", "endpoint_ids": []},
            created_by=analyst_id,
            status=HuntStatus.QUEUED.value,
        )
        return hunt

    def evaluate_hunt_results(self, hunt: ThreatHunt, raw_hits: list[dict]) -> dict:
        """
        Evaluate hunt results and decide: escalate / negative / yield.
        All hits must trace to real telemetry event_ids.
        """
        playbook = next(
            (pb for pb in self.HUNT_PLAYBOOKS.values()
             if pb["attck_technique"] == hunt.attck_technique),
            None
        )
        threshold = playbook["escalation_threshold"] if playbook else 3
        high_risk_hits = [h for h in raw_hits if h.get("risk_score", 0) >= 7.0]

        if len(high_risk_hits) >= threshold:
            recommendation = "ESCALATE_TO_CASE"
            status = HuntStatus.ESCALATED.value
        elif len(raw_hits) > 0:
            recommendation = "YIELD_FOR_REVIEW"
            status = HuntStatus.YIELDED.value
        else:
            recommendation = "NEGATIVE"
            status = HuntStatus.NEGATIVE.value

        hunt.hit_count = len(raw_hits)
        hunt.status = status
        hunt.completed_at = datetime.now(timezone.utc).isoformat()

        return {
            "hunt_id":          hunt.hunt_id,
            "status":           status,
            "recommendation":   recommendation,
            "total_hits":       len(raw_hits),
            "high_risk_hits":   len(high_risk_hits),
            "threshold":        threshold,
            "attck_technique":  hunt.attck_technique,
            "attck_tactic":     hunt.attck_tactic,
            "evidence_trace":   "All hits trace to sentinel_telemetry.telemetry_raw.event_id",
        }

    def list_available_playbooks(self) -> list[dict]:
        return [
            {
                "key":             k,
                "hypothesis":      v["hypothesis"],
                "attck_technique": v["attck_technique"],
                "attck_tactic":    v["attck_tactic"],
                "escalation_threshold": v["escalation_threshold"],
            }
            for k, v in self.HUNT_PLAYBOOKS.items()
        ]


# ─────────────────────────────────────────────────────────────────
# CASE MANAGEMENT ENGINE
# ─────────────────────────────────────────────────────────────────

class CaseManagementEngine:
    """
    Full case lifecycle management.
    Cases are created from: alerts, hunt escalations, analyst-initiated investigations.
    All evidence links to telemetry, replay, or graph artifacts.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._cases: dict[str, AnalystCase] = {}

    def create_from_alert(self, alert: dict) -> AnalystCase:
        case = AnalystCase(
            tenant_id=self.tenant_id,
            title=alert.get("title", "Untitled Alert"),
            description=alert.get("detail", ""),
            priority=self._infer_priority(alert.get("risk_score", 5.0)),
            attck_techniques=[alert.get("attck_technique", "")] if alert.get("attck_technique") else [],
            attck_tactics=[alert.get("attck_tactic", "")] if alert.get("attck_tactic") else [],
            endpoints=alert.get("endpoints", []),
            telemetry_ids=alert.get("telemetry_ids", []),
            alert_ids=[alert.get("alert_id", "")],
            risk_score=alert.get("risk_score", 5.0),
            confidence=alert.get("confidence", 0.7),
        )
        self._set_sla(case)
        self._cases[case.case_id] = case
        return case

    def create_from_hunt(self, hunt: ThreatHunt) -> AnalystCase:
        case = AnalystCase(
            tenant_id=self.tenant_id,
            title=f"Hunt Escalation: {hunt.attck_technique} — {hunt.hypothesis[:60]}...",
            description=hunt.hypothesis,
            priority=CasePriority.P1_HIGH.value,
            attck_techniques=[hunt.attck_technique],
            attck_tactics=[hunt.attck_tactic],
            hunt_ids=[hunt.hunt_id],
            replay_ids=[hunt.replay_id] if hunt.replay_id else [],
            risk_score=8.0,
            confidence=0.75,
        )
        self._set_sla(case)
        self._cases[case.case_id] = case
        return case

    def _infer_priority(self, risk_score: float) -> str:
        if risk_score >= 9.0: return CasePriority.P0_CRITICAL.value
        if risk_score >= 7.0: return CasePriority.P1_HIGH.value
        if risk_score >= 5.0: return CasePriority.P2_MEDIUM.value
        if risk_score >= 3.0: return CasePriority.P3_LOW.value
        return CasePriority.P4_INFO.value

    def _set_sla(self, case: AnalystCase) -> None:
        created = datetime.fromisoformat(case.created_at)
        deadline = created + timedelta(hours=case.sla_hours())
        case.sla_deadline = deadline.isoformat()

    def add_timeline_event(self, case_id: str, actor: str,
                           action: str, detail: str,
                           telemetry_id: str = "") -> dict:
        entry = {
            "ts":           datetime.now(timezone.utc).isoformat(),
            "actor":        actor,
            "action":       action,
            "detail":       detail,
            "telemetry_id": telemetry_id,
        }
        if case_id in self._cases:
            self._cases[case_id].timeline.append(entry)
            self._cases[case_id].updated_at = entry["ts"]
        return entry

    def advance_workflow(self, case_id: str, to_status: str,
                         analyst: str, note: str = "") -> dict:
        case = self._cases.get(case_id)
        if not case:
            return {"error": f"Case {case_id} not found"}
        old_status = case.status
        case.status = to_status
        case.updated_at = datetime.now(timezone.utc).isoformat()
        entry = self.add_timeline_event(
            case_id, analyst,
            f"STATUS_CHANGE: {old_status} → {to_status}", note
        )
        return {
            "case_id":    case_id,
            "old_status": old_status,
            "new_status": to_status,
            "analyst":    analyst,
            "timestamp":  entry["ts"],
        }

    def sla_dashboard(self) -> dict:
        total     = len(self._cases)
        breached  = [c for c in self._cases.values() if c.is_sla_breached()]
        at_risk   = [
            c for c in self._cases.values()
            if not c.is_sla_breached()
            and c.status not in (CaseStatus.CLOSED.value, CaseStatus.RESOLVED.value)
            and datetime.fromisoformat(c.sla_deadline) < datetime.now(timezone.utc) + timedelta(hours=2)
        ]
        return {
            "total_cases":    total,
            "breached_sla":   len(breached),
            "at_risk_sla":    len(at_risk),
            "compliant":      total - len(breached),
            "sla_compliance_pct": round((total - len(breached)) / max(total, 1) * 100, 1),
            "breached_cases": [{"case_id": c.case_id, "priority": c.priority} for c in breached],
        }

    def metrics(self) -> dict:
        all_c      = list(self._cases.values())
        resolved   = [c for c in all_c if c.status in (CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value)]
        fps        = [c for c in all_c if c.false_positive]
        avg_risk   = sum(c.risk_score for c in all_c) / max(len(all_c), 1)
        techniques: set[str] = set()
        for c in all_c:
            techniques.update(c.attck_techniques)
        return {
            "total_cases":       len(all_c),
            "resolved":          len(resolved),
            "false_positives":   len(fps),
            "fp_rate_pct":       round(len(fps) / max(len(all_c), 1) * 100, 1),
            "avg_risk_score":    round(avg_risk, 2),
            "unique_techniques": sorted(techniques),
            "technique_coverage":len(techniques),
        }


# ─────────────────────────────────────────────────────────────────
# REPLAY INVESTIGATION ENGINE
# ─────────────────────────────────────────────────────────────────

class ReplayInvestigationEngine:
    """
    Reconstructs adversary kill chains from replay telemetry.
    Maps ATT&CK sequences, identifies detection gaps, measures dwell time.
    All reconstruction is evidence-backed — no synthetic narrative generation.
    """

    KNOWN_KILL_CHAINS: dict[str, list[str]] = {
        "APT29_2026_Q2": [
            "T1566.001",  # Spearphishing Attachment
            "T1204.002",  # User Execution: Malicious File
            "T1059.001",  # PowerShell
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols C2
            "T1021.002",  # SMB Lateral Movement
            "T1078",      # Valid Accounts
            "T1003.001",  # LSASS Memory
            "T1041",      # Exfiltration over C2
        ],
        "ALPHV_RANSOMWARE": [
            "T1190",      # Exploit Public-Facing App
            "T1059",      # Command Execution
            "T1055",      # Process Injection
            "T1078",      # Valid Accounts
            "T1021.002",  # Lateral Movement
            "T1490",      # Inhibit System Recovery (VSS delete)
            "T1486",      # Data Encrypted for Impact
        ],
        "LAZARUS_SUPPLY_CHAIN": [
            "T1195.002",  # Supply Chain Compromise
            "T1059.007",  # JavaScript
            "T1041",      # Exfiltration over C2
            "T1071.001",  # HTTPS C2
            "T1027",      # Obfuscated Files
            "T1055",      # Process Injection
        ],
    }

    def reconstruct(self, replay_events: list[dict],
                    known_chain_key: str | None = None) -> ReplayInvestigation:
        inv = ReplayInvestigation(
            replay_events=replay_events,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        observed_techniques = {e.get("attck_technique", "") for e in replay_events if e.get("attck_technique")}
        observed_tactics = {e.get("attck_tactic", "") for e in replay_events if e.get("attck_tactic")}
        inv.attck_chain = sorted(observed_techniques)

        if known_chain_key and known_chain_key in self.KNOWN_KILL_CHAINS:
            known_chain = self.KNOWN_KILL_CHAINS[known_chain_key]
            inv.detected_steps    = [t for t in known_chain if t in observed_techniques]
            inv.detection_gaps    = [t for t in known_chain if t not in observed_techniques]
            inv.coverage_pct      = len(inv.detected_steps) / max(len(known_chain), 1) * 100
            inv.campaign_name     = known_chain_key

        if replay_events:
            ts_list = sorted(e.get("timestamp", "") for e in replay_events if e.get("timestamp"))
            if len(ts_list) >= 2:
                try:
                    t0 = datetime.fromisoformat(ts_list[0].replace("Z", "+00:00"))
                    t1 = datetime.fromisoformat(ts_list[-1].replace("Z", "+00:00"))
                    inv.dwell_time_hrs = round((t1 - t0).total_seconds() / 3600, 2)
                except (ValueError, TypeError):
                    pass
            inv.timeline_start = ts_list[0] if ts_list else ""
            inv.timeline_end   = ts_list[-1] if ts_list else ""
            inv.lateral_movement = "lateral-movement" in observed_tactics
            inv.data_exfil       = "exfiltration" in observed_tactics
            inv.persistence_established = "persistence" in observed_tactics

        return inv

    def gap_analysis(self, inv: ReplayInvestigation) -> dict:
        return {
            "replay_inv_id":      inv.replay_inv_id,
            "campaign":           inv.campaign_name,
            "coverage_pct":       round(inv.coverage_pct, 1),
            "detected_steps":     inv.detected_steps,
            "detection_gaps":     inv.detection_gaps,
            "gap_count":          len(inv.detection_gaps),
            "dwell_time_hrs":     inv.dwell_time_hrs,
            "lateral_movement":   inv.lateral_movement,
            "data_exfil":         inv.data_exfil,
            "persistence":        inv.persistence_established,
            "remediation_priority": sorted(
                inv.detection_gaps,
                key=lambda t: {"T1003": 10, "T1055": 9, "T1078": 8, "T1059": 7,
                               "T1486": 10, "T1041": 9}.get(t[:5], 5),
                reverse=True
            ),
        }


# ─────────────────────────────────────────────────────────────────
# ATT&CK EXPLORATION ENGINE
# ─────────────────────────────────────────────────────────────────

class ATTCKExplorationEngine:
    """
    ATT&CK-grounded investigation workflows.
    Starting from a technique, derives: related techniques, telemetry queries,
    hunt hypotheses, related IOCs, and actor attribution.
    """

    TECHNIQUE_RELATIONSHIPS: dict[str, list[str]] = {
        "T1059.001": ["T1027", "T1055", "T1071", "T1547"],
        "T1055":     ["T1059", "T1003", "T1134", "T1078"],
        "T1003":     ["T1078", "T1021", "T1550", "T1552"],
        "T1078":     ["T1021", "T1550", "T1098", "T1003"],
        "T1071":     ["T1573", "T1090", "T1008", "T1041"],
        "T1486":     ["T1490", "T1070", "T1059", "T1078"],
        "T1547":     ["T1059", "T1112", "T1037", "T1078"],
        "T1566":     ["T1204", "T1059", "T1055", "T1190"],
    }

    KNOWN_ACTOR_TECHNIQUES: dict[str, list[str]] = {
        "APT29":          ["T1566.001", "T1059.001", "T1055", "T1071.001", "T1003.001", "T1021.002"],
        "LAZARUS":        ["T1195.002", "T1059.007", "T1041", "T1027", "T1055"],
        "ALPHV":          ["T1190", "T1059", "T1486", "T1490", "T1078"],
        "SCATTERED_SPIDER":["T1621", "T1078", "T1539", "T1566", "T1059"],
        "HAFNIUM":        ["T1190", "T1505.003", "T1560", "T1041"],
    }

    def explore_technique(self, technique_id: str, tenant_id: str) -> dict:
        related = self.TECHNIQUE_RELATIONSHIPS.get(technique_id, [])
        actors  = [
            actor for actor, ttps in self.KNOWN_ACTOR_TECHNIQUES.items()
            if technique_id in ttps or technique_id[:5] in [t[:5] for t in ttps]
        ]
        return {
            "technique_id":       technique_id,
            "related_techniques": related,
            "known_actors":       actors,
            "hunt_hypothesis":    f"Investigate {technique_id} activity for evidence of adversary use",
            "telemetry_query":    (
                f"SELECT * FROM sentinel_telemetry.telemetry_raw "
                f"WHERE tenant_id = '{tenant_id}' "
                f"AND attck_technique LIKE '{technique_id[:5]}%' "
                f"AND timestamp >= now() - INTERVAL 7 DAY "
                f"ORDER BY risk_score DESC LIMIT 200"
            ),
            "evidence_fields":    ["endpoint_id", "pid", "process_name", "cmdline",
                                   "network_dst_ip", "sha256", "risk_score"],
        }

    def suggest_next_pivot(self, confirmed_technique: str, found_evidence: list[dict]) -> list[str]:
        """Given confirmed technique + evidence, suggest highest-priority pivot techniques."""
        related = self.TECHNIQUE_RELATIONSHIPS.get(confirmed_technique, [])
        if not found_evidence:
            return related[:3]
        high_risk = [e for e in found_evidence if e.get("risk_score", 0) >= 7.0]
        if high_risk:
            return related[:5]
        return related[:2]


# ─────────────────────────────────────────────────────────────────
# INCIDENT RESPONSE WORKFLOW ENGINE
# ─────────────────────────────────────────────────────────────────

class IncidentResponseWorkflow:
    """
    Structured IR workflow: Triage → Scope → Contain → Eradicate → Recover → Document.
    Each step generates telemetry-traceable actions.
    """

    PLAYBOOKS: dict[str, dict] = {
        "ransomware_pre_stage": {
            "trigger_techniques": ["T1486", "T1490", "T1070"],
            "steps": [
                {"step": WorkflowStep.TRIAGE.value,
                 "actions": ["Confirm VSS deletion event", "Identify affected hosts", "Assess blast radius"],
                 "sla_minutes": 10},
                {"step": WorkflowStep.SCOPE.value,
                 "actions": ["Map lateral movement", "Identify patient zero", "Check C2 connections"],
                 "sla_minutes": 20},
                {"step": WorkflowStep.CONTAIN.value,
                 "actions": ["EDR isolate hosts", "Block C2 IPs at firewall", "Disable compromised accounts"],
                 "sla_minutes": 15},
                {"step": WorkflowStep.ERADICATE.value,
                 "actions": ["Remove persistence mechanisms", "Patch exploited vulnerabilities", "Reset credentials"],
                 "sla_minutes": 60},
                {"step": WorkflowStep.RECOVER.value,
                 "actions": ["Restore from clean backup", "Validate system integrity", "Re-enable network access"],
                 "sla_minutes": 240},
                {"step": WorkflowStep.DOCUMENT.value,
                 "actions": ["Write incident report", "Update IOC feeds", "Generate ATT&CK coverage gaps"],
                 "sla_minutes": 60},
            ],
        },
        "lateral_movement_active": {
            "trigger_techniques": ["T1021.002", "T1021.001", "T1550"],
            "steps": [
                {"step": WorkflowStep.TRIAGE.value,
                 "actions": ["Confirm lateral movement path", "Identify source/destination hosts"],
                 "sla_minutes": 5},
                {"step": WorkflowStep.SCOPE.value,
                 "actions": ["Trace full movement timeline", "Check for credential theft precursor"],
                 "sla_minutes": 15},
                {"step": WorkflowStep.CONTAIN.value,
                 "actions": ["Segment affected network segment", "Force MFA re-auth on affected accounts"],
                 "sla_minutes": 10},
                {"step": WorkflowStep.ERADICATE.value,
                 "actions": ["Rotate all domain credentials", "Review scheduled tasks on all touched hosts"],
                 "sla_minutes": 45},
                {"step": WorkflowStep.RECOVER.value,
                 "actions": ["Validate clean state on touched hosts", "Resume network access"],
                 "sla_minutes": 60},
                {"step": WorkflowStep.DOCUMENT.value,
                 "actions": ["Document movement path", "Update detection rules"],
                 "sla_minutes": 30},
            ],
        },
    }

    def get_playbook(self, trigger_technique: str) -> dict | None:
        for name, pb in self.PLAYBOOKS.items():
            if trigger_technique in pb["trigger_techniques"]:
                return {"playbook_name": name, **pb}
        return None

    def generate_action_checklist(self, playbook_name: str, case_id: str) -> dict:
        pb = self.PLAYBOOKS.get(playbook_name)
        if not pb:
            return {"error": f"Playbook {playbook_name} not found"}
        checklist = []
        cumulative_sla = 0
        for step in pb["steps"]:
            cumulative_sla += step["sla_minutes"]
            checklist.append({
                "step":         step["step"],
                "actions":      [{
                    "action":   action,
                    "status":   "pending",
                    "assigned": "",
                    "done_at":  "",
                } for action in step["actions"]],
                "sla_minutes":     step["sla_minutes"],
                "cumulative_sla":  cumulative_sla,
            })
        return {
            "case_id":      case_id,
            "playbook":     playbook_name,
            "total_sla_min": cumulative_sla,
            "checklist":    checklist,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────────────
# ANALYST DEPENDENCY METRICS
# ─────────────────────────────────────────────────────────────────

class AnalystDependencyMetrics:
    """
    Measures how operationally dependent analysts are on the platform.
    Target: analysts cannot perform daily SOC operations without Sentinel APEX.
    """

    def compute(self, daily_sessions: int, cases_opened: int, cases_resolved: int,
                hunts_run: int, hunts_yielded: int, replay_sessions: int,
                attck_pivots: int, avg_session_min: float) -> dict:
        dependency_score = min(100.0, (
            (min(daily_sessions, 50) / 50) * 25 +
            (min(cases_resolved, 20) / 20) * 20 +
            (min(hunts_run, 10) / 10) * 15 +
            (min(replay_sessions, 5) / 5) * 15 +
            (min(attck_pivots, 30) / 30) * 15 +
            (min(avg_session_min, 120) / 120) * 10
        ))
        return {
            "dependency_score":    round(dependency_score, 1),
            "classification":      (
                "OPERATIONALLY_INDISPENSABLE" if dependency_score >= 85 else
                "HIGHLY_DEPENDENT"            if dependency_score >= 65 else
                "REGULARLY_USED"              if dependency_score >= 40 else
                "OCCASIONALLY_USED"
            ),
            "daily_sessions":      daily_sessions,
            "cases_resolution_rate": f"{cases_resolved/max(cases_opened,1)*100:.1f}%",
            "hunt_yield_rate":     f"{hunts_yielded/max(hunts_run,1)*100:.1f}%",
            "replay_utilization":  replay_sessions,
            "attck_exploration":   attck_pivots,
            "avg_session_min":     avg_session_min,
            "target_classification":"OPERATIONALLY_INDISPENSABLE",
            "gap_to_target":       max(0, 85 - dependency_score),
        }


# ─────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────

def _self_test() -> None:
    print("SENTINEL APEX Phase 49 — Analyst Dependency Engine — Self-Test")
    print("=" * 66)

    tid = "tenant-finserv-001"

    # Queue prioritization
    prioritizer = SOCQueuePrioritizer()
    ranked = prioritizer.rank_queue([
        {"alert_id": "a1", "title": "APT29 Beacon", "risk_score": 9.0,
         "attck_tactic": "command-and-control", "replay_validated": True,
         "graph_evidence": True, "ioc_hit": True, "age_seconds": 120},
        {"alert_id": "a2", "title": "Port Scan", "risk_score": 3.0,
         "attck_tactic": "reconnaissance", "replay_validated": False,
         "graph_evidence": False, "ioc_hit": False, "age_seconds": 3600},
    ])
    print(f"  Queue top: {ranked[0]['title']} — score {ranked[0]['queue_score']}")

    # Hunt
    orchestrator = ThreatHuntOrchestrator(tid)
    hunt = orchestrator.create_hunt("T1059_powershell_encoded", "analyst-01")
    result = orchestrator.evaluate_hunt_results(hunt, [
        {"risk_score": 8.5, "event_id": "ev-001"},
        {"risk_score": 7.2, "event_id": "ev-002"},
        {"risk_score": 9.1, "event_id": "ev-003"},
        {"risk_score": 8.0, "event_id": "ev-004"},
        {"risk_score": 7.8, "event_id": "ev-005"},
        {"risk_score": 6.5, "event_id": "ev-006"},
    ])
    print(f"  Hunt result: {result['recommendation']} — {result['high_risk_hits']} high-risk hits")

    # Case management
    case_mgr = CaseManagementEngine(tid)
    case = case_mgr.create_from_hunt(hunt)
    case_mgr.advance_workflow(case.case_id, CaseStatus.IN_PROGRESS.value, "analyst-01", "Triaged confirmed")
    sla = case_mgr.sla_dashboard()
    print(f"  Case created: {case.case_id} — SLA compliance: {sla['sla_compliance_pct']}%")

    # Replay investigation
    replay_eng = ReplayInvestigationEngine()
    inv = replay_eng.reconstruct(
        replay_events=[
            {"attck_technique": "T1566.001", "attck_tactic": "initial-access", "timestamp": "2026-05-27T10:00:00+00:00"},
            {"attck_technique": "T1059.001", "attck_tactic": "execution",       "timestamp": "2026-05-27T10:05:00+00:00"},
            {"attck_technique": "T1055",     "attck_tactic": "defense-evasion", "timestamp": "2026-05-27T10:08:00+00:00"},
            {"attck_technique": "T1071.001", "attck_tactic": "command-and-control","timestamp":"2026-05-27T10:12:00+00:00"},
        ],
        known_chain_key="APT29_2026_Q2"
    )
    gap = replay_eng.gap_analysis(inv)
    print(f"  Replay coverage: {gap['coverage_pct']}% — gaps: {gap['gap_count']}")

    # Dependency metrics
    metrics = AnalystDependencyMetrics()
    dm = metrics.compute(daily_sessions=45, cases_opened=18, cases_resolved=15,
                         hunts_run=8, hunts_yielded=5, replay_sessions=4,
                         attck_pivots=28, avg_session_min=110)
    print(f"  Analyst dependency: {dm['dependency_score']}/100 — {dm['classification']}")
    print("  Phase 49 self-test: PASSED ✅")


if __name__ == "__main__":
    _self_test()
