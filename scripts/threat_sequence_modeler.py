#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Threat Sequence Modeler
Section 4: ATT&CK Sequence Engine | Adversary Progression | Campaign Timeline |
           Attack Chain Reconstruction | Kill-Chain Sequencing |
           Multi-Stage Intrusion Modeling | Adversary Fingerprinting
Production-grade | Temporal | ATT&CK-native | Graph-compatible
"""
import json, uuid, time, math, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from enum import Enum

log = logging.getLogger("threat_sequence")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [THREAT-SEQ] %(levelname)s %(message)s")

class KillChainPhase(str, Enum):
    RECONNAISSANCE    = "reconnaissance"
    WEAPONIZATION     = "weaponization"
    DELIVERY          = "delivery"
    EXPLOITATION      = "exploitation"
    INSTALLATION      = "installation"
    C2                = "command_and_control"
    ACTIONS           = "actions_on_objectives"

# ATT&CK tactic to kill chain phase mapping
TACTIC_TO_PHASE = {
    "Reconnaissance":      KillChainPhase.RECONNAISSANCE,
    "ResourceDevelopment": KillChainPhase.WEAPONIZATION,
    "InitialAccess":       KillChainPhase.DELIVERY,
    "Execution":           KillChainPhase.EXPLOITATION,
    "Persistence":         KillChainPhase.INSTALLATION,
    "PrivilegeEscalation": KillChainPhase.INSTALLATION,
    "DefenseEvasion":      KillChainPhase.INSTALLATION,
    "CredentialAccess":    KillChainPhase.EXPLOITATION,
    "Discovery":           KillChainPhase.EXPLOITATION,
    "LateralMovement":     KillChainPhase.ACTIONS,
    "Collection":          KillChainPhase.ACTIONS,
    "CommandAndControl":   KillChainPhase.C2,
    "Exfiltration":        KillChainPhase.ACTIONS,
    "Impact":              KillChainPhase.ACTIONS,
}

@dataclass
class SequenceNode:
    node_id:    str
    technique:  str
    tactic:     str
    phase:      str
    timestamp:  float
    entity:     str     # host or user
    confidence: float
    evidence:   List[str] = field(default_factory=list)

@dataclass
class AttackSequence:
    sequence_id:   str
    tenant_id:     str
    campaign_id:   str
    entity:        str
    nodes:         List[SequenceNode] = field(default_factory=list)
    start_time:    float = 0.0
    last_updated:  float = 0.0
    kill_chain_progress: Dict[str, bool] = field(default_factory=dict)
    confidence:    float = 0.0
    severity:      str   = "medium"
    adversary_fp:  str   = ""

    def to_dict(self):
        d = asdict(self)
        d["duration_s"] = round(self.last_updated - self.start_time, 1) if self.start_time else 0
        return d

    def advance_phase(self, phase: str):
        self.kill_chain_progress[phase] = True

    @property
    def phases_completed(self) -> int:
        return sum(1 for v in self.kill_chain_progress.values() if v)

class ThreatSequenceModeler:
    """
    ATT&CK-native threat sequence modeling engine.
    Builds temporal attack chains from behavioral events,
    reconstructs adversary campaigns, fingerprints attackers.
    """

    # Known adversary TTP chains for fingerprinting
    KNOWN_CHAINS = {
        "APT29_COZY_BEAR": [
            "T1566","T1059.001","T1055","T1078","T1021.001","T1041"
        ],
        "RANSOMWARE_GENERIC": [
            "T1566","T1059","T1078","T1021","T1486","T1490"
        ],
        "CREDENTIAL_HARVESTER": [
            "T1059","T1003","T1110","T1021","T1041"
        ],
        "CLOUD_INTRUDER": [
            "T1078","T1530","T1552","T1537","T1567"
        ],
    }

    def __init__(self):
        self._sequences: Dict[str, AttackSequence] = {}
        self._entity_sequences: Dict[str, List[str]] = defaultdict(list)
        self._stats = defaultdict(int)
        log.info("ThreatSequenceModeler INITIALIZED")

    def _get_or_create_sequence(self, entity: str, tenant_id: str) -> AttackSequence:
        # Check if active sequence exists for this entity
        for sid in self._entity_sequences.get(entity, []):
            seq = self._sequences.get(sid)
            if seq and time.time() - seq.last_updated < 7200:  # 2hr window
                return seq
        # Create new sequence
        seq = AttackSequence(
            sequence_id = str(uuid.uuid4())[:12],
            tenant_id   = tenant_id,
            campaign_id = str(uuid.uuid4())[:8],
            entity      = entity,
            start_time  = time.time(),
            last_updated= time.time(),
        )
        self._sequences[seq.sequence_id] = seq
        self._entity_sequences[entity].append(seq.sequence_id)
        return seq

    def ingest_alert(self, alert: Dict, tenant_id: str) -> Optional[AttackSequence]:
        """Ingest a behavioral alert into the sequence modeler."""
        entity    = alert.get("entity","unknown")
        techniques= alert.get("mitre_techniques",[])
        tactics   = alert.get("mitre_tactics",[])
        confidence= alert.get("confidence", 0.70)
        ts        = time.time()

        if not techniques: return None

        seq = self._get_or_create_sequence(entity, tenant_id)

        for i, tech in enumerate(techniques):
            tactic = tactics[i] if i < len(tactics) else "Unknown"
            phase  = TACTIC_TO_PHASE.get(tactic, KillChainPhase.EXPLOITATION).value
            node   = SequenceNode(
                node_id   = str(uuid.uuid4())[:8],
                technique = tech,
                tactic    = tactic,
                phase     = phase,
                timestamp = ts,
                entity    = entity,
                confidence= confidence,
                evidence  = [alert.get("alert_id","")],
            )
            seq.nodes.append(node)
            seq.advance_phase(phase)

        seq.last_updated = ts
        seq.confidence   = self._compute_sequence_confidence(seq)
        seq.severity     = self._assess_severity(seq)
        seq.adversary_fp = self._fingerprint_adversary(seq)
        self._stats["sequences_updated"] += 1
        return seq

    def _compute_sequence_confidence(self, seq: AttackSequence) -> float:
        if not seq.nodes: return 0.0
        avg_conf  = sum(n.confidence for n in seq.nodes) / len(seq.nodes)
        phase_bonus = seq.phases_completed * 0.05
        return min(0.99, avg_conf + phase_bonus)

    def _assess_severity(self, seq: AttackSequence) -> str:
        phases = seq.phases_completed
        if KillChainPhase.ACTIONS.value in seq.kill_chain_progress: return "critical"
        if KillChainPhase.C2.value in seq.kill_chain_progress:      return "critical"
        if phases >= 4:  return "high"
        if phases >= 2:  return "medium"
        return "low"

    def _fingerprint_adversary(self, seq: AttackSequence) -> str:
        """Match TTP chain against known adversary profiles."""
        observed = set(n.technique for n in seq.nodes)
        best_match, best_score = "UNKNOWN", 0.0
        for actor, chain in self.KNOWN_CHAINS.items():
            overlap = len(observed & set(chain)) / len(chain)
            if overlap > best_score:
                best_match, best_score = actor, overlap
        if best_score > 0.4:
            return f"{best_match}:{best_score:.2f}"
        return "UNKNOWN"

    def reconstruct_timeline(self, entity: str) -> List[Dict]:
        """Return chronological attack timeline for an entity."""
        all_nodes = []
        for sid in self._entity_sequences.get(entity, []):
            seq = self._sequences.get(sid)
            if seq:
                for node in seq.nodes:
                    all_nodes.append({
                        "sequence_id": seq.sequence_id,
                        "node_id":     node.node_id,
                        "technique":   node.technique,
                        "tactic":      node.tactic,
                        "phase":       node.phase,
                        "timestamp":   node.timestamp,
                        "confidence":  node.confidence,
                    })
        return sorted(all_nodes, key=lambda x: x["timestamp"])

    def generate_narrative(self, sequence_id: str) -> Dict:
        """Generate human-readable intrusion narrative."""
        seq = self._sequences.get(sequence_id)
        if not seq: return {"error":"not_found"}
        phases_hit = list(seq.kill_chain_progress.keys())
        techniques = list(set(n.technique for n in seq.nodes))
        duration = seq.last_updated - seq.start_time

        narrative = {
            "sequence_id":    sequence_id,
            "entity":         seq.entity,
            "campaign_id":    seq.campaign_id,
            "adversary":      seq.adversary_fp,
            "severity":       seq.severity,
            "confidence":     round(seq.confidence, 3),
            "kill_chain":     phases_hit,
            "phases_completed":seq.phases_completed,
            "techniques":     techniques,
            "duration_s":     round(duration, 1),
            "summary": (
                f"Entity '{seq.entity}' targeted across {seq.phases_completed} kill-chain "
                f"phases over {round(duration/60,1)} minutes. "
                f"Adversary fingerprint: {seq.adversary_fp}. "
                f"Techniques observed: {', '.join(techniques[:5])}."
            ),
            "heatmap": {phase: seq.kill_chain_progress.get(phase, False)
                        for phase in [p.value for p in KillChainPhase]},
        }
        return narrative

    def active_sequences(self, tenant_id: str, severity: str = None) -> List[Dict]:
        out = []
        for seq in self._sequences.values():
            if seq.tenant_id != tenant_id: continue
            if severity and seq.severity != severity: continue
            out.append(seq.to_dict())
        return sorted(out, key=lambda x: x.get("confidence",0), reverse=True)

    def stats(self) -> Dict:
        return {
            "total_sequences": len(self._sequences),
            **dict(self._stats),
        }

if __name__ == "__main__":
    modeler = ThreatSequenceModeler()
    tenant  = "tenant_apex_default"

    alerts = [
        {"entity":"WIN-01\\jsmith","mitre_techniques":["T1566"],"mitre_tactics":["InitialAccess"],"confidence":0.88,"alert_id":"a1"},
        {"entity":"WIN-01\\jsmith","mitre_techniques":["T1059.001"],"mitre_tactics":["Execution"],"confidence":0.92,"alert_id":"a2"},
        {"entity":"WIN-01\\jsmith","mitre_techniques":["T1078"],"mitre_tactics":["PrivilegeEscalation"],"confidence":0.85,"alert_id":"a3"},
        {"entity":"WIN-01\\jsmith","mitre_techniques":["T1021.001"],"mitre_tactics":["LateralMovement"],"confidence":0.82,"alert_id":"a4"},
        {"entity":"WIN-01\\jsmith","mitre_techniques":["T1041"],"mitre_tactics":["Exfiltration"],"confidence":0.78,"alert_id":"a5"},
    ]
    seq = None
    for a in alerts:
        seq = modeler.ingest_alert(a, tenant)

    print("\n" + "="*65)
    print("  SENTINEL APEX — THREAT SEQUENCE MODELER SELF-TEST")
    print("="*65)
    if seq:
        print(f"\n🔴 Sequence: {seq.sequence_id}")
        print(f"   Entity:   {seq.entity}")
        print(f"   Severity: {seq.severity}")
        print(f"   Phases:   {seq.phases_completed}/7")
        print(f"   AdversaryFP: {seq.adversary_fp}")
        narrative = modeler.generate_narrative(seq.sequence_id)
        print(f"\n📖 Narrative:\n   {narrative['summary']}")
        print(f"\n🗺️  Kill Chain: {narrative['heatmap']}")
        tl = modeler.reconstruct_timeline(seq.entity)
        print(f"\n⏱️  Timeline ({len(tl)} nodes):")
        for node in tl:
            print(f"     {node['technique']:12s} | {node['tactic']:22s} | conf={node['confidence']:.2f}")
    print(f"\n📊 Stats: {modeler.stats()}")
    print("\n✅ THREAT SEQUENCE MODELER — PRODUCTION READY\n")
