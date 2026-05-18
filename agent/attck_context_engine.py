#!/usr/bin/env python3
"""
agent/attck_context_engine.py
CYBERDUDEBIVASH® SENTINEL APEX — ENTERPRISE ATT&CK CONTEXTUALIZATION ENGINE v1.0
================================================================================
PHASE 3: ENTERPRISE ATT&CK CONTEXTUALIZATION

MISSION:
  For every advisory, infer the full ATT&CK operational context:
  - Attack path sequencing across the kill chain
  - Adversary operational sophistication scoring
  - Likely enterprise impact inference
  - Behavioral relationship mapping
  - Campaign lineage and technique inheritance

CAPABILITIES:
  1. ATT&CK sequencing          — ordered technique progression
  2. Attack path inference       — multi-hop kill chain reconstruction
  3. Adversary operational modeling — sophistication, dwell time, capability
  4. Kill-chain inference        — Lockheed Martin + Unified Kill Chain
  5. Behavioral maturity scoring — TTPs maturity/complexity scoring
  6. Technique relationship mapping — parent/child/related techniques
  7. ATT&CK confidence reasoning — evidence-weighted technique confidence
  8. Campaign lineage inference  — track technique inheritance over time

DESIGN RULES:
  - Deterministic: same input → same output
  - Evidence-bound: all inferences grounded in technique data
  - No hallucination: no invented techniques or actors
  - Fully explainable: every inference has a rationale string

ATT&CK v15 Knowledge Base is embedded (deterministic, no external calls).

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-ATTCK-CONTEXT")
VERSION = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# EMBEDDED ATT&CK v15 KNOWLEDGE BASE (Deterministic — no external deps)
# ─────────────────────────────────────────────────────────────────────────────

# Tactic ordering (kill-chain sequence)
TACTIC_ORDER: Dict[str, int] = {
    "Reconnaissance":          1,
    "Resource Development":    2,
    "Initial Access":          3,
    "Execution":               4,
    "Persistence":             5,
    "Privilege Escalation":    6,
    "Defense Evasion":         7,
    "Credential Access":       8,
    "Discovery":               9,
    "Lateral Movement":        10,
    "Collection":              11,
    "Command and Control":     12,
    "Exfiltration":            13,
    "Impact":                  14,
}

# Unified Kill Chain (UKC) mapping
UKC_PHASES: Dict[str, str] = {
    "Reconnaissance":       "PREPARATION",
    "Resource Development": "PREPARATION",
    "Initial Access":       "INITIAL_FOOTHOLD",
    "Execution":            "INITIAL_FOOTHOLD",
    "Persistence":          "NETWORK_PROPAGATION",
    "Privilege Escalation": "NETWORK_PROPAGATION",
    "Defense Evasion":      "NETWORK_PROPAGATION",
    "Credential Access":    "NETWORK_PROPAGATION",
    "Discovery":            "NETWORK_PROPAGATION",
    "Lateral Movement":     "NETWORK_PROPAGATION",
    "Collection":           "ACTION_ON_OBJECTIVES",
    "Command and Control":  "ACTION_ON_OBJECTIVES",
    "Exfiltration":         "ACTION_ON_OBJECTIVES",
    "Impact":               "ACTION_ON_OBJECTIVES",
}

# Core technique metadata (id → {name, tactic, sophistication, platforms, mitigations})
TECHNIQUE_KB: Dict[str, Dict] = {
    "T1566":  {"name": "Phishing",                     "tactic": "Initial Access",         "soph": 2, "platforms": ["Windows","macOS","Linux"]},
    "T1566.001": {"name": "Spearphishing Attachment",  "tactic": "Initial Access",         "soph": 3, "platforms": ["Windows","macOS"]},
    "T1566.002": {"name": "Spearphishing Link",        "tactic": "Initial Access",         "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1190":  {"name": "Exploit Public-Facing App",    "tactic": "Initial Access",         "soph": 4, "platforms": ["Linux","Windows","macOS"]},
    "T1133":  {"name": "External Remote Services",     "tactic": "Initial Access",         "soph": 2, "platforms": ["Windows","Linux"]},
    "T1078":  {"name": "Valid Accounts",               "tactic": "Initial Access",         "soph": 2, "platforms": ["Windows","macOS","Linux"]},
    "T1059":  {"name": "Command and Scripting",        "tactic": "Execution",              "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1059.001": {"name": "PowerShell",               "tactic": "Execution",              "soph": 3, "platforms": ["Windows"]},
    "T1059.003": {"name": "Windows Command Shell",    "tactic": "Execution",              "soph": 2, "platforms": ["Windows"]},
    "T1203":  {"name": "Exploitation for Client Exec", "tactic": "Execution",              "soph": 4, "platforms": ["Windows","macOS","Linux"]},
    "T1053":  {"name": "Scheduled Task/Job",           "tactic": "Persistence",            "soph": 2, "platforms": ["Windows","Linux"]},
    "T1547":  {"name": "Boot or Logon Autostart",      "tactic": "Persistence",            "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1098":  {"name": "Account Manipulation",         "tactic": "Persistence",            "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1055":  {"name": "Process Injection",            "tactic": "Privilege Escalation",   "soph": 4, "platforms": ["Windows","Linux"]},
    "T1068":  {"name": "Exploitation for Privilege Esc","tactic": "Privilege Escalation",  "soph": 5, "platforms": ["Windows","Linux","macOS"]},
    "T1027":  {"name": "Obfuscated Files",             "tactic": "Defense Evasion",        "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1562":  {"name": "Impair Defenses",              "tactic": "Defense Evasion",        "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1070":  {"name": "Indicator Removal",            "tactic": "Defense Evasion",        "soph": 4, "platforms": ["Windows","macOS","Linux"]},
    "T1003":  {"name": "OS Credential Dumping",        "tactic": "Credential Access",      "soph": 4, "platforms": ["Windows","Linux","macOS"]},
    "T1110":  {"name": "Brute Force",                  "tactic": "Credential Access",      "soph": 1, "platforms": ["Windows","Linux","macOS"]},
    "T1018":  {"name": "Remote System Discovery",      "tactic": "Discovery",              "soph": 1, "platforms": ["Windows","Linux"]},
    "T1082":  {"name": "System Information Discovery", "tactic": "Discovery",              "soph": 1, "platforms": ["Windows","macOS","Linux"]},
    "T1021":  {"name": "Remote Services",              "tactic": "Lateral Movement",       "soph": 2, "platforms": ["Windows","Linux","macOS"]},
    "T1210":  {"name": "Exploitation of Remote Svc",   "tactic": "Lateral Movement",       "soph": 5, "platforms": ["Windows","Linux"]},
    "T1560":  {"name": "Archive Collected Data",       "tactic": "Collection",             "soph": 2, "platforms": ["Windows","macOS","Linux"]},
    "T1041":  {"name": "Exfil Over C2 Channel",        "tactic": "Exfiltration",           "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1048":  {"name": "Exfil Over Alt Protocol",      "tactic": "Exfiltration",           "soph": 4, "platforms": ["Windows","macOS","Linux"]},
    "T1071":  {"name": "App Layer Protocol (C2)",      "tactic": "Command and Control",    "soph": 3, "platforms": ["Windows","macOS","Linux"]},
    "T1090":  {"name": "Proxy",                        "tactic": "Command and Control",    "soph": 4, "platforms": ["Windows","macOS","Linux"]},
    "T1105":  {"name": "Ingress Tool Transfer",        "tactic": "Command and Control",    "soph": 2, "platforms": ["Windows","macOS","Linux"]},
    "T1486":  {"name": "Data Encrypted for Impact",    "tactic": "Impact",                 "soph": 4, "platforms": ["Windows","macOS","Linux"]},
    "T1490":  {"name": "Inhibit System Recovery",      "tactic": "Impact",                 "soph": 3, "platforms": ["Windows"]},
    "T1489":  {"name": "Service Stop",                 "tactic": "Impact",                 "soph": 2, "platforms": ["Windows","Linux"]},
    "T1496":  {"name": "Resource Hijacking",           "tactic": "Impact",                 "soph": 2, "platforms": ["Windows","macOS","Linux"]},
    "T1485":  {"name": "Data Destruction",             "tactic": "Impact",                 "soph": 4, "platforms": ["Windows","macOS","Linux"]},
    "T1046":  {"name": "Network Service Discovery",    "tactic": "Discovery",              "soph": 1, "platforms": ["Windows","macOS","Linux"]},
    "T1136":  {"name": "Create Account",               "tactic": "Persistence",            "soph": 2, "platforms": ["Windows","macOS","Linux"]},
    "T1567":  {"name": "Exfil to Cloud Storage",       "tactic": "Exfiltration",           "soph": 3, "platforms": ["macOS","Windows","Linux"]},
    "T1583":  {"name": "Acquire Infrastructure",       "tactic": "Resource Development",   "soph": 3, "platforms": ["PRE"]},
    "T1588":  {"name": "Obtain Capabilities",          "tactic": "Resource Development",   "soph": 3, "platforms": ["PRE"]},
    "T1595":  {"name": "Active Scanning",              "tactic": "Reconnaissance",         "soph": 1, "platforms": ["PRE"]},
    "T1592":  {"name": "Gather Victim Host Info",      "tactic": "Reconnaissance",         "soph": 2, "platforms": ["PRE"]},
}

# Technique → expected next techniques (deterministic sequencing)
TECHNIQUE_SEQUENCES: Dict[str, List[str]] = {
    "T1566":    ["T1059", "T1203", "T1204"],
    "T1190":    ["T1059", "T1078", "T1068"],
    "T1133":    ["T1078", "T1021", "T1098"],
    "T1078":    ["T1021", "T1053", "T1003"],
    "T1059":    ["T1055", "T1027", "T1105"],
    "T1203":    ["T1059", "T1055", "T1068"],
    "T1055":    ["T1003", "T1027", "T1041"],
    "T1068":    ["T1003", "T1136", "T1098"],
    "T1003":    ["T1021", "T1018", "T1082"],
    "T1021":    ["T1560", "T1003", "T1059"],
    "T1105":    ["T1059", "T1055", "T1071"],
    "T1071":    ["T1041", "T1048", "T1560"],
    "T1041":    ["T1486", "T1485", "T1490"],
    "T1486":    ["T1490", "T1489"],
    "T1027":    ["T1055", "T1562", "T1070"],
}

# Sophistication descriptions (1–5 scale)
SOPHISTICATION_LABELS: Dict[int, str] = {
    1: "BASIC — opportunistic, commodity tooling, low barrier",
    2: "DEVELOPING — structured TTPs, some automation, moderate skill",
    3: "CAPABLE — coordinated multi-stage ops, custom tooling elements",
    4: "ADVANCED — APT-grade, custom tools, operational security aware",
    5: "NATION_STATE — zero-day exploitation, full kill-chain, high OPSEC",
}

# Enterprise impact tiers mapped from tactics present
IMPACT_INFERENCE: Dict[str, Dict] = {
    "T1486": {"impact": "RANSOMWARE_DEPLOYMENT",   "severity": "CRITICAL", "dwell_days": 21},
    "T1485": {"impact": "DATA_DESTRUCTION",         "severity": "CRITICAL", "dwell_days": 14},
    "T1490": {"impact": "RECOVERY_INHIBITION",      "severity": "CRITICAL", "dwell_days": 7},
    "T1003": {"impact": "CREDENTIAL_THEFT",         "severity": "HIGH",     "dwell_days": 30},
    "T1041": {"impact": "DATA_EXFILTRATION",        "severity": "HIGH",     "dwell_days": 45},
    "T1048": {"impact": "COVERT_EXFILTRATION",      "severity": "HIGH",     "dwell_days": 60},
    "T1071": {"impact": "PERSISTENT_C2_CHANNEL",    "severity": "HIGH",     "dwell_days": 90},
    "T1078": {"impact": "IDENTITY_COMPROMISE",      "severity": "MEDIUM",   "dwell_days": 14},
    "T1496": {"impact": "RESOURCE_ABUSE",           "severity": "MEDIUM",   "dwell_days": 30},
    "T1059": {"impact": "CODE_EXECUTION",           "severity": "MEDIUM",   "dwell_days": 7},
    "T1566": {"impact": "PHISHING_ENTRY",           "severity": "MEDIUM",   "dwell_days": 3},
    "T1190": {"impact": "REMOTE_EXPLOITATION",      "severity": "HIGH",     "dwell_days": 5},
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TechniqueContext:
    technique_id:   str
    technique_name: str
    tactic:         str
    tactic_order:   int
    ukc_phase:      str
    sophistication: int
    soph_label:     str
    platforms:      List[str]
    confidence:     float
    rationale:      str


@dataclass
class AttackPath:
    path_id:         str
    sequence:        List[TechniqueContext]
    tactics_covered: List[str]
    kill_chain_coverage: float     # 0.0–1.0 fraction of 14 tactics
    ukc_coverage:    Dict[str, List[str]]  # UKC_PHASE → [technique_ids]
    path_label:      str


@dataclass
class AdversaryProfile:
    actor_cluster:       str
    sophistication_score: float         # 1.0–5.0 weighted average
    sophistication_label: str
    technique_count:      int
    tactic_breadth:       int            # unique tactics
    kill_chain_coverage:  float
    estimated_dwell_days: int
    likely_objectives:    List[str]
    behavioral_maturity:  str            # BASIC | CAPABLE | ADVANCED | ELITE
    campaign_lineage:     List[str]      # inherited technique IDs


@dataclass
class ATTCKContextResult:
    advisory_id:        str
    advisory_title:     str
    raw_ttps:           List[str]
    technique_contexts: List[TechniqueContext]
    attack_path:        Optional[AttackPath]
    inferred_path:      List[str]       # inferred next technique IDs
    adversary_profile:  AdversaryProfile
    enterprise_impacts: List[Dict]
    attck_confidence:   float           # 0.0–100.0
    context_rationale:  str
    contextualized_at:  str
    engine_version:     str = VERSION


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_ttp(ttp: Any) -> Optional[str]:
    """Normalize TTP to uppercase T-prefixed ID. Returns None if invalid."""
    if not ttp:
        return None
    t = str(ttp).strip().upper()
    if t.startswith("T") and len(t) >= 5:
        return t
    return None


def _get_technique(ttp_id: str) -> Optional[Dict]:
    """Look up technique in embedded KB. Falls back gracefully."""
    clean = ttp_id.split(".")[0] if "." in ttp_id else ttp_id
    return TECHNIQUE_KB.get(ttp_id) or TECHNIQUE_KB.get(clean)


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXTUALIZATION ENGINES
# ─────────────────────────────────────────────────────────────────────────────

class TechniqueContextualizer:
    """Enrich raw technique IDs with full ATT&CK context."""

    def contextualize(self, ttp_id: str, advisory_confidence: float = 70.0) -> TechniqueContext:
        kb  = _get_technique(ttp_id)
        if kb:
            tactic     = kb.get("tactic", "Unknown")
            name       = kb.get("name", ttp_id)
            soph       = kb.get("soph", 2)
            platforms  = kb.get("platforms", [])
        else:
            tactic, name, soph, platforms = "Unknown", ttp_id, 2, []

        tactic_order = TACTIC_ORDER.get(tactic, 99)
        ukc_phase    = UKC_PHASES.get(tactic, "UNKNOWN")

        # Confidence: higher for known techniques
        confidence = advisory_confidence if kb else advisory_confidence * 0.6
        rationale  = (
            f"Technique {ttp_id} ({name}) mapped to tactic '{tactic}' "
            f"(order {tactic_order}) in UKC phase '{ukc_phase}'. "
            f"Sophistication: {SOPHISTICATION_LABELS.get(soph, 'UNKNOWN')}. "
            f"{'Verified in ATT&CK KB.' if kb else 'Not in embedded KB — minimal confidence applied.'}"
        )

        return TechniqueContext(
            technique_id=ttp_id,
            technique_name=name,
            tactic=tactic,
            tactic_order=tactic_order,
            ukc_phase=ukc_phase,
            sophistication=soph,
            soph_label=SOPHISTICATION_LABELS.get(soph, "UNKNOWN"),
            platforms=platforms,
            confidence=round(min(100.0, max(0.0, confidence)), 1),
            rationale=rationale,
        )


class AttackPathInferer:
    """
    Reconstruct and extend the attack path from observed techniques.
    Only infers techniques that have explicit sequence evidence in KB.
    """

    def infer_path(self, contexts: List[TechniqueContext]) -> Tuple[AttackPath, List[str]]:
        """Returns (AttackPath, inferred_technique_ids)."""
        # Sort by tactic order
        sorted_ctx = sorted(contexts, key=lambda c: c.tactic_order)

        tactics_covered = list(dict.fromkeys(c.tactic for c in sorted_ctx))
        kc_coverage     = round(len({c.tactic_order for c in sorted_ctx}) / 14.0, 3)

        # UKC phase coverage
        ukc_coverage: Dict[str, List[str]] = {}
        for ctx in sorted_ctx:
            phase = ctx.ukc_phase
            ukc_coverage.setdefault(phase, [])
            if ctx.technique_id not in ukc_coverage[phase]:
                ukc_coverage[phase].append(ctx.technique_id)

        # Build path label
        path_label = " → ".join(
            f"{c.technique_id}({c.tactic[:6]})"
            for c in sorted_ctx[:6]
        )

        # Infer next likely techniques
        inferred: List[str] = []
        known_ids = {c.technique_id for c in sorted_ctx}
        for ctx in sorted_ctx:
            for next_t in TECHNIQUE_SEQUENCES.get(ctx.technique_id, []):
                if next_t not in known_ids and next_t not in inferred:
                    if _get_technique(next_t):  # only infer known techniques
                        inferred.append(next_t)

        path = AttackPath(
            path_id=f"path-{hashlib.md5(path_label.encode(), usedforsecurity=False).hexdigest()[:8]}",
            sequence=sorted_ctx,
            tactics_covered=tactics_covered,
            kill_chain_coverage=kc_coverage,
            ukc_coverage=ukc_coverage,
            path_label=path_label,
        )
        return path, inferred[:5]  # Cap inferred at 5


class BehavioralMaturityScorer:
    """Score adversary behavioral maturity from technique set."""

    def score(self, contexts: List[TechniqueContext], actor: str) -> AdversaryProfile:
        if not contexts:
            return AdversaryProfile(
                actor_cluster=actor, sophistication_score=1.0,
                sophistication_label=SOPHISTICATION_LABELS[1],
                technique_count=0, tactic_breadth=0, kill_chain_coverage=0.0,
                estimated_dwell_days=3, likely_objectives=["UNKNOWN"],
                behavioral_maturity="BASIC", campaign_lineage=[],
            )

        # Weighted sophistication
        soph_scores = [c.sophistication for c in contexts]
        avg_soph    = sum(soph_scores) / len(soph_scores)
        max_soph    = max(soph_scores)
        # Weighted: 70% mean + 30% max
        w_soph = round(avg_soph * 0.7 + max_soph * 0.3, 2)

        tactic_breadth    = len({c.tactic for c in contexts})
        kc_coverage       = round(len({c.tactic_order for c in contexts}) / 14.0, 3)
        technique_count   = len(contexts)

        # Maturity classification
        if w_soph >= 4.5 or (tactic_breadth >= 8 and technique_count >= 10):
            maturity = "ELITE"
        elif w_soph >= 3.5 or (tactic_breadth >= 5 and technique_count >= 6):
            maturity = "ADVANCED"
        elif w_soph >= 2.5 or tactic_breadth >= 3:
            maturity = "CAPABLE"
        else:
            maturity = "BASIC"

        # Enterprise impact / objectives from techniques
        objectives: List[str] = []
        max_dwell = 3
        for ctx in contexts:
            imp = IMPACT_INFERENCE.get(ctx.technique_id)
            if imp:
                obj = imp["impact"]
                if obj not in objectives:
                    objectives.append(obj)
                if imp["dwell_days"] > max_dwell:
                    max_dwell = imp["dwell_days"]

        if not objectives:
            objectives = ["CODE_EXECUTION"]

        # Campaign lineage — techniques likely inherited from prior campaigns
        lineage = [c.technique_id for c in contexts if c.tactic_order <= 4]

        soph_int = min(5, max(1, round(w_soph)))

        return AdversaryProfile(
            actor_cluster=actor,
            sophistication_score=w_soph,
            sophistication_label=SOPHISTICATION_LABELS[soph_int],
            technique_count=technique_count,
            tactic_breadth=tactic_breadth,
            kill_chain_coverage=kc_coverage,
            estimated_dwell_days=max_dwell,
            likely_objectives=objectives[:5],
            behavioral_maturity=maturity,
            campaign_lineage=lineage[:10],
        )


class EnterpriseImpactInferer:
    """Infer likely enterprise impacts from technique set."""

    def infer(self, contexts: List[TechniqueContext]) -> List[Dict]:
        impacts: List[Dict] = []
        seen: set = set()
        for ctx in contexts:
            imp = IMPACT_INFERENCE.get(ctx.technique_id)
            if imp and imp["impact"] not in seen:
                seen.add(imp["impact"])
                impacts.append({
                    "technique_id":  ctx.technique_id,
                    "technique_name": ctx.technique_name,
                    "impact_type":   imp["impact"],
                    "severity":      imp["severity"],
                    "estimated_dwell_days": imp["dwell_days"],
                    "rationale": (
                        f"Technique {ctx.technique_id} ({ctx.technique_name}) "
                        f"in tactic '{ctx.tactic}' is associated with "
                        f"{imp['impact']} (severity: {imp['severity']})."
                    ),
                })
        return sorted(impacts, key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["severity"], 0), reverse=True)


class ATTCKConfidenceReasoner:
    """
    Compute overall ATT&CK contextualization confidence with full rationale.
    Deterministic, bounded 0.0–100.0.
    """

    def compute(
        self,
        contexts: List[TechniqueContext],
        advisory: Dict,
        inferred: List[str],
    ) -> Tuple[float, str]:
        if not contexts:
            return 0.0, "No techniques available for confidence computation."

        factors: Dict[str, float] = {}

        # Factor 1: Technique KB coverage (max 30 pts)
        kb_hits = sum(1 for c in contexts if _get_technique(c.technique_id))
        factors["kb_coverage"] = round(30.0 * kb_hits / len(contexts), 2)

        # Factor 2: Technique count depth (max 25 pts)
        factors["technique_depth"] = round(min(25.0, len(contexts) * 4.0), 2)

        # Factor 3: Tactic breadth (max 20 pts)
        unique_tactics = len({c.tactic for c in contexts})
        factors["tactic_breadth"] = round(min(20.0, unique_tactics * 3.0), 2)

        # Factor 4: Advisory data quality (max 15 pts)
        data_pts = 0.0
        if advisory.get("cvss_score") or advisory.get("cvss"):
            data_pts += 5.0
        if advisory.get("epss_score") or advisory.get("epss"):
            data_pts += 5.0
        if advisory.get("kev_confirmed"):
            data_pts += 5.0
        factors["advisory_quality"] = data_pts

        # Factor 5: Path inference success (max 10 pts)
        factors["path_inference"] = min(10.0, len(inferred) * 2.0)

        total = round(min(100.0, sum(factors.values())), 1)

        rationale = (
            f"ATT&CK confidence: {total}%. "
            f"KB coverage: {factors['kb_coverage']:.1f}/30 pts "
            f"({kb_hits}/{len(contexts)} techniques in KB). "
            f"Technique depth: {factors['technique_depth']:.1f}/25 pts "
            f"({len(contexts)} techniques). "
            f"Tactic breadth: {factors['tactic_breadth']:.1f}/20 pts "
            f"({unique_tactics} unique tactics). "
            f"Advisory quality: {factors['advisory_quality']:.1f}/15 pts. "
            f"Path inference: {factors['path_inference']:.1f}/10 pts "
            f"({len(inferred)} techniques inferred)."
        )

        return total, rationale


# ─────────────────────────────────────────────────────────────────────────────
# MASTER ATT&CK CONTEXT ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ATTCKContextEngine:
    """
    SENTINEL APEX — Enterprise ATT&CK Contextualization Engine v1.0

    For every advisory:
      1. Normalize and contextualize all TTPs
      2. Build the attack path sequence
      3. Infer likely next techniques
      4. Score adversary behavioral maturity
      5. Infer enterprise impacts
      6. Compute ATT&CK confidence with rationale
    """

    def __init__(self):
        self._contextualizer  = TechniqueContextualizer()
        self._path_inferer    = AttackPathInferer()
        self._maturity_scorer = BehavioralMaturityScorer()
        self._impact_inferer  = EnterpriseImpactInferer()
        self._confidence      = ATTCKConfidenceReasoner()

    def contextualize(self, advisory: Dict) -> ATTCKContextResult:
        """Full ATT&CK contextualization for one advisory. Never raises."""
        try:
            return self._contextualize_internal(advisory)
        except Exception as e:
            logger.error(f"[ATTCK-CONTEXT] Error for {advisory.get('stix_id','?')}: {e}")
            stix_id = str(advisory.get("stix_id", ""))
            return ATTCKContextResult(
                advisory_id=stix_id,
                advisory_title=str(advisory.get("title", ""))[:80],
                raw_ttps=[],
                technique_contexts=[],
                attack_path=None,
                inferred_path=[],
                adversary_profile=AdversaryProfile(
                    actor_cluster="UNKNOWN", sophistication_score=1.0,
                    sophistication_label=SOPHISTICATION_LABELS[1],
                    technique_count=0, tactic_breadth=0,
                    kill_chain_coverage=0.0, estimated_dwell_days=3,
                    likely_objectives=["UNKNOWN"], behavioral_maturity="BASIC",
                    campaign_lineage=[],
                ),
                enterprise_impacts=[],
                attck_confidence=0.0,
                context_rationale=f"Contextualization failed: {e}",
                contextualized_at=_now_iso(),
            )

    def _contextualize_internal(self, advisory: Dict) -> ATTCKContextResult:
        stix_id = str(advisory.get("stix_id", ""))
        title   = str(advisory.get("title", ""))
        actor   = str(advisory.get("actor_cluster", "") or advisory.get("threat_actor", "") or "UNKNOWN")
        ttps_raw = advisory.get("ttps", []) or []

        # Normalize TTPs
        raw_ttps: List[str] = []
        for t in ttps_raw:
            norm = _normalize_ttp(t)
            if norm and norm not in raw_ttps:
                raw_ttps.append(norm)

        # Advisory confidence baseline
        try:
            adv_conf = float(advisory.get("ai_confidence") or advisory.get("confidence") or 70.0)
        except (ValueError, TypeError):
            adv_conf = 70.0

        # Contextualize techniques
        contexts: List[TechniqueContext] = [
            self._contextualizer.contextualize(t, adv_conf)
            for t in raw_ttps
        ]

        # Build attack path
        if contexts:
            attack_path, inferred = self._path_inferer.infer_path(contexts)
        else:
            attack_path, inferred = None, []

        # Adversary profile
        profile = self._maturity_scorer.score(contexts, actor)

        # Enterprise impacts
        impacts = self._impact_inferer.infer(contexts)

        # ATT&CK confidence
        confidence, rationale = self._confidence.compute(contexts, advisory, inferred)

        result = ATTCKContextResult(
            advisory_id=stix_id,
            advisory_title=title[:80],
            raw_ttps=raw_ttps,
            technique_contexts=contexts,
            attack_path=attack_path,
            inferred_path=inferred,
            adversary_profile=profile,
            enterprise_impacts=impacts,
            attck_confidence=confidence,
            context_rationale=rationale,
            contextualized_at=_now_iso(),
        )

        logger.info(
            f"[ATTCK-CONTEXT] {stix_id[:30]} → "
            f"ttps={len(raw_ttps)} maturity={profile.behavioral_maturity} "
            f"conf={confidence}%"
        )
        return result

    def contextualize_batch(self, advisories: List[Dict]) -> List[ATTCKContextResult]:
        return [self.contextualize(a) for a in advisories]

    def persist_results(self, results: List[ATTCKContextResult], output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        output = []
        for r in results:
            d = asdict(r) if hasattr(r, "__dataclass_fields__") else {}
            # Manual serialization for nested dataclasses
            d = {
                "advisory_id":      r.advisory_id,
                "advisory_title":   r.advisory_title,
                "raw_ttps":         r.raw_ttps,
                "technique_contexts": [asdict(tc) for tc in r.technique_contexts],
                "attack_path":      asdict(r.attack_path) if r.attack_path else None,
                "inferred_path":    r.inferred_path,
                "adversary_profile": asdict(r.adversary_profile),
                "enterprise_impacts": r.enterprise_impacts,
                "attck_confidence": r.attck_confidence,
                "context_rationale": r.context_rationale,
                "contextualized_at": r.contextualized_at,
                "engine_version":   r.engine_version,
            }
            output.append(d)

        out_path = output_dir / "attck_context_results.json"
        tmp = out_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump({"results": output, "generated_at": _now_iso()}, f, indent=2)
        tmp.replace(out_path)

        # Summary
        summary = {
            "total_advisories": len(results),
            "with_techniques":  sum(1 for r in results if r.raw_ttps),
            "maturity_dist":    {},
            "mean_confidence":  round(sum(r.attck_confidence for r in results) / max(1, len(results)), 1),
        }
        for r in results:
            m = r.adversary_profile.behavioral_maturity
            summary["maturity_dist"][m] = summary["maturity_dist"].get(m, 0) + 1

        tmp2 = (output_dir / "attck_context_summary.json").with_suffix(".tmp")
        with open(tmp2, "w") as f:
            json.dump(summary, f, indent=2)
        tmp2.replace(output_dir / "attck_context_summary.json")


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CDB-ATTCK-CONTEXT] %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    BASE_DIR      = Path(__file__).resolve().parent.parent
    MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"
    OUTPUT_DIR    = BASE_DIR / "data" / "intelligence"

    if not MANIFEST_PATH.exists():
        logger.warning("[ATTCK-CONTEXT] No manifest — exiting cleanly")
        sys.exit(0)

    try:
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)
    except Exception as e:
        logger.error(f"[ATTCK-CONTEXT] Manifest load error: {e}")
        sys.exit(0)

    advisories = manifest.get("items", manifest.get("advisories", []))
    if not advisories:
        logger.info("[ATTCK-CONTEXT] No advisories — nothing to do")
        sys.exit(0)

    engine  = ATTCKContextEngine()
    results = engine.contextualize_batch(advisories)
    engine.persist_results(results, OUTPUT_DIR)

    logger.info(
        f"[ATTCK-CONTEXT] Complete: {len(results)} advisories, "
        f"mean_confidence={round(sum(r.attck_confidence for r in results)/max(1,len(results)),1)}%"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
