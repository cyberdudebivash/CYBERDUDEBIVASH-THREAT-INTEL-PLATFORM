#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — AI-SPM Assessment Toolkit v143.0.0       ║
║  AI Security Posture Management — MITRE ATLAS + NIST AI RMF Engine         ║
║  Phase IV Asset 6 — $299/kit (Gumroad/Direct Store)                       ║
║                                                                              ║
║  Coverage:                                                                   ║
║    • MITRE ATLAS v4.0 (ML Attack Lifecycle + AI-specific TTPs)             ║
║    • NIST AI RMF v1.0 (Govern, Map, Measure, Manage)                       ║
║    • OWASP ML Top 10 risk alignment                                         ║
║    • LLM Security Defense Checklist (OWASP LLM Top 10)                    ║
║    • Adversarial ML risk scoring                                            ║
║    • Model governance posture scoring (0–100)                              ║
║                                                                              ║
║  Output: JSON scorecard + PDF-ready text report                            ║
║  CLI: python scripts/ai_spm_assessment.py --target-profile <yaml>          ║
║       python scripts/ai_spm_assessment.py --quick-scan --output report.json║
║                                                                              ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT     = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"
OUT_DIR  = ROOT / "data" / "ai_spm"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TOOLKIT_VERSION = "143.0.0"
GSTIN           = "21ARKPN8270G1ZP"
PRICE_USD       = 299

# ── MITRE ATLAS Technique Catalog (v4.0 subset, AI/ML focused) ────────────────

ATLAS_TECHNIQUES: Dict[str, Dict] = {
    "AML.T0043": {
        "name": "Craft Adversarial Data",
        "tactic": "ML Attack Staging",
        "description": "Adversary crafts inputs to cause mispredictions in ML models.",
        "severity": "HIGH",
        "controls": ["Input validation", "Adversarial robustness training", "Ensemble defense"],
        "mitre_parent": "T1583",
    },
    "AML.T0018": {
        "name": "Backdoor ML Model",
        "tactic": "Persistence",
        "description": "Trojan/backdoor inserted during training via poisoned dataset.",
        "severity": "CRITICAL",
        "controls": ["Training data provenance", "Model integrity checks", "Clean-label defense"],
        "mitre_parent": "T1195",
    },
    "AML.T0031": {
        "name": "Erode ML Model Integrity",
        "tactic": "Impact",
        "description": "Degrade model performance via targeted poisoning over time.",
        "severity": "HIGH",
        "controls": ["Continuous model monitoring", "Drift detection", "Model versioning"],
        "mitre_parent": "T1565",
    },
    "AML.T0016": {
        "name": "Obtain ML Artifacts",
        "tactic": "ML Attack Staging",
        "description": "Acquire model weights, training data, or hyperparameters for downstream attack.",
        "severity": "HIGH",
        "controls": ["Model artifact encryption", "Access control on model registry", "API rate limiting"],
        "mitre_parent": "T1588",
    },
    "AML.T0035": {
        "name": "ML Model Inference API Access",
        "tactic": "Discovery",
        "description": "Query production inference APIs to extract model internals via model extraction.",
        "severity": "MEDIUM",
        "controls": ["Query rate limiting", "Watermarking", "Confidence score truncation"],
        "mitre_parent": "T1590",
    },
    "AML.T0040": {
        "name": "ML Model Inversion Attack",
        "tactic": "Exfiltration",
        "description": "Reconstruct training data from model outputs — privacy violation.",
        "severity": "HIGH",
        "controls": ["Differential privacy", "Output perturbation", "Membership inference defense"],
        "mitre_parent": "T1530",
    },
    "AML.T0034": {
        "name": "Membership Inference Attack",
        "tactic": "Discovery",
        "description": "Determine if specific data was in the training set.",
        "severity": "MEDIUM",
        "controls": ["Differential privacy", "Aggregated outputs only", "Shadow model defense"],
        "mitre_parent": "T1530",
    },
    "AML.T0048": {
        "name": "LLM Prompt Injection",
        "tactic": "Execution",
        "description": "Malicious prompts override LLM system instructions to exfiltrate data or execute unintended actions.",
        "severity": "CRITICAL",
        "controls": ["Prompt sanitization", "Output filtering", "Instruction hierarchy enforcement", "Sandboxed execution"],
        "mitre_parent": "T1059",
    },
    "AML.T0051": {
        "name": "LLM Jailbreak",
        "tactic": "Defense Evasion",
        "description": "Circumvent LLM safety guardrails via adversarial prompting.",
        "severity": "HIGH",
        "controls": ["Guardrail layers", "Constitutional AI enforcement", "Red-team continuous evaluation"],
        "mitre_parent": "T1548",
    },
    "AML.T0054": {
        "name": "LLM Data Exfiltration via Inference",
        "tactic": "Exfiltration",
        "description": "Use LLM reasoning to exfiltrate sensitive context from system prompts or tool outputs.",
        "severity": "CRITICAL",
        "controls": ["Output scanning", "Tool call auditing", "Sensitive data masking in context"],
        "mitre_parent": "T1567",
    },
    "AML.T0044": {
        "name": "Supply Chain Compromise of ML Pipeline",
        "tactic": "Initial Access",
        "description": "Compromise model registry, dataset repo, or training dependency.",
        "severity": "CRITICAL",
        "controls": ["SCA on ML dependencies", "Signed model artifacts", "Provenance tracking"],
        "mitre_parent": "T1195.002",
    },
    "AML.T0036": {
        "name": "Evasion via Feature Space Manipulation",
        "tactic": "Defense Evasion",
        "description": "Craft inputs that exploit decision boundary gaps to evade detection models.",
        "severity": "HIGH",
        "controls": ["Adversarial training", "Feature squeezing", "Certified robustness"],
        "mitre_parent": "T1036",
    },
}

# ── NIST AI RMF Function Domains ──────────────────────────────────────────────

NIST_AI_RMF_DOMAINS: Dict[str, Dict] = {
    "GOVERN": {
        "description": "Establish AI risk governance: policies, accountability, culture.",
        "subcategories": {
            "GOV-1.1": "AI risk policies documented and approved by leadership.",
            "GOV-1.2": "AI risk roles and responsibilities defined (AI Risk Officer, etc.).",
            "GOV-2.1": "Accountability mechanisms in place for AI system decisions.",
            "GOV-3.1": "Organizational culture encourages AI risk disclosure.",
            "GOV-4.1": "AI incident reporting process defined and tested.",
            "GOV-5.1": "Third-party AI component risk assessments conducted.",
            "GOV-6.1": "Policies cover privacy, fairness, and societal risk.",
        },
    },
    "MAP": {
        "description": "Identify AI context, categorize risks, and map to impacts.",
        "subcategories": {
            "MAP-1.1": "AI system purpose, intended users, and deployment context documented.",
            "MAP-1.5": "Organizational risk tolerance defined for AI applications.",
            "MAP-2.1": "Scientific and technical knowledge gaps identified.",
            "MAP-2.2": "Risk categories mapped: safety, security, privacy, bias, explainability.",
            "MAP-3.1": "AI system tasks and capabilities fully inventoried.",
            "MAP-5.1": "Beneficial impacts and intended outcomes documented.",
            "MAP-5.2": "Negative impacts and unintended consequences assessed.",
        },
    },
    "MEASURE": {
        "description": "Analyze, assess, and benchmark AI risks with metrics.",
        "subcategories": {
            "MEASURE-1.1": "Metrics for trustworthiness characteristics defined.",
            "MEASURE-2.1": "AI system tested in realistic deployment conditions.",
            "MEASURE-2.2": "Model performance monitored across demographic groups.",
            "MEASURE-2.5": "Robustness and adversarial testing conducted.",
            "MEASURE-2.6": "Data quality and provenance assessed.",
            "MEASURE-2.7": "Privacy risk measured and quantified.",
            "MEASURE-3.1": "AI risk metrics integrated into broader enterprise risk.",
            "MEASURE-4.1": "Testing results documented and available to stakeholders.",
        },
    },
    "MANAGE": {
        "description": "Prioritize, respond to, and recover from AI risks.",
        "subcategories": {
            "MANAGE-1.1": "AI risks prioritized by impact and likelihood.",
            "MANAGE-1.3": "Responses implemented for top-priority AI risks.",
            "MANAGE-2.2": "AI systems monitored for drift and performance degradation.",
            "MANAGE-2.4": "Fallback mechanisms defined for AI system failures.",
            "MANAGE-3.1": "AI incident response plan documented.",
            "MANAGE-3.2": "Post-incident reviews conducted and documented.",
            "MANAGE-4.1": "Residual risks accepted, mitigated, or transferred.",
        },
    },
}

# ── OWASP LLM Top 10 (2025) ───────────────────────────────────────────────────

OWASP_LLM_TOP10: Dict[str, Dict] = {
    "LLM01": {"name": "Prompt Injection", "severity": "CRITICAL"},
    "LLM02": {"name": "Insecure Output Handling", "severity": "HIGH"},
    "LLM03": {"name": "Training Data Poisoning", "severity": "HIGH"},
    "LLM04": {"name": "Model Denial of Service", "severity": "HIGH"},
    "LLM05": {"name": "Supply Chain Vulnerabilities", "severity": "HIGH"},
    "LLM06": {"name": "Sensitive Information Disclosure", "severity": "CRITICAL"},
    "LLM07": {"name": "Insecure Plugin Design", "severity": "HIGH"},
    "LLM08": {"name": "Excessive Agency", "severity": "HIGH"},
    "LLM09": {"name": "Overreliance", "severity": "MEDIUM"},
    "LLM10": {"name": "Model Theft", "severity": "HIGH"},
}

# ── Assessment Question Bank ──────────────────────────────────────────────────

ASSESSMENT_QUESTIONS: List[Dict] = [
    # Model Security
    {"id": "MS-01", "domain": "Model Security", "atlas_id": "AML.T0018",
     "question": "Are ML model artifacts stored with encryption at rest?",
     "weight": 8, "control_tag": "model_artifact_security"},
    {"id": "MS-02", "domain": "Model Security", "atlas_id": "AML.T0018",
     "question": "Is model integrity verified via cryptographic hash before inference deployment?",
     "weight": 9, "control_tag": "model_integrity"},
    {"id": "MS-03", "domain": "Model Security", "atlas_id": "AML.T0016",
     "question": "Is access to the model registry controlled by RBAC with audit logging?",
     "weight": 7, "control_tag": "model_registry_access"},
    {"id": "MS-04", "domain": "Model Security", "atlas_id": "AML.T0044",
     "question": "Are third-party ML dependencies (packages, pretrained models) scanned for supply chain risk?",
     "weight": 9, "control_tag": "ml_supply_chain"},

    # Adversarial Robustness
    {"id": "AR-01", "domain": "Adversarial Robustness", "atlas_id": "AML.T0043",
     "question": "Has adversarial example testing been conducted against production models?",
     "weight": 8, "control_tag": "adversarial_testing"},
    {"id": "AR-02", "domain": "Adversarial Robustness", "atlas_id": "AML.T0036",
     "question": "Are evasion attacks tested for detection/classification models in scope?",
     "weight": 8, "control_tag": "evasion_testing"},
    {"id": "AR-03", "domain": "Adversarial Robustness", "atlas_id": "AML.T0031",
     "question": "Is model performance monitored for statistical drift post-deployment?",
     "weight": 7, "control_tag": "drift_monitoring"},

    # Training Data Security
    {"id": "TD-01", "domain": "Training Data Security", "atlas_id": "AML.T0018",
     "question": "Is training data provenance tracked (source, lineage, hash)?",
     "weight": 9, "control_tag": "data_provenance"},
    {"id": "TD-02", "domain": "Training Data Security", "atlas_id": "AML.T0031",
     "question": "Is training data scanned for poisoning/backdoor indicators before use?",
     "weight": 8, "control_tag": "data_poisoning_defense"},
    {"id": "TD-03", "domain": "Training Data Security", "atlas_id": "AML.T0031",
     "question": "Are data collection pipelines isolated and access-controlled?",
     "weight": 7, "control_tag": "pipeline_security"},

    # Inference API Security
    {"id": "IA-01", "domain": "Inference API Security", "atlas_id": "AML.T0035",
     "question": "Is the inference API protected by authentication and rate limiting?",
     "weight": 8, "control_tag": "api_auth_ratelimit"},
    {"id": "IA-02", "domain": "Inference API Security", "atlas_id": "AML.T0040",
     "question": "Are confidence scores and logits truncated/perturbed to prevent model inversion?",
     "weight": 7, "control_tag": "output_perturbation"},
    {"id": "IA-03", "domain": "Inference API Security", "atlas_id": "AML.T0034",
     "question": "Are membership inference attack defenses (DP, output aggregation) in place?",
     "weight": 7, "control_tag": "membership_inference_defense"},

    # LLM-Specific Security
    {"id": "LLM-01", "domain": "LLM Security", "atlas_id": "AML.T0048",
     "question": "Are user inputs sanitized and validated before reaching LLM context window?",
     "weight": 10, "control_tag": "prompt_sanitization"},
    {"id": "LLM-02", "domain": "LLM Security", "atlas_id": "AML.T0051",
     "question": "Is a guardrail/safety layer applied to LLM outputs before user delivery?",
     "weight": 9, "control_tag": "output_guardrail"},
    {"id": "LLM-03", "domain": "LLM Security", "atlas_id": "AML.T0054",
     "question": "Are LLM tool calls and agent actions audited and scoped by least privilege?",
     "weight": 9, "control_tag": "agent_least_privilege"},
    {"id": "LLM-04", "domain": "LLM Security", "atlas_id": "AML.T0048",
     "question": "Is the system prompt protected from extraction via indirect injection?",
     "weight": 8, "control_tag": "system_prompt_protection"},
    {"id": "LLM-05", "domain": "LLM Security", "atlas_id": "AML.T0051",
     "question": "Has red-team adversarial prompt testing been conducted on LLM deployments?",
     "weight": 8, "control_tag": "llm_red_team"},

    # Governance & Compliance
    {"id": "GV-01", "domain": "Governance", "nist_id": "GOV-1.1",
     "question": "Is an AI risk policy documented and approved by executive leadership?",
     "weight": 7, "control_tag": "ai_risk_policy"},
    {"id": "GV-02", "domain": "Governance", "nist_id": "GOV-2.1",
     "question": "Is there an assigned AI Risk Officer or equivalent role?",
     "weight": 6, "control_tag": "ai_risk_ownership"},
    {"id": "GV-03", "domain": "Governance", "nist_id": "GOV-4.1",
     "question": "Is there a documented AI incident response procedure?",
     "weight": 8, "control_tag": "ai_incident_response"},
    {"id": "GV-04", "domain": "Governance", "nist_id": "MAP-2.2",
     "question": "Are AI system risks assessed across security, privacy, fairness, and safety dimensions?",
     "weight": 7, "control_tag": "multi_domain_risk_assessment"},

    # MLOps Security
    {"id": "ML-01", "domain": "MLOps Security", "atlas_id": "AML.T0044",
     "question": "Are ML pipeline components (CI/CD, experiment tracking) protected from unauthorized modification?",
     "weight": 8, "control_tag": "mlops_pipeline_security"},
    {"id": "ML-02", "domain": "MLOps Security", "nist_id": "MANAGE-2.2",
     "question": "Is model performance monitored continuously in production with automated alerting?",
     "weight": 7, "control_tag": "model_monitoring"},
    {"id": "ML-03", "domain": "MLOps Security", "nist_id": "MANAGE-2.4",
     "question": "Are fallback/rollback mechanisms defined for failed or degraded model versions?",
     "weight": 7, "control_tag": "model_fallback"},
]


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class QuestionResult:
    question_id: str
    domain: str
    question: str
    answer: str          # "yes" | "no" | "partial" | "na"
    score_earned: float
    score_max: float
    atlas_id: Optional[str] = None
    nist_id: Optional[str] = None
    finding: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class DomainResult:
    name: str
    score: float
    max_score: float
    percentage: float
    risk_level: str
    findings_count: int
    questions: List[QuestionResult] = field(default_factory=list)


@dataclass
class AssessmentReport:
    assessment_id: str
    org_name: str
    ai_system_name: str
    assessment_date: str
    toolkit_version: str
    overall_score: float
    overall_max: float
    overall_percentage: float
    maturity_level: str
    risk_rating: str
    domains: List[DomainResult] = field(default_factory=list)
    atlas_coverage: List[str] = field(default_factory=list)
    owasp_llm_coverage: Dict = field(default_factory=dict)
    nist_rmf_coverage: Dict = field(default_factory=dict)
    critical_gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    generated_by: str = f"CYBERDUDEBIVASH SENTINEL APEX AI-SPM v{TOOLKIT_VERSION}"
    gstin: str = GSTIN


# ── Scoring Engine ────────────────────────────────────────────────────────────

ANSWER_SCORES = {"yes": 1.0, "partial": 0.5, "no": 0.0, "na": None}

RISK_THRESHOLDS = [
    (90, "MINIMAL",  "Mature AI security posture — maintain and continuously improve."),
    (75, "LOW",      "Good posture with minor gaps — address findings within 90 days."),
    (60, "MEDIUM",   "Moderate gaps — remediate HIGH findings within 30 days."),
    (40, "HIGH",     "Significant gaps — prioritize CRITICAL and HIGH findings immediately."),
    (0,  "CRITICAL", "Severe AI security deficiencies — immediate remediation required."),
]

MATURITY_LEVELS = [
    (90, "Optimizing",    "AI security processes continuously improved via metrics."),
    (75, "Managed",       "Quantitative AI security controls applied consistently."),
    (60, "Defined",       "AI security processes documented and standardized."),
    (40, "Developing",    "Some AI security practices in place but inconsistent."),
    (0,  "Initial",       "Ad hoc or absent AI security practices."),
]


def _classify(score_pct: float, thresholds: list) -> Tuple[str, str]:
    for threshold, label, desc in thresholds:
        if score_pct >= threshold:
            return label, desc
    return thresholds[-1][1], thresholds[-1][2]


def score_question(q: Dict, answer: str) -> QuestionResult:
    """Convert a question dict + answer into a scored QuestionResult."""
    answer = answer.strip().lower()
    score_factor = ANSWER_SCORES.get(answer)

    weight = q["weight"]
    if score_factor is None:  # N/A
        score_earned = weight  # Count as full credit if not applicable
        score_max    = weight
    else:
        score_earned = weight * score_factor
        score_max    = weight

    finding = None
    recommendation = None

    if answer == "no":
        technique_id = q.get("atlas_id") or q.get("nist_id") or ""
        finding = f"[{technique_id}] {q['question']} — Not implemented."
        if "atlas_id" in q and q["atlas_id"] in ATLAS_TECHNIQUES:
            t = ATLAS_TECHNIQUES[q["atlas_id"]]
            controls = "; ".join(t["controls"][:2])
            recommendation = f"Implement: {controls}. (ATLAS {q['atlas_id']}: {t['name']})"
    elif answer == "partial":
        finding = f"Partial implementation: {q['question']}"
        recommendation = "Expand to full coverage — review control completeness."

    return QuestionResult(
        question_id=q["id"],
        domain=q["domain"],
        question=q["question"],
        answer=answer,
        score_earned=score_earned,
        score_max=score_max,
        atlas_id=q.get("atlas_id"),
        nist_id=q.get("nist_id"),
        finding=finding,
        recommendation=recommendation,
    )


def compute_domain_results(scored: List[QuestionResult]) -> List[DomainResult]:
    """Aggregate per-domain scores."""
    domains: Dict[str, List[QuestionResult]] = {}
    for r in scored:
        domains.setdefault(r.domain, []).append(r)

    results = []
    for domain_name, questions in sorted(domains.items()):
        total_earned = sum(q.score_earned for q in questions)
        total_max    = sum(q.score_max    for q in questions)
        pct = (total_earned / total_max * 100) if total_max > 0 else 0
        risk, _ = _classify(pct, RISK_THRESHOLDS)
        findings = sum(1 for q in questions if q.finding)

        results.append(DomainResult(
            name=domain_name,
            score=total_earned,
            max_score=total_max,
            percentage=round(pct, 1),
            risk_level=risk,
            findings_count=findings,
            questions=questions,
        ))
    return results


def compute_atlas_coverage(scored: List[QuestionResult]) -> Tuple[List[str], List[str]]:
    """Return (covered_technique_ids, uncovered_technique_ids)."""
    assessed = {q.atlas_id for q in scored if q.atlas_id and q.answer in ("yes", "partial")}
    all_ids  = set(ATLAS_TECHNIQUES.keys())
    covered   = sorted(assessed & all_ids)
    uncovered = sorted(all_ids - assessed)
    return covered, uncovered


def compute_owasp_llm_coverage(scored: List[QuestionResult]) -> Dict:
    """Map LLM question results to OWASP LLM Top 10."""
    owasp_map = {
        "prompt_sanitization": "LLM01",
        "system_prompt_protection": "LLM01",
        "output_guardrail": "LLM02",
        "agent_least_privilege": "LLM08",
        "llm_red_team": "LLM01",
        "ml_supply_chain": "LLM05",
    }
    covered = {}
    for q in scored:
        owasp_id = owasp_map.get(q.control_tag if hasattr(q, "control_tag") else "")
        if owasp_id and q.answer in ("yes", "partial"):
            covered[owasp_id] = OWASP_LLM_TOP10[owasp_id]["name"]

    coverage = {}
    for k, v in OWASP_LLM_TOP10.items():
        coverage[k] = {
            "name": v["name"],
            "severity": v["severity"],
            "covered": k in covered,
        }
    return coverage


def build_recommendations(domain_results: List[DomainResult]) -> List[str]:
    """Generate prioritized remediation recommendations."""
    recs = []
    critical_domains = [d for d in domain_results if d.risk_level in ("CRITICAL", "HIGH")]

    for domain in critical_domains:
        for q in domain.questions:
            if q.recommendation:
                recs.append(f"[{domain.name}] {q.recommendation}")

    # Deduplicate and cap
    seen = set()
    deduped = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return deduped[:20]


# ── Quick Scan Mode (interactive or scripted defaults) ────────────────────────

QUICK_SCAN_DEFAULTS: Dict[str, str] = {
    # Conservative defaults — partial credit for likely-implemented basics
    "MS-01": "partial", "MS-02": "no",   "MS-03": "partial", "MS-04": "no",
    "AR-01": "no",      "AR-02": "no",   "AR-03": "partial",
    "TD-01": "partial", "TD-02": "no",   "TD-03": "partial",
    "IA-01": "yes",     "IA-02": "no",   "IA-03": "no",
    "LLM-01": "partial","LLM-02": "partial", "LLM-03": "no",
    "LLM-04": "no",     "LLM-05": "no",
    "GV-01": "partial", "GV-02": "no",   "GV-03": "no", "GV-04": "partial",
    "ML-01": "partial", "ML-02": "partial", "ML-03": "no",
}


def run_interactive_assessment(org_name: str, system_name: str) -> Dict[str, str]:
    """Interactive CLI assessment session."""
    print(f"\n{'═'*70}")
    print(f"  CYBERDUDEBIVASH AI-SPM Assessment — {system_name}")
    print(f"  Organization: {org_name}")
    print(f"{'═'*70}")
    print("  Answer each question: yes / no / partial / na (not applicable)")
    print(f"{'─'*70}\n")

    answers: Dict[str, str] = {}
    current_domain = ""

    for q in ASSESSMENT_QUESTIONS:
        if q["domain"] != current_domain:
            current_domain = q["domain"]
            print(f"\n  ── {current_domain.upper()} {'─'*40}")

        tech_ref = q.get("atlas_id") or q.get("nist_id") or ""
        while True:
            raw = input(f"  [{q['id']}][{tech_ref}] {q['question']}\n  > ").strip().lower()
            if raw in ANSWER_SCORES:
                answers[q["id"]] = raw
                break
            print("    Invalid answer. Use: yes / no / partial / na")

    return answers


def run_assessment(
    org_name: str,
    system_name: str,
    answers: Dict[str, str],
) -> AssessmentReport:
    """Core assessment engine — produce a full scored report."""

    # Score all questions
    q_map = {q["id"]: q for q in ASSESSMENT_QUESTIONS}
    scored: List[QuestionResult] = []
    for qid, answer in answers.items():
        if qid in q_map:
            # Attach control_tag to result for OWASP mapping
            r = score_question(q_map[qid], answer)
            r.__dict__["control_tag"] = q_map[qid].get("control_tag", "")
            scored.append(r)

    # Domain aggregation
    domain_results = compute_domain_results(scored)
    total_earned = sum(d.score for d in domain_results)
    total_max    = sum(d.max_score for d in domain_results)
    overall_pct  = (total_earned / total_max * 100) if total_max > 0 else 0

    risk, _     = _classify(overall_pct, RISK_THRESHOLDS)
    maturity, _ = _classify(overall_pct, MATURITY_LEVELS)

    # MITRE ATLAS coverage
    covered_atlas, uncovered_atlas = compute_atlas_coverage(scored)

    # OWASP LLM coverage
    owasp_coverage = compute_owasp_llm_coverage(scored)

    # Critical gaps
    critical_gaps = [
        q.finding for q in scored
        if q.finding and q.score_earned == 0 and q.score_max >= 8
    ]

    # Recommendations
    recs = build_recommendations(domain_results)

    # NIST AI RMF subcategory summary
    nist_coverage = {
        domain: {"covered": 0, "total": len(data["subcategories"])}
        for domain, data in NIST_AI_RMF_DOMAINS.items()
    }
    for q in scored:
        if hasattr(q, "nist_id") and q.nist_id and q.answer in ("yes", "partial"):
            for domain, data in NIST_AI_RMF_DOMAINS.items():
                if q.nist_id in data["subcategories"]:
                    nist_coverage[domain]["covered"] = min(
                        nist_coverage[domain]["covered"] + 1,
                        nist_coverage[domain]["total"]
                    )

    assessment_id = "AISPM-" + hashlib.sha256(
        f"{org_name}{system_name}{datetime.now(timezone.utc).date()}".encode()
    ).hexdigest()[:12].upper()

    return AssessmentReport(
        assessment_id=assessment_id,
        org_name=org_name,
        ai_system_name=system_name,
        assessment_date=datetime.now(timezone.utc).isoformat(),
        toolkit_version=TOOLKIT_VERSION,
        overall_score=round(total_earned, 1),
        overall_max=round(total_max, 1),
        overall_percentage=round(overall_pct, 1),
        maturity_level=maturity,
        risk_rating=risk,
        domains=domain_results,
        atlas_coverage=covered_atlas,
        owasp_llm_coverage=owasp_coverage,
        nist_rmf_coverage=nist_coverage,
        critical_gaps=critical_gaps[:10],
        recommendations=recs,
    )


# ── Report Rendering ──────────────────────────────────────────────────────────

def render_text_report(report: AssessmentReport) -> str:
    """Generate human-readable text report for PDF embedding."""
    lines = []
    lines.append("╔" + "═"*76 + "╗")
    lines.append("║  CYBERDUDEBIVASH® SENTINEL APEX — AI Security Posture Management Report  ║")
    lines.append("╚" + "═"*76 + "╝")
    lines.append("")
    lines.append(f"  Assessment ID   : {report.assessment_id}")
    lines.append(f"  Organization    : {report.org_name}")
    lines.append(f"  AI System       : {report.ai_system_name}")
    lines.append(f"  Assessment Date : {report.assessment_date[:10]}")
    lines.append(f"  Toolkit Version : {report.toolkit_version}")
    lines.append(f"  GSTIN           : {report.gstin}")
    lines.append("")
    lines.append("── EXECUTIVE SUMMARY " + "─"*58)
    lines.append(f"  Overall Score   : {report.overall_score:.1f} / {report.overall_max:.1f}  ({report.overall_percentage:.1f}%)")
    lines.append(f"  Maturity Level  : {report.maturity_level}")
    lines.append(f"  Risk Rating     : {report.risk_rating}")
    lines.append(f"  ATLAS Techniques Covered: {len(report.atlas_coverage)} / {len(ATLAS_TECHNIQUES)}")
    lines.append("")
    lines.append("── DOMAIN SCORES " + "─"*62)
    for d in report.domains:
        bar_filled = int(d.percentage / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        lines.append(f"  {d.name:<30} {bar} {d.percentage:5.1f}%  [{d.risk_level}]")
    lines.append("")

    if report.critical_gaps:
        lines.append("── CRITICAL GAPS " + "─"*62)
        for gap in report.critical_gaps:
            lines.append(f"  ⚠ {gap}")
        lines.append("")

    if report.recommendations:
        lines.append("── TOP RECOMMENDATIONS " + "─"*56)
        for i, rec in enumerate(report.recommendations[:10], 1):
            lines.append(f"  {i:2}. {rec}")
        lines.append("")

    lines.append("── MITRE ATLAS COVERAGE " + "─"*55)
    lines.append(f"  Covered   : {', '.join(report.atlas_coverage) or 'None'}")
    uncovered = sorted(set(ATLAS_TECHNIQUES.keys()) - set(report.atlas_coverage))
    lines.append(f"  Uncovered : {', '.join(uncovered) or 'None'}")
    lines.append("")
    lines.append("── NIST AI RMF COVERAGE " + "─"*55)
    for domain, data in report.nist_rmf_coverage.items():
        lines.append(f"  {domain:<12} {data['covered']}/{data['total']} subcategories addressed")
    lines.append("")
    lines.append("  Generated by CYBERDUDEBIVASH SENTINEL APEX AI-SPM Toolkit")
    lines.append(f"  intel.cyberdudebivash.com  |  GSTIN: {GSTIN}  |  $299/kit")
    return "\n".join(lines)


def save_report(report: AssessmentReport, output_path: Optional[Path] = None) -> Path:
    """Atomically save JSON report to disk."""
    if output_path is None:
        fname = f"ai_spm_{report.assessment_id}_{report.assessment_date[:10]}.json"
        output_path = OUT_DIR / fname

    # Convert to plain dict — strip QuestionResult objects into dicts
    def _serialize(obj):
        if isinstance(obj, (QuestionResult, DomainResult, AssessmentReport)):
            d = {k: v for k, v in obj.__dict__.items()}
            return {k: _serialize(v) for k, v in d.items()}
        if isinstance(obj, list):
            return [_serialize(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _serialize(v) for k, v in obj.items()}
        return obj

    data = _serialize(report)
    data["_meta"] = {
        "toolkit": f"CYBERDUDEBIVASH AI-SPM v{TOOLKIT_VERSION}",
        "price_usd": PRICE_USD,
        "gstin": GSTIN,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    tmp = output_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.rename(output_path)
    return output_path


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH AI-SPM Assessment Toolkit — MITRE ATLAS + NIST AI RMF"
    )
    parser.add_argument("--quick-scan",    action="store_true",
                        help="Run with conservative default answers (gap-finding mode)")
    parser.add_argument("--interactive",   action="store_true",
                        help="Interactive CLI assessment")
    parser.add_argument("--answers-json",  type=str, default=None,
                        help="Path to JSON file mapping question IDs to answers")
    parser.add_argument("--org",           type=str, default="Organization",
                        help="Organization name")
    parser.add_argument("--system",        type=str, default="AI System",
                        help="AI system name being assessed")
    parser.add_argument("--output",        type=str, default=None,
                        help="Output JSON path (default: data/ai_spm/)")
    parser.add_argument("--text-report",   action="store_true",
                        help="Print human-readable text report to stdout")
    parser.add_argument("--list-atlas",    action="store_true",
                        help="List all covered MITRE ATLAS techniques")
    parser.add_argument("--list-questions", action="store_true",
                        help="List all assessment questions")
    args = parser.parse_args()

    if args.list_atlas:
        print(f"\nMITRE ATLAS Techniques covered by AI-SPM Toolkit ({len(ATLAS_TECHNIQUES)}):\n")
        for tid, t in ATLAS_TECHNIQUES.items():
            print(f"  {tid}  [{t['severity']:8}]  {t['name']}")
            print(f"            Tactic: {t['tactic']}")
            print(f"            Controls: {'; '.join(t['controls'])}\n")
        return

    if args.list_questions:
        print(f"\nAssessment Questions ({len(ASSESSMENT_QUESTIONS)}):\n")
        for q in ASSESSMENT_QUESTIONS:
            ref = q.get("atlas_id") or q.get("nist_id") or ""
            print(f"  [{q['id']}][W:{q['weight']}][{ref}] {q['question']}")
        return

    # Determine answers source
    if args.answers_json:
        answers = json.loads(Path(args.answers_json).read_text(encoding="utf-8"))
    elif args.quick_scan:
        print(f"[AI-SPM] Quick-scan mode — using conservative gap-finding defaults.")
        answers = QUICK_SCAN_DEFAULTS.copy()
    elif args.interactive:
        answers = run_interactive_assessment(args.org, args.system)
    else:
        print("[AI-SPM] No input mode specified. Use --quick-scan, --interactive, or --answers-json")
        parser.print_help()
        sys.exit(1)

    # Run assessment
    print(f"[AI-SPM] Running assessment for {args.org} — {args.system} ...")
    report = run_assessment(args.org, args.system, answers)

    # Save JSON report
    out_path = Path(args.output) if args.output else None
    saved = save_report(report, out_path)
    print(f"[AI-SPM] Report saved: {saved}")

    # Print summary
    print(f"\n  Overall Score : {report.overall_percentage:.1f}%")
    print(f"  Maturity      : {report.maturity_level}")
    print(f"  Risk Rating   : {report.risk_rating}")
    print(f"  ATLAS Coverage: {len(report.atlas_coverage)}/{len(ATLAS_TECHNIQUES)} techniques")
    print(f"  Critical Gaps : {len(report.critical_gaps)}")

    if args.text_report:
        print("\n" + render_text_report(report))

    return report


if __name__ == "__main__":
    main()
