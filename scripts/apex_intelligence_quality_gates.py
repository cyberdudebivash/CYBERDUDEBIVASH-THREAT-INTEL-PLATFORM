#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/apex_intelligence_quality_gates.py — Intelligence Quality Gate System
================================================================================
Version : 152.0.0

PURPOSE:
  Enforces 12 quality gates that EVERY advisory must pass before publication.
  Hard failures BLOCK publication. Warnings are logged but do not block.

GATES:
  GATE-01: HALLUCINATION_CLEAR   — AHE audit passed (no fabricated content)
  GATE-02: IOC_VALIDITY          — IOC validity rate >= 50% (or 0 IOCs declared)
  GATE-03: SCORE_EVIDENCE        — Risk score has evidence chain (not a static bucket)
  GATE-04: CONFIDENCE_RATIONAL   — Confidence has rationale documented
  GATE-05: ATTRIBUTION_CLEAN     — No synthetic actor names or [APEX-GENERATED] operations
  GATE-06: EXECUTIVE_UNIQUE      — Executive summary entropy > 3.5 (not template)
  GATE-07: ATTACK_JUSTIFIED      — All ATT&CK mappings have justification
  GATE-08: DUPLICATE_CLEAR       — No duplicate entry in this run
  GATE-09: TLP_VALID             — TLP label is valid (CLEAR/GREEN/AMBER/RED)
  GATE-10: STIX_ID_VALID         — STIX ID format is correct
  GATE-11: SEVERITY_CONSISTENT   — Severity label matches apex_risk score range
  GATE-12: ENRICHMENT_COMPLETE   — Required enrichment fields present

INTEGRATION:
  Called as final gate in pipeline before HTML/STIX report generation:
    from scripts.apex_intelligence_quality_gates import QualityGateSystem
    gate = QualityGateSystem()
    for item in items:
        result = gate.evaluate(item)
        if not result.publishable:
            log_blocked(result)
        else:
            publish(item)
================================================================================
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("apex.quality_gates")
ENGINE_VERSION = "152.0.0"
ENGINE_ID      = "APEX-QGS"

# ── Valid TLP Labels ──────────────────────────────────────────────────────────
VALID_TLP = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}

# ── STIX ID Pattern ───────────────────────────────────────────────────────────
STIX_ID_RE = re.compile(
    r"^(indicator|threat-actor|attack-pattern|malware|campaign|"
    r"vulnerability|report|intel|bundle)--[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$|"
    r"^intel--[0-9a-f]{24}$",
    re.IGNORECASE,
)

# ── Synthetic actor patterns (from AHE) ──────────────────────────────────────
SYNTHETIC_ACTOR_RE = re.compile(
    r"(automated\s+cve\s+exploitation\s+cluster|"
    r"advanced\s+persistent\s+threat\s+cluster|"
    r"cdb-apt-gen|cdb-cve-gen|cdb-ran-gen|"
    r"apex-cluster-unattributed)",
    re.IGNORECASE,
)
GENERATED_OP_RE = re.compile(r"\[apex-generated\]", re.IGNORECASE)

# ── Static bucket score detection ─────────────────────────────────────────────
STATIC_BUCKETS = {10.0, 7.5, 5.5, 5.0, 4.8, 2.8, 2.3}

# ── Severity label → risk score range ────────────────────────────────────────
SEVERITY_RANGES = {
    "CRITICAL":      (9.0, 10.0),
    "HIGH":          (7.0, 8.99),
    "MEDIUM":        (4.0, 6.99),
    "LOW":           (1.0, 3.99),
    "INFORMATIONAL": (0.0, 0.99),
}

# ── Template executive phrase detection ──────────────────────────────────────
TEMPLATE_RE = re.compile(
    r"(cyberdudebivash sentinel apex has identified a|"
    r"the vulnerability presents an exploitable attack surface|"
    r"structural and behavioural analysis.*reveals a generic|"
    r"threat vector identified from threat intelligence feed|"
    r"technique id mapped from threat intelligence corpus|"
    r"patch within standard window|"
    r"apex ml corpus|"
    r"escalation probability.*apex model.*14-day)",
    re.IGNORECASE,
)

# ── Required enrichment fields ────────────────────────────────────────────────
REQUIRED_FIELDS = {
    "title",
    "threat_type",
    "tlp",
    "processed_ts",
}
RECOMMENDED_FIELDS = {
    "apex_risk",
    "apex_risk_evidence",
    "confidence",
    "confidence_rationale",
    "executive_summary",
    "intelligence_tier",
    "ioc_count",
    "ttp_count",
}


@dataclass
class GateResult:
    gate_id:     str
    gate_name:   str
    passed:      bool
    severity:    str     # HARD_FAIL | WARN
    evidence:    str
    detail:      str


@dataclass
class QualityReport:
    item_id:     str
    publishable: bool
    gates_passed: int
    gates_failed: int
    gates_warned: int
    results:     List[GateResult] = field(default_factory=list)
    evaluated_ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return {
            "item_id":      self.item_id,
            "publishable":  self.publishable,
            "gates_passed": self.gates_passed,
            "gates_failed": self.gates_failed,
            "gates_warned": self.gates_warned,
            "results":      [r.__dict__ for r in self.results],
            "evaluated_ts": self.evaluated_ts,
            "engine":       ENGINE_ID,
            "version":      ENGINE_VERSION,
        }


def _entropy(text: str) -> float:
    words = re.findall(r"\w+", text.lower())
    if not words:
        return 0.0
    freq = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    total = len(words)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())


class QualityGateSystem:
    """Stateful quality gate system — maintains run-level deduplication state."""

    def __init__(self) -> None:
        self._seen_fps: Set[str] = set()
        self._run_ts = datetime.now(timezone.utc).isoformat()

    def _fp(self, item: Dict) -> str:
        sig = "|".join([
            str(item.get("title") or "").strip().lower(),
            str(item.get("source_url") or "").strip().lower(),
        ])
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    # ── Individual Gates ──────────────────────────────────────────────────────

    def _gate01_hallucination(self, item: Dict) -> GateResult:
        """GATE-01: AHE pre-clearance."""
        ahe_result = item.get("ahe_result") or item.get("anti_hallucination_result")
        # If AHE was run and stored result
        if isinstance(ahe_result, dict):
            if ahe_result.get("hard_fail"):
                violations = ahe_result.get("violations", [])
                codes = [v.get("code", "") for v in violations]
                return GateResult(
                    "GATE-01", "HALLUCINATION_CLEAR", False, "HARD_FAIL",
                    f"AHE violations: {', '.join(codes)}",
                    "Anti-Hallucination Engine detected fabricated content. Publication blocked.",
                )
        # Run inline synthetic actor check
        actor = str(item.get("actor_cluster") or item.get("actor") or "")
        campaign = str(item.get("campaign") or item.get("operation_name") or "")
        if SYNTHETIC_ACTOR_RE.search(actor):
            return GateResult(
                "GATE-01", "HALLUCINATION_CLEAR", False, "HARD_FAIL",
                f"Synthetic actor: {actor}",
                "Synthetic actor cluster name detected. Replace with UNATTRIBUTED or evidence-backed designation.",
            )
        if GENERATED_OP_RE.search(campaign):
            return GateResult(
                "GATE-01", "HALLUCINATION_CLEAR", False, "HARD_FAIL",
                f"Generated operation: {campaign}",
                "AI-generated operation name detected. Remove [APEX-GENERATED] marker or use UNCLASSIFIED.",
            )
        return GateResult("GATE-01", "HALLUCINATION_CLEAR", True, "HARD_FAIL",
                          "No fabrication markers detected", "")

    def _gate02_ioc_validity(self, item: Dict) -> GateResult:
        """GATE-02: IOC validity rate."""
        iocs       = item.get("iocs") or []
        pseudo     = item.get("pseudo_iocs") or []
        invalid    = item.get("invalid_iocs") or []
        total      = len(iocs) + len(pseudo) + len(invalid)
        valid      = len(iocs)

        if total == 0:
            # No IOCs declared → acceptable (not all advisories have IOCs)
            return GateResult("GATE-02", "IOC_VALIDITY", True, "HARD_FAIL",
                              "No IOCs declared", "Pass: no IOC validation required")

        rate = valid / total
        if rate < 0.50 and total > 2:
            return GateResult(
                "GATE-02", "IOC_VALIDITY", False, "HARD_FAIL",
                f"Valid: {valid}/{total} ({rate*100:.0f}%)",
                f"IOC validity rate below 50%. {len(pseudo)} pseudo-IOCs (CVE IDs, advisory URLs) "
                f"and {len(invalid)} invalid IOCs must be removed before publication.",
            )
        if rate < 0.80 and total > 2:
            return GateResult(
                "GATE-02", "IOC_VALIDITY", True, "WARN",
                f"Valid: {valid}/{total} ({rate*100:.0f}%)",
                f"IOC validity rate below 80%. Review {len(pseudo)} pseudo-IOCs and {len(invalid)} invalid IOCs.",
            )
        return GateResult("GATE-02", "IOC_VALIDITY", True, "HARD_FAIL",
                          f"Valid: {valid}/{total} ({rate*100:.0f}%)", "")

    def _gate03_score_evidence(self, item: Dict) -> GateResult:
        """GATE-03: Risk score must have evidence chain."""
        score    = item.get("apex_risk") or item.get("risk_score")
        evidence = item.get("apex_risk_evidence")

        if score is None:
            return GateResult("GATE-03", "SCORE_EVIDENCE", True, "WARN",
                              "No risk score", "Advisory has no risk score — assign via RSE")
        try:
            score_f = float(score)
        except (ValueError, TypeError):
            return GateResult("GATE-03", "SCORE_EVIDENCE", False, "HARD_FAIL",
                              f"Invalid score: {score}", "Risk score is not numeric")

        # Static bucket detection
        if score_f in STATIC_BUCKETS and not evidence:
            return GateResult(
                "GATE-03", "SCORE_EVIDENCE", False, "HARD_FAIL",
                f"Static bucket score: {score_f}",
                f"Score {score_f} matches hardcoded bucket value with no evidence chain. "
                "Run apex_risk_scoring_engine.py before publication.",
            )

        if not evidence:
            return GateResult("GATE-03", "SCORE_EVIDENCE", True, "WARN",
                              f"Score {score_f} without evidence block",
                              "Risk score present but no apex_risk_evidence field. Run RSE for full evidence chain.")

        return GateResult("GATE-03", "SCORE_EVIDENCE", True, "HARD_FAIL",
                          f"Score {score_f} with {len(evidence)} evidence signals", "")

    def _gate04_confidence(self, item: Dict) -> GateResult:
        """GATE-04: Confidence must have rationale."""
        conf      = item.get("confidence")
        rationale = item.get("confidence_rationale")
        if conf is None:
            return GateResult("GATE-04", "CONFIDENCE_RATIONAL", True, "WARN",
                              "No confidence score", "Run apex_confidence_engine.py")
        if not rationale:
            return GateResult("GATE-04", "CONFIDENCE_RATIONAL", True, "WARN",
                              f"Confidence {conf}% without rationale",
                              "Add confidence_rationale field via apex_confidence_engine.py")
        return GateResult("GATE-04", "CONFIDENCE_RATIONAL", True, "HARD_FAIL",
                          f"Confidence {conf}% with rationale", "")

    def _gate05_attribution(self, item: Dict) -> GateResult:
        """GATE-05: Attribution must be clean."""
        actor    = str(item.get("actor_cluster") or item.get("actor") or "")
        campaign = str(item.get("campaign") or item.get("operation_name") or "")
        if SYNTHETIC_ACTOR_RE.search(actor):
            return GateResult("GATE-05", "ATTRIBUTION_CLEAN", False, "HARD_FAIL",
                              actor,
                              "Synthetic actor designation detected. Use UNATTRIBUTED if no evidence exists.")
        if GENERATED_OP_RE.search(campaign):
            return GateResult("GATE-05", "ATTRIBUTION_CLEAN", False, "HARD_FAIL",
                              campaign,
                              "[APEX-GENERATED] operation name must not be published.")
        return GateResult("GATE-05", "ATTRIBUTION_CLEAN", True, "HARD_FAIL",
                          "Attribution clean", "")

    def _gate06_executive(self, item: Dict) -> GateResult:
        """GATE-06: Executive summary must be unique and non-template."""
        summary = str(item.get("executive_summary") or item.get("summary") or "")
        if not summary:
            return GateResult("GATE-06", "EXECUTIVE_UNIQUE", False, "HARD_FAIL",
                              "Empty executive summary",
                              "Executive summary is required. Run apex_narrative_engine.py")
        if TEMPLATE_RE.search(summary):
            return GateResult("GATE-06", "EXECUTIVE_UNIQUE", False, "HARD_FAIL",
                              "Template phrase detected",
                              "Executive summary contains AI-generated boilerplate. Run apex_narrative_engine.py")
        entropy = _entropy(summary)
        if entropy < 3.5:
            return GateResult("GATE-06", "EXECUTIVE_UNIQUE", True, "WARN",
                              f"Entropy: {entropy:.2f}",
                              f"Low entropy ({entropy:.2f}) suggests repetitive/template content. Review summary.")
        return GateResult("GATE-06", "EXECUTIVE_UNIQUE", True, "HARD_FAIL",
                          f"Entropy: {entropy:.2f}", "")

    def _gate07_attack(self, item: Dict) -> GateResult:
        """GATE-07: ATT&CK mappings must be justified."""
        ttps = item.get("ttps") or item.get("attack_techniques") or []
        if not ttps:
            return GateResult("GATE-07", "ATTACK_JUSTIFIED", True, "WARN",
                              "No ATT&CK mappings", "Run apex_mitre_attack_engine.py")
        unjustified = 0
        for ttp in ttps:
            if isinstance(ttp, dict):
                j = str(ttp.get("justification") or "")
                if not j or "mapped from threat intelligence corpus" in j.lower():
                    unjustified += 1
        if unjustified > 0:
            return GateResult("GATE-07", "ATTACK_JUSTIFIED", False, "HARD_FAIL",
                              f"{unjustified}/{len(ttps)} unjustified",
                              "ATT&CK techniques mapped without evidence. Run apex_mitre_attack_engine.py")
        return GateResult("GATE-07", "ATTACK_JUSTIFIED", True, "HARD_FAIL",
                          f"{len(ttps)} techniques justified", "")

    def _gate08_duplicate(self, item: Dict) -> GateResult:
        """GATE-08: Deduplication."""
        fp = self._fp(item)
        if fp in self._seen_fps:
            return GateResult("GATE-08", "DUPLICATE_CLEAR", False, "HARD_FAIL",
                              fp,
                              "Duplicate entry detected in this run. Deduplicate feed before publishing.")
        self._seen_fps.add(fp)
        return GateResult("GATE-08", "DUPLICATE_CLEAR", True, "HARD_FAIL",
                          "No duplicate", "")

    def _gate09_tlp(self, item: Dict) -> GateResult:
        """GATE-09: TLP label validation."""
        tlp = str(item.get("tlp") or item.get("tlp_label") or "")
        if not tlp:
            return GateResult("GATE-09", "TLP_VALID", True, "WARN",
                              "No TLP label", "Default to TLP:GREEN if not specified")
        tlp_upper = tlp.upper().strip()
        if tlp_upper not in VALID_TLP:
            return GateResult("GATE-09", "TLP_VALID", False, "HARD_FAIL",
                              tlp,
                              f"Invalid TLP: '{tlp}'. Valid values: {', '.join(sorted(VALID_TLP))}")
        return GateResult("GATE-09", "TLP_VALID", True, "HARD_FAIL",
                          tlp_upper, "")

    def _gate10_stix_id(self, item: Dict) -> GateResult:
        """GATE-10: STIX ID format validation."""
        stix_id = str(item.get("stix_id") or item.get("id") or item.get("intel_id") or "")
        if not stix_id:
            return GateResult("GATE-10", "STIX_ID_VALID", True, "WARN",
                              "No STIX ID", "Generate STIX ID before STIX 2.1 bundle export")
        if not STIX_ID_RE.match(stix_id):
            return GateResult("GATE-10", "STIX_ID_VALID", False, "HARD_FAIL",
                              stix_id,
                              "STIX ID format is invalid. Expected: type--UUID or intel--hex24")
        return GateResult("GATE-10", "STIX_ID_VALID", True, "HARD_FAIL",
                          stix_id, "")

    def _gate11_severity_consistent(self, item: Dict) -> GateResult:
        """GATE-11: Severity label must match apex_risk range."""
        severity = str(item.get("severity") or "").upper().strip()
        score    = item.get("apex_risk") or item.get("risk_score")

        if not severity or score is None:
            return GateResult("GATE-11", "SEVERITY_CONSISTENT", True, "WARN",
                              f"severity={severity}, score={score}",
                              "Cannot validate consistency without both severity label and risk score")
        try:
            score_f = float(score)
        except (ValueError, TypeError):
            return GateResult("GATE-11", "SEVERITY_CONSISTENT", True, "WARN",
                              f"Non-numeric score: {score}", "")

        expected_range = SEVERITY_RANGES.get(severity)
        if expected_range and not (expected_range[0] <= score_f <= expected_range[1]):
            return GateResult(
                "GATE-11", "SEVERITY_CONSISTENT", False, "HARD_FAIL",
                f"{severity} label with score {score_f}",
                f"Severity label '{severity}' requires risk score "
                f"{expected_range[0]}–{expected_range[1]}, but score is {score_f}. "
                "Either re-score or re-label. This mismatch will confuse analysts.",
            )
        return GateResult("GATE-11", "SEVERITY_CONSISTENT", True, "HARD_FAIL",
                          f"{severity} at {score_f}", "")

    def _gate12_enrichment_complete(self, item: Dict) -> GateResult:
        """GATE-12: Required enrichment fields must be present."""
        missing_required    = [f for f in REQUIRED_FIELDS if not item.get(f)]
        missing_recommended = [f for f in RECOMMENDED_FIELDS if not item.get(f)]

        if missing_required:
            return GateResult(
                "GATE-12", "ENRICHMENT_COMPLETE", False, "HARD_FAIL",
                f"Missing required: {', '.join(missing_required)}",
                f"Required fields absent. Add: {', '.join(missing_required)} before publishing.",
            )
        if missing_recommended:
            return GateResult(
                "GATE-12", "ENRICHMENT_COMPLETE", True, "WARN",
                f"Missing recommended: {', '.join(missing_recommended)}",
                f"Recommended fields absent: {', '.join(missing_recommended)}. Run full enrichment pipeline.",
            )
        return GateResult("GATE-12", "ENRICHMENT_COMPLETE", True, "HARD_FAIL",
                          "All required fields present", "")

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(self, item: Dict) -> QualityReport:
        """Run all 12 gates against a single item."""
        item_id = str(item.get("stix_id") or item.get("id") or item.get("intel_id") or "UNKNOWN")
        gates = [
            self._gate01_hallucination,
            self._gate02_ioc_validity,
            self._gate03_score_evidence,
            self._gate04_confidence,
            self._gate05_attribution,
            self._gate06_executive,
            self._gate07_attack,
            self._gate08_duplicate,
            self._gate09_tlp,
            self._gate10_stix_id,
            self._gate11_severity_consistent,
            self._gate12_enrichment_complete,
        ]
        results = [g(item) for g in gates]

        hard_fails = [r for r in results if not r.passed and r.severity == "HARD_FAIL"]
        warns      = [r for r in results if r.passed and r.severity == "WARN" and r.detail]
        passed     = [r for r in results if r.passed and r.severity == "HARD_FAIL"]

        report = QualityReport(
            item_id=item_id,
            publishable=len(hard_fails) == 0,
            gates_passed=len(passed),
            gates_failed=len(hard_fails),
            gates_warned=len(warns),
            results=results,
        )
        return report

    def evaluate_batch(self, items: List[Dict]) -> Dict:
        reports = [self.evaluate(item) for item in items]
        publishable = [r for r in reports if r.publishable]
        blocked     = [r for r in reports if not r.publishable]
        return {
            "engine":         ENGINE_ID,
            "version":        ENGINE_VERSION,
            "run_ts":         self._run_ts,
            "total":          len(items),
            "publishable":    len(publishable),
            "blocked":        len(blocked),
            "blocked_ids":    [r.item_id for r in blocked],
            "reports":        [r.to_dict() for r in reports],
        }


def main() -> int:
    import argparse, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [QGS] %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="APEX Intelligence Quality Gates v" + ENGINE_VERSION)
    parser.add_argument("--manifest", default="data/stix/feed_manifest.json")
    parser.add_argument("--report",   default="data/quality/gate_report.json")
    parser.add_argument("--strict",   action="store_true")
    args = parser.parse_args()

    path = Path(args.manifest)
    if not path.exists():
        log.error("Not found: %s", path)
        return 1
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("items", [])

    gate = QualityGateSystem()
    batch = gate.evaluate_batch(items)

    rpath = Path(args.report)
    rpath.parent.mkdir(parents=True, exist_ok=True)
    tmp = rpath.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(batch, f, indent=2, ensure_ascii=False)
    tmp.replace(rpath)

    print(f"\n{'='*70}")
    print(f"  APEX INTELLIGENCE QUALITY GATE SYSTEM v{ENGINE_VERSION}")
    print(f"{'='*70}")
    print(f"  Total evaluated  : {batch['total']}")
    print(f"  ✔ Publishable    : {batch['publishable']}")
    print(f"  ✘ Blocked        : {batch['blocked']}")
    if batch['blocked_ids']:
        print(f"\n  Blocked IDs: {batch['blocked_ids'][:10]}")
    print(f"{'='*70}\n")

    if args.strict and batch["blocked"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
