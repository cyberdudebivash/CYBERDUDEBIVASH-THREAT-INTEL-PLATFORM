# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/attck_coverage_analytics_engine.py
# PHASE 6 — ATT&CK COVERAGE ANALYTICS ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
ATT&CK Coverage Analytics Engine — Phase 6 of Enterprise Observability Layer.

Measures ATT&CK framework coverage and quality across the intelligence pipeline:
  - Coverage telemetry: which tactics/techniques are covered vs. gaps
  - Sequencing analytics: kill-chain completeness, tactic ordering quality
  - Confidence telemetry: per-technique confidence distribution
  - Drift analytics: technique coverage changes over time
  - Relationship validation: technique→tactic coherence verification
  - Gap analysis: uncovered ATT&CK tactics and high-priority missing techniques
  - Heat map data: frequency distribution per tactic for dashboard rendering

Outputs:
  data/observability/attck_coverage_report.json (atomic write)
  data/observability/attck_coverage_telemetry.jsonl (append)

Never raises — all errors caught and surfaced in report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinel.attck_coverage")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OBS_DIR = DATA_DIR / "observability"
REPORT_PATH = OBS_DIR / "attck_coverage_report.json"
TELEMETRY_PATH = OBS_DIR / "attck_coverage_telemetry.jsonl"
BASELINE_PATH = OBS_DIR / "attck_coverage_baseline.json"

INTEL_DIR = DATA_DIR / "intelligence"

# ── ATT&CK v15 REFERENCE KNOWLEDGE BASE ──────────────────────────────────────
TACTIC_ORDER = {
    "Reconnaissance": 1, "Resource Development": 2, "Initial Access": 3,
    "Execution": 4, "Persistence": 5, "Privilege Escalation": 6,
    "Defense Evasion": 7, "Credential Access": 8, "Discovery": 9,
    "Lateral Movement": 10, "Collection": 11, "Command and Control": 12,
    "Exfiltration": 13, "Impact": 14,
}

# Technique → tactic mapping (representative subset)
TECHNIQUE_TACTIC_MAP: Dict[str, str] = {
    "T1566": "Initial Access", "T1566.001": "Initial Access", "T1566.002": "Initial Access",
    "T1190": "Initial Access", "T1195": "Initial Access", "T1133": "Initial Access",
    "T1059": "Execution", "T1059.001": "Execution", "T1059.003": "Execution",
    "T1203": "Execution", "T1204": "Execution",
    "T1547": "Persistence", "T1053": "Persistence", "T1078": "Persistence",
    "T1548": "Privilege Escalation", "T1055": "Privilege Escalation",
    "T1027": "Defense Evasion", "T1036": "Defense Evasion", "T1070": "Defense Evasion",
    "T1003": "Credential Access", "T1110": "Credential Access", "T1555": "Credential Access",
    "T1082": "Discovery", "T1083": "Discovery", "T1057": "Discovery",
    "T1021": "Lateral Movement", "T1570": "Lateral Movement",
    "T1560": "Collection", "T1074": "Collection", "T1056": "Collection",
    "T1071": "Command and Control", "T1105": "Command and Control", "T1090": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration",
    "T1486": "Impact", "T1490": "Impact", "T1489": "Impact",
    "T1598": "Reconnaissance", "T1595": "Reconnaissance",
    "T1583": "Resource Development", "T1584": "Resource Development",
}

ALL_TACTICS = set(TACTIC_ORDER.keys())
HIGH_PRIORITY_TECHNIQUES = {
    "T1566", "T1059", "T1190", "T1486", "T1071",
    "T1003", "T1027", "T1547", "T1082", "T1021",
}


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class TacticCoverageEntry:
    tactic: str
    order: int
    technique_count: int
    unique_techniques: int
    advisories_with_tactic: int
    coverage_pct: float
    mean_confidence: float

@dataclass
class KillChainAnalysis:
    complete_chains: int         # advisories covering 5+ ordered tactics
    partial_chains: int          # advisories covering 2-4 tactics
    single_tactic: int           # advisories with only 1 tactic
    mean_chain_length: float     # mean number of distinct tactics per advisory
    dominant_entry_tactic: str   # most common first tactic observed

@dataclass
class ATTCKCoverageReport:
    report_id: str
    generated_at: str
    total_advisories: int
    advisories_with_techniques: int
    technique_coverage_pct: float
    total_unique_techniques: int
    total_unique_tactics: int
    covered_tactics: List[str]
    uncovered_tactics: List[str]
    missing_high_priority: List[str]
    tactic_coverage: List[TacticCoverageEntry]
    kill_chain: KillChainAnalysis
    technique_frequency: Dict[str, int]
    tactic_heat_map: Dict[str, int]
    coherence_violations: int
    drift_detected: bool
    coverage_score: float
    coverage_tier: str
    duration_ms: float = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _short_id(s: str) -> str:
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()[:12]

def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)

def _load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ── TECHNIQUE EXTRACTOR ───────────────────────────────────────────────────────
def _extract_techniques(advisory: Dict) -> List[Dict]:
    """Returns list of technique dicts from an advisory."""
    techs = advisory.get("techniques", advisory.get("ttps", advisory.get("attack_techniques", [])))
    if not isinstance(techs, list):
        return []

    result = []
    for t in techs:
        if isinstance(t, str):
            result.append({"technique_id": t, "tactic": TECHNIQUE_TACTIC_MAP.get(t, "Unknown")})
        elif isinstance(t, dict):
            tid = t.get("technique_id", t.get("id", t.get("technique", "")))
            tactic = t.get("tactic", TECHNIQUE_TACTIC_MAP.get(tid, "Unknown"))
            confidence = t.get("confidence", t.get("score"))
            result.append({"technique_id": tid, "tactic": tactic, "confidence": confidence})
    return result


# ── ANALYZERS ────────────────────────────────────────────────────────────────
class TacticCoverageAnalyzer:

    def analyze(
        self, advisories: List[Dict]
    ) -> Tuple[List[TacticCoverageEntry], Set[str], Dict[str, int]]:
        n = len(advisories)
        tactic_techniques: Dict[str, Set[str]] = defaultdict(set)
        tactic_advisories: Dict[str, int] = defaultdict(int)
        tactic_confidences: Dict[str, List[float]] = defaultdict(list)
        technique_freq: Counter = Counter()
        tactic_heat: Counter = Counter()

        for adv in advisories:
            techs = _extract_techniques(adv)
            adv_tactics: Set[str] = set()
            for t in techs:
                tid = t.get("technique_id", "")
                tactic = t.get("tactic", TECHNIQUE_TACTIC_MAP.get(tid, "Unknown"))
                if tid:
                    tactic_techniques[tactic].add(tid)
                    technique_freq[tid] += 1
                tactic_heat[tactic] += 1
                adv_tactics.add(tactic)
                conf = t.get("confidence")
                if conf is not None:
                    try:
                        tactic_confidences[tactic].append(float(conf))
                    except (TypeError, ValueError):
                        pass
            for tac in adv_tactics:
                tactic_advisories[tac] += 1

        covered_tactics: Set[str] = set(t for t in tactic_techniques if t in ALL_TACTICS and tactic_techniques[t])

        entries: List[TacticCoverageEntry] = []
        for tactic, order in TACTIC_ORDER.items():
            techs = tactic_techniques.get(tactic, set())
            adv_count = tactic_advisories.get(tactic, 0)
            confs = tactic_confidences.get(tactic, [])
            entries.append(TacticCoverageEntry(
                tactic=tactic,
                order=order,
                technique_count=len(techs),
                unique_techniques=len(techs),
                advisories_with_tactic=adv_count,
                coverage_pct=round(adv_count / n * 100, 2) if n > 0 else 0.0,
                mean_confidence=round(sum(confs) / len(confs), 3) if confs else 0.0,
            ))

        return entries, covered_tactics, dict(technique_freq.most_common(50))


class KillChainAnalyzer:

    def analyze(self, advisories: List[Dict]) -> KillChainAnalysis:
        chain_lengths: List[int] = []
        entry_tactics: Counter = Counter()
        complete = 0
        partial = 0
        single = 0

        for adv in advisories:
            techs = _extract_techniques(adv)
            tactics: List[str] = []
            for t in techs:
                tid = t.get("technique_id", "")
                tactic = t.get("tactic", TECHNIQUE_TACTIC_MAP.get(tid, ""))
                if tactic and tactic in TACTIC_ORDER:
                    tactics.append(tactic)

            unique_tactics = list(set(tactics))
            ordered = sorted(unique_tactics, key=lambda x: TACTIC_ORDER.get(x, 99))
            chain_len = len(ordered)
            chain_lengths.append(chain_len)

            if ordered:
                entry_tactics[ordered[0]] += 1

            if chain_len >= 5:
                complete += 1
            elif chain_len >= 2:
                partial += 1
            elif chain_len == 1:
                single += 1

        mean_len = round(sum(chain_lengths) / len(chain_lengths), 2) if chain_lengths else 0.0
        dominant = entry_tactics.most_common(1)[0][0] if entry_tactics else "Unknown"

        return KillChainAnalysis(
            complete_chains=complete,
            partial_chains=partial,
            single_tactic=single,
            mean_chain_length=mean_len,
            dominant_entry_tactic=dominant,
        )


class CoherenceValidator:
    """Validates technique→tactic coherence."""

    def validate(self, advisories: List[Dict]) -> int:
        violations = 0
        for adv in advisories:
            techs = _extract_techniques(adv)
            for t in techs:
                tid = t.get("technique_id", "")
                stated_tactic = t.get("tactic", "")
                expected_tactic = TECHNIQUE_TACTIC_MAP.get(tid, "")
                if (tid and stated_tactic and expected_tactic
                        and stated_tactic != expected_tactic
                        and stated_tactic != "Unknown"):
                    violations += 1
        return violations


# ── DRIFT DETECTOR ───────────────────────────────────────────────────────────
def _detect_coverage_drift(current_unique: int) -> bool:
    baseline = _load_json(BASELINE_PATH)
    if not baseline:
        return False
    prev_unique = baseline.get("unique_techniques", 0)
    delta = abs(current_unique - prev_unique)
    return delta > max(5, prev_unique * 0.15)  # >15% change = drift


def _update_coverage_baseline(unique_techniques: int, covered_tactics: int) -> None:
    snap = {
        "snapshot_at": _now_iso(),
        "unique_techniques": unique_techniques,
        "covered_tactics": covered_tactics,
    }
    try:
        _atomic_write(BASELINE_PATH, snap)
    except Exception:
        pass


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class ATTCKCoverageAnalyticsEngine:

    def __init__(self) -> None:
        self._tactic = TacticCoverageAnalyzer()
        self._killchain = KillChainAnalyzer()
        self._coherence = CoherenceValidator()

    def run_full_pipeline(
        self, advisories: Optional[List[Dict]] = None
    ) -> ATTCKCoverageReport:
        t0 = time.time()
        report_id = f"attck_cov_{_short_id(_now_iso())}"
        logger.info("[ATTCK-COV] Starting ATT&CK coverage analytics %s", report_id)

        if advisories is None:
            advisories = self._load_advisories()

        advisories_with_tech = [
            a for a in advisories
            if _extract_techniques(a)
        ]
        tech_cov_pct = round(
            len(advisories_with_tech) / len(advisories) * 100, 2
        ) if advisories else 0.0

        # Tactic coverage
        tactic_entries, covered_tactics, tech_freq = [], set(), {}
        try:
            tactic_entries, covered_tactics, tech_freq = self._tactic.analyze(advisories)
        except Exception as exc:
            logger.warning("[ATTCK-COV] Tactic analysis error: %s", exc)

        # Kill-chain
        kill_chain = KillChainAnalysis(0, 0, 0, 0.0, "Unknown")
        try:
            kill_chain = self._killchain.analyze(advisories)
        except Exception as exc:
            logger.warning("[ATTCK-COV] Kill-chain error: %s", exc)

        # Coherence
        coherence_violations = 0
        try:
            coherence_violations = self._coherence.validate(advisories)
        except Exception as exc:
            logger.warning("[ATTCK-COV] Coherence error: %s", exc)

        uncovered = sorted(ALL_TACTICS - covered_tactics, key=lambda x: TACTIC_ORDER.get(x, 99))
        missing_hp = [t for t in HIGH_PRIORITY_TECHNIQUES if t not in tech_freq]

        # Tactic heat map
        tactic_heat = {
            e.tactic: e.advisories_with_tactic for e in tactic_entries
        }

        # Drift detection
        drift = False
        try:
            drift = _detect_coverage_drift(len(tech_freq))
        except Exception:
            pass

        # Coverage score
        cov_score, cov_tier = self._score(
            len(covered_tactics), tech_cov_pct, kill_chain.mean_chain_length,
            len(missing_hp), coherence_violations
        )

        report = ATTCKCoverageReport(
            report_id=report_id,
            generated_at=_now_iso(),
            total_advisories=len(advisories),
            advisories_with_techniques=len(advisories_with_tech),
            technique_coverage_pct=tech_cov_pct,
            total_unique_techniques=len(tech_freq),
            total_unique_tactics=len(covered_tactics),
            covered_tactics=sorted(covered_tactics, key=lambda x: TACTIC_ORDER.get(x, 99)),
            uncovered_tactics=uncovered,
            missing_high_priority=missing_hp,
            tactic_coverage=tactic_entries,
            kill_chain=kill_chain,
            technique_frequency=tech_freq,
            tactic_heat_map=tactic_heat,
            coherence_violations=coherence_violations,
            drift_detected=drift,
            coverage_score=cov_score,
            coverage_tier=cov_tier,
            duration_ms=round((time.time() - t0) * 1000, 2),
        )

        self._persist(report)
        _update_coverage_baseline(len(tech_freq), len(covered_tactics))

        logger.info(
            "[ATTCK-COV] Run %s: tactics=%d/%d techniques=%d score=%.1f tier=%s",
            report_id, len(covered_tactics), len(ALL_TACTICS),
            len(tech_freq), cov_score, cov_tier
        )
        return report

    def _score(
        self,
        covered_tactic_count: int,
        tech_cov_pct: float,
        mean_chain_len: float,
        missing_hp_count: int,
        coherence_violations: int,
    ) -> Tuple[float, str]:
        score = 100.0

        # Penalize uncovered tactics
        uncovered_tactics = len(ALL_TACTICS) - covered_tactic_count
        score -= uncovered_tactics * 4.0

        # Penalize low advisory technique coverage
        if tech_cov_pct < 30:
            score -= 20.0
        elif tech_cov_pct < 50:
            score -= 10.0
        elif tech_cov_pct < 70:
            score -= 5.0

        # Penalize shallow kill chains
        if mean_chain_len < 2:
            score -= 15.0
        elif mean_chain_len < 3:
            score -= 8.0

        # Penalize missing high-priority techniques
        score -= missing_hp_count * 3.0

        # Penalize coherence violations
        score -= min(20.0, coherence_violations * 0.5)

        score = round(max(0.0, min(100.0, score)), 2)
        if score >= 80:
            tier = "EXCELLENT"
        elif score >= 65:
            tier = "GOOD"
        elif score >= 50:
            tier = "ACCEPTABLE"
        elif score >= 30:
            tier = "POOR"
        else:
            tier = "CRITICAL"
        return score, tier

    def _load_advisories(self) -> List[Dict]:
        conf_data = _load_json(INTEL_DIR / "explainable_confidence_scores.json")
        if isinstance(conf_data, list) and conf_data:
            return conf_data
        results: List[Dict] = []
        reports_dir = INTEL_DIR / "reports"
        if reports_dir.exists():
            for f in sorted(reports_dir.glob("*.json"))[-30:]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(d, dict):
                        results.append(d)
                    elif isinstance(d, list):
                        results.extend(d[:5])
                except Exception:
                    pass
        return results

    def _persist(self, report: ATTCKCoverageReport) -> None:
        try:
            report_dict = asdict(report)
            _atomic_write(REPORT_PATH, report_dict)

            telem = {
                "report_id": report.report_id,
                "ts": report.generated_at,
                "total": report.total_advisories,
                "with_tech": report.advisories_with_techniques,
                "tech_cov_pct": report.technique_coverage_pct,
                "unique_techniques": report.total_unique_techniques,
                "covered_tactics": report.total_unique_tactics,
                "missing_hp": len(report.missing_high_priority),
                "coherence_violations": report.coherence_violations,
                "score": report.coverage_score,
                "tier": report.coverage_tier,
            }
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(telem) + "\n")
        except Exception as exc:
            logger.error("[ATTCK-COV] Persist error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        report = _load_json(REPORT_PATH)
        if not report:
            return {"status": "no_report"}
        return {
            "status": "ok",
            "score": report.get("coverage_score"),
            "tier": report.get("coverage_tier"),
            "covered_tactics": report.get("total_unique_tactics"),
            "unique_techniques": report.get("total_unique_techniques"),
            "tech_coverage_pct": report.get("technique_coverage_pct"),
            "generated_at": report.get("generated_at"),
        }


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = ATTCKCoverageAnalyticsEngine()
    result = engine.run_full_pipeline()
    print(f"\n[ATTCK-COV] Report: {result.report_id}")
    print(f"  Advisories: {result.total_advisories}  With techniques: {result.advisories_with_techniques}")
    print(f"  Covered tactics: {result.total_unique_tactics}/{len(ALL_TACTICS)}")
    print(f"  Unique techniques: {result.total_unique_techniques}")
    print(f"  Score: {result.coverage_score:.1f}  Tier: {result.coverage_tier}")
    if result.uncovered_tactics:
        print(f"  Uncovered: {', '.join(result.uncovered_tactics[:5])}")
    sys.exit(0 if result.coverage_tier not in ("CRITICAL", "POOR") else 1)
