#!/usr/bin/env python3
"""
scripts/self_improve_recommender.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Self-Improving Engine: Recommendation Engine
=================================================================================
PHASE 3: Improvement Recommendation Engine

Reads data/system_health.json produced by self_improve_monitor.py
Analyses anomalies + metrics and produces:
    - Ranked, actionable recommendations
    - Priority-ordered action plan
    - Estimated impact per recommendation
    - Safe-action flags (can auto-execute vs. requires human approval)

SAFETY CONTRACT:
    - READ ONLY: reads health data, never modifies platform files
    - Zero regression: additive recommendation layer only
    - All recommendations include rollback guidance

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.recommender")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"

HEALTH_PATH = _DATA / "system_health.json"
RECOMMENDATIONS_PATH = _DATA / "recommendations.json"


# ---------------------------------------------------------------------------
# Recommendation Impact Model
# ---------------------------------------------------------------------------
# action_key → human-readable label, safe_auto, description, command, rollback
_ACTION_CATALOGUE: Dict[str, Dict] = {
    # ── Safe auto-actions (Phase 4 allowed) ───────────────────────────────
    "clear_cache": {
        "label":       "Clear data cache",
        "safe_auto":   True,
        "description": "Remove stale cached data files to force fresh ingestion on next run.",
        "command":     "python scripts/bust_kv_cache.py --all",
        "rollback":    "Cache rebuilt automatically on next pipeline run. No data loss.",
        "estimated_fix_time_min": 2,
    },
    "rebuild_manifest": {
        "label":       "Rebuild feed manifest",
        "safe_auto":   True,
        "description": "Re-run manifest builder to consolidate all intel sources into feed_manifest.json.",
        "command":     "python scripts/rebuild_manifest.py",
        "rollback":    "Previous manifest backed up to data/.manifest_backups/ automatically.",
        "estimated_fix_time_min": 5,
    },
    "refresh_feed": {
        "label":       "Refresh API feed files",
        "safe_auto":   True,
        "description": "Regenerate api/feed.json and api/latest.json from current manifest.",
        "command":     "python scripts/master_p0_fix.py",
        "rollback":    "Restore api/feed.json from git: git checkout HEAD -- api/feed.json",
        "estimated_fix_time_min": 3,
    },
    "rerun_apex_ai": {
        "label":       "Force APEX AI rebuild on all items",
        "safe_auto":   True,
        "description": "Run master_p0_fix.py to unconditionally rebuild apex_ai block on every intel item.",
        "command":     "python scripts/master_p0_fix.py --force-apex-rebuild",
        "rollback":    "git checkout HEAD -- api/feed.json api/latest.json",
        "estimated_fix_time_min": 5,
    },
    "run_dedup_validation": {
        "label":       "Validate + clean dedup state",
        "safe_auto":   True,
        "description": "Run dedup_state.py validation against current manifest to purge stale fingerprints.",
        "command":     "python scripts/dedup_state.py --validate-manifest",
        "rollback":    "data/processed_intel.json is backed up as .tmp before any write.",
        "estimated_fix_time_min": 2,
    },
    "run_regression_tests": {
        "label":       "Run full regression test suite",
        "safe_auto":   True,
        "description": "Execute regression_tests.py to verify system integrity before/after changes.",
        "command":     "python scripts/regression_tests.py",
        "rollback":    "No changes made — read-only validation.",
        "estimated_fix_time_min": 3,
    },
    "validate_intel_schema": {
        "label":       "Validate intel schema integrity",
        "safe_auto":   True,
        "description": "Run validate_intel_schema.py to detect missing required fields and malformed items.",
        "command":     "python scripts/validate_intel_schema.py",
        "rollback":    "Read-only — no changes made.",
        "estimated_fix_time_min": 2,
    },
    "seed_dedup_state": {
        "label":       "Seed dedup state from manifest",
        "safe_auto":   True,
        "description": "Bootstrap dedup state from all existing manifest items to prevent future duplicates.",
        "command":     "python scripts/dedup_state.py --seed-manifest",
        "rollback":    "data/processed_intel.json.tmp preserved by atomic write.",
        "estimated_fix_time_min": 3,
    },

    # ── Requires human approval ───────────────────────────────────────────
    "add_new_feed_sources": {
        "label":       "Add new intel feed sources",
        "safe_auto":   False,
        "description": "Integrate additional threat intel sources (OTX, CISA, MISP) to diversify coverage.",
        "command":     "MANUAL: Edit scripts/run_pipeline.py — add new source URLs to FEED_SOURCES list.",
        "rollback":    "Remove added source URLs from FEED_SOURCES. Rerun pipeline.",
        "estimated_fix_time_min": 60,
        "requires_approval": True,
        "approval_reason": "Adding new sources changes ingestion flow and may introduce unvalidated data.",
    },
    "recalibrate_risk_scoring": {
        "label":       "Recalibrate APEX AI risk scoring thresholds",
        "safe_auto":   False,
        "description": "Adjust P1/P2/P3/P4 risk_score thresholds in build_apex_ai() to improve accuracy.",
        "command":     "MANUAL: Edit scripts/master_p0_fix.py — modify risk threshold constants.",
        "rollback":    "git revert last commit to master_p0_fix.py",
        "estimated_fix_time_min": 30,
        "requires_approval": True,
        "approval_reason": "Modifies core APEX AI scoring logic. Requires SOC validation before deployment.",
    },
    "change_dedup_threshold": {
        "label":       "Tighten title similarity dedup threshold",
        "safe_auto":   False,
        "description": "Lower Jaccard similarity threshold in enforce_feed_uniqueness() to catch more near-dupes.",
        "command":     "MANUAL: Edit scripts/dedup_state.py — adjust similarity_threshold parameter.",
        "rollback":    "git revert last commit to dedup_state.py",
        "estimated_fix_time_min": 15,
        "requires_approval": True,
        "approval_reason": "Changing dedup sensitivity may over-filter legitimate intel variants.",
    },
    "update_pipeline_schedule": {
        "label":       "Increase pipeline run frequency",
        "safe_auto":   False,
        "description": "Modify GitHub Actions cron schedule in sentinel-blogger.yml to run more frequently.",
        "command":     "MANUAL: Edit .github/workflows/sentinel-blogger.yml — update cron expression.",
        "rollback":    "git revert last commit to sentinel-blogger.yml",
        "estimated_fix_time_min": 10,
        "requires_approval": True,
        "approval_reason": "Changes CI/CD scheduling — requires repo admin to approve workflow changes.",
    },
    "add_monitoring_alerts": {
        "label":       "Configure external alerting for health anomalies",
        "safe_auto":   False,
        "description": "Integrate Telegram/email alerts when system_health score drops below threshold.",
        "command":     "MANUAL: Configure scripts/pipeline_alert.py with webhook endpoints.",
        "rollback":    "Disable alert config. No platform changes.",
        "estimated_fix_time_min": 20,
        "requires_approval": True,
        "approval_reason": "Requires external service credentials and outbound network configuration.",
    },
}

# Anomaly category → recommended action keys (in priority order)
_CATEGORY_ACTION_MAP: Dict[str, List[str]] = {
    "DEDUP": [
        "run_dedup_validation",
        "seed_dedup_state",
        "rebuild_manifest",
        "change_dedup_threshold",
    ],
    "STALE": [
        "refresh_feed",
        "rebuild_manifest",
        "clear_cache",
        "add_new_feed_sources",
        "update_pipeline_schedule",
    ],
    "FEED": [
        "rebuild_manifest",
        "validate_intel_schema",
        "refresh_feed",
        "clear_cache",
        "add_new_feed_sources",
    ],
    "RUNTIME": [
        "run_regression_tests",
        "clear_cache",
        "update_pipeline_schedule",
    ],
    "AI_INCONSISTENCY": [
        "rerun_apex_ai",
        "refresh_feed",
        "recalibrate_risk_scoring",
    ],
    "API": [
        "refresh_feed",
        "rebuild_manifest",
        "run_regression_tests",
        "add_monitoring_alerts",
    ],
    "SECURITY": [
        "run_regression_tests",
        "validate_intel_schema",
        "rebuild_manifest",
    ],
}

# Severity → priority level for recommendations
_SEVERITY_PRIORITY = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}


# ---------------------------------------------------------------------------
# Recommendation Builder
# ---------------------------------------------------------------------------

class Recommendation:
    """A single actionable recommendation."""

    def __init__(
        self,
        rec_id: str,
        priority: int,
        action_key: str,
        title: str,
        description: str,
        rationale: str,
        safe_auto: bool,
        command: str,
        rollback: str,
        estimated_fix_time_min: int,
        triggered_by: List[str],
        requires_approval: bool = False,
        approval_reason: str = "",
        estimated_impact: str = "",
    ) -> None:
        self.rec_id = rec_id
        self.priority = priority
        self.action_key = action_key
        self.title = title
        self.description = description
        self.rationale = rationale
        self.safe_auto = safe_auto
        self.command = command
        self.rollback = rollback
        self.estimated_fix_time_min = estimated_fix_time_min
        self.triggered_by = triggered_by
        self.requires_approval = requires_approval
        self.approval_reason = approval_reason
        self.estimated_impact = estimated_impact
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            "rec_id":                  self.rec_id,
            "priority":                self.priority,
            "action_key":              self.action_key,
            "title":                   self.title,
            "description":             self.description,
            "rationale":               self.rationale,
            "safe_auto":               self.safe_auto,
            "command":                 self.command,
            "rollback":                self.rollback,
            "estimated_fix_time_min":  self.estimated_fix_time_min,
            "triggered_by":            self.triggered_by,
            "requires_approval":       self.requires_approval,
            "approval_reason":         self.approval_reason,
            "estimated_impact":        self.estimated_impact,
            "created_at":              self.created_at,
        }


class RecommendationEngine:
    """
    Phase 3: Analyses health data and produces ranked, actionable recommendations.

    Logic:
        1. Map each anomaly to candidate action_keys via _CATEGORY_ACTION_MAP
        2. Deduplicate across anomalies (each action recommended once)
        3. Rank by anomaly severity + action safety (auto-safe first)
        4. Enrich with catalogue metadata
        5. Generate natural-language rationale
    """

    def __init__(self, health_report: Dict[str, Any]) -> None:
        self.health = health_report
        self.metrics = health_report.get("metrics", {})
        self.anomalies = health_report.get("anomalies", [])
        self._recommendations: List[Recommendation] = []
        self._action_seq = 0
        self._seen_actions: set = set()

    def _next_id(self) -> str:
        self._action_seq += 1
        return f"REC-{self._action_seq:03d}"

    def _build_rationale(self, anomaly: Dict, action_key: str) -> str:
        """Generate natural-language rationale linking anomaly to action."""
        sev = anomaly.get("severity", "UNKNOWN")
        title = anomaly.get("title", "")
        metric_key = anomaly.get("metric_key", "")
        metric_val = anomaly.get("metric_value")
        threshold = anomaly.get("threshold")

        rationale = f"[{sev}] {title}"
        if metric_key and metric_val is not None:
            if threshold is not None:
                rationale += f" — {metric_key}={metric_val} (threshold: {threshold})"
            else:
                rationale += f" — {metric_key}={metric_val}"
        return rationale

    def _estimate_impact(self, action_key: str, anomalies: List[Dict]) -> str:
        """Estimate business impact of resolving these anomalies via this action."""
        categories = {a.get("category") for a in anomalies}
        severities = {a.get("severity") for a in anomalies}

        if "CRITICAL" in severities and "AI_INCONSISTENCY" in categories:
            return "HIGH: Restores accurate SOC prioritisation. Analysts receive correct P1/P2 alerts. Reduces MTTR."
        if "CRITICAL" in severities and "FEED" in categories:
            return "HIGH: Restores intel ingestion. Eliminates intelligence blind spot."
        if "HIGH" in severities and "DEDUP" in categories:
            return "MEDIUM: Reduces duplicate noise. Improves analyst efficiency. Reduces false positive rate."
        if "STALE" in categories:
            return "MEDIUM: Restores fresh threat intelligence. Reduces exposure window from stale data."
        if "API" in categories:
            return "MEDIUM: Restores dashboard data freshness. Improves user experience."
        if action_key == "run_regression_tests":
            return "LOW: Validates system integrity. Prevents undetected regressions."
        return "LOW: General system hygiene improvement."

    def generate_from_anomalies(self) -> None:
        """Generate recommendations for each anomaly."""
        for anomaly in self.anomalies:
            category = anomaly.get("category", "")
            severity = anomaly.get("severity", "LOW")
            base_priority = _SEVERITY_PRIORITY.get(severity, 4)
            action_keys = _CATEGORY_ACTION_MAP.get(category, ["run_regression_tests"])

            for i, action_key in enumerate(action_keys):
                if action_key in self._seen_actions:
                    continue  # already recommended
                self._seen_actions.add(action_key)

                catalogue = _ACTION_CATALOGUE.get(action_key, {})
                if not catalogue:
                    continue

                triggered_anomalies = [anomaly.get("anomaly_id", "")]
                rationale = self._build_rationale(anomaly, action_key)
                impact = self._estimate_impact(action_key, [anomaly])

                # Sub-priority: safe auto-actions first within same severity
                priority = base_priority * 10 + (0 if catalogue.get("safe_auto") else 5) + i

                self._recommendations.append(Recommendation(
                    rec_id=self._next_id(),
                    priority=priority,
                    action_key=action_key,
                    title=catalogue["label"],
                    description=catalogue["description"],
                    rationale=rationale,
                    safe_auto=catalogue.get("safe_auto", False),
                    command=catalogue["command"],
                    rollback=catalogue["rollback"],
                    estimated_fix_time_min=catalogue.get("estimated_fix_time_min", 10),
                    triggered_by=triggered_anomalies,
                    requires_approval=catalogue.get("requires_approval", False),
                    approval_reason=catalogue.get("approval_reason", ""),
                    estimated_impact=impact,
                ))

    def generate_baseline_recommendations(self) -> None:
        """Always-present baseline recommendations regardless of anomalies."""
        always_actions = [
            ("run_regression_tests", 99, "Baseline: Run regression tests to verify system integrity."),
            ("validate_intel_schema", 98, "Baseline: Validate intel schema on every cycle."),
        ]
        for action_key, priority, rationale in always_actions:
            if action_key in self._seen_actions:
                continue
            catalogue = _ACTION_CATALOGUE.get(action_key, {})
            if not catalogue:
                continue
            self._seen_actions.add(action_key)
            self._recommendations.append(Recommendation(
                rec_id=self._next_id(),
                priority=priority,
                action_key=action_key,
                title=catalogue["label"],
                description=catalogue["description"],
                rationale=rationale,
                safe_auto=catalogue.get("safe_auto", True),
                command=catalogue["command"],
                rollback=catalogue["rollback"],
                estimated_fix_time_min=catalogue.get("estimated_fix_time_min", 3),
                triggered_by=["BASELINE"],
                requires_approval=False,
                approval_reason="",
                estimated_impact="LOW: Continuous validation baseline.",
            ))

    def generate_metric_based_recommendations(self) -> None:
        """Generate recommendations directly from metric values (not anomaly-driven)."""
        # PRO_REQUIRED count
        pro_count = self.metrics.get("dedup_pro_required_count", 0)
        if pro_count > 0 and "rerun_apex_ai" not in self._seen_actions:
            self._seen_actions.add("rerun_apex_ai")
            cat = _ACTION_CATALOGUE["rerun_apex_ai"]
            self._recommendations.append(Recommendation(
                rec_id=self._next_id(),
                priority=5,
                action_key="rerun_apex_ai",
                title=cat["label"],
                description=cat["description"],
                rationale=f"Metric: {pro_count} live feed items still carry kill_chain='PRO_REQUIRED'. "
                          "P0 fix is not reflected in current API output.",
                safe_auto=True,
                command=cat["command"],
                rollback=cat["rollback"],
                estimated_fix_time_min=cat["estimated_fix_time_min"],
                triggered_by=["METRIC:dedup_pro_required_count"],
                estimated_impact="HIGH: Eliminates paywall artifacts from free-tier users.",
            ))

        # Feed age
        feed_age = self.metrics.get("api_feed_age_hours")
        if isinstance(feed_age, float) and feed_age > 6 and "refresh_feed" not in self._seen_actions:
            self._seen_actions.add("refresh_feed")
            cat = _ACTION_CATALOGUE["refresh_feed"]
            self._recommendations.append(Recommendation(
                rec_id=self._next_id(),
                priority=25,
                action_key="refresh_feed",
                title=cat["label"],
                description=cat["description"],
                rationale=f"Metric: api/feed.json is {feed_age:.1f}h old. Dashboard data is stale.",
                safe_auto=True,
                command=cat["command"],
                rollback=cat["rollback"],
                estimated_fix_time_min=cat["estimated_fix_time_min"],
                triggered_by=["METRIC:api_feed_age_hours"],
                estimated_impact="MEDIUM: Restores dashboard freshness for users.",
            ))

    def get_sorted_recommendations(self) -> List[Dict]:
        """Return recommendations sorted by priority (lowest number = highest priority)."""
        sorted_recs = sorted(self._recommendations, key=lambda r: r.priority)
        return [r.to_dict() for r in sorted_recs]

    def run(self) -> List[Dict]:
        """Execute full recommendation generation pipeline."""
        self.generate_from_anomalies()
        self.generate_metric_based_recommendations()
        self.generate_baseline_recommendations()
        recs = self.get_sorted_recommendations()
        log.info(
            "[RECOMMENDER] Generated %d recommendations (%d safe-auto, %d require approval)",
            len(recs),
            sum(1 for r in recs if r["safe_auto"]),
            sum(1 for r in recs if r["requires_approval"]),
        )
        return recs


# ---------------------------------------------------------------------------
# Summary Builder
# ---------------------------------------------------------------------------

def _build_executive_summary(
    health: Dict, anomalies: List[Dict], recommendations: List[Dict]
) -> Dict[str, Any]:
    """Build a concise executive summary for reporting."""
    score = health.get("score", 0)
    status = health.get("status", "UNKNOWN")
    grade = health.get("grade", "?")

    critical_anoms = [a for a in anomalies if a.get("severity") == "CRITICAL"]
    high_anoms = [a for a in anomalies if a.get("severity") == "HIGH"]
    auto_recs = [r for r in recommendations if r.get("safe_auto")]
    manual_recs = [r for r in recommendations if not r.get("safe_auto")]

    narrative_parts = []
    if critical_anoms:
        narrative_parts.append(
            f"CRITICAL: {', '.join(a['title'][:50] for a in critical_anoms[:3])}."
        )
    if high_anoms:
        narrative_parts.append(
            f"HIGH: {', '.join(a['title'][:50] for a in high_anoms[:2])}."
        )
    if not anomalies:
        narrative_parts.append("No anomalies detected. System operating nominally.")

    return {
        "health_score":          score,
        "health_grade":          grade,
        "system_status":         status,
        "total_anomalies":       len(anomalies),
        "critical_anomalies":    len(critical_anoms),
        "high_anomalies":        len(high_anoms),
        "total_recommendations": len(recommendations),
        "auto_executable":       len(auto_recs),
        "requires_approval":     len(manual_recs),
        "narrative":             " ".join(narrative_parts)[:500],
        "top_3_actions":         [r["title"] for r in recommendations[:3]],
    }


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def run_recommender(
    health_report: Optional[Dict] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Phase 3 execution:
        1. Load health report (from file or parameter)
        2. Generate ranked recommendations
        3. Write data/recommendations.json
    Returns the full recommendations report.
    """
    log.info("[RECOMMENDER] ====== RECOMMENDATION ENGINE CYCLE START ======")

    if health_report is None:
        if not HEALTH_PATH.exists():
            log.error("[RECOMMENDER] Health report not found at %s — run monitor first", HEALTH_PATH)
            return {"error": "health_report_missing", "recommendations": []}
        health_report = json.loads(HEALTH_PATH.read_text(encoding="utf-8"))

    engine = RecommendationEngine(health_report)
    recommendations = engine.run()

    health = health_report.get("health", {})
    anomalies = health_report.get("anomalies", [])
    summary = _build_executive_summary(health, anomalies, recommendations)

    output: Dict[str, Any] = {
        "schema_version":    "2.0",
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "based_on_report":   health_report.get("generated_at", ""),
        "executive_summary": summary,
        "recommendations":   recommendations,
        "action_catalogue":  _ACTION_CATALOGUE,
    }

    if not dry_run:
        try:
            RECOMMENDATIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = RECOMMENDATIONS_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
            try:
                import os
                with open(tmp, "rb") as fh:
                    os.fsync(fh.fileno())
            except OSError:
                pass
            import os
            os.replace(tmp, RECOMMENDATIONS_PATH)
            log.info("[RECOMMENDER] Recommendations written: %s (%d total)",
                     RECOMMENDATIONS_PATH, len(recommendations))
        except Exception as exc:
            log.error("[RECOMMENDER] Write failed: %s", exc)

    log.info("[RECOMMENDER] ====== CYCLE COMPLETE: %d recommendations ======",
             len(recommendations))
    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [recommender] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    parser = argparse.ArgumentParser(description="SENTINEL APEX — Recommendation Engine")
    parser.add_argument("--dry-run", action="store_true", help="Run without writing output")
    parser.add_argument("--json",    action="store_true", help="Print full JSON to stdout")
    parser.add_argument("--auto-only", action="store_true",
                        help="Show only safe auto-executable recommendations")
    args = parser.parse_args()

    result = run_recommender(dry_run=args.dry_run)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        summary = result.get("executive_summary", {})
        recs = result.get("recommendations", [])
        if args.auto_only:
            recs = [r for r in recs if r.get("safe_auto")]

        print(f"\n{'='*65}")
        print(f"  SENTINEL APEX — RECOMMENDATION ENGINE REPORT")
        print(f"  Health: {summary.get('health_score')}/100 [{summary.get('system_status')}]")
        print(f"  {summary.get('narrative', '')}")
        print(f"  Total: {len(recs)} recommendations | "
              f"Auto: {summary.get('auto_executable')} | "
              f"Manual: {summary.get('requires_approval')}")
        print(f"{'='*65}\n")

        for r in recs:
            auto_tag = "[AUTO]" if r["safe_auto"] else "[MANUAL-APPROVAL]"
            print(f"  [{r['priority']:3d}] {auto_tag:18s} {r['title']}")
            print(f"        Rationale: {r['rationale'][:80]}")
            print(f"        Command:   {r['command'][:80]}")
            print(f"        Impact:    {r['estimated_impact'][:80]}")
            if r.get("requires_approval"):
                print(f"        Approval:  {r['approval_reason'][:80]}")
            print()

        if not args.dry_run:
            print(f"Recommendations written to: {RECOMMENDATIONS_PATH}")
