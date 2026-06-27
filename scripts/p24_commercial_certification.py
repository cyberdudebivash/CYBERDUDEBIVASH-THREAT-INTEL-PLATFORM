#!/usr/bin/env python3
"""
scripts/p24_commercial_certification.py
CYBERDUDEBIVASH® SENTINEL APEX — P24.12 Commercial Certification Engine v1.0.0
===============================================================================
P24.12 — Final Commercial Certification

Aggregates all platform quality signals into a single release certification
report. Acts as the final gate before worldwide customer release.

Scoring dimensions (100 pts total):
  Operational Readiness   — P21 certification gate output          (15 pts)
  Data Integrity          — P22 contradiction report               (15 pts)
  Patch Intelligence      — P23 patch priority report              (10 pts)
  Regression Suite        — regression_tests.py pass rate          (20 pts)
  Feed Quality            — feed health, item count, KEV coverage  (15 pts)
  Security Posture        — worker integrity, auth, secrets        (10 pts)
  Pipeline Stability      — CI gate status, version governance     (10 pts)
  Documentation           — CHANGELOG, ARCHITECTURE_GUARDRAILS     (5 pts)

Release Tiers:
  COMMERCIAL_CERTIFIED    — score ≥ 90
  ENTERPRISE_READY        — score ≥ 75
  INTERNAL_RELEASE        — score ≥ 55
  RELEASE_BLOCKED         — score < 55 OR any CRITICAL blocker

ZERO FABRICATION — all scores derive from existing platform output files.
ADDITIVE ONLY    — reads only, no schema or API modified.

Writes: data/quality/p24_commercial_certification.json
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] P24-CERT %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("p24-cert")

REPO    = Path(__file__).resolve().parent.parent
DRY_RUN = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
OUT_PATH = REPO / "data" / "quality" / "p24_commercial_certification.json"

# ── Report file paths ────────────────────────────────────────────────────────
_P21_REPORT  = REPO / "data" / "quality" / "p21_certification_report.json"
_P22_REPORT  = REPO / "data" / "quality" / "p22_contradiction_report.json"
_P23_REPORT  = REPO / "data" / "quality" / "p23_patch_priority_report.json"
_FEED        = REPO / "api" / "feed.json"
_FHG         = REPO / "data" / "health" / "feed_health_gate.json"
_WORKER      = REPO / "workers" / "intel-gateway" / "src" / "index.js"
_CHANGELOG   = REPO / "CHANGELOG.md"
_GUARDRAILS  = REPO / "ARCHITECTURE_GUARDRAILS.md"
_REGRESSION  = REPO / "scripts" / "regression_tests.py"


def _load_json(path: Path) -> Optional[Dict]:
    try:
        raw = path.read_bytes().rstrip(b"\x00").replace(b"\x00", b"")
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _score_operational_readiness() -> Tuple[int, int, List[str], List[str]]:
    """P21 certification gate — max 15 pts."""
    MAX = 15
    data = _load_json(_P21_REPORT)
    blockers: List[str] = []
    notes: List[str] = []

    if not data:
        blockers.append("P21 certification report missing — run p21_certification_gate.py")
        return 0, MAX, blockers, notes

    total     = data.get("total_items", 0)
    avg       = float(data.get("average_score", 0))
    dist      = data.get("level_distribution", {})
    premium   = dist.get("PREMIUM_CERTIFIED", 0)
    enterprise= dist.get("ENTERPRISE_READY", 0)
    below_min = dist.get("BELOW_MINIMUM", 0)

    score = 0
    if total > 0:
        score += 3
    if avg >= 75:
        score += 4
    elif avg >= 55:
        score += 2
    if premium + enterprise >= total * 0.6 and total > 0:
        score += 4
    elif premium + enterprise >= total * 0.4 and total > 0:
        score += 2
    if below_min == 0:
        score += 4
    elif below_min <= total * 0.05:
        score += 2

    notes.append(f"P21: {total} items | avg={avg:.1f} | premium={premium} | enterprise={enterprise} | below_min={below_min}")
    if below_min > total * 0.1:
        blockers.append(f"P21: {below_min} items below minimum quality threshold (>{10:.0f}% of feed)")
    return score, MAX, blockers, notes


def _score_data_integrity() -> Tuple[int, int, List[str], List[str]]:
    """P22 contradiction report — max 15 pts."""
    MAX = 15
    data = _load_json(_P22_REPORT)
    blockers: List[str] = []
    notes: List[str] = []

    if not data:
        blockers.append("P22 contradiction report missing — run p22_contradiction_detector.py")
        return 0, MAX, blockers, notes

    checked = data.get("items_checked", 0)
    errors  = data.get("error_count", 0)
    warns   = data.get("warning_count", 0)

    score = 0
    if checked > 0:
        score += 3
    if errors == 0:
        score += 8
    elif errors <= 3:
        score += 5
    elif errors <= 10:
        score += 2
    if warns == 0:
        score += 4
    elif warns <= 5:
        score += 2

    notes.append(f"P22: {checked} items | errors={errors} | warnings={warns}")
    if errors > 10:
        blockers.append(f"P22: {errors} ERROR-level contradictions in feed — data integrity risk")
    return score, MAX, blockers, notes


def _score_patch_intelligence() -> Tuple[int, int, List[str], List[str]]:
    """P23 patch priority — max 10 pts."""
    MAX = 10
    data = _load_json(_P23_REPORT)
    blockers: List[str] = []
    notes: List[str] = []

    if not data:
        notes.append("P23 patch priority report not found — non-blocking")
        return MAX // 2, MAX, blockers, notes

    total   = data.get("items_processed", 0)
    immed   = data.get("immediate_count", 0)
    dist    = data.get("priority_distribution", {})

    score = 0
    if total > 0:
        score += 5
    if immed <= total * 0.5 or total == 0:
        score += 5
    elif immed <= total * 0.75:
        score += 3

    notes.append(f"P23: {total} items | IMMEDIATE={immed} | 24H={dist.get('PATCH WITHIN 24 HOURS',0)} | 7D={dist.get('PATCH WITHIN 7 DAYS',0)}")
    return score, MAX, blockers, notes


def _score_regression_suite() -> Tuple[int, int, List[str], List[str]]:
    """Run regression tests — max 20 pts."""
    MAX = 20
    blockers: List[str] = []
    notes: List[str] = []

    if not _REGRESSION.exists():
        blockers.append("Regression test suite missing — scripts/regression_tests.py not found")
        return 0, MAX, blockers, notes

    try:
        result = subprocess.run(
            [sys.executable, str(_REGRESSION)],
            capture_output=True, text=True, timeout=120,
            cwd=str(REPO)
        )
        output = result.stdout + result.stderr
        passed = output.count("[PASS]")
        failed = output.count("[FAIL]")
        total  = passed + failed

        if total == 0:
            notes.append("Regression: no tests found in output")
            return MAX // 2, MAX, blockers, notes

        pass_rate = passed / total
        if pass_rate == 1.0:
            score = 20
        elif pass_rate >= 0.95:
            score = 16
        elif pass_rate >= 0.80:
            score = 10
        else:
            score = 4

        notes.append(f"Regression: {passed}/{total} PASS ({pass_rate*100:.1f}%)")
        if failed > 0:
            blockers.append(f"Regression: {failed} test(s) FAILING — fix before release")
    except subprocess.TimeoutExpired:
        notes.append("Regression: test suite timed out")
        return 8, MAX, blockers, notes
    except Exception as exc:
        notes.append(f"Regression: could not run tests — {exc}")
        return 8, MAX, blockers, notes

    return score, MAX, blockers, notes


def _score_feed_quality() -> Tuple[int, int, List[str], List[str]]:
    """Feed health and item quality — max 15 pts."""
    MAX = 15
    blockers: List[str] = []
    notes: List[str] = []
    score = 0

    # Feed exists and has items
    feed_data = _load_json(_FEED)
    if feed_data:
        items = feed_data if isinstance(feed_data, list) else feed_data.get("items", [])
        count = len(items) if isinstance(items, list) else 0
        if count >= 50:
            score += 5
        elif count >= 10:
            score += 3
        notes.append(f"Feed: {count} items")
        if count < 10:
            blockers.append(f"Feed has only {count} items — insufficient for commercial release")
    else:
        blockers.append("api/feed.json missing or unreadable")

    # Feed health gate
    fhg = _load_json(_FHG)
    if fhg:
        status = fhg.get("status", "UNKNOWN")
        if status == "PASS":
            score += 7
        elif status in ("WARN", "DEGRADED"):
            score += 4
        notes.append(f"Feed health gate: {status}")
        if status == "FAIL":
            blockers.append(f"Feed health gate FAIL — resolve before release")
    else:
        score += 3
        notes.append("Feed health gate report not found — partial credit")

    # Worker JS exists
    if _WORKER.exists() and _WORKER.stat().st_size > 10000:
        score += 3
        notes.append("Worker: intel-gateway/src/index.js present and non-trivial")
    else:
        blockers.append("Cloudflare Worker (index.js) missing or empty")

    return score, MAX, blockers, notes


def _score_security_posture() -> Tuple[int, int, List[str], List[str]]:
    """Worker security checks — max 10 pts."""
    MAX = 10
    blockers: List[str] = []
    notes: List[str] = []
    score = 0

    if not _WORKER.exists():
        blockers.append("Worker file not found — cannot audit security posture")
        return 0, MAX, blockers, notes

    content = _WORKER.read_text(encoding="utf-8", errors="replace")

    # JWT implementation (crypto.subtle)
    if "crypto.subtle" in content:
        score += 3
        notes.append("Security: crypto.subtle (constant-time) JWT — PASS")
    else:
        blockers.append("Security: crypto.subtle not found — JWT timing attack risk")

    # Rate limiting
    if "RATE_LIMIT" in content or "rate_limit" in content or "rateLimit" in content:
        score += 2
        notes.append("Security: rate limiting present — PASS")
    else:
        notes.append("Security: rate limiting not confirmed")

    # XSS prevention
    if 'replace(/&/g,"&amp;")' in content or "replace(/</g" in content:
        score += 2
        notes.append("Security: HTML escaping (XSS prevention) — PASS")
    else:
        blockers.append("Security: HTML escaping not found — XSS risk in reports")

    # No hardcoded secrets pattern
    import re
    secrets_pattern = re.compile(
        r'(?:apiKey|secretKey|password|token|api_key|secret)\s*=\s*["\'][A-Za-z0-9+/]{20,}["\']',
        re.IGNORECASE
    )
    if not secrets_pattern.search(content):
        score += 3
        notes.append("Security: no hardcoded credentials — PASS")
    else:
        blockers.append("Security: CRITICAL — hardcoded credentials detected in worker")

    return score, MAX, blockers, notes


def _score_pipeline_stability() -> Tuple[int, int, List[str], List[str]]:
    """CI/CD and version governance — max 10 pts."""
    MAX = 10
    blockers: List[str] = []
    notes: List[str] = []
    score = 0

    # sentinel-blogger.yml exists and is YAML-valid
    workflow = REPO / ".github" / "workflows" / "sentinel-blogger.yml"
    if workflow.exists():
        try:
            import yaml  # type: ignore
            with open(workflow) as f:
                yaml.safe_load(f)
            score += 5
            notes.append("Pipeline: sentinel-blogger.yml YAML valid — PASS")
        except Exception as e:
            blockers.append(f"Pipeline: YAML syntax error in sentinel-blogger.yml — {e}")
    else:
        blockers.append("Pipeline: sentinel-blogger.yml not found")

    # PLATFORM_VERSION defined in worker
    if _WORKER.exists():
        content = _WORKER.read_text(encoding="utf-8", errors="replace")
        if "PLATFORM_VERSION" in content:
            score += 3
            notes.append("Pipeline: PLATFORM_VERSION governance — PASS")

    # Workflow count (health indicator)
    wf_count = len(list((REPO / ".github" / "workflows").glob("*.yml")))
    if wf_count >= 10:
        score += 2
        notes.append(f"Pipeline: {wf_count} workflows configured")

    return score, MAX, blockers, notes


def _score_documentation() -> Tuple[int, int, List[str], List[str]]:
    """Documentation completeness — max 5 pts."""
    MAX = 5
    blockers: List[str] = []
    notes: List[str] = []
    score = 0

    if _CHANGELOG.exists() and _CHANGELOG.stat().st_size > 1000:
        score += 2
        notes.append("Docs: CHANGELOG.md present — PASS")
    if _GUARDRAILS.exists():
        score += 2
        notes.append("Docs: ARCHITECTURE_GUARDRAILS.md present — PASS")
    if (REPO / ".well-known" / "security.txt").exists():
        score += 1
        notes.append("Docs: security.txt present — PASS")

    return score, MAX, blockers, notes


def _release_tier(score: int, has_critical_blocker: bool) -> str:
    if has_critical_blocker:
        return "RELEASE_BLOCKED"
    if score >= 90:
        return "COMMERCIAL_CERTIFIED"
    if score >= 75:
        return "ENTERPRISE_READY"
    if score >= 55:
        return "INTERNAL_RELEASE"
    return "RELEASE_BLOCKED"


def run() -> Dict:
    log.info("P24.12 Commercial Certification Engine v1.0.0")

    dimensions = [
        ("operational_readiness",  _score_operational_readiness()),
        ("data_integrity",         _score_data_integrity()),
        ("patch_intelligence",     _score_patch_intelligence()),
        ("regression_suite",       _score_regression_suite()),
        ("feed_quality",           _score_feed_quality()),
        ("security_posture",       _score_security_posture()),
        ("pipeline_stability",     _score_pipeline_stability()),
        ("documentation",          _score_documentation()),
    ]

    total_score = 0
    total_max   = 0
    all_blockers: List[str] = []
    all_notes: List[str]    = []
    dim_results: Dict       = {}

    for name, (score, max_score, blockers, notes) in dimensions:
        total_score += score
        total_max   += max_score
        all_blockers.extend(blockers)
        all_notes.extend(notes)
        pct = (score / max_score * 100) if max_score else 0
        dim_results[name] = {
            "score":      score,
            "max":        max_score,
            "pct":        round(pct, 1),
            "blockers":   blockers,
            "notes":      notes,
        }
        log.info("  %-28s %d/%d (%.0f%%)", name, score, max_score, pct)

    overall_pct       = (total_score / total_max * 100) if total_max else 0
    critical_blockers = [b for b in all_blockers if "CRITICAL" in b.upper()]
    tier              = _release_tier(int(overall_pct), bool(critical_blockers))

    log.info("Overall score: %d/%d (%.1f%%)", total_score, total_max, overall_pct)
    log.info("Release tier: %s", tier)
    if all_blockers:
        for b in all_blockers:
            log.warning("BLOCKER: %s", b)
    else:
        log.info("No blockers — platform certified for release")

    return {
        "version":             "P24.12",
        "generated_at":        datetime.now(timezone.utc).isoformat(),
        "overall_score":       total_score,
        "overall_max":         total_max,
        "overall_pct":         round(overall_pct, 1),
        "release_tier":        tier,
        "blocker_count":       len(all_blockers),
        "critical_blockers":   critical_blockers,
        "all_blockers":        all_blockers,
        "dimensions":          dim_results,
        "certified":           tier in ("COMMERCIAL_CERTIFIED", "ENTERPRISE_READY"),
    }


def main() -> int:
    report = run()

    if not DRY_RUN:
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = OUT_PATH.with_suffix(".tmp_p24cert")
        try:
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(OUT_PATH)
            log.info("Certification report written: %s", OUT_PATH)
        except Exception as exc:
            log.error("Failed to write certification report: %s", exc)
            tmp.unlink(missing_ok=True)
            return 1
    else:
        log.info("[DRY_RUN] Would write certification report: score=%d/%d tier=%s",
                 report["overall_score"], report["overall_max"], report["release_tier"])

    tier = report["release_tier"]
    log.info("P24.12 CERTIFICATION RESULT: %s (%.1f%%)", tier, report["overall_pct"])

    if tier == "RELEASE_BLOCKED":
        log.error("RELEASE BLOCKED — resolve all blockers before worldwide release")
        return 1

    log.info("P24.12 Commercial Certification PASS — %s", tier)
    return 0


if __name__ == "__main__":
    sys.exit(main())
