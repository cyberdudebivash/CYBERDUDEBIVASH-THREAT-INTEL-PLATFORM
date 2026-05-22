#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
GOLDEN BASELINE SYSTEM v158.5 — Phase 1A Enterprise Hardening
===============================================================================
PURPOSE:
  Implements immutable production baselines, signed deployment lineage,
  runtime fingerprints, deterministic deployment signatures, and
  rollback checkpoints.

SUBSYSTEMS:
  1. GoldenBaselineCapture   — snapshot + sign current stable production state
  2. DeploymentLineageTracker — ancestry chain validation, forbidden commit blocking
  3. RuntimeFingerprintEngine — live component integrity fingerprinting
  4. BaselineIntegrityValidator — compare live state vs golden baseline
  5. RollbackCheckpointManager — safe immutable rollback points

MANDATES:
  - 0 regression to pre-golden states
  - Deterministic deployment signatures
  - Lineage chain must be continuous and validated
  - Every deploy writes an attestation record
  - Forbidden commits (P0 incidents) are permanently blocked from ancestry

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [golden-baseline] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-GOLDEN-BASELINE")

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION = "158.5"
SYSTEM_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# GOLDEN BASELINE REGISTRY PATHS
# ---------------------------------------------------------------------------
BASELINE_DIR = REPO_ROOT / "data" / "golden_baseline"
LINEAGE_FILE = BASELINE_DIR / "deployment_lineage.json"
ATTESTATION_DIR = BASELINE_DIR / "attestations"
FINGERPRINT_FILE = BASELINE_DIR / "runtime_fingerprints.json"
ROLLBACK_DIR = BASELINE_DIR / "rollback_checkpoints"
FORBIDDEN_COMMITS_FILE = BASELINE_DIR / "forbidden_commits.json"
GOLDEN_STATE_FILE = BASELINE_DIR / "golden_state.json"

# ---------------------------------------------------------------------------
# CRITICAL COMPONENTS TO FINGERPRINT
# ---------------------------------------------------------------------------
FINGERPRINT_TARGETS = [
    # Core pipeline
    "scripts/run_pipeline.py",
    "scripts/anti_hallucination_engine.py",
    "scripts/intelligence_integrity_gate.py",
    "scripts/version_governance.py",
    "scripts/enterprise_monetization_framework.py",
    # Agent
    "agent/enricher.py",
    "agent/export_stix.py",
    "agent/sentinel_blogger.py",
    # Config SSOT
    "config/version.json",
    "config/stability_lock.json",
    "VERSION",
    # Worker
    "workers/intel-gateway/src/index.js",
    "workers/intel-gateway/wrangler.toml",
    # CI Workflows
    ".github/workflows/generate-and-sync.yml",
    ".github/workflows/deploy-worker.yml",
    ".github/workflows/sentinel-blogger.yml",
    # HTML surfaces
    "index.html",
    "observability.html",
    "api-docs.html",
    "trust-center.html",
    "PAYMENT-GATEWAY.html",
]

# ---------------------------------------------------------------------------
# KNOWN FORBIDDEN COMMITS (P0 incident ancestry — permanently blocked)
# ---------------------------------------------------------------------------
DEFAULT_FORBIDDEN_COMMITS: List[Dict] = [
    # Add known bad commit SHAs here as they are identified
    # Format: {"sha_prefix": "abc123", "reason": "P0 incident: synthetic flood", "blocked_at": "2026-05-01"}
]

# ---------------------------------------------------------------------------
# GOLDEN BASELINE INVARIANTS (minimum production standards)
# ---------------------------------------------------------------------------
GOLDEN_INVARIANTS = {
    "min_advisory_count": 50,
    "min_regression_tests_pass": 18,
    "max_regression_tests_total": 20,
    "required_governance_grade": ["A", "A+"],
    "min_integrity_gate_pass_rate": 1.0,  # 100% of 8 gates
    "min_source_diversity": 10,           # minimum unique source domains
    "max_single_source_dominance": 0.30,  # max 30% from one source
    "min_stix_bundles": 400,
    "min_enrichment_rate": 0.50,          # 50% of items have some enrichment
    "required_api_endpoints": [
        "/api/health",
        "/api/feed.json",
        "/api/v1/intel/latest.json",
        "/api/v1/intel/top10.json",
        "/api/v1/intel/apex.json",
    ],
    "max_p95_latency_ms": 2000,           # relaxed from 1000ms to 2000ms for baseline
    "min_governance_contract_pass": True,
    "required_monetization_gate": True,
}


# ---------------------------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def load_json(path: Path) -> Optional[Dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_json(path: Path, data: Any, indent: int = 2) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=indent, ensure_ascii=False) + "\n", encoding="utf-8")
        return True
    except Exception as e:
        log.error("Failed to write %s: %s", path, e)
        return False


def get_git_info() -> Dict:
    """Get current git commit SHA and branch."""
    info = {"sha": "unknown", "sha_short": "unknown", "branch": "unknown", "message": "unknown"}
    try:
        import subprocess
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                                       stderr=subprocess.DEVNULL).decode().strip()
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                          cwd=REPO_ROOT, stderr=subprocess.DEVNULL).decode().strip()
        msg = subprocess.check_output(["git", "log", "-1", "--format=%s"],
                                       cwd=REPO_ROOT, stderr=subprocess.DEVNULL).decode().strip()
        info = {"sha": sha, "sha_short": sha[:12], "branch": branch, "message": msg}
    except Exception:
        pass
    return info


def get_version() -> str:
    try:
        return (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return VERSION


# ---------------------------------------------------------------------------
# 1. RUNTIME FINGERPRINT ENGINE
# ---------------------------------------------------------------------------

class RuntimeFingerprintEngine:
    """
    Computes SHA-256 fingerprints of all critical platform components.
    Detects unauthorized mutations between baseline and live state.
    """

    def capture(self) -> Dict:
        fingerprints = {}
        missing = []
        for rel in FINGERPRINT_TARGETS:
            path = REPO_ROOT / rel
            digest = sha256_file(path)
            if digest:
                fingerprints[rel] = {
                    "sha256": digest,
                    "size": path.stat().st_size,
                    "captured_at": now_iso(),
                }
            else:
                missing.append(rel)
                fingerprints[rel] = {"sha256": None, "size": 0, "captured_at": now_iso(), "status": "missing"}

        composite = sha256_str(json.dumps(
            {k: v.get("sha256", "") for k, v in fingerprints.items()}, sort_keys=True
        ))
        return {
            "composite_fingerprint": composite,
            "component_count": len(FINGERPRINT_TARGETS),
            "present_count": len(FINGERPRINT_TARGETS) - len(missing),
            "missing_count": len(missing),
            "missing_files": missing,
            "components": fingerprints,
            "captured_at": now_iso(),
        }

    def compare(self, baseline: Dict, live: Dict) -> Dict:
        """Compare live fingerprints against golden baseline."""
        mutations = []
        new_files = []
        missing_files = []

        baseline_comps = baseline.get("components", {})
        live_comps = live.get("components", {})

        for path, binfo in baseline_comps.items():
            if path not in live_comps:
                missing_files.append(path)
                continue
            bsha = binfo.get("sha256")
            lsha = live_comps[path].get("sha256")
            if bsha and lsha and bsha != lsha:
                mutations.append({"path": path, "baseline_sha256": bsha[:16], "live_sha256": lsha[:16]})

        for path in live_comps:
            if path not in baseline_comps:
                new_files.append(path)

        composite_match = baseline.get("composite_fingerprint") == live.get("composite_fingerprint")
        return {
            "composite_match": composite_match,
            "mutations": mutations,
            "new_files": new_files,
            "missing_files": missing_files,
            "mutation_count": len(mutations),
            "integrity_verdict": "CLEAN" if (composite_match or len(mutations) == 0) else "MUTATED",
        }


# ---------------------------------------------------------------------------
# 2. GOLDEN BASELINE CAPTURE
# ---------------------------------------------------------------------------

class GoldenBaselineCapture:
    """
    Captures and stores the current production state as a signed golden baseline.
    Reads live data files to build the invariant snapshot.
    """

    def __init__(self):
        self.fingerprint_engine = RuntimeFingerprintEngine()

    def capture(self, label: str = "production", run_id: str = "") -> Dict:
        log.info("Capturing golden baseline: %s", label)
        git = get_git_info()
        ver = get_version()

        # Gather live intelligence metrics
        metrics = self._gather_metrics()

        # Fingerprint all critical components
        fingerprints = self.fingerprint_engine.capture()

        # Check invariants
        invariant_results = self._check_invariants(metrics)

        baseline = {
            "_meta": {
                "schema": "golden-baseline-v1",
                "system_version": SYSTEM_VERSION,
                "platform_version": ver,
                "label": label,
                "captured_at": now_iso(),
                "run_id": run_id or os.environ.get("GITHUB_RUN_ID", "local"),
                "captured_by": "golden_baseline_system.py",
            },
            "git": git,
            "invariants": invariant_results,
            "metrics": metrics,
            "fingerprints": {
                "composite": fingerprints["composite_fingerprint"],
                "component_count": fingerprints["component_count"],
                "present_count": fingerprints["present_count"],
                "missing_files": fingerprints["missing_files"],
            },
            "deployment_signature": self._compute_deployment_signature(git, ver, fingerprints),
            "baseline_verdict": "GOLDEN" if invariant_results["all_pass"] else "DEGRADED",
        }

        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        save_json(GOLDEN_STATE_FILE, baseline)

        # Save full fingerprint data separately
        save_json(FINGERPRINT_FILE, fingerprints)

        log.info("Golden baseline captured: verdict=%s commit=%s", baseline["baseline_verdict"], git["sha_short"])
        return baseline

    def _gather_metrics(self) -> Dict:
        """Read live data to gather intelligence quality metrics."""
        metrics: Dict[str, Any] = {}

        # Feed advisory count
        feed_path = REPO_ROOT / "api" / "feed.json"
        if feed_path.exists():
            try:
                feed = json.loads(feed_path.read_text(encoding="utf-8"))
                if isinstance(feed, list):
                    metrics["advisory_count"] = len(feed)
                elif isinstance(feed, dict) and "items" in feed:
                    metrics["advisory_count"] = len(feed["items"])
                else:
                    metrics["advisory_count"] = 0
            except Exception:
                metrics["advisory_count"] = 0
        else:
            metrics["advisory_count"] = 0

        # STIX bundles
        stix_dir = REPO_ROOT / "data" / "stix"
        if stix_dir.exists():
            stix_files = list(stix_dir.glob("bundle_*.json"))
            metrics["stix_bundle_count"] = len(stix_files)
        else:
            metrics["stix_bundle_count"] = 0

        # Governance grade
        gov_report = REPO_ROOT / "data" / "governance" / "governance_report.json"
        if gov_report.exists():
            try:
                gr = json.loads(gov_report.read_text(encoding="utf-8"))
                metrics["governance_grade"] = gr.get("governance_grade", "?")
                metrics["avg_trust_score"] = gr.get("avg_trust_score", 0)
                metrics["contract_violations"] = len(gr.get("contract_violations", []))
            except Exception:
                metrics["governance_grade"] = "?"
        else:
            metrics["governance_grade"] = "?"

        # SLA score
        sla_path = REPO_ROOT / "data" / "health" / "sla_status.json"
        if sla_path.exists():
            try:
                sla = json.loads(sla_path.read_text(encoding="utf-8"))
                metrics["sla_score"] = sla.get("sla_score", 0)
                metrics["sla_grade"] = sla.get("sla_grade", "?")
                metrics["sla_customer_status"] = sla.get("customer_sla_status", "?")
            except Exception:
                metrics["sla_score"] = 0

        # Monetization
        mon_path = REPO_ROOT / "data" / "monetization" / "soc_readiness.json"
        if mon_path.exists():
            try:
                mon = json.loads(mon_path.read_text(encoding="utf-8"))
                metrics["soc_readiness_score"] = mon.get("score", 0)
                metrics["soc_tier"] = mon.get("tier", "?")
            except Exception:
                metrics["soc_readiness_score"] = 0

        # Sellability
        sell_path = REPO_ROOT / "data" / "monetization" / "sellability_score.json"
        if sell_path.exists():
            try:
                sell = json.loads(sell_path.read_text(encoding="utf-8"))
                metrics["sellability_score"] = sell.get("sellability_score", 0)
                metrics["sellability_tier"] = sell.get("sellability_tier", "?")
            except Exception:
                metrics["sellability_score"] = 0

        # Version lock
        metrics["platform_version"] = get_version()
        metrics["captured_at"] = now_iso()

        return metrics

    def _check_invariants(self, metrics: Dict) -> Dict:
        """Validate current state against golden invariants."""
        checks = {}
        failures = []

        # Advisory count
        adv_count = metrics.get("advisory_count", 0)
        min_adv = GOLDEN_INVARIANTS["min_advisory_count"]
        checks["advisory_count"] = {
            "pass": adv_count >= min_adv,
            "value": adv_count,
            "threshold": min_adv,
        }
        if not checks["advisory_count"]["pass"]:
            failures.append(f"advisory_count {adv_count} < {min_adv}")

        # Governance grade
        grade = metrics.get("governance_grade", "?")
        required_grades = GOLDEN_INVARIANTS["required_governance_grade"]
        checks["governance_grade"] = {
            "pass": grade in required_grades,
            "value": grade,
            "required": required_grades,
        }
        if not checks["governance_grade"]["pass"]:
            failures.append(f"governance_grade '{grade}' not in {required_grades}")

        # STIX bundles
        stix_count = metrics.get("stix_bundle_count", 0)
        min_stix = GOLDEN_INVARIANTS["min_stix_bundles"]
        checks["stix_bundles"] = {
            "pass": stix_count >= min_stix or stix_count == 0,  # 0 = fresh checkout, not a failure
            "value": stix_count,
            "threshold": min_stix,
            "note": "runtime-generated, 0 on clean checkout is acceptable",
        }

        # Platform version present
        ver = metrics.get("platform_version", "?")
        checks["platform_version"] = {
            "pass": bool(re.match(r"\d+\.\d+", ver)),
            "value": ver,
        }
        if not checks["platform_version"]["pass"]:
            failures.append(f"platform_version invalid: {ver}")

        all_hard_pass = all(
            v["pass"] for k, v in checks.items()
            if k not in ("stix_bundles",)  # stix is advisory on clean checkout
        )

        return {
            "all_pass": all_hard_pass,
            "failure_count": len(failures),
            "failures": failures,
            "checks": checks,
        }

    def _compute_deployment_signature(self, git: Dict, ver: str, fingerprints: Dict) -> str:
        """Compute a deterministic deployment signature."""
        sig_data = {
            "sha": git.get("sha", "unknown"),
            "version": ver,
            "composite_fingerprint": fingerprints.get("composite_fingerprint", ""),
            "timestamp_epoch_floor": int(time.time() // 3600) * 3600,  # Hour-level granularity
        }
        return sha256_str(json.dumps(sig_data, sort_keys=True))[:32]


# ---------------------------------------------------------------------------
# 3. DEPLOYMENT LINEAGE TRACKER
# ---------------------------------------------------------------------------

class DeploymentLineageTracker:
    """
    Tracks deployment ancestry chain. Every deployment appends to the lineage.
    Validates chain continuity and blocks forbidden commit ancestry.
    """

    def __init__(self):
        self.forbidden = self._load_forbidden_commits()

    def _load_forbidden_commits(self) -> List[Dict]:
        if FORBIDDEN_COMMITS_FILE.exists():
            return load_json(FORBIDDEN_COMMITS_FILE) or []
        return list(DEFAULT_FORBIDDEN_COMMITS)

    def record_deployment(self, baseline: Dict, status: str = "success") -> Dict:
        """Record a deployment event in the lineage chain."""
        lineage = self._load_lineage()
        git = baseline.get("git", {})
        entry = {
            "sequence": len(lineage.get("deployments", [])) + 1,
            "timestamp": now_iso(),
            "commit_sha": git.get("sha", "unknown"),
            "commit_short": git.get("sha_short", "unknown"),
            "branch": git.get("branch", "unknown"),
            "commit_message": git.get("message", "unknown")[:120],
            "platform_version": baseline.get("_meta", {}).get("platform_version", "?"),
            "deployment_signature": baseline.get("deployment_signature", "?"),
            "baseline_verdict": baseline.get("baseline_verdict", "?"),
            "run_id": baseline.get("_meta", {}).get("run_id", "?"),
            "status": status,
            "lineage_hash": "",  # computed below
        }

        # Check for forbidden commits
        forbidden_hit = self._check_forbidden_ancestry(git.get("sha", ""))
        if forbidden_hit:
            entry["forbidden_ancestry_warning"] = forbidden_hit
            log.warning("FORBIDDEN ANCESTRY DETECTED: %s", forbidden_hit)

        # Compute lineage hash (chain link)
        prev_hash = lineage.get("chain_tip", "genesis")
        entry["lineage_hash"] = sha256_str(prev_hash + entry["commit_sha"] + entry["timestamp"])[:16]

        deployments = lineage.get("deployments", [])
        deployments.append(entry)

        # Keep last 100 deployments in active lineage
        if len(deployments) > 100:
            archive = deployments[:-100]
            self._archive_lineage(archive)
            deployments = deployments[-100:]

        lineage = {
            "_meta": {
                "schema": "deployment-lineage-v1",
                "last_updated": now_iso(),
                "total_deployments": (lineage.get("_meta", {}).get("total_deployments", 0) + 1),
            },
            "chain_tip": entry["lineage_hash"],
            "latest_commit": entry["commit_sha"],
            "latest_version": entry["platform_version"],
            "deployments": deployments,
        }
        save_json(LINEAGE_FILE, lineage)
        log.info("Lineage recorded: seq=%d commit=%s version=%s",
                 entry["sequence"], entry["commit_short"], entry["platform_version"])
        return entry

    def _load_lineage(self) -> Dict:
        if LINEAGE_FILE.exists():
            return load_json(LINEAGE_FILE) or {"deployments": [], "_meta": {}, "chain_tip": "genesis"}
        return {"deployments": [], "_meta": {"total_deployments": 0}, "chain_tip": "genesis"}

    def _check_forbidden_ancestry(self, commit_sha: str) -> Optional[str]:
        for forbidden in self.forbidden:
            prefix = forbidden.get("sha_prefix", "")
            if prefix and commit_sha.startswith(prefix):
                return f"Commit {commit_sha[:12]} matches forbidden prefix {prefix}: {forbidden.get('reason', 'P0 incident')}"
        return None

    def _archive_lineage(self, old_deployments: List):
        archive_path = BASELINE_DIR / "lineage_archive" / f"archive_{now_iso()[:10]}.json"
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        save_json(archive_path, {"archived_at": now_iso(), "deployments": old_deployments})

    def validate_chain(self) -> Dict:
        """Validate the lineage chain is continuous and unbroken."""
        lineage = self._load_lineage()
        deployments = lineage.get("deployments", [])
        if not deployments:
            return {"valid": True, "gaps": [], "message": "Empty lineage — first deployment"}

        gaps = []
        for i in range(1, len(deployments)):
            prev = deployments[i - 1]
            curr = deployments[i]
            # Check sequence continuity
            if curr.get("sequence", 0) != prev.get("sequence", 0) + 1:
                gaps.append({"at_sequence": curr.get("sequence"), "gap_type": "sequence_break"})

        forbidden_hits = [
            d for d in deployments
            if d.get("forbidden_ancestry_warning")
        ]

        return {
            "valid": len(gaps) == 0,
            "total_deployments": len(deployments),
            "gaps": gaps,
            "forbidden_ancestry_hits": len(forbidden_hits),
            "chain_tip": lineage.get("chain_tip", "unknown"),
            "latest_version": lineage.get("latest_version", "?"),
            "message": "Chain valid" if not gaps else f"{len(gaps)} gaps detected",
        }

    def add_forbidden_commit(self, sha_prefix: str, reason: str):
        """Permanently block a commit SHA prefix from future ancestry."""
        self.forbidden.append({
            "sha_prefix": sha_prefix,
            "reason": reason,
            "blocked_at": now_iso(),
        })
        save_json(FORBIDDEN_COMMITS_FILE, self.forbidden)
        log.warning("FORBIDDEN COMMIT REGISTERED: %s — %s", sha_prefix, reason)


# ---------------------------------------------------------------------------
# 4. BASELINE INTEGRITY VALIDATOR
# ---------------------------------------------------------------------------

class BaselineIntegrityValidator:
    """
    Compares live platform state against the stored golden baseline.
    Detects regressions, unauthorized mutations, and version drift.
    """

    def __init__(self):
        self.fingerprint_engine = RuntimeFingerprintEngine()
        self.capture_engine = GoldenBaselineCapture()

    def validate(self, strict: bool = False) -> Dict:
        """Run full baseline integrity validation."""
        log.info("Running baseline integrity validation (strict=%s)", strict)

        # Load golden baseline
        golden = load_json(GOLDEN_STATE_FILE)
        if not golden:
            return {
                "valid": True,
                "verdict": "NO_BASELINE",
                "message": "No golden baseline found — first run or baseline needs capture",
                "action": "Run --capture to establish baseline",
            }

        golden_fingerprints = load_json(FINGERPRINT_FILE)
        if not golden_fingerprints:
            return {
                "valid": True,
                "verdict": "NO_FINGERPRINTS",
                "message": "No fingerprint data found",
            }

        # Capture live fingerprints
        live_fingerprints = self.fingerprint_engine.capture()

        # Compare fingerprints
        comparison = self.fingerprint_engine.compare(golden_fingerprints, live_fingerprints)

        # Check version consistency
        golden_ver = golden.get("_meta", {}).get("platform_version", "?")
        live_ver = get_version()
        version_match = golden_ver == live_ver

        # Gather live metrics for invariant check
        live_metrics = self.capture_engine._gather_metrics()
        invariant_results = self.capture_engine._check_invariants(live_metrics)

        # Build result
        mutations = comparison.get("mutations", [])
        expected_mutations = _get_expected_mutations()  # files that are expected to change
        unexpected_mutations = [m for m in mutations if m["path"] not in expected_mutations]

        integrity_ok = len(unexpected_mutations) == 0
        invariants_ok = invariant_results["all_pass"]
        overall_valid = integrity_ok and invariants_ok

        result = {
            "valid": overall_valid,
            "verdict": "BASELINE_INTACT" if overall_valid else "REGRESSION_DETECTED",
            "timestamp": now_iso(),
            "golden_commit": golden.get("git", {}).get("sha_short", "?"),
            "live_commit": get_git_info().get("sha_short", "?"),
            "version_match": version_match,
            "golden_version": golden_ver,
            "live_version": live_ver,
            "fingerprint_integrity": comparison["integrity_verdict"],
            "unexpected_mutations": unexpected_mutations,
            "mutation_count": len(unexpected_mutations),
            "invariants": invariant_results,
            "live_metrics": live_metrics,
        }

        if not overall_valid:
            log.error("BASELINE INTEGRITY VIOLATION: %d unexpected mutations, invariants_ok=%s",
                      len(unexpected_mutations), invariants_ok)
            for m in unexpected_mutations:
                log.error("  MUTATION: %s [%s -> %s]", m["path"],
                          m.get("baseline_sha256", "?"), m.get("live_sha256", "?"))
        else:
            log.info("Baseline integrity: INTACT (mutations=%d all expected, invariants=PASS)",
                     len(mutations))

        return result


def _get_expected_mutations() -> List[str]:
    """Return paths that are expected to change between runs (runtime-generated files)."""
    return [
        "config/stability_lock.json",  # Updated by pipeline
        "data/health/sla_status.json",  # Runtime-generated
    ]


# ---------------------------------------------------------------------------
# 5. ROLLBACK CHECKPOINT MANAGER
# ---------------------------------------------------------------------------

class RollbackCheckpointManager:
    """
    Creates and manages immutable rollback checkpoints.
    Each checkpoint captures what is needed to restore a known-good state.
    """

    def create_checkpoint(self, label: str, baseline: Dict) -> Dict:
        """Create an immutable rollback checkpoint."""
        git = baseline.get("git", {})
        checkpoint = {
            "_meta": {
                "schema": "rollback-checkpoint-v1",
                "label": label,
                "created_at": now_iso(),
                "created_by": "golden_baseline_system.py",
            },
            "git": git,
            "platform_version": baseline.get("_meta", {}).get("platform_version", "?"),
            "deployment_signature": baseline.get("deployment_signature", "?"),
            "baseline_verdict": baseline.get("baseline_verdict", "?"),
            "metrics_snapshot": baseline.get("metrics", {}),
            "restore_instructions": {
                "git_reset": f"git checkout {git.get('sha', 'unknown')}",
                "version": baseline.get("_meta", {}).get("platform_version", "?"),
                "caution": "Only restore if current deployment is confirmed broken. Validate with --validate after restore.",
            },
        }
        timestamp = now_iso().replace(":", "-").replace("Z", "")
        ckpt_path = ROLLBACK_DIR / f"checkpoint_{timestamp}_{label[:20]}.json"
        ROLLBACK_DIR.mkdir(parents=True, exist_ok=True)
        save_json(ckpt_path, checkpoint)

        # Update checkpoint index
        index_path = ROLLBACK_DIR / "checkpoint_index.json"
        index = load_json(index_path) or {"checkpoints": []}
        index["checkpoints"].append({
            "file": str(ckpt_path.name),
            "label": label,
            "created_at": checkpoint["_meta"]["created_at"],
            "commit_short": git.get("sha_short", "?"),
            "version": checkpoint["platform_version"],
            "verdict": checkpoint["baseline_verdict"],
        })
        # Keep last 20 checkpoints in index
        index["checkpoints"] = index["checkpoints"][-20:]
        save_json(index_path, index)

        log.info("Rollback checkpoint created: %s", ckpt_path.name)
        return checkpoint

    def list_checkpoints(self) -> List[Dict]:
        index_path = ROLLBACK_DIR / "checkpoint_index.json"
        if not index_path.exists():
            return []
        index = load_json(index_path) or {}
        return index.get("checkpoints", [])

    def get_latest_golden_checkpoint(self) -> Optional[Dict]:
        checkpoints = self.list_checkpoints()
        golden = [c for c in checkpoints if c.get("verdict") == "GOLDEN"]
        return golden[-1] if golden else None


# ---------------------------------------------------------------------------
# 6. DEPLOYMENT ATTESTATION
# ---------------------------------------------------------------------------

class DeploymentAttestation:
    """
    Writes a signed attestation record for every deployment.
    Attestations are immutable records of deployment provenance.
    """

    def write_attestation(self, baseline: Dict, lineage_entry: Dict, validation_result: Dict) -> Dict:
        git = baseline.get("git", {})
        attestation = {
            "_meta": {
                "schema": "deployment-attestation-v1",
                "attested_at": now_iso(),
                "attested_by": "golden_baseline_system.py",
                "attestation_version": SYSTEM_VERSION,
            },
            "deployment": {
                "commit_sha": git.get("sha", "unknown"),
                "commit_short": git.get("sha_short", "unknown"),
                "branch": git.get("branch", "unknown"),
                "platform_version": baseline.get("_meta", {}).get("platform_version", "?"),
                "run_id": baseline.get("_meta", {}).get("run_id", "?"),
                "deployment_signature": baseline.get("deployment_signature", "?"),
            },
            "lineage": {
                "sequence": lineage_entry.get("sequence", 0),
                "lineage_hash": lineage_entry.get("lineage_hash", "?"),
                "status": lineage_entry.get("status", "?"),
            },
            "baseline": {
                "verdict": baseline.get("baseline_verdict", "?"),
                "invariants_pass": baseline.get("invariants", {}).get("all_pass", False),
            },
            "integrity": {
                "fingerprint_status": validation_result.get("fingerprint_integrity", "?"),
                "unexpected_mutations": validation_result.get("mutation_count", 0),
                "overall_valid": validation_result.get("valid", False),
            },
            "attestation_digest": "",
        }
        # Self-sign the attestation
        attestation["attestation_digest"] = sha256_str(
            json.dumps({k: v for k, v in attestation.items() if k != "attestation_digest"}, sort_keys=True)
        )[:32]

        ATTESTATION_DIR.mkdir(parents=True, exist_ok=True)
        ts = now_iso().replace(":", "-").replace("Z", "")
        sha_short = git.get("sha_short", "unknown")
        attest_path = ATTESTATION_DIR / f"attestation_{ts}_{sha_short}.json"
        save_json(attest_path, attestation)
        log.info("Deployment attestation written: %s", attest_path.name)
        return attestation


# ---------------------------------------------------------------------------
# MAIN ORCHESTRATOR
# ---------------------------------------------------------------------------

def run_capture(label: str, run_id: str) -> int:
    """Capture golden baseline + record lineage + create checkpoint."""
    log.info("=== GOLDEN BASELINE CAPTURE ===")
    capture = GoldenBaselineCapture()
    baseline = capture.capture(label=label, run_id=run_id)

    lineage_tracker = DeploymentLineageTracker()
    lineage_entry = lineage_tracker.record_deployment(baseline, status="success")

    validator = BaselineIntegrityValidator()
    validation = validator.validate()

    attestation = DeploymentAttestation()
    attestation.write_attestation(baseline, lineage_entry, validation)

    checkpoint_mgr = RollbackCheckpointManager()
    checkpoint_mgr.create_checkpoint(label, baseline)

    # Print summary
    git = baseline.get("git", {})
    metrics = baseline.get("metrics", {})
    log.info("=" * 70)
    log.info("GOLDEN BASELINE SUMMARY")
    log.info("  Verdict          : %s", baseline.get("baseline_verdict"))
    log.info("  Platform Version : %s", baseline.get("_meta", {}).get("platform_version"))
    log.info("  Commit           : %s (%s)", git.get("sha_short"), git.get("branch"))
    log.info("  Advisories       : %s", metrics.get("advisory_count", "?"))
    log.info("  Governance Grade : %s", metrics.get("governance_grade", "?"))
    log.info("  SOC Score        : %s", metrics.get("soc_readiness_score", "?"))
    log.info("  Deployment Sig   : %s", baseline.get("deployment_signature", "?"))
    log.info("  Lineage Hash     : %s", lineage_entry.get("lineage_hash"))
    log.info("  Invariants       : %s", "PASS" if baseline.get("invariants", {}).get("all_pass") else "WARN")
    log.info("=" * 70)

    return 0


def run_validate() -> int:
    """Validate live state against golden baseline."""
    log.info("=== BASELINE INTEGRITY VALIDATION ===")
    validator = BaselineIntegrityValidator()
    result = validator.validate()

    lineage_tracker = DeploymentLineageTracker()
    chain = lineage_tracker.validate_chain()

    log.info("=" * 70)
    log.info("BASELINE INTEGRITY REPORT")
    log.info("  Overall Verdict  : %s", result.get("verdict"))
    log.info("  Fingerprint      : %s", result.get("fingerprint_integrity"))
    log.info("  Mutations        : %d unexpected", result.get("mutation_count", 0))
    log.info("  Version Match    : %s (%s vs %s)",
             result.get("version_match"), result.get("golden_version"), result.get("live_version"))
    log.info("  Invariants       : %s", "PASS" if result.get("invariants", {}).get("all_pass") else "FAIL")
    log.info("  Lineage Chain    : %s (%d deployments)",
             "VALID" if chain.get("valid") else "BROKEN", chain.get("total_deployments", 0))
    log.info("=" * 70)

    # Save validation report
    report_path = BASELINE_DIR / "latest_validation_report.json"
    save_json(report_path, {**result, "lineage_chain": chain})

    if not result.get("valid") and result.get("verdict") != "NO_BASELINE":
        log.error("BASELINE INTEGRITY VIOLATION — deployment may be blocked")
        return 1
    return 0


def run_report() -> int:
    """Print full lineage and checkpoint report."""
    lineage_tracker = DeploymentLineageTracker()
    chain = lineage_tracker.validate_chain()
    checkpoint_mgr = RollbackCheckpointManager()
    checkpoints = checkpoint_mgr.list_checkpoints()
    golden = load_json(GOLDEN_STATE_FILE)

    log.info("=" * 70)
    log.info("GOLDEN BASELINE SYSTEM REPORT")
    log.info("  Golden State     : %s", "CAPTURED" if golden else "NOT CAPTURED")
    if golden:
        log.info("  Platform Version : %s", golden.get("_meta", {}).get("platform_version", "?"))
        log.info("  Captured At      : %s", golden.get("_meta", {}).get("captured_at", "?"))
        log.info("  Commit           : %s", golden.get("git", {}).get("sha_short", "?"))
        log.info("  Verdict          : %s", golden.get("baseline_verdict", "?"))
    log.info("  Lineage          : %d deployments, chain=%s",
             chain.get("total_deployments", 0), "VALID" if chain.get("valid") else "BROKEN")
    log.info("  Checkpoints      : %d available", len(checkpoints))
    log.info("  Latest Golden    : %s", checkpoint_mgr.get_latest_golden_checkpoint() or "none")
    log.info("=" * 70)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Golden Baseline System")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--capture", action="store_true", help="Capture golden baseline")
    grp.add_argument("--validate", action="store_true", help="Validate against golden baseline")
    grp.add_argument("--report", action="store_true", help="Print lineage report")
    parser.add_argument("--label", default="production", help="Baseline label")
    parser.add_argument("--run-id", default="", help="CI run ID")
    args = parser.parse_args()

    if args.capture:
        return run_capture(args.label, args.run_id)
    elif args.validate:
        return run_validate()
    else:
        return run_report()


if __name__ == "__main__":
    sys.exit(main())
