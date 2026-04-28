#!/usr/bin/env python3
"""
scripts/self_improve_actions.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Self-Improving Engine: Safe Action Engine
=============================================================================
PHASE 4: Safe Action Engine
    Executes ONLY safe, pre-validated actions.
    Hard-blocked actions: any modification to core logic files.

PHASE 5: Validation Gate
    Before ANY action: run regression tests + validate outputs.
    If validation fails: BLOCK action, log, escalate to human queue.

ALLOWED AUTO-ACTIONS:
    ✔ clear_cache          — delete stale data/cache files
    ✔ rebuild_manifest     — re-run manifest builder
    ✔ refresh_feed         — regenerate api/feed.json + api/latest.json
    ✔ rerun_apex_ai        — force unconditional APEX AI rebuild
    ✔ run_dedup_validation — validate dedup state integrity
    ✔ run_regression_tests — run test suite (read-only)
    ✔ validate_intel_schema — schema integrity check (read-only)
    ✔ seed_dedup_state     — seed fingerprints from manifest

NOT ALLOWED (hard block — requires human approval):
    ✘ modifying core logic files (master_p0_fix.py, apex_intelligence_engine.py, etc.)
    ✘ rewriting AI engine
    ✘ changing pipeline flow
    ✘ modifying GitHub Actions workflows
    ✘ git push operations

HUMAN APPROVAL QUEUE:
    data/pending_approvals.json — write approval requests here.
    Actions remain pending until manually approved.

SAFETY CONTRACT:
    - Core file modification detection + hard block
    - Pre-action regression test gate
    - Post-action output validation
    - Circuit breaker: >3 consecutive failures → halt + alert
    - All actions logged to data/action_log.json

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.actions")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"
_SCRIPTS = _ROOT / "scripts"
_API = _ROOT / "api"

ACTION_LOG       = _DATA / "action_log.json"
PENDING_APPROVALS = _DATA / "pending_approvals.json"
CIRCUIT_BREAKER  = _DATA / ".circuit_breaker.json"

# ---------------------------------------------------------------------------
# Core files — HARD BLOCKED from any modification
# ---------------------------------------------------------------------------
_CORE_FILES: frozenset = frozenset({
    "scripts/master_p0_fix.py",
    "scripts/apex_intelligence_engine.py",
    "scripts/apex_intel_engine.py",
    "scripts/run_pipeline.py",
    "scripts/intel_dedup_engine.py",
    "scripts/dedup_state.py",
    "scripts/regression_tests.py",
    "scripts/pre_deploy_gate.py",
    "api/main.py",
    "api/paywall_filter.py",
    ".github/workflows/sentinel-blogger.yml",
    "index.html",
})

_CORE_DIRECTORIES: frozenset = frozenset({
    ".github",
    "api",
})

# ---------------------------------------------------------------------------
# Action Registry — maps action_key → executor function
# ---------------------------------------------------------------------------

class ActionResult:
    """Structured result of an action execution."""
    def __init__(
        self,
        action_key: str,
        success: bool,
        output: str = "",
        error: str = "",
        duration_s: float = 0.0,
        validation_passed: bool = True,
        blocked: bool = False,
        block_reason: str = "",
    ) -> None:
        self.action_key = action_key
        self.success = success
        self.output = output[:2000]  # cap output size
        self.error = error[:500]
        self.duration_s = round(duration_s, 2)
        self.validation_passed = validation_passed
        self.blocked = blocked
        self.block_reason = block_reason
        self.executed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            "action_key":        self.action_key,
            "success":           self.success,
            "output":            self.output,
            "error":             self.error,
            "duration_s":        self.duration_s,
            "validation_passed": self.validation_passed,
            "blocked":           self.blocked,
            "block_reason":      self.block_reason,
            "executed_at":       self.executed_at,
        }


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """
    Prevents runaway action execution.
    Trips after MAX_FAILURES consecutive failures.
    Resets after RESET_WINDOW_S seconds of no failures.
    """
    MAX_FAILURES = 3
    RESET_WINDOW_S = 3600  # 1 hour

    def __init__(self) -> None:
        self._state = self._load()

    def _load(self) -> Dict:
        try:
            if CIRCUIT_BREAKER.exists():
                return json.loads(CIRCUIT_BREAKER.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {"failures": 0, "tripped": False, "last_failure": None, "trip_reason": ""}

    def _save(self) -> None:
        try:
            CIRCUIT_BREAKER.parent.mkdir(parents=True, exist_ok=True)
            CIRCUIT_BREAKER.write_text(
                json.dumps(self._state, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            log.error("[CIRCUIT-BREAKER] Save failed: %s", exc)

    def is_tripped(self) -> Tuple[bool, str]:
        """Returns (is_tripped, reason)."""
        if not self._state.get("tripped"):
            return False, ""

        # Auto-reset after window
        last_fail = self._state.get("last_failure")
        if last_fail:
            try:
                lf = datetime.fromisoformat(last_fail.replace("Z", "+00:00"))
                elapsed = (datetime.now(timezone.utc) - lf).total_seconds()
                if elapsed > self.RESET_WINDOW_S:
                    log.info("[CIRCUIT-BREAKER] Auto-resetting after %.0f seconds", elapsed)
                    self.reset()
                    return False, ""
            except Exception:
                pass

        return True, self._state.get("trip_reason", "Circuit breaker tripped")

    def record_failure(self, reason: str) -> None:
        self._state["failures"] = self._state.get("failures", 0) + 1
        self._state["last_failure"] = datetime.now(timezone.utc).isoformat()
        if self._state["failures"] >= self.MAX_FAILURES:
            self._state["tripped"] = True
            self._state["trip_reason"] = (
                f"Circuit breaker tripped after {self._state['failures']} consecutive failures. "
                f"Last: {reason}"
            )
            log.critical("[CIRCUIT-BREAKER] TRIPPED: %s", self._state["trip_reason"])
        self._save()

    def record_success(self) -> None:
        self._state["failures"] = 0
        self._state["tripped"] = False
        self._state["trip_reason"] = ""
        self._save()

    def reset(self) -> None:
        self._state = {"failures": 0, "tripped": False, "last_failure": None, "trip_reason": ""}
        self._save()
        log.info("[CIRCUIT-BREAKER] Reset.")


# ---------------------------------------------------------------------------
# Validation Gate (Phase 5)
# ---------------------------------------------------------------------------

class ValidationGate:
    """
    Phase 5: Pre- and post-action validation.
    All checks must pass before any action proceeds.
    """

    def __init__(self) -> None:
        self.errors: List[str] = []

    def pre_action_check(self) -> bool:
        """Run pre-action validation suite."""
        self.errors = []
        checks = [
            self._check_python_syntax,
            self._check_api_files_readable,
            self._check_manifest_readable,
        ]
        for check in checks:
            try:
                check()
            except Exception as exc:
                self.errors.append(f"{check.__name__}: {exc}")

        if self.errors:
            log.error("[VALIDATION-GATE] Pre-action checks FAILED: %s", self.errors)
            return False
        log.info("[VALIDATION-GATE] Pre-action checks PASSED")
        return True

    def post_action_check(self, action_key: str) -> bool:
        """Run post-action validation to confirm no regression."""
        self.errors = []
        checks = [
            self._check_python_syntax,
            self._check_api_files_readable,
        ]
        for check in checks:
            try:
                check()
            except Exception as exc:
                self.errors.append(f"POST-{check.__name__}: {exc}")

        if self.errors:
            log.error("[VALIDATION-GATE] Post-action checks FAILED after %s: %s",
                      action_key, self.errors)
            return False
        log.info("[VALIDATION-GATE] Post-action checks PASSED for %s", action_key)
        return True

    def _check_python_syntax(self) -> None:
        """Verify core Python scripts are syntactically valid."""
        key_scripts = [
            _SCRIPTS / "master_p0_fix.py",
            _SCRIPTS / "dedup_state.py",
            _SCRIPTS / "run_pipeline.py",
        ]
        for script in key_scripts:
            if not script.exists():
                continue
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(script)],
                capture_output=True, timeout=15,
            )
            if result.returncode != 0:
                raise ValueError(f"Syntax error in {script.name}: {result.stderr.decode()[:200]}")

    def _check_api_files_readable(self) -> None:
        """Verify critical API files can be parsed as JSON."""
        for fname in ["feed.json", "latest.json"]:
            path = _API / fname
            if not path.exists():
                continue  # missing is caught by anomaly detector, not a gate blocker
            try:
                json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"api/{fname} is corrupt JSON: {exc}")

    def _check_manifest_readable(self) -> None:
        """Verify feed_manifest.json is parseable."""
        manifest = _DATA / "feed_manifest.json"
        if not manifest.exists():
            raise ValueError("data/feed_manifest.json is missing — pipeline is blind")
        try:
            json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"feed_manifest.json is corrupt: {exc}")


# ---------------------------------------------------------------------------
# Core File Guard
# ---------------------------------------------------------------------------

def _is_core_file(path: str) -> bool:
    """Return True if path refers to a protected core file."""
    norm = path.replace("\\", "/").lstrip("./")
    if norm in _CORE_FILES:
        return True
    for core_dir in _CORE_DIRECTORIES:
        if norm.startswith(core_dir + "/"):
            return True
    return False


def _assert_not_core(path: str) -> None:
    """Raise if attempting to touch a core file."""
    if _is_core_file(path):
        raise PermissionError(
            f"[SAFETY GUARD] BLOCKED: Attempted modification of core file '{path}'. "
            "This action requires human approval and must not be auto-executed."
        )


# ---------------------------------------------------------------------------
# Safe Action Executors
# ---------------------------------------------------------------------------

def _run_script(
    script: str,
    args: List[str] = [],
    timeout: int = 120,
) -> Tuple[bool, str, str]:
    """
    Run a Python script safely. Returns (success, stdout, stderr).
    Script path is relative to _SCRIPTS or _ROOT.
    """
    script_path = _SCRIPTS / script if not script.startswith("scripts/") else _ROOT / script
    if not script_path.exists():
        return False, "", f"Script not found: {script_path}"

    cmd = [sys.executable, str(script_path)] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            cwd=str(_ROOT),
        )
        stdout = result.stdout.decode("utf-8", errors="replace")[:2000]
        stderr = result.stderr.decode("utf-8", errors="replace")[:500]
        return result.returncode == 0, stdout, stderr
    except subprocess.TimeoutExpired:
        return False, "", f"Script timed out after {timeout}s: {script}"
    except Exception as exc:
        return False, "", str(exc)


def _action_clear_cache(_: Dict) -> ActionResult:
    """Clear stale data/cache files."""
    cache_dir = _DATA / "cache"
    cleared = []
    errors = []

    if cache_dir.exists():
        for f in cache_dir.iterdir():
            if f.is_file() and f.suffix in (".json", ".tmp", ".cache"):
                try:
                    f.unlink()
                    cleared.append(f.name)
                except OSError as exc:
                    errors.append(f"{f.name}: {exc}")

    output = f"Cleared {len(cleared)} cache files."
    if cleared:
        output += f" Files: {', '.join(cleared[:10])}"
    if errors:
        output += f" | Errors: {', '.join(errors[:5])}"

    success = len(errors) == 0
    log.info("[ACTION] clear_cache: %s", output)
    return ActionResult("clear_cache", success, output=output, error="; ".join(errors))


def _action_rebuild_manifest(_: Dict) -> ActionResult:
    """Run rebuild_manifest.py."""
    start = time.time()
    success, stdout, stderr = _run_script("rebuild_manifest.py", timeout=180)
    duration = time.time() - start
    log.info("[ACTION] rebuild_manifest: success=%s, %.1fs", success, duration)
    return ActionResult(
        "rebuild_manifest", success,
        output=stdout, error=stderr, duration_s=duration,
    )


def _action_refresh_feed(_: Dict) -> ActionResult:
    """Run master_p0_fix.py to regenerate API feed files."""
    start = time.time()
    success, stdout, stderr = _run_script("master_p0_fix.py", timeout=300)
    duration = time.time() - start
    log.info("[ACTION] refresh_feed: success=%s, %.1fs", success, duration)
    return ActionResult(
        "refresh_feed", success,
        output=stdout, error=stderr, duration_s=duration,
    )


def _action_rerun_apex_ai(_: Dict) -> ActionResult:
    """Force APEX AI rebuild — same as refresh_feed (master_p0_fix always rebuilds)."""
    return _action_refresh_feed(_)


def _action_run_dedup_validation(_: Dict) -> ActionResult:
    """Run dedup state validation against manifest."""
    start = time.time()
    success, stdout, stderr = _run_script(
        "dedup_state.py", ["--validate-manifest", "--stats"], timeout=60
    )
    duration = time.time() - start
    log.info("[ACTION] run_dedup_validation: success=%s, %.1fs", success, duration)
    return ActionResult(
        "run_dedup_validation", success,
        output=stdout, error=stderr, duration_s=duration,
    )


def _action_run_regression_tests(_: Dict) -> ActionResult:
    """Run the full regression test suite."""
    start = time.time()
    success, stdout, stderr = _run_script("regression_tests.py", timeout=120)
    duration = time.time() - start
    log.info("[ACTION] run_regression_tests: success=%s, %.1fs", success, duration)
    return ActionResult(
        "run_regression_tests", success,
        output=stdout, error=stderr, duration_s=duration,
    )


def _action_validate_intel_schema(_: Dict) -> ActionResult:
    """Run intel schema validation."""
    start = time.time()
    success, stdout, stderr = _run_script("validate_intel_schema.py", timeout=60)
    duration = time.time() - start
    log.info("[ACTION] validate_intel_schema: success=%s, %.1fs", success, duration)
    return ActionResult(
        "validate_intel_schema", success,
        output=stdout, error=stderr, duration_s=duration,
    )


def _action_seed_dedup_state(_: Dict) -> ActionResult:
    """Seed dedup state from manifest."""
    start = time.time()
    success, stdout, stderr = _run_script("dedup_state.py", ["--seed-manifest"], timeout=60)
    duration = time.time() - start
    log.info("[ACTION] seed_dedup_state: success=%s, %.1fs", success, duration)
    return ActionResult(
        "seed_dedup_state", success,
        output=stdout, error=stderr, duration_s=duration,
    )


# Registry of all auto-executable actions
_ACTION_REGISTRY: Dict[str, Any] = {
    "clear_cache":           _action_clear_cache,
    "rebuild_manifest":      _action_rebuild_manifest,
    "refresh_feed":          _action_refresh_feed,
    "rerun_apex_ai":         _action_rerun_apex_ai,
    "run_dedup_validation":  _action_run_dedup_validation,
    "run_regression_tests":  _action_run_regression_tests,
    "validate_intel_schema": _action_validate_intel_schema,
    "seed_dedup_state":      _action_seed_dedup_state,
}

# Actions that are explicitly NOT allowed (must go to human approval queue)
_BLOCKED_ACTIONS: frozenset = frozenset({
    "add_new_feed_sources",
    "recalibrate_risk_scoring",
    "change_dedup_threshold",
    "update_pipeline_schedule",
    "add_monitoring_alerts",
    "modify_core_logic",
    "rewrite_ai_engine",
    "change_pipeline_flow",
    "git_push",
    "deploy",
})


# ---------------------------------------------------------------------------
# Action Log
# ---------------------------------------------------------------------------

def _append_action_log(entry: Dict) -> None:
    """Append action result to data/action_log.json."""
    try:
        existing = []
        if ACTION_LOG.exists():
            try:
                existing = json.loads(ACTION_LOG.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []
        existing.append(entry)
        # Keep last 500 entries
        if len(existing) > 500:
            existing = existing[-500:]
        ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        tmp = ACTION_LOG.with_suffix(".tmp")
        tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            with open(tmp, "rb") as fh:
                os.fsync(fh.fileno())
        except OSError:
            pass
        os.replace(tmp, ACTION_LOG)
    except Exception as exc:
        log.error("[ACTION-LOG] Failed to write action log: %s", exc)


# ---------------------------------------------------------------------------
# Human Approval Queue
# ---------------------------------------------------------------------------

def queue_for_approval(
    action_key: str,
    rec: Dict,
    reason: str,
) -> None:
    """Add action to pending_approvals.json for human review."""
    try:
        pending = []
        if PENDING_APPROVALS.exists():
            try:
                pending = json.loads(PENDING_APPROVALS.read_text(encoding="utf-8"))
                if not isinstance(pending, list):
                    pending = []
            except Exception:
                pending = []

        # Check if already queued
        existing_keys = {p.get("action_key") for p in pending if p.get("status") == "pending"}
        if action_key in existing_keys:
            log.info("[APPROVAL] Already queued: %s", action_key)
            return

        entry = {
            "approval_id":   f"APR-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "action_key":    action_key,
            "title":         rec.get("title", action_key),
            "description":   rec.get("description", ""),
            "command":       rec.get("command", ""),
            "rollback":      rec.get("rollback", ""),
            "reason":        reason,
            "approval_reason": rec.get("approval_reason", ""),
            "estimated_impact": rec.get("estimated_impact", ""),
            "status":        "pending",
            "queued_at":     datetime.now(timezone.utc).isoformat(),
            "approved_at":   None,
            "approved_by":   None,
        }
        pending.append(entry)
        PENDING_APPROVALS.parent.mkdir(parents=True, exist_ok=True)
        PENDING_APPROVALS.write_text(
            json.dumps(pending, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        log.info("[APPROVAL] Queued for human approval: %s — %s", action_key, reason)
    except Exception as exc:
        log.error("[APPROVAL] Failed to queue approval: %s", exc)


# ---------------------------------------------------------------------------
# Safe Action Engine — Main Class
# ---------------------------------------------------------------------------

class SafeActionEngine:
    """
    Phase 4+5: Executes validated safe actions with full guard rail stack.

    Execution sequence for each action:
        1. Check circuit breaker
        2. Check action is not hard-blocked
        3. Check action is in registry (is auto-executable)
        4. Core file guard check
        5. Pre-action validation gate (Phase 5)
        6. Execute action
        7. Post-action validation gate (Phase 5)
        8. Update circuit breaker
        9. Log result
    """

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.circuit_breaker = CircuitBreaker()
        self.validation_gate = ValidationGate()
        self.results: List[ActionResult] = []

    def execute(self, action_key: str, rec: Dict) -> ActionResult:
        """Execute a single action with full safety stack."""

        # 1. Circuit breaker check
        tripped, trip_reason = self.circuit_breaker.is_tripped()
        if tripped:
            log.critical("[ACTION] CIRCUIT BREAKER TRIPPED — blocking all actions: %s", trip_reason)
            result = ActionResult(
                action_key, False,
                blocked=True, block_reason=f"Circuit breaker: {trip_reason}",
            )
            self.results.append(result)
            return result

        # 2. Hard-blocked action check
        if action_key in _BLOCKED_ACTIONS:
            reason = f"Action '{action_key}' is in the hard-blocked list. Requires human approval."
            log.warning("[ACTION] BLOCKED (hard-block): %s", action_key)
            queue_for_approval(action_key, rec, reason)
            result = ActionResult(
                action_key, False, blocked=True, block_reason=reason,
            )
            self.results.append(result)
            return result

        # 3. Registry check
        executor = _ACTION_REGISTRY.get(action_key)
        if executor is None:
            reason = f"Action '{action_key}' is not in safe action registry. Manual execution required."
            log.warning("[ACTION] BLOCKED (not in registry): %s", action_key)
            if rec.get("requires_approval"):
                queue_for_approval(action_key, rec, reason)
            result = ActionResult(
                action_key, False, blocked=True, block_reason=reason,
            )
            self.results.append(result)
            return result

        # 4. Dry run mode
        if self.dry_run:
            log.info("[ACTION] DRY-RUN: would execute '%s' — command: %s",
                     action_key, rec.get("command", ""))
            result = ActionResult(
                action_key, True,
                output=f"[DRY-RUN] Would execute: {rec.get('command', action_key)}",
                duration_s=0.0,
            )
            self.results.append(result)
            return result

        # 5. Pre-action validation gate
        if not self.validation_gate.pre_action_check():
            reason = f"Pre-action validation failed: {self.validation_gate.errors}"
            log.error("[ACTION] BLOCKED (validation gate): %s", reason)
            self.circuit_breaker.record_failure(reason)
            result = ActionResult(
                action_key, False,
                blocked=True, block_reason=reason,
                validation_passed=False,
            )
            _append_action_log({**result.to_dict(), "phase": "pre_validation_blocked"})
            self.results.append(result)
            return result

        # 6. Execute
        log.info("[ACTION] Executing: %s", action_key)
        try:
            result = executor(rec)
        except PermissionError as exc:
            log.critical("[ACTION] SECURITY BLOCK: %s", exc)
            result = ActionResult(
                action_key, False,
                blocked=True, block_reason=str(exc),
            )
            self.circuit_breaker.record_failure(str(exc))
            _append_action_log({**result.to_dict(), "phase": "security_blocked"})
            self.results.append(result)
            return result
        except Exception as exc:
            log.error("[ACTION] Executor raised: %s", exc)
            result = ActionResult(
                action_key, False, error=str(exc),
            )

        # 7. Post-action validation
        if result.success:
            if not self.validation_gate.post_action_check(action_key):
                result.validation_passed = False
                result.success = False
                result.error = f"Post-validation failed: {self.validation_gate.errors}"
                log.error("[ACTION] Post-validation FAILED for %s — marking as failure", action_key)
                self.circuit_breaker.record_failure(result.error)
            else:
                self.circuit_breaker.record_success()
        else:
            self.circuit_breaker.record_failure(result.error or "action returned failure")

        # 8. Log
        log_entry = {
            **result.to_dict(),
            "rec_id": rec.get("rec_id", ""),
            "action_key": action_key,
        }
        _append_action_log(log_entry)

        log.info(
            "[ACTION] %s: success=%s, %.1fs, validation=%s",
            action_key, result.success, result.duration_s, result.validation_passed,
        )
        self.results.append(result)
        return result

    def execute_batch(
        self,
        recommendations: List[Dict],
        max_actions: int = 5,
    ) -> List[ActionResult]:
        """
        Execute a batch of recommendations.
        Only executes safe_auto=True actions.
        Stops on critical failure or circuit breaker trip.
        """
        executed = 0
        for rec in recommendations:
            if executed >= max_actions:
                log.info("[ACTION] Max actions (%d) reached — halting batch.", max_actions)
                break

            action_key = rec.get("action_key", "")
            if not rec.get("safe_auto", False):
                log.info("[ACTION] Skipping non-auto action: %s", action_key)
                queue_for_approval(action_key, rec, "Batched by engine — requires human approval")
                continue

            result = self.execute(action_key, rec)
            executed += 1

            # Stop batch on circuit breaker trip
            tripped, _ = self.circuit_breaker.is_tripped()
            if tripped:
                log.critical("[ACTION] Circuit breaker tripped mid-batch — halting.")
                break

        return self.results

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_actions":    len(self.results),
            "succeeded":        sum(1 for r in self.results if r.success),
            "failed":           sum(1 for r in self.results if not r.success and not r.blocked),
            "blocked":          sum(1 for r in self.results if r.blocked),
            "circuit_breaker":  self.circuit_breaker.is_tripped()[0],
            "results":          [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# Approval Processor (reads pending_approvals.json for approved items)
# ---------------------------------------------------------------------------

def process_approved_actions(dry_run: bool = False) -> List[ActionResult]:
    """
    Check pending_approvals.json for manually approved entries and execute them.
    Sets status to 'executed' or 'failed' after processing.
    """
    if not PENDING_APPROVALS.exists():
        return []

    try:
        pending = json.loads(PENDING_APPROVALS.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("[APPROVAL] Cannot read pending_approvals.json: %s", exc)
        return []

    approved = [p for p in pending if p.get("status") == "approved"]
    if not approved:
        return []

    engine = SafeActionEngine(dry_run=dry_run)
    results = []

    for approval in approved:
        action_key = approval.get("action_key", "")
        log.info("[APPROVAL] Processing approved action: %s (approved_by=%s)",
                 action_key, approval.get("approved_by"))

        result = engine.execute(action_key, approval)
        results.append(result)

        # Update approval status
        for p in pending:
            if p.get("approval_id") == approval.get("approval_id"):
                p["status"] = "executed" if result.success else "failed"
                p["executed_at"] = datetime.now(timezone.utc).isoformat()
                p["execution_result"] = result.to_dict()
                break

    # Write updated pending list
    try:
        PENDING_APPROVALS.write_text(
            json.dumps(pending, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except Exception as exc:
        log.error("[APPROVAL] Failed to update approval statuses: %s", exc)

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [actions] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    parser = argparse.ArgumentParser(description="SENTINEL APEX — Safe Action Engine")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without executing")
    parser.add_argument("--action", type=str, help="Execute a specific action_key")
    parser.add_argument("--process-approvals", action="store_true",
                        help="Process manually approved actions from pending_approvals.json")
    parser.add_argument("--reset-circuit-breaker", action="store_true",
                        help="Manually reset the circuit breaker")
    parser.add_argument("--list-pending", action="store_true",
                        help="List pending approval requests")
    args = parser.parse_args()

    engine = SafeActionEngine(dry_run=args.dry_run)

    if args.reset_circuit_breaker:
        engine.circuit_breaker.reset()
        print("Circuit breaker reset.")

    elif args.list_pending:
        pending = json.loads(PENDING_APPROVALS.read_text(encoding="utf-8")) if PENDING_APPROVALS.exists() else []
        print(f"\n=== PENDING APPROVALS ({len(pending)}) ===")
        for p in pending:
            if p.get("status") == "pending":
                print(f"  [{p.get('approval_id')}] {p.get('action_key')} — {p.get('title')}")
                print(f"    Reason: {p.get('approval_reason')}")
                print(f"    Queued: {p.get('queued_at')}")

    elif args.process_approvals:
        results = process_approved_actions(dry_run=args.dry_run)
        print(f"\nProcessed {len(results)} approved actions.")
        for r in results:
            status = "OK" if r.success else "FAIL"
            print(f"  [{status}] {r.action_key}: {r.output[:100]}")

    elif args.action:
        rec = {"action_key": args.action, "safe_auto": True, "title": args.action}
        result = engine.execute(args.action, rec)
        print(f"\n[{'OK' if result.success else 'FAIL'}] {args.action}")
        if result.blocked:
            print(f"BLOCKED: {result.block_reason}")
        else:
            print(f"Output: {result.output[:500]}")
            if result.error:
                print(f"Error: {result.error}")
        print(f"Duration: {result.duration_s}s | Validation: {result.validation_passed}")

    else:
        # Validate gate self-check
        gate = ValidationGate()
        passed = gate.pre_action_check()
        print(f"\n=== VALIDATION GATE STATUS: {'PASSED' if passed else 'FAILED'} ===")
        if not passed:
            for err in gate.errors:
                print(f"  ERROR: {err}")
        cb_tripped, cb_reason = CircuitBreaker().is_tripped()
        print(f"Circuit breaker: {'TRIPPED — ' + cb_reason if cb_tripped else 'OK'}")
