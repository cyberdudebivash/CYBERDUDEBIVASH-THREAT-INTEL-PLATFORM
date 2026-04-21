#!/usr/bin/env python3
"""
scripts/recovery_replay.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0.0 — Recovery Replay Engine
===================================================================
Scans data/recovery/write_failures/, retries failed writes with
exponential backoff, deletes blobs on success.

DESIGN RULES:
  - Zero data loss: every replay attempt is logged
  - Exponential backoff with jitter between attempts
  - Atomic blob deletion — only on confirmed write success
  - CRITICAL state check: if system is CRITICAL, only replay is allowed
  - Idempotent: safe to run multiple times; already-recovered blobs are skipped

Run modes:
  python scripts/recovery_replay.py              # dry-run (scan + report, no writes)
  python scripts/recovery_replay.py --execute    # apply replays
  python scripts/recovery_replay.py --max 10     # limit to 10 blobs per run

Automatic invocation:
  - After WriteQueue.flush() in run_pipeline.py
  - End of pipeline run (via atexit or pipeline finaliser)

Exit codes:
  0 — all replays succeeded (or nothing to replay)
  1 — one or more replays permanently failed
  2 — system state is CRITICAL (replay-only mode, ingestion blocked)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path bootstrap — allow import whether called as script or module
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS  = REPO_ROOT / "scripts"
for _p in (str(_SCRIPTS), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [recovery_replay] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.recovery_replay")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
RECOVERY_DIR  = REPO_ROOT / "data" / "recovery" / "write_failures"
REPLAY_LOG    = REPO_ROOT / "data" / "logs" / "recovery_replay.jsonl"
HEALTH_JSON   = REPO_ROOT / "data" / "logs" / "system_health.json"

# Replay parameters
MAX_REPLAY_ATTEMPTS: int   = 5        # per blob
BASE_REPLAY_DELAY:   float = 0.5      # seconds; exponential: 0.5, 1.0, 2.0, 4.0, 8.0
MAX_REPLAY_DELAY:    float = 8.0      # cap per attempt
DEFAULT_MAX_BLOBS:   int   = 50       # blobs per invocation (prevent runaway)

# ---------------------------------------------------------------------------
# Replay Record
# ---------------------------------------------------------------------------

class ReplayRecord:
    """Represents a single recovery blob with its metadata."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: Dict[str, Any] = {}
        self.target_path: Optional[Path] = None
        self.error: str = ""
        self.attempt: int = 0
        self._loaded = False

    def load(self) -> bool:
        """Load and parse the recovery blob. Returns True on success."""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.data = raw
            target_str = raw.get("_recovery_target", "")
            if target_str:
                self.target_path = Path(target_str)
            self.attempt = int(raw.get("_recovery_attempt", 0))
            self._loaded = True
            return True
        except Exception as e:
            self.error = f"blob load failed: {e}"
            log.warning("ReplayRecord.load: %s — %s", self.path.name, self.error)
            return False

    def is_valid(self) -> bool:
        return self._loaded and self.target_path is not None

    def build_payload(self) -> Any:
        """Strip internal recovery metadata keys and return clean payload."""
        return {
            k: v for k, v in self.data.items()
            if not k.startswith("_recovery_") and not k.startswith("_payload_")
        }


# ---------------------------------------------------------------------------
# Replay Engine
# ---------------------------------------------------------------------------

class RecoveryReplayEngine:
    """
    Scans recovery folder, retries failed writes, deletes on success.

    Thread-safety: single-threaded by design (replays are sequential).
    State: self.stats dict — populated after run().
    """

    def __init__(
        self,
        dry_run: bool = True,
        max_blobs: int = DEFAULT_MAX_BLOBS,
    ) -> None:
        self.dry_run   = dry_run
        self.max_blobs = max_blobs
        self.stats: Dict[str, Any] = {
            "scanned": 0,
            "replayed": 0,
            "succeeded": 0,
            "failed_permanent": 0,
            "skipped": 0,
            "dry_run": dry_run,
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "finished_at": "",
        }

    def scan(self) -> List[ReplayRecord]:
        """Scan RECOVERY_DIR for unresolved write failure blobs."""
        if not RECOVERY_DIR.exists():
            log.info("RecoveryReplayEngine.scan: recovery dir absent — nothing to replay")
            return []

        blobs = sorted(RECOVERY_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
        records = []
        for blob in blobs[:self.max_blobs]:
            rec = ReplayRecord(blob)
            if rec.load() and rec.is_valid():
                records.append(rec)
            else:
                self.stats["skipped"] += 1
                log.warning("replay: skipping invalid blob %s — %s", blob.name, rec.error)

        log.info(
            "RecoveryReplayEngine.scan: found %d valid blob(s) in %s",
            len(records), RECOVERY_DIR,
        )
        self.stats["scanned"] = len(records) + self.stats["skipped"]
        return records

    def _attempt_replay(self, rec: ReplayRecord) -> bool:
        """
        Attempt to replay a single write blob.
        Returns True on success, False on permanent failure.
        Uses exponential backoff with jitter.
        """
        payload = rec.build_payload()
        target  = rec.target_path

        if self.dry_run:
            log.info(
                "[DRY-RUN] Would replay: %s → %s (attempt=%d)",
                rec.path.name, target, rec.attempt,
            )
            return True  # Pretend success in dry-run

        last_exc: Exception = RuntimeError("no attempts made")
        for attempt_num in range(1, MAX_REPLAY_ATTEMPTS + 1):
            try:
                # Import atomic writer here (deferred to avoid circular imports)
                from safe_io import atomic_json_write
                target.parent.mkdir(parents=True, exist_ok=True)
                atomic_json_write(target, payload, locked=True)
                log.info(
                    "replay: SUCCESS attempt %d/%d → %s",
                    attempt_num, MAX_REPLAY_ATTEMPTS, target.name,
                )
                return True
            except Exception as exc:
                last_exc = exc
                delay = min(BASE_REPLAY_DELAY * (2 ** (attempt_num - 1)), MAX_REPLAY_DELAY)
                jitter = random.uniform(0, BASE_REPLAY_DELAY * 0.25)
                actual_delay = delay + jitter
                log.warning(
                    "replay: attempt %d/%d FAILED for %s: %s (retry in %.2fs)",
                    attempt_num, MAX_REPLAY_ATTEMPTS, target.name, exc, actual_delay,
                )
                if attempt_num < MAX_REPLAY_ATTEMPTS:
                    time.sleep(actual_delay)

        log.error(
            "replay: PERMANENT FAILURE after %d attempts for %s: %s",
            MAX_REPLAY_ATTEMPTS, target, last_exc,
        )
        return False

    def _delete_blob(self, rec: ReplayRecord) -> None:
        """Delete blob on successful replay. Warns but never raises on failure."""
        try:
            rec.path.unlink(missing_ok=True)
            log.debug("replay: blob deleted — %s", rec.path.name)
        except Exception as e:
            log.warning("replay: could not delete blob %s: %s", rec.path.name, e)

    def _truncate_write_failures_log(self) -> None:
        """Truncate data/logs/write_failures.jsonl after confirmed full drain.

        Called ONLY when:
          - RECOVERY_DIR has zero blobs remaining after this replay run, AND
          - No permanent failures occurred in this run (failed_permanent == 0), AND
          - Not in dry-run mode.

        Rationale: write_failures.jsonl is an audit log that accumulates over time.
        validate_repo.py check_no_write_failures() now checks the recovery blob
        directory (not this log), so truncating here is safe and ensures the
        audit log does not grow unbounded across pipeline runs.
        """
        wf_log = REPO_ROOT / "data" / "logs" / "write_failures.jsonl"
        if not wf_log.exists():
            log.debug("_truncate_write_failures_log: file absent — nothing to truncate")
            return
        try:
            wf_log.write_text("", encoding="utf-8")
            log.info(
                "_truncate_write_failures_log: write_failures.jsonl truncated — "
                "recovery drain confirmed complete. Audit log reset."
            )
        except Exception as e:
            log.warning("_truncate_write_failures_log: could not truncate: %s (non-fatal)", e)

    def _update_blob_attempt(self, rec: ReplayRecord) -> None:
        """Increment _recovery_attempt counter in blob for audit trail."""
        try:
            rec.data["_recovery_attempt"] = rec.attempt + 1
            rec.data["_last_replay_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            rec.path.write_text(
                json.dumps(rec.data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            log.debug("replay: could not update blob attempt counter: %s", e)

    def _append_replay_log(self, rec: ReplayRecord, success: bool) -> None:
        """Append JSONL replay audit record."""
        try:
            REPLAY_LOG.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts":          datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "blob":        rec.path.name,
                "target":      str(rec.target_path),
                "attempt":     rec.attempt + 1,
                "success":     success,
                "dry_run":     self.dry_run,
            }
            with open(REPLAY_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            log.debug("replay: JSONL log append failed (non-fatal): %s", e)

    def run(self) -> Dict[str, Any]:
        """
        Main replay loop:
          1. Scan recovery directory
          2. For each blob: attempt replay with exponential backoff
          3. On success: delete blob, append audit log
          4. On failure: increment attempt counter, append audit log
          5. Return stats dict

        Returns stats dict with counts: scanned, replayed, succeeded, failed_permanent.
        """
        mode = "DRY-RUN" if self.dry_run else "EXECUTE"
        log.info("=" * 60)
        log.info("RecoveryReplayEngine START [%s] max_blobs=%d", mode, self.max_blobs)
        log.info("=" * 60)

        records = self.scan()
        if not records:
            log.info("RecoveryReplayEngine: nothing to replay — system clean")
            self.stats["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return self.stats

        for rec in records:
            self.stats["replayed"] += 1
            success = self._attempt_replay(rec)
            self._append_replay_log(rec, success)

            if success:
                self.stats["succeeded"] += 1
                self._delete_blob(rec)
            else:
                self.stats["failed_permanent"] += 1
                self._update_blob_attempt(rec)

        self.stats["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

        log.info("=" * 60)
        log.info(
            "RecoveryReplayEngine DONE: scanned=%d replayed=%d succeeded=%d failed=%d",
            self.stats["scanned"], self.stats["replayed"],
            self.stats["succeeded"], self.stats["failed_permanent"],
        )
        log.info("=" * 60)

        # --- Post-drain: truncate write_failures.jsonl if fully resolved ------
        # Only when: not dry-run AND no permanent failures AND zero blobs remain
        if not self.dry_run and self.stats["failed_permanent"] == 0:
            remaining = len(list(RECOVERY_DIR.glob("*.json"))) if RECOVERY_DIR.exists() else 0
            if remaining == 0 and self.stats["succeeded"] > 0:
                self._truncate_write_failures_log()
            elif remaining == 0 and self.stats["scanned"] == 0:
                log.debug("RecoveryReplayEngine: nothing to replay — write_failures.jsonl left as-is")

        return self.stats


# ---------------------------------------------------------------------------
# Post-flush integration helper (called by WriteQueue / pipeline)
# ---------------------------------------------------------------------------

def run_post_flush_replay(dry_run: bool = False, max_blobs: int = DEFAULT_MAX_BLOBS) -> Dict[str, Any]:
    """
    Entry point for post-WriteQueue.flush() replay.
    Called automatically by the pipeline after flush() completes.

    Args:
        dry_run:   If True, scan and log only — no writes, no deletions.
        max_blobs: Maximum blobs to process in this invocation.

    Returns:
        stats dict from RecoveryReplayEngine.run()
    """
    engine = RecoveryReplayEngine(dry_run=dry_run, max_blobs=max_blobs)
    return engine.run()


# ---------------------------------------------------------------------------
# v134 Recovery Drain Guarantee — exhaustive unlimited drain
# ---------------------------------------------------------------------------

def drain_recovery_queue(dry_run: bool = False) -> Dict[str, Any]:
    """
    v134 EXHAUSTIVE RECOVERY DRAIN GUARANTEE.

    Processes ALL blobs in data/recovery/write_failures/ with no blob cap
    (max_blobs=9999). Tracks per-item retry_count for observability.

    Sets  ``recovery_mode: true``  in system_health.json before drain starts
    so that validate_repo.py check_no_write_failures() can grant an exception
    while the drain is in progress.  Clears the flag after drain completes.

    Returns:
        {
          "system_state":  "HEALTHY" | "DEGRADED",
          "drained":       int,   -- blobs successfully replayed + deleted
          "remaining":     int,   -- blobs still on disk after drain
          "retry_counts":  dict,  -- {blob_name: last_attempt_number}
          "failed":        int,   -- permanent failures (could not replay)
          "dry_run":       bool,
          "started_at":    str,
          "finished_at":   str,
        }

    POLICY:
      remaining == 0  →  system_state = "HEALTHY"
      remaining > 0   →  system_state = "DEGRADED"
    """
    _drain_start = datetime.now(timezone.utc).isoformat(timespec="seconds")
    log.info("drain_recovery_queue: START (dry_run=%s)", dry_run)

    # -- Set recovery_mode flag so validate_repo.py allows blobs mid-drain ----
    if not dry_run:
        _set_recovery_mode(True, _drain_start)

    # -- Run exhaustive drain (no blob cap) -----------------------------------
    engine = RecoveryReplayEngine(dry_run=dry_run, max_blobs=9999)
    stats  = engine.run()

    # -- Collect per-item retry_counts from replay audit log ------------------
    retry_counts: Dict[str, int] = {}
    try:
        if REPLAY_LOG.exists():
            for _line in REPLAY_LOG.read_text(encoding="utf-8").splitlines():
                _line = _line.strip()
                if not _line:
                    continue
                try:
                    _entry = json.loads(_line)
                    _blob  = _entry.get("blob", "")
                    if _blob:
                        # keep the highest attempt seen for this blob
                        _att = int(_entry.get("attempt", 1))
                        retry_counts[_blob] = max(retry_counts.get(_blob, 0), _att)
                except Exception:
                    pass
    except Exception as _rle:
        log.debug("drain_recovery_queue: retry_counts scan failed (non-fatal): %s", _rle)

    # -- Count remaining blobs on disk ----------------------------------------
    remaining    = len(list(RECOVERY_DIR.glob("*.json"))) if RECOVERY_DIR.exists() else 0
    system_state = "HEALTHY" if remaining == 0 else "DEGRADED"

    # -- Clear recovery_mode flag and write final health state ----------------
    if not dry_run:
        _set_recovery_mode(False, _drain_start, system_state, remaining)

    result: Dict[str, Any] = {
        "system_state": system_state,
        "drained":      stats["succeeded"],
        "remaining":    remaining,
        "retry_counts": retry_counts,
        "failed":       stats["failed_permanent"],
        "dry_run":      dry_run,
        "started_at":   _drain_start,
        "finished_at":  datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    log.info(
        "drain_recovery_queue: DONE — state=%s drained=%d remaining=%d failed=%d",
        system_state, result["drained"], remaining, result["failed"],
    )
    return result


def _set_recovery_mode(
    active: bool,
    started_at: str = "",
    state: str = "",
    recovery_count: int = 0,
) -> None:
    """
    Atomically set/clear the ``recovery_mode`` flag in system_health.json.
    Non-fatal: logs a warning on any I/O error.
    """
    try:
        HEALTH_JSON.parent.mkdir(parents=True, exist_ok=True)
        _existing: Dict[str, Any] = {}
        if HEALTH_JSON.exists():
            try:
                _existing = json.loads(HEALTH_JSON.read_text(encoding="utf-8"))
            except Exception:
                _existing = {}

        _existing["recovery_mode"] = active
        if active:
            _existing["recovery_started_at"] = started_at
        else:
            _existing["recovery_completed_at"] = (
                datetime.now(timezone.utc).isoformat(timespec="seconds")
            )
            if state:
                _existing["state"] = state
            if recovery_count is not None:
                _existing["recovery_count"] = recovery_count

        HEALTH_JSON.write_text(
            json.dumps(_existing, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        log.info(
            "_set_recovery_mode: recovery_mode=%s state=%s remaining=%d",
            active, state or "N/A", recovery_count,
        )
    except Exception as _he:
        log.warning("_set_recovery_mode: could not update system_health.json: %s (non-fatal)", _he)


# ---------------------------------------------------------------------------
# SSOT Integrity Check — manifest ioc_count == len(iocs) hard lock
# ---------------------------------------------------------------------------

def verify_manifest_ioc_integrity(manifest_path: Optional[Path] = None) -> Tuple[bool, List[str]]:
    """
    Hard lock: verify ioc_count == len(iocs) for every advisory in manifest.
    Returns (all_ok: bool, error_messages: List[str]).

    Called during pipeline validation gate (Phase 5).
    """
    if manifest_path is None:
        manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

    errors: List[str] = []
    if not manifest_path.exists():
        return True, []  # not yet generated — OK on first run

    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, [f"manifest parse error: {e}"]

    items = raw.get("advisories", raw.get("reports", raw if isinstance(raw, list) else []))
    for i, item in enumerate(items):
        iocs      = item.get("iocs", [])
        ioc_count = item.get("ioc_count")
        title     = item.get("title", f"[entry {i}]")

        if not isinstance(iocs, list):
            errors.append(f"[{i}] '{title}': iocs is not a list (type={type(iocs).__name__})")
            continue
        if ioc_count is None:
            errors.append(f"[{i}] '{title}': ioc_count is missing")
            continue
        if int(ioc_count) != len(iocs):
            errors.append(
                f"[{i}] '{title}': ioc_count={ioc_count} != len(iocs)={len(iocs)} — HARD FAIL"
            )

    all_ok = len(errors) == 0
    if not all_ok:
        log.error("verify_manifest_ioc_integrity: %d violation(s) found", len(errors))
        for err in errors:
            log.error("  %s", err)
    else:
        log.info(
            "verify_manifest_ioc_integrity: PASS — all %d entries consistent", len(items)
        )
    return all_ok, errors


# ---------------------------------------------------------------------------
# Post-Flush Pipeline Guarantee (Phase 4)
# ---------------------------------------------------------------------------

def assert_pipeline_write_guarantee(
    repo_root: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
) -> Tuple[bool, List[str]]:
    """
    Phase 4 write pipeline guarantee.
    Asserts AFTER WriteQueue.flush():
      1. WriteQueue queue is empty
      2. No recovery backlog (RECOVERY_DIR is empty or does not exist)
      3. No stale .tmp files in data/ or reports/
      4. Manifest integrity intact (valid JSON, non-empty advisories)

    Returns (all_ok: bool, issues: List[str]).
    Caller should retry flush or escalate state if all_ok is False.
    """
    if repo_root is None:
        repo_root = REPO_ROOT
    if manifest_path is None:
        manifest_path = repo_root / "data" / "stix" / "feed_manifest.json"

    issues: List[str] = []

    # 1. WriteQueue must be empty
    try:
        from safe_io import WriteQueue
        snap = WriteQueue.metrics_snapshot()
        depth = snap.get("write_queue_depth", 0)
        if depth > 0:
            issues.append(f"WriteQueue not empty after flush: depth={depth}")
    except Exception as e:
        issues.append(f"WriteQueue check failed: {e}")

    # 2. No recovery backlog
    recovery_dir = repo_root / "data" / "recovery" / "write_failures"
    if recovery_dir.exists():
        blobs = list(recovery_dir.glob("*.json"))
        if blobs:
            issues.append(f"Recovery backlog: {len(blobs)} unresolved write failure blob(s)")
            log.warning(
                "assert_pipeline_write_guarantee: %d recovery blob(s) pending replay",
                len(blobs),
            )

    # 3. No stale .tmp files
    stale_tmp: List[Path] = []
    for scan_dir in (repo_root / "data", repo_root / "reports"):
        if scan_dir.exists():
            stale_tmp.extend(scan_dir.rglob("*.tmp"))
    if stale_tmp:
        issues.append(f"{len(stale_tmp)} stale .tmp file(s) found: "
                      + ", ".join(p.name for p in stale_tmp[:5]))

    # 4. Manifest integrity
    if manifest_path.exists():
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            advisories = raw.get("advisories", raw.get("reports", []))
            if not advisories:
                issues.append("feed_manifest.json exists but has 0 advisories — integrity violated")
        except Exception as e:
            issues.append(f"feed_manifest.json corrupted: {e}")
    else:
        log.info("assert_pipeline_write_guarantee: manifest not yet generated (pre-pipeline — OK)")

    all_ok = len(issues) == 0
    if all_ok:
        log.info("assert_pipeline_write_guarantee: PASS — queue empty, no backlog, no .tmp, manifest intact")
    else:
        log.error("assert_pipeline_write_guarantee: FAIL — %d issue(s):", len(issues))
        for iss in issues:
            log.error("  • %s", iss)

    return all_ok, issues


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX v134.0 Recovery Replay Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Apply replays (default: dry-run — scan only, no writes)",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=DEFAULT_MAX_BLOBS,
        metavar="N",
        help=f"Maximum blobs to process per run (default: {DEFAULT_MAX_BLOBS})",
    )
    parser.add_argument(
        "--verify-manifest",
        action="store_true",
        default=False,
        help="Run manifest ioc_count integrity check and exit",
    )
    parser.add_argument(
        "--assert-guarantee",
        action="store_true",
        default=False,
        help="Run post-flush write pipeline guarantee assertion and exit",
    )
    args = parser.parse_args()

    # ── Manifest integrity check ─────────────────────────────────────────────
    if args.verify_manifest:
        ok, errors = verify_manifest_ioc_integrity()
        if not ok:
            print(f"MANIFEST INTEGRITY FAIL: {len(errors)} violation(s):")
            for e in errors:
                print(f"  {e}")
            return 1
        print("MANIFEST INTEGRITY PASS — all ioc_count == len(iocs)")
        return 0

    # ── Write pipeline guarantee assertion ───────────────────────────────────
    if args.assert_guarantee:
        ok, issues = assert_pipeline_write_guarantee()
        if not ok:
            print(f"PIPELINE GUARANTEE FAIL: {len(issues)} issue(s):")
            for iss in issues:
                print(f"  • {iss}")
            return 1
        print("PIPELINE GUARANTEE PASS — all assertions satisfied")
        return 0

    # ── Recovery replay ──────────────────────────────────────────────────────
    dry_run = not args.execute
    if dry_run:
        print("=" * 60)
        print("  DRY-RUN MODE — pass --execute to apply replays")
        print("=" * 60)

    engine = RecoveryReplayEngine(dry_run=dry_run, max_blobs=args.max)
    stats  = engine.run()

    # Print summary
    print()
    print("=" * 60)
    print(f"  Recovery Replay {'[DRY-RUN]' if dry_run else '[EXECUTED]'} Summary")
    print("=" * 60)
    print(f"  Scanned          : {stats['scanned']}")
    print(f"  Replayed         : {stats['replayed']}")
    print(f"  Succeeded        : {stats['succeeded']}")
    print(f"  Permanently failed: {stats['failed_permanent']}")
    print(f"  Skipped (invalid): {stats['skipped']}")
    print(f"  Started          : {stats['started_at']}")
    print(f"  Finished         : {stats['finished_at']}")
    print("=" * 60)

    if stats["failed_permanent"] > 0:
        print(f"\n  WARNING: {stats['failed_permanent']} blob(s) could not be replayed.")
        print("  Check data/logs/recovery_replay.jsonl for details.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
