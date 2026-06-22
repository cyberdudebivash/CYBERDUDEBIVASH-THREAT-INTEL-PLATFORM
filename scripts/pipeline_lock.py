#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/pipeline_lock.py
CYBERDUDEBIVASH® SENTINEL APEX v184.0 — Runtime Pipeline Lock
================================================================
Implements Phase 6 runtime locking: .lock/pipeline.lock

Guarantees:
  • Only ONE pipeline run writes at any time (per-machine safety net)
  • If lock is held → exit safely (GitHub Actions concurrency handles queuing)
  • Lock contains: PID, timestamp, run_id — for debug inspection
  • Auto-expires after LOCK_TTL_SECONDS (prevents stale lock deadlocks)

Usage (in run_pipeline.py):
    from scripts.pipeline_lock import PipelineLock
    with PipelineLock() as lock:
        ... run pipeline ...
    # lock released on exit (even on exception)

Standalone:
    python3 scripts/pipeline_lock.py status   # show lock status
    python3 scripts/pipeline_lock.py release  # force-release stale lock
    python3 scripts/pipeline_lock.py acquire  # test acquire (exits on success)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.pipeline_lock")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [pipeline-lock] %(levelname)s: %(message)s",
    stream=sys.stderr,
)

REPO_ROOT       = Path(__file__).resolve().parent.parent
LOCK_DIR        = REPO_ROOT / ".lock"
LOCK_FILE       = LOCK_DIR / "pipeline.lock"
LOCK_TTL_SEC    = 3600      # 1 hour — stale lock auto-expires
WAIT_RETRIES    = 0         # 0 = fail immediately if locked (GitHub Actions queues)
WAIT_SLEEP_SEC  = 5


class PipelineLockError(Exception):
    """Raised when lock cannot be acquired."""


class PipelineLock:
    """
    Context manager for the SENTINEL APEX pipeline runtime lock.

    with PipelineLock() as lock:
        # Only one process enters here at a time
        ...
    """

    def __init__(
        self,
        lock_file: Path = LOCK_FILE,
        ttl: int = LOCK_TTL_SEC,
        retries: int = WAIT_RETRIES,
        sleep: float = WAIT_SLEEP_SEC,
    ):
        self.lock_file = lock_file
        self.ttl       = ttl
        self.retries   = retries
        self.sleep     = sleep
        self._acquired = False

    # ── acquire ─────────────────────────────────────────────────────────────
    def acquire(self) -> "PipelineLock":
        LOCK_DIR.mkdir(parents=True, exist_ok=True)
        for attempt in range(self.retries + 1):
            # Expire stale lock
            self._expire_stale()
            if not self.lock_file.exists():
                self._write_lock()
                self._acquired = True
                log.info("[lock] Acquired pipeline.lock (PID=%d)", os.getpid())
                return self
            if attempt < self.retries:
                log.warning("[lock] Lock held — retrying in %ds (attempt %d/%d)",
                            self.sleep, attempt + 1, self.retries)
                time.sleep(self.sleep)

        # Read who holds it
        info = self._read_lock()
        raise PipelineLockError(
            f"Pipeline lock held by PID={info.get('pid')} since "
            f"{info.get('acquired_at')} (run={info.get('run_id')}). "
            f"If stale, run: python3 scripts/pipeline_lock.py release"
        )

    def release(self) -> None:
        if self.lock_file.exists():
            self.lock_file.unlink(missing_ok=True)
            log.info("[lock] Released pipeline.lock")
        self._acquired = False

    def __enter__(self) -> "PipelineLock":
        return self.acquire()

    def __exit__(self, *_) -> None:
        self.release()

    # ── internals ───────────────────────────────────────────────────────────
    def _write_lock(self) -> None:
        payload = {
            "pid":         os.getpid(),
            "acquired_at": datetime.now(timezone.utc).isoformat(),
            "run_id":      os.environ.get("GITHUB_RUN_ID", "local"),
            "run_number":  os.environ.get("GITHUB_RUN_NUMBER", "0"),
            "ttl_seconds": self.ttl,
            "expires_at":  datetime.fromtimestamp(
                               time.time() + self.ttl, tz=timezone.utc
                           ).isoformat(),
        }
        tmp = self.lock_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.lock_file)

    def _read_lock(self) -> dict:
        try:
            return json.loads(self.lock_file.read_bytes().decode("utf-8"))
        except Exception:
            return {}

    def _expire_stale(self) -> None:
        """Remove lock if its TTL has elapsed."""
        if not self.lock_file.exists():
            return
        info = self._read_lock()
        try:
            expires = datetime.fromisoformat(info.get("expires_at", ""))
            if datetime.now(timezone.utc) >= expires:
                log.warning("[lock] Stale lock expired (run=%s) — auto-releasing",
                            info.get("run_id"))
                self.lock_file.unlink(missing_ok=True)
        except Exception:
            # If we can't parse, remove it
            log.warning("[lock] Corrupt lock file — removing")
            self.lock_file.unlink(missing_ok=True)

    # ── status ──────────────────────────────────────────────────────────────
    @staticmethod
    def status() -> dict:
        if not LOCK_FILE.exists():
            return {"locked": False}
        try:
            info = json.loads(LOCK_FILE.read_bytes().decode("utf-8"))
            expires = datetime.fromisoformat(info.get("expires_at", ""))
            info["expired"] = datetime.now(timezone.utc) >= expires
            info["locked"]  = not info["expired"]
            return info
        except Exception as e:
            return {"locked": True, "error": str(e)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Pipeline Lock v184.0")
    parser.add_argument("cmd", choices=["status", "release", "acquire"],
                        help="status|release|acquire")
    args = parser.parse_args()

    if args.cmd == "status":
        info = PipelineLock.status()
        print(json.dumps(info, indent=2))
        sys.exit(0 if not info.get("locked") else 1)

    elif args.cmd == "release":
        lock = PipelineLock()
        lock.release()
        print("Lock released.")

    elif args.cmd == "acquire":
        try:
            PipelineLock().acquire()
            print(f"Lock acquired (PID={os.getpid()}).")
        except PipelineLockError as e:
            print(f"LOCKED: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    _cli()
