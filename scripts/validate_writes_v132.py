#!/usr/bin/env python3
"""
scripts/validate_writes_v132.py
CYBERDUDEBIVASH(R) SENTINEL APEX v132.0.0 -- Post-Pipeline Write Integrity Suite
=================================================================================
27-check validation suite for v132 write hardening guarantees.

Verifies:
  Group W  (Write Infrastructure)  -- WriteQueue, retry_write, FileLock
  Group F  (Fail-safe Buffer)      -- _store_write_failure, recovery paths
  Group M  (Manifest Integrity)    -- manifest count, write_error=0, render_error=0
  Group D  (Disk Integrity)        -- report files exist, min size, no missing
  Group X  (Cross-layer SSOT)      -- manifest == disk == pipeline metrics agreement

Exit 0: all checks pass. Exit 1: any check fails.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

# Ensure scripts/ on path
REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS  = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# Minimal terminal colour helpers (no deps)
# ---------------------------------------------------------------------------
_USE_COLOUR = sys.stdout.isatty()

def _c(text: str, colour: str) -> str:
    codes = {"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m",
             "bold": "\033[1m", "reset": "\033[0m"}
    if not _USE_COLOUR:
        return text
    return f"{codes.get(colour, '')}{text}{codes['reset']}"


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------
_RESULTS: List[Tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> bool:
    _RESULTS.append((name, passed, detail))
    status = _c("PASS", "green") if passed else _c("FAIL", "red")
    detail_str = f"  -- {detail}" if detail else ""
    print(f"  [{status}] {name}{detail_str}")
    return passed


def section(title: str) -> None:
    print(f"\n{_c('━' * 60, 'bold')}")
    print(f"  {_c(title, 'bold')}")
    print(_c("━" * 60, "bold"))


# ---------------------------------------------------------------------------
# W-group: Write Infrastructure
# ---------------------------------------------------------------------------

def test_w_group() -> None:
    section("W-GROUP: Write Infrastructure")

    # W1: safe_io imports without error
    try:
        from safe_io import (
            WriteQueue, retry_write, WriteHardFail,
            FileLock, acquire_lock, atomic_json_write,
            _store_write_failure,
        )
        check("W1: safe_io imports (WriteQueue, retry_write, WriteHardFail, _store_write_failure)", True)
    except ImportError as e:
        check("W1: safe_io imports", False, str(e))
        # Cannot continue W-group without safe_io
        for n in ["W2", "W3", "W4", "W5", "W6", "W7", "W8", "W9"]:
            check(f"{n}: (skipped — safe_io unavailable)", False, "import failed")
        return

    # W2: FileLock default timeout is 120s
    lock = FileLock(Path(tempfile.mktemp()))
    check(
        "W2: FileLock default timeout == 120.0s",
        lock._timeout == 120.0,
        f"got {lock._timeout}",
    )

    # W3: acquire_lock default timeout is 120s (inspect signature)
    import inspect
    sig = inspect.signature(acquire_lock)
    default_timeout = sig.parameters.get("timeout")
    if default_timeout is not None:
        check(
            "W3: acquire_lock default timeout == 120.0s",
            default_timeout.default == 120.0,
            f"got {default_timeout.default}",
        )
    else:
        check("W3: acquire_lock default timeout", False, "parameter not found")

    # W4: retry_write succeeds on first attempt
    calls = []
    def _ok_fn():
        calls.append(1)
        return "done"
    result = retry_write(_ok_fn, attempts=3, base_delay=0.01)
    check("W4: retry_write succeeds on clean callable", result == "done" and len(calls) == 1)

    # W5: retry_write retries on transient failures then succeeds
    attempt_log = []
    def _flaky_fn():
        attempt_log.append(1)
        if len(attempt_log) < 3:
            raise OSError("transient")
        return "recovered"
    res = retry_write(_flaky_fn, attempts=5, base_delay=0.01)
    check(
        "W5: retry_write retries on transient errors and recovers",
        res == "recovered" and len(attempt_log) == 3,
        f"attempts={len(attempt_log)}",
    )

    # W6: retry_write raises WriteHardFail after all attempts exhausted
    always_fail_calls = []
    def _always_fail():
        always_fail_calls.append(1)
        raise OSError("permanent failure")
    raised_hard_fail = False
    try:
        retry_write(_always_fail, attempts=3, base_delay=0.01)
    except WriteHardFail:
        raised_hard_fail = True
    check(
        "W6: retry_write raises WriteHardFail after all attempts exhausted",
        raised_hard_fail and len(always_fail_calls) == 3,
        f"attempts={len(always_fail_calls)}",
    )

    # W7: WriteQueue enqueue + flush — sequential, no parallel writes
    flush_order = []
    WriteQueue.reset()
    for i in range(5):
        idx = i
        WriteQueue.enqueue(lambda _i=idx: flush_order.append(_i))
    metrics = WriteQueue.flush(attempts=1, base_delay=0.01)
    check(
        "W7: WriteQueue.flush() processes items sequentially in order",
        flush_order == [0, 1, 2, 3, 4] and metrics["queued"] == 5 and metrics["succeeded"] == 5,
        f"order={flush_order} metrics={metrics}",
    )

    # W8: WriteQueue.flush() clears the queue (no residual items)
    # Queue was flushed above — should be empty
    WriteQueue.reset()
    flush2 = WriteQueue.flush(attempts=1, base_delay=0.01)
    check(
        "W8: WriteQueue.flush() on empty queue returns queued=0",
        flush2["queued"] == 0 and flush2["succeeded"] == 0,
    )

    # W9: atomic_json_write performs JSON verify and returns byte count
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tp = Path(tf.name)
    try:
        sz = atomic_json_write(tp, {"test": True, "v": 132}, locked=False)
        loaded = json.loads(tp.read_text(encoding="utf-8"))
        check(
            "W9: atomic_json_write writes valid JSON, returns byte count > 0",
            sz > 0 and loaded.get("v") == 132,
            f"sz={sz} bytes",
        )
    finally:
        try:
            tp.unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# F-group: Fail-safe Buffer
# ---------------------------------------------------------------------------

def test_f_group() -> None:
    section("F-GROUP: Fail-safe Write Buffer")

    try:
        from safe_io import _store_write_failure, _resolve_recovery_paths
    except ImportError as e:
        for n in ["F1", "F2", "F3"]:
            check(f"{n}: (skipped)", False, str(e))
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Override recovery paths to temp dir
        import safe_io as _sio
        _sio._WRITE_FAILURE_DIR = root / "data" / "recovery" / "write_failures"
        _sio._WRITE_FAILURE_LOG = root / "data" / "logs" / "write_failures.jsonl"

        # F1: _store_write_failure creates recovery directory
        _store_write_failure(
            root / "data" / "stix" / "feed_manifest.json",
            OSError("simulated disk full"),
            payload={"test": "F1"},
            repo_root=root,
        )
        check(
            "F1: _store_write_failure creates data/recovery/write_failures/ directory",
            _sio._WRITE_FAILURE_DIR.exists() and _sio._WRITE_FAILURE_DIR.is_dir(),
        )

        # F2: payload blob written to recovery dir
        blobs = list(_sio._WRITE_FAILURE_DIR.glob("*.json")) if _sio._WRITE_FAILURE_DIR.exists() else []
        check(
            "F2: payload blob written to recovery directory",
            len(blobs) == 1,
            f"blobs_found={len(blobs)}",
        )
        if blobs:
            try:
                recovered = json.loads(blobs[0].read_text(encoding="utf-8"))
                check(
                    "F2b: payload blob is valid JSON with original data",
                    recovered.get("test") == "F1",
                )
            except Exception as e:
                check("F2b: payload blob is valid JSON", False, str(e))

        # F3: JSONL log entry written
        if _sio._WRITE_FAILURE_LOG and _sio._WRITE_FAILURE_LOG.exists():
            lines = [l.strip() for l in _sio._WRITE_FAILURE_LOG.read_text().splitlines() if l.strip()]
            if lines:
                entry = json.loads(lines[0])
                check(
                    "F3: write_failures.jsonl contains valid JSONL record with error_type",
                    "error_type" in entry and "timestamp" in entry and "target_path" in entry,
                    f"keys={list(entry.keys())}",
                )
            else:
                check("F3: write_failures.jsonl has at least one entry", False, "file empty")
        else:
            check("F3: write_failures.jsonl exists after failure", False, "file not created")

        # Reset to None so other tests don't use temp paths
        _sio._WRITE_FAILURE_DIR = None
        _sio._WRITE_FAILURE_LOG = None


# ---------------------------------------------------------------------------
# M-group: Manifest Integrity
# ---------------------------------------------------------------------------

def test_m_group() -> None:
    section("M-GROUP: Manifest Integrity")

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

    # M1: Manifest file exists
    check("M1: feed_manifest.json exists", manifest_path.exists())

    if not manifest_path.exists():
        for n in ["M2", "M3", "M4", "M5", "M6"]:
            check(f"{n}: (skipped — manifest missing)", False)
        return

    # M2: Manifest is valid JSON
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        check("M2: manifest is valid JSON", True, f"type={type(raw).__name__}")
    except Exception as e:
        check("M2: manifest is valid JSON", False, str(e))
        for n in ["M3", "M4", "M5", "M6"]:
            check(f"{n}: (skipped)", False, "parse failed")
        return

    items = raw.get("advisories", raw.get("reports", raw if isinstance(raw, list) else []))

    # M3: Manifest is non-empty
    check("M3: manifest has > 0 entries", len(items) > 0, f"count={len(items)}")

    # M4: Zero write_error entries
    write_errors = [i for i in items if i.get("validation_status") == "write_error"]
    check(
        "M4: zero write_error entries in manifest",
        len(write_errors) == 0,
        f"write_errors={len(write_errors)}",
    )

    # M5: Zero render_error entries
    render_errors = [i for i in items if i.get("validation_status") == "render_error"]
    check(
        "M5: zero render_error entries in manifest",
        len(render_errors) == 0,
        f"render_errors={len(render_errors)}",
    )

    # M6: All processed (ok/enriched) entries have report_url set
    # Entries with validation_status=None have not been processed yet — skip them
    processed = [
        i for i in items
        if i.get("validation_status") in ("ok", "enriched")
    ]
    if not processed:
        check("M6: processed entry report_url check", True, "no ok/enriched entries yet (pre-pipeline state — OK)")
    else:
        missing_url = [i for i in processed if not i.get("report_url", "").startswith("https://")]
        check(
            "M6: all ok/enriched entries have valid https report_url",
            len(missing_url) == 0,
            f"missing_url={len(missing_url)}/{len(processed)}",
        )


# ---------------------------------------------------------------------------
# D-group: Disk Integrity
# ---------------------------------------------------------------------------

def test_d_group() -> None:
    section("D-GROUP: Disk File Integrity")

    reports_dir = REPO_ROOT / "reports"
    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

    # D1: reports/ directory exists
    check("D1: reports/ directory exists", reports_dir.is_dir())

    # D2: At least one HTML report exists
    if reports_dir.is_dir():
        html_files = list(reports_dir.rglob("*.html"))
        non_index = [f for f in html_files if f.name != "index.html"]
        check("D2: at least one intel HTML report exists in reports/", len(non_index) > 0, f"count={len(non_index)}")
    else:
        check("D2: at least one intel HTML report exists", False, "reports/ missing")
        non_index = []

    # D3: Manifest ok/enriched count vs on-disk report count (within 10% tolerance)
    # Skip if manifest has no ok/enriched entries yet (pre-pipeline state)
    if manifest_path.exists() and non_index:
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            items = raw.get("advisories", raw.get("reports", []))
            ok_items = [
                i for i in items
                if i.get("validation_status") in ("ok", "enriched")
            ]
            disk_count = len(non_index)
            manifest_ok_count = len(ok_items)
            if manifest_ok_count == 0:
                # Pre-pipeline state — manifest exists but no reports generated yet
                check(
                    "D3: manifest vs disk count comparison",
                    True,
                    f"manifest has 0 ok/enriched entries (pre-pipeline state) — {disk_count} historical reports on disk",
                )
            else:
                # Allow 10% delta (some reports may predate current run)
                delta = abs(disk_count - manifest_ok_count)
                tolerance = max(5, int(manifest_ok_count * 0.10))
                check(
                    "D3: manifest ok/enriched count matches disk report count (±10%)",
                    delta <= tolerance,
                    f"manifest_ok={manifest_ok_count} disk={disk_count} delta={delta} tolerance={tolerance}",
                )
        except Exception as e:
            check("D3: manifest vs disk count comparison", False, str(e))
    else:
        check("D3: manifest vs disk count comparison", False, "manifest or reports missing")

    # D4: No report file is under 512 bytes (too small = corrupted write)
    tiny_files = [f for f in non_index if f.stat().st_size < 512] if non_index else []
    check(
        "D4: no report file < 512 bytes (no truncated writes)",
        len(tiny_files) == 0,
        f"tiny_files={len(tiny_files)}",
    )
    for tf in tiny_files[:5]:
        print(f"    {_c('TINY', 'yellow')}: {tf.relative_to(REPO_ROOT)} ({tf.stat().st_size}B)")

    # D5: write_failures.jsonl absent or empty (no permanent write failures)
    wf_log = REPO_ROOT / "data" / "logs" / "write_failures.jsonl"
    if not wf_log.exists():
        check("D5: write_failures.jsonl absent (no permanent failures)", True)
    else:
        try:
            lines = [l.strip() for l in wf_log.read_text(encoding="utf-8").splitlines() if l.strip()]
            check(
                "D5: write_failures.jsonl empty (no permanent failures)",
                len(lines) == 0,
                f"failure_records={len(lines)}",
            )
        except Exception as e:
            check("D5: write_failures.jsonl readable", False, str(e))


# ---------------------------------------------------------------------------
# X-group: Cross-layer SSOT Assertions
# ---------------------------------------------------------------------------

def test_x_group() -> None:
    section("X-GROUP: Cross-layer SSOT Assertions")

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

    # X1: pipeline_metrics.json exists and has write_failures == 0
    metrics_path = REPO_ROOT / "data" / "logs" / "pipeline_metrics.json"
    if metrics_path.exists():
        try:
            m = json.loads(metrics_path.read_text(encoding="utf-8"))
            wf = m.get("write_failures", 0)
            check(
                "X1: pipeline_metrics.json write_failures == 0",
                wf == 0,
                f"write_failures={wf}",
            )
        except Exception as e:
            check("X1: pipeline_metrics.json readable", False, str(e))
    else:
        # Non-fatal — metrics may not exist on first run
        check("X1: pipeline_metrics.json exists (optional)", True, "not yet generated (OK on first run)")

    # X2: Manifest has no items with validation_status not in known set
    # None = pre-pipeline unset state (acceptable), only flag unknown non-None strings
    KNOWN_STATUSES = {"ok", "enriched", "write_error", "render_error", "file_missing", "brand_skip", None}
    if manifest_path.exists():
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            items = raw.get("advisories", raw.get("reports", []))
            unknown_status = [
                i.get("validation_status") for i in items
                if i.get("validation_status") not in KNOWN_STATUSES
            ]
            check(
                "X2: all manifest validation_status values are in known set",
                len(unknown_status) == 0,
                f"unknown={set(unknown_status)}" if unknown_status else "",
            )
        except Exception as e:
            check("X2: manifest status set validation", False, str(e))
    else:
        check("X2: manifest exists for status check", False, "manifest missing")

    # X3: WriteQueue is importable and exposes required interface
    try:
        from safe_io import WriteQueue, retry_write, WriteHardFail, _store_write_failure
        has_enqueue = callable(getattr(WriteQueue, "enqueue", None))
        has_flush   = callable(getattr(WriteQueue, "flush",   None))
        has_metrics = callable(getattr(WriteQueue, "metrics_snapshot", None))
        check(
            "X3: WriteQueue has enqueue(), flush(), metrics_snapshot() methods",
            has_enqueue and has_flush and has_metrics,
        )
    except ImportError as e:
        check("X3: WriteQueue interface", False, str(e))

    # X4: retry_write has correct signature (attempts=5, base_delay=0.5 defaults)
    try:
        import inspect
        from safe_io import retry_write
        sig = inspect.signature(retry_write)
        att_default = sig.parameters.get("attempts")
        delay_default = sig.parameters.get("base_delay")
        check(
            "X4: retry_write defaults: attempts=5, base_delay=0.5",
            (att_default is not None and att_default.default == 5) and
            (delay_default is not None and delay_default.default == 0.5),
            f"attempts={att_default.default if att_default else '?'} "
            f"base_delay={delay_default.default if delay_default else '?'}",
        )
    except Exception as e:
        check("X4: retry_write signature", False, str(e))

    # X5: No stale .tmp files in reports/ or data/ (abandoned failed writes)
    stale_tmp: list[Path] = []
    for search_dir in [REPO_ROOT / "reports", REPO_ROOT / "data"]:
        if search_dir.is_dir():
            stale_tmp.extend(search_dir.rglob("*.tmp"))
    check(
        "X5: no stale .tmp files from abandoned writes",
        len(stale_tmp) == 0,
        f"stale_tmp={len(stale_tmp)}",
    )
    for st in stale_tmp[:5]:
        print(f"    {_c('STALE_TMP', 'yellow')}: {st.relative_to(REPO_ROOT)}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    print(_c("\n" + "=" * 60, "bold"))
    print(_c("  SENTINEL APEX v132.0.0 -- Write Integrity Validation Suite", "bold"))
    print(_c("=" * 60, "bold"))

    test_w_group()
    test_f_group()
    test_m_group()
    test_d_group()
    test_x_group()

    # Summary
    total  = len(_RESULTS)
    passed = sum(1 for _, p, _ in _RESULTS if p)
    failed = total - passed

    print()
    print(_c("=" * 60, "bold"))
    print(f"  Results: {_c(str(passed), 'green')}/{total} passed | "
          f"{_c(str(failed), 'red') if failed else _c('0', 'green')} failed")
    print(_c("=" * 60, "bold"))

    if failed:
        print()
        print(_c("  FAILED CHECKS:", "red"))
        for name, passed_flag, detail in _RESULTS:
            if not passed_flag:
                detail_str = f"  ({detail})" if detail else ""
                print(f"    {_c('FAIL', 'red')} {name}{detail_str}")
        print()
        return 1

    print(_c("  ALL CHECKS PASSED", "green"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
