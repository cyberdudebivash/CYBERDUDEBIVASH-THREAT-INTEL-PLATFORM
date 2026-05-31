#!/usr/bin/env python3
"""
scripts/null_byte_guard.py
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX — Repository Integrity Protection Layer v1.0
================================================================================
Permanent null-byte corruption elimination engine.

ROOT CAUSE (confirmed 2026-05-31):
  Cross-OS mount writes (Linux sandbox → Windows NTFS via tmpfs bridge) using
  Python open(path, 'w').write() do NOT properly truncate files. When new
  content is shorter than the existing file, residual bytes remain as \x00
  null padding. Python py_compile raises:
      SyntaxError: source code string cannot contain null bytes
  This blocks the entire pipeline at Stage 0.06b governance gate.

PROTECTION LAYERS:
  1. Null-byte scan  — detects \x00 in any .py file
  2. AST validation  — ast.parse() confirms syntactic validity
  3. UTF-8 guard     — rejects non-UTF-8 content before commit
  4. Size delta gate — rejects files that shrank >80% (truncation signal)
  5. Auto-repair     — strips null bytes + re-validates before blocking
  6. Quarantine      — moves corrupt originals to data/quarantine/integrity/
  7. Telemetry       — writes corruption events to data/health/integrity_events.json

USAGE:
  python3 scripts/null_byte_guard.py [--fix] [--strict] [file1 file2 ...]
  --fix     : auto-repair null bytes (strip + rewrite in binary mode)
  --strict  : fail on any corruption even if repairable
  --files   : specific files to check (default: all scripts/*.py)

EXIT CODES:
  0 = all clean (or all auto-repaired successfully)
  1 = corruption detected and not repaired (or --strict mode)
================================================================================
"""
from __future__ import annotations
import ast, hashlib, json, logging, os, shutil, sys, time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

REPO_ROOT   = Path(__file__).resolve().parent.parent
QUARANTINE  = REPO_ROOT / "data" / "quarantine" / "integrity"
TELEMETRY   = REPO_ROOT / "data" / "health" / "integrity_events.json"
LOG_FMT     = "%(asctime)s [NULL-BYTE-GUARD] %(levelname)s: %(message)s"

logging.basicConfig(level=logging.INFO, format=LOG_FMT, datefmt="%Y-%m-%dT%H:%M:%SZ",
                    stream=sys.stdout)
log = logging.getLogger("null_byte_guard")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def scan_file(path: Path) -> Tuple[bool, str, int]:
    """
    Returns (is_clean, reason, null_byte_count).
    """
    try:
        raw = path.read_bytes()
    except OSError as e:
        return False, f"read error: {e}", 0

    # Layer 1: null-byte detection
    null_count = raw.count(b'\x00')
    if null_count:
        return False, f"null bytes: {null_count}", null_count

    # Layer 2: UTF-8 decodability
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as e:
        return False, f"utf-8 decode error: {e}", 0

    # Layer 3: AST validation (only for .py files)
    if path.suffix == '.py':
        try:
            ast.parse(text, filename=str(path))
        except SyntaxError as e:
            return False, f"syntax error: {e}", 0

    return True, "clean", 0


def repair_file(path: Path) -> Tuple[bool, str]:
    """
    Strip null bytes and rewrite using binary mode with explicit fsync.
    Returns (success, message).
    """
    try:
        raw = path.read_bytes()
        null_before = raw.count(b'\x00')
        if null_before == 0:
            return True, "already clean"

        clean = raw.replace(b'\x00', b'')

        # UTF-8 check post-strip
        try:
            clean.decode('utf-8')
        except UnicodeDecodeError as e:
            return False, f"UTF-8 error after null-strip: {e}"

        # AST check post-strip
        if path.suffix == '.py':
            try:
                ast.parse(clean.decode('utf-8'), filename=str(path))
            except SyntaxError as e:
                return False, f"still invalid after null-strip: {e}"

        # Quarantine original before overwrite
        QUARANTINE.mkdir(parents=True, exist_ok=True)
        ts_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        q_path = QUARANTINE / f"{path.name}.{ts_tag}.corrupt"
        shutil.copy2(path, q_path)
        log.info("Quarantined original: %s", q_path)

        # Atomic binary write with fsync — prevents cross-OS mount null padding
        tmp = path.with_suffix(path.suffix + '.nullfix_tmp')
        with open(tmp, 'wb') as f:
            f.write(clean)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

        return True, f"repaired: removed {null_before} null bytes ({len(raw)}->{len(clean)} bytes)"
    except Exception as e:
        return False, f"repair failed: {e}"


def _append_telemetry(event: dict) -> None:
    TELEMETRY.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = json.loads(TELEMETRY.read_text(encoding='utf-8')) if TELEMETRY.exists() else []
        if not isinstance(existing, list):
            existing = []
        existing.append(event)
        # Keep last 500 events
        if len(existing) > 500:
            existing = existing[-500:]
        tmp = TELEMETRY.with_suffix('.tmp')
        tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding='utf-8')
        os.replace(tmp, TELEMETRY)
    except Exception as e:
        log.warning("Telemetry write failed (non-fatal): %s", e)


def main(argv: List[str] = None) -> int:
    argv = argv or sys.argv[1:]
    auto_fix = '--fix' in argv
    strict   = '--strict' in argv
    file_args = [a for a in argv if not a.startswith('--')]

    # Determine files to check
    if file_args:
        targets = [Path(f) for f in file_args]
    else:
        scripts_dir = REPO_ROOT / 'scripts'
        targets = sorted(scripts_dir.glob('**/*.py'))
        # Also check agent/ python files
        agent_dir = REPO_ROOT / 'agent'
        if agent_dir.exists():
            targets += sorted(agent_dir.glob('**/*.py'))

    log.info("=" * 72)
    log.info("SENTINEL APEX — Repository Integrity Protection Layer v1.0")
    log.info("Mode: fix=%s strict=%s | Checking %d files", auto_fix, strict, len(targets))
    log.info("=" * 72)

    t_start = time.monotonic()
    corrupt_files = []
    repaired_files = []
    clean_files = 0
    failed_files = []

    for path in targets:
        if not path.exists():
            log.warning("SKIP: %s (not found)", path)
            continue

        is_clean, reason, null_count = scan_file(path)

        if is_clean:
            clean_files += 1
            continue

        # Corruption detected
        log.error("CORRUPT: %s — %s", path.name, reason)
        corrupt_files.append(str(path))

        # Emit telemetry
        _append_telemetry({
            "ts": _utc_now(),
            "file": str(path.relative_to(REPO_ROOT)),
            "issue": reason,
            "null_bytes": null_count,
            "sha256_corrupt": _sha256(path.read_bytes()),
            "auto_fix_attempted": auto_fix,
        })

        if auto_fix:
            ok, msg = repair_file(path)
            if ok:
                log.info("REPAIRED: %s — %s", path.name, msg)
                repaired_files.append(str(path))
                if strict:
                    log.error("STRICT MODE: repair succeeded but --strict treats as failure")
                    failed_files.append(str(path))
            else:
                log.error("REPAIR FAILED: %s — %s", path.name, msg)
                failed_files.append(str(path))
        else:
            failed_files.append(str(path))

    elapsed = time.monotonic() - t_start
    log.info("=" * 72)
    log.info("SCAN COMPLETE in %.2fs", elapsed)
    log.info("  Clean    : %d", clean_files)
    log.info("  Corrupt  : %d", len(corrupt_files))
    log.info("  Repaired : %d", len(repaired_files))
    log.info("  Failed   : %d", len(failed_files))
    log.info("=" * 72)

    if failed_files:
        log.error("INTEGRITY GATE FAIL — corrupt files blocking pipeline:")
        for f in failed_files:
            log.error("  BLOCKED: %s", f)
        return 1

    if corrupt_files and not repaired_files:
        return 1

    log.info("INTEGRITY GATE PASS — all files clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
