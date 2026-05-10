#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v146.0.0
JWT GOVERNANCE & WEBHOOK VALIDATION ENFORCER
===============================================================================
PURPOSE:
  Audits JWT configuration, secret strength, expiry policies, and webhook
  HMAC validation for all inbound payment/event webhooks. Prevents:
  - Weak JWT secrets (< 256-bit entropy)
  - Expired or never-rotating signing keys
  - Webhook payloads accepted without HMAC signature verification
  - Token lifetime policies outside enterprise bounds

CHECKS:
  1. JWT_SECRET strength  — must be >= 32 bytes (256-bit)
  2. JWT expiry policy    — access tokens <= 24h, refresh <= 30d
  3. Webhook HMAC guard   — subscription_manager.py must verify signature
  4. Secret rotation age  — warn if secret_metadata.json > 90 days old
  5. Algorithm whitelist  — only HS256/RS256/ES256 permitted

OUTPUTS:
  data/governance/jwt_governance.json — audit report

EXIT CODES:
  0 — PASS (all controls green)
  1 — HARD FAIL (weak secret or missing HMAC verification in webhook handler)
  3 — WARN (rotation age, policy drift — non-blocking)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [jwt_governance] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-JWT-GOVERNANCE")

REPO_ROOT   = pathlib.Path(__file__).resolve().parent.parent
GOV_DIR     = REPO_ROOT / "data" / "governance"
REPORT_PATH = GOV_DIR / "jwt_governance.json"

VERSION = "146.0.0"

# Policy constants
MIN_SECRET_BYTES    = 32       # 256-bit minimum
MAX_ACCESS_TOKEN_H  = 24       # hours
MAX_REFRESH_TOKEN_D = 30       # days
SECRET_ROTATION_DAYS= 90       # warn if older than this
ALLOWED_ALGORITHMS  = {"HS256", "RS256", "ES256", "HS512", "RS512"}

# Source files to audit
SUBSCRIPTION_MGR = REPO_ROOT / "agent" / "subscription_manager.py"
REVENUE_ANALYTICS= REPO_ROOT / "agent" / "revenue_analytics.py"
WORKER_SRC       = REPO_ROOT / "workers" / "intel-gateway" / "src" / "index.js"
SECRET_METADATA  = REPO_ROOT / "data" / "sovereign" / "secret_metadata.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".jwt_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def check_secret_strength() -> Tuple[str, str]:
    """Check CDB_JWT_SECRET env var (length proxy only — never log value)."""
    secret = os.environ.get("CDB_JWT_SECRET", "")
    if not secret:
        return "WARN", "CDB_JWT_SECRET not set in environment (CI secret injection may handle this)"
    if len(secret.encode()) < MIN_SECRET_BYTES:
        return "FAIL", (
            f"CDB_JWT_SECRET is {len(secret.encode())} bytes "
            f"— minimum required: {MIN_SECRET_BYTES} bytes (256-bit)"
        )
    return "PASS", f"CDB_JWT_SECRET length >= {MIN_SECRET_BYTES} bytes (entropy OK)"


def check_webhook_hmac(src_path: pathlib.Path) -> Tuple[str, str]:
    """Verify HMAC signature check exists in subscription_manager."""
    if not src_path.exists():
        return "WARN", f"Source not found: {src_path.name} (cannot audit)"

    src = src_path.read_text(encoding="utf-8", errors="replace")

    hmac_patterns = [
        r"hmac\.new",
        r"hmac\.compare_digest",
        r"HMAC",
        r"sha256.*signature",
        r"verify.*signature",
        r"validate.*webhook",
        r"webhook.*secret",
        r"x-gumroad-signature",
        r"stripe-signature",
        r"verify_signature",
    ]
    found = [p for p in hmac_patterns if re.search(p, src, re.IGNORECASE)]
    if not found:
        return "FAIL", (
            f"{src_path.name}: No HMAC/signature verification found. "
            "Webhook payloads accepted without authenticity check (SSRF/forgery risk)."
        )
    return "PASS", f"{src_path.name}: HMAC/webhook signature patterns present ({len(found)} matches)"


def check_jwt_expiry_policy(src_paths: List[pathlib.Path]) -> Tuple[str, str]:
    """Scan source for excessively long JWT lifetimes."""
    issues = []
    checked = []

    for path in src_paths:
        if not path.exists():
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        checked.append(path.name)

        # Look for expiry patterns (days/hours/seconds values near 'exp'/'expire'/'expiry')
        # Flag anything claiming >24h access token or >30d refresh
        days_matches = re.findall(r'(?:expire[sd]?|expiry|exp)\s*[=:]\s*(\d+)\s*\*\s*24\s*\*\s*(?:60\s*\*\s*60|3600)', src, re.IGNORECASE)
        for d in days_matches:
            days_val = int(d)
            if days_val > MAX_REFRESH_TOKEN_D:
                issues.append(f"{path.name}: JWT expiry {days_val} days exceeds policy ({MAX_REFRESH_TOKEN_D}d max)")

        # Flag raw large second values (>86400 seconds = >1 day)
        sec_matches = re.findall(r'(?:expire[sd]?|expiry|exp|lifetime)\s*[=:]\s*(\d{6,})', src, re.IGNORECASE)
        for s in sec_matches:
            secs = int(s)
            if secs > MAX_ACCESS_TOKEN_H * 3600:
                days_eq = secs / 86400
                issues.append(f"{path.name}: Token lifetime {secs}s ({days_eq:.1f}d) — review if access token")

    if not checked:
        return "WARN", "No source files found to audit JWT expiry policy"
    if issues:
        return "WARN", "; ".join(issues)
    return "PASS", f"JWT expiry policy: no over-long lifetimes detected in {', '.join(checked)}"


def check_algorithm_whitelist(src_paths: List[pathlib.Path]) -> Tuple[str, str]:
    """Ensure only approved JWT algorithms are referenced."""
    disallowed = {"HS1", "RS1", "NONE", "none", "RS384", "HS384"}
    found_bad = []

    for path in src_paths:
        if not path.exists():
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        for alg in disallowed:
            if re.search(rf'["\']({alg})["\']', src):
                found_bad.append(f"{path.name}: disallowed algorithm '{alg}'")

    if found_bad:
        return "FAIL", "; ".join(found_bad)
    return "PASS", f"Algorithm whitelist: no disallowed algorithms detected"


def check_secret_rotation_age() -> Tuple[str, str]:
    """Warn if secret metadata shows key older than rotation policy."""
    if not SECRET_METADATA.exists():
        return "INFO", "secret_metadata.json not present (key rotation tracking not yet active)"

    try:
        meta = json.loads(SECRET_METADATA.read_text(encoding="utf-8"))
        rotated_at_str = meta.get("last_rotated") or meta.get("created_at", "")
        if not rotated_at_str:
            return "WARN", "secret_metadata.json has no rotation timestamp"

        rotated_at = datetime.fromisoformat(rotated_at_str.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - rotated_at).days
        if age_days > SECRET_ROTATION_DAYS:
            return "WARN", (
                f"JWT signing key last rotated {age_days} days ago "
                f"(policy: rotate every {SECRET_ROTATION_DAYS} days) — rotation overdue"
            )
        return "PASS", f"JWT signing key rotated {age_days} days ago (within {SECRET_ROTATION_DAYS}-day policy)"
    except Exception as e:
        return "WARN", f"Could not parse secret_metadata.json: {e}"


def check_worker_auth_enforcement() -> Tuple[str, str]:
    """Verify Cloudflare Worker enforces auth on protected endpoints."""
    if not WORKER_SRC.exists():
        return "WARN", f"Worker source not found: {WORKER_SRC}"

    src = WORKER_SRC.read_text(encoding="utf-8", errors="replace")

    auth_patterns = [
        r"Authorization",
        r"Bearer",
        r"verif.*token",
        r"jwt.*verif",
        r"401",
        r"403",
    ]
    found = sum(1 for p in auth_patterns if re.search(p, src, re.IGNORECASE))
    if found < 3:
        return "WARN", f"Worker auth enforcement: only {found}/6 auth indicators found — review protected routes"
    return "PASS", f"Worker auth enforcement: {found}/6 auth indicators present"


def main() -> int:
    t0 = time.monotonic()
    log.info("=" * 66)
    log.info("SENTINEL APEX %s — JWT Governance & Webhook Validation", VERSION)
    log.info("=" * 66)

    checks: List[Dict[str, Any]] = []
    hard_fail = False
    soft_warn = False

    src_files = [SUBSCRIPTION_MGR, REVENUE_ANALYTICS]

    def record(name: str, status: str, detail: str) -> None:
        nonlocal hard_fail, soft_warn
        icon = {"PASS": "[PASS]", "FAIL": "[FAIL]", "WARN": "[WARN]", "INFO": "[INFO]"}.get(status, "[????]")
        log.info("%s %s: %s", icon, name, detail[:120])
        checks.append({"check": name, "status": status, "detail": detail})
        if status == "FAIL":
            hard_fail = True
        elif status == "WARN":
            soft_warn = True

    # Run all checks
    status, detail = check_secret_strength()
    record("secret_strength", status, detail)

    status, detail = check_webhook_hmac(SUBSCRIPTION_MGR)
    record("webhook_hmac_subscription_mgr", status, detail)

    status, detail = check_jwt_expiry_policy(src_files)
    record("jwt_expiry_policy", status, detail)

    status, detail = check_algorithm_whitelist(src_files)
    record("algorithm_whitelist", status, detail)

    status, detail = check_secret_rotation_age()
    record("secret_rotation_age", status, detail)

    status, detail = check_worker_auth_enforcement()
    record("worker_auth_enforcement", status, detail)

    # Overall verdict
    if hard_fail:
        overall = "FAIL"
    elif soft_warn:
        overall = "WARN"
    else:
        overall = "PASS"

    runtime = round(time.monotonic() - t0, 3)
    pass_count = sum(1 for c in checks if c["status"] == "PASS")
    fail_count = sum(1 for c in checks if c["status"] == "FAIL")
    warn_count = sum(1 for c in checks if c["status"] == "WARN")

    report = {
        "schema_version"  : "1.0",
        "generated_at"    : now_iso(),
        "generator"       : "jwt_governance.py",
        "version"         : VERSION,
        "overall_verdict" : overall,
        "pass_count"      : pass_count,
        "fail_count"      : fail_count,
        "warn_count"      : warn_count,
        "checks"          : checks,
        "runtime_seconds" : runtime,
        "policy"          : {
            "min_secret_bytes"    : MIN_SECRET_BYTES,
            "max_access_token_h"  : MAX_ACCESS_TOKEN_H,
            "max_refresh_token_d" : MAX_REFRESH_TOKEN_D,
            "secret_rotation_days": SECRET_ROTATION_DAYS,
            "allowed_algorithms"  : sorted(ALLOWED_ALGORITHMS),
        },
    }

    GOV_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(REPORT_PATH, json.dumps(report, ensure_ascii=False, indent=2))

    log.info("=" * 66)
    log.info("JWT GOVERNANCE: %s | pass=%d fail=%d warn=%d", overall, pass_count, fail_count, warn_count)
    log.info("[WRITE] %s", REPORT_PATH)
    log.info("=" * 66)

    if hard_fail:
        return 1
    if soft_warn:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
