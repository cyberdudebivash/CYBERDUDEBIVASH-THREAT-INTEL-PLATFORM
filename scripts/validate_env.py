#!/usr/bin/env python3
"""
scripts/validate_env.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.2.0 -- Environment Validator
===================================================================
Validates that all required environment variables and secrets are present
before the pipeline begins expensive operations.

Exit codes:
  0 -- all required vars present (warnings for optional vars)
  1 -- one or more REQUIRED vars missing (hard fail)

Required:
  CDB_JWT_SECRET

Optional (warnings only):
  NVD_API_KEY, CF_ACCOUNT_ID, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
  WORKER_ADMIN_SECRET, GUMROAD_ACCESS_TOKEN, TELEGRAM_BOT_TOKEN

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [validate_env] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.validate_env")

REQUIRED = {
    "CDB_JWT_SECRET": "JWT auth secret for Sentinel engine. Generate: openssl rand -hex 32",
}

OPTIONAL = {
    "NVD_API_KEY":            "NVD intel source (reduced rate limit without key)",
    "CF_ACCOUNT_ID":          "Cloudflare account ID (R2 upload will fail without this)",
    "AWS_ACCESS_KEY_ID":      "R2 access key (R2 upload will fail without this)",
    "AWS_SECRET_ACCESS_KEY":  "R2 secret key (R2 upload will fail without this)",
    "WORKER_ADMIN_SECRET":    "Worker KV cache bust (cache will expire naturally without this)",
    "GUMROAD_ACCESS_TOKEN":   "Revenue tracking (revenue module disabled without this)",
    "TELEGRAM_BOT_TOKEN":     "Telegram alerts (alerts disabled without this)",
}


def main() -> None:
    log.info("=" * 60)
    log.info("SENTINEL APEX -- Environment Validator")
    log.info("=" * 60)

    missing_required: list[str] = []
    missing_optional: list[str] = []

    for var, description in REQUIRED.items():
        value = os.environ.get(var, "").strip()
        if value:
            log.info("[OK]  REQUIRED  %s -- set", var)
        else:
            log.error("[FAIL] REQUIRED  %s -- MISSING", var)
            log.error("       Description: %s", description)
            missing_required.append(var)

    for var, description in OPTIONAL.items():
        value = os.environ.get(var, "").strip()
        if value:
            log.info("[OK]  optional  %s -- set", var)
        else:
            log.warning("[WARN] optional  %s -- not set (%s)", var, description)
            missing_optional.append(var)

    log.info("-" * 60)
    log.info("Required vars : %d/%d present", len(REQUIRED) - len(missing_required), len(REQUIRED))
    log.info("Optional vars : %d/%d present", len(OPTIONAL) - len(missing_optional), len(OPTIONAL))

    if missing_required:
        log.error("FATAL: %d required variable(s) missing: %s", len(missing_required), missing_required)
        log.error("Set these in: Repository Settings -> Secrets -> Actions")
        sys.exit(1)

    log.info("Environment validation PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        log.critical("validate_env.py crashed:\n%s\n%s", e, traceback.format_exc())
        sys.exit(1)
