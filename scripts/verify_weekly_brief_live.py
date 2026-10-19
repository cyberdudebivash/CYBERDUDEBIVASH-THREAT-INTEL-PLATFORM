#!/usr/bin/env python3
"""Verify the live Weekly Threat Brief API matches the artifact from this run."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests


REPO_ROOT = Path(__file__).resolve().parent.parent
LOCAL_PATH = REPO_ROOT / "api" / "v1" / "intel" / "weekly_brief.json"
LIVE_URL = os.environ.get(
    "WEEKLY_BRIEF_LIVE_URL",
    "https://intel.cyberdudebivash.com/api/v1/intel/weekly_brief.json",
).strip()
LIVE_HTML_URL = os.environ.get(
    "WEEKLY_BRIEF_HTML_URL",
    "https://intel.cyberdudebivash.com/weekly-brief",
).strip()
ATTEMPTS = max(1, int(os.environ.get("WEEKLY_BRIEF_VERIFY_ATTEMPTS", "8")))
SLEEP_SECONDS = max(1, int(os.environ.get("WEEKLY_BRIEF_VERIFY_SLEEP_SECONDS", "5")))
TIMEOUT_SECONDS = max(2, int(os.environ.get("WEEKLY_BRIEF_VERIFY_TIMEOUT_SECONDS", "10")))


def fail(message: str) -> None:
    print(f"::error::{message}", flush=True)
    raise SystemExit(1)


def load_local() -> dict:
    if not LOCAL_PATH.is_file() or LOCAL_PATH.stat().st_size <= 0:
        fail(f"local weekly brief missing or empty: {LOCAL_PATH}")
    try:
        payload = json.loads(LOCAL_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"local weekly brief is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        fail("local weekly brief must be a JSON object")
    for field in ("_schema", "week", "generated_at"):
        if not str(payload.get(field, "")).strip():
            fail(f"local weekly brief missing required field: {field}")
    return payload


def verify_customer_page(expected_week: str, expected_generated: str) -> str | None:
    """Production evidence must cover the customer URL, not JSON alone.

    A dynamic page must explicitly fetch the R2-backed artifact. Alternatively,
    the existing static report is accepted only when it matches THIS run.
    """
    response = requests.get(
        LIVE_HTML_URL,
        timeout=TIMEOUT_SECONDS,
        headers={"Cache-Control": "no-cache", "Accept": "text/html"},
    )
    if response.status_code != 200:
        return f"customer HTML HTTP {response.status_code}"
    body = response.text
    if '<html' not in body.lower():
        return "customer URL did not return HTML"
    if 'data-weekly-brief-live="r2"' in body and "/api/v1/intel/weekly_brief.json" in body:
        return None
    # A static deploy is valid only for exactly this source-generated report.
    if expected_week in body and expected_generated[:10] in body:
        return None
    return "customer HTML is stale or does not fetch the authoritative weekly API"


def main() -> int:
    local = load_local()
    expected_generated = str(local["generated_at"])
    expected_week = str(local["week"])
    last_error = "no request attempted"

    for attempt in range(1, ATTEMPTS + 1):
        try:
            response = requests.get(
                LIVE_URL,
                timeout=TIMEOUT_SECONDS,
                headers={
                    "Accept": "application/json",
                    "Cache-Control": "no-cache",
                    "User-Agent": "sentinel-apex-weekly-brief-release-verifier/201.0",
                },
            )
            if response.status_code != 200:
                last_error = f"HTTP {response.status_code}: {response.text[:240]}"
            else:
                live = response.json()
                if not isinstance(live, dict):
                    last_error = "live response is not a JSON object"
                elif live.get("generated_at") != expected_generated:
                    last_error = (
                        "generated_at mismatch: "
                        f"expected={expected_generated!r} live={live.get('generated_at')!r}"
                    )
                elif live.get("week") != expected_week:
                    last_error = (
                        f"week mismatch: expected={expected_week!r} live={live.get('week')!r}"
                    )
                elif live.get("_schema") != local.get("_schema"):
                    last_error = (
                        "schema mismatch: "
                        f"expected={local.get('_schema')!r} live={live.get('_schema')!r}"
                    )
                else:
                    page_error = verify_customer_page(expected_week, expected_generated)
                    if page_error:
                        last_error = page_error
                    else:
                        print(
                            "[PASS] Live API and customer HTML verified: "
                            f"week={expected_week} generated_at={expected_generated}",
                            flush=True,
                        )
                        return 0
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        print(
            f"[WAIT] live weekly brief verification {attempt}/{ATTEMPTS}: {last_error}",
            flush=True,
        )
        if attempt < ATTEMPTS:
            time.sleep(SLEEP_SECONDS)

    fail(f"live weekly brief did not converge to this run: {last_error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
