#!/usr/bin/env python3
"""Fetch the canonical weekly intelligence source from R2, without fallback to git.

The checked-out api/feed.json is intentionally not a production data source.
Never republish a historical checkout copy when the authoritative R2 read fails.
One R2 GET per weekly publication; no LIST, no retries, no R2 writes.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from r2_upload import BUCKET_DATA, get_credentials, install_awscli, s3_get

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_KEY = "intel/feed_manifest.json"
DESTINATION = REPO_ROOT / "data" / "stix" / "feed_manifest.json"


def fetch_source(destination: Path = DESTINATION) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    account, _, _ = get_credentials()
    # The same canonical object sentinel-apex.yml and intel-gateway use.
    endpoint = f"https://{account}.r2.cloudflarestorage.com"
    install_awscli()
    fd, temp_name = tempfile.mkstemp(prefix=".weekly-source-", suffix=".json", dir=destination.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        status = s3_get(str(temp_path), BUCKET_DATA, SOURCE_KEY, endpoint)
        if status != "OK":
            print(f"::error::Weekly source unavailable in canonical R2: {status}", flush=True)
            return 1
        try:
            raw = json.loads(temp_path.read_text(encoding="utf-8"))
            items = raw if isinstance(raw, list) else raw.get("advisories", raw.get("items")) if isinstance(raw, dict) else None
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"::error::Invalid R2 weekly source: {type(exc).__name__}", flush=True)
            return 1
        if not isinstance(items, list) or not items or not all(isinstance(i, dict) for i in items):
            print("::error::Canonical R2 weekly source has no valid advisory list", flush=True)
            return 1
        os.replace(temp_path, destination)
        print(f"[PASS] Canonical R2 weekly source loaded ({len(items)} entries); publication still requires eligible in-window records", flush=True)
        return 0
    finally:
        temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(fetch_source())
