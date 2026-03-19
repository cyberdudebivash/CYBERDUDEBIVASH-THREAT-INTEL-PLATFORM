#!/usr/bin/env python3
"""
SENTINEL APEX v65 — Pipeline Persistence Layer
Writes processed advisories from GitHub Actions pipeline to Supabase PG.

Integration: Add as stage in sentinel-blogger.yml after STIX export.
CLI: python -m agent.v65_persistence.pg_writer --manifest data/feed_manifest.json
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger("sentinel.v65.persistence")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
SENTINEL_API_URL = os.environ.get("SENTINEL_API_URL", "")
PIPELINE_SECRET = os.environ.get("PIPELINE_SECRET", "")

BATCH_SIZE = 25
RETRY_ATTEMPTS = 3
RETRY_BACKOFF = 2.0


class PipelinePersistence:
    def __init__(self, mode: str = "auto"):
        self.mode = mode
        self._stats = {"persisted": 0, "skipped": 0, "errors": 0}

    async def persist_batch(self, advisories: list[dict[str, Any]]) -> dict[str, int]:
        if not advisories:
            return self._stats
        logger.info(f"Persisting {len(advisories)} advisories via {self.mode}")

        if self.mode == "api" or (self.mode == "auto" and SENTINEL_API_URL and PIPELINE_SECRET):
            return await self._persist_via_api(advisories)
        elif SUPABASE_URL and SUPABASE_SERVICE_KEY:
            return await self._persist_via_supabase(advisories)
        else:
            logger.error("No persistence backend configured")
            return self._stats

    async def _persist_via_api(self, advisories: list[dict]) -> dict[str, int]:
        url = f"{SENTINEL_API_URL.rstrip('/')}/api/v1/ingest"
        async with httpx.AsyncClient(timeout=60.0) as client:
            for i in range(0, len(advisories), BATCH_SIZE):
                batch = advisories[i:i + BATCH_SIZE]
                payload = {"advisories": [self._normalize(a) for a in batch], "pipeline_secret": PIPELINE_SECRET}
                for attempt in range(RETRY_ATTEMPTS):
                    try:
                        resp = await client.post(url, json=payload)
                        resp.raise_for_status()
                        result = resp.json()
                        self._stats["persisted"] += result.get("ingested", 0)
                        self._stats["errors"] += result.get("errors", 0)
                        break
                    except Exception as e:
                        if attempt < RETRY_ATTEMPTS - 1:
                            await asyncio.sleep(RETRY_BACKOFF ** (attempt + 1))
                        else:
                            logger.error(f"API ingest failed: {e}")
                            self._stats["errors"] += len(batch)
        return self._stats

    async def _persist_via_supabase(self, advisories: list[dict]) -> dict[str, int]:
        headers = {
            "apikey": SUPABASE_SERVICE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        }
        url = f"{SUPABASE_URL}/rest/v1/advisories"
        async with httpx.AsyncClient(timeout=30.0) as client:
            for i in range(0, len(advisories), BATCH_SIZE):
                batch = advisories[i:i + BATCH_SIZE]
                rows = [self._to_row(a) for a in batch]
                for attempt in range(RETRY_ATTEMPTS):
                    try:
                        resp = await client.post(url, headers=headers, json=rows)
                        resp.raise_for_status()
                        self._stats["persisted"] += len(rows)
                        break
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code == 409:
                            self._stats["skipped"] += len(rows)
                            break
                        if attempt < RETRY_ATTEMPTS - 1:
                            await asyncio.sleep(RETRY_BACKOFF ** (attempt + 1))
                        else:
                            logger.error(f"Supabase batch failed: {e.response.text}")
                            self._stats["errors"] += len(rows)
                    except Exception as e:
                        if attempt < RETRY_ATTEMPTS - 1:
                            await asyncio.sleep(RETRY_BACKOFF ** (attempt + 1))
                        else:
                            logger.error(f"Supabase error: {e}")
                            self._stats["errors"] += len(rows)
        return self._stats

    def _normalize(self, advisory: dict) -> dict:
        return {
            "id": advisory.get("id") or self._generate_id(advisory),
            "title": advisory.get("title", "Untitled"),
            "description": advisory.get("description") or advisory.get("content"),
            "summary_ai": advisory.get("summary_ai") or advisory.get("ai_summary"),
            "risk_score": advisory.get("risk_score"),
            "confidence": advisory.get("confidence"),
            "severity": self._classify_severity(advisory),
            "cvss": advisory.get("cvss"),
            "epss": advisory.get("epss"),
            "kev": advisory.get("kev") or advisory.get("kev_listed", False),
            "cve_id": advisory.get("cve_id") or advisory.get("cve"),
            "mitre_techniques": advisory.get("mitre_techniques") or advisory.get("mitre", []),
            "iocs": advisory.get("iocs", []),
            "stix_bundle_url": advisory.get("stix_bundle_url") or advisory.get("stix_url"),
            "defense_kit": advisory.get("defense_kit", {}),
            "source": advisory.get("source"),
            "source_url": advisory.get("source_url") or advisory.get("link"),
            "tags": advisory.get("tags", []),
            "published_at": advisory.get("published_at") or advisory.get("published"),
        }

    def _to_row(self, advisory: dict) -> dict:
        n = self._normalize(advisory)
        for f in ("mitre_techniques", "iocs"):
            if isinstance(n.get(f), (list, dict)):
                n[f] = json.dumps(n[f])
        if isinstance(n.get("defense_kit"), dict):
            n["defense_kit"] = json.dumps(n["defense_kit"])
        n["ingested_at"] = datetime.now(timezone.utc).isoformat()
        return n

    @staticmethod
    def _generate_id(advisory: dict) -> str:
        c = f"{advisory.get('title','')}{advisory.get('source_url','')}{advisory.get('published','')}"
        return hashlib.sha256(c.encode()).hexdigest()[:16]

    @staticmethod
    def _classify_severity(advisory: dict) -> Optional[str]:
        if advisory.get("severity"):
            return advisory["severity"]
        s = advisory.get("risk_score")
        if s is None:
            return None
        if s >= 90: return "critical"
        if s >= 70: return "high"
        if s >= 40: return "medium"
        if s >= 20: return "low"
        return "info"


async def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX v65 Pipeline Persistence")
    parser.add_argument("--manifest", default="data/feed_manifest.json")
    parser.add_argument("--mode", choices=["auto", "api", "supabase"], default="auto")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

    path = Path(args.manifest)
    if not path.exists():
        logger.error(f"Manifest not found: {path}")
        sys.exit(1)

    with open(path) as f:
        manifest = json.load(f)

    advisories = manifest if isinstance(manifest, list) else manifest.get("advisories", [])
    logger.info(f"Loaded {len(advisories)} advisories")

    if args.dry_run:
        logger.info(f"DRY RUN: Would persist {len(advisories)}")
        return

    stats = await PipelinePersistence(mode=args.mode).persist_batch(advisories)
    logger.info(f"DONE: {stats}")
    if stats["errors"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
