"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Multi-Cloud Bucket Hunter
=================================================================
Discovers misconfigured cloud storage across AWS S3, Azure Blob, and GCP.
Uses intelligent name permutation based on target domain.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import logging
from typing import List, Dict

logger = logging.getLogger("CDB-BH-CLOUD")


class CloudBucketHunter:
    """
    Multi-cloud storage enumeration engine.
    Generates permutations and probes:
      - AWS S3: {name}.s3.amazonaws.com
      - Azure Blob: {name}.blob.core.windows.net
      - GCP Storage: storage.googleapis.com/{name}
    """

    KEYWORDS = [
        "backup", "data", "logs", "internal", "sql", "dev",
        "staging", "config", "assets", "media", "uploads",
        "static", "prod", "test", "archive", "db", "secrets",
    ]

    def __init__(self, target_domain: str, concurrency: int = 50):
        self.target = target_domain.split(".")[0].lower()
        self.concurrency = concurrency
        self.results: List[Dict] = []

    def _generate_permutations(self) -> List[str]:
        """Generate high-probability bucket name candidates."""
        perms = [self.target]
        for kw in self.KEYWORDS:
            perms.extend([
                f"{self.target}-{kw}",
                f"{kw}-{self.target}",
                f"{self.target}.{kw}",
                f"{self.target}_{kw}",
            ])
        return perms

    async def _check_s3(self, session, bucket: str):
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    self.results.append({
                        "provider": "AWS_S3", "bucket": bucket,
                        "status": "PUBLIC_LISTING", "url": url,
                        "severity": "CRITICAL", "type": "CLOUD_LEAK",
                    })
                elif resp.status == 403:
                    self.results.append({
                        "provider": "AWS_S3", "bucket": bucket,
                        "status": "EXISTS_PRIVATE", "url": url,
                        "severity": "INFO", "type": "CLOUD_ENUM",
                    })
        except Exception:
            pass

    async def _check_azure(self, session, account: str):
        url = f"https://{account}.blob.core.windows.net"
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                if resp.status in (200, 403):
                    status = "PUBLIC" if resp.status == 200 else "EXISTS"
                    self.results.append({
                        "provider": "AZURE_BLOB", "bucket": account,
                        "status": status, "url": url,
                        "severity": "CRITICAL" if resp.status == 200 else "INFO",
                        "type": "CLOUD_LEAK" if resp.status == 200 else "CLOUD_ENUM",
                    })
        except Exception:
            pass

    async def _check_gcp(self, session, bucket: str):
        url = f"https://storage.googleapis.com/{bucket}"
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    self.results.append({
                        "provider": "GCP_STORAGE", "bucket": bucket,
                        "status": "PUBLIC_LISTING", "url": url,
                        "severity": "CRITICAL", "type": "CLOUD_LEAK",
                    })
        except Exception:
            pass

    async def run(self) -> List[Dict]:
        """Execute multi-cloud enumeration."""
        try:
            import aiohttp
        except ImportError:
            return []

        buckets = self._generate_permutations()
        logger.info(f"[CLOUD] Testing {len(buckets)} permutations across 3 providers")

        sem = asyncio.Semaphore(self.concurrency)

        async def bounded(coro):
            async with sem:
                await coro

        async with aiohttp.ClientSession() as session:
            tasks = []
            for b in buckets:
                tasks.append(bounded(self._check_s3(session, b)))
                tasks.append(bounded(self._check_azure(session, b)))
                tasks.append(bounded(self._check_gcp(session, b)))
            await asyncio.gather(*tasks)

        critical = [r for r in self.results if r["severity"] == "CRITICAL"]
        if critical:
            logger.warning(f"[CLOUD] Found {len(critical)} CRITICAL cloud exposures")
        return self.results
