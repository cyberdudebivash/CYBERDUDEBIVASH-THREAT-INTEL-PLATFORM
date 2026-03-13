"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — HTTP Probe Engine
=========================================================
High-speed async HTTP/HTTPS probing with title extraction,
header analysis, redirect detection, and response timing.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import re
import time
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("CDB-BH-PROBE")


class HTTPProbeEngine:
    """Async HTTP probing engine for discovered hosts."""

    def __init__(self, concurrency: int = 100, timeout: int = 10):
        self.concurrency = concurrency
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)

    @staticmethod
    def extract_title(html: str) -> str:
        try:
            match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ""
        except Exception:
            return ""

    async def probe_host(self, session, host: str) -> List[Dict]:
        """Probe a host over both HTTP and HTTPS."""
        results = []
        for scheme in ("http", "https"):
            url = f"{scheme}://{host}"
            async with self.sem:
                try:
                    start = time.time()
                    async with session.get(
                        url, allow_redirects=True, timeout=self.timeout, ssl=False
                    ) as resp:
                        elapsed = round(time.time() - start, 3)
                        body = await resp.text(errors="ignore")
                        headers = dict(resp.headers)
                        results.append({
                            "url": url,
                            "status": resp.status,
                            "title": self.extract_title(body),
                            "server": headers.get("Server"),
                            "content_length": headers.get("Content-Length"),
                            "redirect": headers.get("Location"),
                            "response_time": elapsed,
                        })
                except (asyncio.TimeoutError, Exception):
                    pass
        return results

    async def run(self, hosts: List[str]) -> List[Dict]:
        """Probe all hosts concurrently."""
        try:
            import aiohttp
        except ImportError:
            logger.error("[PROBE] aiohttp not installed")
            return []

        results = []
        timeout_config = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=0, ssl=False)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout_config) as session:
            tasks = [self.probe_host(session, h) for h in hosts]
            responses = await asyncio.gather(*tasks)
            for batch in responses:
                results.extend(batch)

        logger.info(f"[PROBE] Probed {len(hosts)} hosts → {len(results)} live endpoints")
        return results


async def probe_hosts(hosts: List[str], concurrency: int = 100) -> List[Dict]:
    """Convenience wrapper."""
    engine = HTTPProbeEngine(concurrency=concurrency)
    return await engine.run(hosts)
