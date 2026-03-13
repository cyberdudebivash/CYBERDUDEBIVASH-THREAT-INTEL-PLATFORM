"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Subdomain Intelligence Engine
=====================================================================
Passive (Certificate Transparency) + Active (DNS Bruteforce) subdomain discovery.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import socket
import logging
from typing import List, Set, Optional

logger = logging.getLogger("CDB-BH-SUBDOMAIN")

CRT_SH_API = "https://crt.sh/?q=%25.{domain}&output=json"


class SubdomainEngine:
    """
    Dual-mode subdomain discovery:
      1. Passive: Certificate Transparency log scraping via crt.sh
      2. Active: Async DNS bruteforce with configurable wordlist + concurrency
    """

    def __init__(self, domain: str, wordlist_path: Optional[str] = None,
                 concurrency: int = 100):
        self.domain = domain.strip().lower()
        self.wordlist_path = wordlist_path
        self.concurrency = concurrency
        self.passive_results: Set[str] = set()
        self.active_results: Set[str] = set()

    async def fetch_ct_logs(self) -> Set[str]:
        """Query crt.sh Certificate Transparency API for passive discovery."""
        try:
            import aiohttp
        except ImportError:
            logger.warning("[CT] aiohttp not installed — skipping CT log fetch")
            return set()

        url = CRT_SH_API.format(domain=self.domain)
        logger.info(f"[CT] Fetching CT logs for {self.domain}")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        logger.warning(f"[CT] Non-200 response: {resp.status}")
                        return set()
                    data = await resp.json(content_type=None)
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub and self.domain in sub and "*" not in sub:
                                self.passive_results.add(sub)
        except Exception as e:
            logger.error(f"[CT] Fetch error: {e}")

        logger.info(f"[CT] Discovered {len(self.passive_results)} subdomains passively")
        return self.passive_results

    async def dns_bruteforce(self) -> Set[str]:
        """Active DNS resolution against a wordlist."""
        if not self.wordlist_path:
            logger.info("[DNS] No wordlist provided — skipping active bruteforce")
            return set()

        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"[DNS] Wordlist not found: {self.wordlist_path}")
            return set()

        sem = asyncio.Semaphore(self.concurrency)

        async def resolve(word: str):
            target = f"{word}.{self.domain}"
            async with sem:
                try:
                    loop = asyncio.get_event_loop()
                    result = await asyncio.wait_for(
                        loop.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM),
                        timeout=3.0
                    )
                    if result:
                        self.active_results.add(target)
                except (socket.gaierror, asyncio.TimeoutError, OSError):
                    pass

        logger.info(f"[DNS] Bruteforcing {len(words)} candidates for {self.domain}")
        tasks = [resolve(w) for w in words]
        await asyncio.gather(*tasks)
        logger.info(f"[DNS] Discovered {len(self.active_results)} subdomains actively")
        return self.active_results

    async def run(self) -> List[str]:
        """Execute full subdomain discovery pipeline."""
        await asyncio.gather(
            self.fetch_ct_logs(),
            self.dns_bruteforce(),
        )
        combined = self.passive_results | self.active_results
        logger.info(f"[SUBDOMAIN] Total unique subdomains: {len(combined)}")
        return sorted(combined)

    def run_sync(self) -> List[str]:
        """Synchronous wrapper for non-async contexts."""
        return asyncio.run(self.run())
