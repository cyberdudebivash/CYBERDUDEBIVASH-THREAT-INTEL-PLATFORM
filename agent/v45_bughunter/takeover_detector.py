"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Subdomain Takeover Detector
===================================================================
Detects potential subdomain takeover vulnerabilities via
DNS CNAME analysis + HTTP response fingerprint matching.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("CDB-BH-TAKEOVER")

TAKEOVER_FINGERPRINTS = {
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app", "no-such-app"],
    "Azure": ["The resource you are looking for has been removed"],
    "Fastly": ["Fastly error: unknown domain"],
    "CloudFront": ["The request could not be satisfied", "Bad request"],
    "Netlify": ["Not Found - Request ID"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Surge.sh": ["project not found"],
    "Tumblr": ["There's nothing here", "Whatever you were looking for"],
    "WordPress.com": ["Do you want to register"],
    "Pantheon": ["404 error unknown site"],
    "Unbounce": ["The requested URL was not found on this server"],
    "Bitbucket": ["Repository not found"],
}


class TakeoverDetector:
    """Identifies subdomain takeover opportunities through DNS + HTTP analysis."""

    def __init__(self, concurrency: int = 50):
        self.concurrency = concurrency
        self.sem = asyncio.Semaphore(concurrency)

    async def _resolve_cname(self, host: str) -> Optional[str]:
        """Attempt CNAME resolution via asyncio DNS."""
        try:
            import aiodns
            resolver = aiodns.DNSResolver()
            result = await resolver.query(host, "CNAME")
            return result[0].host if result else None
        except Exception:
            return None

    async def _fetch_body(self, session, url: str) -> str:
        try:
            async with session.get(url, timeout=8, ssl=False, allow_redirects=True) as resp:
                return await resp.text(errors="ignore")
        except Exception:
            return ""

    async def analyze_host(self, session, host: str) -> List[Dict]:
        """Check a single host for takeover indicators."""
        findings = []
        cname = await self._resolve_cname(host)

        for scheme in ("http", "https"):
            url = f"{scheme}://{host}"
            async with self.sem:
                body = await self._fetch_body(session, url)
                if not body:
                    continue

                for provider, fingerprints in TAKEOVER_FINGERPRINTS.items():
                    for fp in fingerprints:
                        if fp.lower() in body.lower():
                            findings.append({
                                "type": "SUBDOMAIN_TAKEOVER",
                                "host": host,
                                "provider": provider,
                                "cname": cname,
                                "url": url,
                                "indicator": fp,
                                "severity": "HIGH",
                            })
                            logger.warning(f"[TAKEOVER] {host} → {provider}")
                            break
        return findings

    async def run(self, hosts: List[str]) -> List[Dict]:
        try:
            import aiohttp
        except ImportError:
            return []

        results = []
        timeout_conf = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout_conf) as session:
            tasks = [self.analyze_host(session, h) for h in hosts]
            responses = await asyncio.gather(*tasks)
            for batch in responses:
                results.extend(batch)

        if results:
            logger.warning(f"[TAKEOVER] {len(results)} potential takeovers detected")
        return results


async def detect_takeovers(hosts: List[str], concurrency=50) -> List[Dict]:
    detector = TakeoverDetector(concurrency)
    return await detector.run(hosts)
