"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — JavaScript Endpoint Extractor
=====================================================================
Discovers JS files from pages, extracts API endpoints, URLs, paths,
and detects hardcoded tokens/keys (AWS, GCP, Stripe).

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import re
import logging
from typing import List, Dict, Set
from urllib.parse import urljoin

logger = logging.getLogger("CDB-BH-JSEXTRACT")

# ══════════════════════════════════════════════════════════════
# REGEX PATTERNS
# ══════════════════════════════════════════════════════════════

ENDPOINT_RE = re.compile(
    r"""(?:"|')((?:https?://[^\s"']+)|(?:/[a-zA-Z0-9_\-/.]+))(?:"|')""",
    re.VERBOSE,
)

API_RE = re.compile(r"""(?:"|')(/api/[a-zA-Z0-9_\-/.]+)(?:"|')""", re.VERBOSE)

TOKEN_RE = re.compile(
    r"""(?:"|')("""
    r"(?:AKIA[0-9A-Z]{16})"       # AWS Access Key
    r"|(?:AIza[0-9A-Za-z\-_]{35})" # Google API Key
    r"|(?:sk_live_[0-9a-zA-Z]{24})" # Stripe Live Key
    r"|(?:ghp_[0-9a-zA-Z]{36})"    # GitHub PAT
    r"|(?:xox[bprs]-[0-9a-zA-Z\-]{10,})" # Slack Token
    r""")(?:"|')""",
    re.VERBOSE,
)

JS_FILE_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


class JSEndpointExtractor:
    """Extracts endpoints and secrets from JavaScript files discovered on pages."""

    def __init__(self, concurrency: int = 50, timeout: int = 10):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def _fetch(self, session, url: str) -> str:
        try:
            async with self.sem:
                async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                    return await resp.text(errors="ignore")
        except Exception:
            return ""

    def discover_js_files(self, html: str, base_url: str) -> List[str]:
        """Find all <script src="..."> references in HTML."""
        matches = JS_FILE_RE.findall(html)
        return list({urljoin(base_url, m) for m in matches})

    def extract_endpoints(self, js_content: str) -> List[str]:
        endpoints: Set[str] = set()
        endpoints.update(ENDPOINT_RE.findall(js_content))
        endpoints.update(API_RE.findall(js_content))
        # Filter noise: skip common framework paths
        return [
            ep for ep in endpoints
            if not any(skip in ep.lower() for skip in [
                ".png", ".jpg", ".gif", ".css", ".svg", "font", "polyfill"
            ])
        ]

    def extract_tokens(self, js_content: str) -> List[Dict]:
        """Detect hardcoded secrets/API keys."""
        findings = []
        for match in TOKEN_RE.findall(js_content):
            token_type = "UNKNOWN"
            if match.startswith("AKIA"):
                token_type = "AWS_ACCESS_KEY"
            elif match.startswith("AIza"):
                token_type = "GOOGLE_API_KEY"
            elif match.startswith("sk_live"):
                token_type = "STRIPE_LIVE_KEY"
            elif match.startswith("ghp_"):
                token_type = "GITHUB_PAT"
            elif match.startswith("xox"):
                token_type = "SLACK_TOKEN"
            findings.append({"token_type": token_type, "prefix": match[:12] + "..."})
        return findings

    async def analyze_host(self, session, url: str) -> Dict:
        result = {
            "host": url,
            "javascript_files": [],
            "endpoints": [],
            "secrets": [],
        }

        html = await self._fetch(session, url)
        if not html:
            return result

        js_files = self.discover_js_files(html, url)
        result["javascript_files"] = js_files

        js_contents = await asyncio.gather(*[self._fetch(session, js) for js in js_files])

        all_endpoints: Set[str] = set()
        all_secrets: List[Dict] = []

        for js_content in js_contents:
            if js_content:
                all_endpoints.update(self.extract_endpoints(js_content))
                all_secrets.extend(self.extract_tokens(js_content))

        result["endpoints"] = sorted(all_endpoints)
        result["secrets"] = all_secrets

        if result["endpoints"]:
            logger.info(f"[JS] {url} → {len(result['endpoints'])} endpoints")
        if result["secrets"]:
            logger.warning(f"[JS] {url} → {len(result['secrets'])} SECRETS DETECTED")

        return result

    async def run(self, urls: List[str]) -> List[Dict]:
        try:
            import aiohttp
        except ImportError:
            return []

        results = []
        timeout_conf = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout_conf) as session:
            tasks = [self.analyze_host(session, u) for u in urls]
            results = await asyncio.gather(*tasks)
        return list(results)


async def extract_js_endpoints(urls: List[str]) -> List[str]:
    """Convenience: returns flat list of all discovered API endpoints."""
    extractor = JSEndpointExtractor()
    results = await extractor.run(urls)
    all_eps = []
    for r in results:
        all_eps.extend(r.get("endpoints", []))
    return list(set(all_eps))
