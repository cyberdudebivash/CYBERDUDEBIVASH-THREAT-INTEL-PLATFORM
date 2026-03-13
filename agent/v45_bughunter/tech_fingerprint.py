"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Technology Fingerprinter
================================================================
Response-based technology identification via header and body signatures.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import logging
from typing import List, Dict

logger = logging.getLogger("CDB-BH-FINGERPRINT")

# ══════════════════════════════════════════════════════════════
# TECHNOLOGY SIGNATURE DATABASE
# ══════════════════════════════════════════════════════════════

SIGNATURES: Dict[str, Dict] = {
    "nginx": {"pattern": "nginx", "category": "web_server"},
    "apache": {"pattern": "Apache", "category": "web_server"},
    "iis": {"pattern": "Microsoft-IIS", "category": "web_server"},
    "cloudflare": {"pattern": "cloudflare", "category": "cdn"},
    "akamai": {"pattern": "AkamaiGHost", "category": "cdn"},
    "fastly": {"pattern": "Fastly", "category": "cdn"},
    "wordpress": {"pattern": "wp-content", "category": "cms"},
    "drupal": {"pattern": "Drupal", "category": "cms"},
    "joomla": {"pattern": "Joomla", "category": "cms"},
    "django": {"pattern": "csrfmiddlewaretoken", "category": "framework"},
    "flask": {"pattern": "Werkzeug", "category": "framework"},
    "express": {"pattern": "X-Powered-By: Express", "category": "framework"},
    "laravel": {"pattern": "laravel_session", "category": "framework"},
    "rails": {"pattern": "X-Request-Id", "category": "framework"},
    "react": {"pattern": "__NEXT_DATA__", "category": "frontend"},
    "angular": {"pattern": "ng-version", "category": "frontend"},
    "vue": {"pattern": "__vue__", "category": "frontend"},
    "aws_s3": {"pattern": "AmazonS3", "category": "cloud"},
    "aws_elb": {"pattern": "awselb", "category": "cloud"},
    "azure": {"pattern": "azure", "category": "cloud"},
    "gcp": {"pattern": "X-Cloud-Trace-Context", "category": "cloud"},
    "php": {"pattern": "X-Powered-By: PHP", "category": "language"},
    "asp_net": {"pattern": "X-AspNet-Version", "category": "language"},
    "java": {"pattern": "JSESSIONID", "category": "language"},
    "tomcat": {"pattern": "Apache-Coyote", "category": "web_server"},
    "varnish": {"pattern": "X-Varnish", "category": "cache"},
    "envoy": {"pattern": "x-envoy", "category": "proxy"},
}


class TechFingerprinter:
    """Identifies web technologies from HTTP response content and headers."""

    def __init__(self, custom_signatures: Dict = None):
        self.signatures = {**SIGNATURES}
        if custom_signatures:
            self.signatures.update(custom_signatures)

    def fingerprint(self, body: str, headers: Dict) -> List[Dict]:
        """Match signatures against response body + headers combined."""
        combined = body.lower() + " " + " ".join(
            f"{k}: {v}" for k, v in headers.items()
        ).lower()

        detected = []
        for tech_name, sig_info in self.signatures.items():
            if sig_info["pattern"].lower() in combined:
                detected.append({
                    "technology": tech_name,
                    "category": sig_info["category"],
                    "confidence": "HIGH" if sig_info["pattern"].lower() in combined[:2000] else "MEDIUM",
                })
        return detected

    async def fingerprint_url(self, url: str) -> List[Dict]:
        """Fetch a URL and fingerprint it."""
        try:
            import aiohttp
        except ImportError:
            return []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text(errors="ignore")
                    headers = dict(resp.headers)
                    return self.fingerprint(body, headers)
        except Exception as e:
            logger.debug(f"[FINGERPRINT] Error for {url}: {e}")
            return []

    def fingerprint_sync(self, body: str, headers: Dict) -> List[str]:
        """Synchronous convenience returning just technology names."""
        return [d["technology"] for d in self.fingerprint(body, headers)]


async def fingerprint_host(url: str) -> List[str]:
    """Top-level convenience wrapper returning tech name list."""
    fp = TechFingerprinter()
    results = await fp.fingerprint_url(url)
    return [r["technology"] for r in results]
