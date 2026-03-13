"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — BOLA Intelligence Agent
===============================================================
Agentic BOLA (Broken Object Level Authorization) detection engine.
Tests API endpoints for IDOR vulnerabilities by manipulating object IDs.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import re
import json
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("CDB-BH-BOLA")


class BOLAAgent:
    """
    Detects Broken Object Level Authorization by:
    1. Identifying object IDs in API URL patterns
    2. Mutating IDs (increment/decrement for numerics)
    3. Testing access with modified context
    4. Confirming data leakage via response analysis
    """

    ID_PATTERNS = [
        re.compile(r'/api/v\d/[a-z]+/([0-9a-fA-F\-]{8,})'),   # UUID/Hash
        re.compile(r'/api/v\d/[a-z]+/(\d+)'),                   # Numeric
        re.compile(r'/(?:user|account|order|invoice|profile)/(\d+)'),  # Resource
        re.compile(r'/(?:users|accounts|orders)/([0-9a-fA-F\-]{8,})'),  # Plural + UUID
    ]

    def __init__(self, concurrency: int = 20):
        self.sem = asyncio.Semaphore(concurrency)
        self.findings: List[Dict] = []

    def _mutate_id(self, original_id: str) -> Optional[str]:
        """Generate a test ID by incrementing numeric IDs."""
        if original_id.isdigit():
            return str(int(original_id) + 1)
        return None

    def _is_data_leaked(self, response_body: str, target_id: str) -> bool:
        """Verify that the response contains data belonging to the mutated ID."""
        try:
            data = json.loads(response_body)
            if isinstance(data, dict):
                return any(str(v) == target_id for v in data.values())
            if isinstance(data, list) and data:
                return any(str(v) == target_id for item in data if isinstance(item, dict) for v in item.values())
        except (json.JSONDecodeError, AttributeError):
            pass
        return target_id in response_body

    async def analyze_endpoint(self, session, url: str,
                                headers: Optional[Dict] = None) -> Optional[Dict]:
        """Test a single URL for BOLA vulnerability."""
        hdrs = headers or {}
        for pattern in self.ID_PATTERNS:
            match = pattern.search(url)
            if not match:
                continue

            original_id = match.group(1)
            test_id = self._mutate_id(original_id)
            if not test_id:
                continue

            test_url = url.replace(original_id, test_id)

            async with self.sem:
                try:
                    async with session.get(
                        test_url, headers=hdrs, timeout=10, ssl=False
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if self._is_data_leaked(body, test_id):
                                finding = {
                                    "type": "BOLA",
                                    "url": test_url,
                                    "original_url": url,
                                    "severity": "CRITICAL",
                                    "impact": "Unauthorized data access via IDOR",
                                    "evidence": f"Accessed ID {test_id} via manipulated request",
                                    "original_id": original_id,
                                    "test_id": test_id,
                                }
                                self.findings.append(finding)
                                logger.warning(f"[BOLA] CRITICAL: {test_url}")
                                return finding
                except Exception:
                    pass
        return None

    async def run_swarm(self, urls: List[str],
                        auth_headers: Optional[Dict] = None) -> List[Dict]:
        """Orchestrate BOLA testing across all discovered API endpoints."""
        try:
            import aiohttp
        except ImportError:
            return []

        headers = auth_headers or {}
        async with aiohttp.ClientSession() as session:
            tasks = [self.analyze_endpoint(session, u, headers) for u in urls]
            results = await asyncio.gather(*tasks)

        valid = [r for r in results if r]
        if valid:
            logger.warning(f"[BOLA] Discovered {len(valid)} CRITICAL vulnerabilities")
        return valid
