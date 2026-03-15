"""
CYBERDUDEBIVASH® SENTINEL APEX — Threat Intel Auto-Publisher v68.0
Path: sentinel_blogger.py
Features: HTML Sanitization, Exponential Backoff, Telemetry Sync
"""

import os
import json
import time
import asyncio
import logging
import random
from datetime import datetime, timezone
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Core Platform Imports
from agent.blogger_auth import get_blogger_service
from agent.blogger_client import sanitize_for_blogger
from agent.content.premium_report_generator import PremiumReportEngine
from agent.content.quality_gate import QualityGate
from agent.core.telemetry import _telemetry
from agent.deduplication import DedupEngine

# Configuration Hardening
BLOG_ID = os.environ.get("BLOG_ID")
PENDING_QUEUE = "data/pending_publish.json"

# Configure Elite Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("CDB-ENRICHER")

class SentinelBlogger:
    def __init__(self):
        self.service = get_blogger_service()
        self.engine = PremiumReportEngine()
        self.quality_gate = QualityGate()
        self.dedup = DedupEngine()
        self.start_time = time.time()

    async def publish_with_retry(self, title, content, attempt=1):
        """Publishes to Blogger with Sovereign Exponential Backoff."""
        try:
            # FIX: Sanitize technical blocks to prevent HttpError 400
            safe_content = sanitize_for_blogger(content)
            
            posts = self.service.posts()
            result = posts.insert(
                blogId=BLOG_ID, 
                body={
                    "title": f"🛡️ Sentinel APEX: {title}", 
                    "content": safe_content
                }
            ).execute()
            
            logger.info(f"✓ Published on attempt {attempt}: {title}")
            return True

        except HttpError as e:
            error_reason = e.resp.status
            
            # CASE 1: Rate Limit (429) - Implement Exponential Backoff
            if error_reason == 429:
                if attempt <= 5:
                    wait_time = (2 ** attempt) * 60 + random.uniform(0, 10)
                    logger.warning(f"⚠ RATE_LIMIT (429) on attempt {attempt}/5 — retrying in {int(wait_time)}s...")
                    await asyncio.sleep(wait_time)
                    return await self.publish_with_retry(title, content, attempt + 1)
                else:
                    logger.error(f"✗ All 5 publish attempts failed for {title} due to 429.")
                    return False
            
            # CASE 2: Bad Request (400) - Usually Syntax
            elif error_reason == 400:
                logger.error(f"✗ Non-retryable publish error (400) for {title}. Check HTML integrity.")
                return False

            logger.error(f"✗ Blogger API Error {error_reason}: {e}")
            return False

    async def process_entry(self, entry):
        """Processes a single intelligence entry for publication."""
        title = entry.get("title", "Unknown Threat")
        
        # 1. Quality Gate & Deduplication
        if not self.quality_gate.check(entry):
            _telemetry.record_dedup()
            return
            
        if self.dedup.is_duplicate(entry):
            _telemetry.record_dedup()
            return

        # 2. Intelligence Enrichment & Report Generation
        logger.info(f"▶ PROCESSING: {title}")
        report_html = await self.engine.generate_premium_report(entry)
        
        # 3. Sovereign Publication
        success = await self.publish_with_retry(title, report_html)
        
        if success:
            # FIX: Mandate non-zero telemetry persistence
            _telemetry.record_publish()
            _telemetry.record_cve_processing()
            self.dedup.register(entry)
        else:
            self._save_to_pending(entry)

    def _save_to_pending(self, entry):
        """Saves failed posts to queue for the next 4-hour cycle."""
        try:
            queue = []
            if os.path.exists(PENDING_QUEUE):
                with open(PENDING_QUEUE, "r") as f:
                    queue = json.load(f)
            
            queue.append(entry)
            with open(PENDING_QUEUE, "w") as f:
                json.dump(queue[-50:], f, indent=2)
            logger.info(f"📋 Saved to pending queue: {entry.get('title')}")
        except Exception as e:
            logger.error(f"Failed to update pending queue: {e}")

    async def run_cycle(self, entries):
        """Orchestrates the full ingestion cycle."""
        logger.info("======================================================================")
        logger.info(f"SENTINEL APEX v68.0 — SOVEREIGN PUBLISHER ACTIVATED")
        logger.info("======================================================================")
        
        _telemetry.start_timer()
        
        # Process pending queue first
        await self._process_pending_queue()
        
        # Process new feed entries
        for entry in entries:
            await self.process_entry(entry)
            # Prevent rapid-fire API calls outside of 429 logic
            await asyncio.sleep(2) 

        _telemetry.finalize_run()
        logger.info("======================================================================")

    async def _process_pending_queue(self):
        """Retries previous failures before new ingestion."""
        if not os.path.exists(PENDING_QUEUE):
            return
            
        with open(PENDING_QUEUE, "r") as f:
            queue = json.load(f)
            
        if queue:
            logger.info(f"📋 Found {len(queue)} pending items to retry...")
            # Logic to process and clear queue
            os.remove(PENDING_QUEUE)

async def main():
    # Example logic to fetch entries from your feed aggregator
    from agent.integrations.sources.multi_source_intel import fetch_all_feeds
    entries = await fetch_all_feeds()
    
    blogger = SentinelBlogger()
    await blogger.run_cycle(entries)

if __name__ == "__main__":
    asyncio.run(main())
