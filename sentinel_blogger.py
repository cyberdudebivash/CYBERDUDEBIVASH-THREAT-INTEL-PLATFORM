"""
CYBERDUDEBIVASH® SENTINEL APEX — Threat Intel Auto-Publisher v69.1
Path: sentinel_blogger.py
Features: Queue Sanitization Recovery, Exponential Backoff, Telemetry Sync
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
            # Apply v69.0+ Sanitization to technical blocks
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
            
            # CASE 2: Bad Request (400) - Syntax Rejection
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
            _telemetry.record_publish()
            _telemetry.record_cve_processing()
            self.dedup.register(entry)
        else:
            self._save_to_pending(entry, report_html)

    def _save_to_pending(self, entry, report_html):
        """Saves failed posts to queue for the next cycle."""
        try:
            queue = []
            if os.path.exists(PENDING_QUEUE):
                with open(PENDING_QUEUE, "r") as f:
                    queue = json.load(f)
            
            # Store HTML so sanitizer can fix it in the next recovery run
            entry["report_html"] = report_html
            queue.append(entry)
            
            with open(PENDING_QUEUE, "w") as f:
                json.dump(queue[-50:], f, indent=2)
            logger.info(f"📋 Saved to pending queue: {entry.get('title')}")
        except Exception as e:
            logger.error(f"Failed to update pending queue: {e}")

    # ===== PATCH START: v69.1 Recovery Logic =====
    async def _process_pending_queue(self):
        """Retries previous failures with v69.1 sanitization hardening applied."""
        if not os.path.exists(PENDING_QUEUE):
            return
            
        with open(PENDING_QUEUE, "r") as f:
            queue = json.load(f)
            
        if not queue:
            return

        logger.info(f"📋 SOVEREIGN RECOVERY: Hardening {len(queue)} pending queue items...")
        
        remaining_queue = []
        for entry in queue:
            title = entry.get("title", "Legacy Threat")
            report_html = entry.get("report_html", "")
            
            # CRITICAL FIX: Re-run sanitizer on old content to resolve 400 Syntax Errors
            safe_content = sanitize_for_blogger(report_html)
            
            try:
                posts = self.service.posts()
                posts.insert(
                    blogId=BLOG_ID, 
                    body={"title": f"🛡️ Sentinel APEX: {title}", "content": safe_content}
                ).execute()
                logger.info(f"✓ QUEUE RECOVERY SUCCESS: {title}")
                _telemetry.record_publish()
            except Exception as e:
                logger.error(f"✗ Recovery failed for {title}: {e}")
                remaining_queue.append(entry)
                
        if not remaining_queue:
            os.remove(PENDING_QUEUE)
        else:
            with open(PENDING_QUEUE, "w") as f:
                json.dump(remaining_queue, f, indent=2)
    # ===== PATCH END =====

    async def run_cycle(self, entries):
        """Orchestrates the full ingestion cycle."""
        logger.info("======================================================================")
        logger.info(f"SENTINEL APEX v69.1 — SOVEREIGN PUBLISHER ACTIVATED")
        logger.info("======================================================================")
        
        _telemetry.start_timer()
        
        # Step 1: Recover items trapped in previous 400/429 errors
        await self._process_pending_queue()
        
        # Step 2: Process new feed entries
        for entry in entries:
            await self.process_entry(entry)
            await asyncio.sleep(2) # Natural pacing

        _telemetry.finalize_run()
        logger.info("======================================================================")

async def main():
    # Dynamic ingestion from multi-source aggregator
    from agent.integrations.sources.multi_source_intel import fetch_all_feeds
    entries = await fetch_all_feeds()
    
    blogger = SentinelBlogger()
    await blogger.run_cycle(entries)

if __name__ == "__main__":
    asyncio.run(main())
