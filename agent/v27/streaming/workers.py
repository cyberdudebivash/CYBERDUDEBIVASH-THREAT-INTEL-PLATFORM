"""
SENTINEL APEX v27.0 — Streaming Workers
========================================
Specialized workers for threat processing.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from .pipeline import StreamEvent, StreamingPipeline, Priority

logger = logging.getLogger("CDB-Workers")


class BaseWorker(ABC):
    """Base class for streaming workers"""
    
    def __init__(self, pipeline: StreamingPipeline, name: str = "worker"):
        self.pipeline = pipeline
        self.name = name
        self._running = False
        self._processed = 0
        self._errors = 0
    
    @abstractmethod
    async def process(self, event: StreamEvent) -> bool:
        """Process a single event"""
        pass
    
    async def start(self):
        """Start the worker"""
        self._running = True
        logger.info(f"Worker {self.name} started")
    
    async def stop(self):
        """Stop the worker"""
        self._running = False
        logger.info(f"Worker {self.name} stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "running": self._running,
            "processed": self._processed,
            "errors": self._errors,
        }


class ThreatWorker(BaseWorker):
    """
    Worker for processing threat intelligence events.
    
    Handles:
    - CVE ingestion
    - Advisory processing
    - IOC extraction
    """
    
    def __init__(self, pipeline: StreamingPipeline):
        super().__init__(pipeline, "threat-worker")
        self._ioc_extractor = None
        self._enricher = None
    
    async def process(self, event: StreamEvent) -> bool:
        """Process threat event"""
        try:
            payload = event.payload
            event_type = event.event_type
            
            if event_type == "cve":
                return await self._process_cve(payload)
            elif event_type == "advisory":
                return await self._process_advisory(payload)
            elif event_type == "ioc":
                return await self._process_ioc(payload)
            else:
                logger.warning(f"Unknown event type: {event_type}")
                return False
            
        except Exception as e:
            logger.error(f"Threat processing error: {e}")
            self._errors += 1
            return False
    
    async def _process_cve(self, payload: Dict) -> bool:
        """Process CVE event"""
        cve_id = payload.get("cve_id")
        if not cve_id:
            return False
        
        logger.info(f"Processing CVE: {cve_id}")
        
        # Extract IOCs from description
        description = payload.get("description", "")
        
        # Enrich with EPSS/KEV data
        # (Integration with existing enricher_pro.py)
        
        self._processed += 1
        return True
    
    async def _process_advisory(self, payload: Dict) -> bool:
        """Process threat advisory"""
        advisory_id = payload.get("id")
        logger.info(f"Processing advisory: {advisory_id}")
        
        self._processed += 1
        return True
    
    async def _process_ioc(self, payload: Dict) -> bool:
        """Process individual IOC"""
        ioc_value = payload.get("value")
        ioc_type = payload.get("type")
        
        logger.info(f"Processing IOC: {ioc_type}={ioc_value}")
        
        self._processed += 1
        return True


class EnrichmentWorker(BaseWorker):
    """
    Worker for enriching threat data.
    
    Handles:
    - EPSS enrichment
    - MITRE ATT&CK mapping
    - Threat actor attribution
    - Geo/industry targeting
    """
    
    def __init__(self, pipeline: StreamingPipeline):
        super().__init__(pipeline, "enrichment-worker")
    
    async def process(self, event: StreamEvent) -> bool:
        """Process enrichment event"""
        try:
            payload = event.payload
            
            # Enrich with EPSS
            if "cve_id" in payload:
                await self._enrich_epss(payload)
            
            # Map MITRE techniques
            if "description" in payload or "content" in payload:
                await self._map_mitre(payload)
            
            # Attribute threat actors
            if "indicators" in payload:
                await self._attribute_actors(payload)
            
            self._processed += 1
            return True
            
        except Exception as e:
            logger.error(f"Enrichment error: {e}")
            self._errors += 1
            return False
    
    async def _enrich_epss(self, payload: Dict) -> None:
        """Add EPSS scores"""
        # Integration with existing enricher_pro.py
        pass
    
    async def _map_mitre(self, payload: Dict) -> None:
        """Map to MITRE ATT&CK"""
        # Integration with existing mitre_mapper.py
        pass
    
    async def _attribute_actors(self, payload: Dict) -> None:
        """Attribute to threat actors"""
        # Integration with existing threat_actor module
        pass


class RuleGenerationWorker(BaseWorker):
    """
    Worker for auto-generating detection rules.
    
    Handles:
    - Sigma rule generation
    - YARA rule generation
    - KQL/SPL query generation
    """
    
    def __init__(self, pipeline: StreamingPipeline):
        super().__init__(pipeline, "rule-gen-worker")
    
    async def process(self, event: StreamEvent) -> bool:
        """Generate detection rules from event"""
        try:
            payload = event.payload
            rule_type = event.payload.get("rule_type", "sigma")
            
            if rule_type == "sigma":
                await self._generate_sigma(payload)
            elif rule_type == "yara":
                await self._generate_yara(payload)
            elif rule_type == "kql":
                await self._generate_kql(payload)
            elif rule_type == "spl":
                await self._generate_spl(payload)
            
            self._processed += 1
            return True
            
        except Exception as e:
            logger.error(f"Rule generation error: {e}")
            self._errors += 1
            return False
    
    async def _generate_sigma(self, payload: Dict) -> Optional[str]:
        """Generate Sigma rule"""
        # Delegated to auto_rules module
        pass
    
    async def _generate_yara(self, payload: Dict) -> Optional[str]:
        """Generate YARA rule"""
        pass
    
    async def _generate_kql(self, payload: Dict) -> Optional[str]:
        """Generate KQL query"""
        pass
    
    async def _generate_spl(self, payload: Dict) -> Optional[str]:
        """Generate Splunk SPL query"""
        pass


class WorkerPool:
    """
    Manages a pool of workers for parallel processing.
    """
    
    def __init__(self, pipeline: StreamingPipeline, worker_count: int = 4):
        self.pipeline = pipeline
        self.worker_count = worker_count
        self.workers: List[BaseWorker] = []
        self._tasks: List[asyncio.Task] = []
    
    def add_worker(self, worker: BaseWorker):
        """Add a worker to the pool"""
        self.workers.append(worker)
    
    async def start_all(self):
        """Start all workers"""
        for worker in self.workers:
            await worker.start()
            task = asyncio.create_task(self._run_worker(worker))
            self._tasks.append(task)
        
        logger.info(f"Started {len(self.workers)} workers")
    
    async def stop_all(self):
        """Stop all workers gracefully"""
        for worker in self.workers:
            await worker.stop()
        
        for task in self._tasks:
            task.cancel()
        
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("All workers stopped")
    
    async def _run_worker(self, worker: BaseWorker):
        """Run worker loop"""
        while worker._running:
            try:
                # Process from pipeline using registered handler
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        return {
            "total_workers": len(self.workers),
            "workers": [w.get_stats() for w in self.workers],
        }


__all__ = [
    "BaseWorker",
    "ThreatWorker",
    "EnrichmentWorker",
    "RuleGenerationWorker",
    "WorkerPool",
]
