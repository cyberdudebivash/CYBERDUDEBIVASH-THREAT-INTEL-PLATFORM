"""
CYBERDUDEBIVASH® SENTINEL APEX v27.0 — Prometheus Metrics Exporter
===================================================================
Production-grade metrics for monitoring and alerting.

Metrics Exposed:
----------------
- cdb_sentinel_threats_total: Total threats processed
- cdb_sentinel_threats_by_severity: Threats by severity level
- cdb_sentinel_iocs_total: Total IOCs extracted
- cdb_sentinel_api_requests_total: API requests by endpoint/status
- cdb_sentinel_api_latency_seconds: API response latency histogram
- cdb_sentinel_queue_depth: Current queue depths
- cdb_sentinel_enrichment_requests_total: Enrichment API calls
- cdb_sentinel_enrichment_latency_seconds: Enrichment latency
- cdb_sentinel_sync_status: Last sync status (1=success, 0=fail)
- cdb_sentinel_sync_timestamp: Last successful sync timestamp
- cdb_sentinel_rules_generated_total: Detection rules generated
- cdb_sentinel_errors_total: Errors by type/module

Usage:
------
    from agent.v27.observability import get_metrics
    
    metrics = get_metrics()
    metrics.inc_threats(severity="critical")
    metrics.observe_api_latency("/api/v27/threats", 0.125)
    
    # Start metrics server
    metrics.start_server(port=9090)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import time
import logging
from typing import Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
import threading

logger = logging.getLogger("CDB-Metrics")

# Check if prometheus_client is available
try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary,
        start_http_server, REGISTRY, generate_latest
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client not installed, using fallback metrics")


class FallbackMetric:
    """Fallback metric when prometheus_client not available"""
    
    def __init__(self, name: str):
        self.name = name
        self._value = 0
        self._labels: Dict[str, float] = {}
    
    def inc(self, amount: float = 1):
        self._value += amount
    
    def dec(self, amount: float = 1):
        self._value -= amount
    
    def set(self, value: float):
        self._value = value
    
    def observe(self, value: float):
        self._value = value
    
    def labels(self, **kwargs) -> "FallbackMetric":
        key = str(kwargs)
        if key not in self._labels:
            self._labels[key] = 0
        return self
    
    def get_value(self) -> float:
        return self._value


class MetricsExporter:
    """
    Prometheus metrics exporter for SENTINEL APEX.
    
    Provides comprehensive metrics for:
    - Threat intelligence processing
    - API performance
    - Queue depths
    - Enrichment operations
    - Error tracking
    """
    
    PREFIX = "cdb_sentinel"
    
    def __init__(self):
        self._initialized = False
        self._server_started = False
        self._metrics: Dict[str, Any] = {}
        self._fallback_metrics: Dict[str, FallbackMetric] = {}
        
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize all metrics"""
        if PROMETHEUS_AVAILABLE:
            self._init_prometheus_metrics()
        else:
            self._init_fallback_metrics()
        
        self._initialized = True
    
    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        # Counters
        self._metrics["threats_total"] = Counter(
            f"{self.PREFIX}_threats_total",
            "Total threats processed",
            ["severity", "source"]
        )
        
        self._metrics["iocs_total"] = Counter(
            f"{self.PREFIX}_iocs_total",
            "Total IOCs extracted",
            ["type"]
        )
        
        self._metrics["api_requests_total"] = Counter(
            f"{self.PREFIX}_api_requests_total",
            "API requests by endpoint and status",
            ["endpoint", "method", "status"]
        )
        
        self._metrics["enrichment_requests_total"] = Counter(
            f"{self.PREFIX}_enrichment_requests_total",
            "Enrichment API calls",
            ["provider", "status"]
        )
        
        self._metrics["rules_generated_total"] = Counter(
            f"{self.PREFIX}_rules_generated_total",
            "Detection rules generated",
            ["type"]  # sigma, yara, kql, spl
        )
        
        self._metrics["errors_total"] = Counter(
            f"{self.PREFIX}_errors_total",
            "Errors by type and module",
            ["type", "module"]
        )
        
        # Gauges
        self._metrics["queue_depth"] = Gauge(
            f"{self.PREFIX}_queue_depth",
            "Current queue depth",
            ["queue"]
        )
        
        self._metrics["sync_status"] = Gauge(
            f"{self.PREFIX}_sync_status",
            "Last sync status (1=success, 0=fail)"
        )
        
        self._metrics["sync_timestamp"] = Gauge(
            f"{self.PREFIX}_sync_timestamp",
            "Last successful sync timestamp (unix)"
        )
        
        self._metrics["active_workers"] = Gauge(
            f"{self.PREFIX}_active_workers",
            "Number of active workers",
            ["type"]
        )
        
        self._metrics["threats_active"] = Gauge(
            f"{self.PREFIX}_threats_active",
            "Currently active threats by severity",
            ["severity"]
        )
        
        # Histograms
        self._metrics["api_latency_seconds"] = Histogram(
            f"{self.PREFIX}_api_latency_seconds",
            "API response latency",
            ["endpoint", "method"],
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        self._metrics["enrichment_latency_seconds"] = Histogram(
            f"{self.PREFIX}_enrichment_latency_seconds",
            "Enrichment API latency",
            ["provider"],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0]
        )
        
        self._metrics["processing_latency_seconds"] = Histogram(
            f"{self.PREFIX}_processing_latency_seconds",
            "Event processing latency",
            ["event_type"],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        
        # Summaries
        self._metrics["report_size_bytes"] = Summary(
            f"{self.PREFIX}_report_size_bytes",
            "Generated report sizes"
        )
    
    def _init_fallback_metrics(self):
        """Initialize fallback metrics when Prometheus not available"""
        metric_names = [
            "threats_total", "iocs_total", "api_requests_total",
            "enrichment_requests_total", "rules_generated_total",
            "errors_total", "queue_depth", "sync_status",
            "sync_timestamp", "active_workers", "threats_active",
            "api_latency_seconds", "enrichment_latency_seconds",
            "processing_latency_seconds", "report_size_bytes"
        ]
        
        for name in metric_names:
            self._fallback_metrics[name] = FallbackMetric(name)
            self._metrics[name] = self._fallback_metrics[name]
    
    # ══════════════════════════════════════════════════════════════════════════
    # THREAT METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def inc_threats(self, severity: str = "medium", source: str = "feed"):
        """Increment threat counter"""
        self._metrics["threats_total"].labels(
            severity=severity, source=source
        ).inc()
    
    def set_active_threats(self, severity: str, count: int):
        """Set active threat count by severity"""
        self._metrics["threats_active"].labels(severity=severity).set(count)
    
    def inc_iocs(self, ioc_type: str = "unknown", count: int = 1):
        """Increment IOC counter"""
        self._metrics["iocs_total"].labels(type=ioc_type).inc(count)
    
    # ══════════════════════════════════════════════════════════════════════════
    # API METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def inc_api_request(self, endpoint: str, method: str = "GET", status: int = 200):
        """Increment API request counter"""
        self._metrics["api_requests_total"].labels(
            endpoint=endpoint, method=method, status=str(status)
        ).inc()
    
    def observe_api_latency(self, endpoint: str, latency_seconds: float, method: str = "GET"):
        """Record API latency"""
        self._metrics["api_latency_seconds"].labels(
            endpoint=endpoint, method=method
        ).observe(latency_seconds)
    
    def track_api_request(self, endpoint: str, method: str = "GET"):
        """Decorator to track API requests"""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                start = time.time()
                status = 200
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    status = 500
                    raise
                finally:
                    latency = time.time() - start
                    self.inc_api_request(endpoint, method, status)
                    self.observe_api_latency(endpoint, latency, method)
            return wrapper
        return decorator
    
    # ══════════════════════════════════════════════════════════════════════════
    # ENRICHMENT METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def inc_enrichment(self, provider: str, success: bool = True):
        """Increment enrichment counter"""
        status = "success" if success else "failure"
        self._metrics["enrichment_requests_total"].labels(
            provider=provider, status=status
        ).inc()
    
    def observe_enrichment_latency(self, provider: str, latency_seconds: float):
        """Record enrichment latency"""
        self._metrics["enrichment_latency_seconds"].labels(
            provider=provider
        ).observe(latency_seconds)
    
    # ══════════════════════════════════════════════════════════════════════════
    # QUEUE METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def set_queue_depth(self, queue: str, depth: int):
        """Set current queue depth"""
        self._metrics["queue_depth"].labels(queue=queue).set(depth)
    
    def set_active_workers(self, worker_type: str, count: int):
        """Set active worker count"""
        self._metrics["active_workers"].labels(type=worker_type).set(count)
    
    # ══════════════════════════════════════════════════════════════════════════
    # SYNC METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def set_sync_status(self, success: bool):
        """Set sync status"""
        self._metrics["sync_status"].set(1 if success else 0)
        if success:
            self._metrics["sync_timestamp"].set(time.time())
    
    # ══════════════════════════════════════════════════════════════════════════
    # RULE GENERATION METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def inc_rules_generated(self, rule_type: str = "sigma"):
        """Increment rule generation counter"""
        self._metrics["rules_generated_total"].labels(type=rule_type).inc()
    
    # ══════════════════════════════════════════════════════════════════════════
    # ERROR METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def inc_error(self, error_type: str, module: str = "unknown"):
        """Increment error counter"""
        self._metrics["errors_total"].labels(
            type=error_type, module=module
        ).inc()
    
    # ══════════════════════════════════════════════════════════════════════════
    # PROCESSING METRICS
    # ══════════════════════════════════════════════════════════════════════════
    
    def observe_processing_latency(self, event_type: str, latency_seconds: float):
        """Record event processing latency"""
        self._metrics["processing_latency_seconds"].labels(
            event_type=event_type
        ).observe(latency_seconds)
    
    def observe_report_size(self, size_bytes: int):
        """Record report size"""
        self._metrics["report_size_bytes"].observe(size_bytes)
    
    # ══════════════════════════════════════════════════════════════════════════
    # SERVER
    # ══════════════════════════════════════════════════════════════════════════
    
    def start_server(self, port: int = 9090):
        """Start Prometheus metrics HTTP server"""
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus not available, metrics server not started")
            return
        
        if self._server_started:
            logger.warning("Metrics server already running")
            return
        
        try:
            start_http_server(port)
            self._server_started = True
            logger.info(f"Metrics server started on port {port}")
        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")
    
    def generate_metrics(self) -> str:
        """Generate metrics output (for custom HTTP handlers)"""
        if PROMETHEUS_AVAILABLE:
            return generate_latest(REGISTRY).decode("utf-8")
        else:
            # Generate text format for fallback metrics
            lines = []
            for name, metric in self._fallback_metrics.items():
                lines.append(f"{self.PREFIX}_{name} {metric.get_value()}")
            return "\n".join(lines)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current metric values as dict"""
        if not PROMETHEUS_AVAILABLE:
            return {
                name: metric.get_value()
                for name, metric in self._fallback_metrics.items()
            }
        
        # For Prometheus, return basic stats
        return {
            "prometheus_available": True,
            "server_started": self._server_started,
            "metrics_count": len(self._metrics),
        }


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
_metrics: Optional[MetricsExporter] = None


def get_metrics() -> MetricsExporter:
    """Get or create the global metrics exporter"""
    global _metrics
    if _metrics is None:
        _metrics = MetricsExporter()
    return _metrics


__all__ = ["MetricsExporter", "get_metrics", "PROMETHEUS_AVAILABLE"]
