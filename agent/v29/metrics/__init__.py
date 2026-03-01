"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — Prometheus Metrics
==========================================================
Enterprise-grade /metrics endpoint with Prometheus format.

Metrics Exposed:
- sentinel_threats_total (Counter)
- sentinel_iocs_extracted (Counter)
- sentinel_risk_score (Gauge)
- sentinel_api_requests (Counter)
- sentinel_api_latency (Histogram)
- sentinel_enrichment_duration (Histogram)
- sentinel_stix_bundles_generated (Counter)
- sentinel_feed_sync_duration (Histogram)
- sentinel_active_connections (Gauge)
- sentinel_queue_depth (Gauge)
- sentinel_dlq_messages (Gauge)

SLA Metrics:
- sentinel_uptime_seconds (Counter)
- sentinel_availability_ratio (Gauge)
- sentinel_sla_violations (Counter)
- sentinel_mttr_seconds (Histogram)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import time
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# METRIC TYPES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MetricValue:
    """Generic metric value with labels"""
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class Counter:
    """Monotonically increasing counter"""
    
    def __init__(self, name: str, description: str, labels: List[str] = None):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def inc(self, value: float = 1.0, **labels):
        """Increment counter"""
        label_key = tuple(sorted(labels.items()))
        with self._lock:
            self._values[label_key] += value
    
    def get(self, **labels) -> float:
        """Get counter value"""
        label_key = tuple(sorted(labels.items()))
        return self._values.get(label_key, 0.0)
    
    def to_prometheus(self) -> str:
        """Export to Prometheus format"""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} counter",
        ]
        for label_key, value in self._values.items():
            if label_key:
                labels_str = ",".join(f'{k}="{v}"' for k, v in label_key)
                lines.append(f"{self.name}{{{labels_str}}} {value}")
            else:
                lines.append(f"{self.name} {value}")
        return "\n".join(lines)


class Gauge:
    """Value that can go up and down"""
    
    def __init__(self, name: str, description: str, labels: List[str] = None):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self._values: Dict[tuple, float] = {}
        self._lock = threading.Lock()
    
    def set(self, value: float, **labels):
        """Set gauge value"""
        label_key = tuple(sorted(labels.items()))
        with self._lock:
            self._values[label_key] = value
    
    def inc(self, value: float = 1.0, **labels):
        """Increment gauge"""
        label_key = tuple(sorted(labels.items()))
        with self._lock:
            self._values[label_key] = self._values.get(label_key, 0.0) + value
    
    def dec(self, value: float = 1.0, **labels):
        """Decrement gauge"""
        self.inc(-value, **labels)
    
    def get(self, **labels) -> float:
        """Get gauge value"""
        label_key = tuple(sorted(labels.items()))
        return self._values.get(label_key, 0.0)
    
    def to_prometheus(self) -> str:
        """Export to Prometheus format"""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} gauge",
        ]
        for label_key, value in self._values.items():
            if label_key:
                labels_str = ",".join(f'{k}="{v}"' for k, v in label_key)
                lines.append(f"{self.name}{{{labels_str}}} {value}")
            else:
                lines.append(f"{self.name} {value}")
        return "\n".join(lines)


class Histogram:
    """Distribution of values"""
    
    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))
    
    def __init__(self, name: str, description: str, labels: List[str] = None, buckets: tuple = None):
        self.name = name
        self.description = description
        self.label_names = labels or []
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self._observations: Dict[tuple, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def observe(self, value: float, **labels):
        """Record observation"""
        label_key = tuple(sorted(labels.items()))
        with self._lock:
            self._observations[label_key].append(value)
    
    def time(self, **labels):
        """Context manager for timing"""
        return HistogramTimer(self, labels)
    
    def to_prometheus(self) -> str:
        """Export to Prometheus format"""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} histogram",
        ]
        
        for label_key, observations in self._observations.items():
            labels_str = ",".join(f'{k}="{v}"' for k, v in label_key) if label_key else ""
            
            # Calculate bucket counts
            for bucket in self.buckets:
                count = sum(1 for o in observations if o <= bucket)
                bucket_label = f'le="{bucket}"' if bucket != float("inf") else 'le="+Inf"'
                if labels_str:
                    lines.append(f"{self.name}_bucket{{{labels_str},{bucket_label}}} {count}")
                else:
                    lines.append(f"{self.name}_bucket{{{bucket_label}}} {count}")
            
            # Sum and count
            total = sum(observations)
            count = len(observations)
            if labels_str:
                lines.append(f"{self.name}_sum{{{labels_str}}} {total}")
                lines.append(f"{self.name}_count{{{labels_str}}} {count}")
            else:
                lines.append(f"{self.name}_sum {total}")
                lines.append(f"{self.name}_count {count}")
        
        return "\n".join(lines)


class HistogramTimer:
    """Context manager for histogram timing"""
    
    def __init__(self, histogram: Histogram, labels: dict):
        self.histogram = histogram
        self.labels = labels
        self.start = None
    
    def __enter__(self):
        self.start = time.time()
        return self
    
    def __exit__(self, *args):
        duration = time.time() - self.start
        self.histogram.observe(duration, **self.labels)


# ══════════════════════════════════════════════════════════════════════════════
# PROMETHEUS EXPORTER
# ══════════════════════════════════════════════════════════════════════════════

class PrometheusExporter:
    """
    Prometheus metrics exporter for SENTINEL APEX.
    Exposes all platform metrics in Prometheus format.
    """
    
    def __init__(self):
        self._start_time = time.time()
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize all metrics"""
        
        # ─── THREAT INTELLIGENCE METRICS ──────────────────────────────────
        self.threats_total = Counter(
            "sentinel_threats_total",
            "Total number of threats processed",
            ["severity", "source"]
        )
        
        self.iocs_extracted = Counter(
            "sentinel_iocs_extracted",
            "Total IOCs extracted",
            ["type"]  # ip, domain, hash, url, email
        )
        
        self.risk_score = Gauge(
            "sentinel_risk_score",
            "Current average risk score",
            ["category"]
        )
        
        self.stix_bundles = Counter(
            "sentinel_stix_bundles_generated",
            "Total STIX bundles generated",
            ["type"]
        )
        
        # ─── API METRICS ──────────────────────────────────────────────────
        self.api_requests = Counter(
            "sentinel_api_requests_total",
            "Total API requests",
            ["method", "endpoint", "status"]
        )
        
        self.api_latency = Histogram(
            "sentinel_api_request_duration_seconds",
            "API request latency",
            ["method", "endpoint"],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )
        
        self.active_connections = Gauge(
            "sentinel_active_connections",
            "Number of active API connections",
            []
        )
        
        # ─── ENRICHMENT METRICS ───────────────────────────────────────────
        self.enrichment_duration = Histogram(
            "sentinel_enrichment_duration_seconds",
            "Enrichment processing time",
            ["source"],  # virustotal, shodan, misp, etc.
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
        )
        
        self.enrichment_errors = Counter(
            "sentinel_enrichment_errors_total",
            "Enrichment errors",
            ["source", "error_type"]
        )
        
        # ─── FEED SYNC METRICS ────────────────────────────────────────────
        self.feed_sync_duration = Histogram(
            "sentinel_feed_sync_duration_seconds",
            "Feed synchronization time",
            ["feed"],
            buckets=(1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0)
        )
        
        self.feed_items_processed = Counter(
            "sentinel_feed_items_processed_total",
            "Feed items processed",
            ["feed", "status"]
        )
        
        # ─── QUEUE METRICS ────────────────────────────────────────────────
        self.queue_depth = Gauge(
            "sentinel_queue_depth",
            "Current queue depth",
            ["queue"]
        )
        
        self.dlq_messages = Gauge(
            "sentinel_dlq_messages",
            "Messages in dead letter queue",
            ["queue"]
        )
        
        # ─── SLA METRICS ──────────────────────────────────────────────────
        self.uptime_seconds = Counter(
            "sentinel_uptime_seconds",
            "Platform uptime in seconds",
            []
        )
        
        self.availability_ratio = Gauge(
            "sentinel_availability_ratio",
            "Platform availability (0-1)",
            []
        )
        
        self.sla_violations = Counter(
            "sentinel_sla_violations_total",
            "SLA violations",
            ["type"]  # latency, availability, error_rate
        )
        
        self.mttr_seconds = Histogram(
            "sentinel_mttr_seconds",
            "Mean time to recovery",
            [],
            buckets=(60, 300, 600, 1800, 3600, 7200, 14400)
        )
        
        # ─── ML METRICS ───────────────────────────────────────────────────
        self.model_predictions = Counter(
            "sentinel_model_predictions_total",
            "ML model predictions",
            ["model", "result"]
        )
        
        self.model_inference_time = Histogram(
            "sentinel_model_inference_seconds",
            "ML model inference time",
            ["model"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5)
        )
        
        # ─── INFO METRICS ─────────────────────────────────────────────────
        self.build_info = Gauge(
            "sentinel_build_info",
            "Build information",
            ["version", "codename"]
        )
        self.build_info.set(1, version="29.0.0", codename="APEX_SCALE")
    
    def record_threat(self, severity: str, source: str, count: int = 1):
        """Record threat processed"""
        self.threats_total.inc(count, severity=severity, source=source)
    
    def record_ioc(self, ioc_type: str, count: int = 1):
        """Record IOC extraction"""
        self.iocs_extracted.inc(count, type=ioc_type)
    
    def record_api_request(self, method: str, endpoint: str, status: int, duration: float):
        """Record API request"""
        self.api_requests.inc(method=method, endpoint=endpoint, status=str(status))
        self.api_latency.observe(duration, method=method, endpoint=endpoint)
    
    def record_enrichment(self, source: str, duration: float, success: bool = True):
        """Record enrichment operation"""
        self.enrichment_duration.observe(duration, source=source)
        if not success:
            self.enrichment_errors.inc(source=source, error_type="failure")
    
    def record_feed_sync(self, feed: str, duration: float, items: int, success: bool = True):
        """Record feed sync"""
        self.feed_sync_duration.observe(duration, feed=feed)
        status = "success" if success else "failure"
        self.feed_items_processed.inc(items, feed=feed, status=status)
    
    def set_queue_depth(self, queue: str, depth: int):
        """Set queue depth"""
        self.queue_depth.set(depth, queue=queue)
    
    def set_dlq_count(self, queue: str, count: int):
        """Set DLQ count"""
        self.dlq_messages.set(count, queue=queue)
    
    def update_uptime(self):
        """Update uptime counter"""
        uptime = time.time() - self._start_time
        self.uptime_seconds.inc(uptime)
    
    def export(self) -> str:
        """Export all metrics in Prometheus format"""
        metrics = [
            self.threats_total,
            self.iocs_extracted,
            self.risk_score,
            self.stix_bundles,
            self.api_requests,
            self.api_latency,
            self.active_connections,
            self.enrichment_duration,
            self.enrichment_errors,
            self.feed_sync_duration,
            self.feed_items_processed,
            self.queue_depth,
            self.dlq_messages,
            self.uptime_seconds,
            self.availability_ratio,
            self.sla_violations,
            self.mttr_seconds,
            self.model_predictions,
            self.model_inference_time,
            self.build_info,
        ]
        
        output = []
        for metric in metrics:
            output.append(metric.to_prometheus())
            output.append("")
        
        return "\n".join(output)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary as dict"""
        return {
            "uptime_seconds": time.time() - self._start_time,
            "threats_total": sum(self.threats_total._values.values()),
            "iocs_extracted": sum(self.iocs_extracted._values.values()),
            "api_requests": sum(self.api_requests._values.values()),
            "stix_bundles": sum(self.stix_bundles._values.values()),
        }


# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

def create_metrics_router():
    """Create FastAPI router for /metrics endpoint"""
    try:
        from fastapi import APIRouter, Response
        from fastapi.responses import PlainTextResponse
        
        router = APIRouter(tags=["Metrics"])
        exporter = get_exporter()
        
        @router.get("/metrics", response_class=PlainTextResponse)
        async def metrics():
            """Prometheus metrics endpoint"""
            return Response(
                content=exporter.export(),
                media_type="text/plain; version=0.0.4; charset=utf-8"
            )
        
        @router.get("/metrics/summary")
        async def metrics_summary():
            """Metrics summary in JSON"""
            return exporter.get_summary()
        
        return router
    
    except ImportError:
        logger.warning("FastAPI not installed - metrics router unavailable")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════

class MetricsMiddleware:
    """FastAPI middleware for automatic metrics collection"""
    
    def __init__(self, app, exporter: Optional[PrometheusExporter] = None):
        self.app = app
        self.exporter = exporter or get_exporter()
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        start_time = time.time()
        
        # Track connection
        self.exporter.active_connections.inc()
        
        # Process request
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                duration = time.time() - start_time
                method = scope.get("method", "GET")
                path = scope.get("path", "/")
                status = message.get("status", 200)
                
                self.exporter.record_api_request(method, path, status, duration)
                self.exporter.active_connections.dec()
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

_exporter_instance: Optional[PrometheusExporter] = None


def get_exporter() -> PrometheusExporter:
    """Get metrics exporter singleton"""
    global _exporter_instance
    if _exporter_instance is None:
        _exporter_instance = PrometheusExporter()
    return _exporter_instance


__all__ = [
    "Counter",
    "Gauge",
    "Histogram",
    "PrometheusExporter",
    "MetricsMiddleware",
    "create_metrics_router",
    "get_exporter",
]
