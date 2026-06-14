"""
CYBERDUDEBIVASH® SENTINEL APEX — Webhook Registry & Delivery Engine
P0 Fix #7: API Economy Maturity — Webhook Ecosystem

Provides:
  - WebhookSubscription registration and lifecycle management
  - 14 event type catalog with TLP-gated delivery
  - HMAC-SHA256 payload signing
  - Exponential backoff retry (up to 72h window)
  - Delivery audit trail (JSONL)
  - Quota-aware event throttling
  - Dead letter queue management
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional
import threading

logger = logging.getLogger("sentinel.webhook_registry")

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

WEBHOOK_EVENT_CATALOG = {
    "advisory.created":           "New advisory published to the intelligence feed",
    "advisory.updated":           "Advisory risk score, TTPs, or confidence updated",
    "advisory.kev_promoted":      "Advisory added to CISA KEV catalog — auto-elevated to HIGH",
    "ioc.new_malicious":          "New high-confidence malicious IOC observed in telemetry",
    "ioc.verdict_changed":        "IOC verdict changed (benign→malicious or vice versa)",
    "telemetry.honeynet_hit":     "Honeynet sensor triggered — new actor observation recorded",
    "telemetry.deception_triggered": "Deception trap activated — actor interaction recorded",
    "actor.cluster_new":          "New actor cluster formed in the global threat graph",
    "actor.cluster_updated":      "Existing actor cluster merged, expanded, or re-attributed",
    "quota.warning":              "API quota at 75% or 90% utilization — action recommended",
    "quota.exceeded":             "API quota exceeded — requests being throttled or rejected",
    "feed.source_degraded":       "Feed source latency >5s or returning error responses",
    "auth.key_rotated":           "API key rotated successfully — old key entering grace period",
    "graph.campaign_detected":    "Multi-tenant correlated campaign pattern detected",
}

TLP_DELIVERY_RULES = {
    "WHITE":  ["*"],              # Any subscriber
    "GREEN":  ["professional", "enterprise"],
    "AMBER":  ["enterprise", "mssp"],
    "RED":    ["mssp"],           # MSSP-only controlled delivery
}

RETRY_SCHEDULE_SECONDS = [10, 30, 120, 600, 1800, 7200, 14400, 28800]
MAX_DELIVERY_WINDOW_HOURS = 72
SIGNATURE_ALGORITHM = "sha256"
DELIVERY_LOG_PATH = Path("data/api/webhook_deliveries.jsonl")
SUBSCRIPTION_STORE_PATH = Path("data/api/webhook_subscriptions.json")
DLQ_PATH = Path("data/api/webhook_dlq.jsonl")


# ─────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────

class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    FAILED = "failed"         # Too many consecutive failures
    SUSPENDED = "suspended"   # Admin-suspended


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    RETRYING = "retrying"
    FAILED = "failed"
    DLQ = "dlq"               # Dead letter queue


@dataclass
class WebhookSubscription:
    """Represents a registered webhook endpoint with delivery configuration."""
    subscription_id: str
    tenant_id: str
    api_key_prefix: str
    endpoint_url: str
    secret: str                           # HMAC signing secret (stored hashed in prod)
    events: list[str]                     # List of subscribed event types
    plan_tier: str                        # starter, professional, enterprise, mssp
    created_at: str
    status: str = SubscriptionStatus.ACTIVE
    tls_verify: bool = True
    custom_headers: dict = field(default_factory=dict)
    filter_expression: Optional[str] = None   # JSONPath filter on payload
    delivery_timeout_s: int = 10
    consecutive_failures: int = 0
    last_success_at: Optional[str] = None
    total_delivered: int = 0
    total_failed: int = 0

    def is_eligible_for_event(self, event_type: str, tlp: str = "WHITE") -> bool:
        if self.status != SubscriptionStatus.ACTIVE:
            return False
        if event_type not in self.events and "*" not in self.events:
            return False
        allowed_tiers = TLP_DELIVERY_RULES.get(tlp, ["enterprise"])
        if "*" not in allowed_tiers and self.plan_tier not in allowed_tiers:
            return False
        return True

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("secret", None)   # Never serialize the raw secret
        return d


@dataclass
class WebhookEvent:
    """A fired event ready for delivery."""
    event_id: str
    event_type: str
    source: str
    tlp: str
    payload: dict
    fired_at: str
    tenant_scope: Optional[str] = None   # None = global, tenantId = scoped

    def to_signed_payload(self, secret: str) -> tuple[bytes, str]:
        """Returns (body_bytes, signature_header_value)."""
        body = json.dumps({
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "tlp": self.tlp,
            "fired_at": self.fired_at,
            "data": self.payload,
        }, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        return body, f"sha256={signature}"


@dataclass
class DeliveryAttempt:
    """Tracks a single delivery attempt."""
    attempt_id: str
    event_id: str
    subscription_id: str
    attempted_at: str
    status: str
    http_status: Optional[int] = None
    response_ms: Optional[int] = None
    error_message: Optional[str] = None
    attempt_number: int = 1
    next_retry_at: Optional[str] = None


@dataclass
class WebhookQuotaRecord:
    """Per-tenant webhook delivery quota tracking."""
    tenant_id: str
    events_per_hour: int
    events_delivered_this_hour: int = 0
    window_start: str = field(default_factory=lambda: _utcnow())
    throttled_count: int = 0


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def _event_id() -> str:
    return f"evt_{uuid.uuid4().hex[:16]}"

def _attempt_id() -> str:
    return f"atm_{uuid.uuid4().hex[:12]}"

def _sub_id() -> str:
    return f"whk_{uuid.uuid4().hex[:16]}"


# ─────────────────────────────────────────────────────────────
# QUOTA GOVERNOR
# ─────────────────────────────────────────────────────────────

PLAN_WEBHOOK_QUOTAS = {
    "starter":      0,        # No webhooks on starter
    "professional": 10_000,   # 10K events/hour
    "enterprise":   100_000,  # 100K events/hour
    "mssp":         500_000,  # 500K events/hour
}

class WebhookQuotaGovernor:
    """Thread-safe per-tenant quota enforcement."""

    def __init__(self):
        self._records: dict[str, WebhookQuotaRecord] = {}
        self._lock = threading.Lock()

    def check_and_consume(self, tenant_id: str, plan_tier: str) -> tuple[bool, str]:
        """Returns (allowed, reason)."""
        with self._lock:
            quota = PLAN_WEBHOOK_QUOTAS.get(plan_tier, 0)
            if quota == 0:
                return False, f"Plan '{plan_tier}' does not include webhook delivery"

            rec = self._records.get(tenant_id)
            now = time.time()

            if rec is None:
                rec = WebhookQuotaRecord(
                    tenant_id=tenant_id,
                    events_per_hour=quota,
                    window_start=_utcnow()
                )
                self._records[tenant_id] = rec

            # Reset window if >1 hour passed
            window_start_ts = datetime.fromisoformat(rec.window_start).timestamp()
            if now - window_start_ts > 3600:
                rec.events_delivered_this_hour = 0
                rec.window_start = _utcnow()

            if rec.events_delivered_this_hour >= rec.events_per_hour:
                rec.throttled_count += 1
                return False, f"Quota exceeded: {rec.events_delivered_this_hour}/{rec.events_per_hour} per hour"

            rec.events_delivered_this_hour += 1
            return True, "ok"

    def get_utilization_pct(self, tenant_id: str) -> float:
        with self._lock:
            rec = self._records.get(tenant_id)
            if not rec or rec.events_per_hour == 0:
                return 0.0
            return round(rec.events_delivered_this_hour / rec.events_per_hour * 100, 2)


# ─────────────────────────────────────────────────────────────
# REGISTRY
# ─────────────────────────────────────────────────────────────

class WebhookRegistry:
    """
    Central registry for webhook subscriptions.
    Manages CRUD, persistence, and event routing.
    """

    def __init__(self, store_path: Path = SUBSCRIPTION_STORE_PATH):
        self.store_path = store_path
        self._subscriptions: dict[str, WebhookSubscription] = {}
        self._quota_governor = WebhookQuotaGovernor()
        self._lock = threading.Lock()
        store_path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def register(
        self,
        tenant_id: str,
        api_key_prefix: str,
        endpoint_url: str,
        secret: str,
        events: list[str],
        plan_tier: str,
        custom_headers: dict = None,
        filter_expression: str = None,
    ) -> WebhookSubscription:
        """Register a new webhook subscription."""
        # Validate events
        invalid = [e for e in events if e not in WEBHOOK_EVENT_CATALOG and e != "*"]
        if invalid:
            raise ValueError(f"Unknown event types: {invalid}. Valid: {list(WEBHOOK_EVENT_CATALOG)}")

        if plan_tier == "starter":
            raise PermissionError("Starter plan does not include webhook delivery. Upgrade to Professional.")

        sub = WebhookSubscription(
            subscription_id=_sub_id(),
            tenant_id=tenant_id,
            api_key_prefix=api_key_prefix,
            endpoint_url=endpoint_url,
            secret=secret,
            events=events,
            plan_tier=plan_tier,
            created_at=_utcnow(),
            custom_headers=custom_headers or {},
            filter_expression=filter_expression,
        )
        with self._lock:
            self._subscriptions[sub.subscription_id] = sub
        self._persist()
        logger.info(f"Webhook registered: {sub.subscription_id} → {endpoint_url} events={events}")
        return sub

    def pause(self, subscription_id: str) -> None:
        with self._lock:
            sub = self._subscriptions.get(subscription_id)
            if sub:
                sub.status = SubscriptionStatus.PAUSED
        self._persist()

    def resume(self, subscription_id: str) -> None:
        with self._lock:
            sub = self._subscriptions.get(subscription_id)
            if sub:
                sub.status = SubscriptionStatus.ACTIVE
                sub.consecutive_failures = 0
        self._persist()

    def delete(self, subscription_id: str) -> bool:
        with self._lock:
            existed = subscription_id in self._subscriptions
            self._subscriptions.pop(subscription_id, None)
        self._persist()
        return existed

    def get_eligible_subscriptions(
        self, event_type: str, tlp: str, tenant_scope: Optional[str] = None
    ) -> list[WebhookSubscription]:
        """Return all active subscriptions eligible for this event."""
        with self._lock:
            return [
                sub for sub in self._subscriptions.values()
                if sub.is_eligible_for_event(event_type, tlp)
                and (tenant_scope is None or sub.tenant_id == tenant_scope)
            ]

    def list_for_tenant(self, tenant_id: str) -> list[dict]:
        with self._lock:
            return [
                sub.to_dict() for sub in self._subscriptions.values()
                if sub.tenant_id == tenant_id
            ]

    def record_delivery_result(
        self, subscription_id: str, success: bool
    ) -> None:
        with self._lock:
            sub = self._subscriptions.get(subscription_id)
            if not sub:
                return
            if success:
                sub.consecutive_failures = 0
                sub.last_success_at = _utcnow()
                sub.total_delivered += 1
            else:
                sub.consecutive_failures += 1
                sub.total_failed += 1
                if sub.consecutive_failures >= 10:
                    sub.status = SubscriptionStatus.FAILED
                    logger.warning(
                        f"Subscription {subscription_id} suspended after "
                        f"{sub.consecutive_failures} consecutive failures"
                    )
        self._persist()

    def _load(self):
        if self.store_path.exists():
            try:
                data = json.loads(self.store_path.read_text())
                for sub_dict in data.get("subscriptions", []):
                    sub = WebhookSubscription(**sub_dict)
                    self._subscriptions[sub.subscription_id] = sub
                logger.info(f"Loaded {len(self._subscriptions)} webhook subscriptions")
            except Exception as e:
                logger.error(f"Failed to load subscriptions: {e}")

    def _persist(self):
        try:
            with self._lock:
                data = {
                    "subscriptions": [s.to_dict() for s in self._subscriptions.values()],
                    "updated_at": _utcnow(),
                    "count": len(self._subscriptions),
                }
            self.store_path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to persist subscriptions: {e}")


# ─────────────────────────────────────────────────────────────
# DELIVERY ENGINE
# ─────────────────────────────────────────────────────────────

class WebhookDeliveryEngine:
    """
    Simulates HTTP delivery to webhook endpoints with retry logic,
    signature, audit trail, and DLQ management.

    In production: replace _do_http_post with actual httpx/aiohttp calls.
    """

    def __init__(
        self,
        registry: WebhookRegistry,
        delivery_log: Path = DELIVERY_LOG_PATH,
        dlq_path: Path = DLQ_PATH,
    ):
        self.registry = registry
        self.delivery_log = delivery_log
        self.dlq_path = dlq_path
        delivery_log.parent.mkdir(parents=True, exist_ok=True)

    def dispatch(self, event: WebhookEvent) -> list[DeliveryAttempt]:
        """Dispatch event to all eligible subscribers. Returns delivery attempts."""
        subscribers = self.registry.get_eligible_subscriptions(
            event.event_type, event.tlp, event.tenant_scope
        )

        attempts = []
        for sub in subscribers:
            # Quota check
            allowed, reason = self.registry._quota_governor.check_and_consume(
                sub.tenant_id, sub.plan_tier
            )
            if not allowed:
                logger.warning(f"Quota throttle for {sub.tenant_id}: {reason}")
                self._write_dlq(event, sub.subscription_id, f"Throttled: {reason}")
                continue

            attempt = self._attempt_delivery(event, sub, attempt_number=1)
            attempts.append(attempt)
            self._log_attempt(attempt)

            if attempt.status == DeliveryStatus.FAILED:
                self._schedule_retry(event, sub, attempt_number=2)

        return attempts

    def _attempt_delivery(
        self,
        event: WebhookEvent,
        sub: WebhookSubscription,
        attempt_number: int,
    ) -> DeliveryAttempt:
        """Simulate delivery. In production, make real HTTP POST."""
        body, sig = event.to_signed_payload(sub.secret)

        attempt = DeliveryAttempt(
            attempt_id=_attempt_id(),
            event_id=event.event_id,
            subscription_id=sub.subscription_id,
            attempted_at=_utcnow(),
            status=DeliveryStatus.PENDING,
            attempt_number=attempt_number,
        )

        try:
            # ── PRODUCTION: replace with httpx.post ──
            result = self._do_http_post(sub.endpoint_url, body, sig, sub)
            attempt.http_status = result["status_code"]
            attempt.response_ms = result["response_ms"]

            if 200 <= result["status_code"] < 300:
                attempt.status = DeliveryStatus.DELIVERED
                self.registry.record_delivery_result(sub.subscription_id, success=True)
                logger.debug(
                    f"✓ Delivered {event.event_type} to {sub.endpoint_url} "
                    f"[{result['status_code']}] {result['response_ms']}ms"
                )
            else:
                attempt.status = DeliveryStatus.FAILED
                attempt.error_message = f"HTTP {result['status_code']}"
                self.registry.record_delivery_result(sub.subscription_id, success=False)

        except Exception as e:
            attempt.status = DeliveryStatus.FAILED
            attempt.error_message = str(e)
            self.registry.record_delivery_result(sub.subscription_id, success=False)

        return attempt

    def _schedule_retry(
        self,
        event: WebhookEvent,
        sub: WebhookSubscription,
        attempt_number: int,
    ) -> None:
        """In production: enqueue to retry scheduler (Celery/RQ/cron)."""
        if attempt_number > len(RETRY_SCHEDULE_SECONDS):
            logger.warning(
                f"Max retries exhausted for event {event.event_id} → "
                f"subscription {sub.subscription_id}. Sending to DLQ."
            )
            self._write_dlq(event, sub.subscription_id, "Max retries exhausted")
            return

        delay = RETRY_SCHEDULE_SECONDS[attempt_number - 2]
        retry_at = _utcnow()
        logger.info(
            f"Retry scheduled: event={event.event_id} sub={sub.subscription_id} "
            f"attempt={attempt_number} delay={delay}s"
        )
        # Production: enqueue(event, sub, attempt_number, delay)

    def _do_http_post(
        self,
        url: str,
        body: bytes,
        signature: str,
        sub: WebhookSubscription,
    ) -> dict:
        """
        Simulated HTTP POST. In production replace with:
            import httpx
            resp = httpx.post(url, content=body, headers={
                "Content-Type": "application/json",
                "X-CDB-Signature": signature,
                "X-CDB-Event-ID": event.event_id,
                **sub.custom_headers
            }, timeout=sub.delivery_timeout_s, verify=sub.tls_verify)
        """
        import random
        start = time.monotonic()
        time.sleep(random.uniform(0.01, 0.05))  # Simulate network
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Simulate 98% success rate
        status_code = 200 if random.random() > 0.02 else random.choice([502, 503, 408])
        return {"status_code": status_code, "response_ms": elapsed_ms}

    def _log_attempt(self, attempt: DeliveryAttempt) -> None:
        try:
            with open(self.delivery_log, "a") as f:
                f.write(json.dumps(asdict(attempt)) + "\n")
        except Exception as e:
            logger.error(f"Failed to log delivery attempt: {e}")

    def _write_dlq(
        self, event: WebhookEvent, subscription_id: str, reason: str
    ) -> None:
        try:
            entry = {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "subscription_id": subscription_id,
                "failed_at": _utcnow(),
                "reason": reason,
                "payload": event.payload,
            }
            with open(self.dlq_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to DLQ: {e}")


# ─────────────────────────────────────────────────────────────
# EVENT FACTORY
# ─────────────────────────────────────────────────────────────

class WebhookEventFactory:
    """Constructs standardized WebhookEvent objects for each event type."""

    @staticmethod
    def advisory_created(advisory: dict, tlp: str = "WHITE") -> WebhookEvent:
        return WebhookEvent(
            event_id=_event_id(),
            event_type="advisory.created",
            source="sentinel_apex.advisory_engine",
            tlp=tlp,
            fired_at=_utcnow(),
            payload={
                "cve_id": advisory.get("cve_id"),
                "severity": advisory.get("severity"),
                "risk_score": advisory.get("risk_score"),
                "confidence_pct": advisory.get("confidence_pct"),
                "kev": advisory.get("kev", False),
                "epss_score": advisory.get("epss_score"),
                "advisory_url": advisory.get("advisory_url"),
            }
        )

    @staticmethod
    def advisory_kev_promoted(advisory: dict) -> WebhookEvent:
        return WebhookEvent(
            event_id=_event_id(),
            event_type="advisory.kev_promoted",
            source="sentinel_apex.kev_monitor",
            tlp="WHITE",
            fired_at=_utcnow(),
            payload={
                "cve_id": advisory.get("cve_id"),
                "previous_severity": advisory.get("previous_severity"),
                "promoted_severity": "HIGH",
                "kev_added_date": advisory.get("kev_added_date"),
                "cisa_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        )

    @staticmethod
    def ioc_new_malicious(ioc_value: str, ioc_type: str, confidence: float,
                          actor_cluster: str = None, tlp: str = "WHITE") -> WebhookEvent:
        return WebhookEvent(
            event_id=_event_id(),
            event_type="ioc.new_malicious",
            source="sentinel_apex.telemetry_engine",
            tlp=tlp,
            fired_at=_utcnow(),
            payload={
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "verdict": "MALICIOUS",
                "confidence_pct": confidence,
                "actor_cluster": actor_cluster,
                "first_observed": _utcnow(),
            }
        )

    @staticmethod
    def honeynet_hit(source_ip: str, ttp: str, region: str,
                     payload_fingerprint: str = None) -> WebhookEvent:
        return WebhookEvent(
            event_id=_event_id(),
            event_type="telemetry.honeynet_hit",
            source="sentinel_apex.honeynet",
            tlp="GREEN",
            fired_at=_utcnow(),
            payload={
                "source_ip": source_ip,
                "ttp": ttp,
                "honeynet_region": region,
                "payload_fingerprint": payload_fingerprint,
                "observed_at": _utcnow(),
            }
        )

    @staticmethod
    def quota_warning(tenant_id: str, utilization_pct: float,
                      limit: int, current: int) -> WebhookEvent:
        level = "critical" if utilization_pct >= 90 else "warning"
        return WebhookEvent(
            event_id=_event_id(),
            event_type="quota.warning",
            source="sentinel_apex.quota_governor",
            tlp="WHITE",
            fired_at=_utcnow(),
            tenant_scope=tenant_id,
            payload={
                "tenant_id": tenant_id,
                "utilization_pct": utilization_pct,
                "calls_used": current,
                "calls_limit": limit,
                "level": level,
                "upgrade_url": "https://intel.cyberdudebivash.com/upgrade",
            }
        )

    @staticmethod
    def campaign_detected(campaign_id: str, tenants_affected: int,
                          actor_cluster: str, ttp_list: list) -> WebhookEvent:
        return WebhookEvent(
            event_id=_event_id(),
            event_type="graph.campaign_detected",
            source="sentinel_apex.graph_engine",
            tlp="AMBER",
            fired_at=_utcnow(),
            payload={
                "campaign_id": campaign_id,
                "tenants_affected": tenants_affected,
                "actor_cluster": actor_cluster,
                "techniques": ttp_list,
                "detected_at": _utcnow(),
            }
        )


# ─────────────────────────────────────────────────────────────
# API OBSERVABILITY RECORDER
# ─────────────────────────────────────────────────────────────

@dataclass
class APICallRecord:
    """Lightweight record for API observability."""
    call_id: str
    tenant_id: str
    endpoint: str
    method: str
    status_code: int
    response_ms: int
    timestamp: str
    quota_consumed: int = 1
    cache_hit: bool = False
    error_code: Optional[str] = None


class APIObservabilityRecorder:
    """
    Records API call metrics for observability dashboards.
    Writes JSONL for ingestion into ClickHouse or similar.
    """

    METRICS_LOG = Path("data/api/api_calls.jsonl")

    def __init__(self):
        self.METRICS_LOG.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: list[dict] = []
        self._lock = threading.Lock()
        self._flush_interval = 100   # Flush every 100 records

    def record(
        self,
        tenant_id: str,
        endpoint: str,
        method: str,
        status_code: int,
        response_ms: int,
        cache_hit: bool = False,
        error_code: str = None,
    ) -> None:
        record = APICallRecord(
            call_id=f"api_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_ms=response_ms,
            timestamp=_utcnow(),
            cache_hit=cache_hit,
            error_code=error_code,
        )
        with self._lock:
            self._buffer.append(asdict(record))
            if len(self._buffer) >= self._flush_interval:
                self._flush()

    def _flush(self):
        if not self._buffer:
            return
        try:
            with open(self.METRICS_LOG, "a") as f:
                for rec in self._buffer:
                    f.write(json.dumps(rec) + "\n")
            self._buffer.clear()
        except Exception as e:
            logger.error(f"Failed to flush API metrics: {e}")

    def get_summary(self, tenant_id: str = None) -> dict:
        """Return in-memory summary (production: query ClickHouse)."""
        with self._lock:
            records = self._buffer if not tenant_id else [
                r for r in self._buffer if r["tenant_id"] == tenant_id
            ]
        if not records:
            return {"calls": 0, "avg_ms": 0, "error_rate_pct": 0, "cache_hit_pct": 0}

        total = len(records)
        errors = sum(1 for r in records if r["status_code"] >= 400)
        cache_hits = sum(1 for r in records if r["cache_hit"])
        avg_ms = sum(r["response_ms"] for r in records) / total

        return {
            "calls": total,
            "avg_ms": round(avg_ms, 1),
            "error_rate_pct": round(errors / total * 100, 2),
            "cache_hit_pct": round(cache_hits / total * 100, 1),
            "tenant_id": tenant_id,
            "as_of": _utcnow(),
        }


# ─────────────────────────────────────────────────────────────
# SINGLETON ACCESSORS
# ─────────────────────────────────────────────────────────────

_registry: Optional[WebhookRegistry] = None
_delivery_engine: Optional[WebhookDeliveryEngine] = None
_observability: Optional[APIObservabilityRecorder] = None


def get_registry() -> WebhookRegistry:
    global _registry
    if _registry is None:
        _registry = WebhookRegistry()
    return _registry


def get_delivery_engine() -> WebhookDeliveryEngine:
    global _delivery_engine
    if _delivery_engine is None:
        _delivery_engine = WebhookDeliveryEngine(get_registry())
    return _delivery_engine


def get_observability() -> APIObservabilityRecorder:
    global _observability
    if _observability is None:
        _observability = APIObservabilityRecorder()
    return _observability


# ─────────────────────────────────────────────────────────────
# PUBLIC API — fire_event() convenience function
# ─────────────────────────────────────────────────────────────

def fire_event(event: WebhookEvent) -> list[DeliveryAttempt]:
    """
    Top-level convenience function for firing a webhook event.
    Called from advisory engine, risk engine, telemetry bus, etc.

    Usage:
        from api_economy.webhook_registry import fire_event, WebhookEventFactory

        # When a KEV advisory is promoted:
        event = WebhookEventFactory.advisory_kev_promoted(advisory)
        attempts = fire_event(event)
    """
    engine = get_delivery_engine()
    attempts = engine.dispatch(event)
    logger.info(
        f"Fired {event.event_type} → {len(attempts)} delivery attempt(s) "
        f"| {sum(1 for a in attempts if a.status == DeliveryStatus.DELIVERED)} delivered"
    )
    return attempts


# ─────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    print("=" * 60)
    print("CYBERDUDEBIVASH® SENTINEL APEX — Webhook Registry Self-Test")
    print("=" * 60)

    registry = WebhookRegistry()

    # Register test subscriptions
    sub1 = registry.register(
        tenant_id="T-001",
        api_key_prefix="sk-cdb-r-t001",
        endpoint_url="https://soc.globalbank.com/webhooks/sentinel",
        secret=os.environ.get("DEMO_WEBHOOK_SECRET_1", "your_demo_signing_key_1"),
        events=["advisory.created", "advisory.kev_promoted", "ioc.new_malicious", "quota.warning"],
        plan_tier="enterprise",
    )
    sub2 = registry.register(
        tenant_id="T-004",
        api_key_prefix="sk-cdb-r-t004",
        endpoint_url="https://alerts.techpulse.io/cdb-hook",
        secret=os.environ.get("DEMO_WEBHOOK_SECRET_2", "your_demo_signing_key_2"),
        events=["advisory.created", "telemetry.honeynet_hit"],
        plan_tier="professional",
    )
    print(f"\n✓ Registered: {sub1.subscription_id} ({sub1.endpoint_url})")
    print(f"✓ Registered: {sub2.subscription_id} ({sub2.endpoint_url})")

    # Fire events
    engine = WebhookDeliveryEngine(registry)

    print("\n→ Firing advisory.created event (TLP:WHITE)...")
    event1 = WebhookEventFactory.advisory_created({
        "cve_id": "CVE-2026-6565",
        "severity": "low",
        "risk_score": 0.74,
        "confidence_pct": 18.4,
        "kev": False,
    })
    attempts1 = engine.dispatch(event1)
    for a in attempts1:
        print(f"  Attempt {a.attempt_id}: {a.status} HTTP={a.http_status} {a.response_ms}ms")

    print("\n→ Firing advisory.kev_promoted (TLP:WHITE)...")
    event2 = WebhookEventFactory.advisory_kev_promoted({
        "cve_id": "CVE-2026-9999",
        "previous_severity": "medium",
        "kev_added_date": "2026-05-27",
    })
    attempts2 = engine.dispatch(event2)
    for a in attempts2:
        print(f"  Attempt {a.attempt_id}: {a.status} HTTP={a.http_status}")

    print("\n→ Firing graph.campaign_detected (TLP:AMBER — enterprise only)...")
    event3 = WebhookEventFactory.campaign_detected(
        campaign_id="CMP-2026-042",
        tenants_affected=3,
        actor_cluster="Lazarus-Infra-Cluster-7",
        ttp_list=["T1059.003", "T1486"]
    )
    attempts3 = engine.dispatch(event3)
    print(f"  TLP:AMBER → {len(attempts3)} delivery attempts (enterprise tenants only)")

    # Observability
    obs = get_observability()
    obs.record("T-001", "/advisories", "GET", 200, 42)
    obs.record("T-001", "/ioc/lookup", "GET", 200, 12, cache_hit=True)
    obs.record("T-001", "/risk/score/CVE-2026-6565", "GET", 200, 88)
    obs.record("T-004", "/advisories", "GET", 429, 5, error_code="RATE_LIMITED")
    summary = obs.get_summary("T-001")
    print(f"\n→ Observability summary for T-001: {summary}")

    # Quota test
    print("\n→ Event catalog:")
    for event_type, desc in WEBHOOK_EVENT_CATALOG.items():
        print(f"  {event_type:40s} {desc[:55]}…")

    print("\n✅ Webhook Registry self-test complete.")
