#!/usr/bin/env python3
"""
b2b_streaming_api.py — CYBERDUDEBIVASH® SENTINEL APEX v55.0
B2B INTELLIGENCE STREAMING & WEBHOOK FIREHOSE ENGINE

Production-grade secure intelligence distribution for B2B vendors:
  - HMAC-SHA256 signed threat pulses on every webhook delivery
  - mTLS certificate-based authentication for "God-Mode" Enterprise tier
  - Subscription management (create/update/pause/revoke)
  - Delivery guarantees with retry + dead-letter queue
  - Rate-limited per-subscriber with backpressure
  - STIX 2.1 compatible payload format
  - Integration with existing ApexDataStreamer (agent/sdk/cdb_apex_streamer.py)

Integration:
    from agent.intel.b2b_streaming_api import b2b_streaming_engine
    sub = b2b_streaming_engine.create_subscription("org_abc", "https://soc.client.com/webhook")
    b2b_streaming_engine.dispatch_pulse(threat_pulse_payload)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
Founder & CEO — Bivash Kumar Nayak
"""

import os
import json
import hmac
import hashlib
import ssl
import time
import uuid
import asyncio
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("CDB-B2B-STREAMING")

# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

B2B_HMAC_SECRET_ENV = "CDB_B2B_HMAC_SECRET"
B2B_MTLS_CA_CERT = os.environ.get("CDB_MTLS_CA_CERT", "certs/ca.pem")
B2B_MTLS_SERVER_CERT = os.environ.get("CDB_MTLS_SERVER_CERT", "certs/server.pem")
B2B_MTLS_SERVER_KEY = os.environ.get("CDB_MTLS_SERVER_KEY", "certs/server-key.pem")

DATA_DIR = Path("data/b2b_streaming")
SUBSCRIPTIONS_FILE = DATA_DIR / "subscriptions.json"
DLQ_DIR = DATA_DIR / "dead_letter_queue"
DELIVERY_LOG = DATA_DIR / "delivery_log.jsonl"

DATA_DIR.mkdir(parents=True, exist_ok=True)
DLQ_DIR.mkdir(parents=True, exist_ok=True)

MAX_RETRY_ATTEMPTS = 5
RETRY_BACKOFF_BASE = 2      # Exponential backoff: 2^attempt seconds
DELIVERY_TIMEOUT_SEC = 10
MAX_PAYLOAD_SIZE_BYTES = 1_048_576  # 1MB
SIGNATURE_TIMESTAMP_TOLERANCE_SEC = 300  # 5 minutes


# ═══════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════

class SubscriptionTier(str, Enum):
    STANDARD = "STANDARD"     # HMAC-signed webhooks
    ENTERPRISE = "ENTERPRISE" # HMAC + mTLS "God-Mode"


class SubscriptionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    SUSPENDED = "SUSPENDED"   # Failed delivery threshold
    REVOKED = "REVOKED"


class DeliveryStatus(str, Enum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    DLQ = "DEAD_LETTER"


@dataclass
class WebhookSubscription:
    subscription_id: str
    org_id: str
    webhook_url: str
    tier: str = SubscriptionTier.STANDARD
    status: str = SubscriptionStatus.ACTIVE
    hmac_secret: str = ""
    mtls_client_cert_fingerprint: str = ""  # SHA-256 of client cert for mTLS
    event_filters: List[str] = field(default_factory=list)  # Filter by event type
    created_at: str = ""
    updated_at: str = ""
    consecutive_failures: int = 0
    max_consecutive_failures: int = 10
    total_deliveries: int = 0
    total_failures: int = 0
    last_delivery_at: str = ""
    rate_limit_per_minute: int = 60
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class ThreatPulse:
    """STIX-compatible threat intelligence pulse."""
    pulse_id: str
    timestamp: str
    source: str = "CYBERDUDEBIVASH_SENTINEL_APEX"
    event_type: str = "THREAT_INTEL"
    severity: str = "MEDIUM"
    confidence: float = 0.85
    tlp: str = "TLP:AMBER"
    payload: Dict = field(default_factory=dict)
    stix_objects: List[Dict] = field(default_factory=list)
    indicators: List[Dict] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════
# HMAC SIGNING ENGINE
# ═══════════════════════════════════════════════════════════

class HMACSigner:
    """
    HMAC-SHA256 signing for webhook payloads.
    
    Signature format:
        X-CDB-Signature: t=<unix_timestamp>,v1=<hmac_sha256_hex>
    
    The signed payload is: "<timestamp>.<json_body>"
    """

    @staticmethod
    def sign(payload_bytes: bytes, secret: str, timestamp: Optional[int] = None) -> Tuple[str, int]:
        """
        Sign a payload with HMAC-SHA256.
        
        Returns:
            (signature_header_value, timestamp)
        """
        ts = timestamp or int(time.time())
        signed_content = f"{ts}.".encode() + payload_bytes
        signature = hmac.new(
            secret.encode("utf-8"),
            signed_content,
            hashlib.sha256,
        ).hexdigest()
        header_value = f"t={ts},v1={signature}"
        return header_value, ts

    @staticmethod
    def verify(
        payload_bytes: bytes,
        signature_header: str,
        secret: str,
        tolerance_sec: int = SIGNATURE_TIMESTAMP_TOLERANCE_SEC,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify an HMAC-SHA256 signature.
        
        Returns:
            (is_valid, error_message)
        """
        try:
            parts = {}
            for element in signature_header.split(","):
                key, value = element.strip().split("=", 1)
                parts[key] = value

            ts = int(parts.get("t", "0"))
            received_sig = parts.get("v1", "")

            # Timestamp freshness
            now = int(time.time())
            if abs(now - ts) > tolerance_sec:
                return False, f"Timestamp expired: {abs(now - ts)}s > {tolerance_sec}s"

            # Recompute signature
            signed_content = f"{ts}.".encode() + payload_bytes
            expected_sig = hmac.new(
                secret.encode("utf-8"),
                signed_content,
                hashlib.sha256,
            ).hexdigest()

            if hmac.compare_digest(received_sig, expected_sig):
                return True, None
            return False, "Signature mismatch"

        except Exception as e:
            return False, f"Signature parse error: {e}"


# ═══════════════════════════════════════════════════════════
# mTLS CERTIFICATE AUTHENTICATION
# ═══════════════════════════════════════════════════════════

class MTLSAuthenticator:
    """
    Certificate-based mutual TLS authentication for Enterprise "God-Mode" tier.
    
    Validates client certificate fingerprint against registered subscription.
    """

    @staticmethod
    def create_ssl_context() -> ssl.SSLContext:
        """Create server-side mTLS SSL context."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        # Load server certificate and key
        if os.path.exists(B2B_MTLS_SERVER_CERT) and os.path.exists(B2B_MTLS_SERVER_KEY):
            ctx.load_cert_chain(B2B_MTLS_SERVER_CERT, B2B_MTLS_SERVER_KEY)
        else:
            logger.warning("mTLS server cert/key not found — mTLS disabled")

        # Load CA for client cert verification
        if os.path.exists(B2B_MTLS_CA_CERT):
            ctx.load_verify_locations(B2B_MTLS_CA_CERT)
        else:
            logger.warning("mTLS CA cert not found — client verification disabled")

        # Harden TLS
        ctx.set_ciphers(
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256"
        )

        return ctx

    @staticmethod
    def get_cert_fingerprint(cert_pem: str) -> str:
        """Compute SHA-256 fingerprint of a PEM certificate."""
        try:
            import base64
            # Strip PEM headers
            lines = [l for l in cert_pem.strip().split("\n")
                     if not l.startswith("-----")]
            der_bytes = base64.b64decode("".join(lines))
            return hashlib.sha256(der_bytes).hexdigest()
        except Exception as e:
            logger.error(f"Certificate fingerprint computation failed: {e}")
            return ""

    @staticmethod
    def validate_client_cert(cert_fingerprint: str, subscription: WebhookSubscription) -> Tuple[bool, str]:
        """Validate client certificate against subscription registration."""
        if subscription.tier != SubscriptionTier.ENTERPRISE:
            return True, "Non-Enterprise tier — mTLS not required"

        if not subscription.mtls_client_cert_fingerprint:
            return False, "Enterprise subscription missing client cert fingerprint"

        if hmac.compare_digest(cert_fingerprint, subscription.mtls_client_cert_fingerprint):
            return True, "mTLS client certificate validated"

        return False, "Client certificate fingerprint mismatch"


# ═══════════════════════════════════════════════════════════
# DELIVERY ENGINE
# ═══════════════════════════════════════════════════════════

class DeliveryEngine:
    """Async webhook delivery with retry, backpressure, and DLQ."""

    def __init__(self):
        self._rate_counters: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    async def deliver(
        self,
        subscription: WebhookSubscription,
        pulse: ThreatPulse,
    ) -> Dict[str, Any]:
        """
        Deliver a signed threat pulse to a subscriber's webhook endpoint.
        
        Returns delivery result with status and metadata.
        """
        # Rate limiting check
        if not self._check_rate_limit(subscription.subscription_id, subscription.rate_limit_per_minute):
            return {
                "status": DeliveryStatus.FAILED,
                "reason": "RATE_LIMITED",
                "subscription_id": subscription.subscription_id,
            }

        # Serialize payload
        payload_dict = {
            "pulse_id": pulse.pulse_id,
            "timestamp": pulse.timestamp,
            "source": pulse.source,
            "event_type": pulse.event_type,
            "severity": pulse.severity,
            "confidence": pulse.confidence,
            "tlp": pulse.tlp,
            "payload": pulse.payload,
            "indicators": pulse.indicators,
            "mitre_techniques": pulse.mitre_techniques,
        }

        if pulse.stix_objects:
            payload_dict["stix_bundle"] = {
                "type": "bundle",
                "id": f"bundle--{pulse.pulse_id}",
                "objects": pulse.stix_objects,
            }

        payload_bytes = json.dumps(payload_dict, separators=(",", ":"), default=str).encode()

        # Size check
        if len(payload_bytes) > MAX_PAYLOAD_SIZE_BYTES:
            return {
                "status": DeliveryStatus.FAILED,
                "reason": "PAYLOAD_TOO_LARGE",
                "size_bytes": len(payload_bytes),
            }

        # Sign payload
        signer = HMACSigner()
        signature, ts = signer.sign(payload_bytes, subscription.hmac_secret)

        headers = {
            "Content-Type": "application/json",
            "X-CDB-Signature": signature,
            "X-CDB-Timestamp": str(ts),
            "X-CDB-Pulse-ID": pulse.pulse_id,
            "X-CDB-Event-Type": pulse.event_type,
            "X-CDB-Source": "CYBERDUDEBIVASH-SENTINEL-APEX",
            "User-Agent": "CDB-B2B-StreamingAPI/v55.0",
        }

        # Deliver with retry
        last_error = None
        for attempt in range(MAX_RETRY_ATTEMPTS):
            try:
                status_code, response_body = await self._http_post(
                    subscription.webhook_url,
                    payload_bytes,
                    headers,
                    subscription,
                )

                if 200 <= status_code < 300:
                    return {
                        "status": DeliveryStatus.DELIVERED,
                        "subscription_id": subscription.subscription_id,
                        "pulse_id": pulse.pulse_id,
                        "status_code": status_code,
                        "attempt": attempt + 1,
                        "delivered_at": datetime.now(timezone.utc).isoformat(),
                    }

                last_error = f"HTTP {status_code}: {response_body[:200]}"

            except Exception as e:
                last_error = str(e)

            # Exponential backoff
            if attempt < MAX_RETRY_ATTEMPTS - 1:
                wait = RETRY_BACKOFF_BASE ** attempt
                await asyncio.sleep(wait)

        # All retries exhausted → DLQ
        dlq_result = self._send_to_dlq(subscription, pulse, payload_bytes, last_error)

        return {
            "status": DeliveryStatus.DLQ,
            "subscription_id": subscription.subscription_id,
            "pulse_id": pulse.pulse_id,
            "attempts": MAX_RETRY_ATTEMPTS,
            "last_error": last_error,
            "dlq_path": dlq_result.get("path"),
        }

    async def _http_post(
        self,
        url: str,
        body: bytes,
        headers: Dict[str, str],
        subscription: WebhookSubscription,
    ) -> Tuple[int, str]:
        """Execute HTTP POST with optional mTLS."""
        try:
            import aiohttp

            ssl_ctx = None
            if subscription.tier == SubscriptionTier.ENTERPRISE:
                ssl_ctx = self._build_mtls_client_context()

            timeout = aiohttp.ClientTimeout(total=DELIVERY_TIMEOUT_SEC)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, data=body, headers=headers, ssl=ssl_ctx) as resp:
                    body_text = await resp.text()
                    return resp.status, body_text

        except ImportError:
            # Fallback: urllib (no mTLS in fallback)
            import urllib.request
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=DELIVERY_TIMEOUT_SEC) as resp:
                    return resp.status, resp.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode()

    def _build_mtls_client_context(self) -> Optional[ssl.SSLContext]:
        """Build SSL context for mTLS outbound connections."""
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if os.path.exists(B2B_MTLS_CA_CERT):
                ctx.load_verify_locations(B2B_MTLS_CA_CERT)
            if os.path.exists(B2B_MTLS_SERVER_CERT) and os.path.exists(B2B_MTLS_SERVER_KEY):
                ctx.load_cert_chain(B2B_MTLS_SERVER_CERT, B2B_MTLS_SERVER_KEY)
            return ctx
        except Exception as e:
            logger.error(f"mTLS context creation failed: {e}")
            return None

    def _check_rate_limit(self, subscription_id: str, limit_per_minute: int) -> bool:
        """Sliding window rate limit per subscriber."""
        now = time.monotonic()
        with self._lock:
            if subscription_id not in self._rate_counters:
                self._rate_counters[subscription_id] = []
            timestamps = self._rate_counters[subscription_id]
            # Prune old entries
            cutoff = now - 60
            self._rate_counters[subscription_id] = [t for t in timestamps if t > cutoff]
            if len(self._rate_counters[subscription_id]) >= limit_per_minute:
                return False
            self._rate_counters[subscription_id].append(now)
            return True

    def _send_to_dlq(
        self,
        subscription: WebhookSubscription,
        pulse: ThreatPulse,
        payload_bytes: bytes,
        error: str,
    ) -> Dict:
        """Send failed delivery to dead-letter queue."""
        dlq_entry = {
            "subscription_id": subscription.subscription_id,
            "org_id": subscription.org_id,
            "webhook_url": subscription.webhook_url,
            "pulse_id": pulse.pulse_id,
            "error": error,
            "payload_size": len(payload_bytes),
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "attempts": MAX_RETRY_ATTEMPTS,
        }
        filename = f"{subscription.subscription_id}_{pulse.pulse_id}.json"
        filepath = DLQ_DIR / filename
        try:
            with open(filepath, "w") as f:
                json.dump(dlq_entry, f, indent=2)
            logger.warning(f"DLQ: {subscription.subscription_id} → {filepath}")
            return {"path": str(filepath)}
        except Exception as e:
            logger.error(f"DLQ write failed: {e}")
            return {"path": None}


# ═══════════════════════════════════════════════════════════
# B2B STREAMING ENGINE (Main Orchestrator)
# ═══════════════════════════════════════════════════════════

class B2BStreamingEngine:
    """
    Central B2B intelligence streaming orchestrator.
    
    Manages webhook subscriptions, dispatches HMAC-signed threat pulses,
    and handles mTLS for Enterprise "God-Mode" subscribers.
    """

    def __init__(self):
        self._subscriptions: Dict[str, WebhookSubscription] = {}
        self._delivery = DeliveryEngine()
        self._hmac = HMACSigner()
        self._mtls = MTLSAuthenticator()
        self._load_subscriptions()

    # ── Subscription Management ──

    def create_subscription(
        self,
        org_id: str,
        webhook_url: str,
        tier: str = SubscriptionTier.STANDARD,
        event_filters: Optional[List[str]] = None,
        client_cert_pem: Optional[str] = None,
        rate_limit_per_minute: int = 60,
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Register a new B2B webhook subscription."""
        # Validate URL
        if not webhook_url.startswith("https://"):
            return {"error": "Webhook URL must use HTTPS", "code": "INSECURE_URL"}

        sub_id = f"bsub_{uuid.uuid4().hex[:16]}"
        hmac_secret = hashlib.sha256(
            f"{sub_id}:{org_id}:{time.time_ns()}".encode()
        ).hexdigest()

        # mTLS fingerprint for Enterprise
        cert_fingerprint = ""
        if tier == SubscriptionTier.ENTERPRISE and client_cert_pem:
            cert_fingerprint = self._mtls.get_cert_fingerprint(client_cert_pem)
            if not cert_fingerprint:
                return {"error": "Invalid client certificate", "code": "CERT_INVALID"}

        now = datetime.now(timezone.utc).isoformat()
        sub = WebhookSubscription(
            subscription_id=sub_id,
            org_id=org_id,
            webhook_url=webhook_url,
            tier=tier,
            status=SubscriptionStatus.ACTIVE,
            hmac_secret=hmac_secret,
            mtls_client_cert_fingerprint=cert_fingerprint,
            event_filters=event_filters or [],
            created_at=now,
            updated_at=now,
            rate_limit_per_minute=rate_limit_per_minute,
            metadata=metadata or {},
        )

        self._subscriptions[sub_id] = sub
        self._persist_subscriptions()

        logger.info(f"B2B subscription created: {sub_id} org={org_id} tier={tier}")

        return {
            "subscription_id": sub_id,
            "hmac_secret": hmac_secret,     # Return once — client must store
            "tier": tier,
            "status": SubscriptionStatus.ACTIVE,
            "webhook_url": webhook_url,
            "mtls_required": tier == SubscriptionTier.ENTERPRISE,
            "event_filters": event_filters or ["ALL"],
            "rate_limit_per_minute": rate_limit_per_minute,
            "created_at": now,
            "verification_endpoint": f"https://intel.cyberdudebivash.com/api/v1/b2b/verify/{sub_id}",
        }

    def update_subscription(
        self,
        subscription_id: str,
        webhook_url: Optional[str] = None,
        event_filters: Optional[List[str]] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an existing subscription."""
        sub = self._subscriptions.get(subscription_id)
        if not sub:
            return {"error": "Subscription not found", "code": "NOT_FOUND"}

        if webhook_url:
            if not webhook_url.startswith("https://"):
                return {"error": "HTTPS required", "code": "INSECURE_URL"}
            sub.webhook_url = webhook_url

        if event_filters is not None:
            sub.event_filters = event_filters

        if status and status in [s.value for s in SubscriptionStatus]:
            sub.status = status

        sub.updated_at = datetime.now(timezone.utc).isoformat()
        self._persist_subscriptions()

        return {"subscription_id": subscription_id, "status": sub.status, "updated": True}

    def revoke_subscription(self, subscription_id: str) -> Dict:
        """Permanently revoke a subscription."""
        sub = self._subscriptions.get(subscription_id)
        if not sub:
            return {"error": "Subscription not found"}

        sub.status = SubscriptionStatus.REVOKED
        sub.updated_at = datetime.now(timezone.utc).isoformat()
        self._persist_subscriptions()

        logger.info(f"B2B subscription revoked: {subscription_id}")
        return {"subscription_id": subscription_id, "status": "REVOKED"}

    def list_subscriptions(self, org_id: Optional[str] = None) -> List[Dict]:
        """List all or org-filtered subscriptions."""
        subs = self._subscriptions.values()
        if org_id:
            subs = [s for s in subs if s.org_id == org_id]

        return [
            {
                "subscription_id": s.subscription_id,
                "org_id": s.org_id,
                "tier": s.tier,
                "status": s.status,
                "webhook_url": s.webhook_url,
                "event_filters": s.event_filters,
                "total_deliveries": s.total_deliveries,
                "total_failures": s.total_failures,
                "consecutive_failures": s.consecutive_failures,
                "last_delivery_at": s.last_delivery_at,
            }
            for s in subs
        ]

    # ── Dispatch Engine ──

    async def dispatch_pulse(self, pulse: ThreatPulse) -> Dict[str, Any]:
        """
        Dispatch a threat pulse to all active matching subscribers.
        
        Returns aggregate delivery results.
        """
        active_subs = [
            s for s in self._subscriptions.values()
            if s.status == SubscriptionStatus.ACTIVE
        ]

        # Filter by event type
        matching = []
        for sub in active_subs:
            if not sub.event_filters or "ALL" in sub.event_filters:
                matching.append(sub)
            elif pulse.event_type in sub.event_filters:
                matching.append(sub)

        if not matching:
            return {"dispatched": 0, "pulse_id": pulse.pulse_id, "note": "No matching subscribers"}

        results = []
        for sub in matching:
            result = await self._delivery.deliver(sub, pulse)
            results.append(result)

            # Update subscription stats
            sub.total_deliveries += 1
            if result["status"] == DeliveryStatus.DELIVERED:
                sub.consecutive_failures = 0
                sub.last_delivery_at = datetime.now(timezone.utc).isoformat()
            else:
                sub.consecutive_failures += 1
                sub.total_failures += 1
                # Auto-suspend after max consecutive failures
                if sub.consecutive_failures >= sub.max_consecutive_failures:
                    sub.status = SubscriptionStatus.SUSPENDED
                    logger.warning(f"Subscription auto-suspended: {sub.subscription_id}")

        self._persist_subscriptions()
        self._log_delivery_batch(pulse.pulse_id, results)

        delivered = sum(1 for r in results if r["status"] == DeliveryStatus.DELIVERED)
        failed = sum(1 for r in results if r["status"] != DeliveryStatus.DELIVERED)

        return {
            "pulse_id": pulse.pulse_id,
            "dispatched": len(matching),
            "delivered": delivered,
            "failed": failed,
            "results": results,
        }

    def create_pulse_from_finding(self, finding: Dict) -> ThreatPulse:
        """
        Convert a platform finding (from BugHunter, ReasoningOrchestrator, etc.)
        into a B2B-ready ThreatPulse.
        """
        return ThreatPulse(
            pulse_id=f"pulse-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=finding.get("event_type", "THREAT_INTEL"),
            severity=finding.get("severity", "MEDIUM"),
            confidence=finding.get("confidence", finding.get("confidence_score", 0.85)),
            tlp=finding.get("tlp", "TLP:AMBER"),
            payload={
                "title": finding.get("title", ""),
                "description": finding.get("description", ""),
                "finding_type": finding.get("type", "UNKNOWN"),
                "risk_score": finding.get("risk_score", 0),
                "cvss_score": finding.get("cvss_score"),
                "epss_score": finding.get("epss_score"),
                "affected_asset": finding.get("target", finding.get("asset", "")),
            },
            indicators=[
                {"type": ioc.get("type", "unknown"), "value": ioc.get("value", "")}
                for ioc in finding.get("iocs", finding.get("indicators", []))
            ],
            mitre_techniques=finding.get("mitre_tactics", finding.get("mitre_techniques", [])),
        )

    # ── Verification Endpoint ──

    def verify_signature(
        self,
        subscription_id: str,
        payload_bytes: bytes,
        signature_header: str,
    ) -> Tuple[bool, str]:
        """Verify incoming webhook signature (for clients to validate)."""
        sub = self._subscriptions.get(subscription_id)
        if not sub:
            return False, "Subscription not found"

        return self._hmac.verify(payload_bytes, signature_header, sub.hmac_secret)

    # ── Persistence ──

    def _load_subscriptions(self):
        """Load subscriptions from disk."""
        if SUBSCRIPTIONS_FILE.exists():
            try:
                with open(SUBSCRIPTIONS_FILE, "r") as f:
                    data = json.load(f)
                for sub_dict in data.get("subscriptions", []):
                    sub = WebhookSubscription(**sub_dict)
                    self._subscriptions[sub.subscription_id] = sub
                logger.info(f"Loaded {len(self._subscriptions)} B2B subscriptions")
            except Exception as e:
                logger.error(f"Failed to load subscriptions: {e}")

    def _persist_subscriptions(self):
        """Save subscriptions to disk."""
        try:
            data = {
                "subscriptions": [asdict(s) for s in self._subscriptions.values()],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(SUBSCRIPTIONS_FILE, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Subscription persist failed: {e}")

    def _log_delivery_batch(self, pulse_id: str, results: List[Dict]):
        """Append delivery results to log."""
        try:
            with open(DELIVERY_LOG, "a") as f:
                entry = {
                    "pulse_id": pulse_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "count": len(results),
                    "delivered": sum(1 for r in results if r.get("status") == DeliveryStatus.DELIVERED),
                }
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def get_health(self) -> Dict:
        """Return streaming engine health metrics."""
        active = sum(1 for s in self._subscriptions.values()
                     if s.status == SubscriptionStatus.ACTIVE)
        suspended = sum(1 for s in self._subscriptions.values()
                        if s.status == SubscriptionStatus.SUSPENDED)
        total_deliveries = sum(s.total_deliveries for s in self._subscriptions.values())

        return {
            "engine": "CDB-B2B-Streaming-v55",
            "total_subscriptions": len(self._subscriptions),
            "active": active,
            "suspended": suspended,
            "total_deliveries": total_deliveries,
            "dlq_pending": len(list(DLQ_DIR.glob("*.json"))),
            "mtls_configured": os.path.exists(B2B_MTLS_CA_CERT),
        }


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

b2b_streaming_engine = B2BStreamingEngine()
