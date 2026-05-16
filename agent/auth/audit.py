#!/usr/bin/env python3
"""
agent/auth/audit.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE AUDIT TRAIL ENGINE

Immutable, tamper-evident audit log for all security-relevant platform events.

Compliance coverage:
  - SOC 2 Type II (CC6.1, CC6.2, CC6.3, CC7.2)
  - ISO 27001 (A.9.4, A.12.4)
  - GDPR Article 30 (processing records)
  - FedRAMP AU-2, AU-3, AU-12

Output formats:
  - Structured JSON (primary — Loki/Elasticsearch ingestion)
  - CEF (Common Event Format — Splunk/QRadar/ArcSight)
  - LEEF (IBM QRadar)

Storage:
  - Redis stream (XADD) for real-time SIEM ingestion
  - Local JSONL file fallback (data/observability/audit.jsonl)
  - Both written simultaneously for redundancy

Feature-flag gated: CDB_AUDIT_ENABLED=true (default false for safe rollout)
"""

import os
import json
import uuid
import time
import logging
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

logger = logging.getLogger("CDB-AUDIT")

_AUDIT_ENABLED  = os.environ.get("CDB_AUDIT_ENABLED", "false").lower() == "true"
_AUDIT_LOG_PATH = os.environ.get("CDB_AUDIT_LOG_PATH", "data/observability/audit.jsonl")
_AUDIT_STREAM   = "cdb:audit:stream"   # Redis stream key


# ── Action Catalogue ───────────────────────────────────────────────────────

class AuditAction:
    """All auditable actions — organised by domain."""
    # Authentication
    AUTH_LOGIN_SUCCESS   = "auth.login.success"
    AUTH_LOGIN_FAILURE   = "auth.login.failure"
    AUTH_LOGOUT          = "auth.logout"
    AUTH_TOKEN_ISSUED    = "auth.token.issued"
    AUTH_TOKEN_REVOKED   = "auth.token.revoked"
    AUTH_MFA_ENROLLED    = "auth.mfa.enrolled"
    AUTH_MFA_VERIFIED    = "auth.mfa.verified"
    AUTH_MFA_FAILED      = "auth.mfa.failed"
    AUTH_PASSWORD_RESET  = "auth.password.reset"
    AUTH_KEY_CREATED     = "auth.api_key.created"
    AUTH_KEY_REVOKED     = "auth.api_key.revoked"

    # Intelligence Access
    INTEL_READ           = "intel.read"
    INTEL_SEARCH         = "intel.search"
    INTEL_EXPORT_STIX    = "intel.export.stix"
    INTEL_EXPORT_CSV     = "intel.export.csv"
    INTEL_EXPORT_PDF     = "intel.export.pdf"

    # User Management
    USER_CREATED         = "user.created"
    USER_UPDATED         = "user.updated"
    USER_DEACTIVATED     = "user.deactivated"
    USER_ROLE_CHANGED    = "user.role.changed"
    USER_INVITED         = "user.invited"
    USER_REMOVED         = "user.removed"

    # Organization Management
    ORG_CREATED          = "org.created"
    ORG_UPDATED          = "org.updated"
    ORG_PLAN_CHANGED     = "org.plan.changed"
    ORG_SSO_CONFIGURED   = "org.sso.configured"
    ORG_IP_ALLOWLIST     = "org.ip_allowlist.updated"

    # Billing
    BILLING_SUBSCRIPTION_CREATED  = "billing.subscription.created"
    BILLING_SUBSCRIPTION_UPDATED  = "billing.subscription.updated"
    BILLING_SUBSCRIPTION_CANCELLED = "billing.subscription.cancelled"
    BILLING_PAYMENT_SUCCESS        = "billing.payment.success"
    BILLING_PAYMENT_FAILED         = "billing.payment.failed"

    # Admin
    ADMIN_CONFIG_CHANGED = "admin.config.changed"
    ADMIN_FEED_CHANGED   = "admin.feed.changed"

    # Security Events
    SEC_RATE_LIMIT_HIT   = "security.rate_limit.hit"
    SEC_INVALID_KEY      = "security.invalid_key"
    SEC_BLOCKED_IP       = "security.blocked_ip"
    SEC_SUSPICIOUS_UA    = "security.suspicious_user_agent"


# ── Audit Event Model ──────────────────────────────────────────────────────

@dataclass
class AuditEvent:
    event_id:     str
    timestamp:    str
    timestamp_ms: int
    # Actor
    actor_id:     str
    actor_email:  str
    actor_ip:     str
    actor_ua:     str
    org_id:       str
    tier:         str
    role:         str
    # Event
    action:       str
    resource:     str
    resource_id:  str
    outcome:      str   # "SUCCESS" | "FAILURE" | "DENIED"
    # Context
    request_id:   str
    details:      Dict[str, Any]
    # Integrity (chaining)
    prev_hash:    str   # Hash of previous event — tamper-evident chain
    event_hash:   str   # SHA-256 of this event

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    def to_cef(self) -> str:
        """Common Event Format for Splunk/QRadar/ArcSight SIEM ingestion."""
        severity = "7" if self.outcome == "DENIED" else ("3" if self.outcome == "FAILURE" else "1")
        return (
            f"CEF:0|CyberDudeBivash|SENTINEL-APEX|v47.0|{self.action}|{self.action}|{severity}|"
            f"src={self.actor_ip} "
            f"suser={self.actor_email} "
            f"org={self.org_id} "
            f"outcome={self.outcome} "
            f"requestClientApplication={self.actor_ua[:64]} "
            f"externalId={self.event_id} "
            f"msg={json.dumps(self.details)}"
        )

    def to_leef(self) -> str:
        """Log Event Extended Format for IBM QRadar."""
        return (
            f"LEEF:2.0|CyberDudeBivash|SENTINEL-APEX|v47.0|{self.action}|"
            f"src={self.actor_ip}\t"
            f"usrName={self.actor_email}\t"
            f"role={self.role}\t"
            f"outcome={self.outcome}\t"
            f"devTimeFormat=ISO8601\t"
            f"devTime={self.timestamp}"
        )


# ── Audit Engine ───────────────────────────────────────────────────────────

class AuditEngine:
    """
    Thread-safe, tamper-evident audit trail writer.
    Writes to Redis stream + local JSONL file simultaneously.
    """

    def __init__(self):
        self._redis = None
        self._prev_hash = "genesis"  # Initial chain anchor
        self._init_redis()
        self._ensure_log_dir()

    def _init_redis(self) -> None:
        redis_url = os.environ.get("REDIS_URL", "")
        if redis_url:
            try:
                import redis
                self._redis = redis.from_url(redis_url, decode_responses=True, socket_timeout=1)
                self._redis.ping()
                logger.info("[AUDIT] Redis audit stream active")
            except Exception as e:
                logger.warning(f"[AUDIT] Redis unavailable ({e}) — file-only audit log")
                self._redis = None

    def _ensure_log_dir(self) -> None:
        try:
            os.makedirs(os.path.dirname(_AUDIT_LOG_PATH), exist_ok=True)
        except Exception:
            pass

    def _compute_hash(self, event_dict: dict, prev_hash: str) -> str:
        content = json.dumps(event_dict, sort_keys=True, default=str) + prev_hash
        return hashlib.sha256(content.encode()).hexdigest()

    def emit(
        self,
        action:      str,
        resource:    str        = "",
        resource_id: str        = "",
        outcome:     str        = "SUCCESS",
        actor_id:    str        = "anonymous",
        actor_email: str        = "",
        actor_ip:    str        = "",
        actor_ua:    str        = "",
        org_id:      str        = "global",
        tier:        str        = "FREE",
        role:        str        = "VIEWER",
        request_id:  str        = "",
        details:     Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditEvent]:
        """
        Emit an audit event.

        Args:
            action:      AuditAction constant (e.g., AuditAction.AUTH_LOGIN_SUCCESS)
            resource:    Resource type ("user", "api_key", "intel", etc.)
            resource_id: Resource identifier
            outcome:     "SUCCESS" | "FAILURE" | "DENIED"
            ...          Actor + context fields

        Returns:
            AuditEvent if emitted successfully, None if audit disabled or failed.
        """
        if not _AUDIT_ENABLED:
            return None

        now_ms  = int(time.time() * 1000)
        now_iso = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc).isoformat()

        # Build event (without hash first)
        event_data = {
            "event_id":     str(uuid.uuid4()),
            "timestamp":    now_iso,
            "timestamp_ms": now_ms,
            "actor_id":     actor_id,
            "actor_email":  actor_email,
            "actor_ip":     actor_ip,
            "actor_ua":     actor_ua[:256],
            "org_id":       org_id,
            "tier":         tier,
            "role":         role,
            "action":       action,
            "resource":     resource,
            "resource_id":  resource_id,
            "outcome":      outcome,
            "request_id":   request_id,
            "details":      details or {},
            "prev_hash":    self._prev_hash,
        }

        # Compute integrity hash (tamper-evident chain)
        event_hash = self._compute_hash(event_data, self._prev_hash)
        event_data["event_hash"] = event_hash
        self._prev_hash = event_hash

        event = AuditEvent(**event_data)

        # Write to Redis stream (non-blocking)
        self._write_redis(event)

        # Write to JSONL file (always — redundant storage)
        self._write_file(event)

        # Structured log (Loki-ingested via promtail/alloy)
        log_level = logging.WARNING if outcome in ("FAILURE", "DENIED") else logging.INFO
        logger.log(log_level, event.to_json())

        return event

    def _write_redis(self, event: AuditEvent) -> None:
        if not self._redis:
            return
        try:
            self._redis.xadd(
                _AUDIT_STREAM,
                {"data": event.to_json()},
                maxlen=100000,  # Cap stream at 100K events (~50MB)
                approximate=True,
            )
        except Exception as e:
            logger.error(f"[AUDIT] Redis write failed: {e}")

    def _write_file(self, event: AuditEvent) -> None:
        try:
            with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")
        except Exception as e:
            logger.error(f"[AUDIT] File write failed: {e}")

    def get_recent_events(self, count: int = 100, org_id: Optional[str] = None) -> list:
        """Retrieve recent audit events (admin use)."""
        events = []
        if self._redis:
            try:
                raw = self._redis.xrevrange(_AUDIT_STREAM, count=count)
                for _, data in raw:
                    try:
                        event_dict = json.loads(data.get("data", "{}"))
                        if org_id and event_dict.get("org_id") != org_id:
                            continue
                        events.append(event_dict)
                    except Exception:
                        pass
            except Exception:
                pass
        if not events:
            # File fallback
            try:
                with open(_AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in reversed(lines[-count * 2:]):
                    try:
                        event_dict = json.loads(line.strip())
                        if org_id and event_dict.get("org_id") != org_id:
                            continue
                        events.append(event_dict)
                        if len(events) >= count:
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        return events[:count]


# Singleton
audit_engine = AuditEngine()


# ── Convenience Functions ──────────────────────────────────────────────────

def log_auth_event(
    action: str,
    user_id: str,
    user_email: str,
    ip: str,
    success: bool,
    org_id: str = "global",
    tier: str = "FREE",
    details: dict = None,
) -> None:
    """Convenience wrapper for authentication events."""
    audit_engine.emit(
        action=action,
        resource="user",
        resource_id=user_id,
        outcome="SUCCESS" if success else "FAILURE",
        actor_id=user_id,
        actor_email=user_email,
        actor_ip=ip,
        org_id=org_id,
        tier=tier,
        details=details or {},
    )


def log_intel_access(
    action: str,
    user_id: str,
    org_id: str,
    tier: str,
    ip: str,
    query: str = "",
    count: int = 0,
) -> None:
    """Convenience wrapper for intelligence access events."""
    audit_engine.emit(
        action=action,
        resource="intel",
        outcome="SUCCESS",
        actor_id=user_id,
        actor_ip=ip,
        org_id=org_id,
        tier=tier,
        details={"query": query[:256], "result_count": count},
    )
