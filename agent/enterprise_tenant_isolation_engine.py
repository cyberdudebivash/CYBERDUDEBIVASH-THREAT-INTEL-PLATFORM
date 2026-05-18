"""
CYBERDUDEBIVASH® SENTINEL APEX
ENTERPRISE TENANT ISOLATION & RBAC ENGINE v1.0
Phase 6: Multi-tenant data isolation, role-based access control,
audit logging, SLA enforcement, and resource quota management.
Zero cross-tenant data leakage. Full audit trail. Deterministic.
"""
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("CDB-TENANT-ENGINE")

# ── ENUMS ──────────────────────────────────────────────────────────────────────

class TierLevel(str, Enum):
    FREE       = "free"
    PRO        = "pro"
    ENTERPRISE = "enterprise"
    INTERNAL   = "internal"   # CDB admin / CI pipelines

class Permission(str, Enum):
    READ_PREVIEW      = "read:preview"
    READ_FEED         = "read:feed"
    READ_IOC          = "read:ioc"
    READ_STIX         = "read:stix"
    READ_DETECTION    = "read:detection"
    READ_AI_SCORES    = "read:ai_scores"
    READ_FULL_AI      = "read:full_ai"
    WRITE_API_KEY     = "write:api_key"
    WRITE_WEBHOOK     = "write:webhook"
    ADMIN_TENANT      = "admin:tenant"
    ADMIN_PLATFORM    = "admin:platform"

class AuditAction(str, Enum):
    API_REQUEST       = "api_request"
    AUTH_SUCCESS      = "auth_success"
    AUTH_FAILURE      = "auth_failure"
    TIER_UPGRADE      = "tier_upgrade"
    RATE_LIMIT_HIT    = "rate_limit_hit"
    DATA_ACCESS       = "data_access"
    KEY_CREATED       = "key_created"
    KEY_REVOKED       = "key_revoked"
    QUOTA_EXCEEDED    = "quota_exceeded"
    POLICY_VIOLATION  = "policy_violation"

# ── TIER PERMISSION MAP ────────────────────────────────────────────────────────

TIER_PERMISSIONS: Dict[TierLevel, Set[Permission]] = {
    TierLevel.FREE: {
        Permission.READ_PREVIEW,
    },
    TierLevel.PRO: {
        Permission.READ_PREVIEW,
        Permission.READ_FEED,
        Permission.READ_IOC,
        Permission.READ_DETECTION,
        Permission.READ_AI_SCORES,
        Permission.WRITE_API_KEY,
    },
    TierLevel.ENTERPRISE: {
        Permission.READ_PREVIEW,
        Permission.READ_FEED,
        Permission.READ_IOC,
        Permission.READ_STIX,
        Permission.READ_DETECTION,
        Permission.READ_AI_SCORES,
        Permission.READ_FULL_AI,
        Permission.WRITE_API_KEY,
        Permission.WRITE_WEBHOOK,
        Permission.ADMIN_TENANT,
    },
    TierLevel.INTERNAL: {p for p in Permission},  # All permissions
}

# ── RATE LIMIT CONFIG ─────────────────────────────────────────────────────────

TIER_RATE_LIMITS: Dict[TierLevel, Dict[str, int]] = {
    TierLevel.FREE:       {"per_minute": 60,   "per_day": 100},
    TierLevel.PRO:        {"per_minute": 500,  "per_day": 5000},
    TierLevel.ENTERPRISE: {"per_minute": 2000, "per_day": 999999},
    TierLevel.INTERNAL:   {"per_minute": 9999, "per_day": 999999},
}

TIER_ITEM_LIMITS: Dict[TierLevel, int] = {
    TierLevel.FREE:       10,
    TierLevel.PRO:        100,
    TierLevel.ENTERPRISE: 9999,
    TierLevel.INTERNAL:   9999,
}

TIER_KEY_LIMITS: Dict[TierLevel, int] = {
    TierLevel.FREE:       2,
    TierLevel.PRO:        10,
    TierLevel.ENTERPRISE: 50,
    TierLevel.INTERNAL:   999,
}

# ── DATA CLASSES ──────────────────────────────────────────────────────────────

@dataclass
class TenantProfile:
    tenant_id:     str
    email:         str
    tier:          TierLevel
    api_keys:      List[str] = field(default_factory=list)
    created_at:    str = ""
    last_active:   str = ""
    daily_calls:   int = 0
    minute_calls:  int = 0
    last_minute_ts: float = 0.0
    last_day_ts:   float = 0.0
    sla_violations: int = 0

    def has_permission(self, perm: Permission) -> bool:
        return perm in TIER_PERMISSIONS.get(self.tier, set())

    def get_item_limit(self) -> int:
        return TIER_ITEM_LIMITS.get(self.tier, 10)

    def get_rate_limit(self) -> Dict[str, int]:
        return TIER_RATE_LIMITS.get(self.tier, {"per_minute": 60, "per_day": 100})

@dataclass
class AccessDecision:
    allowed:        bool
    tenant_id:      str
    tier:           str
    permission:     str
    reason:         str
    rate_limit_remaining: Dict[str, int] = field(default_factory=dict)
    item_limit:     int = 10
    audit_id:       str = ""
    decided_at:     str = ""

@dataclass
class AuditEvent:
    audit_id:     str
    tenant_id:    str
    action:       AuditAction
    endpoint:     str
    permission:   str
    outcome:      str   # ALLOWED / DENIED
    reason:       str
    ip_hash:      str   # hashed for privacy
    timestamp:    str
    extra:        Dict = field(default_factory=dict)

@dataclass
class QuotaStatus:
    tenant_id:        str
    tier:             str
    minute_used:      int
    minute_limit:     int
    minute_remaining: int
    day_used:         int
    day_limit:        int
    day_remaining:    int
    key_count:        int
    key_limit:        int
    within_quota:     bool
    checked_at:       str

@dataclass
class TenantIsolationReport:
    total_tenants:     int
    tier_distribution: Dict[str, int]
    permission_audit:  Dict[str, int]   # permission → grant count
    rate_limit_hits:   int
    quota_violations:  int
    sla_violations:    int
    policy_violations: int
    audit_event_count: int
    isolation_score:   float  # 0-100
    integrity_status:  str    # SECURE / DEGRADED / CRITICAL
    recommendations:   List[str]
    generated_at:      str

# ── IOC SCRUBBING (cross-tenant data isolation) ───────────────────────────────

class TenantDataScrubber:
    """
    Strips fields that must NOT cross tenant boundaries.
    Applies per-tier field visibility rules.
    Zero cross-contamination guarantee.
    """
    # Fields visible only at ENTERPRISE+
    ENTERPRISE_ONLY_FIELDS = {"iocs", "stix_id", "stix_bundle"}
    # Fields visible only at PRO+
    PRO_ONLY_FIELDS        = {"detection_rules", "ttps", "ioc_count", "apex_ai"}
    # Fields stripped for FREE tier
    FREE_STRIP_FIELDS      = ENTERPRISE_ONLY_FIELDS | PRO_ONLY_FIELDS | {
        "actor_attribution", "campaign", "kill_chain"
    }

    def scrub(self, advisory: Dict, tier: TierLevel) -> Dict:
        """Return a copy of the advisory with fields stripped per tier."""
        advisory = dict(advisory)  # shallow copy — no mutation of original
        if tier == TierLevel.FREE:
            for f in self.FREE_STRIP_FIELDS:
                advisory.pop(f, None)
            # Paywall markers
            advisory["ioc_paywall"]       = True
            advisory["detection_paywall"] = True
        elif tier == TierLevel.PRO:
            for f in self.ENTERPRISE_ONLY_FIELDS:
                advisory.pop(f, None)
            advisory["stix_paywall"] = True
        # ENTERPRISE and INTERNAL get full data
        return advisory

    def scrub_batch(self, advisories: List[Dict], tier: TierLevel) -> List[Dict]:
        return [self.scrub(a, tier) for a in advisories]

# ── RBAC ENGINE ───────────────────────────────────────────────────────────────

class RBACEngine:
    """
    Role-based access control. Deterministic, no external calls.
    All decisions logged to audit trail.
    """

    def __init__(self):
        self._tenants: Dict[str, TenantProfile] = {}
        self._audit:   List[AuditEvent]          = []
        self._scrubber = TenantDataScrubber()

    # ── tenant management ──────────────────────────────────────────────────────

    def register_tenant(self, tenant_id: str, email: str, tier: TierLevel) -> TenantProfile:
        now = datetime.now(timezone.utc).isoformat()
        profile = TenantProfile(
            tenant_id=tenant_id,
            email=email,
            tier=tier,
            created_at=now,
            last_active=now,
        )
        self._tenants[tenant_id] = profile
        logger.info(f"[RBAC] Registered tenant {tenant_id} tier={tier.value}")
        return profile

    def get_tenant(self, tenant_id: str) -> Optional[TenantProfile]:
        return self._tenants.get(tenant_id)

    def upgrade_tier(self, tenant_id: str, new_tier: TierLevel) -> bool:
        profile = self._tenants.get(tenant_id)
        if not profile:
            return False
        old_tier = profile.tier
        profile.tier = new_tier
        self._emit_audit(AuditEvent(
            audit_id=self._audit_id(),
            tenant_id=tenant_id,
            action=AuditAction.TIER_UPGRADE,
            endpoint="internal",
            permission="admin:platform",
            outcome="ALLOWED",
            reason=f"Tier upgraded {old_tier.value} → {new_tier.value}",
            ip_hash="internal",
            timestamp=datetime.now(timezone.utc).isoformat(),
            extra={"old_tier": old_tier.value, "new_tier": new_tier.value},
        ))
        return True

    # ── access decisions ───────────────────────────────────────────────────────

    def check_access(
        self,
        tenant_id: str,
        permission: Permission,
        endpoint: str = "",
        ip: str = "",
        limit_override: Optional[int] = None,
    ) -> AccessDecision:
        now_ts  = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        ip_hash = hashlib.md5(ip.encode(), usedforsecurity=False).hexdigest()[:12] if ip else "unknown"
        audit_id = self._audit_id()

        profile = self._tenants.get(tenant_id)
        if not profile:
            decision = AccessDecision(
                allowed=False, tenant_id=tenant_id, tier="unknown",
                permission=permission.value, reason="TENANT_NOT_FOUND",
                audit_id=audit_id, decided_at=now_iso,
            )
            self._emit_audit(AuditEvent(
                audit_id=audit_id, tenant_id=tenant_id,
                action=AuditAction.AUTH_FAILURE, endpoint=endpoint,
                permission=permission.value, outcome="DENIED",
                reason="TENANT_NOT_FOUND", ip_hash=ip_hash, timestamp=now_iso,
            ))
            return decision

        # Update last_active
        profile.last_active = now_iso

        # Permission check
        if not profile.has_permission(permission):
            decision = AccessDecision(
                allowed=False, tenant_id=tenant_id, tier=profile.tier.value,
                permission=permission.value, reason="PERMISSION_DENIED",
                item_limit=profile.get_item_limit(),
                audit_id=audit_id, decided_at=now_iso,
            )
            self._emit_audit(AuditEvent(
                audit_id=audit_id, tenant_id=tenant_id,
                action=AuditAction.POLICY_VIOLATION, endpoint=endpoint,
                permission=permission.value, outcome="DENIED",
                reason=f"Tier {profile.tier.value} lacks {permission.value}",
                ip_hash=ip_hash, timestamp=now_iso,
            ))
            return decision

        # Rate limiting — per minute window
        rl = profile.get_rate_limit()
        if now_ts - profile.last_minute_ts > 60:
            profile.minute_calls   = 0
            profile.last_minute_ts = now_ts
        if now_ts - profile.last_day_ts > 86400:
            profile.daily_calls  = 0
            profile.last_day_ts  = now_ts

        profile.minute_calls += 1
        profile.daily_calls  += 1

        if profile.minute_calls > rl["per_minute"]:
            self._emit_audit(AuditEvent(
                audit_id=audit_id, tenant_id=tenant_id,
                action=AuditAction.RATE_LIMIT_HIT, endpoint=endpoint,
                permission=permission.value, outcome="DENIED",
                reason=f"Rate limit: {profile.minute_calls}/{rl['per_minute']} per minute",
                ip_hash=ip_hash, timestamp=now_iso,
            ))
            return AccessDecision(
                allowed=False, tenant_id=tenant_id, tier=profile.tier.value,
                permission=permission.value, reason="RATE_LIMIT_EXCEEDED",
                rate_limit_remaining={"minute": 0, "day": max(0, rl["per_day"] - profile.daily_calls)},
                item_limit=profile.get_item_limit(),
                audit_id=audit_id, decided_at=now_iso,
            )

        if profile.daily_calls > rl["per_day"]:
            self._emit_audit(AuditEvent(
                audit_id=audit_id, tenant_id=tenant_id,
                action=AuditAction.QUOTA_EXCEEDED, endpoint=endpoint,
                permission=permission.value, outcome="DENIED",
                reason=f"Daily quota: {profile.daily_calls}/{rl['per_day']}",
                ip_hash=ip_hash, timestamp=now_iso,
            ))
            return AccessDecision(
                allowed=False, tenant_id=tenant_id, tier=profile.tier.value,
                permission=permission.value, reason="DAILY_QUOTA_EXCEEDED",
                rate_limit_remaining={"minute": max(0, rl["per_minute"] - profile.minute_calls), "day": 0},
                item_limit=profile.get_item_limit(),
                audit_id=audit_id, decided_at=now_iso,
            )

        # ALLOWED
        self._emit_audit(AuditEvent(
            audit_id=audit_id, tenant_id=tenant_id,
            action=AuditAction.DATA_ACCESS, endpoint=endpoint,
            permission=permission.value, outcome="ALLOWED",
            reason="OK", ip_hash=ip_hash, timestamp=now_iso,
        ))
        return AccessDecision(
            allowed=True, tenant_id=tenant_id, tier=profile.tier.value,
            permission=permission.value, reason="OK",
            rate_limit_remaining={
                "minute": max(0, rl["per_minute"] - profile.minute_calls),
                "day":    max(0, rl["per_day"]    - profile.daily_calls),
            },
            item_limit=limit_override or profile.get_item_limit(),
            audit_id=audit_id, decided_at=now_iso,
        )

    # ── quota status ───────────────────────────────────────────────────────────

    def get_quota_status(self, tenant_id: str) -> Optional[QuotaStatus]:
        profile = self._tenants.get(tenant_id)
        if not profile:
            return None
        rl = profile.get_rate_limit()
        return QuotaStatus(
            tenant_id=tenant_id,
            tier=profile.tier.value,
            minute_used=profile.minute_calls,
            minute_limit=rl["per_minute"],
            minute_remaining=max(0, rl["per_minute"] - profile.minute_calls),
            day_used=profile.daily_calls,
            day_limit=rl["per_day"],
            day_remaining=max(0, rl["per_day"] - profile.daily_calls),
            key_count=len(profile.api_keys),
            key_limit=TIER_KEY_LIMITS.get(profile.tier, 2),
            within_quota=(profile.minute_calls <= rl["per_minute"] and
                          profile.daily_calls  <= rl["per_day"]),
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    # ── audit ──────────────────────────────────────────────────────────────────

    def _emit_audit(self, event: AuditEvent) -> None:
        self._audit.append(event)
        # Persist to JSONL (append-only, ordered)
        log_path = "data/audit/tenant_audit.jsonl"
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "audit_id":   event.audit_id,
                    "tenant_id":  event.tenant_id,
                    "action":     event.action.value,
                    "endpoint":   event.endpoint,
                    "permission": event.permission,
                    "outcome":    event.outcome,
                    "reason":     event.reason,
                    "ip_hash":    event.ip_hash,
                    "timestamp":  event.timestamp,
                    "extra":      event.extra,
                }, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning(f"[RBAC] Audit write failed: {e}")

    def get_audit_trail(self, tenant_id: Optional[str] = None,
                        limit: int = 100) -> List[Dict]:
        events = self._audit
        if tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]
        return [
            {"audit_id": e.audit_id, "tenant_id": e.tenant_id,
             "action": e.action.value, "outcome": e.outcome,
             "reason": e.reason, "timestamp": e.timestamp}
            for e in events[-limit:]
        ]

    @staticmethod
    def _audit_id() -> str:
        return hashlib.md5(
            f"{time.time_ns()}".encode()
        , usedforsecurity=False).hexdigest()[:16]

# ── SLA MONITOR ───────────────────────────────────────────────────────────────

class SLAMonitor:
    """
    Tracks SLA commitments per tier.
    FREE → best-effort  PRO → 99.5%  ENTERPRISE → 99.9%
    """
    SLA_TARGETS = {
        TierLevel.FREE:       0.0,
        TierLevel.PRO:        99.5,
        TierLevel.ENTERPRISE: 99.9,
        TierLevel.INTERNAL:   99.9,
    }

    def __init__(self):
        self._windows: Dict[str, List[bool]] = {}  # tenant_id → [success, ...]

    def record(self, tenant_id: str, success: bool, tier: TierLevel) -> None:
        if tenant_id not in self._windows:
            self._windows[tenant_id] = []
        wins = self._windows[tenant_id]
        wins.append(success)
        if len(wins) > 1000:
            wins.pop(0)

    def get_uptime(self, tenant_id: str) -> float:
        wins = self._windows.get(tenant_id, [])
        if not wins:
            return 100.0
        return 100.0 * sum(wins) / len(wins)

    def is_sla_breached(self, tenant_id: str, tier: TierLevel) -> bool:
        uptime = self.get_uptime(tenant_id)
        target = self.SLA_TARGETS.get(tier, 0.0)
        return uptime < target

# ── ISOLATION REPORT ──────────────────────────────────────────────────────────

class TenantIsolationReporter:
    def __init__(self, rbac: RBACEngine, sla: SLAMonitor):
        self._rbac = rbac
        self._sla  = sla

    def generate(self) -> TenantIsolationReport:
        tenants  = self._rbac._tenants
        audit    = self._rbac._audit

        tier_dist: Dict[str, int] = {}
        perm_audit: Dict[str, int] = {}
        rate_hits = 0
        quota_viol = 0
        sla_viol   = 0
        policy_viol = 0

        for ev in audit:
            if ev.action == AuditAction.RATE_LIMIT_HIT:
                rate_hits += 1
            elif ev.action == AuditAction.QUOTA_EXCEEDED:
                quota_viol += 1
            elif ev.action == AuditAction.POLICY_VIOLATION:
                policy_viol += 1
            if ev.outcome == "ALLOWED":
                perm_audit[ev.permission] = perm_audit.get(ev.permission, 0) + 1

        for t in tenants.values():
            tier_dist[t.tier.value] = tier_dist.get(t.tier.value, 0) + 1
            if self._sla.is_sla_breached(t.tenant_id, t.tier):
                sla_viol += 1

        # Isolation score: starts at 100, deduct per violation type
        score = 100.0
        score -= min(20.0, policy_viol * 5.0)
        score -= min(15.0, rate_hits   * 0.5)
        score -= min(10.0, sla_viol    * 5.0)
        score = max(0.0, score)

        if score >= 90:
            status = "SECURE"
        elif score >= 70:
            status = "DEGRADED"
        else:
            status = "CRITICAL"

        recs: List[str] = []
        if policy_viol > 0:
            recs.append(f"Review {policy_viol} policy violation(s) — possible tier abuse")
        if rate_hits > 5:
            recs.append("High rate-limit hit rate — consider adaptive throttling")
        if sla_viol > 0:
            recs.append(f"{sla_viol} SLA breach(es) detected — investigate pipeline latency")

        return TenantIsolationReport(
            total_tenants=len(tenants),
            tier_distribution=tier_dist,
            permission_audit=perm_audit,
            rate_limit_hits=rate_hits,
            quota_violations=quota_viol,
            sla_violations=sla_viol,
            policy_violations=policy_viol,
            audit_event_count=len(audit),
            isolation_score=round(score, 1),
            integrity_status=status,
            recommendations=recs,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

# ── MASTER ENGINE ─────────────────────────────────────────────────────────────

class EnterpriseTenantIsolationEngine:
    """
    Master engine: RBAC + data scrubbing + SLA + audit + isolation reporting.
    Non-blocking, deterministic, zero cross-tenant leakage.
    """

    def __init__(self):
        self.rbac     = RBACEngine()
        self.sla      = SLAMonitor()
        self.scrubber = TenantDataScrubber()
        self.reporter = TenantIsolationReporter(self.rbac, self.sla)
        self._output_dir = "data/tenant"
        os.makedirs(self._output_dir, exist_ok=True)
        os.makedirs("data/audit", exist_ok=True)

    def register_tenant(self, tenant_id: str, email: str,
                        tier_str: str) -> TenantProfile:
        try:
            tier = TierLevel(tier_str.lower())
        except ValueError:
            tier = TierLevel.FREE
        return self.rbac.register_tenant(tenant_id, email, tier)

    def gate_request(
        self,
        tenant_id: str,
        permission_str: str,
        endpoint: str = "",
        ip: str = "",
    ) -> AccessDecision:
        try:
            perm = Permission(permission_str)
        except ValueError:
            perm = Permission.READ_PREVIEW
        decision = self.rbac.check_access(tenant_id, perm, endpoint, ip)
        self.sla.record(tenant_id, decision.allowed,
                        self.rbac.get_tenant(tenant_id).tier
                        if self.rbac.get_tenant(tenant_id) else TierLevel.FREE)
        return decision

    def apply_tenant_view(
        self, advisory: Dict, tenant_id: str
    ) -> Dict:
        """Return tier-scrubbed advisory for this tenant. Zero mutation of original."""
        profile = self.rbac.get_tenant(tenant_id)
        tier    = profile.tier if profile else TierLevel.FREE
        return self.scrubber.scrub(advisory, tier)

    def apply_tenant_view_batch(
        self, advisories: List[Dict], tenant_id: str
    ) -> List[Dict]:
        profile = self.rbac.get_tenant(tenant_id)
        tier    = profile.tier if profile else TierLevel.FREE
        limit   = profile.get_item_limit() if profile else 10
        return self.scrubber.scrub_batch(advisories[:limit], tier)

    def generate_report(self) -> TenantIsolationReport:
        report = self.reporter.generate()
        out = {
            "total_tenants":     report.total_tenants,
            "tier_distribution": report.tier_distribution,
            "permission_audit":  report.permission_audit,
            "rate_limit_hits":   report.rate_limit_hits,
            "quota_violations":  report.quota_violations,
            "sla_violations":    report.sla_violations,
            "policy_violations": report.policy_violations,
            "audit_event_count": report.audit_event_count,
            "isolation_score":   report.isolation_score,
            "integrity_status":  report.integrity_status,
            "recommendations":   report.recommendations,
            "generated_at":      report.generated_at,
        }
        path = os.path.join(self._output_dir, "tenant_isolation_report.json")
        tmp  = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        return report


# ── SMOKE TEST ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    engine = EnterpriseTenantIsolationEngine()

    # Register 3 tenants
    engine.register_tenant("t001", "free@test.com",        "free")
    engine.register_tenant("t002", "pro@test.com",         "pro")
    engine.register_tenant("t003", "enterprise@test.com",  "enterprise")

    # Simulate requests
    sample_advisory = {
        "id": "adv001", "title": "Critical RCE — CVE-2026-9999",
        "severity": "CRITICAL", "risk_score": 9.8,
        "iocs": {"ips": ["1.2.3.4"], "domains": ["evil.test"]},
        "stix_id": "indicator--abc123",
        "detection_rules": {"sigma": "title: test"},
        "ttps": ["T1190"],
        "apex_ai": {"priority": "P1"},
        "ioc_count": 2,
    }

    results = []
    for (tid, perm, ep) in [
        ("t001", "read:preview", "/api/preview"),
        ("t001", "read:ioc",     "/api/feed"),   # should fail
        ("t002", "read:ioc",     "/api/feed"),   # should pass
        ("t002", "read:stix",    "/api/stix"),   # should fail (PRO)
        ("t003", "read:stix",    "/api/stix"),   # should pass
        ("t003", "admin:platform", "/admin"),    # should fail (not INTERNAL)
    ]:
        d = engine.gate_request(tid, perm, ep)
        results.append(f"  {'✓' if d.allowed else '✗'} [{tid}] {perm} → {d.reason}")

    # Data scrubbing test
    free_view = engine.apply_tenant_view(sample_advisory, "t001")
    pro_view  = engine.apply_tenant_view(sample_advisory, "t002")
    ent_view  = engine.apply_tenant_view(sample_advisory, "t003")

    # Report
    report = engine.generate_report()

    print("\n[TENANT-ISOLATION] Smoke Test")
    for r in results:
        print(r)
    print(f"\n  FREE view fields:       {sorted(free_view.keys())}")
    print(f"  PRO  view fields:       {sorted(pro_view.keys())}")
    print(f"  ENT  view has STIX:     {'stix_id' in ent_view}")
    print(f"\n  Isolation Score:        {report.isolation_score}")
    print(f"  Integrity Status:       {report.integrity_status}")
    print(f"  Audit Events:           {report.audit_event_count}")
    print(f"  Policy Violations:      {report.policy_violations}")
    print(f"  Tier Distribution:      {report.tier_distribution}")
