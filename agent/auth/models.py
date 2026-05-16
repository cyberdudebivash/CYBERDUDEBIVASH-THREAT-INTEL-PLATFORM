#!/usr/bin/env python3
"""
agent/auth/models.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE IDENTITY & TENANCY DATA MODELS

Defines the core organizational model for multi-tenant enterprise deployments:
  Organization → Workspaces → Users → API Keys

Design principles:
  - All models are pure Python dataclasses (no ORM dependency)
  - Serializable to/from JSON and Redis
  - Additive to existing 4-tier API key model (backward compatible)
  - ID format: deterministic prefixes for easy log triage

Storage backends (in priority order):
  1. Redis (REDIS_URL env var) — fast, distributed
  2. JSON file (data/orgs/) — fallback, single-node

All fields have safe defaults — no required fields block existing flows.
"""

import os
import json
import uuid
import secrets
import hashlib
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("CDB-AUTH-MODELS")


# ── ID Generators ──────────────────────────────────────────────────────────

def _new_org_id()       -> str: return f"org_{uuid.uuid4().hex[:12]}"
def _new_workspace_id() -> str: return f"ws_{uuid.uuid4().hex[:12]}"
def _new_user_id()      -> str: return f"usr_{uuid.uuid4().hex[:12]}"
def _new_key_id()       -> str: return f"key_{uuid.uuid4().hex[:10]}"
def _now_iso()          -> str: return datetime.now(timezone.utc).isoformat()


# ── Tier / Plan Constants ──────────────────────────────────────────────────

class Plan:
    FREE       = "FREE"
    PRO        = "PRO"
    ENTERPRISE = "ENTERPRISE"
    MSSP       = "MSSP"


class Role:
    OWNER    = "OWNER"     # Full org control
    ADMIN    = "ADMIN"     # Manage users/workspaces, no billing
    ANALYST  = "ANALYST"   # Read/export intel, manage own API keys
    VIEWER   = "VIEWER"    # Read-only intel access
    API_ONLY = "API_ONLY"  # Machine accounts — no UI access


# ── Feature Set per Plan ───────────────────────────────────────────────────

PLAN_FEATURES: Dict[str, Dict[str, Any]] = {
    Plan.FREE: {
        "api_calls_per_hour":  100,
        "max_users":           1,
        "max_workspaces":      1,
        "max_api_keys":        2,
        "stix_export":         False,
        "csv_export":          True,
        "ioc_details":         False,
        "actor_intel":         False,
        "darkweb_intel":       False,
        "ai_analyst":          False,
        "custom_feeds":        False,
        "siem_integration":    False,
        "sso":                 False,
        "mfa_required":        False,
        "audit_log":           False,
        "sla_tier":            None,
    },
    Plan.PRO: {
        "api_calls_per_hour":  2000,
        "max_users":           3,
        "max_workspaces":      1,
        "max_api_keys":        10,
        "stix_export":         True,
        "csv_export":          True,
        "ioc_details":         True,
        "actor_intel":         False,
        "darkweb_intel":       False,
        "ai_analyst":          True,
        "custom_feeds":        False,
        "siem_integration":    True,
        "sso":                 False,
        "mfa_required":        False,
        "audit_log":           False,
        "sla_tier":            "99%",
    },
    Plan.ENTERPRISE: {
        "api_calls_per_hour":  10000,
        "max_users":           25,
        "max_workspaces":      10,
        "max_api_keys":        50,
        "stix_export":         True,
        "csv_export":          True,
        "ioc_details":         True,
        "actor_intel":         True,
        "darkweb_intel":       True,
        "ai_analyst":          True,
        "custom_feeds":        False,
        "siem_integration":    True,
        "sso":                 True,
        "mfa_required":        True,
        "audit_log":           True,
        "sla_tier":            "99.5%",
    },
    Plan.MSSP: {
        "api_calls_per_hour":  100000,
        "max_users":           -1,   # Unlimited
        "max_workspaces":      -1,
        "max_api_keys":        -1,
        "stix_export":         True,
        "csv_export":          True,
        "ioc_details":         True,
        "actor_intel":         True,
        "darkweb_intel":       True,
        "ai_analyst":          True,
        "custom_feeds":        True,
        "siem_integration":    True,
        "sso":                 True,
        "mfa_required":        True,
        "audit_log":           True,
        "sla_tier":            "99.9%",
        "white_label":         True,
        "tenant_management":   True,
        "api_resale":          True,
    },
}


# ── Data Models ────────────────────────────────────────────────────────────

@dataclass
class APIKey:
    """API key credential attached to a user/org."""
    key_id:       str  = field(default_factory=_new_key_id)
    key_value:    str  = field(default_factory=lambda: f"cdb-{secrets.token_urlsafe(32)}")
    key_hash:     str  = ""          # SHA-256 of key_value (never store plaintext after creation)
    org_id:       str  = ""
    user_id:      str  = ""
    tier:         str  = Plan.FREE
    label:        str  = "Default"
    created_at:   str  = field(default_factory=_now_iso)
    expires_at:   Optional[str] = None
    last_used_at: Optional[str] = None
    is_active:    bool = True
    scopes:       List[str] = field(default_factory=lambda: ["intel:read"])
    ip_allowlist: List[str] = field(default_factory=list)  # Empty = any IP

    def __post_init__(self):
        if not self.key_hash and self.key_value:
            self.key_hash = hashlib.sha256(self.key_value.encode()).hexdigest()

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("key_value", None)  # Never serialize plaintext key after creation
        return d

    def to_dict_with_key(self) -> dict:
        """Include plaintext key — only for first-time delivery to customer."""
        return asdict(self)


@dataclass
class Workspace:
    """Logical namespace for team/project isolation within an Organization."""
    workspace_id:         str  = field(default_factory=_new_workspace_id)
    org_id:               str  = ""
    name:                 str  = "Default Workspace"
    description:          str  = ""
    created_by_user_id:   str  = ""
    created_at:           str  = field(default_factory=_now_iso)
    updated_at:           str  = field(default_factory=_now_iso)
    data_retention_days:  int  = 365
    is_active:            bool = True
    member_user_ids:      List[str] = field(default_factory=list)
    # Workspace-level feature overrides (inherits from org plan if empty)
    feature_overrides:    Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CDBUser:
    """Platform user within an Organization."""
    user_id:         str  = field(default_factory=_new_user_id)
    email:           str  = ""
    display_name:    str  = ""
    org_id:          str  = ""
    role:            str  = Role.ANALYST
    workspace_ids:   List[str] = field(default_factory=list)
    api_key_ids:     List[str] = field(default_factory=list)
    # Authentication state
    is_active:       bool = True
    email_verified:  bool = False
    mfa_enabled:     bool = False
    mfa_secret_enc:  Optional[str] = None    # Encrypted TOTP secret
    mfa_backup_codes_enc: Optional[str] = None  # Encrypted backup codes JSON
    # SSO federation
    sso_provider:    Optional[str] = None    # "google" | "microsoft" | "okta"
    sso_subject:     Optional[str] = None    # External IDP subject claim
    # Timestamps
    created_at:      str  = field(default_factory=_now_iso)
    updated_at:      str  = field(default_factory=_now_iso)
    last_login_at:   Optional[str] = None
    last_login_ip:   Optional[str] = None
    # Metadata
    timezone:        str  = "UTC"
    notification_prefs: Dict[str, bool] = field(default_factory=lambda: {
        "email_weekly_briefing": True,
        "email_critical_alerts": True,
        "email_billing":         True,
    })

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("mfa_secret_enc", None)         # Never expose MFA secret
        d.pop("mfa_backup_codes_enc", None)
        return d


@dataclass
class Organization:
    """Top-level multi-tenant isolation unit."""
    org_id:               str  = field(default_factory=_new_org_id)
    name:                 str  = ""
    slug:                 str  = ""  # URL-safe name for routing
    plan:                 str  = Plan.FREE
    owner_user_id:        str  = ""
    # Contact
    billing_email:        str  = ""
    technical_email:      str  = ""
    # Stripe
    stripe_customer_id:   Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    # SSO configuration
    sso_domain:           Optional[str] = None   # "acmecorp.com" → enforce SSO
    sso_provider:         Optional[str] = None   # "okta" | "google" | "microsoft"
    sso_config:           Dict[str, str] = field(default_factory=dict)
    # IP security
    allowed_ip_ranges:    List[str] = field(default_factory=list)
    # Status
    status:               str  = "active"   # active | suspended | cancelled
    created_at:           str  = field(default_factory=_now_iso)
    updated_at:           str  = field(default_factory=_now_iso)
    # Limits (from plan, can be overridden by admin)
    max_users:            int  = 1
    max_workspaces:       int  = 1
    max_api_keys:         int  = 2
    # Computed from plan
    features:             Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.features:
            self.features = PLAN_FEATURES.get(self.plan, PLAN_FEATURES[Plan.FREE]).copy()
        if not self.slug and self.name:
            self.slug = self.name.lower().replace(" ", "-").replace("_", "-")[:32]
        # Set max_* from plan
        plan_f = PLAN_FEATURES.get(self.plan, PLAN_FEATURES[Plan.FREE])
        if self.max_users == 1:    self.max_users     = plan_f.get("max_users", 1)
        if self.max_workspaces == 1: self.max_workspaces = plan_f.get("max_workspaces", 1)
        if self.max_api_keys == 2: self.max_api_keys  = plan_f.get("max_api_keys", 2)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("sso_config", None)  # SSO secrets not serialized to API responses
        return d

    def is_feature_enabled(self, feature: str) -> bool:
        return bool(self.features.get(feature, False))


# ── Persistence Layer ──────────────────────────────────────────────────────

class OrgRegistry:
    """
    Organization persistence — Redis first, JSON file fallback.
    All methods are safe to call even when Redis is unavailable.
    """

    _ORG_KEY_PREFIX  = "cdb:org:"
    _USER_KEY_PREFIX = "cdb:user:"
    _KEY_MAP_PREFIX  = "cdb:keymap:"  # sha256(api_key) → org_id
    _ORG_FILE        = "data/orgs/orgs.json"

    def __init__(self):
        self._redis = None
        redis_url = os.environ.get("REDIS_URL", "")
        if redis_url:
            try:
                import redis
                self._redis = redis.from_url(redis_url, decode_responses=True, socket_timeout=1)
                self._redis.ping()
                logger.info("[ORG-REGISTRY] Redis connected")
            except Exception as e:
                logger.warning(f"[ORG-REGISTRY] Redis unavailable ({e}) — file fallback active")
                self._redis = None

    # ── Organization CRUD ──────────────────────────────────────────────────

    def save_org(self, org: Organization) -> bool:
        data = json.dumps(org.to_dict())
        if self._redis:
            try:
                self._redis.set(f"{self._ORG_KEY_PREFIX}{org.org_id}", data, ex=60*60*24*365*5)
                return True
            except Exception as e:
                logger.error(f"[ORG-REGISTRY] Redis save failed: {e}")
        return self._file_append(self._ORG_FILE, org.org_id, org.to_dict())

    def get_org(self, org_id: str) -> Optional[Organization]:
        raw = None
        if self._redis:
            try:
                raw = self._redis.get(f"{self._ORG_KEY_PREFIX}{org_id}")
            except Exception:
                pass
        if not raw:
            raw = self._file_get(self._ORG_FILE, org_id)
        if raw:
            try:
                d = json.loads(raw) if isinstance(raw, str) else raw
                return Organization(**{k: v for k, v in d.items() if k in Organization.__dataclass_fields__})
            except Exception as e:
                logger.error(f"[ORG-REGISTRY] Deserialize failed: {e}")
        return None

    def get_org_by_api_key(self, api_key: str) -> Optional[str]:
        """Return org_id for a given API key (via hash map)."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        if self._redis:
            try:
                return self._redis.get(f"{self._KEY_MAP_PREFIX}{key_hash}")
            except Exception:
                pass
        return None

    def register_api_key(self, api_key_hash: str, org_id: str, ttl_days: int = 365 * 5) -> bool:
        """Map API key hash → org_id for fast lookup."""
        if self._redis:
            try:
                self._redis.set(f"{self._KEY_MAP_PREFIX}{api_key_hash}", org_id, ex=ttl_days * 86400)
                return True
            except Exception as e:
                logger.error(f"[ORG-REGISTRY] Key map registration failed: {e}")
        return False

    # ── File Fallback ──────────────────────────────────────────────────────

    def _file_append(self, path: str, record_id: str, data: dict) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            records = {}
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    records = json.load(f)
            records[record_id] = data
            with open(path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"[ORG-REGISTRY] File write failed {path}: {e}")
            return False

    def _file_get(self, path: str, record_id: str) -> Optional[dict]:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    records = json.load(f)
                return records.get(record_id)
        except Exception as e:
            logger.error(f"[ORG-REGISTRY] File read failed {path}: {e}")
        return None


# Singletons
org_registry = OrgRegistry()
