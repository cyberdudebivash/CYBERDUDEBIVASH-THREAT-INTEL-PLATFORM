"""
CYBERDUDEBIVASH SENTINEL APEX v53 — Subscription & SaaS Management
Production-grade subscription management with user/org accounts, tier enforcement,
API usage tracking, and Stripe/Gumroad billing integration.

Data Store: data/intelligence/subscriptions.json
"""

import json
import hashlib
import hmac
import secrets
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
INTEL_DIR = BASE_DIR / "data" / "intelligence"
SUBS_FILE = INTEL_DIR / "subscriptions.json"
USAGE_FILE = INTEL_DIR / "subscription_usage.json"
INTEL_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SUBSCRIPTIONS] %(levelname)s %(message)s")
logger = logging.getLogger("subscriptions")

# ---------------------------------------------------------------------------
# Tier Definitions
# ---------------------------------------------------------------------------

class Tier(str, Enum):
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"

TIER_CONFIG = {
    Tier.FREE: {
        "price_monthly_usd": 0,
        "price_annual_usd": 0,
        "api_calls_per_month": 5000,
        "api_calls_per_hour": 60,
        "max_ioc_search_results": 25,
        "max_reports_per_month": 2,
        "stix_export": False,
        "detection_rules": False,
        "campaign_intel": False,
        "attack_surface_scans": 0,
        "custom_feeds": 0,
        "priority_support": False,
        "sla_uptime": "99.0%",
        "data_retention_days": 30,
        "webhook_integrations": 0,
        "features": [
            "IOC search (limited)",
            "CVE intelligence",
            "Basic threat actor profiles",
            "Community dashboard access",
        ],
    },
    Tier.PRO: {
        "price_monthly_usd": 149,
        "price_annual_usd": 1490,
        "api_calls_per_month": 100000,
        "api_calls_per_hour": 600,
        "max_ioc_search_results": 100,
        "max_reports_per_month": 20,
        "stix_export": True,
        "detection_rules": True,
        "campaign_intel": True,
        "attack_surface_scans": 10,
        "custom_feeds": 5,
        "priority_support": False,
        "sla_uptime": "99.5%",
        "data_retention_days": 180,
        "webhook_integrations": 5,
        "features": [
            "Full IOC search",
            "CVE intelligence + EPSS scoring",
            "Full threat actor profiles",
            "Campaign correlation",
            "Detection rule generation (Sigma/YARA/Suricata)",
            "STIX 2.1 export",
            "Premium HTML/PDF reports",
            "Attack surface monitoring (10 scans/month)",
            "Webhook integrations",
            "180-day data retention",
        ],
    },
    Tier.ENTERPRISE: {
        "price_monthly_usd": 499,
        "price_annual_usd": 4990,
        "api_calls_per_month": 1000000,
        "api_calls_per_hour": 6000,
        "max_ioc_search_results": 500,
        "max_reports_per_month": -1,  # unlimited
        "stix_export": True,
        "detection_rules": True,
        "campaign_intel": True,
        "attack_surface_scans": -1,  # unlimited
        "custom_feeds": -1,  # unlimited
        "priority_support": True,
        "sla_uptime": "99.9%",
        "data_retention_days": 365,
        "webhook_integrations": -1,  # unlimited
        "features": [
            "Everything in PRO",
            "Unlimited API calls",
            "Unlimited attack surface scans",
            "Unlimited custom intelligence feeds",
            "Priority 24/7 support",
            "Custom integration support",
            "Dedicated account manager",
            "Custom reporting templates",
            "365-day data retention",
            "99.9% SLA guarantee",
            "TAXII feed access",
            "Bulk IOC export",
            "Multi-user organization accounts",
        ],
    },
}

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class User:
    user_id: str
    email: str
    name: str
    password_hash: str
    org_id: Optional[str] = None
    role: str = "member"  # admin, member, viewer
    created_at: str = ""
    last_login: str = ""
    is_active: bool = True
    mfa_enabled: bool = False
    mfa_secret: str = ""

@dataclass
class Organization:
    org_id: str
    name: str
    admin_user_id: str
    tier: str = "FREE"
    subscription_id: Optional[str] = None
    stripe_customer_id: Optional[str] = None
    gumroad_license_key: Optional[str] = None
    billing_email: str = ""
    created_at: str = ""
    subscription_start: str = ""
    subscription_end: str = ""
    is_active: bool = True
    member_ids: List[str] = field(default_factory=list)
    max_members: int = 1  # FREE=1, PRO=5, ENTERPRISE=unlimited

@dataclass
class Subscription:
    sub_id: str
    org_id: str
    tier: str
    status: str = "active"  # active, canceled, past_due, trialing
    billing_cycle: str = "monthly"  # monthly, annual
    current_period_start: str = ""
    current_period_end: str = ""
    cancel_at_period_end: bool = False
    payment_provider: str = ""  # stripe, gumroad, manual
    external_sub_id: str = ""
    created_at: str = ""

@dataclass
class UsageRecord:
    org_id: str
    period: str  # YYYY-MM
    api_calls: int = 0
    reports_generated: int = 0
    attack_surface_scans: int = 0
    ioc_searches: int = 0
    detection_rules_generated: int = 0
    stix_exports: int = 0


# ---------------------------------------------------------------------------
# Subscription Manager
# ---------------------------------------------------------------------------

class SubscriptionManager:
    """Core subscription and account management."""

    def __init__(self):
        self._data: Dict[str, Any] = {"users": {}, "orgs": {}, "subscriptions": {}}
        self._usage: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        if SUBS_FILE.exists():
            try:
                with open(SUBS_FILE, "r") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {"users": {}, "orgs": {}, "subscriptions": {}}
        if USAGE_FILE.exists():
            try:
                with open(USAGE_FILE, "r") as f:
                    self._usage = json.load(f)
            except Exception:
                self._usage = {}

    def _save(self):
        with open(SUBS_FILE, "w") as f:
            json.dump(self._data, f, indent=2, default=str)

    def _save_usage(self):
        with open(USAGE_FILE, "w") as f:
            json.dump(self._usage, f, indent=2, default=str)

    # ----- User Management -----

    def create_user(self, email: str, name: str, password: str, org_id: Optional[str] = None) -> Dict:
        """Create a new user account."""
        email = email.lower().strip()

        # Check duplicate
        for uid, user in self._data["users"].items():
            if user.get("email") == email:
                raise ValueError(f"Email already registered: {email}")

        user_id = f"usr_{hashlib.sha256(f'{email}:{time.time_ns()}'.encode()).hexdigest()[:16]}"
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), email.encode(), 100000
        ).hex()

        user = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "password_hash": password_hash,
            "org_id": org_id,
            "role": "admin" if not org_id else "member",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": "",
            "is_active": True,
            "mfa_enabled": False,
        }

        self._data["users"][user_id] = user
        self._save()
        logger.info(f"User created: {email} ({user_id})")

        return {"user_id": user_id, "email": email, "name": name}

    def authenticate_user(self, email: str, password: str) -> Optional[Dict]:
        """Authenticate user and return profile."""
        email = email.lower().strip()
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), email.encode(), 100000
        ).hex()

        for uid, user in self._data["users"].items():
            if user.get("email") == email and user.get("password_hash") == password_hash:
                if not user.get("is_active", True):
                    return None
                user["last_login"] = datetime.now(timezone.utc).isoformat()
                self._save()
                return {
                    "user_id": uid,
                    "email": email,
                    "name": user.get("name", ""),
                    "org_id": user.get("org_id"),
                    "role": user.get("role"),
                    "session_token": self._generate_session_token(uid),
                }
        return None

    def _generate_session_token(self, user_id: str) -> str:
        payload = f"{user_id}:{time.time()}:{secrets.token_hex(16)}"
        return hashlib.sha256(payload.encode()).hexdigest()

    # ----- Organization Management -----

    def create_organization(self, name: str, admin_user_id: str, billing_email: str = "") -> Dict:
        """Create a new organization."""
        org_id = f"org_{hashlib.sha256(f'{name}:{time.time_ns()}'.encode()).hexdigest()[:16]}"

        org = {
            "org_id": org_id,
            "name": name,
            "admin_user_id": admin_user_id,
            "tier": "FREE",
            "billing_email": billing_email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True,
            "member_ids": [admin_user_id],
            "max_members": 1,
        }

        self._data["orgs"][org_id] = org

        # Update user's org
        if admin_user_id in self._data["users"]:
            self._data["users"][admin_user_id]["org_id"] = org_id
            self._data["users"][admin_user_id]["role"] = "admin"

        self._save()
        logger.info(f"Organization created: {name} ({org_id})")

        return {"org_id": org_id, "name": name, "tier": "FREE"}

    def add_member(self, org_id: str, user_id: str, requester_role: str = "admin") -> bool:
        """Add a member to an organization."""
        if requester_role != "admin":
            raise PermissionError("Only admins can add members")

        org = self._data["orgs"].get(org_id)
        if not org:
            raise ValueError(f"Organization not found: {org_id}")

        tier = org.get("tier", "FREE")
        max_members = {"FREE": 1, "PRO": 5, "ENTERPRISE": 999}.get(tier, 1)

        if len(org.get("member_ids", [])) >= max_members:
            raise ValueError(f"Organization member limit reached ({max_members} for {tier})")

        if user_id not in org.get("member_ids", []):
            org.setdefault("member_ids", []).append(user_id)

        if user_id in self._data["users"]:
            self._data["users"][user_id]["org_id"] = org_id
            self._data["users"][user_id]["role"] = "member"

        self._save()
        return True

    # ----- Subscription Management -----

    def create_subscription(self, org_id: str, tier: str, billing_cycle: str = "monthly",
                            payment_provider: str = "stripe", external_sub_id: str = "") -> Dict:
        """Create or upgrade a subscription."""
        if tier not in ("FREE", "PRO", "ENTERPRISE"):
            raise ValueError(f"Invalid tier: {tier}")

        org = self._data["orgs"].get(org_id)
        if not org:
            raise ValueError(f"Organization not found: {org_id}")

        sub_id = f"sub_{hashlib.sha256(f'{org_id}:{tier}:{time.time_ns()}'.encode()).hexdigest()[:16]}"
        now = datetime.now(timezone.utc)

        if billing_cycle == "annual":
            period_end = now + timedelta(days=365)
        else:
            period_end = now + timedelta(days=30)

        sub = {
            "sub_id": sub_id,
            "org_id": org_id,
            "tier": tier,
            "status": "active",
            "billing_cycle": billing_cycle,
            "current_period_start": now.isoformat(),
            "current_period_end": period_end.isoformat(),
            "cancel_at_period_end": False,
            "payment_provider": payment_provider,
            "external_sub_id": external_sub_id,
            "created_at": now.isoformat(),
        }

        self._data["subscriptions"][sub_id] = sub

        # Update org tier
        org["tier"] = tier
        org["subscription_id"] = sub_id
        org["subscription_start"] = now.isoformat()
        org["subscription_end"] = period_end.isoformat()
        org["max_members"] = {"FREE": 1, "PRO": 5, "ENTERPRISE": 999}.get(tier, 1)

        self._save()
        logger.info(f"Subscription created: org={org_id} tier={tier} ({sub_id})")

        return {"sub_id": sub_id, "tier": tier, "status": "active", "period_end": period_end.isoformat()}

    def cancel_subscription(self, sub_id: str, immediate: bool = False) -> Dict:
        """Cancel a subscription."""
        sub = self._data["subscriptions"].get(sub_id)
        if not sub:
            raise ValueError(f"Subscription not found: {sub_id}")

        if immediate:
            sub["status"] = "canceled"
            org = self._data["orgs"].get(sub["org_id"])
            if org:
                org["tier"] = "FREE"
        else:
            sub["cancel_at_period_end"] = True
            sub["status"] = "canceling"

        self._save()
        logger.info(f"Subscription canceled: {sub_id} (immediate={immediate})")
        return {"sub_id": sub_id, "status": sub["status"]}

    def get_org_tier(self, org_id: str) -> str:
        """Get the current tier for an organization."""
        org = self._data["orgs"].get(org_id)
        if not org:
            return "FREE"
        return org.get("tier", "FREE")

    def get_tier_config(self, tier: str) -> Dict:
        """Get configuration for a tier."""
        return TIER_CONFIG.get(Tier(tier), TIER_CONFIG[Tier.FREE])

    # ----- Usage Tracking -----

    def record_usage(self, org_id: str, metric: str, count: int = 1):
        """Record API/feature usage for billing and enforcement."""
        period = datetime.now(timezone.utc).strftime("%Y-%m")
        key = f"{org_id}:{period}"

        if key not in self._usage:
            self._usage[key] = {
                "org_id": org_id,
                "period": period,
                "api_calls": 0,
                "reports_generated": 0,
                "attack_surface_scans": 0,
                "ioc_searches": 0,
                "detection_rules_generated": 0,
                "stix_exports": 0,
            }

        if metric in self._usage[key]:
            self._usage[key][metric] += count

        # Periodic save
        if self._usage[key].get("api_calls", 0) % 100 == 0:
            self._save_usage()

    def check_usage_limit(self, org_id: str, metric: str) -> Tuple[bool, Dict]:
        """Check if an org is within its usage limits."""
        tier = self.get_org_tier(org_id)
        config = self.get_tier_config(tier)
        period = datetime.now(timezone.utc).strftime("%Y-%m")
        key = f"{org_id}:{period}"

        usage = self._usage.get(key, {})
        current = usage.get(metric, 0)

        limit_map = {
            "api_calls": config.get("api_calls_per_month", 5000),
            "reports_generated": config.get("max_reports_per_month", 2),
            "attack_surface_scans": config.get("attack_surface_scans", 0),
        }

        limit = limit_map.get(metric, -1)
        if limit == -1:  # Unlimited
            return True, {"current": current, "limit": "unlimited", "tier": tier}

        allowed = current < limit
        return allowed, {
            "current": current,
            "limit": limit,
            "remaining": max(0, limit - current),
            "tier": tier,
            "upgrade_url": "https://cyberdudebivash.com/pricing",
        }

    def get_usage_stats(self, org_id: str) -> Dict:
        """Get usage statistics for current period."""
        period = datetime.now(timezone.utc).strftime("%Y-%m")
        key = f"{org_id}:{period}"
        usage = self._usage.get(key, {})
        tier = self.get_org_tier(org_id)
        config = self.get_tier_config(tier)

        return {
            "org_id": org_id,
            "tier": tier,
            "period": period,
            "usage": usage,
            "limits": {
                "api_calls_per_month": config.get("api_calls_per_month"),
                "max_reports_per_month": config.get("max_reports_per_month"),
                "attack_surface_scans": config.get("attack_surface_scans"),
            },
        }

    # ----- Stripe Webhook Handler -----

    def handle_stripe_webhook(self, event_type: str, event_data: Dict) -> Dict:
        """Process Stripe webhook events for subscription lifecycle."""
        handlers = {
            "checkout.session.completed": self._handle_checkout_completed,
            "customer.subscription.updated": self._handle_sub_updated,
            "customer.subscription.deleted": self._handle_sub_deleted,
            "invoice.payment_failed": self._handle_payment_failed,
        }

        handler = handlers.get(event_type)
        if handler:
            return handler(event_data)
        return {"status": "ignored", "event_type": event_type}

    def _handle_checkout_completed(self, data: Dict) -> Dict:
        metadata = data.get("metadata", {})
        org_id = metadata.get("org_id")
        tier = metadata.get("tier", "PRO")
        stripe_sub_id = data.get("subscription", "")

        if org_id:
            result = self.create_subscription(
                org_id, tier, "monthly", "stripe", stripe_sub_id
            )
            return {"status": "subscription_created", **result}
        return {"status": "error", "detail": "Missing org_id in metadata"}

    def _handle_sub_updated(self, data: Dict) -> Dict:
        stripe_sub_id = data.get("id", "")
        status = data.get("status", "")

        for sub_id, sub in self._data["subscriptions"].items():
            if sub.get("external_sub_id") == stripe_sub_id:
                sub["status"] = status
                self._save()
                return {"status": "updated", "sub_id": sub_id, "new_status": status}
        return {"status": "not_found"}

    def _handle_sub_deleted(self, data: Dict) -> Dict:
        stripe_sub_id = data.get("id", "")
        for sub_id, sub in self._data["subscriptions"].items():
            if sub.get("external_sub_id") == stripe_sub_id:
                return self.cancel_subscription(sub_id, immediate=True)
        return {"status": "not_found"}

    def _handle_payment_failed(self, data: Dict) -> Dict:
        stripe_sub_id = data.get("subscription", "")
        for sub_id, sub in self._data["subscriptions"].items():
            if sub.get("external_sub_id") == stripe_sub_id:
                sub["status"] = "past_due"
                self._save()
                return {"status": "marked_past_due", "sub_id": sub_id}
        return {"status": "not_found"}

    # ----- Pricing Info -----

    def get_pricing(self) -> Dict:
        """Return public pricing information."""
        return {
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "tiers": {
                tier.value: {
                    "price_monthly": config["price_monthly_usd"],
                    "price_annual": config["price_annual_usd"],
                    "features": config["features"],
                    "api_calls_per_month": config["api_calls_per_month"],
                    "sla": config["sla_uptime"],
                }
                for tier, config in TIER_CONFIG.items()
            },
            "currency": "USD",
            "contact_enterprise": "enterprise@cyberdudebivash.com",
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CDB SENTINEL APEX — Subscription Manager v53")
    sub = parser.add_subparsers(dest="command")

    p_pricing = sub.add_parser("pricing", help="Show pricing tiers")
    p_create_user = sub.add_parser("create-user", help="Create a user")
    p_create_user.add_argument("--email", required=True)
    p_create_user.add_argument("--name", required=True)
    p_create_user.add_argument("--password", required=True)

    p_create_org = sub.add_parser("create-org", help="Create an organization")
    p_create_org.add_argument("--name", required=True)
    p_create_org.add_argument("--admin-user-id", required=True)

    args = parser.parse_args()
    mgr = SubscriptionManager()

    if args.command == "pricing":
        print(json.dumps(mgr.get_pricing(), indent=2))
    elif args.command == "create-user":
        result = mgr.create_user(args.email, args.name, args.password)
        print(json.dumps(result, indent=2))
    elif args.command == "create-org":
        result = mgr.create_organization(args.name, args.admin_user_id)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
