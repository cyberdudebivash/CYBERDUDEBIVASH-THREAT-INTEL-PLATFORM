"""
CYBERDUDEBIVASH® SENTINEL APEX
CYBER THREAT INTEL MARKETPLACE v1.0
API-driven threat intel monetization: subscriptions, data access control,
tiered pricing, usage tracking, Gumroad integration.
"""
import hashlib, json, logging, os, secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-MARKETPLACE")

SUBSCRIPTION_TIERS = {
    "free": {
        "price_monthly": 0,
        "rate_limit_per_day": 10,
        "access_level": 1,
        "features": ["basic_feed", "top10_advisories"],
        "stix_exports": False,
        "api_access": False,
        "yara_rules": False,
        "sigma_rules": False,
        "premium_iocs": False,
    },
    "pro": {
        "price_monthly": 49,
        "rate_limit_per_day": 500,
        "access_level": 3,
        "features": ["full_feed", "stix_exports", "sigma_rules", "yara_rules", "api_key"],
        "stix_exports": True,
        "api_access": True,
        "yara_rules": True,
        "sigma_rules": True,
        "premium_iocs": True,
    },
    "enterprise": {
        "price_monthly": 499,
        "rate_limit_per_day": 50000,
        "access_level": 5,
        "features": ["unlimited_feed", "stix_exports", "stix_taxii", "custom_feeds", "sla", "dedicated_support",
                     "misp_export", "webhook", "white_label"],
        "stix_exports": True,
        "api_access": True,
        "yara_rules": True,
        "sigma_rules": True,
        "premium_iocs": True,
    },
    "mssp": {
        "price_monthly": 1999,
        "rate_limit_per_day": 200000,
        "access_level": 10,
        "features": ["multi_tenant", "custom_api", "white_label", "reseller", "dedicated_engineer"],
        "stix_exports": True,
        "api_access": True,
        "yara_rules": True,
        "sigma_rules": True,
        "premium_iocs": True,
    },
}

DATA_PRODUCTS = [
    {"id": "dp_001", "name": "Critical CVE Intelligence Pack",   "price": 19, "type": "one_time",
     "includes": ["STIX bundle", "SIGMA rules", "YARA rules", "IOC list"], "tier_required": "free"},
    {"id": "dp_002", "name": "Ransomware TTP Intelligence",      "price": 49, "type": "one_time",
     "includes": ["Actor profiles", "TTPs", "Detection rules", "Playbook"], "tier_required": "free"},
    {"id": "dp_003", "name": "Weekly Threat Briefing PDF",       "price": 9,  "type": "subscription",
     "includes": ["Executive summary", "Top threats", "IOCs"], "tier_required": "free"},
    {"id": "dp_004", "name": "APT Campaign Intelligence Bundle", "price": 99, "type": "one_time",
     "includes": ["Nation-state actor profiles", "Infrastructure maps", "Detection kit"], "tier_required": "pro"},
    {"id": "dp_005", "name": "Supply Chain Security Report",     "price": 39, "type": "one_time",
     "includes": ["Compromised packages", "Dependencies at risk", "Mitigations"], "tier_required": "free"},
]


DATA_DIR = os.environ.get("CDB_DATA_DIR", os.path.join("data", "marketplace"))


class ThreatIntelMarketplace:
    """
    Threat intelligence marketplace engine.
    Manages subscriptions, API keys, data access control, and usage tracking.
    """

    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.api_keys: Dict[str, Dict] = {}       # key → {tenant, tier, usage}
        self.subscriptions: Dict[str, Dict] = {}  # tenant_id → subscription
        self.revenue_log: List[Dict] = []
        self._load_state()

    def _load_state(self) -> None:
        state_file = os.path.join(DATA_DIR, "marketplace_state.json")
        if os.path.exists(state_file):
            try:
                with open(state_file, encoding="utf-8") as f:
                    state = json.load(f)
                self.api_keys = state.get("api_keys", {})
                self.subscriptions = state.get("subscriptions", {})
            except Exception as e:
                logger.error(f"[MARKETPLACE] Failed to load state: {e}")

    def _save_state(self) -> None:
        state_file = os.path.join(DATA_DIR, "marketplace_state.json")
        try:
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump({"api_keys": self.api_keys,
                           "subscriptions": self.subscriptions}, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[MARKETPLACE] Failed to save state: {e}")

    def create_subscription(self, tenant_id: str, tier: str, email: str = "") -> Dict:
        """Create or upgrade a tenant subscription."""
        if tier not in SUBSCRIPTION_TIERS:
            return {"error": f"Unknown tier: {tier}. Valid: {list(SUBSCRIPTION_TIERS.keys())}"}
        tier_config = SUBSCRIPTION_TIERS[tier]
        api_key = self._generate_api_key(tier)
        now = datetime.now(timezone.utc)

        subscription = {
            "tenant_id":      tenant_id,
            "tier":           tier,
            "email":          email,
            "api_key":        api_key,
            "access_level":   tier_config["access_level"],
            "rate_limit":     tier_config["rate_limit_per_day"],
            "features":       tier_config["features"],
            "created_at":     now.isoformat(),
            "expires_at":     (now + timedelta(days=30)).isoformat(),
            "usage_today":    0,
            "total_calls":    0,
            "status":         "ACTIVE",
        }

        self.subscriptions[tenant_id] = subscription
        self.api_keys[api_key] = {
            "tenant_id": tenant_id, "tier": tier,
            "access_level": tier_config["access_level"],
            "usage_today": 0, "total_calls": 0,
        }
        self._save_state()
        logger.info(f"[MARKETPLACE] Subscription created: {tenant_id} tier={tier}")
        return {"status": "CREATED", "subscription": subscription}

    def validate_api_key(self, api_key: str, requested_feature: str = "") -> Dict:
        """Validate API key and check feature access."""
        key_data = self.api_keys.get(api_key)
        if not key_data:
            return {"valid": False, "error": "Invalid API key", "http_status": 401}

        tier = key_data.get("tier", "free")
        tier_config = SUBSCRIPTION_TIERS.get(tier, SUBSCRIPTION_TIERS["free"])

        # Rate limit check
        if key_data["usage_today"] >= tier_config["rate_limit_per_day"]:
            return {"valid": False, "error": "Rate limit exceeded",
                    "reset_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "http_status": 429}

        # Feature check
        if requested_feature and requested_feature not in tier_config["features"]:
            return {"valid": False, "error": f"Feature '{requested_feature}' requires upgrade",
                    "required_tier": self._get_required_tier(requested_feature),
                    "upgrade_url": "https://tools.cyberdudebivash.com/",
                    "http_status": 403}

        # Increment usage
        key_data["usage_today"] += 1
        key_data["total_calls"] += 1
        self._save_state()

        return {
            "valid": True,
            "tenant_id": key_data["tenant_id"],
            "tier": tier,
            "access_level": key_data["access_level"],
            "remaining_calls": tier_config["rate_limit_per_day"] - key_data["usage_today"],
            "http_status": 200,
        }

    def get_accessible_data(self, api_key: str, data_type: str,
                             advisories: List[Dict]) -> Dict:
        """Return data filtered by subscription tier."""
        validation = self.validate_api_key(api_key, data_type)
        if not validation.get("valid"):
            return {"error": validation.get("error"), "http_status": validation.get("http_status", 403)}

        tier = validation.get("tier", "free")
        tier_config = SUBSCRIPTION_TIERS[tier]
        access_level = tier_config["access_level"]

        # Filter by access level
        if access_level >= 5:
            data = advisories  # Full access
        elif access_level >= 3:
            data = advisories[:100]  # Pro: 100 advisories
        else:
            # Free: top 10, no IOCs, no STIX
            data = [{k: v for k, v in adv.items()
                     if k not in ("iocs", "stix_id")} for adv in advisories[:10]]

        return {
            "tier": tier,
            "data_type": data_type,
            "count": len(data),
            "data": data,
            "access_level": access_level,
            "full_access": access_level >= 5,
        }

    def get_catalog(self) -> Dict:
        """Return marketplace catalog."""
        return {
            "subscription_tiers": SUBSCRIPTION_TIERS,
            "data_products": DATA_PRODUCTS,
            "total_products": len(DATA_PRODUCTS),
            "currency": "USD",
            "payment_url": "https://tools.cyberdudebivash.com/",
            "api_docs": "https://intel.cyberdudebivash.com/api/docs",
        }

    def get_revenue_summary(self) -> Dict:
        active_subs = {tid: sub for tid, sub in self.subscriptions.items()
                       if sub.get("status") == "ACTIVE"}
        mrr = sum(SUBSCRIPTION_TIERS.get(s["tier"], {}).get("price_monthly", 0)
                  for s in active_subs.values())
        return {
            "active_subscriptions": len(active_subs),
            "mrr": mrr,
            "arr": mrr * 12,
            "tier_breakdown": {tier: sum(1 for s in active_subs.values() if s["tier"] == tier)
                               for tier in SUBSCRIPTION_TIERS},
            "total_api_calls": sum(k["total_calls"] for k in self.api_keys.values()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _generate_api_key(self, tier: str) -> str:
        prefix = {"free": "cdb_free", "pro": "cdb_pro",
                  "enterprise": "cdb_ent", "mssp": "cdb_mssp"}.get(tier, "cdb")
        return f"{prefix}_{secrets.token_urlsafe(32)}"

    def _get_required_tier(self, feature: str) -> str:
        for tier, config in SUBSCRIPTION_TIERS.items():
            if feature in config.get("features", []):
                return tier
        return "enterprise"
