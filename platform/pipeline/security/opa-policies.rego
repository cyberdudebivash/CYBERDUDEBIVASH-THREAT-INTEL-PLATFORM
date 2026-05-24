# SENTINEL APEX — OPA Policy Engine
# Zero Trust + RBAC + ABAC enforcement
package sentinel.apex

import future.keywords.if
import future.keywords.in

# ── Default Deny ──────────────────────────────────────────
default allow := false

# ── Tier Permission Matrix ────────────────────────────────
tier_permissions := {
  "free": {
    "api_calls_per_month": 1000,
    "endpoints": ["/api/intel/feed", "/api/health", "/api/reports/list"],
    "features": ["basic_feed", "pdf_view"],
  },
  "pro": {
    "api_calls_per_month": 100000,
    "endpoints": ["/api/intel/*", "/api/soc/alerts", "/api/reports/*", "/api/ioc/*"],
    "features": ["full_intel", "soc_view", "pdf_download", "api_access"],
  },
  "enterprise": {
    "api_calls_per_month": 10000000,
    "endpoints": ["*"],
    "features": ["*"],
  },
  "government": {
    "api_calls_per_month": -1,
    "endpoints": ["*"],
    "features": ["*", "classified_intel", "gov_only_feeds"],
  },
}

# ── Endpoint Access Control ───────────────────────────────
allow if {
  input.method in {"GET", "POST", "PUT", "DELETE"}
  tier := input.user.tier
  perms := tier_permissions[tier]
  endpoint_allowed(input.path, perms.endpoints)
  not rate_limit_exceeded(input.user.tenant_id, input.user.tier)
}

endpoint_allowed(path, endpoints) if {
  "*" in endpoints
}

endpoint_allowed(path, endpoints) if {
  some ep in endpoints
  ep != "*"
  startswith(path, trim_suffix(ep, "*"))
}

# ── Rate Limiting ─────────────────────────────────────────
rate_limit_exceeded(tenant_id, tier) if {
  count := data.usage[tenant_id].api_calls_current_month
  limit := tier_permissions[tier].api_calls_per_month
  limit != -1
  count >= limit
}

# ── ABAC: Attribute-Based Access ─────────────────────────
allow if {
  input.action == "read_classified_intel"
  input.user.clearance_level in {"ts", "secret", "top_secret"}
  input.user.tier == "government"
}

# ── AI Agent Governance ───────────────────────────────────
allow_ai_action if {
  input.agent.trust_score >= 0.7
  input.action.type in {"llm_call", "memory_read", "api_call"}
  not input.agent.killswitch_active
}

deny_ai_action if {
  input.action.type == "file_write"
  not input.user.tier in {"enterprise", "government"}
}

# ── Admin Actions ─────────────────────────────────────────
allow if {
  "admin" in input.user.roles
  input.path startswith "/admin/"
}
