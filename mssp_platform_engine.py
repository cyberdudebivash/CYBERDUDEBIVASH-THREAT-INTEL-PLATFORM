"""
SENTINEL APEX — MSSP Platform Engine
Phase 121-130: Multi-tenant management, partner billing, sub-tenant isolation, analytics.
Supports MSSPs managing hundreds of end-customer tenants.
"""

import hashlib
import random
import uuid
from datetime import datetime, timedelta
from typing import Optional


# ── Tier Config ───────────────────────────────────────────────────────────────
MSSP_TIERS = {
    "silver":   {"max_tenants": 25,  "margin_pct": 20, "monthly_fee": 150_000},
    "gold":     {"max_tenants": 100, "margin_pct": 25, "monthly_fee": 400_000},
    "platinum": {"max_tenants": 500, "margin_pct": 30, "monthly_fee": 800_000},
    "elite":    {"max_tenants": 999, "margin_pct": 35, "monthly_fee": 1_500_000},
}

TENANT_PLAN_PRICES = {
    "starter": 8_000,       # MSSP buys at discount, resells at premium
    "professional": 28_000,
    "enterprise": 68_000,
}


def _rng(seed: str) -> random.Random:
    return random.Random(int(hashlib.md5(seed.encode()).hexdigest()[:8], 16))


def create_mssp_account(org_name: str, contact_email: str, tier: str = "gold") -> dict:
    """Provision a new MSSP partner account."""
    partner_id = f"MSSP-{uuid.uuid4().hex[:8].upper()}"
    tier_config = MSSP_TIERS.get(tier, MSSP_TIERS["gold"])
    return {
        "partner_id": partner_id,
        "org_name": org_name,
        "contact_email": contact_email,
        "tier": tier,
        "max_tenants": tier_config["max_tenants"],
        "margin_pct": tier_config["margin_pct"],
        "monthly_fee": tier_config["monthly_fee"],
        "status": "active",
        "api_key": f"sk-mssp-{uuid.uuid4().hex[:20].upper()}",
        "white_label_enabled": tier in ("platinum", "elite"),
        "revenue_sharing_enabled": tier in ("gold", "platinum", "elite"),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "portal_url": f"https://mssp.cyberdudebivash.in/{partner_id.lower()}",
    }


def provision_sub_tenant(partner_id: str, customer_name: str, plan: str, sector: str = "technology") -> dict:
    """Provision an isolated sub-tenant under an MSSP partner."""
    tenant_id = f"TNT-{partner_id[-6:]}-{uuid.uuid4().hex[:6].upper()}"
    return {
        "tenant_id": tenant_id,
        "partner_id": partner_id,
        "customer_name": customer_name,
        "plan": plan,
        "sector": sector,
        "isolation_namespace": f"ns_{tenant_id.lower().replace('-','_')}",
        "data_residency": "IN",       # configurable: IN, US, EU, SG
        "api_key": f"sk-{tenant_id.lower()}-{uuid.uuid4().hex[:12].upper()}",
        "status": "active",
        "provisioned_at": datetime.utcnow().isoformat() + "Z",
        "intel_feed_url": f"https://api.cyberdudebivash.in/taxii/{tenant_id}/",
        "dashboard_url": f"https://portal.cyberdudebivash.in/tenant/{tenant_id}/",
        "mssp_billing_rate": TENANT_PLAN_PRICES.get(plan, 28_000),
    }


def calculate_partner_revenue(partner_id: str, tenants: list) -> dict:
    """Calculate revenue breakdown for an MSSP partner."""
    total_billed = 0
    total_cost = 0
    by_plan = {}

    for t in tenants:
        if t.get("partner_id") != partner_id or t.get("status") != "active":
            continue
        plan = t.get("plan", "professional")
        billed = t.get("mssp_billing_rate", TENANT_PLAN_PRICES.get(plan, 28_000))
        cost = round(billed * 0.70)    # MSSP pays 70% of price to platform
        margin = billed - cost
        total_billed += billed
        total_cost += cost
        by_plan.setdefault(plan, {"count": 0, "billed": 0, "margin": 0})
        by_plan[plan]["count"] += 1
        by_plan[plan]["billed"] += billed
        by_plan[plan]["margin"] += margin

    total_margin = total_billed - total_cost

    return {
        "partner_id": partner_id,
        "tenant_count": sum(1 for t in tenants if t.get("partner_id") == partner_id),
        "gross_billed": total_billed,
        "platform_cost": total_cost,
        "partner_margin": total_margin,
        "margin_pct": round((total_margin / total_billed * 100) if total_billed else 0, 1),
        "by_plan": by_plan,
        "calculated_at": datetime.utcnow().isoformat() + "Z",
    }


def get_mssp_health_rollup(partner_id: str, tenants: list, health_scores: dict) -> dict:
    """Aggregate health scores across all sub-tenants for an MSSP."""
    partner_tenants = [t for t in tenants if t.get("partner_id") == partner_id]
    if not partner_tenants:
        return {"partner_id": partner_id, "tenant_count": 0}

    scores = [health_scores.get(t["tenant_id"], 50) for t in partner_tenants]
    healthy   = sum(1 for s in scores if s >= 80)
    at_risk   = sum(1 for s in scores if 50 <= s < 80)
    critical  = sum(1 for s in scores if s < 50)

    return {
        "partner_id": partner_id,
        "tenant_count": len(partner_tenants),
        "avg_health": round(sum(scores) / len(scores), 1),
        "healthy": healthy,
        "at_risk": at_risk,
        "critical": critical,
        "requires_attention": at_risk + critical,
        "healthy_pct": round(healthy / len(partner_tenants) * 100, 1),
    }


def generate_mssp_platform_data(partner_count: int = 20) -> dict:
    """Generate simulated MSSP platform data for dashboard."""
    rng = _rng("mssp_platform_v1")
    tiers = ["silver", "gold", "platinum", "elite"]
    tier_weights = [0.3, 0.4, 0.2, 0.1]

    partners = []
    all_tenants = []
    health_scores = {}

    for i in range(partner_count):
        tier = rng.choices(tiers, weights=tier_weights)[0]
        p = create_mssp_account(f"MSSP Partner {i+1}", f"partner{i+1}@mssp.com", tier)
        tenant_count = rng.randint(5, MSSP_TIERS[tier]["max_tenants"] // 3)
        p["active_tenants"] = tenant_count
        partners.append(p)

        for j in range(tenant_count):
            plan = rng.choice(["starter", "professional", "enterprise"])
            t = provision_sub_tenant(p["partner_id"], f"Customer {j+1}", plan)
            t["mssp_billing_rate"] = TENANT_PLAN_PRICES.get(plan, 28_000)
            all_tenants.append(t)
            health_scores[t["tenant_id"]] = rng.randint(30, 100)

    total_tenants = len(all_tenants)
    total_mrr = sum(t["mssp_billing_rate"] for t in all_tenants)
    platform_revenue = round(total_mrr * 0.70)
    partner_margins = round(total_mrr * 0.30)

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "partner_count": partner_count,
        "total_sub_tenants": total_tenants,
        "total_mrr": total_mrr,
        "platform_revenue": platform_revenue,
        "partner_total_margins": partner_margins,
        "avg_tenants_per_partner": round(total_tenants / partner_count, 1),
        "partners": partners[:10],  # Top 10 for dashboard
        "health_rollup": {
            "healthy": sum(1 for s in health_scores.values() if s >= 80),
            "at_risk": sum(1 for s in health_scores.values() if 50 <= s < 80),
            "critical": sum(1 for s in health_scores.values() if s < 50),
        },
    }


# ── CLI Demo ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    data = generate_mssp_platform_data(20)
    print(f"\n{'='*55}")
    print(f"SENTINEL APEX — MSSP Platform (Phase 121-130)")
    print(f"{'='*55}")
    print(f"Partners        : {data['partner_count']}")
    print(f"Sub-Tenants     : {data['total_sub_tenants']}")
    print(f"Platform MRR    : ₹{data['platform_revenue']:,.0f}")
    print(f"Partner Margins : ₹{data['partner_total_margins']:,.0f}")
    print(f"Avg Tenants/P   : {data['avg_tenants_per_partner']}")
    print(f"{'='*55}")
    for p in data["partners"][:5]:
        print(f"  {p['org_name']:25s} | {p['tier']:9s} | {p['active_tenants']:3d} tenants")
