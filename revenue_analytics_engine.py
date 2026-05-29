"""
SENTINEL APEX — Revenue Analytics Engine
Phase 106: Real-time revenue operations, cohort analysis, churn forecasting, expansion tracking.
Production engine for billing, MRR, ARR, NRR, LTV, CAC calculations.
"""

from datetime import datetime, timedelta
from typing import Optional
import hashlib
import random


# ── Plan Pricing ──────────────────────────────────────────────────────────────
PLAN_MRR = {
    "starter":      12_000,
    "professional": 36_000,
    "enterprise":   84_000,
    "mssp":        150_000,
}

PLAN_WEIGHTS = {
    "starter": 0.15,
    "professional": 0.35,
    "enterprise": 0.35,
    "mssp": 0.15,
}

GST_RATE = 0.18


def _rng(seed_str: str) -> random.Random:
    seed = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16)
    return random.Random(seed)


def calculate_mrr(subscriptions: list) -> dict:
    """
    Calculate MRR from active subscriptions.
    Breaks down by plan tier, new MRR, expansion MRR, churned MRR.
    """
    total_mrr = 0
    by_plan = {p: {"count": 0, "mrr": 0} for p in PLAN_MRR}

    for sub in subscriptions:
        if sub.get("status") not in ("active", "trial_converting"):
            continue
        plan = sub["plan"].lower()
        cycle_discount = {"monthly": 1.0, "annual": 0.8, "biannual": 0.7}.get(sub.get("billing_cycle", "monthly"), 1.0)
        base_mrr = PLAN_MRR.get(plan, 0) * cycle_discount
        seats_multiplier = max(1, sub.get("extra_seats", 0) * 0.1 + 1)
        sub_mrr = round(base_mrr * seats_multiplier)
        total_mrr += sub_mrr
        by_plan[plan]["count"] += 1
        by_plan[plan]["mrr"] += sub_mrr

    return {
        "total_mrr": total_mrr,
        "total_arr": total_mrr * 12,
        "by_plan": by_plan,
        "active_subscriptions": sum(1 for s in subscriptions if s.get("status") == "active"),
        "calculated_at": datetime.utcnow().isoformat() + "Z",
    }


def calculate_nrr(cohort_start_mrr: float, cohort_end_mrr: float) -> float:
    """Net Revenue Retention = (End MRR – Churned) / Start MRR × 100"""
    if cohort_start_mrr == 0:
        return 0.0
    return round((cohort_end_mrr / cohort_start_mrr) * 100, 1)


def calculate_ltv(avg_mrr: float, avg_lifetime_months: float, gross_margin: float = 0.80) -> float:
    """LTV = (MRR × Gross Margin) × Avg Customer Lifetime (months)"""
    return round(avg_mrr * gross_margin * avg_lifetime_months)


def calculate_cac(total_sales_marketing_spend: float, new_customers_acquired: int) -> float:
    """CAC = Total S&M Spend / New Customers"""
    if new_customers_acquired == 0:
        return 0.0
    return round(total_sales_marketing_spend / new_customers_acquired)


def churn_forecast(subscriptions: list, health_scores: dict) -> dict:
    """
    Forecast churn for next 90 days based on health scores and renewal dates.
    health_scores: {tenant_id: score}
    """
    at_risk = []
    forecasted_churn_mrr = 0

    for sub in subscriptions:
        if sub.get("status") != "active":
            continue
        tenant_id = sub.get("tenant_id", "")
        health = health_scores.get(tenant_id, 75)
        plan = sub["plan"].lower()
        mrr = PLAN_MRR.get(plan, 0)

        # Churn probability model (simplified logistic)
        p_churn = 0.0
        if health < 30:   p_churn = 0.75
        elif health < 45: p_churn = 0.50
        elif health < 60: p_churn = 0.25
        elif health < 70: p_churn = 0.12
        else:             p_churn = 0.03

        # Boost if renewal within 30 days and health low
        days_to_renewal = sub.get("days_to_renewal", 90)
        if days_to_renewal <= 30 and health < 65:
            p_churn = min(p_churn * 1.4, 0.95)

        if p_churn >= 0.20:
            at_risk.append({
                "tenant_id": tenant_id,
                "org_name": sub.get("org_name", "Unknown"),
                "plan": plan,
                "mrr": mrr,
                "health_score": health,
                "churn_probability": round(p_churn * 100, 1),
                "days_to_renewal": days_to_renewal,
                "expected_mrr_loss": round(mrr * p_churn),
                "intervention": "URGENT" if p_churn >= 0.5 else "REQUIRED",
            })
            forecasted_churn_mrr += round(mrr * p_churn)

    at_risk.sort(key=lambda x: -x["churn_probability"])

    return {
        "forecast_window_days": 90,
        "at_risk_count": len(at_risk),
        "forecasted_churn_mrr": forecasted_churn_mrr,
        "forecasted_churn_arr": forecasted_churn_mrr * 12,
        "at_risk_accounts": at_risk,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def expansion_opportunities(subscriptions: list, health_scores: dict,
                             usage_data: dict) -> dict:
    """
    Identify accounts ready for upsell / expansion.
    usage_data: {tenant_id: {api_usage_pct, seat_usage_pct, feature_usage}}
    """
    opportunities = []

    upgrade_path = {
        "starter": "professional",
        "professional": "enterprise",
        "enterprise": "mssp",
        "mssp": None,
    }

    for sub in subscriptions:
        if sub.get("status") != "active":
            continue
        tid = sub.get("tenant_id", "")
        plan = sub["plan"].lower()
        health = health_scores.get(tid, 0)
        usage = usage_data.get(tid, {})
        api_pct = usage.get("api_usage_pct", 0)
        seat_pct = usage.get("seat_usage_pct", 0)
        next_plan = upgrade_path.get(plan)

        if not next_plan:
            continue

        score = 0
        signals = []

        if health >= 80:       score += 30; signals.append("Healthy customer (80+)")
        if api_pct >= 80:      score += 25; signals.append(f"API usage at {api_pct}%")
        if seat_pct >= 90:     score += 20; signals.append(f"Seat usage at {seat_pct}%")
        if health >= 90:       score += 10; signals.append("Mission-critical dependency")
        if sub.get("tenure_months", 0) >= 6: score += 15; signals.append("6+ month tenure")

        if score >= 40:
            current_mrr = PLAN_MRR.get(plan, 0)
            next_mrr = PLAN_MRR.get(next_plan, 0)
            expansion_mrr = next_mrr - current_mrr
            opportunities.append({
                "tenant_id": tid,
                "org_name": sub.get("org_name", "Unknown"),
                "current_plan": plan,
                "recommended_plan": next_plan,
                "expansion_mrr": expansion_mrr,
                "expansion_score": score,
                "signals": signals,
                "health_score": health,
                "priority": "HIGH" if score >= 70 else "MEDIUM",
            })

    opportunities.sort(key=lambda x: -x["expansion_mrr"])
    total_expansion_mrr = sum(o["expansion_mrr"] for o in opportunities)

    return {
        "opportunity_count": len(opportunities),
        "total_expansion_mrr": total_expansion_mrr,
        "total_expansion_arr": total_expansion_mrr * 12,
        "opportunities": opportunities,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def generate_revenue_dashboard_data(customer_count: int = 500) -> dict:
    """
    Generate simulated revenue dashboard data for N customers.
    Production: replace with DB queries to billing tables.
    """
    rng = _rng("revenue_dash_v2")
    plans = list(PLAN_MRR.keys())
    weights = list(PLAN_WEIGHTS.values())

    subscriptions = []
    health_scores = {}
    usage_data = {}
    monthly_mrr = []

    for i in range(customer_count):
        tid = f"TNT-{i:04d}"
        plan = rng.choices(plans, weights=weights)[0]
        health = rng.randint(25, 100)
        days_renewal = rng.randint(1, 365)
        tenure = rng.randint(1, 36)
        subscriptions.append({
            "tenant_id": tid,
            "org_name": f"Enterprise Corp {i+1}",
            "plan": plan,
            "status": "active" if rng.random() > 0.03 else "churned",
            "billing_cycle": rng.choice(["monthly", "annual", "annual"]),
            "extra_seats": rng.randint(0, 20),
            "days_to_renewal": days_renewal,
            "tenure_months": tenure,
        })
        health_scores[tid] = health
        usage_data[tid] = {
            "api_usage_pct": rng.randint(20, 100),
            "seat_usage_pct": rng.randint(30, 100),
        }

    # Monthly MRR trend (last 12 months)
    base_mrr = sum(PLAN_MRR.get(s["plan"], 0) for s in subscriptions if s["status"] == "active")
    for m in range(12, 0, -1):
        growth = 1 - (m * 0.015)
        monthly_mrr.append({
            "month": (datetime.utcnow() - timedelta(days=m*30)).strftime("%b %Y"),
            "mrr": round(base_mrr * growth),
        })
    monthly_mrr.append({"month": datetime.utcnow().strftime("%b %Y"), "mrr": base_mrr})

    mrr_data = calculate_mrr(subscriptions)
    churn_data = churn_forecast(subscriptions, health_scores)
    expansion_data = expansion_opportunities(subscriptions, health_scores, usage_data)

    avg_mrr = mrr_data["total_mrr"] / customer_count
    ltv = calculate_ltv(avg_mrr, 28)  # 28 month avg lifetime
    nrr = 114.0  # Net Revenue Retention target

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "customer_count": customer_count,
        "mrr": mrr_data,
        "churn_forecast": churn_data,
        "expansion": expansion_data,
        "monthly_trend": monthly_mrr,
        "metrics": {
            "ltv": ltv,
            "cac": calculate_cac(2_500_000, 22),
            "ltv_cac_ratio": round(ltv / calculate_cac(2_500_000, 22), 1),
            "nrr": nrr,
            "gross_margin": 80.0,
            "avg_revenue_per_account": round(avg_mrr),
        },
    }


# ── CLI Demo ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    data = generate_revenue_dashboard_data(500)
    m = data["mrr"]
    print(f"\n{'='*60}")
    print(f"SENTINEL APEX — Revenue Analytics (500 Customers)")
    print(f"{'='*60}")
    print(f"Total MRR    : ₹{m['total_mrr']:,.0f}")
    print(f"Total ARR    : ₹{m['total_arr']:,.0f}")
    print(f"NRR          : {data['metrics']['nrr']}%")
    print(f"LTV          : ₹{data['metrics']['ltv']:,.0f}")
    print(f"LTV/CAC      : {data['metrics']['ltv_cac_ratio']}x")
    print(f"Churn Risk   : {data['churn_forecast']['at_risk_count']} accounts")
    print(f"Churn MRR    : ₹{data['churn_forecast']['forecasted_churn_mrr']:,.0f}")
    print(f"Expansion Opp: ₹{data['expansion']['total_expansion_mrr']:,.0f}/mo")
    print(f"{'='*60}")
    for tier, info in m["by_plan"].items():
        if info["count"]:
            print(f"  {tier:15s}: {info['count']:3d} customers  ₹{info['mrr']:>12,.0f}/mo")
