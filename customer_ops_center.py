"""
CYBERDUDEBIVASH SENTINEL APEX
Customer Operations Center - FILE 10/10
Master aggregation dashboard: health, billing, renewals, tickets, MSSP, reports.
Aggregates all 9 other engines. Includes scale simulation up to 1000 customers.
Port: 8510
"""

import uuid
import random
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Import all other engines (inline aggregation — no external HTTP calls needed)
# ---------------------------------------------------------------------------
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# We re-import engine modules to access their in-memory stores directly
import customer_identity_engine as identity_eng
import tenant_management_engine as tenant_eng
import subscription_engine as sub_eng
import billing_engine as billing_eng
import customer_health_engine as health_eng
import support_operations_engine as support_eng
import mssp_operations_engine as mssp_eng
import executive_reporting_engine as report_eng
import renewal_engine as renewal_eng

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Alert definitions
# ---------------------------------------------------------------------------
ALERT_TYPES = {
    "health_degradation":  {"severity": "high",     "category": "customer_health"},
    "sla_breach":          {"severity": "critical",  "category": "support"},
    "renewal_risk":        {"severity": "high",      "category": "renewals"},
    "billing_overdue":     {"severity": "medium",    "category": "billing"},
    "quota_exceeded":      {"severity": "medium",    "category": "platform"},
    "tenant_suspended":    {"severity": "low",       "category": "platform"},
    "churn_risk_critical": {"severity": "critical",  "category": "customer_health"},
}


# ---------------------------------------------------------------------------
# Aggregation functions
# ---------------------------------------------------------------------------

def get_ops_summary() -> dict:
    """Aggregate real-time metrics across all engines."""
    now = datetime.now(timezone.utc)

    # --- Identity / Org metrics ---
    orgs = list(identity_eng.ORGANIZATIONS.values())
    active_orgs = [o for o in orgs if o.get("status") == "active"]

    # --- Health metrics ---
    health_scores = list(health_eng.HEALTH_SCORES.values())
    healthy = [h for h in health_scores if h["health_score"] >= 80]
    at_risk = [h for h in health_scores if 50 <= h["health_score"] < 80]
    renewal_risk_h = [h for h in health_scores if h["health_score"] < 50]
    avg_health = round(sum(h["health_score"] for h in health_scores) / max(len(health_scores), 1), 1)

    # --- Subscription / Revenue metrics ---
    subs = list(sub_eng.SUBSCRIPTIONS.values())
    active_subs = [s for s in subs if s["status"] in ("active", "trialing")]
    plan_prices = {"free": 0, "professional": 299, "enterprise": 999, "mssp": 2499, "oem": 9999}
    mrr = sum(plan_prices.get(s["plan"], 0) for s in active_subs)
    arr = mrr * 12

    # --- Billing metrics ---
    invoices = list(billing_eng.INVOICES.values())
    overdue_invoices = [i for i in invoices if i.get("overdue") and i["status"] != "paid"]
    outstanding = sum(i["amount"] for i in invoices if i["status"] == "open")

    # --- Support metrics ---
    tickets = list(support_eng.TICKETS.values())
    open_tickets = [t for t in tickets if t["status"] not in ("resolved", "closed")]
    p1_open = [t for t in open_tickets if t["priority"] == "P1"]
    escalated = [t for t in tickets if t.get("escalation_level", 0) > 0]

    # --- Renewal metrics ---
    renewals = list(renewal_eng.RENEWALS.values())
    upcoming_renewals_30d = [r for r in renewals if r["days_to_renewal"] <= 30]
    high_risk_renewals = [r for r in renewals if r["risk_level"] in ("High", "Critical")]
    renewal_pipeline = sum(r["contract_value"] for r in upcoming_renewals_30d)

    # --- MSSP metrics ---
    mssp_partners = list(mssp_eng.MSSP_PARTNERS.values())
    managed_customers = list(mssp_eng.MANAGED_CUSTOMERS.values())

    # --- Tenants ---
    tenants = list(tenant_eng.TENANTS.values())
    suspended_tenants = [t for t in tenants if t["status"] == "suspended"]

    return {
        "summary_generated_at": now.isoformat(),
        "platform": "CYBERDUDEBIVASH SENTINEL APEX",
        "version": "v28.0",
        "customers": {
            "total_organizations": len(orgs),
            "active_organizations": len(active_orgs),
            "total_tenants": len(tenants),
            "suspended_tenants": len(suspended_tenants),
            "total_users": len(identity_eng.USERS),
            "mfa_enabled_pct": round(
                sum(1 for u in identity_eng.USERS.values() if u["mfa_enabled"]) / max(len(identity_eng.USERS), 1) * 100, 1
            ),
        },
        "health": {
            "avg_health_score": avg_health,
            "healthy_customers": len(healthy),
            "at_risk_customers": len(at_risk),
            "renewal_risk_customers": len(renewal_risk_h),
            "healthy_pct": round(len(healthy) / max(len(health_scores), 1) * 100, 1),
        },
        "revenue": {
            "mrr_usd": mrr,
            "arr_usd": arr,
            "active_subscriptions": len(active_subs),
            "outstanding_invoices_usd": round(outstanding, 2),
            "overdue_invoices": len(overdue_invoices),
        },
        "support": {
            "open_tickets": len(open_tickets),
            "p1_open": len(p1_open),
            "escalated_tickets": len(escalated),
            "total_tickets": len(tickets),
        },
        "renewals": {
            "upcoming_30d": len(upcoming_renewals_30d),
            "high_risk_count": len(high_risk_renewals),
            "pipeline_at_risk_30d_usd": round(renewal_pipeline, 2),
            "total_tracked": len(renewals),
        },
        "mssp": {
            "total_partners": len(mssp_partners),
            "total_managed_customers": len(managed_customers),
            "total_mssp_mrr_usd": round(sum(p["monthly_revenue"] for p in mssp_partners), 2),
        },
        "reports": {
            "reports_generated": len(report_eng.REPORTS),
            "active_schedules": len(report_eng.REPORT_SCHEDULES),
        },
    }


def get_all_alerts() -> List[dict]:
    """Scan all engines and generate active alerts."""
    alerts = []
    now = datetime.now(timezone.utc)

    # Health degradation alerts
    for org_id, hs in health_eng.HEALTH_SCORES.items():
        profile = health_eng.CUSTOMER_PROFILES.get(org_id, {})
        if hs["health_score"] < 30:
            alerts.append(_make_alert("churn_risk_critical", org_id, profile.get("name", org_id),
                f"Health score critically low: {hs['health_score']}/100", hs["health_score"]))
        elif hs["health_score"] < 50:
            alerts.append(_make_alert("health_degradation", org_id, profile.get("name", org_id),
                f"Health score below threshold: {hs['health_score']}/100", hs["health_score"]))

    # SLA breach alerts (check open P1/P2 tickets past response deadline)
    for ticket in support_eng.TICKETS.values():
        if ticket["status"] not in ("resolved", "closed") and ticket["priority"] in ("P1", "P2"):
            try:
                deadline = datetime.fromisoformat(ticket["sla_response_deadline"].replace("Z", "+00:00"))
                if now > deadline:
                    alerts.append(_make_alert("sla_breach", ticket["org_id"], ticket["org_id"],
                        f"SLA breach on {ticket['priority']} ticket {ticket['ticket_id']}: {ticket['subject'][:60]}",
                        100))
            except Exception:
                pass

    # Renewal risk alerts
    for r in renewal_eng.RENEWALS.values():
        if r["risk_level"] == "Critical":
            alerts.append(_make_alert("renewal_risk", r["org_id"], r["org_name"],
                f"CRITICAL renewal risk - {r['days_to_renewal']} days to contract end, score {r['renewal_score']}",
                r["renewal_score"]))
        elif r["risk_level"] == "High" and r["days_to_renewal"] <= 30:
            alerts.append(_make_alert("renewal_risk", r["org_id"], r["org_name"],
                f"High renewal risk - {r['days_to_renewal']} days remaining",
                r["renewal_score"]))

    # Billing overdue alerts
    for inv in billing_eng.INVOICES.values():
        if inv.get("overdue") and inv["status"] != "paid":
            alerts.append(_make_alert("billing_overdue", inv["org_id"], inv.get("org_name", inv["org_id"]),
                f"Invoice {inv['invoice_id']} overdue: ${inv['amount']:,.2f}",
                50))

    # Quota exceeded alerts
    for tenant_id, usage_data in tenant_eng.TENANT_USAGE.items():
        tenant = tenant_eng.TENANTS.get(tenant_id, {})
        quota = tenant.get("api_quota", {})
        if quota:
            used = usage_data.get("api_calls_today", 0)
            limit = quota.get("api_calls_per_day", 1)
            if used >= limit * 0.95:
                alerts.append(_make_alert("quota_exceeded", tenant.get("org_id", "unknown"),
                    tenant.get("name", tenant_id),
                    f"Tenant {tenant.get('name', tenant_id)} API quota at {round(used/limit*100)}%",
                    used))

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: sev_order.get(a["severity"], 4))
    return alerts


def _make_alert(alert_type: str, org_id: str, org_name: str, message: str, value: Any) -> dict:
    meta = ALERT_TYPES.get(alert_type, {"severity": "medium", "category": "general"})
    return {
        "alert_id": "alrt-" + str(uuid.uuid4())[:8],
        "type": alert_type,
        "severity": meta["severity"],
        "category": meta["category"],
        "org_id": org_id,
        "org_name": org_name,
        "message": message,
        "value": value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "acknowledged": False,
    }


def get_customer_360(org_id: str) -> dict:
    """Build a 360-degree customer view aggregating all engines."""
    # Identity
    org = identity_eng.get_org(org_id)
    if not org:
        raise ValueError(f"Organization {org_id} not found")
    users = identity_eng.list_users(org_id)

    # Subscription
    sub_status = sub_eng.get_subscription_status(org_id)

    # Billing
    billing_summary = billing_eng.get_billing_summary(org_id)

    # Health
    health_data = health_eng.HEALTH_SCORES.get(org_id)
    health_profile = health_eng.CUSTOMER_PROFILES.get(org_id, {})
    churn = health_eng.detect_churn_risk(org_id) if health_data else {}

    # Tickets
    tickets = [t for t in support_eng.TICKETS.values() if t["org_id"] == org_id]
    open_t = [t for t in tickets if t["status"] not in ("resolved", "closed")]

    # Renewal
    renewal = next((r for r in renewal_eng.RENEWALS.values() if r["org_id"] == org_id), None)

    # Tenants
    tenants = tenant_eng.list_tenants(org_id)

    # Reports
    reports = [r for r in report_eng.REPORTS.values() if r["org_id"] == org_id]

    return {
        "org_id": org_id,
        "organization": org,
        "users": [{k: v for k, v in u.items() if k != "mfa_secret"} for u in users],
        "subscription": sub_status,
        "health": {
            "score": health_data["health_score"] if health_data else None,
            "category": health_data["category"] if health_data else "unknown",
            "breakdown": health_data["breakdown"] if health_data else {},
            "churn_risk": churn.get("churn_risk"),
        },
        "billing": {
            "total_paid_usd": billing_summary.get("total_paid_usd", 0),
            "total_outstanding_usd": billing_summary.get("total_outstanding_usd", 0),
            "overdue_invoices": billing_summary.get("overdue_invoices", 0),
        },
        "support": {
            "open_tickets": len(open_t),
            "total_tickets": len(tickets),
            "p1_open": sum(1 for t in open_t if t["priority"] == "P1"),
        },
        "renewal": {
            "days_to_renewal": renewal["days_to_renewal"] if renewal else None,
            "renewal_score": renewal["renewal_score"] if renewal else None,
            "risk_level": renewal["risk_level"] if renewal else "unknown",
            "contract_value": renewal["contract_value"] if renewal else 0,
        },
        "tenants": tenants,
        "recent_reports": [{"report_id": r["report_id"], "type": r["type"],
                             "generated_at": r["generated_at"]} for r in reports[-3:]],
        "csm": health_profile.get("csm"),
        "snapshot_generated_at": datetime.now(timezone.utc).isoformat(),
    }


def run_ops_audit() -> dict:
    """Run a full platform health and compliance audit."""
    summary = get_ops_summary()
    alerts = get_all_alerts()
    issues = []
    recommendations = []

    if summary["health"]["healthy_pct"] < 70:
        issues.append(f"Customer health below target: {summary['health']['healthy_pct']}% healthy (target 70%)")
        recommendations.append("Launch proactive CSM outreach for at-risk customers")

    if summary["support"]["p1_open"] > 0:
        issues.append(f"{summary['support']['p1_open']} P1 tickets unresolved")
        recommendations.append("Escalate all open P1 tickets to senior engineering immediately")

    if summary["revenue"]["overdue_invoices"] > 0:
        issues.append(f"{summary['revenue']['overdue_invoices']} overdue invoices totaling potential ${summary['revenue']['outstanding_invoices_usd']:,.0f}")
        recommendations.append("Initiate accounts receivable follow-up for overdue invoices")

    if summary["renewals"]["high_risk_count"] > 0:
        issues.append(f"{summary['renewals']['high_risk_count']} high/critical renewal risk accounts")
        recommendations.append("Activate renewal save playbooks for high/critical risk accounts")

    critical_alerts = [a for a in alerts if a["severity"] == "critical"]
    audit_score = max(0, 100 - len(issues) * 15 - len(critical_alerts) * 10)
    return {
        "audit_id": "audit-" + str(uuid.uuid4())[:8],
        "audit_score": audit_score,
        "status": "healthy" if audit_score >= 80 else "degraded" if audit_score >= 60 else "critical",
        "issues_found": len(issues),
        "critical_alerts": len(critical_alerts),
        "issues": issues,
        "recommendations": recommendations,
        "summary": summary,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


def simulate_scale(n_customers: int) -> dict:
    """
    Simulate platform load with n_customers (10, 100, or 1000).
    Returns projected metrics and performance estimates.
    """
    if n_customers not in (10, 100, 1000):
        raise ValueError("n_customers must be 10, 100, or 1000")
    start_ts = time.time()
    plans = ["free", "professional", "enterprise", "mssp"]
    plan_weights = [0.2, 0.5, 0.25, 0.05]
    plan_prices = {"free": 0, "professional": 299, "enterprise": 999, "mssp": 2499}
    customers_simulated = []
    rng = random.Random(42)
    for i in range(n_customers):
        plan = rng.choices(plans, weights=plan_weights)[0]
        health = rng.gauss(72, 18)
        health = max(5, min(100, health))
        health_cat = "Healthy" if health >= 80 else "At Risk" if health >= 50 else "Renewal Risk"
        customers_simulated.append({
            "org_id": f"sim-org-{i:05d}",
            "plan": plan,
            "health_score": round(health, 1),
            "health_category": health_cat,
            "contract_value": plan_prices[plan] * 12,
        })
    healthy = [c for c in customers_simulated if c["health_category"] == "Healthy"]
    at_risk = [c for c in customers_simulated if c["health_category"] == "At Risk"]
    renewal_risk = [c for c in customers_simulated if c["health_category"] == "Renewal Risk"]
    total_mrr = sum(plan_prices[c["plan"]] for c in customers_simulated)
    total_arr = total_mrr * 12
    avg_health = round(sum(c["health_score"] for c in customers_simulated) / n_customers, 1)
    elapsed_ms = round((time.time() - start_ts) * 1000, 2)
    # Extrapolated support load
    est_tickets_per_month = int(n_customers * 0.15)
    est_p1_per_month = int(n_customers * 0.02)
    est_api_calls_per_day = n_customers * 8500
    return {
        "simulation_id": "sim-" + str(uuid.uuid4())[:8],
        "n_customers": n_customers,
        "simulation_time_ms": elapsed_ms,
        "projected_metrics": {
            "mrr_usd": total_mrr,
            "arr_usd": total_arr,
            "avg_health_score": avg_health,
            "healthy_pct": round(len(healthy) / n_customers * 100, 1),
            "at_risk_pct": round(len(at_risk) / n_customers * 100, 1),
            "renewal_risk_pct": round(len(renewal_risk) / n_customers * 100, 1),
            "at_risk_count": len(at_risk),
            "renewal_risk_count": len(renewal_risk),
        },
        "platform_load_estimates": {
            "api_calls_per_day": est_api_calls_per_day,
            "estimated_tickets_per_month": est_tickets_per_month,
            "estimated_p1_incidents_per_month": est_p1_per_month,
            "estimated_reports_per_month": n_customers * 4,
            "required_csm_headcount": max(1, n_customers // 50),
        },
        "plan_distribution": {
            plan: sum(1 for c in customers_simulated if c["plan"] == plan)
            for plan in plans
        },
        "simulated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/ops/summary", methods=["GET"])
def api_ops_summary():
    """Get master operations summary."""
    try:
        summary = get_ops_summary()
        return jsonify(summary), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ops/alerts", methods=["GET"])
def api_ops_alerts():
    """Get all active platform alerts."""
    try:
        alerts = get_all_alerts()
        severity = request.args.get("severity")
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        return jsonify({"alerts": alerts, "total": len(alerts),
                        "critical": sum(1 for a in alerts if a["severity"] == "critical"),
                        "high": sum(1 for a in alerts if a["severity"] == "high")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ops/customer/<org_id>", methods=["GET"])
def api_customer_360(org_id):
    """Get 360-degree customer view."""
    try:
        view = get_customer_360(org_id)
        return jsonify(view), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ops/audit", methods=["GET"])
def api_ops_audit():
    """Run and return a full ops audit."""
    try:
        audit = run_ops_audit()
        return jsonify(audit), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ops/simulate", methods=["POST"])
def api_simulate():
    """Simulate platform at scale (10, 100, 1000 customers)."""
    try:
        data = request.get_json(force=True) or {}
        n = int(data.get("n_customers", 100))
        result = simulate_scale(n)
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ops/health-map", methods=["GET"])
def api_health_map():
    """Return health status for all tracked customers."""
    try:
        health_map = []
        for org_id, hs in health_eng.HEALTH_SCORES.items():
            profile = health_eng.CUSTOMER_PROFILES.get(org_id, {})
            renewal = next((r for r in renewal_eng.RENEWALS.values() if r["org_id"] == org_id), {})
            health_map.append({
                "org_id": org_id,
                "org_name": profile.get("name", org_id),
                "plan": profile.get("plan"),
                "health_score": hs["health_score"],
                "category": hs["category"],
                "days_to_renewal": renewal.get("days_to_renewal"),
                "renewal_risk": renewal.get("risk_level"),
                "contract_value": renewal.get("contract_value", 0),
                "csm": profile.get("csm"),
            })
        health_map.sort(key=lambda x: x["health_score"])
        return jsonify({"health_map": health_map, "total": len(health_map)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ops/revenue", methods=["GET"])
def api_ops_revenue():
    """Revenue overview aggregating subscriptions, billing, and renewals."""
    try:
        plan_prices = {"free": 0, "professional": 299, "enterprise": 999, "mssp": 2499, "oem": 9999}
        active_subs = [s for s in sub_eng.SUBSCRIPTIONS.values() if s["status"] in ("active", "trialing")]
        mrr = sum(plan_prices.get(s["plan"], 0) for s in active_subs)
        forecast = renewal_eng.get_revenue_forecast()
        invoices = list(billing_eng.INVOICES.values())
        total_billed = sum(i["amount"] for i in invoices)
        total_collected = sum(i["amount"] for i in invoices if i["status"] == "paid")
        mssp_mrr = sum(p["monthly_revenue"] for p in mssp_eng.MSSP_PARTNERS.values())
        return jsonify({
            "mrr_usd": mrr,
            "arr_usd": mrr * 12,
            "mssp_mrr_usd": mssp_mrr,
            "combined_mrr_usd": mrr + mssp_mrr,
            "combined_arr_usd": (mrr + mssp_mrr) * 12,
            "total_billed_usd": round(total_billed, 2),
            "total_collected_usd": round(total_collected, 2),
            "collection_rate_pct": round(total_collected / max(total_billed, 1) * 100, 1),
            "renewal_forecast_90d": forecast["renewal_windows"]["90_days"],
            "expansion_pipeline_usd": forecast["expansion_pipeline_usd"],
            "as_of": datetime.now(timezone.utc).isoformat(),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "engine": "customer_ops_center",
        "version": "1.0.0",
        "engines_loaded": [
            "customer_identity_engine",
            "tenant_management_engine",
            "subscription_engine",
            "billing_engine",
            "customer_health_engine",
            "support_operations_engine",
            "mssp_operations_engine",
            "executive_reporting_engine",
            "renewal_engine",
        ],
    }), 200


if __name__ == "__main__":
    print("=" * 60)
    print("CYBERDUDEBIVASH SENTINEL APEX - Customer Ops Center")
    print("=" * 60)
    summary = get_ops_summary()
    print(f"  Organizations    : {summary['customers']['total_organizations']}")
    print(f"  Active Subs      : {summary['revenue']['active_subscriptions']}")
    print(f"  MRR              : ${summary['revenue']['mrr_usd']:,}/mo")
    print(f"  ARR              : ${summary['revenue']['arr_usd']:,}/yr")
    print(f"  Avg Health Score : {summary['health']['avg_health_score']}")
    print(f"  Healthy Customers: {summary['health']['healthy_pct']}%")
    print(f"  Open Tickets     : {summary['support']['open_tickets']}")
    alerts = get_all_alerts()
    critical = [a for a in alerts if a["severity"] == "critical"]
    print(f"  Active Alerts    : {len(alerts)} ({len(critical)} critical)")
    print("=" * 60)
    print("Starting Customer Ops Center on port 8510")
    app.run(host="0.0.0.0", port=8510, debug=False)
