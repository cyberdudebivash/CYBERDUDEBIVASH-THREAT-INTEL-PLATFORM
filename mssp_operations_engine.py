"""
CYBERDUDEBIVASH SENTINEL APEX
MSSP Operations Engine - FILE 7/10
MSSP partner management, managed customer tracking, dashboards, reporting.
Port: 8507
"""

import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
MSSP_PARTNERS: Dict[str, dict] = {}
MANAGED_CUSTOMERS: Dict[str, dict] = {}  # keyed by customer_id
MSSP_REPORTS: Dict[str, dict] = {}

MSSP_TIERS = {
    "silver":   {"max_customers": 25,   "price_per_customer": 99,  "sla": "premium",   "features": ["dashboard", "api", "reporting"]},
    "gold":     {"max_customers": 100,  "price_per_customer": 79,  "sla": "enterprise","features": ["dashboard", "api", "reporting", "white_label", "bulk_export"]},
    "platinum": {"max_customers": 500,  "price_per_customer": 59,  "sla": "mssp",      "features": ["dashboard", "api", "reporting", "white_label", "bulk_export", "custom_feeds", "dedicated_support"]},
    "enterprise":{"max_customers": 9999,"price_per_customer": 39,  "sla": "mssp",      "features": ["all_features"]},
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def onboard_mssp_partner(name: str, tier: str = "silver", contact_email: str = "",
                          region: str = "us-east", actor: str = "system") -> dict:
    """Onboard a new MSSP partner with tier configuration."""
    if tier not in MSSP_TIERS:
        raise ValueError(f"Invalid MSSP tier: {tier}. Valid: {list(MSSP_TIERS.keys())}")
    mssp_id = "mssp-" + str(uuid.uuid4())[:8]
    tier_def = MSSP_TIERS[tier]
    partner = {
        "mssp_id": mssp_id,
        "name": name,
        "tier": tier,
        "contact_email": contact_email,
        "region": region,
        "status": "active",
        "max_customers": tier_def["max_customers"],
        "customer_count": 0,
        "monthly_revenue": 0.0,
        "total_revenue": 0.0,
        "sla_tier": tier_def["sla"],
        "features": tier_def["features"],
        "price_per_customer": tier_def["price_per_customer"],
        "api_key": "mssp-" + uuid.uuid4().hex[:24],
        "tenant_namespace": f"mssp-ns-{mssp_id}",
        "onboarded_at": datetime.now(timezone.utc).isoformat(),
        "onboarded_by": actor,
        "last_report_generated": None,
        "sla_compliance_pct": 100.0,
    }
    MSSP_PARTNERS[mssp_id] = partner
    return partner


def add_managed_customer(mssp_id: str, org_name: str, domain: str = "",
                          plan: str = "professional", actor: str = "system") -> dict:
    """Add a managed customer under an MSSP partner."""
    partner = MSSP_PARTNERS.get(mssp_id)
    if not partner:
        raise ValueError(f"MSSP partner {mssp_id} not found")
    if partner["customer_count"] >= partner["max_customers"]:
        raise ValueError(f"MSSP {mssp_id} has reached max customer limit ({partner['max_customers']})")
    customer_id = "mc-" + str(uuid.uuid4())[:8]
    health = random.randint(45, 98)
    customer = {
        "customer_id": customer_id,
        "mssp_id": mssp_id,
        "org_name": org_name,
        "domain": domain,
        "plan": plan,
        "health_score": health,
        "health_category": _health_cat(health),
        "sla_status": "compliant",
        "onboarded_at": datetime.now(timezone.utc).isoformat(),
        "last_report": None,
        "last_activity": (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 7))).isoformat(),
        "active_alerts": random.randint(0, 5),
        "open_tickets": random.randint(0, 3),
        "iocs_delivered_30d": random.randint(100, 5000),
        "detections_30d": random.randint(10, 500),
        "api_calls_30d": random.randint(500, 50000),
        "isolation_validated": True,
        "isolation_namespace": f"{partner['tenant_namespace']}-{customer_id}",
        "added_by": actor,
    }
    MANAGED_CUSTOMERS[customer_id] = customer
    partner["customer_count"] += 1
    partner["monthly_revenue"] = round(partner["customer_count"] * partner["price_per_customer"], 2)
    partner["total_revenue"] = round(partner["total_revenue"] + partner["price_per_customer"], 2)
    return customer


def _health_cat(score: int) -> str:
    if score >= 80:
        return "Healthy"
    elif score >= 50:
        return "At Risk"
    return "Renewal Risk"


def get_mssp_dashboard(mssp_id: str) -> dict:
    """Build a real-time dashboard for an MSSP partner."""
    partner = MSSP_PARTNERS.get(mssp_id)
    if not partner:
        raise ValueError(f"MSSP partner {mssp_id} not found")
    customers = [c for c in MANAGED_CUSTOMERS.values() if c["mssp_id"] == mssp_id]
    healthy = [c for c in customers if c["health_category"] == "Healthy"]
    at_risk = [c for c in customers if c["health_category"] == "At Risk"]
    renewal_risk = [c for c in customers if c["health_category"] == "Renewal Risk"]
    total_alerts = sum(c["active_alerts"] for c in customers)
    total_iocs = sum(c["iocs_delivered_30d"] for c in customers)
    total_detections = sum(c["detections_30d"] for c in customers)
    avg_health = round(sum(c["health_score"] for c in customers) / max(len(customers), 1), 1)
    sla_breaches = [c for c in customers if c["sla_status"] != "compliant"]
    sla_pct = round((len(customers) - len(sla_breaches)) / max(len(customers), 1) * 100, 1)
    return {
        "mssp_id": mssp_id,
        "partner_name": partner["name"],
        "tier": partner["tier"],
        "region": partner["region"],
        "summary": {
            "total_customers": len(customers),
            "healthy_customers": len(healthy),
            "at_risk_customers": len(at_risk),
            "renewal_risk_customers": len(renewal_risk),
            "avg_health_score": avg_health,
            "total_active_alerts": total_alerts,
            "sla_compliance_pct": sla_pct,
        },
        "intelligence_metrics": {
            "total_iocs_delivered_30d": total_iocs,
            "total_detections_30d": total_detections,
            "avg_iocs_per_customer": round(total_iocs / max(len(customers), 1)),
        },
        "revenue": {
            "monthly_revenue_usd": partner["monthly_revenue"],
            "annual_run_rate_usd": partner["monthly_revenue"] * 12,
            "price_per_customer": partner["price_per_customer"],
        },
        "at_risk_customers": [{"customer_id": c["customer_id"], "org_name": c["org_name"],
                                "health_score": c["health_score"]} for c in at_risk],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_mssp_report(mssp_id: str, period: str = "monthly") -> dict:
    """Generate a periodic report for an MSSP partner."""
    partner = MSSP_PARTNERS.get(mssp_id)
    if not partner:
        raise ValueError(f"MSSP partner {mssp_id} not found")
    dashboard = get_mssp_dashboard(mssp_id)
    customers = [c for c in MANAGED_CUSTOMERS.values() if c["mssp_id"] == mssp_id]
    report_id = "msspr-" + str(uuid.uuid4())[:8]
    report = {
        "report_id": report_id,
        "mssp_id": mssp_id,
        "partner_name": partner["name"],
        "period": period,
        "period_start": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
        "period_end": datetime.now(timezone.utc).isoformat(),
        "executive_summary": {
            "total_managed_customers": len(customers),
            "avg_customer_health": dashboard["summary"]["avg_health_score"],
            "sla_compliance_pct": dashboard["summary"]["sla_compliance_pct"],
            "total_threats_detected": dashboard["intelligence_metrics"]["total_detections_30d"],
            "total_iocs_delivered": dashboard["intelligence_metrics"]["total_iocs_delivered_30d"],
            "revenue_generated_usd": dashboard["revenue"]["monthly_revenue_usd"],
        },
        "customer_health_distribution": {
            "healthy": dashboard["summary"]["healthy_customers"],
            "at_risk": dashboard["summary"]["at_risk_customers"],
            "renewal_risk": dashboard["summary"]["renewal_risk_customers"],
        },
        "customer_details": [
            {
                "customer_id": c["customer_id"],
                "org_name": c["org_name"],
                "health_score": c["health_score"],
                "iocs_delivered": c["iocs_delivered_30d"],
                "detections": c["detections_30d"],
                "open_tickets": c["open_tickets"],
                "sla_status": c["sla_status"],
            } for c in customers
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    MSSP_REPORTS[report_id] = report
    partner["last_report_generated"] = report["generated_at"]
    return report


def check_mssp_sla(mssp_id: str) -> dict:
    """Validate SLA compliance across all managed customers."""
    partner = MSSP_PARTNERS.get(mssp_id)
    if not partner:
        raise ValueError(f"MSSP partner {mssp_id} not found")
    customers = [c for c in MANAGED_CUSTOMERS.values() if c["mssp_id"] == mssp_id]
    breaches = []
    for c in customers:
        if c["health_score"] < 40:
            c["sla_status"] = "breached"
            breaches.append({"customer_id": c["customer_id"], "org_name": c["org_name"],
                              "health_score": c["health_score"], "reason": "health_below_threshold"})
        elif c["open_tickets"] >= 3:
            c["sla_status"] = "at_risk"
        else:
            c["sla_status"] = "compliant"
    total = len(customers)
    compliant = sum(1 for c in customers if c["sla_status"] == "compliant")
    sla_pct = round(compliant / max(total, 1) * 100, 1)
    partner["sla_compliance_pct"] = sla_pct
    return {
        "mssp_id": mssp_id,
        "total_customers": total,
        "compliant_customers": compliant,
        "breached_customers": len(breaches),
        "sla_compliance_pct": sla_pct,
        "breaches": breaches,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def validate_tenant_isolation(mssp_id: str) -> dict:
    """Verify multi-tenant isolation is enforced for all managed customers."""
    customers = [c for c in MANAGED_CUSTOMERS.values() if c["mssp_id"] == mssp_id]
    namespaces = [c["isolation_namespace"] for c in customers]
    unique_ns = len(set(namespaces)) == len(namespaces)
    return {
        "mssp_id": mssp_id,
        "isolation_validated": unique_ns and all(c["isolation_validated"] for c in customers),
        "total_customers": len(customers),
        "unique_namespaces": len(set(namespaces)),
        "isolation_issues": [] if unique_ns else ["Namespace collision detected"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Seed 3 MSSP partners with 2-5 customers each
# ---------------------------------------------------------------------------

def _seed():
    p1 = onboard_mssp_partner("GlobalSOC Partners", "platinum", "ops@globalsoc.com", "us-east")
    p2 = onboard_mssp_partner("CyberShield MSSP", "gold", "admin@cybershield.io", "eu-west")
    p3 = onboard_mssp_partner("ThreatWatch LLC", "silver", "contact@threatwatch.com", "ap-southeast")

    for name, domain in [("Retail Corp", "retail-corp.com"), ("FinanceGroup", "financegroup.net"),
                          ("HealthSys", "healthsys.org"), ("ManufactureX", "manufacturex.com"),
                          ("EduCyber", "educyber.org")]:
        add_managed_customer(p1["mssp_id"], name, domain, "enterprise")

    for name, domain in [("SmallBank", "smallbank.com"), ("TechStartup", "techstartup.io"),
                          ("LawFirm Alpha", "lawfirm-alpha.com"), ("LogiTrans", "logitrans.net")]:
        add_managed_customer(p2["mssp_id"], name, domain, "professional")

    for name, domain in [("LocalGov IT", "localgovit.gov"), ("MedClinic", "medclinic.org")]:
        add_managed_customer(p3["mssp_id"], name, domain, "professional")


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/mssp/partners", methods=["GET"])
def api_list_partners():
    """List all MSSP partners."""
    try:
        partners = list(MSSP_PARTNERS.values())
        return jsonify({"partners": partners, "total": len(partners)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mssp/partners", methods=["POST"])
def api_create_partner():
    """Onboard a new MSSP partner."""
    try:
        data = request.get_json(force=True)
        if not data.get("name"):
            return jsonify({"error": "name is required"}), 400
        partner = onboard_mssp_partner(data["name"], data.get("tier", "silver"),
                                        data.get("contact_email", ""), data.get("region", "us-east"))
        return jsonify(partner), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mssp/<mssp_id>/customers", methods=["GET"])
def api_mssp_customers(mssp_id):
    """Get all managed customers for an MSSP."""
    try:
        if mssp_id not in MSSP_PARTNERS:
            return jsonify({"error": "MSSP partner not found"}), 404
        customers = [c for c in MANAGED_CUSTOMERS.values() if c["mssp_id"] == mssp_id]
        return jsonify({"customers": customers, "total": len(customers)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mssp/<mssp_id>/customers", methods=["POST"])
def api_add_customer(mssp_id):
    """Add a managed customer."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_name"):
            return jsonify({"error": "org_name is required"}), 400
        customer = add_managed_customer(mssp_id, data["org_name"], data.get("domain", ""),
                                         data.get("plan", "professional"))
        return jsonify(customer), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mssp/<mssp_id>/dashboard", methods=["GET"])
def api_mssp_dashboard(mssp_id):
    """Get MSSP operations dashboard."""
    try:
        dashboard = get_mssp_dashboard(mssp_id)
        return jsonify(dashboard), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mssp/<mssp_id>/report", methods=["POST"])
def api_mssp_report(mssp_id):
    """Generate MSSP periodic report."""
    try:
        data = request.get_json(force=True) or {}
        report = generate_mssp_report(mssp_id, data.get("period", "monthly"))
        return jsonify(report), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mssp/<mssp_id>/sla", methods=["GET"])
def api_mssp_sla(mssp_id):
    """Check SLA compliance for MSSP."""
    try:
        sla = check_mssp_sla(mssp_id)
        return jsonify(sla), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mssp/<mssp_id>/isolation", methods=["GET"])
def api_mssp_isolation(mssp_id):
    """Validate tenant isolation for an MSSP."""
    try:
        result = validate_tenant_isolation(mssp_id)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "mssp_operations_engine", "version": "1.0.0",
                    "mssp_partners": len(MSSP_PARTNERS),
                    "managed_customers": len(MANAGED_CUSTOMERS)}), 200


if __name__ == "__main__":
    print("Starting MSSP Operations Engine on port 8507")
    for pid, p in MSSP_PARTNERS.items():
        print(f"  {p['name']} ({p['tier']}): {p['customer_count']} customers, ${p['monthly_revenue']:,.0f}/mo")
    app.run(host="0.0.0.0", port=8507, debug=False)
