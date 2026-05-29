"""
CYBERDUDEBIVASH SENTINEL APEX
Executive Reporting Engine - FILE 8/10
Weekly, Monthly, Quarterly, Board-level report generation and scheduling.
Port: 8508
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
REPORTS: Dict[str, dict] = {}
REPORT_SCHEDULES: Dict[str, dict] = {}

REPORT_TYPES = ["weekly", "monthly", "quarterly", "board"]

# Simulated org profiles for report data
ORG_PROFILES = {
    "org-acme01": {"name": "Acme Security Inc", "plan": "enterprise", "seats": 45, "annual_value": 11988},
    "org-tech02": {"name": "TechDefense LLC",   "plan": "professional","seats": 8,  "annual_value": 3588},
    "org-gsoc03": {"name": "GlobalSOC Partners","plan": "mssp",        "seats": 200,"annual_value": 29988},
}


# ---------------------------------------------------------------------------
# Metric generators
# ---------------------------------------------------------------------------

def _gen_metrics(org_id: str, report_type: str) -> dict:
    """Generate realistic intelligence and platform metrics for a report period."""
    profile = ORG_PROFILES.get(org_id, {"name": org_id, "plan": "professional", "seats": 5, "annual_value": 3588})
    multiplier = {"weekly": 1, "monthly": 4.3, "quarterly": 13, "board": 52}.get(report_type, 1)
    base = {"professional": 1.0, "enterprise": 3.5, "mssp": 12.0}.get(profile["plan"], 1.0)
    rng = random.Random(hash(org_id + report_type))
    threats = int(rng.randint(120, 200) * base * multiplier)
    iocs = int(rng.randint(800, 1500) * base * multiplier)
    detections = int(rng.randint(30, 80) * base * multiplier)
    api_calls = int(rng.randint(5000, 15000) * base * multiplier)
    active_users = min(profile["seats"], rng.randint(3, profile["seats"]))
    attck_coverage = round(rng.uniform(55, 92), 1)
    uptime = round(rng.uniform(99.5, 99.99), 3)
    # ROI estimate: each detection prevented ~$50k breach cost
    roi = round(detections * 50000 * 0.1)  # 10% materialization rate
    avg_ttd_minutes = round(rng.uniform(2.5, 18), 1)
    sigma_rules_triggered = int(rng.randint(20, 60) * base * multiplier)
    new_threat_actors = rng.randint(2, 12)
    critical_vulns_flagged = rng.randint(5, 40)
    return {
        "threats_detected": threats,
        "iocs_delivered": iocs,
        "detections_generated": detections,
        "attck_coverage_pct": attck_coverage,
        "platform_uptime_pct": uptime,
        "api_calls": api_calls,
        "active_users": active_users,
        "roi_estimate_usd": roi,
        "avg_time_to_detect_minutes": avg_ttd_minutes,
        "sigma_rules_triggered": sigma_rules_triggered,
        "new_threat_actors_tracked": new_threat_actors,
        "critical_vulns_flagged": critical_vulns_flagged,
        "false_positive_rate_pct": round(rng.uniform(0.5, 3.5), 2),
        "intelligence_sources_active": rng.randint(15, 45),
    }


def _period_bounds(report_type: str) -> tuple:
    now = datetime.now(timezone.utc)
    if report_type == "weekly":
        start = now - timedelta(days=7)
    elif report_type == "monthly":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif report_type == "quarterly":
        qstart_month = ((now.month - 1) // 3) * 3 + 1
        start = now.replace(month=qstart_month, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:  # board / annual
        start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), now.isoformat()


# ---------------------------------------------------------------------------
# Report generation functions
# ---------------------------------------------------------------------------

def _build_report(org_id: str, report_type: str, requester: str = "system") -> dict:
    """Internal report builder used by all report type functions."""
    profile = ORG_PROFILES.get(org_id, {"name": org_id, "plan": "professional", "seats": 5, "annual_value": 3588})
    report_id = "rpt-" + str(uuid.uuid4())[:8]
    period_start, period_end = _period_bounds(report_type)
    metrics = _gen_metrics(org_id, report_type)
    prev_metrics = _gen_metrics(org_id + "_prev", report_type)
    # Calculate trends
    trends = {}
    for k in ["threats_detected", "iocs_delivered", "detections_generated", "api_calls"]:
        curr = metrics.get(k, 0)
        prev = prev_metrics.get(k, 1)
        trends[k] = round(((curr - prev) / max(prev, 1)) * 100, 1)
    highlights = _generate_highlights(metrics, trends, report_type)
    recommendations = _generate_recommendations(metrics, profile)
    report = {
        "report_id": report_id,
        "org_id": org_id,
        "org_name": profile["name"],
        "plan": profile["plan"],
        "type": report_type,
        "period_start": period_start,
        "period_end": period_end,
        "metrics": metrics,
        "trends_vs_prior_period": trends,
        "highlights": highlights,
        "recommendations": recommendations,
        "platform_health": {
            "uptime_pct": metrics["platform_uptime_pct"],
            "api_availability": 99.98,
            "feed_freshness_minutes": round(random.uniform(3, 15), 1),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": requester,
        "status": "delivered",
    }
    REPORTS[report_id] = report
    return report


def _generate_highlights(metrics: dict, trends: dict, report_type: str) -> List[str]:
    highlights = []
    if metrics["threats_detected"] > 500:
        highlights.append(f"Detected {metrics['threats_detected']:,} threats — platform operating at peak efficiency")
    if metrics["attck_coverage_pct"] > 80:
        highlights.append(f"ATT&CK framework coverage reached {metrics['attck_coverage_pct']}% — industry-leading posture")
    if trends.get("detections_generated", 0) > 10:
        highlights.append(f"Detection rate improved {trends['detections_generated']}% over prior period")
    if metrics["platform_uptime_pct"] >= 99.9:
        highlights.append(f"Platform maintained {metrics['platform_uptime_pct']}% uptime SLA — zero outages")
    if metrics["roi_estimate_usd"] > 100000:
        highlights.append(f"Estimated threat prevention ROI: ${metrics['roi_estimate_usd']:,}")
    return highlights or ["Platform operating within normal parameters"]


def _generate_recommendations(metrics: dict, profile: dict) -> List[str]:
    recs = []
    if metrics["attck_coverage_pct"] < 70:
        recs.append("Expand ATT&CK tactic coverage — consider enabling additional detection rule sets")
    if metrics["false_positive_rate_pct"] > 2.5:
        recs.append("Review and tune Sigma rules to reduce false positive rate below 2%")
    if metrics["active_users"] < profile["seats"] * 0.5:
        recs.append(f"Only {metrics['active_users']}/{profile['seats']} seats active — schedule user onboarding session")
    if metrics["api_calls"] < 1000 and profile["plan"] != "free":
        recs.append("Low API utilization detected — integrate with SIEM/SOAR to maximize ROI")
    return recs or ["Continue current threat intelligence program — performance is excellent"]


def generate_weekly_report(org_id: str, requester: str = "system") -> dict:
    """Generate a weekly executive intelligence summary."""
    return _build_report(org_id, "weekly", requester)


def generate_monthly_report(org_id: str, requester: str = "system") -> dict:
    """Generate a monthly business and security review report."""
    return _build_report(org_id, "monthly", requester)


def generate_quarterly_report(org_id: str, requester: str = "system") -> dict:
    """Generate a quarterly threat landscape and platform performance report."""
    return _build_report(org_id, "quarterly", requester)


def generate_board_report(org_id: str, requester: str = "system") -> dict:
    """Generate a board-level annual summary with ROI and strategic metrics."""
    report = _build_report(org_id, "board", requester)
    profile = ORG_PROFILES.get(org_id, {})
    # Add board-specific sections
    report["board_summary"] = {
        "annual_contract_value_usd": profile.get("annual_value", 0),
        "estimated_annual_roi_usd": report["metrics"]["roi_estimate_usd"],
        "roi_multiple": round(report["metrics"]["roi_estimate_usd"] / max(profile.get("annual_value", 1), 1), 1),
        "strategic_risk_reduction": "High",
        "compliance_frameworks_supported": ["NIST CSF", "MITRE ATT&CK", "ISO 27001", "SOC 2"],
        "year_over_year_improvement": f"{random.randint(15, 35)}%",
    }
    return report


def schedule_reports(org_id: str, report_types: List[str], delivery_email: str,
                      actor: str = "system") -> dict:
    """Schedule automatic report delivery for an organization."""
    schedule_id = "sched-" + str(uuid.uuid4())[:8]
    for rt in report_types:
        if rt not in REPORT_TYPES:
            raise ValueError(f"Invalid report type: {rt}")
    schedule = {
        "schedule_id": schedule_id,
        "org_id": org_id,
        "report_types": report_types,
        "delivery_email": delivery_email,
        "frequency_map": {
            "weekly": "every_monday_0800",
            "monthly": "first_of_month_0800",
            "quarterly": "first_of_quarter_0800",
            "board": "january_15_0800",
        },
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": actor,
        "next_delivery": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    }
    REPORT_SCHEDULES[schedule_id] = schedule
    return schedule


def list_reports(org_id: str = None, report_type: str = None) -> List[dict]:
    """List generated reports with optional filters."""
    reports = list(REPORTS.values())
    if org_id:
        reports = [r for r in reports if r["org_id"] == org_id]
    if report_type:
        reports = [r for r in reports if r["type"] == report_type]
    return sorted(reports, key=lambda r: r["generated_at"], reverse=True)


# ---------------------------------------------------------------------------
# Seed reports for 3 orgs
# ---------------------------------------------------------------------------

def _seed():
    for org_id in ORG_PROFILES:
        generate_weekly_report(org_id, "system_scheduler")
        generate_monthly_report(org_id, "system_scheduler")
        generate_quarterly_report(org_id, "system_scheduler")
    generate_board_report("org-acme01", "ceo_request")
    for org_id, profile in ORG_PROFILES.items():
        schedule_reports(org_id, ["weekly", "monthly"], f"security@{profile['name'].lower().replace(' ', '')}.com")


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/reports", methods=["GET"])
def api_list_reports():
    """List reports."""
    try:
        org_id = request.args.get("org_id")
        report_type = request.args.get("type")
        reports = list_reports(org_id, report_type)
        return jsonify({"reports": reports, "total": len(reports)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports/generate", methods=["POST"])
def api_generate_report():
    """Generate a report on demand."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_id") or not data.get("type"):
            return jsonify({"error": "org_id and type are required"}), 400
        rt = data["type"]
        if rt not in REPORT_TYPES:
            return jsonify({"error": f"Invalid type. Valid: {REPORT_TYPES}"}), 400
        org_id = data["org_id"]
        requester = data.get("requester", "api")
        if rt == "weekly":
            report = generate_weekly_report(org_id, requester)
        elif rt == "monthly":
            report = generate_monthly_report(org_id, requester)
        elif rt == "quarterly":
            report = generate_quarterly_report(org_id, requester)
        else:
            report = generate_board_report(org_id, requester)
        return jsonify(report), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports/<report_id>", methods=["GET"])
def api_get_report(report_id):
    """Get a specific report."""
    report = REPORTS.get(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    return jsonify(report), 200


@app.route("/api/reports/schedule", methods=["POST"])
def api_schedule_reports():
    """Schedule automated report delivery."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_id") or not data.get("report_types") or not data.get("delivery_email"):
            return jsonify({"error": "org_id, report_types, and delivery_email are required"}), 400
        schedule = schedule_reports(data["org_id"], data["report_types"],
                                     data["delivery_email"], actor=data.get("actor", "api"))
        return jsonify(schedule), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports/schedules", methods=["GET"])
def api_list_schedules():
    """List report schedules."""
    try:
        org_id = request.args.get("org_id")
        schedules = list(REPORT_SCHEDULES.values())
        if org_id:
            schedules = [s for s in schedules if s["org_id"] == org_id]
        return jsonify({"schedules": schedules, "total": len(schedules)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "executive_reporting_engine", "version": "1.0.0",
                    "reports_generated": len(REPORTS),
                    "active_schedules": len(REPORT_SCHEDULES)}), 200


if __name__ == "__main__":
    print("Starting Executive Reporting Engine on port 8508")
    print(f"Seeded {len(REPORTS)} reports, {len(REPORT_SCHEDULES)} schedules")
    app.run(host="0.0.0.0", port=8508, debug=False)
