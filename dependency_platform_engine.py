"""
CYBERDUDEBIVASH SENTINEL APEX — Phase 100
Customer Dependency Platform Engine
Port: 8515

Tracks all integration touchpoints that create platform stickiness: scheduled
reports, API integrations, webhooks, detection rule distribution, and SOC workflows.
Calculates dependency scores and simulates daily operations.
"""

import uuid
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
scheduled_reports: dict = {}
api_integrations: dict = {}
webhook_subscriptions: dict = {}
detection_distributions: dict = {}
soc_workflows: dict = {}
org_registry: dict = {}

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
def _seed():
    random.seed(99)
    now = datetime.utcnow()

    orgs = [
        {"org_id": "ORG-001", "name": "Apex FinGroup"},
        {"org_id": "ORG-002", "name": "NovaMed Health"},
        {"org_id": "ORG-003", "name": "ClearLogix LLC"},
    ]
    for org in orgs:
        org_registry[org["org_id"]] = org

    # Scheduled reports
    report_configs = [
        ("ORG-001", "threat_intelligence", "daily", ["soc@apexfin.com", "ciso@apexfin.com"]),
        ("ORG-001", "executive_summary", "weekly", ["ceo@apexfin.com", "ciso@apexfin.com"]),
        ("ORG-001", "compliance_posture", "monthly", ["compliance@apexfin.com"]),
        ("ORG-002", "threat_intelligence", "weekly", ["security@novamed.io"]),
        ("ORG-002", "incident_digest", "daily", ["soc@novamed.io"]),
        ("ORG-003", "executive_summary", "monthly", ["admin@clearlogix.net"]),
        ("ORG-003", "threat_intelligence", "weekly", ["it@clearlogix.net"]),
    ]
    for org_id, rtype, freq, recipients in report_configs:
        sid = _next_id("SCHED")
        scheduled_reports[sid] = {
            "schedule_id": sid,
            "org_id": org_id,
            "report_type": rtype,
            "frequency": freq,
            "next_run": (now + timedelta(days=1)).isoformat(),
            "recipients": recipients,
            "last_sent": (now - timedelta(days=random.randint(1, 7))).isoformat(),
            "status": "active",
        }

    # API integrations
    integrations_seed = [
        ("ORG-001", "Splunk SIEM", "siem", "https://splunk.apexfin.internal/api", "api_key"),
        ("ORG-001", "ServiceNow Ticketing", "ticketing", "https://apexfin.service-now.com/api", "oauth2"),
        ("ORG-001", "Palo Alto SOAR", "soar", "https://soar.apexfin.internal/xsoar/api", "bearer"),
        ("ORG-002", "Microsoft Sentinel", "siem", "https://management.azure.com/sentinel", "oauth2"),
        ("ORG-002", "Jira Service Desk", "ticketing", "https://novamed.atlassian.net/rest/api", "basic"),
        ("ORG-003", "QRadar SIEM", "siem", "https://qradar.clearlogix.net/api", "api_key"),
        ("ORG-003", "Custom Webhook", "custom", "https://hooks.clearlogix.net/sentinel", "hmac"),
    ]
    for org_id, name, itype, endpoint, auth in integrations_seed:
        iid = _next_id("INT")
        api_integrations[iid] = {
            "integration_id": iid,
            "org_id": org_id,
            "name": name,
            "type": itype,
            "endpoint": endpoint,
            "auth_type": auth,
            "last_sync": (now - timedelta(minutes=random.randint(5, 120))).isoformat(),
            "records_synced": random.randint(100, 5000),
            "status": "active",
        }

    # Webhooks
    webhook_seed = [
        ("ORG-001", "https://hooks.apexfin.com/sentinel", ["threat.critical", "incident.new", "advisory.published"]),
        ("ORG-002", "https://novamed.io/webhooks/sentinel", ["threat.critical", "cve.high"]),
        ("ORG-003", "https://clearlogix.net/api/hooks", ["advisory.published"]),
    ]
    for org_id, url, events in webhook_seed:
        wid = _next_id("WH")
        webhook_subscriptions[wid] = {
            "webhook_id": wid,
            "org_id": org_id,
            "url": url,
            "events": events,
            "secret": uuid.uuid4().hex,
            "delivery_count": random.randint(50, 800),
            "failure_count": random.randint(0, 5),
            "last_delivery": (now - timedelta(hours=random.randint(1, 24))).isoformat(),
        }

    # Detection distributions
    dist_seed = [
        ("ORG-001", "sigma", "Splunk"),
        ("ORG-001", "kql", "Microsoft Sentinel"),
        ("ORG-002", "kql", "Microsoft Sentinel"),
        ("ORG-002", "yara", "CrowdStrike"),
        ("ORG-003", "sigma", "QRadar"),
    ]
    for org_id, fmt, platform in dist_seed:
        did = _next_id("DIST")
        detection_distributions[did] = {
            "dist_id": did,
            "org_id": org_id,
            "format": fmt,
            "platform": platform,
            "rules_distributed": random.randint(40, 250),
            "last_distribution": (now - timedelta(hours=random.randint(2, 48))).isoformat(),
        }

    # SOC workflows
    workflows_seed = [
        ("ORG-001", "Auto-Escalate Critical Threats", "threat.critical", ["create_ticket", "page_oncall", "isolate_host"]),
        ("ORG-001", "Phishing Response", "email.suspicious", ["quarantine_email", "reset_credentials", "notify_user"]),
        ("ORG-002", "Ransomware Containment", "threat.ransomware", ["isolate_host", "snapshot_disk", "create_ticket"]),
        ("ORG-003", "IOC Enrichment", "ioc.new", ["enrich_vtotal", "update_blocklist"]),
    ]
    for org_id, name, trigger, actions in workflows_seed:
        wfid = _next_id("WF")
        soc_workflows[wfid] = {
            "workflow_id": wfid,
            "org_id": org_id,
            "name": name,
            "trigger": trigger,
            "actions": actions,
            "status": "active",
            "executions_count": random.randint(5, 120),
        }


def _next_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"

_seed()

# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------

def create_scheduled_report(org_id: str, report_type: str, frequency: str, recipients: list) -> dict:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")
    sid = _next_id("SCHED")
    now = datetime.utcnow()
    freq_days = {"daily": 1, "weekly": 7, "monthly": 30}.get(frequency, 7)
    record = {
        "schedule_id": sid,
        "org_id": org_id,
        "report_type": report_type,
        "frequency": frequency,
        "next_run": (now + timedelta(days=freq_days)).isoformat(),
        "recipients": recipients,
        "last_sent": None,
        "status": "active",
    }
    scheduled_reports[sid] = record
    return record


def register_api_integration(org_id: str, name: str, itype: str, endpoint: str) -> dict:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")
    iid = _next_id("INT")
    record = {
        "integration_id": iid,
        "org_id": org_id,
        "name": name,
        "type": itype,
        "endpoint": endpoint,
        "auth_type": "api_key",
        "last_sync": None,
        "records_synced": 0,
        "status": "active",
    }
    api_integrations[iid] = record
    return record


def add_webhook(org_id: str, url: str, events: list) -> dict:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")
    wid = _next_id("WH")
    record = {
        "webhook_id": wid,
        "org_id": org_id,
        "url": url,
        "events": events,
        "secret": uuid.uuid4().hex,
        "delivery_count": 0,
        "failure_count": 0,
        "last_delivery": None,
    }
    webhook_subscriptions[wid] = record
    return record


def configure_detection_distribution(org_id: str, fmt: str, platform: str) -> dict:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")
    did = _next_id("DIST")
    record = {
        "dist_id": did,
        "org_id": org_id,
        "format": fmt,
        "platform": platform,
        "rules_distributed": 0,
        "last_distribution": None,
    }
    detection_distributions[did] = record
    return record


def create_soc_workflow(org_id: str, name: str, trigger: str, actions: list) -> dict:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")
    wfid = _next_id("WF")
    record = {
        "workflow_id": wfid,
        "org_id": org_id,
        "name": name,
        "trigger": trigger,
        "actions": actions,
        "status": "active",
        "executions_count": 0,
    }
    soc_workflows[wfid] = record
    return record


def calculate_dependency_score(org_id: str) -> dict:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")

    integrations = [i for i in api_integrations.values() if i["org_id"] == org_id and i["status"] == "active"]
    reports = [r for r in scheduled_reports.values() if r["org_id"] == org_id and r["status"] == "active"]
    webhooks = [w for w in webhook_subscriptions.values() if w["org_id"] == org_id]
    dists = [d for d in detection_distributions.values() if d["org_id"] == org_id]
    workflows = [wf for wf in soc_workflows.values() if wf["org_id"] == org_id and wf["status"] == "active"]

    # Scoring weights
    score = (
        min(len(integrations) * 15, 30) +
        min(len(reports) * 8, 25) +
        min(len(webhooks) * 10, 20) +
        min(len(dists) * 8, 15) +
        min(len(workflows) * 5, 10)
    )

    return {
        "org_id": org_id,
        "score": min(score, 100),
        "integrations_count": len(integrations),
        "reports_count": len(reports),
        "webhooks_count": len(webhooks),
        "detection_distributions_count": len(dists),
        "workflows_count": len(workflows),
    }


def get_platform_stickiness() -> list:
    rankings = []
    for org_id, org in org_registry.items():
        dep = calculate_dependency_score(org_id)
        rankings.append({
            "org_id": org_id,
            "org_name": org["name"],
            "dependency_score": dep["score"],
            "integrations": dep["integrations_count"],
            "reports": dep["reports_count"],
            "webhooks": dep["webhooks_count"],
            "workflows": dep["workflows_count"],
        })
    return sorted(rankings, key=lambda x: x["dependency_score"], reverse=True)


def simulate_daily_operations() -> dict:
    now = datetime.utcnow()
    reports_sent = 0
    webhooks_fired = 0
    syncs_run = 0

    # Process scheduled reports due today
    for rec in scheduled_reports.values():
        if rec["status"] != "active":
            continue
        next_run = datetime.fromisoformat(rec["next_run"])
        if next_run <= now:
            rec["last_sent"] = now.isoformat()
            freq_days = {"daily": 1, "weekly": 7, "monthly": 30}.get(rec["frequency"], 7)
            rec["next_run"] = (now + timedelta(days=freq_days)).isoformat()
            reports_sent += 1

    # Simulate webhook deliveries
    for wh in webhook_subscriptions.values():
        deliveries = random.randint(1, 5)
        wh["delivery_count"] += deliveries
        wh["last_delivery"] = now.isoformat()
        webhooks_fired += deliveries

    # Simulate integration syncs
    for integration in api_integrations.values():
        if integration["status"] == "active":
            new_records = random.randint(10, 500)
            integration["records_synced"] += new_records
            integration["last_sync"] = now.isoformat()
            syncs_run += 1

    # Update detection distributions
    for dist in detection_distributions.values():
        new_rules = random.randint(0, 3)
        dist["rules_distributed"] += new_rules
        dist["last_distribution"] = now.isoformat()

    return {
        "simulation_time": now.isoformat(),
        "reports_dispatched": reports_sent,
        "webhook_deliveries": webhooks_fired,
        "integration_syncs": syncs_run,
        "status": "completed",
    }

# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/api/dependency/<org_id>/reports", methods=["GET"])
def api_get_reports(org_id):
    """List all scheduled reports for an organization."""
    try:
        if org_id not in org_registry:
            return jsonify({"error": f"Org {org_id} not found"}), 404
        result = [r for r in scheduled_reports.values() if r["org_id"] == org_id]
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/reports", methods=["POST"])
def api_create_report(org_id):
    """Create a new scheduled report for an organization."""
    try:
        data = request.get_json(force=True) or {}
        rec = create_scheduled_report(
            org_id,
            data.get("report_type", "threat_intelligence"),
            data.get("frequency", "weekly"),
            data.get("recipients", []),
        )
        return jsonify(rec), 201
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/integrations", methods=["GET"])
def api_get_integrations(org_id):
    """List all API integrations for an organization."""
    try:
        if org_id not in org_registry:
            return jsonify({"error": f"Org {org_id} not found"}), 404
        result = [i for i in api_integrations.values() if i["org_id"] == org_id]
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/integrations", methods=["POST"])
def api_create_integration(org_id):
    """Register a new API integration."""
    try:
        data = request.get_json(force=True) or {}
        rec = register_api_integration(
            org_id,
            data.get("name", "New Integration"),
            data.get("type", "custom"),
            data.get("endpoint", ""),
        )
        return jsonify(rec), 201
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/webhooks", methods=["GET"])
def api_get_webhooks(org_id):
    """List all webhooks for an organization."""
    try:
        if org_id not in org_registry:
            return jsonify({"error": f"Org {org_id} not found"}), 404
        result = [w for w in webhook_subscriptions.values() if w["org_id"] == org_id]
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/webhooks", methods=["POST"])
def api_create_webhook(org_id):
    """Register a new webhook subscription."""
    try:
        data = request.get_json(force=True) or {}
        rec = add_webhook(org_id, data.get("url", ""), data.get("events", []))
        return jsonify(rec), 201
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/detections", methods=["GET"])
def api_get_detections(org_id):
    """List detection rule distributions for an organization."""
    try:
        if org_id not in org_registry:
            return jsonify({"error": f"Org {org_id} not found"}), 404
        result = [d for d in detection_distributions.values() if d["org_id"] == org_id]
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/detections", methods=["POST"])
def api_create_detection_dist(org_id):
    """Configure a detection rule distribution."""
    try:
        data = request.get_json(force=True) or {}
        rec = configure_detection_distribution(
            org_id,
            data.get("format", "sigma"),
            data.get("platform", "Generic SIEM"),
        )
        return jsonify(rec), 201
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/<org_id>/score", methods=["GET"])
def api_dep_score(org_id):
    """Return dependency score for an organization."""
    try:
        return jsonify(calculate_dependency_score(org_id))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/stickiness", methods=["GET"])
def api_stickiness():
    """Return all organizations ranked by dependency score."""
    try:
        return jsonify(get_platform_stickiness())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dependency/simulate-ops", methods=["POST"])
def api_simulate_ops():
    """Run a daily operations simulation."""
    try:
        return jsonify(simulate_daily_operations())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "dependency_platform_engine", "phase": 100})


if __name__ == "__main__":
    print("CYBERDUDEBIVASH SENTINEL APEX — Phase 100: Customer Dependency Platform Engine")
    print("Running on http://0.0.0.0:8515")
    app.run(host="0.0.0.0", port=8515, debug=False)
