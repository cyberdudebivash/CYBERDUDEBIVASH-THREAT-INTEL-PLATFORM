"""
CYBERDUDEBIVASH® SENTINEL APEX — Phase 152
Intelligence Action Center
Port: 8552

Full workflow pipeline:
  Threat → Detection → Ticket → Response → Verification

Integrations (production-ready mock connectors):
  - Jira (ticket creation, status tracking)
  - ServiceNow (incident management)
  - Slack (alert notifications)
  - Microsoft Teams (SOC channel alerts)

Author: CYBERDUDEBIVASH
Version: v170.0 — Customer Value Realization Release
"""

import uuid
import json
import hashlib
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from flask import Flask, jsonify, request

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Workflow State Machine
# ─────────────────────────────────────────────────────────────────────────────
# States:  THREAT_INGESTED → DETECTION_GENERATED → TICKET_CREATED →
#          RESPONSE_INITIATED → RESPONSE_IN_PROGRESS → VERIFIED → CLOSED

WORKFLOW_STATES = [
    "THREAT_INGESTED",
    "DETECTION_GENERATED",
    "TICKET_CREATED",
    "RESPONSE_INITIATED",
    "RESPONSE_IN_PROGRESS",
    "VERIFIED",
    "CLOSED",
]

# ─────────────────────────────────────────────────────────────────────────────
# Detection Templates (per ATT&CK technique)
# ─────────────────────────────────────────────────────────────────────────────
DETECTION_TEMPLATES: Dict[str, dict] = {
    "T1190": {
        "name":       "Exploit Public-Facing Application",
        "sigma_rule": "title: Exploit Public-Facing App\ndetection:\n  selection:\n    http.status: [500, 403]\n    http.uri|contains: ['../','%2e%2e','cmd=','exec=']\n  condition: selection",
        "spl_query":  "index=web sourcetype=access_combined (status=500 OR status=403) uri IN (\"*../*\", \"*cmd=*\", \"*exec=*\") | stats count by src_ip, uri | where count > 5",
        "kql_query":  "SecurityAlert | where AlertName has 'Web Application Attack' | where TimeGenerated > ago(1h)",
        "severity":   "critical",
        "response":   ["isolate_asset", "block_source_ip", "notify_soc", "escalate_p1"],
    },
    "T1078": {
        "name":       "Valid Accounts Abuse",
        "sigma_rule": "title: Valid Account Abuse\ndetection:\n  selection:\n    event_id: [4624, 4625]\n    logon_type: [3, 10]\n    ip_address|not: '10.*'\n  condition: selection | count > 10",
        "spl_query":  "index=wineventlog EventCode IN (4624, 4625) Logon_Type IN (3, 10) NOT src_ip=10.* | stats count by src_ip, user | where count > 10",
        "kql_query":  "SigninLogs | where ResultType != 0 | where IPAddress !startswith '10.' | summarize count() by UserPrincipalName, IPAddress | where count_ > 10",
        "severity":   "high",
        "response":   ["disable_account", "reset_password", "notify_user", "notify_soc"],
    },
    "T1566": {
        "name":       "Phishing",
        "sigma_rule": "title: Phishing Email Detected\ndetection:\n  selection:\n    email.attachment_type: ['.exe','.js','.vbs','.docm','.xlsm']\n    email.links|contains: ['bit.ly','tinyurl']\n  condition: selection",
        "spl_query":  "index=email sourcetype=mail (attachment IN (\".exe\",\".js\",\".vbs\") OR url IN (\"*bit.ly*\",\"*tinyurl*\")) | stats count by sender, recipient",
        "kql_query":  "EmailAttachmentInfo | where FileType in ('exe','js','vbs') | join EmailEvents on NetworkMessageId | project SenderFromAddress, RecipientEmailAddress, FileName",
        "severity":   "high",
        "response":   ["quarantine_email", "block_sender", "user_awareness_alert", "scan_endpoint"],
    },
    "T1003": {
        "name":       "OS Credential Dumping",
        "sigma_rule": "title: Credential Dumping\ndetection:\n  selection:\n    process_name: ['mimikatz.exe','procdump.exe','lsass.exe']\n    event_id: 10\n  condition: selection",
        "spl_query":  "index=wineventlog EventCode=10 (process_name=lsass.exe OR TargetImage=lsass.exe) | stats count by host, user",
        "kql_query":  "DeviceProcessEvents | where FileName in ('mimikatz.exe','procdump.exe') or InitiatingProcessFileName == 'lsass.exe' | project DeviceName, AccountName, FileName",
        "severity":   "critical",
        "response":   ["isolate_endpoint", "kill_process", "collect_forensics", "escalate_p0"],
    },
    "T1486": {
        "name":       "Ransomware — Data Encrypted for Impact",
        "sigma_rule": "title: Ransomware Activity\ndetection:\n  selection:\n    file_extension|endswith: ['.locked','.encrypted','.ransom','.crypto']\n    file_count: '>100'\n  timeframe: 1m\n  condition: selection",
        "spl_query":  "index=endpoint sourcetype=file_events file_name IN (\"*.locked\",\"*.encrypted\",\"*.ransom\") | bucket _time span=1m | stats count by host | where count > 100",
        "kql_query":  "DeviceFileEvents | where FileName endswith '.locked' or FileName endswith '.encrypted' | summarize count() by DeviceName, bin(Timestamp, 1m) | where count_ > 100",
        "severity":   "critical",
        "response":   ["isolate_all_endpoints", "kill_network", "activate_ir_team", "executive_notification", "escalate_p0"],
    },
    "DEFAULT": {
        "name":       "Generic Threat Indicator",
        "sigma_rule": "title: Generic Threat\ndetection:\n  selection:\n    event_type: threat_indicator\n  condition: selection",
        "spl_query":  "index=* sourcetype=threat_intel | stats count by src_ip, technique_id",
        "kql_query":  "SecurityAlert | where TimeGenerated > ago(1h) | project AlertName, Severity, Entities",
        "severity":   "medium",
        "response":   ["notify_soc", "log_event", "monitor_24h"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# In-memory stores
# ─────────────────────────────────────────────────────────────────────────────
ACTION_WORKFLOWS:    Dict[str, dict] = {}   # workflow_id → workflow
INTEGRATION_LOGS:    List[dict]      = []   # audit trail


# ─────────────────────────────────────────────────────────────────────────────
# Integration Connectors (mock — production config via ENV)
# ─────────────────────────────────────────────────────────────────────────────

class JiraConnector:
    """Mock Jira connector — replace with atlassian-python-api in production."""
    BASE_URL = "https://your-org.atlassian.net"

    @staticmethod
    def create_ticket(project: str, summary: str, description: str, priority: str,
                      labels: List[str] = None) -> dict:
        ticket_id = f"SOC-{random.randint(1000, 9999)}"
        return {
            "connector":  "jira",
            "ticket_id":  ticket_id,
            "url":        f"{JiraConnector.BASE_URL}/browse/{ticket_id}",
            "project":    project,
            "summary":    summary,
            "priority":   priority,
            "labels":     labels or ["sentinel-apex", "auto-created"],
            "status":     "Open",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def update_ticket(ticket_id: str, status: str, comment: str = "") -> dict:
        return {
            "connector":  "jira",
            "ticket_id":  ticket_id,
            "action":     "update",
            "new_status": status,
            "comment":    comment,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }


class ServiceNowConnector:
    """Mock ServiceNow connector — replace with pysnow in production."""
    BASE_URL = "https://your-instance.service-now.com"

    @staticmethod
    def create_incident(short_description: str, description: str, urgency: int = 2,
                         impact: int = 2, category: str = "Security") -> dict:
        sys_id = str(uuid.uuid4())[:8]
        number = f"INC{random.randint(1000000, 9999999)}"
        return {
            "connector":         "servicenow",
            "sys_id":            sys_id,
            "number":            number,
            "url":               f"{ServiceNowConnector.BASE_URL}/incident.do?sys_id={sys_id}",
            "short_description": short_description,
            "urgency":           urgency,
            "impact":            impact,
            "category":          category,
            "state":             "New",
            "created_at":        datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def resolve_incident(sys_id: str, resolution_notes: str) -> dict:
        return {
            "connector":          "servicenow",
            "sys_id":             sys_id,
            "action":             "resolve",
            "resolution_notes":   resolution_notes,
            "state":              "Resolved",
            "resolved_at":        datetime.now(timezone.utc).isoformat(),
        }


class SlackConnector:
    """Mock Slack connector — replace with slack-sdk in production."""

    @staticmethod
    def send_alert(channel: str, message: str, severity: str = "medium",
                   blocks: List[dict] = None) -> dict:
        SEVERITY_EMOJI = {"critical": "🚨", "high": "⚠️", "medium": "🔔", "low": "ℹ️"}
        return {
            "connector":  "slack",
            "channel":    channel,
            "message":    f"{SEVERITY_EMOJI.get(severity, '🔔')} {message}",
            "severity":   severity,
            "blocks":     blocks,
            "sent_at":    datetime.now(timezone.utc).isoformat(),
            "status":     "delivered",
        }


class TeamsConnector:
    """Mock Microsoft Teams connector — replace with pymsteams in production."""

    @staticmethod
    def send_card(webhook_url: str, title: str, text: str, color: str = "FF0000",
                  facts: List[dict] = None) -> dict:
        return {
            "connector":  "teams",
            "title":      title,
            "text":       text,
            "color":      color,
            "facts":      facts or [],
            "sent_at":    datetime.now(timezone.utc).isoformat(),
            "status":     "delivered",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Workflow Engine
# ─────────────────────────────────────────────────────────────────────────────

def _log_integration(workflow_id: str, connector: str, action: str, result: dict):
    INTEGRATION_LOGS.append({
        "workflow_id": workflow_id,
        "connector":   connector,
        "action":      action,
        "result":      result,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    })


def create_action_workflow(threat: dict, org_id: str = "ORG-DEMO-001",
                            integrations: List[str] = None) -> dict:
    """
    Entry point — takes a threat indicator and drives the full pipeline.

    threat keys:
        technique_id: str
        threat_actor: str (optional)
        ioc:          str (optional, IP/domain/hash)
        source:       str
        confidence:   int (0-100)
        description:  str
    """
    if integrations is None:
        integrations = ["jira", "slack"]

    workflow_id  = "wf-" + str(uuid.uuid4())[:8]
    technique_id = threat.get("technique_id", "DEFAULT")
    template     = DETECTION_TEMPLATES.get(technique_id, DETECTION_TEMPLATES["DEFAULT"])
    severity     = template["severity"]
    now          = datetime.now(timezone.utc)

    # ── STEP 1: Threat Ingested ────────────────────────────────────────────
    workflow = {
        "workflow_id":    workflow_id,
        "org_id":         org_id,
        "threat":         threat,
        "technique_id":   technique_id,
        "technique_name": template["name"],
        "severity":       severity,
        "state":          "THREAT_INGESTED",
        "created_at":     now.isoformat(),
        "updated_at":     now.isoformat(),
        "steps":          [],
        "integrations":   {},
        "sla": {
            "p0_target_minutes": 15,
            "p1_target_minutes": 60,
            "p2_target_minutes": 240,
            "triggered_at":      now.isoformat(),
        },
    }

    workflow["steps"].append({
        "step": "THREAT_INGESTED",
        "timestamp": now.isoformat(),
        "details": f"Threat {technique_id} ingested from {threat.get('source','unknown')} "
                   f"— confidence {threat.get('confidence', 50)}%",
    })

    # ── STEP 2: Detection Generated ───────────────────────────────────────
    detection = {
        "detection_id":  "det-" + str(uuid.uuid4())[:8],
        "sigma_rule":    template["sigma_rule"],
        "spl_query":     template["spl_query"],
        "kql_query":     template["kql_query"],
        "generated_at":  now.isoformat(),
        "technique_id":  technique_id,
        "severity":      severity,
    }
    workflow["detection"] = detection
    workflow["state"]     = "DETECTION_GENERATED"
    workflow["steps"].append({
        "step":      "DETECTION_GENERATED",
        "timestamp": now.isoformat(),
        "details":   f"Sigma rule, SPL, and KQL detections generated for {technique_id}",
    })

    # ── STEP 3: Ticket Created ─────────────────────────────────────────────
    ticket_summary = f"[APEX] {severity.upper()} — {template['name']} ({technique_id})"
    ticket_desc    = (
        f"Threat Actor: {threat.get('threat_actor','Unknown')}\n"
        f"IOC: {threat.get('ioc','N/A')}\n"
        f"Source: {threat.get('source','Sentinel APEX')}\n"
        f"Confidence: {threat.get('confidence',50)}%\n\n"
        f"Description: {threat.get('description', template['name'])}\n\n"
        f"Detection rules deployed:\n"
        f"  Sigma: {detection['detection_id']}\n"
        f"  Workflow: {workflow_id}\n"
    )

    if "jira" in integrations:
        priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
        jira_ticket = JiraConnector.create_ticket(
            project="SOC",
            summary=ticket_summary,
            description=ticket_desc,
            priority=priority_map.get(severity, "Medium"),
            labels=["sentinel-apex", technique_id, f"sev-{severity}"]
        )
        workflow["integrations"]["jira"] = jira_ticket
        _log_integration(workflow_id, "jira", "create_ticket", jira_ticket)

    if "servicenow" in integrations:
        urgency_map = {"critical": 1, "high": 1, "medium": 2, "low": 3}
        snow_ticket = ServiceNowConnector.create_incident(
            short_description=ticket_summary,
            description=ticket_desc,
            urgency=urgency_map.get(severity, 2),
            impact=urgency_map.get(severity, 2),
        )
        workflow["integrations"]["servicenow"] = snow_ticket
        _log_integration(workflow_id, "servicenow", "create_incident", snow_ticket)

    workflow["state"] = "TICKET_CREATED"
    workflow["steps"].append({
        "step":      "TICKET_CREATED",
        "timestamp": now.isoformat(),
        "details":   f"Tickets created in: {', '.join(integrations)}",
    })

    # ── STEP 4: Response Initiated ─────────────────────────────────────────
    response_actions = template.get("response", ["notify_soc"])
    workflow["response_plan"] = {
        "actions":      response_actions,
        "initiated_at": now.isoformat(),
        "assigned_to":  "SOC-L2",
        "playbook":     f"https://intel.cyberdudebivash.com/playbooks/{technique_id}",
    }
    workflow["state"] = "RESPONSE_INITIATED"
    workflow["steps"].append({
        "step":      "RESPONSE_INITIATED",
        "timestamp": now.isoformat(),
        "details":   f"Response plan initiated: {', '.join(response_actions)}",
    })

    # ── STEP 5: Slack/Teams Notification ──────────────────────────────────
    alert_msg = (
        f"*[SENTINEL APEX]* {severity.upper()} Alert — {template['name']}\n"
        f">Technique: `{technique_id}`\n"
        f">IOC: `{threat.get('ioc','N/A')}`\n"
        f">Confidence: {threat.get('confidence',50)}%\n"
        f">Workflow: `{workflow_id}`"
    )

    if "slack" in integrations:
        slack_result = SlackConnector.send_alert(
            channel="#soc-alerts",
            message=alert_msg,
            severity=severity,
        )
        workflow["integrations"]["slack"] = slack_result
        _log_integration(workflow_id, "slack", "send_alert", slack_result)

    if "teams" in integrations:
        color_map = {"critical": "FF0000", "high": "FF8800", "medium": "FFCC00", "low": "00AA00"}
        teams_result = TeamsConnector.send_card(
            webhook_url="https://outlook.office.com/webhook/...",
            title=f"SENTINEL APEX — {severity.upper()} Alert",
            text=f"{template['name']} ({technique_id})",
            color=color_map.get(severity, "0076D7"),
            facts=[
                {"name": "Technique",   "value": technique_id},
                {"name": "Severity",    "value": severity.capitalize()},
                {"name": "IOC",         "value": threat.get("ioc", "N/A")},
                {"name": "Workflow ID", "value": workflow_id},
            ]
        )
        workflow["integrations"]["teams"] = teams_result
        _log_integration(workflow_id, "teams", "send_card", teams_result)

    workflow["state"] = "RESPONSE_IN_PROGRESS"
    workflow["steps"].append({
        "step":      "RESPONSE_IN_PROGRESS",
        "timestamp": now.isoformat(),
        "details":   "Notifications sent. SOC engaged. Response in progress.",
    })

    workflow["updated_at"] = datetime.now(timezone.utc).isoformat()
    ACTION_WORKFLOWS[workflow_id] = workflow
    return workflow


def verify_workflow(workflow_id: str, verified_by: str = "SOC-L2",
                     resolution: str = "Threat contained and mitigated") -> dict:
    """Mark a workflow as verified and closed."""
    wf = ACTION_WORKFLOWS.get(workflow_id)
    if not wf:
        return {"error": f"Workflow {workflow_id} not found"}

    now = datetime.now(timezone.utc)
    triggered = datetime.fromisoformat(wf["sla"]["triggered_at"])
    minutes_to_resolve = round((now - triggered).total_seconds() / 60, 1)

    wf["verification"] = {
        "verified_by":        verified_by,
        "resolution":         resolution,
        "verified_at":        now.isoformat(),
        "minutes_to_resolve": minutes_to_resolve,
    }
    wf["state"] = "VERIFIED"
    wf["steps"].append({
        "step":      "VERIFIED",
        "timestamp": now.isoformat(),
        "details":   f"Verified by {verified_by}: {resolution}",
    })

    # Update Jira ticket if present
    if "jira" in wf["integrations"]:
        jira_update = JiraConnector.update_ticket(
            wf["integrations"]["jira"]["ticket_id"],
            status="Done",
            comment=f"Resolved by Sentinel APEX in {minutes_to_resolve}m. {resolution}"
        )
        wf["integrations"]["jira_close"] = jira_update

    # Update ServiceNow if present
    if "servicenow" in wf["integrations"]:
        snow_resolve = ServiceNowConnector.resolve_incident(
            wf["integrations"]["servicenow"]["sys_id"],
            resolution_notes=resolution
        )
        wf["integrations"]["servicenow_close"] = snow_resolve

    wf["state"]      = "CLOSED"
    wf["updated_at"] = now.isoformat()
    wf["steps"].append({
        "step":      "CLOSED",
        "timestamp": now.isoformat(),
        "details":   f"Workflow closed. Total time: {minutes_to_resolve} minutes.",
    })
    ACTION_WORKFLOWS[workflow_id] = wf
    return wf


# ─────────────────────────────────────────────────────────────────────────────
# REST API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/action-center/workflow", methods=["POST"])
def create_workflow():
    payload      = request.get_json(force=True) or {}
    threat       = payload.get("threat", {"technique_id": "T1190", "source": "Sentinel APEX", "confidence": 85})
    org_id       = payload.get("org_id", "ORG-DEMO-001")
    integrations = payload.get("integrations", ["jira", "slack"])
    wf = create_action_workflow(threat, org_id, integrations)
    return jsonify({"status": "ok", "data": wf})


@app.route("/action-center/workflow/<workflow_id>", methods=["GET"])
def get_workflow(workflow_id: str):
    wf = ACTION_WORKFLOWS.get(workflow_id)
    if not wf:
        return jsonify({"status": "error", "message": "Not found"}), 404
    return jsonify({"status": "ok", "data": wf})


@app.route("/action-center/workflow/<workflow_id>/verify", methods=["POST"])
def verify(workflow_id: str):
    payload    = request.get_json(force=True) or {}
    result     = verify_workflow(workflow_id, payload.get("verified_by", "SOC-L2"), payload.get("resolution", "Mitigated"))
    return jsonify({"status": "ok", "data": result})


@app.route("/action-center/workflows", methods=["GET"])
def list_workflows():
    org_id  = request.args.get("org_id")
    state   = request.args.get("state")
    results = list(ACTION_WORKFLOWS.values())
    if org_id:
        results = [w for w in results if w["org_id"] == org_id]
    if state:
        results = [w for w in results if w["state"] == state]
    return jsonify({"status": "ok", "count": len(results), "data": results})


@app.route("/action-center/stats", methods=["GET"])
def stats():
    wfs      = list(ACTION_WORKFLOWS.values())
    by_state = {}
    for wf in wfs:
        by_state[wf["state"]] = by_state.get(wf["state"], 0) + 1
    resolved = [w for w in wfs if w["state"] == "CLOSED" and "verification" in w]
    avg_ttd  = round(sum(w["verification"]["minutes_to_resolve"] for w in resolved) / len(resolved), 1) if resolved else 0
    return jsonify({
        "status":             "ok",
        "total_workflows":    len(wfs),
        "by_state":           by_state,
        "closed_workflows":   len(resolved),
        "avg_ttd_minutes":    avg_ttd,
    })


@app.route("/action-center/integration-log", methods=["GET"])
def integration_log():
    limit = int(request.args.get("limit", 50))
    return jsonify({"status": "ok", "count": len(INTEGRATION_LOGS), "data": INTEGRATION_LOGS[-limit:]})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "engine": "phase152-action-center", "version": "v170.0"})


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

def run_self_test() -> dict:
    results = {}

    # Test 1: Full workflow pipeline
    threat = {
        "technique_id": "T1003",
        "threat_actor": "APT-LAZARUS",
        "ioc":          "192.168.100.55",
        "source":       "Sentinel APEX Feed",
        "confidence":   92,
        "description":  "Credential dumping attempt detected via LSASS access",
    }
    wf = create_action_workflow(threat, "TEST-ORG-001", ["jira", "slack", "teams"])
    results["workflow_creation"] = "PASS" if wf["state"] == "RESPONSE_IN_PROGRESS" else "FAIL"
    results["detection_generated"] = "PASS" if "detection" in wf else "FAIL"
    results["jira_ticket"] = "PASS" if "jira" in wf["integrations"] else "FAIL"
    results["slack_alert"] = "PASS" if "slack" in wf["integrations"] else "FAIL"
    results["teams_alert"] = "PASS" if "teams" in wf["integrations"] else "FAIL"

    # Test 2: Verification
    verified = verify_workflow(wf["workflow_id"], "SOC-LEAD", "Threat isolated and remediated")
    results["verification"] = "PASS" if verified.get("state") == "CLOSED" else "FAIL"

    # Test 3: Ransomware workflow
    ransomware_threat = {"technique_id": "T1486", "source": "APEX-EDR", "confidence": 98, "ioc": "10.0.1.45"}
    wf2 = create_action_workflow(ransomware_threat, "TEST-ORG-002", ["servicenow", "teams"])
    results["ransomware_workflow"] = "PASS" if "escalate_p0" in wf2.get("response_plan", {}).get("actions", []) else "FAIL"

    passed = sum(1 for v in results.values() if v == "PASS")
    results["summary"] = f"{passed}/{len(results)-1} tests passed"
    results["status"]  = "PASS" if passed == len(results) - 1 else "PARTIAL"
    return results


if __name__ == "__main__":
    print("=== Phase 152 — Intelligence Action Center Self-Test ===")
    test_results = run_self_test()
    for k, v in test_results.items():
        print(f"  {k}: {v}")
    print(f"\nStarting server on port 8552...")
    app.run(host="0.0.0.0", port=8552, debug=False)
