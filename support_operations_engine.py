"""
CYBERDUDEBIVASH SENTINEL APEX
Support Operations Engine - FILE 6/10
Ticket management, SLA tracking, escalation, metrics.
Port: 8506
"""

import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# SLA definitions (response + resolution targets in hours)
# ---------------------------------------------------------------------------
SLA_MATRIX = {
    "standard": {
        "P1": {"response_hours": 4,  "resolution_hours": 24},
        "P2": {"response_hours": 8,  "resolution_hours": 48},
        "P3": {"response_hours": 24, "resolution_hours": 96},
        "P4": {"response_hours": 72, "resolution_hours": 240},
    },
    "premium": {
        "P1": {"response_hours": 2,  "resolution_hours": 8},
        "P2": {"response_hours": 4,  "resolution_hours": 24},
        "P3": {"response_hours": 12, "resolution_hours": 72},
        "P4": {"response_hours": 48, "resolution_hours": 168},
    },
    "enterprise": {
        "P1": {"response_hours": 1,  "resolution_hours": 4},
        "P2": {"response_hours": 2,  "resolution_hours": 12},
        "P3": {"response_hours": 8,  "resolution_hours": 48},
        "P4": {"response_hours": 24, "resolution_hours": 120},
    },
    "mssp": {
        "P1": {"response_hours": 0.5,"resolution_hours": 2},
        "P2": {"response_hours": 1,  "resolution_hours": 8},
        "P3": {"response_hours": 4,  "resolution_hours": 24},
        "P4": {"response_hours": 12, "resolution_hours": 72},
    },
}

PRIORITY_LABELS = {
    "P1": "Critical",
    "P2": "High",
    "P3": "Medium",
    "P4": "Low",
}

TICKET_STATUSES = ["open", "in_progress", "pending_customer", "escalated", "resolved", "closed"]
TICKETS: Dict[str, dict] = {}
SUPPORT_AGENTS = ["Alex Turner", "Priya Sharma", "James O'Brien", "Liu Wei", "Fatima Hassan"]


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def create_ticket(org_id: str, subject: str, description: str, priority: str = "P3",
                   sla_tier: str = "standard", reporter: str = "customer") -> dict:
    """Create a new support ticket with SLA deadlines."""
    if priority not in PRIORITY_LABELS:
        raise ValueError(f"Invalid priority: {priority}. Valid: {list(PRIORITY_LABELS.keys())}")
    if sla_tier not in SLA_MATRIX:
        raise ValueError(f"Invalid SLA tier: {sla_tier}. Valid: {list(SLA_MATRIX.keys())}")
    ticket_id = "tkt-" + str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc)
    sla = SLA_MATRIX[sla_tier][priority]
    ticket = {
        "ticket_id": ticket_id,
        "org_id": org_id,
        "subject": subject,
        "description": description,
        "priority": priority,
        "priority_label": PRIORITY_LABELS[priority],
        "status": "open",
        "sla_tier": sla_tier,
        "sla_response_deadline": (now + timedelta(hours=sla["response_hours"])).isoformat(),
        "sla_resolution_deadline": (now + timedelta(hours=sla["resolution_hours"])).isoformat(),
        "sla_response_met": None,
        "sla_resolution_met": None,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "resolved_at": None,
        "closed_at": None,
        "assignee": None,
        "reporter": reporter,
        "escalation_level": 0,
        "comments": [],
        "tags": [],
    }
    TICKETS[ticket_id] = ticket
    # Auto-assign for P1/P2
    if priority in ("P1", "P2"):
        ticket["assignee"] = random.choice(SUPPORT_AGENTS)
        ticket["status"] = "in_progress"
    return ticket


def update_ticket(ticket_id: str, updates: dict, actor: str = "agent") -> dict:
    """Update ticket fields."""
    ticket = TICKETS.get(ticket_id)
    if not ticket:
        raise ValueError(f"Ticket {ticket_id} not found")
    allowed = {"status", "assignee", "priority", "tags", "description"}
    for k, v in updates.items():
        if k in allowed:
            if k == "status" and v not in TICKET_STATUSES:
                raise ValueError(f"Invalid status: {v}")
            ticket[k] = v
    if updates.get("comment"):
        ticket["comments"].append({
            "comment_id": str(uuid.uuid4())[:8],
            "author": actor,
            "text": updates["comment"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    ticket["updated_at"] = datetime.now(timezone.utc).isoformat()
    return ticket


def escalate_ticket(ticket_id: str, reason: str = "sla_breach", actor: str = "system") -> dict:
    """Escalate a ticket to the next level."""
    ticket = TICKETS.get(ticket_id)
    if not ticket:
        raise ValueError(f"Ticket {ticket_id} not found")
    if ticket["status"] == "resolved":
        raise ValueError("Cannot escalate a resolved ticket")
    ticket["escalation_level"] += 1
    ticket["status"] = "escalated"
    ticket["escalated_at"] = datetime.now(timezone.utc).isoformat()
    ticket["escalation_reason"] = reason
    ticket["escalated_by"] = actor
    # Reassign to senior agent on escalation
    ticket["assignee"] = SUPPORT_AGENTS[0]
    ticket["comments"].append({
        "comment_id": str(uuid.uuid4())[:8],
        "author": "system",
        "text": f"Escalated to level {ticket['escalation_level']}: {reason}",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    ticket["updated_at"] = datetime.now(timezone.utc).isoformat()
    return ticket


def resolve_ticket(ticket_id: str, resolution: str, actor: str = "agent") -> dict:
    """Mark a ticket as resolved with a resolution note."""
    ticket = TICKETS.get(ticket_id)
    if not ticket:
        raise ValueError(f"Ticket {ticket_id} not found")
    if ticket["status"] in ("resolved", "closed"):
        raise ValueError("Ticket is already resolved/closed")
    now = datetime.now(timezone.utc)
    ticket["status"] = "resolved"
    ticket["resolved_at"] = now.isoformat()
    ticket["resolved_by"] = actor
    ticket["resolution"] = resolution
    ticket["updated_at"] = now.isoformat()
    # Check SLA
    res_deadline = datetime.fromisoformat(ticket["sla_resolution_deadline"].replace("Z", "+00:00"))
    ticket["sla_resolution_met"] = now <= res_deadline
    created = datetime.fromisoformat(ticket["created_at"].replace("Z", "+00:00"))
    resp_deadline = datetime.fromisoformat(ticket["sla_response_deadline"].replace("Z", "+00:00"))
    ticket["sla_response_met"] = True  # Approximation: if it was in_progress, assume responded
    ticket["time_to_resolve_hours"] = round((now - created).total_seconds() / 3600, 2)
    return ticket


def check_sla_breach(ticket_id: str) -> dict:
    """Check whether a ticket has breached its SLA deadlines."""
    ticket = TICKETS.get(ticket_id)
    if not ticket:
        raise ValueError(f"Ticket {ticket_id} not found")
    now = datetime.now(timezone.utc)
    response_dl = datetime.fromisoformat(ticket["sla_response_deadline"].replace("Z", "+00:00"))
    resolution_dl = datetime.fromisoformat(ticket["sla_resolution_deadline"].replace("Z", "+00:00"))
    response_breach = now > response_dl and ticket["status"] == "open"
    resolution_breach = now > resolution_dl and ticket["status"] not in ("resolved", "closed")
    response_hrs_remaining = round((response_dl - now).total_seconds() / 3600, 2)
    resolution_hrs_remaining = round((resolution_dl - now).total_seconds() / 3600, 2)
    return {
        "ticket_id": ticket_id,
        "priority": ticket["priority"],
        "sla_tier": ticket["sla_tier"],
        "response_breach": response_breach,
        "resolution_breach": resolution_breach,
        "response_hrs_remaining": response_hrs_remaining,
        "resolution_hrs_remaining": resolution_hrs_remaining,
        "status": ticket["status"],
        "checked_at": now.isoformat(),
    }


def get_support_metrics(org_id: str = None) -> dict:
    """Calculate support metrics across all tickets or for a specific org."""
    tickets = list(TICKETS.values())
    if org_id:
        tickets = [t for t in tickets if t["org_id"] == org_id]
    if not tickets:
        return {"total_tickets": 0}
    resolved = [t for t in tickets if t["status"] in ("resolved", "closed")]
    open_t = [t for t in tickets if t["status"] not in ("resolved", "closed")]
    escalated = [t for t in tickets if t.get("escalation_level", 0) > 0]
    avg_ttresolve = 0
    if resolved:
        ttrs = [t.get("time_to_resolve_hours", 0) for t in resolved if t.get("time_to_resolve_hours")]
        avg_ttresolve = round(sum(ttrs) / len(ttrs), 2) if ttrs else 0
    sla_met = [t for t in resolved if t.get("sla_resolution_met")]
    sla_pct = round(len(sla_met) / max(len(resolved), 1) * 100, 1)
    by_priority = {}
    for p in ("P1", "P2", "P3", "P4"):
        pt = [t for t in tickets if t["priority"] == p]
        by_priority[p] = {"total": len(pt), "open": sum(1 for t in pt if t["status"] not in ("resolved","closed"))}
    return {
        "org_id": org_id or "all",
        "total_tickets": len(tickets),
        "open_tickets": len(open_t),
        "resolved_tickets": len(resolved),
        "escalated_tickets": len(escalated),
        "avg_time_to_resolve_hours": avg_ttresolve,
        "sla_compliance_pct": sla_pct,
        "tickets_by_priority": by_priority,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _seed():
    samples = [
        ("org-acme01", "Cannot access threat feed API", "API returns 403 on all intelligence endpoints", "P2", "enterprise"),
        ("org-tech02", "False positive detections in SIEM", "Sigma rule generating 500+ false positives per hour", "P3", "premium"),
        ("org-gsoc03", "MSSP dashboard not loading customer list", "Blank page after login for last 2 hours", "P1", "mssp"),
        ("org-cyberco05", "Need help configuring MISP integration", "Export connector not mapping TTP fields", "P3", "standard"),
        ("org-netsec07", "Export feature missing in report builder", "Cannot export quarterly board report to PDF", "P4", "enterprise"),
        ("org-redfort06", "Login failure after MFA enrollment", "User locked out post TOTP setup", "P2", "standard"),
        ("org-gsoc03", "API rate limit too low for MSSP workload", "Need quota increase for managed customer feeds", "P2", "mssp"),
    ]
    for org_id, subject, desc, priority, sla in samples:
        tkt = create_ticket(org_id, subject, desc, priority, sla)
        # Resolve some tickets
        if priority in ("P3", "P4") and random.random() > 0.5:
            resolve_ticket(tkt["ticket_id"], "Issue resolved by support team", actor="Alex Turner")
    # Escalate a P1
    p1_tickets = [t for t in TICKETS.values() if t["priority"] == "P1" and t["status"] != "resolved"]
    if p1_tickets:
        escalate_ticket(p1_tickets[0]["ticket_id"], reason="customer_requested_escalation", actor="system")


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/tickets", methods=["GET"])
def api_list_tickets():
    """List tickets with optional filters."""
    try:
        org_id = request.args.get("org_id")
        priority = request.args.get("priority")
        status = request.args.get("status")
        tickets = list(TICKETS.values())
        if org_id:
            tickets = [t for t in tickets if t["org_id"] == org_id]
        if priority:
            tickets = [t for t in tickets if t["priority"] == priority]
        if status:
            tickets = [t for t in tickets if t["status"] == status]
        return jsonify({"tickets": tickets, "total": len(tickets)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tickets", methods=["POST"])
def api_create_ticket():
    """Create a new support ticket."""
    try:
        data = request.get_json(force=True)
        required = ["org_id", "subject", "description"]
        for f in required:
            if not data.get(f):
                return jsonify({"error": f"{f} is required"}), 400
        ticket = create_ticket(data["org_id"], data["subject"], data["description"],
                                data.get("priority", "P3"), data.get("sla_tier", "standard"),
                                data.get("reporter", "api"))
        return jsonify(ticket), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tickets/<ticket_id>", methods=["GET"])
def api_get_ticket(ticket_id):
    """Get a specific ticket."""
    ticket = TICKETS.get(ticket_id)
    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404
    return jsonify(ticket), 200


@app.route("/api/tickets/<ticket_id>", methods=["PATCH"])
def api_update_ticket(ticket_id):
    """Update a ticket."""
    try:
        data = request.get_json(force=True)
        ticket = update_ticket(ticket_id, data, actor=data.get("actor", "api"))
        return jsonify(ticket), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tickets/<ticket_id>/escalate", methods=["POST"])
def api_escalate_ticket(ticket_id):
    """Escalate a ticket."""
    try:
        data = request.get_json(force=True) or {}
        ticket = escalate_ticket(ticket_id, data.get("reason", "manual_escalation"),
                                  actor=data.get("actor", "api"))
        return jsonify(ticket), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tickets/<ticket_id>/resolve", methods=["POST"])
def api_resolve_ticket(ticket_id):
    """Resolve a ticket."""
    try:
        data = request.get_json(force=True)
        if not data.get("resolution"):
            return jsonify({"error": "resolution is required"}), 400
        ticket = resolve_ticket(ticket_id, data["resolution"], actor=data.get("actor", "agent"))
        return jsonify(ticket), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tickets/<ticket_id>/sla", methods=["GET"])
def api_check_sla(ticket_id):
    """Check SLA breach status for a ticket."""
    try:
        sla = check_sla_breach(ticket_id)
        return jsonify(sla), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/support-metrics", methods=["GET"])
def api_support_metrics():
    """Get support metrics."""
    try:
        org_id = request.args.get("org_id")
        metrics = get_support_metrics(org_id)
        return jsonify(metrics), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "support_operations_engine", "version": "1.0.0",
                    "total_tickets": len(TICKETS)}), 200


if __name__ == "__main__":
    print("Starting Support Operations Engine on port 8506")
    print(f"Seeded {len(TICKETS)} tickets")
    app.run(host="0.0.0.0", port=8506, debug=False)
