"""
CYBERDUDEBIVASH SENTINEL APEX
Billing Engine - FILE 4/10
Invoice generation, usage metering, payment recording, overdue detection.
Port: 8504
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
INVOICES: Dict[str, dict] = {}
PAYMENTS: Dict[str, dict] = {}
USAGE_METERS: Dict[str, dict] = {}   # keyed by org_id

PLAN_PRICES = {
    "free":         {"base": 0,    "per_seat": 0,   "per_1k_api_calls": 0,   "per_intel_request": 0},
    "professional": {"base": 299,  "per_seat": 29,  "per_1k_api_calls": 1.5, "per_intel_request": 0.05},
    "enterprise":   {"base": 999,  "per_seat": 9,   "per_1k_api_calls": 0.8, "per_intel_request": 0.02},
    "mssp":         {"base": 2499, "per_seat": 5,   "per_1k_api_calls": 0.5, "per_intel_request": 0.01},
    "oem":          {"base": 9999, "per_seat": 2,   "per_1k_api_calls": 0.2, "per_intel_request": 0.005},
}


# ---------------------------------------------------------------------------
# Usage metering
# ---------------------------------------------------------------------------

def init_usage_meter(org_id: str, plan: str = "professional") -> dict:
    """Initialize or reset the usage meter for an organization."""
    now = datetime.now(timezone.utc)
    meter = {
        "org_id": org_id,
        "plan": plan,
        "period_start": now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat(),
        "period_end": (now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                       + timedelta(days=32)).replace(day=1).isoformat(),
        "api_calls": 0,
        "intelligence_requests": 0,
        "active_seats": 1,
        "storage_gb": 0.0,
        "updated_at": now.isoformat(),
    }
    USAGE_METERS[org_id] = meter
    return meter


def record_meter_usage(org_id: str, api_calls: int = 0, intel_requests: int = 0,
                        seats: int = None, storage_gb: float = 0.0) -> dict:
    """Record incremental usage for billing purposes."""
    meter = USAGE_METERS.get(org_id)
    if not meter:
        meter = init_usage_meter(org_id)
    meter["api_calls"] += api_calls
    meter["intelligence_requests"] += intel_requests
    if seats is not None:
        meter["active_seats"] = seats
    meter["storage_gb"] += storage_gb
    meter["updated_at"] = datetime.now(timezone.utc).isoformat()
    return meter


def calculate_usage_charges(org_id: str) -> dict:
    """Calculate itemized usage-based charges for an organization."""
    meter = USAGE_METERS.get(org_id)
    if not meter:
        return {"org_id": org_id, "total": 0, "items": []}
    plan = meter["plan"]
    prices = PLAN_PRICES.get(plan, PLAN_PRICES["professional"])
    items = []
    base_charge = prices["base"]
    items.append({"description": f"{plan.title()} Plan Base Fee", "quantity": 1,
                  "unit_price": base_charge, "amount": base_charge})
    extra_seats = max(0, meter["active_seats"] - 1)
    seat_charge = extra_seats * prices["per_seat"]
    if seat_charge > 0:
        items.append({"description": f"Additional Seats ({extra_seats})", "quantity": extra_seats,
                      "unit_price": prices["per_seat"], "amount": seat_charge})
    api_blocks = meter["api_calls"] / 1000
    api_charge = round(api_blocks * prices["per_1k_api_calls"], 2)
    if api_charge > 0:
        items.append({"description": f"API Calls ({meter['api_calls']:,})", "quantity": meter["api_calls"],
                      "unit_price": prices["per_1k_api_calls"] / 1000, "amount": api_charge})
    intel_charge = round(meter["intelligence_requests"] * prices["per_intel_request"], 2)
    if intel_charge > 0:
        items.append({"description": f"Intelligence Requests ({meter['intelligence_requests']:,})",
                      "quantity": meter["intelligence_requests"],
                      "unit_price": prices["per_intel_request"], "amount": intel_charge})
    total = round(base_charge + seat_charge + api_charge + intel_charge, 2)
    return {
        "org_id": org_id,
        "plan": plan,
        "period_start": meter["period_start"],
        "period_end": meter["period_end"],
        "items": items,
        "subtotal": total,
        "tax_rate": 0.0,
        "tax_amount": 0.0,
        "total": total,
    }


# ---------------------------------------------------------------------------
# Invoice functions
# ---------------------------------------------------------------------------

def generate_invoice(org_id: str, org_name: str, plan: str = "professional",
                      due_days: int = 30) -> dict:
    """Generate an invoice from current usage meters."""
    charges = calculate_usage_charges(org_id)
    invoice_id = "inv-" + str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc)
    invoice = {
        "invoice_id": invoice_id,
        "org_id": org_id,
        "org_name": org_name,
        "status": "open",
        "amount": charges["total"],
        "subtotal": charges["subtotal"],
        "tax_amount": charges["tax_amount"],
        "currency": "USD",
        "items": charges["items"],
        "period_start": charges["period_start"],
        "period_end": charges["period_end"],
        "due_date": (now + timedelta(days=due_days)).isoformat(),
        "created_at": now.isoformat(),
        "paid_at": None,
        "payment_id": None,
        "overdue": False,
    }
    INVOICES[invoice_id] = invoice
    return invoice


def record_payment(invoice_id: str, amount: float, method: str = "credit_card",
                    reference: str = None) -> dict:
    """Record a payment against an invoice."""
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        raise ValueError(f"Invoice {invoice_id} not found")
    if invoice["status"] == "paid":
        raise ValueError("Invoice is already paid")
    if amount < invoice["amount"]:
        raise ValueError(f"Partial payment: received {amount}, required {invoice['amount']}")
    payment_id = "pay-" + str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc)
    payment = {
        "payment_id": payment_id,
        "invoice_id": invoice_id,
        "org_id": invoice["org_id"],
        "amount": amount,
        "method": method,
        "reference": reference or f"TXN-{uuid.uuid4().hex[:12].upper()}",
        "status": "succeeded",
        "processed_at": now.isoformat(),
    }
    PAYMENTS[payment_id] = payment
    invoice["status"] = "paid"
    invoice["paid_at"] = now.isoformat()
    invoice["payment_id"] = payment_id
    return payment


def get_billing_summary(org_id: str) -> dict:
    """Get a full billing summary for an organization."""
    org_invoices = [i for i in INVOICES.values() if i["org_id"] == org_id]
    now = datetime.now(timezone.utc)
    # Mark overdue
    for inv in org_invoices:
        if inv["status"] == "open":
            due = datetime.fromisoformat(inv["due_date"].replace("Z", "+00:00"))
            if now > due:
                inv["overdue"] = True
    paid = [i for i in org_invoices if i["status"] == "paid"]
    open_inv = [i for i in org_invoices if i["status"] == "open"]
    overdue = [i for i in org_invoices if i.get("overdue")]
    total_paid = sum(i["amount"] for i in paid)
    total_outstanding = sum(i["amount"] for i in open_inv)
    meter = USAGE_METERS.get(org_id, {})
    return {
        "org_id": org_id,
        "total_invoices": len(org_invoices),
        "paid_invoices": len(paid),
        "open_invoices": len(open_inv),
        "overdue_invoices": len(overdue),
        "total_paid_usd": round(total_paid, 2),
        "total_outstanding_usd": round(total_outstanding, 2),
        "current_month_usage": {
            "api_calls": meter.get("api_calls", 0),
            "intelligence_requests": meter.get("intelligence_requests", 0),
            "active_seats": meter.get("active_seats", 0),
        },
        "current_charges": calculate_usage_charges(org_id) if meter else {},
        "as_of": now.isoformat(),
    }


def list_invoices(org_id: str = None, status: str = None) -> List[dict]:
    """List invoices with optional filters."""
    invs = list(INVOICES.values())
    if org_id:
        invs = [i for i in invs if i["org_id"] == org_id]
    if status:
        invs = [i for i in invs if i["status"] == status]
    return sorted(invs, key=lambda i: i["created_at"], reverse=True)


def detect_overdue_invoices() -> List[dict]:
    """Scan all open invoices and flag overdue ones."""
    now = datetime.now(timezone.utc)
    overdue = []
    for inv in INVOICES.values():
        if inv["status"] == "open":
            due = datetime.fromisoformat(inv["due_date"].replace("Z", "+00:00"))
            if now > due:
                inv["overdue"] = True
                days_overdue = (now - due).days
                overdue.append({**inv, "days_overdue": days_overdue})
    return overdue


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _seed():
    orgs = [
        ("org-acme01", "Acme Security Inc", "enterprise", 55000, 4200),
        ("org-tech02", "TechDefense LLC", "professional", 8500, 900),
        ("org-gsoc03", "GlobalSOC Partners", "mssp", 310000, 42000),
    ]
    for org_id, name, plan, api_calls, intel_req in orgs:
        init_usage_meter(org_id, plan)
        record_meter_usage(org_id, api_calls=api_calls, intel_requests=intel_req, seats=5)
        inv = generate_invoice(org_id, name, plan, due_days=30)
    # Mark first invoice as paid
    first_inv = list(INVOICES.values())[0]
    record_payment(first_inv["invoice_id"], first_inv["amount"])
    # Create an overdue invoice for demo
    overdue_inv_id = "inv-overdue01"
    overdue_dt = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
    INVOICES[overdue_inv_id] = {
        "invoice_id": overdue_inv_id,
        "org_id": "org-tech02",
        "org_name": "TechDefense LLC",
        "status": "open",
        "amount": 299.00,
        "subtotal": 299.00,
        "tax_amount": 0,
        "currency": "USD",
        "items": [{"description": "Professional Plan Base Fee", "quantity": 1,
                   "unit_price": 299, "amount": 299}],
        "period_start": (datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),
        "period_end": (datetime.now(timezone.utc) - timedelta(days=15)).isoformat(),
        "due_date": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
        "created_at": overdue_dt,
        "paid_at": None,
        "payment_id": None,
        "overdue": True,
    }


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/billing", methods=["GET"])
def api_billing_summary():
    """Get billing summary for an org."""
    try:
        org_id = request.args.get("org_id")
        if not org_id:
            # Return all orgs summary
            summaries = {}
            for oid in set(i["org_id"] for i in INVOICES.values()):
                summaries[oid] = get_billing_summary(oid)
            return jsonify({"summaries": summaries}), 200
        summary = get_billing_summary(org_id)
        return jsonify(summary), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/invoices", methods=["GET"])
def api_list_invoices():
    """List invoices."""
    try:
        org_id = request.args.get("org_id")
        status = request.args.get("status")
        invs = list_invoices(org_id, status)
        return jsonify({"invoices": invs, "total": len(invs)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/invoices/generate", methods=["POST"])
def api_generate_invoice():
    """Generate an invoice for an org."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_id") or not data.get("org_name"):
            return jsonify({"error": "org_id and org_name are required"}), 400
        inv = generate_invoice(data["org_id"], data["org_name"],
                                data.get("plan", "professional"), data.get("due_days", 30))
        return jsonify(inv), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/billing/pay", methods=["POST"])
def api_record_payment():
    """Record a payment for an invoice."""
    try:
        data = request.get_json(force=True)
        if not data.get("invoice_id"):
            return jsonify({"error": "invoice_id is required"}), 400
        invoice = INVOICES.get(data["invoice_id"])
        if not invoice:
            return jsonify({"error": "Invoice not found"}), 404
        amount = data.get("amount", invoice["amount"])
        payment = record_payment(data["invoice_id"], amount, data.get("method", "credit_card"),
                                  data.get("reference"))
        return jsonify(payment), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/billing/overdue", methods=["GET"])
def api_overdue_invoices():
    """List all overdue invoices."""
    try:
        overdue = detect_overdue_invoices()
        return jsonify({"overdue_invoices": overdue, "total": len(overdue)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/billing/usage/<org_id>", methods=["GET"])
def api_usage_charges(org_id):
    """Get calculated usage charges for an org."""
    try:
        charges = calculate_usage_charges(org_id)
        return jsonify(charges), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/billing/usage/<org_id>", methods=["POST"])
def api_record_usage(org_id):
    """Record incremental usage."""
    try:
        data = request.get_json(force=True) or {}
        meter = record_meter_usage(org_id, data.get("api_calls", 0),
                                    data.get("intel_requests", 0),
                                    data.get("seats"), data.get("storage_gb", 0.0))
        return jsonify(meter), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "billing_engine", "version": "1.0.0",
                    "invoices": len(INVOICES), "payments": len(PAYMENTS)}), 200


if __name__ == "__main__":
    print("Starting Billing Engine on port 8504")
    print(f"Seeded {len(INVOICES)} invoices, {len(PAYMENTS)} payments")
    app.run(host="0.0.0.0", port=8504, debug=False)
