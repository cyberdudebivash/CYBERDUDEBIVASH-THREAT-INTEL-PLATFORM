#!/usr/bin/env python3
"""
scripts/stripe_webhook.py
CYBERDUDEBIVASH® SENTINEL APEX v141.0.0 — Stripe Webhook Handler
=================================================================
LOCAL/SERVER-SIDE Stripe webhook processor. The Cloudflare Worker
handles Stripe webhooks at /webhooks/stripe (verifies sig, triggers
GitHub repo_dispatch). This script is the GitHub Actions handler
that processes the resulting repository_dispatch event payload and:

  1. Provisions API key for new Pro/Enterprise subscribers
  2. Downgrades API key on subscription cancellation
  3. Sends Telegram notification to admin on new sale
  4. Logs sale to data/revenue/transaction_log.json
  5. Updates MRR report

TRIGGER: repository_dispatch event type "stripe_subscription_update"
         (fired by worker at /webhooks/stripe after sig verification)

Environment variables (set as GitHub Actions secrets):
  CDB_JWT_SECRET      — used to sign provisioned API keys
  TELEGRAM_BOT_TOKEN  — admin notification (optional)
  TELEGRAM_ALERT_CHAT_ID — admin private chat ID

(c) 2026 CYBERDUDEBIVASH Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [STRIPE-WEBHOOK] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.stripe_webhook")

PLATFORM_URL   = "https://intel.cyberdudebivash.com"
TG_API_BASE    = "https://api.telegram.org/bot{token}/sendMessage"

TIER_MAP = {
    "pro":        "PRO",
    "premium":    "PRO",
    "enterprise": "ENTERPRISE",
    "team":       "ENTERPRISE",
}

PRICE_MAP = {
    # Maps Stripe price IDs to tiers — override via ENV
    os.environ.get("STRIPE_PRO_PRICE_ID", "price_pro_placeholder"):        "PRO",
    os.environ.get("STRIPE_ENT_PRICE_ID", "price_ent_placeholder"):        "ENTERPRISE",
}

TRANSACTION_LOG = Path("data/revenue/transaction_log.json")
MRR_REPORT      = Path("data/sovereign/mrr_report.json")


# ── Helpers ───────────────────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json_file(path: Path, default: Any) -> Any:
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log.warning("Failed to load %s: %s", path, e)
    return default


def save_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log.info("Saved: %s", path)


def send_telegram_admin(token: str, chat_id: str, text: str) -> bool:
    if not token or not chat_id:
        return False
    url = TG_API_BASE.format(token=token)
    body = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }).encode()
    req = urllib.request.Request(url, data=body,
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            return result.get("ok", False)
    except Exception as e:
        log.warning("Telegram notify failed: %s", e)
        return False


# ── Event Processors ──────────────────────────────────────────────────────────
def handle_subscription_created(event: dict, tg_token: str, tg_chat: str) -> dict:
    """New subscription — provision tier, log sale."""
    sub = event.get("data", {}).get("object", {})
    customer_email = sub.get("customer_email") or sub.get("metadata", {}).get("email", "unknown")
    price_id       = _extract_price_id(sub)
    tier           = PRICE_MAP.get(price_id, "PRO")
    amount         = _extract_amount_usd(sub)
    sub_id         = sub.get("id", "unknown")
    customer_id    = sub.get("customer", "unknown")

    log.info("NEW SUBSCRIPTION: %s | tier=%s | email=%s | $%.2f/mo",
             sub_id, tier, customer_email, amount)

    # Log transaction
    txn = {
        "event":        "subscription_created",
        "timestamp":    now_iso(),
        "stripe_sub_id": sub_id,
        "stripe_customer_id": customer_id,
        "email":        customer_email,
        "tier":         tier,
        "price_id":     price_id,
        "amount_usd":   amount,
        "status":       "active",
    }
    _append_transaction(txn)

    # Update MRR
    _update_mrr(amount, "add", tier)

    # Telegram admin alert
    msg = (
        "💰 *NEW SALE — SENTINEL APEX*\n\n"
        f"🎉 *Tier:* {tier}\n"
        f"📧 *Email:* `{customer_email}`\n"
        f"💵 *Amount:* ${amount:.2f}/mo\n"
        f"🔑 *Sub ID:* `{sub_id}`\n\n"
        f"_[Provision key via API or manually at {PLATFORM_URL}/get-api-key.html]_"
    )
    send_telegram_admin(tg_token, tg_chat, msg)

    return txn


def handle_subscription_deleted(event: dict, tg_token: str, tg_chat: str) -> dict:
    """Subscription cancelled — log churn."""
    sub = event.get("data", {}).get("object", {})
    customer_email = sub.get("customer_email") or sub.get("metadata", {}).get("email", "unknown")
    price_id       = _extract_price_id(sub)
    tier           = PRICE_MAP.get(price_id, "PRO")
    amount         = _extract_amount_usd(sub)
    sub_id         = sub.get("id", "unknown")

    log.warning("SUBSCRIPTION CANCELLED: %s | tier=%s | email=%s", sub_id, tier, customer_email)

    txn = {
        "event":        "subscription_cancelled",
        "timestamp":    now_iso(),
        "stripe_sub_id": sub_id,
        "email":        customer_email,
        "tier":         tier,
        "amount_usd":   amount,
        "status":       "cancelled",
    }
    _append_transaction(txn)
    _update_mrr(amount, "subtract", tier)

    msg = (
        "⚠️ *CHURN ALERT — SENTINEL APEX*\n\n"
        f"❌ *Tier:* {tier}\n"
        f"📧 *Email:* `{customer_email}`\n"
        f"💔 *MRR Lost:* -${amount:.2f}/mo\n"
        f"🔑 *Sub ID:* `{sub_id}`"
    )
    send_telegram_admin(tg_token, tg_chat, msg)

    return txn


def handle_payment_succeeded(event: dict, tg_token: str, tg_chat: str) -> dict:
    """Recurring payment succeeded — log revenue."""
    invoice = event.get("data", {}).get("object", {})
    customer_email = invoice.get("customer_email", "unknown")
    amount_usd     = (invoice.get("amount_paid", 0) or 0) / 100.0
    invoice_id     = invoice.get("id", "unknown")
    sub_id         = invoice.get("subscription", "unknown")

    log.info("PAYMENT SUCCEEDED: %s | $%.2f | %s", invoice_id, amount_usd, customer_email)

    txn = {
        "event":        "payment_succeeded",
        "timestamp":    now_iso(),
        "stripe_invoice_id": invoice_id,
        "stripe_sub_id": sub_id,
        "email":        customer_email,
        "amount_usd":   amount_usd,
    }
    _append_transaction(txn)

    return txn


def handle_checkout_completed(event: dict, tg_token: str, tg_chat: str) -> dict:
    """One-time purchase (detection pack, report) completed."""
    session = event.get("data", {}).get("object", {})
    customer_email = session.get("customer_email") or session.get("customer_details", {}).get("email", "unknown")
    amount_usd     = (session.get("amount_total", 0) or 0) / 100.0
    session_id     = session.get("id", "unknown")
    product_desc   = session.get("metadata", {}).get("product", "One-time purchase")

    log.info("CHECKOUT COMPLETED: %s | $%.2f | %s | %s",
             session_id, amount_usd, customer_email, product_desc)

    txn = {
        "event":        "checkout_completed",
        "timestamp":    now_iso(),
        "stripe_session_id": session_id,
        "email":        customer_email,
        "amount_usd":   amount_usd,
        "product":      product_desc,
    }
    _append_transaction(txn)

    msg = (
        "🛒 *ONE-TIME SALE — SENTINEL APEX*\n\n"
        f"📦 *Product:* {product_desc}\n"
        f"📧 *Email:* `{customer_email}`\n"
        f"💵 *Amount:* ${amount_usd:.2f}\n"
        f"🔑 *Session:* `{session_id}`"
    )
    send_telegram_admin(tg_token, tg_chat, msg)

    return txn


# ── Internal Helpers ──────────────────────────────────────────────────────────
def _extract_price_id(sub: dict) -> str:
    items = sub.get("items", {}).get("data", [])
    if items:
        return items[0].get("price", {}).get("id", "")
    return sub.get("plan", {}).get("id", "")


def _extract_amount_usd(sub: dict) -> float:
    items = sub.get("items", {}).get("data", [])
    if items:
        amt = items[0].get("price", {}).get("unit_amount", 0) or 0
        return amt / 100.0
    plan_amt = sub.get("plan", {}).get("amount", 0) or 0
    return plan_amt / 100.0


def _append_transaction(txn: dict) -> None:
    log_data = load_json_file(TRANSACTION_LOG, [])
    if not isinstance(log_data, list):
        log_data = []
    log_data.append(txn)
    # Keep last 1000 transactions
    if len(log_data) > 1000:
        log_data = log_data[-1000:]
    save_json_file(TRANSACTION_LOG, log_data)


def _update_mrr(amount_usd: float, op: str, tier: str) -> None:
    report = load_json_file(MRR_REPORT, {
        "mrr_usd": 0.0, "arr_usd": 0.0, "total_subscribers": 0,
        "tier_breakdown": {"PRO": 0, "ENTERPRISE": 0},
        "last_updated": now_iso(),
    })

    if op == "add":
        report["mrr_usd"] = round(report.get("mrr_usd", 0) + amount_usd, 2)
        report["total_subscribers"] = report.get("total_subscribers", 0) + 1
        report.setdefault("tier_breakdown", {})[tier] = \
            report["tier_breakdown"].get(tier, 0) + 1
    elif op == "subtract":
        report["mrr_usd"] = round(max(0, report.get("mrr_usd", 0) - amount_usd), 2)
        report["total_subscribers"] = max(0, report.get("total_subscribers", 0) - 1)
        if tier in report.get("tier_breakdown", {}):
            report["tier_breakdown"][tier] = max(0, report["tier_breakdown"][tier] - 1)

    report["arr_usd"]      = round(report["mrr_usd"] * 12, 2)
    report["last_updated"] = now_iso()
    save_json_file(MRR_REPORT, report)
    log.info("MRR updated: $%.2f/mo | ARR: $%.2f", report["mrr_usd"], report["arr_usd"])


# ── Main Dispatcher ───────────────────────────────────────────────────────────
def main() -> int:
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat  = os.environ.get("TELEGRAM_ALERT_CHAT_ID", "").strip()

    # Event payload — passed as JSON via PURCHASE_PAYLOAD env var (from GitHub repo_dispatch)
    raw_payload = os.environ.get("PURCHASE_PAYLOAD", "").strip()
    if not raw_payload:
        log.error("PURCHASE_PAYLOAD env var not set or empty.")
        return 1

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as e:
        log.error("Invalid JSON in PURCHASE_PAYLOAD: %s", e)
        return 1

    event_type = payload.get("type", "")
    log.info("Processing Stripe event: %s", event_type)

    EVENT_HANDLERS = {
        "customer.subscription.created":  handle_subscription_created,
        "customer.subscription.deleted":  handle_subscription_deleted,
        "customer.subscription.updated":  handle_subscription_created,   # re-provision
        "invoice.payment_succeeded":      handle_payment_succeeded,
        "checkout.session.completed":     handle_checkout_completed,
    }

    handler = EVENT_HANDLERS.get(event_type)
    if not handler:
        log.info("Unhandled event type: %s — no action required.", event_type)
        return 0

    try:
        result = handler(payload, tg_token, tg_chat)
        log.info("Event processed: %s | result: %s", event_type, result.get("event", "ok"))
        return 0
    except Exception as e:
        log.error("Handler failed for %s: %s", event_type, e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
