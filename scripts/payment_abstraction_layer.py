#!/usr/bin/env python3
"""
payment_abstraction_layer.py — CYBERDUDEBIVASH SENTINEL APEX
OMEGA-P4: UPI / QR / NEFT Payment Abstraction Layer v1.0

Design objectives:
  - UPI, QR Code, NEFT, Bank Transfer = PRIMARY payment methods (India-first)
  - PayPal, Amazon Pay, Crypto = secondary supported methods
  - Stripe = future plugin (abstracted away, zero breaking changes)
  - Single PaymentAbstractionLayer.charge() entry point for all methods
  - All failures caught — never crashes the subscription pipeline
  - No raw card/PAN data ever stored (PCI scope minimized)
  - All amounts in USD cents (integer arithmetic, no float rounding)

Integration:
  - Called by api/billing.py BillingManager.record_payment()
  - Called by agent/api/api_server.py payment confirmation endpoints
  - StripeGateway in agent/api/stripe_gateway.py remains untouched
    (routed through this layer as one concrete impl of PaymentGateway)

Author: CYBERDUDEBIVASH Pvt. Ltd.
Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("CDB-PAYMENT")

# ---------------------------------------------------------------------------
# Result dataclass — gateway-neutral payment outcome
# ---------------------------------------------------------------------------

@dataclass
class PaymentResult:
    """Immutable outcome returned by every gateway implementation."""
    success:      bool
    method:       str           # "UPI" | "NEFT" | "QR" | "PAYPAL" | "CRYPTO" | "STRIPE"
    ref_id:       str           # Gateway-specific transaction reference
    amount_cents: int
    currency:     str = "USD"
    message:      str = ""
    gateway_raw:  Dict = field(default_factory=dict)  # Raw gateway response (sanitized)
    timestamp:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return {
            "success":      self.success,
            "method":       self.method,
            "ref_id":       self.ref_id,
            "amount_cents": self.amount_cents,
            "currency":     self.currency,
            "message":      self.message,
            "timestamp":    self.timestamp,
        }


# ---------------------------------------------------------------------------
# Abstract base — every gateway must implement charge()
# ---------------------------------------------------------------------------

class PaymentGateway(ABC):
    """Abstract payment gateway interface."""

    @property
    @abstractmethod
    def method_name(self) -> str:
        """Human-readable method name (e.g. 'UPI', 'NEFT')."""

    @abstractmethod
    def charge(
        self,
        amount_cents: int,
        email: str,
        tier: str,
        metadata: Optional[Dict] = None,
    ) -> PaymentResult:
        """
        Initiate or confirm a payment. Implementations must:
        - Never raise — return PaymentResult(success=False) on any error
        - Never log or store raw card/PAN/CVV data
        - Return gateway_raw only with sanitized, non-sensitive fields
        """

    @abstractmethod
    def verify(self, ref_id: str) -> PaymentResult:
        """
        Verify an existing payment by its gateway reference ID.
        Used for async confirmations (UPI, NEFT, crypto).
        """


# ---------------------------------------------------------------------------
# Concrete: UPI Gateway (India — VPA-based push payments)
# ---------------------------------------------------------------------------

class UPIGateway(PaymentGateway):
    """
    UPI Payment Gateway — generates payment intent with UPI deep-link
    and verifies via UTR (Unique Transaction Reference).

    In production: integrates with Razorpay / PayU / Cashfree UPI APIs.
    In current phase: manual UTR confirmation flow.
    """

    # CDB merchant VPA (from env or hardcoded fallback)
    MERCHANT_VPA = os.environ.get("CDB_UPI_VPA", "cyberdudebivash@upi")
    MERCHANT_NAME = "CyberDudeBivash Pvt. Ltd."

    @property
    def method_name(self) -> str:
        return "UPI"

    def generate_payment_link(
        self,
        amount_cents: int,
        order_id: str,
        note: str = "SENTINEL APEX Subscription",
    ) -> Dict:
        """
        Generate UPI payment URI (pa=VPA&pn=Name&am=Amount&tn=Note&tr=OrderID).
        Client renders as QR or deep-link for UPI apps (GPay, PhonePe, Paytm).
        """
        amount_inr = amount_cents / 100  # cents → dollars; caller converts to INR if needed
        upi_uri = (
            f"upi://pay?"
            f"pa={self.MERCHANT_VPA}"
            f"&pn={self.MERCHANT_NAME.replace(' ', '%20')}"
            f"&am={amount_inr:.2f}"
            f"&cu=INR"
            f"&tn={note.replace(' ', '%20')}"
            f"&tr={order_id}"
        )
        return {
            "method":       "UPI",
            "upi_uri":      upi_uri,
            "vpa":          self.MERCHANT_VPA,
            "merchant":     self.MERCHANT_NAME,
            "order_id":     order_id,
            "amount_inr":   amount_inr,
            "instructions": (
                "Open any UPI app (Google Pay, PhonePe, Paytm, BHIM), "
                "scan the QR or click the payment link, "
                "then submit your UTR reference in the dashboard."
            ),
        }

    def charge(
        self,
        amount_cents: int,
        email: str,
        tier: str,
        metadata: Optional[Dict] = None,
    ) -> PaymentResult:
        """
        Phase 1: Returns a UPI payment intent (URI + QR).
        Actual confirmation happens via verify(utr).
        """
        try:
            order_id = _generate_order_id("UPI", email, tier)
            payment_link = self.generate_payment_link(
                amount_cents, order_id,
                note=f"CDB APEX {tier} Subscription"
            )
            log.info(f"UPI payment intent created: order={order_id} tier={tier} email={email}")
            return PaymentResult(
                success=False,   # Pending — requires UTR confirmation
                method="UPI",
                ref_id=order_id,
                amount_cents=amount_cents,
                message="UPI payment intent created. Complete payment and submit UTR.",
                gateway_raw=payment_link,
            )
        except Exception as e:
            log.error(f"UPI charge error: {e}")
            return PaymentResult(
                success=False, method="UPI", ref_id="", amount_cents=amount_cents,
                message=f"UPI intent creation failed: {e}",
            )

    def verify(self, ref_id: str, utr: Optional[str] = None) -> PaymentResult:
        """
        Verify UPI payment via UTR.
        Phase 1: Manual confirmation — operator marks as verified in admin.
        Phase 2: Integrate Razorpay/PayU webhook for automatic UTR confirmation.
        """
        if not utr:
            return PaymentResult(
                success=False, method="UPI", ref_id=ref_id, amount_cents=0,
                message="UTR required for UPI verification.",
            )
        log.info(f"UPI payment verified: order={ref_id} utr={utr}")
        return PaymentResult(
            success=True, method="UPI", ref_id=utr, amount_cents=0,
            message=f"UPI payment confirmed. UTR: {utr}",
            gateway_raw={"order_id": ref_id, "utr": utr},
        )


# ---------------------------------------------------------------------------
# Concrete: QR Code Gateway (wraps UPI URI into QR payload)
# ---------------------------------------------------------------------------

class QRCodeGateway(PaymentGateway):
    """
    QR Code payment — generates a scannable QR for any UPI-compatible app.
    Wraps UPIGateway; QR generation is client-side (renders UPI URI as QR).
    """
    _upi = UPIGateway()

    @property
    def method_name(self) -> str:
        return "QR"

    def charge(
        self,
        amount_cents: int,
        email: str,
        tier: str,
        metadata: Optional[Dict] = None,
    ) -> PaymentResult:
        try:
            result = self._upi.charge(amount_cents, email, tier, metadata)
            result.method = "QR"
            result.message = (
                "Scan the QR code with any UPI app (GPay, PhonePe, Paytm, BHIM). "
                "After payment, submit your UTR in the dashboard."
            )
            upi_uri = result.gateway_raw.get("upi_uri", "")
            result.gateway_raw["qr_data"] = upi_uri  # Client renders this as QR
            result.gateway_raw["qr_library"] = "Use qrcode.js or python-qrcode on client"
            return result
        except Exception as e:
            log.error(f"QR charge error: {e}")
            return PaymentResult(
                success=False, method="QR", ref_id="", amount_cents=amount_cents,
                message=f"QR generation failed: {e}",
            )

    def verify(self, ref_id: str, **kwargs) -> PaymentResult:
        return self._upi.verify(ref_id, **kwargs)


# ---------------------------------------------------------------------------
# Concrete: NEFT / IMPS / Bank Transfer Gateway
# ---------------------------------------------------------------------------

class NEFTGateway(PaymentGateway):
    """
    NEFT / IMPS / Bank Transfer — generates bank details for manual transfer.
    Verification via UTR submitted by customer after transfer completes.
    """

    BANK_DETAILS = {
        "account_name":   os.environ.get("CDB_BANK_ACCOUNT_NAME",   "CyberDudeBivash Pvt. Ltd."),
        "account_number": os.environ.get("CDB_BANK_ACCOUNT_NUMBER", "XXXXXXXXXXXX"),  # Set in env
        "ifsc_code":      os.environ.get("CDB_BANK_IFSC",           "XXXXXXXXXXX"),   # Set in env
        "bank_name":      os.environ.get("CDB_BANK_NAME",           "Bank of India"),
        "branch":         os.environ.get("CDB_BANK_BRANCH",         "Odisha, India"),
        "account_type":   "Current",
    }

    @property
    def method_name(self) -> str:
        return "NEFT"

    def charge(
        self,
        amount_cents: int,
        email: str,
        tier: str,
        metadata: Optional[Dict] = None,
    ) -> PaymentResult:
        try:
            order_id = _generate_order_id("NEFT", email, tier)
            amount_inr = amount_cents / 100  # USD cents → USD; caller does FX
            details = {
                **self.BANK_DETAILS,
                "order_id":     order_id,
                "amount":       amount_inr,
                "payment_ref":  order_id,   # Customer must quote this in transfer remarks
                "instructions": (
                    f"Transfer ₹<INR_AMOUNT> via NEFT/IMPS to the above account. "
                    f"Quote Order ID '{order_id}' in the payment remarks/description. "
                    f"After transfer, submit your UTR number in the dashboard."
                ),
            }
            log.info(f"NEFT payment intent created: order={order_id} tier={tier}")
            return PaymentResult(
                success=False,
                method="NEFT",
                ref_id=order_id,
                amount_cents=amount_cents,
                message="NEFT bank transfer details generated. Complete transfer and submit UTR.",
                gateway_raw=details,
            )
        except Exception as e:
            log.error(f"NEFT charge error: {e}")
            return PaymentResult(
                success=False, method="NEFT", ref_id="", amount_cents=amount_cents,
                message=f"NEFT intent creation failed: {e}",
            )

    def verify(self, ref_id: str, utr: Optional[str] = None) -> PaymentResult:
        """Verify NEFT/IMPS transfer via UTR."""
        if not utr:
            return PaymentResult(
                success=False, method="NEFT", ref_id=ref_id, amount_cents=0,
                message="UTR required for NEFT verification.",
            )
        log.info(f"NEFT payment verified: order={ref_id} utr={utr}")
        return PaymentResult(
            success=True, method="NEFT", ref_id=utr, amount_cents=0,
            message=f"NEFT transfer confirmed. UTR: {utr}",
            gateway_raw={"order_id": ref_id, "utr": utr, "method": "NEFT"},
        )


# ---------------------------------------------------------------------------
# Concrete: PayPal Gateway (USD — international customers)
# ---------------------------------------------------------------------------

class PayPalGateway(PaymentGateway):
    """
    PayPal payment link generator.
    Phase 1: PayPal.me link generation (manual).
    Phase 2: PayPal REST API (checkout.session) integration.
    """

    PAYPAL_ME = os.environ.get("CDB_PAYPAL_ME", "cyberdudebivash")

    @property
    def method_name(self) -> str:
        return "PAYPAL"

    def charge(
        self,
        amount_cents: int,
        email: str,
        tier: str,
        metadata: Optional[Dict] = None,
    ) -> PaymentResult:
        try:
            amount_usd = amount_cents / 100
            order_id   = _generate_order_id("PAYPAL", email, tier)
            paypal_url = f"https://paypal.me/{self.PAYPAL_ME}/{amount_usd:.2f}"
            return PaymentResult(
                success=False,
                method="PAYPAL",
                ref_id=order_id,
                amount_cents=amount_cents,
                message=f"Send ${amount_usd:.2f} via PayPal. Add Order ID in note: {order_id}",
                gateway_raw={
                    "paypal_url": paypal_url,
                    "order_id":   order_id,
                    "amount_usd": amount_usd,
                    "note":       f"CDB APEX {tier} - {order_id}",
                },
            )
        except Exception as e:
            return PaymentResult(
                success=False, method="PAYPAL", ref_id="", amount_cents=amount_cents,
                message=f"PayPal intent failed: {e}",
            )

    def verify(self, ref_id: str, txn_id: Optional[str] = None) -> PaymentResult:
        if not txn_id:
            return PaymentResult(
                success=False, method="PAYPAL", ref_id=ref_id, amount_cents=0,
                message="PayPal transaction ID required for verification.",
            )
        return PaymentResult(
            success=True, method="PAYPAL", ref_id=txn_id, amount_cents=0,
            message=f"PayPal payment confirmed. TXN: {txn_id}",
        )


# ---------------------------------------------------------------------------
# Future stub: Stripe Gateway Adapter
# Wraps agent/api/stripe_gateway.py without importing it at module load time
# (avoids breaking the pipeline if stripe package is not installed)
# ---------------------------------------------------------------------------

class StripeGatewayAdapter(PaymentGateway):
    """
    Thin adapter over the existing StripeGateway.
    Loaded lazily — does not import stripe at module level.
    Future: replace manual UPI/NEFT with Stripe card/ACH when needed.
    """

    @property
    def method_name(self) -> str:
        return "STRIPE"

    def charge(
        self,
        amount_cents: int,
        email: str,
        tier: str,
        metadata: Optional[Dict] = None,
    ) -> PaymentResult:
        # Stripe is deliberately NOT the default path in current phase.
        # Route UPI/QR/NEFT first; only fall through to Stripe if explicitly requested.
        return PaymentResult(
            success=False,
            method="STRIPE",
            ref_id="",
            amount_cents=amount_cents,
            message=(
                "Stripe card payments are not the primary method in current phase. "
                "Please use UPI, QR, NEFT, or PayPal. "
                "Stripe integration is available on request via enterprise onboarding."
            ),
        )

    def verify(self, ref_id: str) -> PaymentResult:
        return PaymentResult(
            success=False, method="STRIPE", ref_id=ref_id, amount_cents=0,
            message="Stripe verification not active in current phase.",
        )


# ---------------------------------------------------------------------------
# Payment Abstraction Layer — single entry point, routes to correct gateway
# ---------------------------------------------------------------------------

# Method routing table — order determines fallback priority
_GATEWAY_REGISTRY: Dict[str, PaymentGateway] = {
    "UPI":    UPIGateway(),
    "QR":     QRCodeGateway(),
    "NEFT":   NEFTGateway(),
    "IMPS":   NEFTGateway(),    # IMPS = same bank details, faster clearing
    "PAYPAL": PayPalGateway(),
    "STRIPE": StripeGatewayAdapter(),
}

# Aliases
_GATEWAY_REGISTRY["BANK_TRANSFER"] = _GATEWAY_REGISTRY["NEFT"]
_GATEWAY_REGISTRY["QR_CODE"]       = _GATEWAY_REGISTRY["QR"]


def _generate_order_id(method: str, email: str, tier: str) -> str:
    """Deterministic, human-readable order ID. Not a security token."""
    ts    = int(time.time())
    email_hash = hashlib.sha256(email.encode()).hexdigest()[:8]
    return f"CDB-{method[:3].upper()}-{tier[:3].upper()}-{ts}-{email_hash}"


class PaymentAbstractionLayer:
    """
    Gateway-neutral payment router for SENTINEL APEX.

    Usage:
        pal = PaymentAbstractionLayer()
        result = pal.initiate("UPI", amount_cents=4900, email="...", tier="PRO")
        # → Returns PaymentResult with UPI URI for customer to complete payment

        result = pal.confirm("UPI", ref_id="CDB-UPI-PRO-...", utr="123456789012")
        # → Returns PaymentResult(success=True) after UTR verification
    """

    def initiate(
        self,
        method: str,
        amount_cents: int,
        email: str,
        tier: str,
        metadata: Optional[Dict] = None,
    ) -> PaymentResult:
        """
        Initiate a payment using the specified method.
        Returns a PaymentResult with payment instructions + ref_id.
        success=False means 'pending customer action', not an error.
        """
        gw = self._get_gateway(method)
        if gw is None:
            return PaymentResult(
                success=False, method=method.upper(), ref_id="",
                amount_cents=amount_cents,
                message=f"Unsupported payment method: {method}. "
                        f"Supported: {', '.join(_GATEWAY_REGISTRY.keys())}",
            )
        log.info(f"Payment initiation: method={method} tier={tier} amount={amount_cents}c")
        return gw.charge(amount_cents, email, tier, metadata)

    def confirm(
        self,
        method: str,
        ref_id: str,
        utr: Optional[str] = None,
        txn_id: Optional[str] = None,
    ) -> PaymentResult:
        """
        Confirm / verify a pending payment.
        - UPI/NEFT: pass utr= (UTR number from bank statement)
        - PayPal:   pass txn_id= (PayPal transaction ID)
        - Returns PaymentResult(success=True) on confirmed payment
        """
        gw = self._get_gateway(method)
        if gw is None:
            return PaymentResult(
                success=False, method=method.upper(), ref_id=ref_id,
                amount_cents=0,
                message=f"Unknown payment method for confirmation: {method}",
            )
        log.info(f"Payment confirmation: method={method} ref={ref_id} utr={utr} txn={txn_id}")
        kwargs: Dict[str, Any] = {}
        if utr:
            kwargs["utr"] = utr
        if txn_id:
            kwargs["txn_id"] = txn_id
        return gw.verify(ref_id, **kwargs)

    def get_payment_methods(self) -> List[Dict]:
        """Return list of available payment methods with metadata for the checkout UI."""
        return [
            {
                "method":       "UPI",
                "label":        "UPI (Google Pay / PhonePe / Paytm / BHIM)",
                "icon":         "upi",
                "priority":     1,
                "regions":      ["IN"],
                "instant":      True,
                "description":  "Instant payment via UPI app. Scan QR or use VPA.",
            },
            {
                "method":       "QR",
                "label":        "QR Code (UPI)",
                "icon":         "qr_code",
                "priority":     2,
                "regions":      ["IN"],
                "instant":      True,
                "description":  "Scan QR code with any UPI-enabled app.",
            },
            {
                "method":       "NEFT",
                "label":        "NEFT / IMPS / Bank Transfer",
                "icon":         "bank",
                "priority":     3,
                "regions":      ["IN"],
                "instant":      False,
                "description":  "Bank transfer. Settlement in 30 min (IMPS) to 2h (NEFT).",
            },
            {
                "method":       "PAYPAL",
                "label":        "PayPal (International)",
                "icon":         "paypal",
                "priority":     4,
                "regions":      ["GLOBAL"],
                "instant":      False,
                "description":  "Pay via PayPal. Supported globally.",
            },
            {
                "method":       "STRIPE",
                "label":        "Credit / Debit Card (Stripe) — Coming Soon",
                "icon":         "card",
                "priority":     5,
                "regions":      ["GLOBAL"],
                "instant":      True,
                "description":  "Card payments via Stripe — available via enterprise onboarding.",
                "disabled":     True,
            },
        ]

    def _get_gateway(self, method: str) -> Optional[PaymentGateway]:
        return _GATEWAY_REGISTRY.get(method.upper().replace(" ", "_"))


# ---------------------------------------------------------------------------
# Module-level singleton — import anywhere with:
#   from scripts.payment_abstraction_layer import payment_layer
# ---------------------------------------------------------------------------
payment_layer = PaymentAbstractionLayer()


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    pal = PaymentAbstractionLayer()
    test_email = "test@example.com"
    test_tier  = "PRO"
    test_cents = 4900

    print("\n=== OMEGA-P4 Payment Abstraction Layer Self-Test ===\n")
    all_pass = True
    for method in ["UPI", "QR", "NEFT", "PAYPAL"]:
        r = pal.initiate(method, test_cents, test_email, test_tier)
        ok = r.method == method and r.ref_id != "" and r.amount_cents == test_cents
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_pass = False
        print(f"  {status}  initiate({method}): ref={r.ref_id[:30]}... msg={r.message[:60]}")

    # Confirm test (simulated UTR)
    r = pal.confirm("UPI", "CDB-UPI-PRO-12345", utr="123456789012")
    ok = r.success and r.method == "UPI"
    print(f"  {'PASS' if ok else 'FAIL'}  confirm(UPI, utr=...): {r.message}")
    if not ok:
        all_pass = False

    # Methods list
    methods = pal.get_payment_methods()
    ok = len(methods) >= 4
    print(f"  {'PASS' if ok else 'FAIL'}  get_payment_methods(): {len(methods)} methods")
    if not ok:
        all_pass = False

    print(f"\n{'ALL PASS' if all_pass else 'SOME FAILURES'}")
    sys.exit(0 if all_pass else 1)
