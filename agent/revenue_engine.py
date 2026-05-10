#!/usr/bin/env python3
"""
revenue_engine.py - CYBERDUDEBIVASH(R) SENTINEL APEX v45.0
CENTRAL REVENUE ORCHESTRATION ENGINE
Founder & CEO - CyberDudeBivash Pvt. Ltd.

v45.0 ENTERPRISE-GRADE FIXES:
  - Idempotency: caller-supplied idempotency_key prevents double-billing on
    network retries, race conditions, or duplicate API calls. Key is stored
    in a persistent idempotency registry; re-submissions return original tx.
  - Thread-safe file writes: threading.Lock guards all reads and writes to
    transaction_log.json to prevent corruption under concurrent API load.
  - Atomic write: write to temp file then os.replace() — guarantees the log
    is never left in a partially-written state on crash.
  - Revenue telemetry: per-feature revenue counters and monthly totals written
    to data/revenue/revenue_telemetry.json for commercial observability.
"""

import hashlib
import json
import logging
import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("CDB-REVENUE")

_LOCK = threading.Lock()


class CDBRevenueEngine:
    def __init__(self):
        self.log_file      = "data/revenue/transaction_log.json"
        self.idem_file     = "data/revenue/idempotency_registry.json"
        self.telemetry_file = "data/revenue/revenue_telemetry.json"
        self.authority     = "CYBERDUDEBIVASH OFFICIAL AUTHORITY"
        self._ensure_paths()

    def _ensure_paths(self):
        os.makedirs("data/revenue", exist_ok=True)
        for path, default in [
            (self.log_file,      {"total_revenue_usd": 0.0, "transactions": []}),
            (self.idem_file,     {"keys": {}}),
            (self.telemetry_file, {"by_feature": {}, "by_month": {}, "by_tenant": {}}),
        ]:
            if not os.path.exists(path):
                self._atomic_write(path, default)

    # ── Idempotency ─────────────────────────────────────────────────────────

    def _idem_key(self, tenant_id: str, feature: str, units: int,
                  idempotency_key: Optional[str]) -> str:
        """Derive a stable idempotency key. Uses caller-supplied key if provided,
        otherwise derives from (tenant + feature + units + UTC date) so that
        the same metered call within the same UTC day is idempotent."""
        if idempotency_key:
            return idempotency_key
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        raw = f"{tenant_id}:{feature}:{units}:{day}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _check_idempotency(self, key: str) -> Optional[Dict]:
        """Return existing transaction if key already processed, else None."""
        try:
            with open(self.idem_file, "r", encoding="utf-8") as f:
                registry = json.load(f)
            return registry.get("keys", {}).get(key)
        except Exception:
            return None

    def _register_idempotency(self, key: str, transaction: Dict):
        try:
            with open(self.idem_file, "r", encoding="utf-8") as f:
                registry = json.load(f)
            registry.setdefault("keys", {})[key] = {
                "transaction_id": transaction["transaction_id"],
                "registered_at":  transaction["timestamp"],
                "tenant_id":      transaction["tenant_id"],
                "feature":        transaction["feature"],
                "amount":         transaction["amount"],
            }
            # Prune idempotency registry to 10 000 keys (FIFO)
            keys = registry["keys"]
            if len(keys) > 10_000:
                oldest = sorted(keys.items(), key=lambda x: x[1].get("registered_at", ""))
                for k, _ in oldest[:len(keys) - 10_000]:
                    del keys[k]
            self._atomic_write(self.idem_file, registry)
        except Exception as e:
            logger.warning(f"[REVENUE] Idempotency registry write failed (non-fatal): {e}")

    # ── Core billing ─────────────────────────────────────────────────────────

    def process_usage(
        self,
        tenant_id: str,
        units: int,
        unit_price: float,
        feature: str,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Calculates and logs metered usage. Idempotent — safe to retry.

        Args:
            tenant_id:        Customer/tenant identifier.
            units:            Billable unit count (API calls, records, etc.).
            unit_price:       USD price per unit.
            feature:          Feature name for revenue attribution.
            idempotency_key:  Caller-supplied dedup key. If None, auto-derived
                              from (tenant + feature + units + UTC date).

        Returns:
            Transaction dict. Repeated calls with same key return original tx.
        """
        ikey = self._idem_key(tenant_id, feature, units, idempotency_key)

        with _LOCK:
            # Idempotency guard — return existing transaction without re-billing
            existing = self._check_idempotency(ikey)
            if existing:
                logger.info(
                    f"[REVENUE] Idempotent replay: tenant={tenant_id} "
                    f"feature={feature} ikey={ikey[:12]}... — returning original tx"
                )
                return dict(existing, idempotent_replay=True)

            billed_amount = round(units * unit_price, 6)
            transaction = {
                "transaction_id":  str(uuid.uuid4()),
                "timestamp":       datetime.now(timezone.utc).isoformat(),
                "tenant_id":       tenant_id,
                "feature":         feature,
                "units":           units,
                "unit_price":      unit_price,
                "amount":          billed_amount,
                "currency":        "USD",
                "idempotency_key": ikey,
                "authority":       self.authority,
            }

            # Append to transaction log (atomic write)
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {"total_revenue_usd": 0.0, "transactions": []}

            data["transactions"].append(transaction)
            data["total_revenue_usd"] = round(
                data.get("total_revenue_usd", 0.0) + billed_amount, 6
            )
            self._atomic_write(self.log_file, data)

            # Register idempotency key
            self._register_idempotency(ikey, transaction)

            # Update revenue telemetry
            self._update_telemetry(tenant_id, feature, billed_amount)

            logger.info(
                f"[REVENUE] Billed: tenant={tenant_id} feature={feature} "
                f"units={units} amount=${billed_amount:.4f} "
                f"tx={transaction['transaction_id'][:8]}"
            )
            return transaction

    # ── Telemetry ────────────────────────────────────────────────────────────

    def _update_telemetry(self, tenant_id: str, feature: str, amount: float):
        try:
            with open(self.telemetry_file, "r", encoding="utf-8") as f:
                telem = json.load(f)
        except Exception:
            telem = {"by_feature": {}, "by_month": {}, "by_tenant": {}}

        month = datetime.now(timezone.utc).strftime("%Y-%m")

        telem.setdefault("by_feature", {}).setdefault(feature, 0.0)
        telem["by_feature"][feature] = round(telem["by_feature"][feature] + amount, 6)

        telem.setdefault("by_month", {}).setdefault(month, 0.0)
        telem["by_month"][month] = round(telem["by_month"][month] + amount, 6)

        telem.setdefault("by_tenant", {}).setdefault(tenant_id, 0.0)
        telem["by_tenant"][tenant_id] = round(telem["by_tenant"][tenant_id] + amount, 6)

        telem["last_updated"] = datetime.now(timezone.utc).isoformat()
        self._atomic_write(self.telemetry_file, telem)

    def get_revenue_summary(self) -> Dict[str, Any]:
        """Returns current revenue totals — safe to call at any time."""
        try:
            with _LOCK:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            with open(self.telemetry_file, "r", encoding="utf-8") as f:
                telem = json.load(f)
            return {
                "total_revenue_usd": data.get("total_revenue_usd", 0.0),
                "transaction_count": len(data.get("transactions", [])),
                "by_feature":        telem.get("by_feature", {}),
                "by_month":          telem.get("by_month", {}),
                "top_tenant":        max(
                    telem.get("by_tenant", {"none": 0}).items(),
                    key=lambda x: x[1], default=("none", 0)
                )[0],
                "last_updated":      telem.get("last_updated", ""),
            }
        except Exception as e:
            logger.warning(f"[REVENUE] Summary read failed: {e}")
            return {}

    # ── Atomic write helper ──────────────────────────────────────────────────

    @staticmethod
    def _atomic_write(path: str, data: Any):
        """Write JSON atomically via tmp file + os.replace() — crash-safe."""
        dir_ = os.path.dirname(path) or "."
        os.makedirs(dir_, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


# Global instance for platform-wide access
REVENUE_CORE = CDBRevenueEngine()