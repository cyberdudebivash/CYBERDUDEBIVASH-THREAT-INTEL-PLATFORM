"""
CYBERDUDEBIVASH® SENTINEL APEX
ZERO TRUST IDENTITY AI ENGINE v1.0
Identity behavior analysis, access risk scoring, continuous authentication.
"""
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-ZERO-TRUST")

RISK_SIGNALS = {
    "off_hours_access":      2.0,
    "new_device":            1.5,
    "impossible_travel":     3.5,
    "unusual_resource":      1.8,
    "privilege_escalation":  2.5,
    "bulk_download":         2.2,
    "failed_then_success":   2.0,
    "admin_action_non_admin":3.0,
    "vpn_new_location":      1.2,
    "sensitive_data_access": 1.5,
}

TRUST_LEVELS = {
    "FULL":      (0.0, 2.0,  "Access granted — normal behavior"),
    "ELEVATED":  (2.0, 4.5,  "Step-up auth required — elevated risk"),
    "RESTRICTED":(4.5, 7.0,  "MFA required + session monitoring"),
    "BLOCKED":   (7.0, 99.0, "Access denied — investigate immediately"),
}


class ZeroTrustEngine:
    """
    Continuous identity risk scoring engine.
    Applies zero-trust principles: never trust, always verify.
    """

    def __init__(self):
        self.session_store: Dict[str, Dict] = {}
        self.risk_events: List[Dict] = []

    def compute_identity_risk(self, identity_event: Dict) -> Dict:
        """Compute real-time risk score for an identity event."""
        user_id   = identity_event.get("user_id", "unknown")
        resource  = identity_event.get("resource", "")
        timestamp = identity_event.get("timestamp", datetime.now(timezone.utc).isoformat())
        source_ip = identity_event.get("source_ip", "")
        device_id = identity_event.get("device_id", "")

        risk_score = 0.0
        triggered_signals = []

        # Check off-hours (22:00–06:00 UTC)
        try:
            hour = int(timestamp[11:13])
            if hour >= 22 or hour < 6:
                risk_score += RISK_SIGNALS["off_hours_access"]
                triggered_signals.append("off_hours_access")
        except Exception:
            pass

        # New device
        known_devices = self.session_store.get(user_id, {}).get("known_devices", [])
        if device_id and device_id not in known_devices:
            risk_score += RISK_SIGNALS["new_device"]
            triggered_signals.append("new_device")

        # Bulk download
        if identity_event.get("bytes_accessed", 0) > 100_000_000:
            risk_score += RISK_SIGNALS["bulk_download"]
            triggered_signals.append("bulk_download")

        # Sensitive resource
        sensitive_keywords = ["admin", "credential", "secret", "backup", "prod-db", "finance"]
        if any(kw in str(resource).lower() for kw in sensitive_keywords):
            risk_score += RISK_SIGNALS["sensitive_data_access"]
            triggered_signals.append("sensitive_data_access")

        # Failed then success
        if identity_event.get("preceded_by_failures", False):
            risk_score += RISK_SIGNALS["failed_then_success"]
            triggered_signals.append("failed_then_success")

        # Privilege escalation
        if identity_event.get("privilege_escalated", False):
            risk_score += RISK_SIGNALS["privilege_escalation"]
            triggered_signals.append("privilege_escalation")

        # Impossible travel
        if identity_event.get("impossible_travel", False):
            risk_score += RISK_SIGNALS["impossible_travel"]
            triggered_signals.append("impossible_travel")

        risk_score = round(min(10.0, risk_score), 2)

        # Determine trust level
        trust_level = "FULL"
        action = "Access granted"
        for level, (lo, hi, msg) in TRUST_LEVELS.items():
            if lo <= risk_score < hi:
                trust_level = level
                action = msg
                break

        # Update session store
        if user_id not in self.session_store:
            self.session_store[user_id] = {"known_devices": [], "risk_history": []}
        if device_id:
            self.session_store[user_id]["known_devices"].append(device_id)
        self.session_store[user_id]["risk_history"].append(risk_score)

        result = {
            "user_id":          user_id,
            "resource":         resource,
            "risk_score":       risk_score,
            "trust_level":      trust_level,
            "action":           action,
            "triggered_signals": triggered_signals,
            "requires_mfa":     risk_score >= 2.0,
            "requires_step_up": risk_score >= 4.5,
            "block_access":     risk_score >= 7.0,
            "evaluated_at":     datetime.now(timezone.utc).isoformat(),
        }
        self.risk_events.append(result)
        logger.info(f"[ZERO-TRUST] {user_id} → risk={risk_score} trust={trust_level}")
        return result

    def get_high_risk_users(self, threshold: float = 5.0) -> List[Dict]:
        """Return users with elevated risk scores."""
        risky = []
        for uid, data in self.session_store.items():
            history = data.get("risk_history", [])
            if history:
                avg_risk = sum(history) / len(history)
                max_risk = max(history)
                if max_risk >= threshold:
                    risky.append({
                        "user_id": uid,
                        "avg_risk": round(avg_risk, 2),
                        "max_risk": max_risk,
                        "event_count": len(history),
                    })
        return sorted(risky, key=lambda x: -x["max_risk"])

    def get_engine_status(self) -> Dict:
        return {
            "engine": "ZeroTrustEngine v1.0",
            "monitored_users": len(self.session_store),
            "risk_events": len(self.risk_events),
            "status": "OPERATIONAL",
        }
