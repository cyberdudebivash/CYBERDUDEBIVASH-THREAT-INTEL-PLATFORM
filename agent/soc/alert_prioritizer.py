"""
CYBERDUDEBIVASH® SENTINEL APEX
ALERT PRIORITIZER — CVSS/EPSS/KEV/Context-aware scoring
Produces P1/P2/P3/P4 prioritization with full rationale.
"""
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-SOC-PRIORITIZER")


# ── Severity weight tables ─────────────────────────────────────────────────
SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25, "INFO": 0.10}
TLP_WEIGHT      = {"TLP:RED": 1.0, "TLP:AMBER": 0.80, "TLP:GREEN": 0.50, "TLP:WHITE": 0.30}
KEV_BONUS       = 2.5   # CISA KEV confirmed
EXPLOIT_BONUS   = 1.5   # Active exploit confirmed
ZERO_DAY_BONUS  = 2.0   # Zero-day
NATION_STATE_B  = 1.2   # Nation-state actor
RANSOMWARE_B    = 1.8   # Ransomware

PRIORITY_THRESHOLDS = {
    "P1": 8.0,   # Critical — immediate response required (<15 min)
    "P2": 6.0,   # High — response within 1 hour
    "P3": 4.0,   # Medium — response within 4 hours
    "P4": 0.0,   # Low — response within 24 hours
}

PRIORITY_SLAS = {
    "P1": "15 minutes",
    "P2": "1 hour",
    "P3": "4 hours",
    "P4": "24 hours",
}


class AlertPrioritizer:
    """
    Production-grade alert prioritizer for CYBERDUDEBIVASH SOC.
    Implements multi-factor scoring: CVSS + EPSS + KEV + context signals.
    """

    def __init__(self):
        self.logger = logging.getLogger("CDB-SOC-PRIORITIZER")

    # ── Core scoring ────────────────────────────────────────────────────────

    def compute_priority_score(self, alert: Dict[str, Any]) -> Tuple[float, Dict]:
        """Compute composite priority score 0-10 with full factor breakdown."""
        score = 0.0
        factors = {}

        # 1. CVSS base score (0-10)
        def _sf(v):
            try: return float(v) if v is not None else 0.0
            except (ValueError, TypeError): return 0.0
        cvss = _sf(alert.get("cvss") or alert.get("cvss_score"))
        cvss_contribution = cvss * 0.35
        score += cvss_contribution
        factors["cvss"] = {"value": cvss, "contribution": round(cvss_contribution, 2)}

        # 2. EPSS probability (0-1 → 0-10 scale)
        epss = _sf(alert.get("epss") or alert.get("epss_score"))
        epss_contribution = epss * 10 * 0.25
        score += epss_contribution
        factors["epss"] = {"value": epss, "contribution": round(epss_contribution, 2)}

        # 3. Severity weight
        severity = str(alert.get("severity", "MEDIUM")).upper()
        sev_w = SEVERITY_WEIGHT.get(severity, 0.50)
        sev_contribution = sev_w * 2.0
        score += sev_contribution
        factors["severity"] = {"value": severity, "contribution": round(sev_contribution, 2)}

        # 4. TLP weight
        tlp = str(alert.get("tlp", "TLP:GREEN")).upper()
        tlp_w = TLP_WEIGHT.get(tlp, 0.30)
        tlp_contribution = tlp_w * 0.5
        score += tlp_contribution
        factors["tlp"] = {"value": tlp, "contribution": round(tlp_contribution, 2)}

        # 5. Contextual bonuses
        bonuses = []
        title = str(alert.get("title") or "").lower()
        tags = [str(t).lower() for t in (alert.get("tags") or [])]
        all_text = title + " " + " ".join(tags)

        if alert.get("kev_confirmed") or "kev" in all_text:
            score += KEV_BONUS; bonuses.append(f"+KEV({KEV_BONUS})")
        if alert.get("exploit_available") or "exploit" in all_text:
            score += EXPLOIT_BONUS; bonuses.append(f"+EXPLOIT({EXPLOIT_BONUS})")
        if "0-day" in all_text or "zero-day" in all_text or "zeroday" in all_text:
            score += ZERO_DAY_BONUS; bonuses.append(f"+ZERODAY({ZERO_DAY_BONUS})")
        if any(k in all_text for k in ["ransomware", "ransom"]):
            score += RANSOMWARE_B; bonuses.append(f"+RANSOMWARE({RANSOMWARE_B})")
        if any(k in all_text for k in ["apt", "nation-state", "nation state", "state-sponsored"]):
            score += NATION_STATE_B; bonuses.append(f"+NATIONSTATE({NATION_STATE_B})")

        factors["bonuses"] = bonuses

        # 6. IOC count signal
        ioc_count = len(alert.get("iocs") or [])
        if ioc_count > 10:
            ioc_b = min(1.0, ioc_count / 50)
            score += ioc_b
            factors["ioc_boost"] = round(ioc_b, 2)

        # Cap at 10
        final_score = round(min(score, 10.0), 2)
        factors["final_score"] = final_score
        return final_score, factors

    def assign_priority(self, score: float) -> str:
        """Map score to P1-P4 priority."""
        for p, threshold in PRIORITY_THRESHOLDS.items():
            if score >= threshold:
                return p
        return "P4"

    def prioritize(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Full prioritization of a single alert."""
        score, factors = self.compute_priority_score(alert)
        priority = self.assign_priority(score)
        sla = PRIORITY_SLAS.get(priority, "24 hours")

        return {
            "alert_id":        alert.get("stix_id", alert.get("id", "unknown")),
            "title":           alert.get("title", ""),
            "priority":        priority,
            "priority_score":  score,
            "sla":             sla,
            "severity":        alert.get("severity", "UNKNOWN"),
            "scoring_factors": factors,
            "prioritized_at":  datetime.now(timezone.utc).isoformat(),
            "requires_immediate_action": priority in ("P1", "P2"),
            "escalate_to_tier2":         priority == "P1",
            "escalate_to_tier3":         score >= 9.0,
        }

    def batch_prioritize(self, alerts: List[Dict]) -> List[Dict]:
        """Prioritize a list of alerts, sorted by score descending."""
        results = [self.prioritize(a) for a in alerts]
        return sorted(results, key=lambda x: x["priority_score"], reverse=True)

    def get_p1_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Return only P1 alerts."""
        return [r for r in self.batch_prioritize(alerts) if r["priority"] == "P1"]

    def get_summary(self, prioritized: List[Dict]) -> Dict:
        """Aggregate summary of prioritized alerts."""
        by_priority: Dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for r in prioritized:
            by_priority[r.get("priority", "P4")] = by_priority.get(r.get("priority","P4"), 0) + 1
        return {
            "total": len(prioritized),
            "by_priority": by_priority,
            "p1_critical_count": by_priority["P1"],
            "immediate_action_required": by_priority["P1"] > 0,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
