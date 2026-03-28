"""
CYBERDUDEBIVASH® SENTINEL APEX
TIER-1 TRIAGE AGENT — First-line autonomous alert analysis
Performs: classification, deduplication, enrichment, escalation decision.
"""
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .alert_prioritizer import AlertPrioritizer

logger = logging.getLogger("CDB-SOC-TIER1")

# Known false-positive patterns (reduce noise)
FP_PATTERNS = [
    r"test\s+(alert|event|scan)",
    r"scheduled\s+scan",
    r"baseline\s+check",
    r"nessus\s+scan",
    r"vulnerability\s+scan\s+result",
]

TRIAGE_DECISION = {
    "P1": "ESCALATE_TIER2_IMMEDIATE",
    "P2": "ESCALATE_TIER2_STANDARD",
    "P3": "MONITOR_INVESTIGATE",
    "P4": "LOG_AND_CLOSE",
}


class Tier1TriageAgent:
    """
    Autonomous Tier-1 SOC agent.
    Classifies, enriches, deduplicates, and routes alerts.
    """

    def __init__(self):
        self.prioritizer = AlertPrioritizer()
        self.processed_hashes: set = set()
        self.stats = {"total": 0, "fp_filtered": 0, "duplicates": 0, "escalated": 0, "closed": 0}

    # ── Deduplication ────────────────────────────────────────────────────────

    def _fingerprint(self, alert: Dict) -> str:
        """SHA-256 fingerprint for deduplication."""
        key = f"{alert.get('title','')}|{alert.get('severity','')}|{alert.get('cvss','')}"
        return hashlib.sha256(key.encode()).hexdigest()

    def _is_duplicate(self, alert: Dict) -> bool:
        fp = self._fingerprint(alert)
        if fp in self.processed_hashes:
            return True
        self.processed_hashes.add(fp)
        return False

    # ── False-positive filter ────────────────────────────────────────────────

    def _is_false_positive(self, alert: Dict) -> bool:
        text = f"{str(alert.get('title') or '')} {str(alert.get('summary') or '')}".lower()
        return any(re.search(p, text, re.I) for p in FP_PATTERNS)

    # ── Enrichment ──────────────────────────────────────────────────────────

    def _extract_ioc_types(self, alert: Dict) -> List[str]:
        ioc_types = set()
        for ioc in (alert.get("iocs") or []):
            v = str(ioc.get("value", ioc) if isinstance(ioc, dict) else ioc)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
                ioc_types.add("ip")
            elif re.match(r"^[0-9a-f]{32,64}$", v, re.I):
                ioc_types.add("hash")
            elif re.match(r"^https?://", v):
                ioc_types.add("url")
            elif "." in v and " " not in v:
                ioc_types.add("domain")
            else:
                ioc_types.add("string")
        return list(ioc_types)

    def _enrich_alert(self, alert: Dict) -> Dict:
        """Add Tier-1 enrichment fields."""
        enriched = dict(alert)
        enriched["tier1_processed_at"] = datetime.now(timezone.utc).isoformat()
        enriched["ioc_types"] = self._extract_ioc_types(alert)
        enriched["ioc_count"] = len(alert.get("iocs") or [])
        enriched["cve_count"] = len(alert.get("cves") or [])
        enriched["mitre_technique_count"] = len(alert.get("mitre_techniques") or [])
        # Extract CVEs from title/summary if not present
        if not enriched.get("cves"):
            cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", f"{alert.get('title','')} {alert.get('summary','')}", re.I)
            enriched["cves"] = list(set(cve_matches))
        return enriched

    # ── Core triage ─────────────────────────────────────────────────────────

    def triage(self, alert: Dict) -> Dict:
        """Run full Tier-1 triage on a single alert."""
        self.stats["total"] += 1

        # Stage 1: False-positive filter
        if self._is_false_positive(alert):
            self.stats["fp_filtered"] += 1
            return {"status": "FALSE_POSITIVE", "alert_id": alert.get("stix_id", ""), "tier": "T1", "action": "CLOSED_FP"}

        # Stage 2: Deduplication
        if self._is_duplicate(alert):
            self.stats["duplicates"] += 1
            return {"status": "DUPLICATE", "alert_id": alert.get("stix_id", ""), "tier": "T1", "action": "DEDUPLICATED"}

        # Stage 3: Enrichment
        enriched = self._enrich_alert(alert)

        # Stage 4: Prioritization
        prio_result = self.prioritizer.prioritize(enriched)
        priority = prio_result["priority"]
        action = TRIAGE_DECISION.get(priority, "LOG_AND_CLOSE")

        if priority in ("P1", "P2"):
            self.stats["escalated"] += 1
        else:
            self.stats["closed"] += 1

        logger.info(f"[T1-TRIAGE] {str(alert.get('title') or '')[:60]} → {priority} | {action}")

        return {
            "status": "TRIAGED",
            "tier": "T1",
            "action": action,
            "priority": priority,
            "priority_score": prio_result["priority_score"],
            "sla": prio_result["sla"],
            "scoring_factors": prio_result["scoring_factors"],
            "enriched_alert": enriched,
            "escalate": priority in ("P1", "P2"),
            "requires_tier2": priority == "P1",
            "triaged_at": datetime.now(timezone.utc).isoformat(),
        }

    def batch_triage(self, alerts: List[Dict]) -> Dict:
        """Triage a batch of alerts."""
        results = [self.triage(a) for a in alerts]
        escalations = [r for r in results if r.get("escalate")]
        return {
            "total_processed": len(results),
            "results": results,
            "escalations": escalations,
            "stats": self.stats,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_stats(self) -> Dict:
        return self.stats
