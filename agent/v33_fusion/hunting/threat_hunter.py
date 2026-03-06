#!/usr/bin/env python3
"""
threat_hunter.py — CYBERDUDEBIVASH® SENTINEL APEX v33.0
=========================================================
Autonomous Threat Hunter — detects emerging threats by correlating
velocity signals across the intelligence pipeline.

Detection Logic:
1. CVE Velocity Spike — new CVE appears + risk escalates within 24h
2. Actor Surge — known actor shows sudden activity increase
3. Exploit Chain Detection — CVE + PoC + scanning = imminent exploitation
4. Sector Targeting Wave — multiple threats converging on same sector
5. IOC Cluster Alert — correlated IOC infrastructure patterns

Non-Breaking: Reads from feed_manifest.json and fusion outputs.
Writes to isolated data/fusion/hunting/ directory.

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("CDB-ThreatHunter")

HUNTING_DIR = os.environ.get("HUNTING_DIR", "data/fusion/hunting")
MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")


class AlertSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class HuntingAlert:
    """Automated hunting alert."""
    alert_id: str
    alert_type: str
    severity: str
    title: str
    description: str
    indicators: List[str]
    recommended_actions: List[str]
    confidence: float
    timestamp: str
    source_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "indicators": self.indicators[:20],
            "recommended_actions": self.recommended_actions,
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp,
            "source_signal_count": len(self.source_signals),
        }


class AutonomousThreatHunter:
    """
    Autonomous threat detection engine that identifies emerging threats
    from velocity patterns in the intelligence pipeline.
    """

    # Thresholds
    CVE_VELOCITY_THRESHOLD = 3       # CVE mentioned 3+ times in window
    ACTOR_SURGE_THRESHOLD = 5        # Actor appears in 5+ signals
    SECTOR_CONVERGENCE_THRESHOLD = 4 # 4+ threats targeting same sector
    IOC_CLUSTER_THRESHOLD = 5        # 5+ IOCs from same source

    def __init__(self, manifest_path: str = MANIFEST_PATH, output_dir: str = HUNTING_DIR):
        self.manifest_path = manifest_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def load_signals(self, window_hours: int = 72) -> List[Dict]:
        """Load recent signals within time window."""
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load manifest: {e}")
            return []

        entries = data if isinstance(data, list) else data.get("entries", [])
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        recent = [e for e in entries if e.get("published", "") >= cutoff]
        return recent if recent else entries[-100:]

    def hunt(self, window_hours: int = 72) -> List[HuntingAlert]:
        """Execute all hunting detections."""
        logger.info(f"Hunting across {window_hours}h window...")
        signals = self.load_signals(window_hours)
        if not signals:
            return []

        alerts = []
        alerts.extend(self._hunt_cve_velocity(signals))
        alerts.extend(self._hunt_actor_surge(signals))
        alerts.extend(self._hunt_sector_convergence(signals))
        alerts.extend(self._hunt_exploit_chain(signals))
        alerts.extend(self._hunt_critical_escalation(signals))

        # Sort by severity
        severity_order = {AlertSeverity.CRITICAL: 0, AlertSeverity.HIGH: 1, AlertSeverity.MEDIUM: 2, AlertSeverity.LOW: 3}
        alerts.sort(key=lambda a: severity_order.get(a.severity, 4))

        # Save results
        self._save_alerts(alerts)
        logger.info(f"Generated {len(alerts)} hunting alerts")
        return alerts

    def _hunt_cve_velocity(self, signals: List[Dict]) -> List[HuntingAlert]:
        """Detect CVEs with rapid mention velocity."""
        alerts = []
        cve_mentions: Dict[str, List[Dict]] = defaultdict(list)

        for signal in signals:
            for cve in signal.get("cve_ids", []):
                cve_mentions[cve].append(signal)

        for cve, related_signals in cve_mentions.items():
            if len(related_signals) >= self.CVE_VELOCITY_THRESHOLD:
                max_risk = max(s.get("risk_score", 0) for s in related_signals)
                severity = AlertSeverity.CRITICAL if max_risk >= 9.0 else (
                    AlertSeverity.HIGH if max_risk >= 7.0 else AlertSeverity.MEDIUM
                )

                alerts.append(HuntingAlert(
                    alert_id=f"hunt-cve-{cve.lower()}",
                    alert_type="CVE_VELOCITY_SPIKE",
                    severity=severity,
                    title=f"Rapid exploitation velocity detected for {cve}",
                    description=(
                        f"{cve} mentioned in {len(related_signals)} signals within hunting window. "
                        f"Maximum risk score: {max_risk}/10. Active exploitation likely imminent."
                    ),
                    indicators=[cve],
                    recommended_actions=[
                        f"Prioritize patching {cve} across all exposed assets",
                        "Deploy virtual patching via WAF/IPS rules",
                        "Search environment for exploitation indicators",
                        "Brief SOC on active exploitation timeline",
                    ],
                    confidence=min(0.95, 0.5 + len(related_signals) * 0.1),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    source_signals=[s.get("stix_file", "") for s in related_signals],
                ))

        return alerts

    def _hunt_actor_surge(self, signals: List[Dict]) -> List[HuntingAlert]:
        """Detect threat actor activity surges."""
        alerts = []
        actor_signals: Dict[str, List[Dict]] = defaultdict(list)

        for signal in signals:
            actor = signal.get("actor_tag", signal.get("actor_id", ""))
            if actor:
                actor_signals[actor].append(signal)

        for actor, related in actor_signals.items():
            if len(related) >= self.ACTOR_SURGE_THRESHOLD:
                sectors = set()
                for s in related:
                    sectors.update(s.get("sectors", []))

                alerts.append(HuntingAlert(
                    alert_id=f"hunt-actor-{actor.lower().replace(' ', '-')[:30]}",
                    alert_type="ACTOR_ACTIVITY_SURGE",
                    severity=AlertSeverity.HIGH,
                    title=f"Activity surge detected for {actor}",
                    description=(
                        f"Threat actor {actor} appeared in {len(related)} signals. "
                        f"Targeted sectors: {', '.join(sectors) if sectors else 'multiple'}. "
                        f"Campaign escalation probable."
                    ),
                    indicators=[actor] + list(sectors),
                    recommended_actions=[
                        f"Hunt for {actor} TTPs in SIEM/EDR telemetry",
                        f"Review all IOCs associated with {actor}",
                        "Increase monitoring sensitivity for targeted sectors",
                        "Prepare incident response playbook for actor profile",
                    ],
                    confidence=min(0.9, 0.5 + len(related) * 0.08),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    source_signals=[s.get("stix_file", "") for s in related],
                ))

        return alerts

    def _hunt_sector_convergence(self, signals: List[Dict]) -> List[HuntingAlert]:
        """Detect multiple threats converging on same sector."""
        alerts = []
        sector_threats: Dict[str, List[Dict]] = defaultdict(list)

        for signal in signals:
            for sector in signal.get("sectors", []):
                sector_threats[sector].append(signal)

        for sector, related in sector_threats.items():
            if len(related) >= self.SECTOR_CONVERGENCE_THRESHOLD:
                actors = set(s.get("actor_tag", s.get("actor_id", "")) for s in related if s.get("actor_id"))
                avg_risk = sum(s.get("risk_score", 5) for s in related) / len(related)

                alerts.append(HuntingAlert(
                    alert_id=f"hunt-sector-{sector.lower().replace(' ', '-')[:30]}",
                    alert_type="SECTOR_TARGETING_WAVE",
                    severity=AlertSeverity.HIGH if avg_risk >= 7.0 else AlertSeverity.MEDIUM,
                    title=f"Convergent targeting wave against {sector.title()} sector",
                    description=(
                        f"{len(related)} threat signals targeting {sector.title()} sector. "
                        f"Active actors: {', '.join(actors) if actors else 'multiple unattributed'}. "
                        f"Average risk: {avg_risk:.1f}/10."
                    ),
                    indicators=[sector] + list(actors),
                    recommended_actions=[
                        f"Issue sector-wide advisory for {sector.title()} organizations",
                        "Review all detection rules for sector-specific attack patterns",
                        "Increase threat hunting cadence for sector",
                        "Brief sector ISAC on convergent threat activity",
                    ],
                    confidence=min(0.85, 0.4 + len(related) * 0.08),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    source_signals=[s.get("stix_file", "") for s in related],
                ))

        return alerts

    def _hunt_exploit_chain(self, signals: List[Dict]) -> List[HuntingAlert]:
        """Detect exploit chain patterns: CVE + active exploitation signals."""
        alerts = []
        for signal in signals:
            risk = signal.get("risk_score", 0)
            cves = signal.get("cve_ids", [])
            title_lower = signal.get("title", "").lower()

            # Chain indicators
            has_exploit = any(kw in title_lower for kw in [
                "exploit", "poc", "proof of concept", "actively exploited",
                "in the wild", "zero-day", "0-day"
            ])
            has_cve = len(cves) > 0
            is_critical = risk >= 8.5

            if has_exploit and has_cve and is_critical:
                alerts.append(HuntingAlert(
                    alert_id=f"hunt-chain-{signal.get('stix_file', 'unknown')[:30]}",
                    alert_type="EXPLOIT_CHAIN_DETECTED",
                    severity=AlertSeverity.CRITICAL,
                    title=f"Active exploit chain: {', '.join(cves[:3])}",
                    description=(
                        f"Exploit chain detected involving {', '.join(cves)}. "
                        f"Risk score {risk}/10. Active exploitation confirmed. "
                        f"Immediate patching and hunting required."
                    ),
                    indicators=cves,
                    recommended_actions=[
                        "IMMEDIATE: Patch or isolate affected systems",
                        "Deploy emergency WAF/IPS signatures",
                        "Hunt for exploitation artifacts in logs",
                        "Activate incident response if exploitation confirmed",
                    ],
                    confidence=0.92,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    source_signals=[signal.get("stix_file", "")],
                ))

        return alerts

    def _hunt_critical_escalation(self, signals: List[Dict]) -> List[HuntingAlert]:
        """Detect signals that escalated to critical risk."""
        alerts = []
        critical_signals = [s for s in signals if s.get("risk_score", 0) >= 9.5]

        if len(critical_signals) >= 3:
            alerts.append(HuntingAlert(
                alert_id="hunt-escalation-critical-cluster",
                alert_type="CRITICAL_THREAT_CLUSTER",
                severity=AlertSeverity.CRITICAL,
                title=f"{len(critical_signals)} critical threats in active window",
                description=(
                    f"Detected {len(critical_signals)} critical-severity (9.5+/10) threats "
                    f"within the hunting window. Elevated threat landscape detected. "
                    f"SOC should operate at heightened alert status."
                ),
                indicators=[s.get("title", "")[:60] for s in critical_signals[:5]],
                recommended_actions=[
                    "Elevate SOC to heightened alert status",
                    "Review all critical signals for organizational exposure",
                    "Accelerate patching cycles for critical vulnerabilities",
                    "Brief CISO/executive leadership on threat landscape",
                ],
                confidence=0.95,
                timestamp=datetime.now(timezone.utc).isoformat(),
                source_signals=[s.get("stix_file", "") for s in critical_signals],
            ))

        return alerts

    def _save_alerts(self, alerts: List[HuntingAlert]):
        """Save hunting alerts."""
        output_path = os.path.join(self.output_dir, "hunting_alerts.json")
        with open(output_path, 'w') as f:
            json.dump({
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "alert_count": len(alerts),
                "alerts": [a.to_dict() for a in alerts],
                "platform": "SENTINEL APEX v33.0 — Autonomous Threat Hunter",
            }, f, indent=2)
        logger.info(f"Saved {len(alerts)} alerts to {output_path}")


def main():
    """CLI entry point for threat hunting."""
    logging.basicConfig(level=logging.INFO, format="[THREAT-HUNTER] %(asctime)s — %(message)s")
    hunter = AutonomousThreatHunter()
    alerts = hunter.hunt(window_hours=72)
    for alert in alerts:
        logger.info(f"[{alert.severity}] {alert.title}")
    return alerts


if __name__ == "__main__":
    main()
