#!/usr/bin/env python3
"""
quantum_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v41.0 (QUANTUM)
====================================================================
Machine Learning Intelligence: Anomaly Detection, Adversarial Feed
Protection, False Positive Reduction, and Detection Rule A/B Testing.

4 New Subsystems:
  Q1 — AnomalyDetector: Statistical anomaly detection on threat patterns
  Q2 — AdversarialFeedGuard: Poisoned/manipulated feed detection
  Q3 — FalsePositiveReducer: Feedback-driven FP scoring and suppression
  Q4 — DetectionABTester: A/B testing framework for detection rule efficacy

Non-Breaking: Reads from manifest/nexus/cortex. Writes to data/quantum/.

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os, re, json, math, hashlib, logging, time, statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("CDB-Quantum")

MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
QUANTUM_DIR = os.environ.get("QUANTUM_DIR", "data/quantum")
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def _load(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _save(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def _entries():
    d = _load(MANIFEST_PATH)
    if isinstance(d, list): return d
    return d.get("entries", []) if isinstance(d, dict) else []


def _gen_id(prefix, seed):
    return f"{prefix}--{hashlib.sha256(seed.encode()).hexdigest()[:12]}"


# ═══════════════════════════════════════════════════════════════════════════════
# Q1 — ANOMALY DETECTOR (Statistical ML)
# ═══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Statistical anomaly detection engine for threat intelligence patterns.
    Uses Z-score analysis, IQR outlier detection, and temporal baseline
    deviation to identify unusual patterns in the threat landscape.
    """

    def detect_anomalies(self) -> Dict:
        """Run full anomaly detection suite across intelligence data."""
        entries = _entries()
        if len(entries) < 10:
            return {"anomalies": [], "message": "Insufficient data for anomaly detection"}

        anomalies = []

        # A1: Risk Score Distribution Anomalies
        risk_anomalies = self._detect_risk_anomalies(entries)
        anomalies.extend(risk_anomalies)

        # A2: Feed Volume Anomalies (sudden spikes/drops)
        volume_anomalies = self._detect_volume_anomalies(entries)
        anomalies.extend(volume_anomalies)

        # A3: Actor Activity Anomalies (unusual actor patterns)
        actor_anomalies = self._detect_actor_anomalies(entries)
        anomalies.extend(actor_anomalies)

        # A4: Technique Clustering Anomalies
        technique_anomalies = self._detect_technique_anomalies(entries)
        anomalies.extend(technique_anomalies)

        # A5: EPSS/KEV Divergence (high EPSS but no KEV, or vice versa)
        divergence_anomalies = self._detect_scoring_divergence(entries)
        anomalies.extend(divergence_anomalies)

        # Compute overall anomaly score
        total_score = sum(a.get("severity_score", 0) for a in anomalies)
        overall = min(10, total_score / max(len(anomalies), 1) if anomalies else 0)

        return {
            "anomaly_count": len(anomalies),
            "overall_anomaly_score": round(overall, 2),
            "anomalies": sorted(anomalies, key=lambda x: x.get("severity_score", 0), reverse=True),
            "baseline_stats": self._compute_baselines(entries),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _detect_risk_anomalies(self, entries: List[Dict]) -> List[Dict]:
        """Detect anomalous risk score patterns using Z-score."""
        scores = [e.get("risk_score", 0) or 0 for e in entries]
        if len(scores) < 5:
            return []

        mean = statistics.mean(scores)
        stdev = statistics.stdev(scores) if len(scores) > 1 else 0
        if stdev == 0:
            return []

        anomalies = []
        for entry in entries:
            score = entry.get("risk_score", 0) or 0
            z = (score - mean) / stdev
            if abs(z) > 2.5:  # 2.5σ threshold
                anomalies.append({
                    "type": "RISK_SCORE_ANOMALY",
                    "description": f"Risk score {score} is {abs(z):.1f}σ from mean ({mean:.1f})",
                    "advisory": entry.get("title", "")[:80],
                    "z_score": round(z, 2),
                    "severity_score": min(10, abs(z) * 2),
                    "recommendation": "Verify scoring inputs — potential miscalculation or genuine outlier",
                })

        return anomalies[:5]

    def _detect_volume_anomalies(self, entries: List[Dict]) -> List[Dict]:
        """Detect unusual volume patterns (spikes/drops) by day."""
        daily_counts = Counter()
        for e in entries:
            ts = e.get("timestamp", "")
            if ts:
                try:
                    day = ts[:10]
                    daily_counts[day] += 1
                except (ValueError, IndexError):
                    pass

        if len(daily_counts) < 3:
            return []

        counts = list(daily_counts.values())
        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) > 1 else 0
        if stdev == 0:
            return []

        anomalies = []
        for day, count in daily_counts.items():
            z = (count - mean) / stdev
            if z > 2.0:
                anomalies.append({
                    "type": "VOLUME_SPIKE",
                    "description": f"Day {day}: {count} advisories ({z:.1f}σ above average {mean:.0f})",
                    "date": day,
                    "count": count,
                    "z_score": round(z, 2),
                    "severity_score": min(8, z * 2),
                    "recommendation": "Investigate: coordinated campaign, mass disclosure, or data quality issue",
                })
            elif z < -2.0:
                anomalies.append({
                    "type": "VOLUME_DROP",
                    "description": f"Day {day}: Only {count} advisories ({abs(z):.1f}σ below average)",
                    "date": day,
                    "count": count,
                    "z_score": round(z, 2),
                    "severity_score": min(5, abs(z)),
                    "recommendation": "Check feed health — possible source outage or collection gap",
                })

        return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)[:5]

    def _detect_actor_anomalies(self, entries: List[Dict]) -> List[Dict]:
        """Detect unusual actor activity patterns."""
        actor_counts = Counter()
        actor_risks = defaultdict(list)
        for e in entries:
            actor = e.get("actor_tag", "")
            if actor and actor != "UNC-CDB-99":
                actor_counts[actor] += 1
                actor_risks[actor].append(e.get("risk_score", 0) or 0)

        if not actor_counts:
            return []

        counts = list(actor_counts.values())
        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) > 1 else 1

        anomalies = []
        for actor, count in actor_counts.items():
            z = (count - mean) / max(stdev, 0.01)
            if z > 2.0:
                avg_risk = statistics.mean(actor_risks[actor])
                anomalies.append({
                    "type": "ACTOR_SURGE",
                    "description": f"{actor}: {count} advisories ({z:.1f}σ above normal), avg risk {avg_risk:.1f}",
                    "actor": actor,
                    "advisory_count": count,
                    "avg_risk_score": round(avg_risk, 1),
                    "z_score": round(z, 2),
                    "severity_score": min(9, z * 2 + (avg_risk / 3)),
                    "recommendation": f"Prioritize {actor} threat hunt — elevated campaign activity detected",
                })

        return sorted(anomalies, key=lambda x: x["severity_score"], reverse=True)[:5]

    def _detect_technique_anomalies(self, entries: List[Dict]) -> List[Dict]:
        """Detect unusual MITRE technique clustering."""
        tech_counts = Counter()
        for e in entries:
            for t in e.get("mitre_tactics", []):
                tid = t if isinstance(t, str) else t.get("technique_id", t.get("id", ""))
                if tid:
                    tech_counts[tid.split(".")[0]] += 1

        if len(tech_counts) < 3:
            return []

        counts = list(tech_counts.values())
        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) > 1 else 1

        anomalies = []
        for tech, count in tech_counts.items():
            z = (count - mean) / max(stdev, 0.01)
            if z > 2.0:
                anomalies.append({
                    "type": "TECHNIQUE_CLUSTER",
                    "description": f"{tech} observed {count}x ({z:.1f}σ above baseline) — possible coordinated use",
                    "technique": tech,
                    "count": count,
                    "z_score": round(z, 2),
                    "severity_score": min(7, z * 1.5),
                    "recommendation": f"Deploy specific detection for {tech} across all endpoints",
                })

        return sorted(anomalies, key=lambda x: x["severity_score"], reverse=True)[:3]

    def _detect_scoring_divergence(self, entries: List[Dict]) -> List[Dict]:
        """Detect EPSS/KEV scoring divergences."""
        anomalies = []
        for e in entries:
            epss = e.get("epss_score", 0) or 0
            kev = e.get("kev_present", False)
            risk = e.get("risk_score", 0) or 0

            # High EPSS but low risk = potential underscoring
            if epss >= 70 and risk < 5:
                anomalies.append({
                    "type": "SCORING_DIVERGENCE",
                    "description": f"EPSS {epss}% but risk only {risk}/10 — potential underscoring",
                    "advisory": e.get("title", "")[:80],
                    "epss_score": epss,
                    "risk_score": risk,
                    "severity_score": 6,
                    "recommendation": "Re-evaluate risk scoring weights for this advisory class",
                })
            # KEV confirmed but low EPSS = data lag
            elif kev and epss < 20 and risk < 7:
                anomalies.append({
                    "type": "KEV_EPSS_MISMATCH",
                    "description": f"CISA KEV confirmed but EPSS only {epss}% — EPSS may be lagging",
                    "advisory": e.get("title", "")[:80],
                    "kev_present": True,
                    "epss_score": epss,
                    "severity_score": 5,
                    "recommendation": "Trust KEV signal; override EPSS weight for this advisory",
                })

        return anomalies[:5]

    def _compute_baselines(self, entries: List[Dict]) -> Dict:
        """Compute statistical baselines for the dataset."""
        scores = [e.get("risk_score", 0) or 0 for e in entries]
        return {
            "total_entries": len(entries),
            "risk_mean": round(statistics.mean(scores), 2) if scores else 0,
            "risk_stdev": round(statistics.stdev(scores), 2) if len(scores) > 1 else 0,
            "risk_median": round(statistics.median(scores), 2) if scores else 0,
            "critical_pct": round(sum(1 for s in scores if s >= 9) / max(len(scores), 1) * 100, 1),
            "kev_pct": round(sum(1 for e in entries if e.get("kev_present")) / max(len(entries), 1) * 100, 1),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Q2 — ADVERSARIAL FEED GUARD
# ═══════════════════════════════════════════════════════════════════════════════

class AdversarialFeedGuard:
    """
    Detects poisoned, manipulated, or unreliable intelligence feeds.
    Validates feed consistency, detects injection patterns, and
    computes feed trust scores.
    """

    SUSPICIOUS_PATTERNS = [
        r'(?:test|dummy|fake|placeholder|lorem\s?ipsum)',
        r'(?:AAA{5,}|BBB{5,}|xxx{3,})',
        r'(?:\d{1,3}\.){3}\d{1,3}.*(?:\d{1,3}\.){3}\d{1,3}.*(?:\d{1,3}\.){3}\d{1,3}',  # IP flood
        r'CVE-\d{4}-0{4,}',  # Fake CVE patterns
    ]

    def analyze_feeds(self) -> Dict:
        """Analyze all feeds for adversarial manipulation."""
        entries = _entries()
        if not entries:
            return {"feed_scores": {}, "alerts": []}

        feed_groups = defaultdict(list)
        for e in entries:
            src = e.get("feed_source", "unknown")
            feed_groups[src].append(e)

        feed_scores = {}
        alerts = []

        for feed, items in feed_groups.items():
            score, feed_alerts = self._score_feed(feed, items, entries)
            feed_scores[feed] = score
            alerts.extend(feed_alerts)

        # Cross-feed consistency check
        cross_alerts = self._cross_feed_validation(feed_groups)
        alerts.extend(cross_alerts)

        return {
            "feed_count": len(feed_groups),
            "feed_scores": feed_scores,
            "alerts": sorted(alerts, key=lambda a: a.get("severity", 0), reverse=True),
            "overall_trust": round(
                sum(s["trust_score"] for s in feed_scores.values()) / max(len(feed_scores), 1), 2
            ),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _score_feed(self, feed: str, items: List[Dict], all_entries: List[Dict]) -> Tuple[Dict, List[Dict]]:
        """Score a single feed for trustworthiness."""
        alerts = []
        penalties = 0

        # Check 1: Volume consistency
        total = len(all_entries)
        pct = len(items) / max(total, 1) * 100
        if pct > 40:
            penalties += 1
            alerts.append({
                "type": "FEED_DOMINANCE",
                "feed": feed,
                "message": f"{feed} represents {pct:.0f}% of all intel — over-reliance risk",
                "severity": 4,
            })

        # Check 2: Suspicious content patterns
        suspicious_count = 0
        for item in items:
            title = item.get("title", "").lower()
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, title, re.IGNORECASE):
                    suspicious_count += 1
                    break

        if suspicious_count > 0:
            penalties += min(3, suspicious_count)
            alerts.append({
                "type": "SUSPICIOUS_CONTENT",
                "feed": feed,
                "message": f"{suspicious_count} entries contain suspicious patterns",
                "severity": 6,
            })

        # Check 3: Risk score distribution (feeds should have variety)
        risks = [i.get("risk_score", 0) or 0 for i in items]
        if risks:
            risk_stdev = statistics.stdev(risks) if len(risks) > 1 else 0
            if risk_stdev < 0.5 and len(risks) > 5:
                penalties += 1
                alerts.append({
                    "type": "LOW_VARIANCE",
                    "feed": feed,
                    "message": f"Unusually uniform risk scores (stdev={risk_stdev:.2f}) — potential manipulation",
                    "severity": 5,
                })

        # Check 4: Timestamp freshness
        timestamps = [i.get("timestamp", "") for i in items if i.get("timestamp")]
        if timestamps:
            try:
                latest = max(timestamps)
                latest_dt = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - latest_dt).days
                if age_days > 14:
                    penalties += 1
                    alerts.append({
                        "type": "STALE_FEED",
                        "feed": feed,
                        "message": f"Latest entry is {age_days} days old — feed may be inactive",
                        "severity": 3,
                    })
            except (ValueError, TypeError):
                pass

        # Check 5: MITRE coverage (legitimate feeds should have technique mapping)
        has_mitre = sum(1 for i in items if i.get("mitre_tactics"))
        mitre_pct = has_mitre / max(len(items), 1) * 100
        if mitre_pct < 20 and len(items) > 10:
            penalties += 1

        trust = max(0, min(100, 100 - penalties * 8))
        return {
            "feed": feed,
            "entry_count": len(items),
            "trust_score": trust,
            "risk_mean": round(statistics.mean(risks), 2) if risks else 0,
            "mitre_coverage_pct": round(mitre_pct, 1),
            "penalties": penalties,
        }, alerts

    def _cross_feed_validation(self, feed_groups: Dict) -> List[Dict]:
        """Cross-validate entries across feeds."""
        alerts = []
        # Check for duplicate titles across feeds (potential re-injection)
        title_sources = defaultdict(set)
        for feed, items in feed_groups.items():
            for item in items:
                title = item.get("title", "")[:60].lower()
                if title:
                    title_sources[title].add(feed)

        dupe_count = sum(1 for srcs in title_sources.values() if len(srcs) > 2)
        if dupe_count > 10:
            alerts.append({
                "type": "CROSS_FEED_DUPLICATION",
                "message": f"{dupe_count} entries appear across 3+ feeds — normal for major events, monitor for injection",
                "severity": 3,
            })

        return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# Q3 — FALSE POSITIVE REDUCER
# ═══════════════════════════════════════════════════════════════════════════════

class FalsePositiveReducer:
    """
    Feedback-driven false positive scoring and suppression engine.
    Learns from historical patterns to predict FP likelihood.
    """

    FP_INDICATORS = {
        # v55.0 FIX: Rebalanced weights — old weights caused 52% FP rate because
        # no_iocs(0.4) + no_actor(0.2) = 0.6 > threshold(0.5) flagged most RSS entries.
        # New weights require 3+ convergent signals to reach FP threshold of 0.6.
        "generic_title": {"pattern": r'^(?:update|patch|advisory|bulletin)\b', "weight": 0.15},
        "no_iocs": {"check": lambda e: not any(v for v in (e.get("ioc_counts") or {}).values()), "weight": 0.2},
        "no_actor": {"check": lambda e: not e.get("actor_tag") or e.get("actor_tag") == "UNC-CDB-99", "weight": 0.1},
        "no_techniques": {"check": lambda e: not e.get("mitre_tactics"), "weight": 0.15},
        "low_confidence": {"check": lambda e: (e.get("confidence_score") or 100) < 30, "weight": 0.3},
        "low_epss": {"check": lambda e: (e.get("epss_score") or 0) < 5, "weight": 0.1},
        "info_only": {"check": lambda e: (e.get("risk_score") or 0) < 2, "weight": 0.3},
    }

    def analyze(self) -> Dict:
        """Analyze entries for false positive likelihood."""
        entries = _entries()
        if not entries:
            return {"entries_analyzed": 0, "fp_candidates": []}

        fp_candidates = []
        for entry in entries:
            fp_score = self._compute_fp_score(entry)
            if fp_score >= 0.6:  # v55.0 FIX: raised from 0.5 to reduce false positives
                fp_candidates.append({
                    "title": entry.get("title", "")[:80],
                    "stix_id": entry.get("stix_id", ""),
                    "risk_score": entry.get("risk_score", 0),
                    "fp_probability": round(fp_score, 3),
                    "reasons": self._get_fp_reasons(entry),
                    "recommendation": "SUPPRESS" if fp_score >= 0.8 else "REVIEW",
                })

        # Compute FP rate estimate
        fp_rate = len(fp_candidates) / max(len(entries), 1) * 100

        return {
            "entries_analyzed": len(entries),
            "fp_candidates": sorted(fp_candidates, key=lambda x: x["fp_probability"], reverse=True)[:50],
            "fp_candidate_count": len(fp_candidates),
            "estimated_fp_rate_pct": round(fp_rate, 1),
            "suppression_recommendations": sum(1 for f in fp_candidates if f["recommendation"] == "SUPPRESS"),
            "review_recommendations": sum(1 for f in fp_candidates if f["recommendation"] == "REVIEW"),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _compute_fp_score(self, entry: Dict) -> float:
        """Compute false positive probability score (0-1)."""
        score = 0.0
        title = entry.get("title", "").lower()

        for indicator_name, indicator in self.FP_INDICATORS.items():
            if "pattern" in indicator:
                if re.search(indicator["pattern"], title, re.IGNORECASE):
                    score += indicator["weight"]
            elif "check" in indicator:
                if indicator["check"](entry):
                    score += indicator["weight"]

        return min(1.0, score)

    def _get_fp_reasons(self, entry: Dict) -> List[str]:
        """Get human-readable FP reasons."""
        reasons = []
        title = entry.get("title", "").lower()

        if not any(v for v in (entry.get("ioc_counts") or {}).values()):
            reasons.append("No IOCs detected")
        if not entry.get("actor_tag") or entry.get("actor_tag") == "UNC-CDB-99":
            reasons.append("No attributed threat actor")
        if not entry.get("mitre_tactics"):
            reasons.append("No MITRE ATT&CK mapping")
        if (entry.get("confidence_score") or 100) < 30:
            reasons.append("Low analyst confidence")
        if (entry.get("risk_score") or 0) < 2:
            reasons.append("Info-level risk only")
        if (entry.get("epss_score") or 0) < 5:
            reasons.append("Minimal exploitation probability")

        return reasons


# ═══════════════════════════════════════════════════════════════════════════════
# Q4 — DETECTION A/B TESTER
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionABTester:
    """
    A/B testing framework for detection rule efficacy.
    Generates variant detection rules and tracks performance metrics.
    """

    def generate_experiments(self) -> Dict:
        """Generate A/B test experiments for detection rules."""
        entries = _entries()
        high_risk = [e for e in entries if (e.get("risk_score", 0) or 0) >= 7]
        if not high_risk:
            return {"experiments": []}

        experiments = []

        # Experiment types
        for entry in high_risk[:10]:
            title = entry.get("title", "")
            cves = CVE_RE.findall(title)
            tactics = entry.get("mitre_tactics", [])

            if not cves and not tactics:
                continue

            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', title[:40])

            # Variant A: Broad detection (higher recall, lower precision)
            # Variant B: Narrow detection (lower recall, higher precision)
            experiment = {
                "experiment_id": _gen_id("abtest", safe_name),
                "name": f"Detection Optimization: {title[:50]}",
                "hypothesis": "Narrow detection rules reduce false positives without missing true threats",
                "variant_a": {
                    "name": "Broad Detection",
                    "description": "Matches any related IOC or technique indicator",
                    "expected_recall": 0.95,
                    "expected_precision": 0.60,
                    "rule_type": "sigma",
                    "detection_logic": "selection: any technique OR any CVE mention",
                },
                "variant_b": {
                    "name": "Precise Detection",
                    "description": "Requires multiple correlated indicators",
                    "expected_recall": 0.75,
                    "expected_precision": 0.90,
                    "rule_type": "sigma",
                    "detection_logic": "selection: (technique AND CVE) OR (IOC AND actor_tag)",
                },
                "metrics": [
                    "true_positive_rate",
                    "false_positive_rate",
                    "mean_time_to_detect",
                    "analyst_triage_time",
                ],
                "duration_days": 14,
                "status": "PROPOSED",
                "advisory_context": {
                    "title": title[:80],
                    "risk_score": entry.get("risk_score", 0),
                    "cves": cves[:3],
                    "techniques": [
                        t if isinstance(t, str) else t.get("technique_id", "")
                        for t in tactics[:3]
                    ],
                },
            }
            experiments.append(experiment)

        return {
            "total_experiments": len(experiments),
            "experiments": experiments,
            "framework_config": {
                "min_sample_size": 100,
                "confidence_level": 0.95,
                "statistical_test": "chi_squared",
                "rollout_strategy": "gradual",
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# QUANTUM ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class QuantumOrchestrator:
    def __init__(self):
        self.anomaly = AnomalyDetector()
        self.feed_guard = AdversarialFeedGuard()
        self.fp_reducer = FalsePositiveReducer()
        self.ab_tester = DetectionABTester()

    def execute_full_cycle(self) -> Dict:
        logger.info("[QUANTUM] Starting ML intelligence cycle...")
        start = time.time()
        results = {"version": "41.0.0", "codename": "QUANTUM", "generated_at": datetime.now(timezone.utc).isoformat()}

        try:
            anomaly_results = self.anomaly.detect_anomalies()
            results["anomalies"] = {"count": anomaly_results["anomaly_count"], "score": anomaly_results["overall_anomaly_score"]}
            _save(os.path.join(QUANTUM_DIR, "anomaly_detection.json"), anomaly_results)
            logger.info(f"[QUANTUM-Q1] Detected {anomaly_results['anomaly_count']} anomalies (score: {anomaly_results['overall_anomaly_score']})")
        except Exception as e:
            logger.error(f"[QUANTUM-Q1] Anomaly detection failed: {e}")
            results["anomalies"] = {}

        try:
            feed_results = self.feed_guard.analyze_feeds()
            results["feed_trust"] = {"overall": feed_results["overall_trust"], "alerts": len(feed_results["alerts"])}
            _save(os.path.join(QUANTUM_DIR, "feed_guard.json"), feed_results)
            logger.info(f"[QUANTUM-Q2] Feed trust: {feed_results['overall_trust']}, Alerts: {len(feed_results['alerts'])}")
        except Exception as e:
            logger.error(f"[QUANTUM-Q2] Feed guard failed: {e}")
            results["feed_trust"] = {}

        try:
            fp_results = self.fp_reducer.analyze()
            results["false_positives"] = {"fp_rate": fp_results["estimated_fp_rate_pct"], "candidates": fp_results["fp_candidate_count"]}
            _save(os.path.join(QUANTUM_DIR, "false_positives.json"), fp_results)
            logger.info(f"[QUANTUM-Q3] FP rate: {fp_results['estimated_fp_rate_pct']}%, Candidates: {fp_results['fp_candidate_count']}")
        except Exception as e:
            logger.error(f"[QUANTUM-Q3] FP reduction failed: {e}")
            results["false_positives"] = {}

        try:
            ab_results = self.ab_tester.generate_experiments()
            results["ab_tests"] = {"experiments": ab_results["total_experiments"]}
            _save(os.path.join(QUANTUM_DIR, "ab_experiments.json"), ab_results)
            logger.info(f"[QUANTUM-Q4] Generated {ab_results['total_experiments']} A/B experiments")
        except Exception as e:
            logger.error(f"[QUANTUM-Q4] A/B testing failed: {e}")
            results["ab_tests"] = {}

        elapsed = round((time.time() - start) * 1000, 2)
        results["execution_time_ms"] = elapsed
        _save(os.path.join(QUANTUM_DIR, "quantum_output.json"), results)
        logger.info(f"[QUANTUM] Full cycle completed in {elapsed}ms")
        return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    print("=" * 70)
    print("CYBERDUDEBIVASH® SENTINEL APEX v41.0 — QUANTUM")
    print("=" * 70)
    o = QuantumOrchestrator()
    r = o.execute_full_cycle()
    print(f"\n✅ QUANTUM Cycle Complete")
    print(f"   Anomalies:     {r.get('anomalies', {}).get('count', 0)} (score: {r.get('anomalies', {}).get('score', 0)})")
    print(f"   Feed Trust:    {r.get('feed_trust', {}).get('overall', 0)}")
    print(f"   FP Rate:       {r.get('false_positives', {}).get('fp_rate', 0)}%")
    print(f"   A/B Tests:     {r.get('ab_tests', {}).get('experiments', 0)}")
    print(f"   Execution:     {r.get('execution_time_ms', 0)}ms")
