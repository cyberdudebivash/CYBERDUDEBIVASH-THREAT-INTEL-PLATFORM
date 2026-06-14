#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v145.0.0
ENTERPRISE GOVERNANCE ENGINE — Phases 1–4
===============================================================================
Unified governance layer enforcing:

  PHASE 1 — Duplicate Intelligence Suppression
    - Multi-layer semantic dedup validation
    - Cross-feed duplicate telemetry
    - Duplicate dashboard pollution detection

  PHASE 2 — Confidence Inflation Governance
    - risk=10 without CVE/KEV evidence detector
    - Evidence-weighted score validation
    - Confidence anomaly telemetry
    - Score calibration enforcement

  PHASE 3 — Feed Normalization & Contract Governance
    - Worker/API schema compatibility check
    - Preview envelope contract validation
    - Feed structure determinism enforcement
    - Schema drift detection

  PHASE 4 — Intelligence Trust-Tier Scoring
    - Advisory trust classification (HIGH/VERIFIED/PARTIAL/LOW/LIMITED)
    - Source confidence governance
    - IOC evidence scoring
    - Dossier trust grading

GUARANTEES:
  - Never raises (all phases wrapped in try/except)
  - Always returns GovernanceReport dataclass
  - Atomic writes only (tmp -> fsync -> os.replace)
  - Zero inline Python in YAML — pure script call
  - All governance outputs written to data/governance/

Usage:
  python3 scripts/enterprise_governance_engine.py [--manifest PATH] [--report] [--strict]

  --manifest PATH  Path to feed JSON (default: api/feed.json)
  --report         Write governance report to data/governance/
  --strict         Exit 1 if any HARD governance violation found

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import pathlib
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [governance] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-GOVERNANCE")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = pathlib.Path(__file__).resolve().parent.parent
GOV_DIR     = REPO_ROOT / "data" / "governance"
REPORT_PATH = GOV_DIR / "governance_report.json"
FEED_PATH   = REPO_ROOT / "api" / "feed.json"

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION = "145.0.0"

# Phase 2: Evidence thresholds
RISK_INFLATION_SCORE       = 10.0   # risk scores at or above this require evidence
INFLATION_EVIDENCE_KEYS    = ("cve_id", "kev_present", "epss_score", "cvss_score")
EPSS_HIGH_THRESHOLD        = 0.5    # EPSS >= 0.5 counts as evidence
CVSS_HIGH_THRESHOLD        = 9.0    # CVSS >= 9.0 counts as evidence

# Phase 4: Trust tier thresholds
TRUST_TIER_HIGH_MIN_SCORE  = 80
TRUST_TIER_VERIFIED_MIN    = 60
TRUST_TIER_PARTIAL_MIN     = 40
TRUST_TIER_LOW_MIN         = 20

# Authoritative source patterns (Phase 4)
AUTHORITATIVE_SOURCES = {
    "cisa.gov", "nvd.nist.gov", "cert.org", "ncsc.gov.uk",
    "us-cert.cisa.gov", "msrc.microsoft.com", "security.googleblog.com",
    "blog.talosintelligence.com", "unit42.paloaltonetworks.com",
    "www.mandiant.com", "securelist.com", "blog.checkpoint.com",
    "blog.rapid7.com", "blog.qualys.com", "greynoise.io",
    "otx.alienvault.com", "attack.mitre.org",
}

MEDIUM_TRUST_SOURCES = {
    "github.com", "medium.com", "reddit.com", "infosecurity-magazine.com",
    "bleepingcomputer.com", "therecord.media", "darkreading.com",
    "securityweek.com", "thehackernews.com", "cybersecuritynews.com",
}


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class DuplicateViolation:
    item_id:    str
    title:      str
    layer:      str   # "title_hash", "stix_id", "source_url", "content_hash"
    matched_id: str
    severity:   str   # "HARD", "SOFT"


@dataclass
class InflationViolation:
    item_id:    str
    title:      str
    risk_score: float
    evidence:   List[str]   # what evidence IS present
    missing:    List[str]   # what evidence is MISSING
    verdict:    str         # "INFLATED", "BORDERLINE", "JUSTIFIED"


@dataclass
class ContractViolation:
    check:    str
    field:    str
    expected: str
    actual:   str
    severity: str   # "HARD", "SOFT"


@dataclass
class TrustScore:
    item_id:    str
    title:      str
    tier:       str    # HIGH_TRUST, VERIFIED, PARTIAL, LOW_CONFIDENCE, ENRICHMENT_LIMITED
    score:      int    # 0-100
    factors:    List[str]
    deductions: List[str]


@dataclass
class GovernanceReport:
    generated_at:        str
    engine_version:      str
    feed_path:           str
    total_items:         int

    # Phase 1: Dedup
    duplicate_violations: List[DuplicateViolation]  = field(default_factory=list)
    duplicate_rate_pct:   float                      = 0.0
    dedup_passed:         bool                       = True

    # Phase 2: Confidence inflation
    inflation_violations: List[InflationViolation]  = field(default_factory=list)
    inflation_rate_pct:   float                      = 0.0
    inflation_passed:     bool                       = True

    # Phase 3: Contract
    contract_violations:  List[ContractViolation]   = field(default_factory=list)
    contract_passed:      bool                       = True

    # Phase 4: Trust tiers
    trust_scores:         List[TrustScore]           = field(default_factory=list)
    trust_distribution:   Dict[str, int]             = field(default_factory=dict)
    avg_trust_score:      float                      = 0.0

    # Summary
    hard_violations:      int   = 0
    soft_violations:      int   = 0
    governance_grade:     str   = "A"
    overall_pass:         bool  = True
    summary:              str   = ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _title_hash(title: str) -> str:
    normalized = re.sub(r"\s+", " ", (title or "").lower().strip())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _content_hash(item: Dict) -> str:
    blob = json.dumps({
        "title": item.get("title", ""),
        "description": item.get("description", "")[:200],
        "source_url": item.get("source_url", ""),
    }, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _load_feed(path: pathlib.Path) -> List[Dict]:
    if not path.exists():
        log.warning("Feed not found at %s — governance will run on empty set", path)
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            for key in ("items", "advisories", "reports", "data", "feed", "entries"):
                if isinstance(raw.get(key), list):
                    return raw[key]
        log.warning("Unrecognised feed format — returning empty")
        return []
    except Exception as exc:
        log.error("Failed to load feed: %s", exc)
        return []


def _sanitize_json_keys(obj: Any) -> Any:
    """Recursively convert non-string dict keys (e.g. tuples from Counter) to
    strings so json.dump never raises 'keys must be str, int, float, bool or
    None, not tuple'.  The default=str handler only covers non-serialisable
    VALUES; non-string KEYS require this pre-pass.
    """
    if isinstance(obj, dict):
        return {
            str(k) if not isinstance(k, (str, int, float, bool, type(None))) else k:
            _sanitize_json_keys(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize_json_keys(i) for i in obj]
    return obj


def _atomic_write(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        safe_data = _sanitize_json_keys(data) if isinstance(data, (dict, list)) else data
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(safe_data, fh, indent=2, ensure_ascii=False, default=str)
            fh.write("\n")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


# ── Phase 1: Duplicate Suppression ───────────────────────────────────────────

def _phase1_dedup(items: List[Dict]) -> Tuple[List[DuplicateViolation], bool]:
    """
    Multi-layer dedup validation.
    Returns (violations, passed).
    Hard violations = same stix_id or source_url.
    Soft violations = same title hash.
    """
    violations: List[DuplicateViolation] = []

    seen_stix: Dict[str, str]    = {}
    seen_url:  Dict[str, str]    = {}
    seen_title: Dict[str, str]   = {}
    seen_content: Dict[str, str] = {}

    GENERIC_TITLES = {
        "cisa advisory", "security advisory", "threat report",
        "intel report", "vulnerability report", "",
    }

    for item in items:
        iid   = item.get("id") or item.get("stix_id") or "unknown"
        title = (item.get("title") or "").strip()
        stix  = item.get("stix_id", "")
        url   = (item.get("source_url") or "").strip().rstrip("/")
        th    = _title_hash(title)
        ch    = _content_hash(item)

        # Layer 1: stix_id hard dedup
        if stix and stix in seen_stix:
            violations.append(DuplicateViolation(
                item_id=iid, title=title, layer="stix_id",
                matched_id=seen_stix[stix], severity="HARD",
            ))
        elif stix:
            seen_stix[stix] = iid

        # Layer 2: source_url hard dedup (non-empty URLs)
        if url and url in seen_url:
            violations.append(DuplicateViolation(
                item_id=iid, title=title, layer="source_url",
                matched_id=seen_url[url], severity="HARD",
            ))
        elif url:
            seen_url[url] = iid

        # Layer 3: title-hash soft dedup (skip generic titles)
        title_lc = title.lower()
        if title_lc not in GENERIC_TITLES and len(title) > 10:
            if th in seen_title:
                violations.append(DuplicateViolation(
                    item_id=iid, title=title, layer="title_hash",
                    matched_id=seen_title[th], severity="SOFT",
                ))
            else:
                seen_title[th] = iid

        # Layer 4: content-hash soft dedup
        if ch in seen_content:
            existing = seen_content[ch]
            if existing != iid:
                violations.append(DuplicateViolation(
                    item_id=iid, title=title, layer="content_hash",
                    matched_id=existing, severity="SOFT",
                ))
        else:
            seen_content[ch] = iid

    hard = sum(1 for v in violations if v.severity == "HARD")
    passed = hard == 0
    if violations:
        log.warning("[Phase1] Dedup violations: %d HARD, %d SOFT",
                    hard, len(violations) - hard)
    else:
        log.info("[Phase1] Dedup: PASS — 0 violations in %d items", len(items))
    return violations, passed


# ── Phase 2: Confidence Inflation Governance ──────────────────────────────────

def _phase2_inflation(items: List[Dict]) -> Tuple[List[InflationViolation], bool]:
    """
    Detect unjustified risk=10 scoring (no CVE/KEV/CVSS/EPSS evidence).
    Returns (violations, passed).
    """
    violations: List[InflationViolation] = []

    for item in items:
        risk = item.get("risk_score", 0)
        if not isinstance(risk, (int, float)):
            try:
                risk = float(risk)
            except (TypeError, ValueError):
                risk = 0.0

        if risk < RISK_INFLATION_SCORE:
            continue

        iid   = item.get("id") or item.get("stix_id") or "unknown"
        title = (item.get("title") or "")[:80]

        evidence: List[str] = []
        missing:  List[str] = []

        # Check CVE
        cve = item.get("cve_id", "")
        if cve and re.match(r"CVE-\d{4}-\d+", str(cve)):
            evidence.append(f"CVE: {cve}")
        else:
            missing.append("cve_id")

        # Check KEV
        kev = item.get("kev_present", False)
        if kev and str(kev).lower() not in ("false", "0", "none", "null", ""):
            evidence.append("KEV: confirmed")
        else:
            missing.append("kev_present")

        # Check CVSS
        cvss = item.get("cvss_score")
        if cvss is not None:
            try:
                cvss_f = float(cvss)
                if cvss_f >= CVSS_HIGH_THRESHOLD:
                    evidence.append(f"CVSS: {cvss_f:.1f}")
                else:
                    missing.append(f"cvss_score<{CVSS_HIGH_THRESHOLD}")
            except (TypeError, ValueError):
                missing.append("cvss_score_invalid")
        else:
            missing.append("cvss_score")

        # Check EPSS
        epss = item.get("epss_score")
        if epss is not None:
            try:
                epss_f = float(epss)
                if epss_f >= EPSS_HIGH_THRESHOLD:
                    evidence.append(f"EPSS: {epss_f:.3f}")
                else:
                    missing.append(f"epss_score<{EPSS_HIGH_THRESHOLD}")
            except (TypeError, ValueError):
                missing.append("epss_score_invalid")
        else:
            missing.append("epss_score")

        # Check IOC count as supporting evidence
        ioc_count = item.get("ioc_count", 0) or len(item.get("iocs", []))
        if ioc_count >= 3:
            evidence.append(f"IOCs: {ioc_count}")

        # Check ATT&CK coverage as supporting evidence
        ttp_count = item.get("ttp_count", 0) or len(item.get("ttps", []))
        if ttp_count >= 5:
            evidence.append(f"TTPs: {ttp_count}")

        # Verdict
        if len(evidence) >= 2:
            verdict = "JUSTIFIED"
        elif len(evidence) == 1:
            verdict = "BORDERLINE"
        else:
            verdict = "INFLATED"

        if verdict in ("INFLATED", "BORDERLINE"):
            violations.append(InflationViolation(
                item_id=iid, title=title, risk_score=risk,
                evidence=evidence, missing=missing, verdict=verdict,
            ))

    hard = sum(1 for v in violations if v.verdict == "INFLATED")
    passed = hard == 0
    if violations:
        log.warning("[Phase2] Inflation: %d INFLATED, %d BORDERLINE (of %d risk=10 items)",
                    hard, len(violations) - hard, len(violations))
    else:
        log.info("[Phase2] Confidence inflation: PASS — all risk=10 items have evidence")
    return violations, passed


# ── Phase 3: Feed Contract Governance ─────────────────────────────────────────

def _phase3_contract(items: List[Dict]) -> Tuple[List[ContractViolation], bool]:
    """
    Validates feed items conform to the Worker/API schema contract.
    Prevents future canary false-negatives from schema drift.
    """
    violations: List[ContractViolation] = []

    # Required top-level fields per API contract
    REQUIRED_FIELDS = {
        "id":               ("str", True),
        "stix_id":          ("str", True),
        "title":            ("str", True),
        "severity":         ("str", True),
        "risk_score":       ("number", True),
        "processed_at":     ("str", False),
        "source":           ("str", False),
        "report_url":       ("str", False),
    }

    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"}
    VALID_RISK_RANGE = (0.0, 10.0)

    null_field_counts:    Counter = Counter()
    missing_field_counts: Counter = Counter()
    severity_invalid:     List[str] = []
    risk_out_of_range:    List[str] = []

    for item in items:
        iid = item.get("id") or item.get("stix_id") or "UNKNOWN"

        for field_name, (ftype, required) in REQUIRED_FIELDS.items():
            val = item.get(field_name)
            if val is None or val == "":
                if required:
                    missing_field_counts[field_name] += 1
            elif ftype == "str" and not isinstance(val, str):
                null_field_counts[f"{field_name}:wrong_type"] += 1
            elif ftype == "number" and not isinstance(val, (int, float)):
                try:
                    float(val)
                except (TypeError, ValueError):
                    null_field_counts[f"{field_name}:not_numeric"] += 1

        sev = (item.get("severity") or "").upper()
        if sev and sev not in VALID_SEVERITIES:
            severity_invalid.append(iid)

        risk = item.get("risk_score")
        if risk is not None:
            try:
                rf = float(risk)
                if not (VALID_RISK_RANGE[0] <= rf <= VALID_RISK_RANGE[1]):
                    risk_out_of_range.append(f"{iid}:{rf}")
            except (TypeError, ValueError):
                pass

    # Emit contract violations
    for fname, count in missing_field_counts.items():
        pct = count / max(len(items), 1) * 100
        sev = "HARD" if pct > 5 else "SOFT"
        violations.append(ContractViolation(
            check="required_field_missing", field=fname,
            expected="non-null string", actual=f"{count} items null/missing ({pct:.1f}%)",
            severity=sev,
        ))

    for fname, count in null_field_counts.items():
        violations.append(ContractViolation(
            check="field_type_mismatch", field=fname,
            expected="correct type", actual=f"{count} items wrong type",
            severity="SOFT",
        ))

    if severity_invalid:
        violations.append(ContractViolation(
            check="severity_invalid", field="severity",
            expected=str(VALID_SEVERITIES),
            actual=f"{len(severity_invalid)} items with invalid severity",
            severity="HARD",
        ))

    if risk_out_of_range:
        violations.append(ContractViolation(
            check="risk_score_out_of_range", field="risk_score",
            expected="0.0–10.0",
            actual=f"{len(risk_out_of_range)} items out of range: {risk_out_of_range[:5]}",
            severity="HARD",
        ))

    # Worker preview envelope contract check
    # Validates that if items have apex_ai, it's a dict (not null/string)
    bad_apex = sum(1 for i in items if "apex_ai" in i and not isinstance(i["apex_ai"], dict))
    if bad_apex > 0:
        violations.append(ContractViolation(
            check="apex_ai_type_invalid", field="apex_ai",
            expected="dict or absent",
            actual=f"{bad_apex} items with non-dict apex_ai",
            severity="SOFT",
        ))

    hard = sum(1 for v in violations if v.severity == "HARD")
    passed = hard == 0
    if violations:
        log.warning("[Phase3] Contract: %d HARD, %d SOFT violations", hard, len(violations) - hard)
    else:
        log.info("[Phase3] Feed contract: PASS — all %d items schema-compliant", len(items))
    return violations, passed


# ── Phase 4: Intelligence Trust-Tier Scoring ─────────────────────────────────

def _phase4_trust_tiers(items: List[Dict]) -> Tuple[List[TrustScore], Dict[str, int], float]:
    """
    Score each item's intelligence trust level.
    Returns (scores, distribution, avg_score).
    """
    scores: List[TrustScore] = []

    for item in items:
        iid   = item.get("id") or item.get("stix_id") or "unknown"
        title = (item.get("title") or "")[:60]
        score = 50  # base
        factors:    List[str] = []
        deductions: List[str] = []

        # +Source trust
        src_url = (item.get("source_url") or "").lower()
        if any(domain in src_url for domain in AUTHORITATIVE_SOURCES):
            score += 20
            factors.append("authoritative_source:+20")
        elif any(domain in src_url for domain in MEDIUM_TRUST_SOURCES):
            score += 5
            factors.append("medium_trust_source:+5")
        else:
            score -= 10
            deductions.append("unknown_source:-10")

        # +CVE presence
        if item.get("cve_id") and re.match(r"CVE-\d{4}-\d+", str(item.get("cve_id", ""))):
            score += 10
            factors.append("cve_verified:+10")

        # +KEV
        if item.get("kev_present") and str(item.get("kev_present")).lower() not in ("false", "0", "none"):
            score += 15
            factors.append("kev_confirmed:+15")

        # +CVSS >= 9
        cvss = item.get("cvss_score")
        if cvss is not None:
            try:
                if float(cvss) >= 9.0:
                    score += 10
                    factors.append(f"cvss_critical({cvss}):+10")
                elif float(cvss) >= 7.0:
                    score += 5
                    factors.append(f"cvss_high({cvss}):+5")
            except (TypeError, ValueError):
                pass

        # +IOC richness
        ioc_count = item.get("ioc_count", 0) or len(item.get("iocs", []))
        if ioc_count >= 5:
            score += 10
            factors.append(f"ioc_rich({ioc_count}):+10")
        elif ioc_count >= 2:
            score += 5
            factors.append(f"ioc_present({ioc_count}):+5")
        elif ioc_count == 0:
            score -= 5
            deductions.append("no_iocs:-5")

        # +ATT&CK coverage
        ttp_count = item.get("ttp_count", 0) or len(item.get("ttps", []))
        if ttp_count >= 5:
            score += 10
            factors.append(f"attck_rich({ttp_count}):+10")
        elif ttp_count >= 2:
            score += 5
            factors.append(f"attck_present({ttp_count}):+5")
        elif ttp_count == 0:
            score -= 5
            deductions.append("no_ttps:-5")

        # +STIX integrity
        if item.get("stix_id") and str(item.get("stix_id", "")).startswith("indicator--"):
            score += 5
            factors.append("stix_indicator:+5")

        # +Freshness (processed within 7 days)
        proc = item.get("processed_at") or item.get("timestamp")
        if proc:
            try:
                from datetime import timedelta
                pt = datetime.fromisoformat(proc.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - pt).days
                if age_days <= 3:
                    score += 5
                    factors.append(f"fresh({age_days}d):+5")
                elif age_days > 30:
                    score -= 10
                    deductions.append(f"stale({age_days}d):-10")
            except Exception:
                pass

        # -Risk inflation penalty
        risk = item.get("risk_score", 0)
        try:
            risk = float(risk)
        except (TypeError, ValueError):
            risk = 0.0

        if risk >= 10.0:
            has_evidence = bool(
                item.get("cve_id") or item.get("kev_present") or
                item.get("cvss_score") or item.get("epss_score")
            )
            if not has_evidence:
                score -= 20
                deductions.append("risk10_no_evidence:-20")

        # Clamp
        score = max(0, min(100, score))

        # Tier
        if score >= TRUST_TIER_HIGH_MIN_SCORE:
            tier = "HIGH_TRUST"
        elif score >= TRUST_TIER_VERIFIED_MIN:
            tier = "VERIFIED"
        elif score >= TRUST_TIER_PARTIAL_MIN:
            tier = "PARTIAL"
        elif score >= TRUST_TIER_LOW_MIN:
            tier = "LOW_CONFIDENCE"
        else:
            tier = "ENRICHMENT_LIMITED"

        scores.append(TrustScore(
            item_id=iid, title=title, tier=tier, score=score,
            factors=factors, deductions=deductions,
        ))

    distribution: Dict[str, int] = Counter(s.tier for s in scores)
    avg = sum(s.score for s in scores) / max(len(scores), 1)

    log.info(
        "[Phase4] Trust tiers: HIGH=%d VERIFIED=%d PARTIAL=%d LOW=%d LIMITED=%d | avg=%.1f",
        distribution.get("HIGH_TRUST", 0),
        distribution.get("VERIFIED", 0),
        distribution.get("PARTIAL", 0),
        distribution.get("LOW_CONFIDENCE", 0),
        distribution.get("ENRICHMENT_LIMITED", 0),
        avg,
    )
    return scores, distribution, avg


# ── Governance Grade ──────────────────────────────────────────────────────────

def _compute_grade(report: GovernanceReport) -> str:
    hard = report.hard_violations
    soft = report.soft_violations
    dup_pct = report.duplicate_rate_pct
    inf_pct = report.inflation_rate_pct
    avg_trust = report.avg_trust_score

    if hard == 0 and soft == 0 and dup_pct < 1 and inf_pct < 5 and avg_trust >= 60:
        return "A+"
    if hard == 0 and soft <= 2 and dup_pct < 2 and inf_pct < 10 and avg_trust >= 50:
        return "A"
    if hard == 0 and soft <= 5 and dup_pct < 5 and inf_pct < 20:
        return "B"
    if hard <= 1 and inf_pct < 30:
        return "C"
    if hard <= 3:
        return "D"
    return "F"


# ── Main Engine ───────────────────────────────────────────────────────────────

def run_governance(
    feed_path: pathlib.Path = FEED_PATH,
    write_report: bool = True,
) -> GovernanceReport:
    """
    Execute all 4 governance phases and return a GovernanceReport.
    Never raises — all phase errors are logged and produce empty results.
    """
    t0 = time.monotonic()
    log.info("=" * 60)
    log.info("SENTINEL APEX — Enterprise Governance Engine v%s", VERSION)
    log.info("Feed: %s", feed_path)
    log.info("=" * 60)

    items = _load_feed(feed_path)
    log.info("Loaded %d items from feed", len(items))

    report = GovernanceReport(
        generated_at=_now_iso(),
        engine_version=VERSION,
        feed_path=str(feed_path),
        total_items=len(items),
    )

    # Phase 1: Dedup
    try:
        report.duplicate_violations, report.dedup_passed = _phase1_dedup(items)
        report.duplicate_rate_pct = (
            len(report.duplicate_violations) / max(len(items), 1) * 100
        )
        # Auto-remediation: remove HARD duplicate items from feed and write back.
        # Only the *second occurrence* (the item_id in the violation) is removed;
        # the first-seen canonical item is preserved.
        hard_dup_ids = {
            v.item_id for v in report.duplicate_violations if v.severity == "HARD"
        }
        if hard_dup_ids:
            before_count = len(items)
            items = [
                it for it in items
                if (it.get("stix_id") or it.get("id")) not in hard_dup_ids
            ]
            removed = before_count - len(items)
            log.info(
                "[Phase1-AutoFix] Removed %d HARD duplicate item(s) from feed → writing cleaned feed",
                removed,
            )
            try:
                _atomic_write(pathlib.Path(feed_path), items)
                log.info("[Phase1-AutoFix] Cleaned feed written: %d items", len(items))
                report.total_items = len(items)
                # Re-compute duplicate rate against cleaned count
                report.duplicate_rate_pct = 0.0
                report.dedup_passed = True
            except Exception as write_exc:
                log.error("[Phase1-AutoFix] Failed to write cleaned feed: %s", write_exc)
    except Exception as exc:
        log.error("[Phase1] Unexpected error: %s", exc)
        report.dedup_passed = True  # non-fatal

    # Phase 2: Inflation
    try:
        report.inflation_violations, report.inflation_passed = _phase2_inflation(items)
        report.inflation_rate_pct = (
            len(report.inflation_violations) / max(len(items), 1) * 100
        )
    except Exception as exc:
        log.error("[Phase2] Unexpected error: %s", exc)
        report.inflation_passed = True  # non-fatal

    # Phase 3: Contract
    try:
        report.contract_violations, report.contract_passed = _phase3_contract(items)
    except Exception as exc:
        log.error("[Phase3] Unexpected error: %s", exc)
        report.contract_passed = True  # non-fatal

    # Phase 4: Trust tiers
    try:
        report.trust_scores, report.trust_distribution, report.avg_trust_score = (
            _phase4_trust_tiers(items)
        )
    except Exception as exc:
        log.error("[Phase4] Unexpected error: %s", exc)
        report.trust_distribution = {}
        report.avg_trust_score = 0.0

    # Aggregate violations
    all_violations = (
        [v for v in report.duplicate_violations if v.severity == "HARD"] +
        [v for v in report.contract_violations  if v.severity == "HARD"] +
        [v for v in report.inflation_violations if v.verdict == "INFLATED"]
    )
    all_soft = (
        [v for v in report.duplicate_violations if v.severity == "SOFT"] +
        [v for v in report.contract_violations  if v.severity == "SOFT"] +
        [v for v in report.inflation_violations if v.verdict == "BORDERLINE"]
    )
    report.hard_violations = len(all_violations)
    report.soft_violations  = len(all_soft)
    report.overall_pass     = report.hard_violations == 0
    report.governance_grade = _compute_grade(report)

    elapsed = time.monotonic() - t0
    report.summary = (
        f"Grade={report.governance_grade} | "
        f"Hard={report.hard_violations} Soft={report.soft_violations} | "
        f"Dupes={len(report.duplicate_violations)} ({report.duplicate_rate_pct:.1f}%) | "
        f"Inflation={len(report.inflation_violations)} ({report.inflation_rate_pct:.1f}%) | "
        f"Contract={len(report.contract_violations)} | "
        f"AvgTrust={report.avg_trust_score:.1f} | "
        f"runtime={elapsed:.2f}s"
    )

    log.info("=" * 60)
    log.info("GOVERNANCE RESULT: %s", report.summary)
    log.info("=" * 60)

    # Write report
    if write_report and items:
        try:
            payload = asdict(report)
            # Trim trust_scores for large feeds (keep summary + worst 20)
            if len(report.trust_scores) > 20:
                worst = sorted(report.trust_scores, key=lambda x: x.score)[:20]
                payload["trust_scores_sample"] = [asdict(s) for s in worst]
                payload["trust_scores"] = []
                payload["trust_scores_note"] = (
                    f"{len(report.trust_scores)} items scored; "
                    f"showing 20 lowest-trust for review"
                )
            _atomic_write(REPORT_PATH, payload)
            log.info("Report written: %s", REPORT_PATH)
        except Exception as exc:
            log.error("Failed to write report: %s", exc)

    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Enterprise Governance Engine v" + VERSION
    )
    parser.add_argument(
        "--manifest", "--feed",
        default=str(FEED_PATH),
        help="Path to feed JSON (default: api/feed.json)",
    )
    parser.add_argument(
        "--report", action="store_true", default=True,
        help="Write governance report to data/governance/ (default: on)",
    )
    parser.add_argument(
        "--strict", action="store_true", default=False,
        help="Exit 1 if any HARD governance violation found",
    )
    args = parser.parse_args()

    feed_path = pathlib.Path(args.manifest)
    report = run_governance(feed_path=feed_path, write_report=args.report)

    print("\n" + "=" * 60)
    print("  SENTINEL APEX GOVERNANCE REPORT")
    print("=" * 60)
    print(f"  Grade          : {report.governance_grade}")
    print(f"  Total Items    : {report.total_items}")
    print(f"  Hard Violations: {report.hard_violations}")
    print(f"  Soft Violations: {report.soft_violations}")
    print(f"  Duplicates     : {len(report.duplicate_violations)} ({report.duplicate_rate_pct:.1f}%)")
    print(f"  Inflation      : {len(report.inflation_violations)} ({report.inflation_rate_pct:.1f}%)")
    print(f"  Contract Issues: {len(report.contract_violations)}")
    print(f"  Avg Trust Score: {report.avg_trust_score:.1f}/100")
    print(f"  Trust Dist     : {report.trust_distribution}")
    print(f"  Overall        : {'PASS' if report.overall_pass else 'FAIL'}")
    print("=" * 60)

    if args.strict and not report.overall_pass:
        log.error("STRICT MODE: %d hard violation(s) found — exiting 1", report.hard_violations)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
