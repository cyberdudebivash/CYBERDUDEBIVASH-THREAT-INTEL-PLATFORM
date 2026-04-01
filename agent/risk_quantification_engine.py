#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX                                            ║
║  ROI-DRIVEN RISK QUANTIFICATION + BRAND PROTECTION ENGINE v1.0            ║
║  Financial Impact · Severity Tiers · Phishing Detection · Takedown        ║
╚══════════════════════════════════════════════════════════════════════════════╝
Zero-regression · Explainable outputs · No exaggeration · Deterministic scoring
"""

import os
import sys
import re
import json
import math
import hashlib
import logging
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-RISK-QUANT")
logging.basicConfig(level=logging.INFO, format="[RISK-QUANT] %(asctime)s %(levelname)s %(message)s")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH    = os.path.join(BASE_DIR, "data", "enriched_manifest.json")
OUTPUT_DIR       = os.path.join(BASE_DIR, "data", "risk_quantification")
FINANCIAL_IMPACT = os.path.join(OUTPUT_DIR, "financial_impact.json")
BRAND_PROTECTION = os.path.join(OUTPUT_DIR, "brand_protection.json")
RISK_TIERS       = os.path.join(OUTPUT_DIR, "risk_tiers.json")
PORTFOLIO_RISK   = os.path.join(OUTPUT_DIR, "portfolio_risk_summary.json")
ENGINE_META      = os.path.join(OUTPUT_DIR, "engine_meta.json")

# ── Industry breach cost baselines (2025-2026, USD) ──────────────────────────
# Source: IBM Cost of a Data Breach Report 2024 sector averages
SECTOR_BREACH_COSTS: Dict[str, int] = {
    "healthcare":      9_770_000,   # $9.77M average
    "finance":         6_080_000,   # $6.08M
    "pharma":          5_050_000,   # $5.05M
    "energy":          4_780_000,   # $4.78M
    "technology":      4_970_000,   # $4.97M
    "education":       3_790_000,   # $3.79M
    "government":      2_760_000,   # $2.76M
    "manufacturing":   4_470_000,   # $4.47M
    "telecom":         3_690_000,   # $3.69M
    "retail":          2_960_000,   # $2.96M
    "DEFAULT":         4_450_000,   # Cross-industry average
}

# ── Regulatory fine maxima (2025-2026) ────────────────────────────────────────
REGULATORY_MAXIMA: Dict[str, Dict] = {
    "GDPR":      {"max_usd": 20_000_000, "basis": "or 4% global revenue"},
    "HIPAA":     {"max_usd": 1_900_000,  "basis": "per category per year"},
    "PCI_DSS":   {"max_usd": 500_000,    "basis": "per incident"},
    "CCPA":      {"max_usd": 7_500,      "basis": "per intentional violation"},
    "NIS2":      {"max_usd": 10_000_000, "basis": "or 2% global revenue"},
    "SOX":       {"max_usd": 5_000_000,  "basis": "per violation + criminal"},
}

# ── CVSS→financial multiplier mapping ────────────────────────────────────────
CVSS_FINANCIAL_MULTIPLIERS = {
    (9.0, 10.0): 1.00,   # Critical: 100% of sector baseline
    (7.0, 8.9):  0.65,   # High: 65%
    (4.0, 6.9):  0.30,   # Medium: 30%
    (0.0, 3.9):  0.10,   # Low: 10%
}

# ── Exploit status multipliers ────────────────────────────────────────────────
EXPLOIT_MULTIPLIERS = {
    "WEAPONIZED":         2.5,
    "EXPLOITED_IN_WILD":  2.0,
    "POC_AVAILABLE":      1.5,
    "HIGH_PROBABILITY":   1.3,
    "MEDIUM_PROBABILITY": 1.1,
    "LOW_PROBABILITY":    1.0,
    "NO_EXPLOIT":         0.8,
    "UNKNOWN":            1.0,
}

# ── Phishing / impersonation domain patterns ──────────────────────────────────
PHISHING_INDICATORS = [
    "phishing", "spoofed domain", "typosquat", "lookalike", "impersonat",
    "fake website", "fraudulent", "brand abuse", "homoglyph",
    "clone site", "credential harvesting", "credential phish",
    "business email compromise", "bec", "whaling", "vishing",
]

# ── Brand impersonation keyword detection ─────────────────────────────────────
BRAND_IMPERSONATION_TARGETS = [
    "microsoft", "google", "amazon", "apple", "paypal", "netflix",
    "linkedin", "facebook", "twitter", "instagram", "bank", "irs",
    "government", "fedex", "ups", "dhl", "adobe", "docusign",
]


def _atomic_write(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _load_manifest() -> List[Dict]:
    for candidate in [MANIFEST_PATH,
                      os.path.join(BASE_DIR, "data", "advisory_manifest.json"),
                      os.path.join(BASE_DIR, "data", "stix", "manifest.json")]:
        if os.path.exists(candidate):
            try:
                with open(candidate, encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else data.get("advisories", [])
            except Exception as e:
                logger.warning(f"Failed to load {candidate}: {e}")
    return []


def _get_cvss_multiplier(cvss: float) -> float:
    for (low, high), mult in CVSS_FINANCIAL_MULTIPLIERS.items():
        if low <= cvss <= high:
            return mult
    return 0.30


def _sector_from_text(text: str) -> str:
    for sector in SECTOR_BREACH_COSTS:
        if sector != "DEFAULT" and sector in text.lower():
            return sector
    return "DEFAULT"


def _format_usd(amount: float) -> str:
    if amount >= 1_000_000:
        return f"${amount/1_000_000:.2f}M"
    elif amount >= 1_000:
        return f"${amount/1_000:.1f}K"
    return f"${amount:.0f}"


# ──────────────────────────────────────────────────────────────────────────────
# FINANCIAL IMPACT QUANTIFIER
# ──────────────────────────────────────────────────────────────────────────────
class FinancialImpactQuantifier:
    """
    Converts CVE + exploit scores into USD financial impact estimates.
    Uses ALE (Annualized Loss Exposure) = SLE × ARO model.
    Fully explainable — no black box outputs.
    """

    def quantify(self, advisories: List[Dict]) -> Dict:
        scored = []
        total_potential_loss = 0.0
        critical_count = 0

        for adv in advisories:
            cve = adv.get("cve_id", "")
            if not cve or not cve.startswith("CVE-"):
                continue

            # Base CVSS
            cvss = float(adv.get("cvss") or adv.get("risk_score") or 5.0)
            cvss = min(10.0, max(0.0, cvss))

            # Sector
            text = " ".join([adv.get("title", ""), adv.get("summary", "")])
            sector = _sector_from_text(text)
            baseline = SECTOR_BREACH_COSTS[sector]

            # Exploit multiplier
            exploit_status = adv.get("ei_exploit_status", "UNKNOWN")
            exp_mult = EXPLOIT_MULTIPLIERS.get(exploit_status, 1.0)

            # KEV boost
            kev_mult = 1.4 if (adv.get("kev_confirmed") or adv.get("ei_kev_confirmed")) else 1.0

            # EPSS-based ARO (Annual Rate of Occurrence)
            epss = float(adv.get("epss") or adv.get("ei_epss") or 0.05)
            aro = min(2.0, max(0.01, epss * 3.0))  # Max 2x per year

            # Single Loss Expectancy
            cvss_mult = _get_cvss_multiplier(cvss)
            sle = baseline * cvss_mult * exp_mult * kev_mult

            # Annualized Loss Expectancy
            ale = sle * aro

            # Confidence in estimate (explainable)
            confidence_factors = []
            if cvss > 0: confidence_factors.append("CVSS present")
            if exploit_status != "UNKNOWN": confidence_factors.append(f"exploit={exploit_status}")
            if epss > 0.05: confidence_factors.append(f"EPSS={epss:.3f}")
            if adv.get("ei_kev_confirmed"): confidence_factors.append("KEV confirmed")

            severity_tier = (
                "CATASTROPHIC"  if ale >= 5_000_000 else
                "CRITICAL"      if ale >= 1_000_000 else
                "HIGH"          if ale >= 250_000  else
                "MEDIUM"        if ale >= 50_000   else
                "LOW"
            )

            if severity_tier in ("CATASTROPHIC", "CRITICAL"):
                critical_count += 1

            total_potential_loss += ale

            scored.append({
                "cve_id": cve,
                "cvss": cvss,
                "sector": sector,
                "exploit_status": exploit_status,
                "kev_confirmed": bool(adv.get("ei_kev_confirmed") or adv.get("kev_confirmed")),
                "epss": round(epss, 4),
                "annual_rate_of_occurrence": round(aro, 4),
                "single_loss_expectancy_usd": round(sle, 2),
                "annualized_loss_expectancy_usd": round(ale, 2),
                "ale_formatted": _format_usd(ale),
                "severity_tier": severity_tier,
                "confidence_factors": confidence_factors,
                "explanation": (
                    f"Sector {sector} baseline {_format_usd(baseline)} × "
                    f"CVSS mult {cvss_mult:.2f} × exploit {exp_mult:.1f} × "
                    f"KEV {kev_mult:.1f} × ARO {aro:.2f}/yr = "
                    f"ALE {_format_usd(ale)}"
                ),
            })

        # Sort by ALE descending
        scored.sort(key=lambda x: -x["annualized_loss_expectancy_usd"])

        return {
            "top_financial_risks": scored[:100],
            "total_cves_quantified": len(scored),
            "total_potential_loss_usd": round(total_potential_loss, 2),
            "total_potential_loss_formatted": _format_usd(total_potential_loss),
            "critical_risk_cve_count": critical_count,
            "severity_distribution": {
                tier: sum(1 for s in scored if s["severity_tier"] == tier)
                for tier in ["CATASTROPHIC", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# BRAND PROTECTION ENGINE
# ──────────────────────────────────────────────────────────────────────────────
class BrandProtectionEngine:
    """
    Detects phishing domains, brand impersonation, and BEC activity.
    Simulates takedown workflow (mock-safe).
    """

    def analyze(self, advisories: List[Dict]) -> Dict:
        phishing_threats = []
        impersonation_events = []
        takedown_queue = []
        domain_re = re.compile(r'\b([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,})\b')

        for adv in advisories:
            text_lower = " ".join([
                adv.get("title", ""), adv.get("summary", ""),
                adv.get("description", ""),
            ]).lower()

            # Phishing detection
            phish_hits = [ind for ind in PHISHING_INDICATORS if ind in text_lower]
            if phish_hits:
                conf = min(1.0, 0.35 + len(phish_hits) * 0.12)
                phishing_threats.append({
                    "advisory_id": adv.get("id", ""),
                    "cve_id": adv.get("cve_id", ""),
                    "title": adv.get("title", "")[:100],
                    "phishing_indicators": phish_hits[:5],
                    "confidence": round(conf, 4),
                    "severity": adv.get("severity", "MEDIUM"),
                })

                # High-confidence threats go to takedown queue
                if conf >= 0.65:
                    takedown_queue.append({
                        "threat_id": f"TD-{hashlib.md5(adv.get('id','unknown').encode()).hexdigest()[:8].upper()}",
                        "advisory_id": adv.get("id", ""),
                        "type": "PHISHING_INFRASTRUCTURE",
                        "confidence": round(conf, 4),
                        "status": "PENDING_REVIEW",
                        "workflow_stage": "1_IDENTIFICATION",
                        "workflow_steps": [
                            "1_IDENTIFICATION", "2_EVIDENCE_COLLECTION",
                            "3_REGISTRAR_CONTACT", "4_TAKEDOWN_REQUEST",
                            "5_VERIFICATION"
                        ],
                        "current_step": "1_IDENTIFICATION",
                        "execution_mode": "SIMULATION",
                    })

            # Brand impersonation
            brand_hits = [brand for brand in BRAND_IMPERSONATION_TARGETS if brand in text_lower]
            if brand_hits and any(ind in text_lower for ind in ["fake", "spoof", "impersonat",
                                                                   "phish", "clone", "lookalike"]):
                impersonation_events.append({
                    "advisory_id": adv.get("id", ""),
                    "title": adv.get("title", "")[:100],
                    "impersonated_brands": brand_hits[:5],
                    "severity": adv.get("severity", "MEDIUM"),
                    "confidence": min(1.0, 0.5 + len(brand_hits) * 0.1),
                })

        return {
            "phishing_threats": phishing_threats[:100],
            "total_phishing_threats": len(phishing_threats),
            "impersonation_events": impersonation_events[:50],
            "total_impersonation_events": len(impersonation_events),
            "takedown_queue": takedown_queue[:50],
            "takedown_queue_size": len(takedown_queue),
            "brand_risk_level": (
                "CRITICAL" if len(phishing_threats) >= 20 else
                "HIGH" if len(phishing_threats) >= 10 else
                "MEDIUM" if len(phishing_threats) >= 3 else "LOW"
            ),
        }


# ──────────────────────────────────────────────────────────────────────────────
# RISK QUANTIFICATION ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────
class RiskQuantificationEngine:
    def __init__(self):
        self.financial = FinancialImpactQuantifier()
        self.brand = BrandProtectionEngine()

    def run(self) -> int:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        logger.info("=== RISK QUANTIFICATION ENGINE START ===")

        advisories = _load_manifest()
        if not advisories:
            logger.warning("No advisories — writing empty outputs")
            self._write_empty()
            return 0

        logger.info(f"Quantifying risk for {len(advisories)} advisories")

        fin_result = self.financial.quantify(advisories)
        logger.info(f"CVEs quantified: {fin_result['total_cves_quantified']}")
        logger.info(f"Total potential loss: {fin_result['total_potential_loss_formatted']}")

        brand_result = self.brand.analyze(advisories)
        logger.info(f"Phishing threats: {brand_result['total_phishing_threats']}")
        logger.info(f"Takedown queue: {brand_result['takedown_queue_size']}")

        # Risk tier summary
        tiers = fin_result["severity_distribution"]
        risk_tiers = {
            "tier_summary": tiers,
            "tier_details": {
                "CATASTROPHIC": {"range": "≥$5M ALE", "count": tiers.get("CATASTROPHIC", 0)},
                "CRITICAL":     {"range": "$1M-$5M ALE", "count": tiers.get("CRITICAL", 0)},
                "HIGH":         {"range": "$250K-$1M ALE", "count": tiers.get("HIGH", 0)},
                "MEDIUM":       {"range": "$50K-$250K ALE", "count": tiers.get("MEDIUM", 0)},
                "LOW":          {"range": "<$50K ALE", "count": tiers.get("LOW", 0)},
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Portfolio risk summary
        portfolio = {
            "total_potential_loss_usd": fin_result["total_potential_loss_usd"],
            "total_potential_loss_formatted": fin_result["total_potential_loss_formatted"],
            "critical_cves": fin_result["critical_risk_cve_count"],
            "brand_risk_level": brand_result["brand_risk_level"],
            "phishing_threats": brand_result["total_phishing_threats"],
            "takedown_queue": brand_result["takedown_queue_size"],
            "top_3_risks": [
                {
                    "cve": r["cve_id"],
                    "ale": r["ale_formatted"],
                    "tier": r["severity_tier"],
                    "explanation": r["explanation"],
                }
                for r in fin_result["top_financial_risks"][:3]
            ],
            "regulatory_exposure": REGULATORY_MAXIMA,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Atomic writes
        _atomic_write(FINANCIAL_IMPACT, {
            **fin_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(BRAND_PROTECTION, {
            **brand_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
        _atomic_write(RISK_TIERS, risk_tiers)
        _atomic_write(PORTFOLIO_RISK, portfolio)

        meta = {
            "engine": "RiskQuantificationEngine",
            "version": "1.0.0",
            "advisories_processed": len(advisories),
            "cves_quantified": fin_result["total_cves_quantified"],
            "total_potential_loss_usd": fin_result["total_potential_loss_usd"],
            "critical_risk_cves": fin_result["critical_risk_cve_count"],
            "phishing_threats": brand_result["total_phishing_threats"],
            "takedown_queue_size": brand_result["takedown_queue_size"],
            "brand_risk_level": brand_result["brand_risk_level"],
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(ENGINE_META, meta)

        logger.info(f"Portfolio risk: {fin_result['total_potential_loss_formatted']}")
        logger.info(f"Brand risk: {brand_result['brand_risk_level']}")
        logger.info("=== RISK QUANTIFICATION ENGINE COMPLETE ===")
        return 0

    def _write_empty(self) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        for path in [FINANCIAL_IMPACT, BRAND_PROTECTION, RISK_TIERS, PORTFOLIO_RISK]:
            _atomic_write(path, {"generated_at": ts})
        _atomic_write(ENGINE_META, {
            "engine": "RiskQuantificationEngine", "version": "1.0.0",
            "advisories_processed": 0, "run_timestamp": ts,
        })


def main() -> int:
    try:
        engine = RiskQuantificationEngine()
        return engine.run()
    except Exception as e:
        logger.error(f"RiskQuantificationEngine fatal: {e}", exc_info=True)
        try:
            _atomic_write(ENGINE_META, {
                "engine": "RiskQuantificationEngine", "version": "1.0.0",
                "error": str(e)[:500],
                "run_timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass
        return 0  # Never fail pipeline


if __name__ == "__main__":
    sys.exit(main())
