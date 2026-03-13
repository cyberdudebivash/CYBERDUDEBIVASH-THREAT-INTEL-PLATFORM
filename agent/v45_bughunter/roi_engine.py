"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — ROI & Risk Exposure Calculator
======================================================================
Automates financial risk quantification using industry breach cost models.
Calculates Annualized Loss Exposure (ALE) and platform ROSI.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import logging
from typing import Dict, List

logger = logging.getLogger("CDB-BH-ROI")


class ROIEngine:
    """Quantifies financial impact of discovered vulnerabilities."""

    # 2025-2026 industry benchmarks
    IMPACT_MATRIX = {
        "BOLA": 250_000,
        "CLOUD_LEAK": 500_000,
        "SUBDOMAIN_TAKEOVER": 150_000,
        "OPEN_PORT": 25_000,
        "SECRET_LEAK": 350_000,
        "CLOUD_ENUM": 10_000,
    }

    SEVERITY_MULTIPLIER = {
        "CRITICAL": 2.5,
        "HIGH": 1.5,
        "MEDIUM": 1.0,
        "LOW": 0.5,
        "INFO": 0.1,
    }

    MITIGATION_RATE = 0.95  # CDB mitigates 95% of identified risk
    AVG_SUBSCRIPTION_COST = 50_000  # Annual platform cost baseline

    def calculate_exposure(self, findings: List[Dict]) -> Dict:
        """
        Calculate total risk exposure and ROI metrics.
        
        Formula:
          SLE = base_impact × severity_multiplier
          ALE = Σ(SLE) × ARO (assumed 1.0 per year for critical)
          ROSI = (mitigated_loss / subscription_cost) × 100
        """
        total_sle = 0.0
        by_type: Dict[str, float] = {}

        for f in findings:
            f_type = f.get("type", "").upper()
            severity = f.get("severity", "MEDIUM").upper()

            base = self.IMPACT_MATRIX.get(f_type, 50_000)
            multiplier = self.SEVERITY_MULTIPLIER.get(severity, 1.0)
            sle = base * multiplier

            total_sle += sle
            by_type[f_type] = by_type.get(f_type, 0) + sle

        mitigated = total_sle * self.MITIGATION_RATE
        rosi = (mitigated / self.AVG_SUBSCRIPTION_COST) * 100 if mitigated > 0 else 0

        return {
            "total_risk_exposure": round(total_sle, 2),
            "mitigated_value": round(mitigated, 2),
            "rosi_percentage": round(rosi, 1),
            "finding_count": len(findings),
            "exposure_by_type": {k: round(v, 2) for k, v in by_type.items()},
        }

    def format_executive_summary(self, findings: List[Dict]) -> str:
        """Generate human-readable financial summary for reports."""
        data = self.calculate_exposure(findings)
        return (
            f"CyberDudeBivash Financial Intelligence\n"
            f"{'='*42}\n"
            f"Estimated Risk Exposure: ${data['total_risk_exposure']:,.2f}\n"
            f"Mitigated Value (CDB):   ${data['mitigated_value']:,.2f}\n"
            f"Platform ROSI:           {data['rosi_percentage']:.1f}%\n"
            f"Findings Analyzed:       {data['finding_count']}\n"
        )
