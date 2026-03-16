"""
CYBERDUDEBIVASH® SENTINEL APEX — Quality Gate Audit v1.0
Path: agent/quality_gate_audit.py
Feature: Identifies Premium-Grade Intel & Maps Remediation Assets
"""

import json
import os
import logging
from datetime import datetime, timezone

# Configure Technical Logging
logger = logging.getLogger("CDB-QUALITY-GATE")

class QualityGateAudit:
    def __init__(self):
        self.manifest_path = "data/stix/feed_manifest.json"
        self.remediation_path = "data/remediation"
        self.premium_threshold = 0.75  # 75th percentile for exploit probability
        self.audit_report_path = "data/sovereign/quality_audit_report.json"

    def run_audit(self):
        """Analyzes manifest for licensing-ready high-yield intelligence."""
        logger.info("============================================================")
        logger.info("SENTINEL APEX — QUALITY GATE AUDIT START")
        logger.info("============================================================")

        if not os.path.exists(self.manifest_path):
            logger.error("Manifest not found. Audit aborted.")
            return

        with open(self.manifest_path, "r") as f:
            items = json.load(f)

        premium_items = []
        for item in items:
            # Extract scores
            epss = item.get("epss_score", 0)
            cvss = item.get("cvss_score", 0)
            cve_id = item.get("id", "N/A")
            
            # --- PATCH: Premium Licensing Logic ---
            # Criteria: High Exploit Probability OR Critical Severity
            if epss >= self.premium_threshold or cvss >= 9.0:
                asset_name = f"cdb_patch_{cve_id.replace('-', '_')}.sh"
                has_remediation = os.path.exists(os.path.join(self.remediation_path, asset_name))
                
                premium_items.append({
                    "cve_id": cve_id,
                    "title": item.get("title"),
                    "epss": epss,
                    "cvss": cvss,
                    "is_kev": item.get("kev_present", False),
                    "remediation_ready": has_remediation,
                    "monetization_status": "READY" if has_remediation else "PENDING_PATCH"
                })
            # --- END PATCH ---

        # Finalize Audit Report
        audit_data = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_items_scanned": len(items),
            "premium_grade_count": len(premium_items),
            "remediation_coverage": f"{(len([i for i in premium_items if i['remediation_ready']]) / len(premium_items) * 100):.2f}%" if premium_items else "0%",
            "high_yield_assets": premium_items
        }

        os.makedirs(os.path.dirname(self.audit_report_path), exist_ok=True)
        with open(self.audit_report_path, "w") as f:
            json.dump(audit_data, f, indent=2)

        logger.info(f"Audit Complete: {len(premium_items)} Premium Items Identified.")
        logger.info(f"Report sharded to: {self.audit_report_path}")
        return audit_data

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    audit = QualityGateAudit()
    audit.run_audit()