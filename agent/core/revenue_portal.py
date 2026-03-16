"""
CYBERDUDEBIVASH® SENTINEL APEX — Revenue Dashboard v1.0
Path: agent/core/revenue_portal.py
Feature: Gumroad Sales Sync + EPSS Demand Correlation
"""

import os
import json
import requests
import logging
from datetime import datetime, timezone

logger = logging.getLogger("CDB-REVENUE-PORTAL")

class SovereignRevenueDashboard:
    def __init__(self):
        self.gumroad_token = os.getenv("GUMROAD_ACCESS_TOKEN")
        self.manifest_path = "data/stix/feed_manifest.json"
        self.output_report = "data/sovereign/revenue_intelligence.json"
        self.epss_api_url = "https://api.first.org/data/v1/epss"

    def fetch_gumroad_metrics(self):
        """Retrieves real-time sales and revenue from Gumroad API."""
        if not self.gumroad_token:
            return {"status": "ERROR", "msg": "Missing Token"}

        url = f"https://api.gumroad.com/v2/sales?access_token={self.gumroad_token}"
        try:
            response = requests.get(url)
            data = response.json()
            if data.get("success"):
                sales = data.get("sales", [])
                total_rev = sum(s.get("price", 0) for s in sales) / 100  # Cents to USD
                return {
                    "total_revenue_usd": total_rev,
                    "total_sales_count": len(sales),
                    "last_sale": sales[0].get("timestamp") if sales else "None"
                }
        except Exception as e:
            logger.error(f"Gumroad Sync Failed: {e}")
            return {"status": "ERROR"}

    def correlate_market_demand(self):
Correlates EPSS probability with current manifest items."""
        if not os.path.exists(self.manifest_path):
            return []

        with open(self.manifest_path, "r") as f:
            items = json.load(f)

        demand_matrix = []
        for item in items[:20]:  # Top 20 for real-time dashboard performance
            epss = float(item.get("epss_score", 0))
            # Flag "Money Gaps": High exploit risk but low market visibility
            demand_matrix.append({
                "cve_id": item.get("id"),
                "market_demand_pct": f"{epss * 100:.2f}%",
                "priority_level": "SOVEREIGN" if epss > 0.8 else "STABLE",
                "remediation_status": "READY" if item.get("kev_present") else "AUDIT_REQUIRED"
            })
        
        return demand_matrix

    def update_portal(self):
        """Generates the unified intelligence artifact for the dashboard."""
        logger.info("Syncing Sovereign Revenue Portal...")
        
        sales_data = self.fetch_gumroad_metrics()
        demand_data = self.correlate_market_demand()
        
        dashboard_state = {
            "authority": "CYBERDUDEBIVASH OFFICIAL AUTHORITY",
            "sync_time": datetime.now(timezone.utc).isoformat(),
            "financial_performance": sales_data,
            "threat_market_demand": demand_data,
            "system_status": "OPERATIONAL"
        }

        os.makedirs(os.path.dirname(self.output_report), exist_ok=True)
        with open(self.output_report, "w") as f:
            json.dump(dashboard_state, f, indent=4)
        
        logger.info(f"✓ Revenue Intelligence archived to {self.output_report}")
        return dashboard_state

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    portal = SovereignRevenueDashboard()
    portal.update_portal()