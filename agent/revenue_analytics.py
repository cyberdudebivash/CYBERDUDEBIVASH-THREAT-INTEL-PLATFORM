#!/usr/bin/env python3
"""
revenue_analytics.py — CYBERDUDEBIVASH® SENTINEL APEX v44.0
CEO REVENUE MONITORING
Founder & CEO — CyberDudeBivash Pvt. Ltd.
"""

import json
from typing import Dict, Any
from agent.revenue_engine import REVENUE_CORE

class CDBRevenueAnalytics:
    def get_ceo_briefing(self) -> Dict[str, Any]:
        """Aggregates platform performance for the Founder."""
        try:
            with open(REVENUE_CORE.log_file, "r") as f:
                data = json.load(f)
                transactions = data.get("transactions", [])
                
                briefing = {
                    "platform": "CYBERDUDEBIVASH® SENTINEL APEX",
                    "version": "44.0",
                    "total_mrr": data.get("total_revenue_usd", 0.0),
                    "transaction_count": len(transactions),
                    "latest_sale": transactions[-1] if transactions else None,
                    "top_monetized_feature": self._calculate_top_feature(transactions)
                }
                return briefing
        except Exception:
            return {"error": "Revenue stream not yet initialized."}

    def _calculate_top_feature(self, transactions):
        if not transactions: return "None"
        feature_map = {}
        for t in transactions:
            f = t["feature"]
            feature_map[f] = feature_map.get(f, 0) + t["amount"]
        return max(feature_map, key=feature_map.get)

# Global Analytics Instance
MONEY_ANALYTICS = CDBRevenueAnalytics()