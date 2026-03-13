#!/usr/bin/env python3
"""
license_validator.py — CYBERDUDEBIVASH® SENTINEL APEX v44.0
ZERO-TRUST LICENSE INTERCEPTOR
Founder & CEO — CyberDudeBivash Pvt. Ltd.
"""

import json
import os
from datetime import datetime

class CDBLicenseValidator:
    def __init__(self):
        self.tenant_store = "data/sovereign/tenants.json"
        self._initialize_registry()

    def _initialize_registry(self):
        os.makedirs("data/sovereign", exist_ok=True)
        if not os.path.exists(self.tenant_store):
            # Default Enterprise Beta Key for initial deployment
            initial_data = {
                "CDB-ENT-2026-ALPHA": {
                    "tier": "enterprise",
                    "status": "active",
                    "expires": "2027-01-01T00:00:00",
                    "owner": "Bivash"
                }
            }
            with open(self.tenant_store, "w") as f:
                json.dump(initial_data, f, indent=4)

    def is_valid(self, api_key: str) -> bool:
        """Validates API Key against the Sovereign Registry."""
        if not api_key:
            return False
        try:
            with open(self.tenant_store, "r") as f:
                tenants = json.load(f)
                if api_key in tenants:
                    t = tenants[api_key]
                    expiry = datetime.fromisoformat(t["expires"])
                    return t["status"] == "active" and datetime.now() < expiry
        except Exception:
            return False
        return False

# Global instance for API Middleware
LICENSE_VALIDATOR = CDBLicenseValidator()