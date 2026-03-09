#!/usr/bin/env python3
"""
gumroad_handler.py — CYBERDUDEBIVASH® SENTINEL APEX v44.0
GUMROAD PURCHASE FULFILLMENT & API PROVISIONING
Founder & CEO — CyberDudeBivash Pvt. Ltd.

This module automates the bridge between a Gumroad sale and the 
Sentinel APEX Enterprise SaaS environment.
"""

import json
import os
import httpx
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from agent.subscription_manager import SUBSCRIPTION_CORE

class GumroadFulfillment:
    def __init__(self):
        self.access_token = os.getenv("GUMROAD_ACCESS_TOKEN")
        self.authority = "CYBERDUDEBIVASH OFFICIAL"

    async def process_purchase(self, payload: Dict[str, Any]) -> Optional[str]:
        """
        Processes a Gumroad Webhook Payload.
        1. Verifies the license_key with Gumroad API.
        2. Provisions a Sentinel APEX API Key via subscription_manager.
        3. Returns the Provisioned Key for customer onboarding.
        """
        license_key = payload.get("license_key")
        product_id = payload.get("product_id")
        buyer_email = payload.get("email")
        buyer_name = payload.get("full_name", "Enterprise Client")

        if not license_key:
            logging.error("Fulfillment Error: No Gumroad license key found in payload.")
            return None

        # Verify with Gumroad API
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://api.gumroad.com/v2/licenses/verify",
                    data={
                        "product_id": product_id,
                        "license_key": license_key
                    }
                )
                verification = response.json()
                
                if verification.get("success"):
                    # Provision Sentinel APEX Enterprise Key
                    new_api_key = SUBSCRIPTION_CORE.provision_tenant(
                        name=buyer_name, 
                        tier="enterprise"
                    )
                    
                    logging.info(f"Fulfillment Success: Provisioned {new_api_key} for {buyer_email}")
                    return new_api_key
                else:
                    logging.warning(f"Fulfillment Declined: Invalid Gumroad key {license_key}")
                    return None
            except Exception as e:
                logging.error(f"Fulfillment API Error: {str(e)}")
                return None

# Global Instance
FULFILLMENT_HANDLER = GumroadFulfillment()