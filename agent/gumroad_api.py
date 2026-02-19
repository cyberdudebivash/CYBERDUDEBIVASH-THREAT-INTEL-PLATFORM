#!/usr/bin/env python3
"""
gumroad_api.py — CyberDudeBivash v16.4
Automated Monetization Engine for Sentinel APEX
"""

import os
import requests
import logging

logger = logging.getLogger("CDB-GUMROAD")

def create_intel_product(title, description="Defense Kit", price_usd=99.0):
    """
    Creates a new digital product on Gumroad for the detected threat.
   
    """
    access_token = os.getenv("GUMROAD_ACCESS_TOKEN")
    if not access_token:
        logger.warning("⚠️ GUMROAD_ACCESS_TOKEN not set. Skipping monetization.")
        return None

    url = "https://api.gumroad.com/v2/products"
    payload = {
        "name": title,
        "description": description,
        "price": int(price_usd * 100), # Gumroad expects price in cents
        "currency": "usd"
    }
    
    try:
        response = requests.post(url, data=payload, params={"access_token": access_token})
        if response.status_code == 201:
            product_url = response.json().get('product', {}).get('short_url')
            logger.info(f"✅ GUMROAD PRODUCT CREATED: {product_url}")
            return product_url
        else:
            logger.error(f"❌ GUMROAD FAILURE: {response.text}")
            return None
    except Exception as e:
        logger.error(f"✗ GUMROAD API SYSTEM ERROR: {e}")
        return None
