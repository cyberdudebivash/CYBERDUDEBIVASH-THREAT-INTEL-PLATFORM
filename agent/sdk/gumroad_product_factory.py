#!/usr/bin/env python3
"""
gumroad_product_factory.py — CYBERDUDEBIVASH® SENTINEL APEX v30.0+
Production Factory for Automated Product Creation.

FIX: Corrects the "Product Creation Failure" by enforcing 
Bearer Token Auth and URL-Encoded Data Payloads.
"""

import httpx
import asyncio
import logging

# Production logger
logger = logging.getLogger("CDB_GUMROAD_FACTORY")

class GumroadProductFactory:
    def __init__(self, access_token: str):
        self.token = access_token
        self.api_url = "https://api.gumroad.com/v2/products"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

    async def create_sdk_product(self, name: str, price_usd: float, description: str):
        """
        Creates a new product in the CyberDudeBivash Gumroad Store.
        :param price_usd: Float (e.g., 499.00). Will be converted to cents for API.
        """
        payload = {
            "name": name,
            "price": int(price_usd * 100), # Gumroad API expects cents
            "description": description,
            "url": name.lower().replace(" ", "-"),
            "is_physical": "false",
            "published": "false" # Created as draft for CEO review
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.post(self.api_url, data=payload, headers=self.headers)
                
                if response.status_code == 201:
                    product_data = response.json()
                    p_id = product_data['product']['id']
                    logger.info(f"SUCCESS: Created product '{name}'. ID: {p_id}")
                    return p_id
                else:
                    logger.error(f"FAILURE: {response.status_code} - {response.text}")
                    return None
            except Exception as e:
                logger.error(f"Network Error during Gumroad product creation: {e}")
                return None

# CEO QUICK-START (Only run this once to create the product)
if __name__ == "__main__":
    TOKEN = "YOUR_GUMROAD_ACCESS_TOKEN" # Must have 'edit_products' scope
    factory = GumroadProductFactory(TOKEN)
    
    async def run():
        # Creating the flagship Enterprise SDK product
        await factory.create_sdk_product(
            name="Sentinel APEX Enterprise SDK",
            price_usd=499.00,
            description="Real-time predictive threat intelligence stream access for the CYBERDUDEBIVASH Ecosystem."
        )
    
    asyncio.run(run())