import os
import requests
import logging

logger = logging.getLogger("CDB-GUMROAD")

class GumroadClient:
    """
    CYBERDUDEBIVASH® GUMROAD ENGINE (v2.0)
    Automates product creation and authenticated file delivery.
    """
    def __init__(self, access_token=None):
        self.access_token = access_token or os.getenv("GUMROAD_ACCESS_TOKEN")
        self.base_url = "https://api.gumroad.com/v2"

    def create_product(self, name, price_usd, description, file_path):
        """Creates a product and uploads the signed security asset."""
        if not self.access_token:
            logger.error("Gumroad Access Token missing.")
            return None

        # Step 1: Create the Listing
        create_url = f"{self.base_url}/products"
        payload = {
            "access_token": self.access_token,
            "name": f"CDB-Asset: {name}",
            "price": int(price_usd * 100),
            "description": f"{description}\n\n© 2026 CYBERDUDEBIVASH PVT LTD",
            "published": True
        }

        try:
            response = requests.post(create_url, data=payload)
            if response.status_code not in [200, 201]:
                logger.error(f"Failed to create listing: {response.text}")
                return None

            product = response.json().get("product", {})
            product_id = product.get("id")
            
            # Step 2: Upload the Digital Asset
            upload_url = f"{self.base_url}/products/{product_id}/files"
            with open(file_path, 'rb') as f:
                files = {'file': f}
                upload_res = requests.post(
                    upload_url, 
                    data={"access_token": self.access_token}, 
                    files=files
                )
            
            if upload_res.status_code in [200, 201]:
                logger.info(f"✅ REVENUE LIVE: {product.get('short_url')}")
                return product.get("short_url")
            else:
                logger.error(f"Asset upload failed for {product_id}: {upload_res.text}")
                return None

        except Exception as e:
            logger.error(f"Gumroad Integration Error: {e}")
            return None

gumroad_engine = GumroadClient()
