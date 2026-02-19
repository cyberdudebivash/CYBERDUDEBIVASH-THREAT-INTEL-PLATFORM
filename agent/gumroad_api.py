import os
import requests
import logging

logger = logging.getLogger("CDB-GUMROAD")

def create_intel_product(title, description="CyberDudeBivash Defense Kit", price_usd=99.0):
    access_token = os.getenv("GUMROAD_ACCESS_TOKEN")
    if not access_token:
        return None

    # v16.4 Update: Ensuring correct API structure
    url = "https://api.gumroad.com/v2/products/" # Trailing slash can be critical
    
    payload = {
        "name": f"🚨 {title}",
        "description": f"Verified Sovereign Intelligence. {description}",
        "price": int(price_usd * 100),
        "currency": "usd"
    }
    
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    try:
        # Use json=payload for modern API consistency
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 201 or response.status_code == 200:
            return response.json().get('product', {}).get('short_url')
        else:
            logger.error(f"❌ GUMROAD FAIL ({response.status_code}): {response.text}")
            return None
    except Exception as e:
        logger.error(f"✗ GUMROAD API ERROR: {e}")
        return None
