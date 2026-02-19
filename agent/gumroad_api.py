import os
import logging

logger = logging.getLogger("CDB-GUMROAD")

def create_intel_product(title, description="Defense Kit", price_usd=99.0):
    """
    Gumroad API Limitation: Product creation is not supported via API.
    This function now acts as a placeholder to prevent pipeline crashes.
    """
    logger.warning(f"⚠️ GUMROAD: API does not support automated product creation. Skipping for: {title}")
    # Return None so the blogger script knows there is no product URL to inject.
    return None
