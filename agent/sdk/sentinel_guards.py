import functools
import asyncio
import httpx
import logging
from typing import Callable, Any

logger = logging.getLogger("CDB_LICENSE_GUARD")

def apex_license_guard(product_id: str):
    """
    Decorator: Gates functions behind a valid CyberDudeBivash Gumroad License.
    MANDATE: Non-blocking, 0 Regression, 2026-Tier Verification.
    """
    def decorator(func: Callable[..., Any]):
        @functools.wraps(func)
        async def async_wrapper(self, *args, **kwargs):
            # 1. Retrieve license from the Client instance
            license_key = getattr(self, 'license_key', None)
            
            if not license_key:
                raise PermissionError("Access Denied: No license key provided for APEX features.")

            # 2. Non-blocking verification against Gumroad API v2
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        "https://api.gumroad.com/v2/licenses/verify",
                        data={
                            "product_id": product_id,
                            "license_key": license_key,
                            "increment_uses_count": "false" # Heartbeat check only
                        },
                        timeout=5.0
                    )
                    data = response.json()
                    
                    if not data.get("success") or data.get("purchase", {}).get("refunded"):
                        logger.warning(f"Invalid license key attempt: {license_key}")
                        raise PermissionError("Access Denied: Invalid or expired Sentinel APEX license.")
                    
            except httpx.RequestError as exc:
                # 0 FAILURE FALLBACK: If Gumroad is down, we allow cached valid state 
                # to prevent breaking legitimate user workflows.
                logger.error(f"License server unreachable: {exc}. Using grace period.")
                if not getattr(self, 'is_authenticated', False):
                    raise ConnectionError("License server unreachable. Please check connection.")

            # 3. Success: Mark client as authenticated and execute elite feature
            self.is_authenticated = True
            return await func(self, *args, **kwargs)

        return async_wrapper
    return decorator