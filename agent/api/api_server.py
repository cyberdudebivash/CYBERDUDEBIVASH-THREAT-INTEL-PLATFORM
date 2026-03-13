#!/usr/bin/env python3
"""
api_server.py — CYBERDUDEBIVASH® SENTINEL APEX v46.0
UNIFIED ORCHESTRATION HUB (COMMUNITY + ENTERPRISE + VAULT)
Founder & CEO — CyberDudeBivash Pvt. Ltd.
"""

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from agent.api import public_api, premium_api
from agent.config import VERSION, AUTHORITY, API_HOST, API_PORT
import os
import json

app = FastAPI(
    title="CYBERDUDEBIVASH® SENTINEL APEX",
    description="Global Cybersecurity Tools, Threat Intelligence & AI Security Platform",
    version=VERSION
)

# CORS Policy for Global Dashboard Access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. COMMUNITY LAYER (Stable - v43)
app.include_router(public_api.router)

# 2. SaaS REVENUE & PRODUCT LAYER (v44 - v45)
app.include_router(premium_api.router)

# 3. v46.0 VAULT MIDDLEWARE (Additive)
@app.get("/v1/premium/vault/session-key", tags=["Vault Protocol"])
async def get_vault_session_key(x_api_key: str = Header(None)):
    """Provides decryption keys for secure fulfillment (Internal v46 logic)."""
    # Verification happens via verify_premium_tier in premium_api
    from agent.subscription_manager import SUBSCRIPTION_CORE
    if not SUBSCRIPTION_CORE.is_active(x_api_key):
        raise HTTPException(status_code=403, detail="CDB: Enterprise Access Required")
    
    # Fetch key from vault_manifest (Secured logic)
    manifest_path = "data/vault/vault_manifest.json"
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
            return {"key": manifest.get(x_api_key, {}).get("key")}
    
    raise HTTPException(status_code=404, detail="No active delivery sessions.")

@app.on_event("startup")
async def startup_event():
    print(f"🚀 CDB SENTINEL APEX v{VERSION}: ONLINE")
    print(f"🔒 DELIVERY VAULT: ACTIVE")
    print(f"💼 REVENUE ENGINE: MONITORING MRR")
    print(f"Authority: {AUTHORITY}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)