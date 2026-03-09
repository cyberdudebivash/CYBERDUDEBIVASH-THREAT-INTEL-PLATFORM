#!/usr/bin/env python3
"""
api_server.py — CYBERDUDEBIVASH® SENTINEL APEX v44.0
REVENUE-OPTIMIZED ORCHESTRATION HUB
Founder & CEO — CyberDudeBivash Pvt. Ltd.
"""

from fastapi import FastAPI
from agent.api import public_api, premium_api  # Additive import of Premium Mesh
from agent.config import VERSION, AUTHORITY

app = FastAPI(title="CYBERDUDEBIVASH® SENTINEL APEX")

# 1. COMMUNITY LAYER (Stable - v43 Genesis)
app.include_router(public_api.router)

# 2. SaaS REVENUE LAYER (New - v44 Money Engine)
app.include_router(premium_api.router)

@app.on_event("startup")
async def startup_event():
    print(f"🛰️ CDB SENTINEL APEX v{VERSION}: ONLINE")
    print(f"💰 MONEY ENGINE v44: ACTIVATED")
    print(f"Signature: {AUTHORITY}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)