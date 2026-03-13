#!/usr/bin/env python3
"""
premium_api.py — CYBERDUDEBIVASH® SENTINEL APEX v45.0
PREMIUM PRODUCT DELIVERY MESH
Founder & CEO — CyberDudeBivash Pvt. Ltd.
"""

from fastapi import APIRouter, Header, HTTPException, Depends
from fastapi.responses import FileResponse
from typing import Optional, List, Dict
import os
import json
from agent.subscription_manager import SUBSCRIPTION_CORE
from agent.revenue_engine import REVENUE_CORE

router = APIRouter(prefix="/v1/premium", tags=["SaaS Product Factory"])

async def verify_premium_tier(x_api_key: Optional[str] = Header(None)):
    if not SUBSCRIPTION_CORE.is_active(x_api_key):
        raise HTTPException(status_code=403, detail="CYBERDUDEBIVASH: Active Enterprise License Required")
    return x_api_key

@router.get("/products/latest-detection-pack")
async def download_latest_detections(license: str = Depends(verify_premium_tier)):
    """Serves the latest automated ZIP bundle of Sigma/YARA rules."""
    product_dir = "data/products/detections"
    try:
        # Find latest ZIP in factory output
        files = [f for f in os.listdir(product_dir) if f.endswith('.zip')]
        if not files:
            raise HTTPException(status_code=404, detail="No detection packs available.")
        
        latest_pack = sorted(files)[-1]
        file_path = os.path.join(product_dir, latest_pack)
        
        # Log metered download: $49.00 per pack sync
        REVENUE_CORE.track_consumption(license, 1, 49.00, "DETECTION_PACK_DOWNLOAD")
        
        return FileResponse(path=file_path, filename=latest_pack, media_type='application/zip')
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/products/playbook/{threat_type}")
async def get_dynamic_playbook(threat_type: str, license: str = Depends(verify_premium_tier)):
    """Access to v45.0 Generated SOC Response Playbooks."""
    pb_file = f"data/products/playbooks/PB-{threat_type.upper()}-LAZARUS-VARIANT.json"
    if os.path.exists(pb_file):
        REVENUE_CORE.track_consumption(license, 1, 15.00, f"PLAYBOOK_ACCESS_{threat_type}")
        with open(pb_file, "r") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="Playbook for this threat type not yet generated.")