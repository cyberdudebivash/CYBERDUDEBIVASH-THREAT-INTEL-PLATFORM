#!/usr/bin/env python3
"""
enterprise_firehose.py — CyberDudeBivash v30.0 (APEX WEBSOCKET FIREHOSE)
Author: CYBERGOD / TECH GOD
Description: Ultra-low latency WebSocket server for Enterprise clients. 
             Streams STIX 2.1 JSON payloads in real-time as they are created.
Compliance: 0 REGRESSION. Runs as a parallel microservice. 
"""

import os
import json
import time
import glob
import asyncio
import logging
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
import jwt
import uvicorn

# Safely import your existing configuration
from agent.config import CDB_JWT_SECRET, MANIFEST_DIR

logging.basicConfig(level=logging.INFO, format="[APEX-FIREHOSE] %(asctime)s - %(message)s")
logger = logging.getLogger("CDB-Firehose")

app = FastAPI(
    title="CyberDudeBivash APEX Enterprise Firehose",
    description="Real-time Zero-Day Telemetry Streaming",
    version="30.0.0"
)

class EnterpriseConnectionManager:
    """Manages active WebSocket connections for Enterprise clients."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New Enterprise Client Connected. Total Active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"Enterprise Client Disconnected. Total Active: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Pushes the payload to all connected clients simultaneously."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to client: {e}")

manager = EnterpriseConnectionManager()

def verify_enterprise_token(token: str) -> bool:
    """Validates the JWT to ensure ONLY paying Enterprise clients get access."""
    try:
        payload = jwt.decode(token, CDB_JWT_SECRET, algorithms=["HS256"])
        if payload.get("tier") == "ENTERPRISE":
            return True
        return False
    except jwt.ExpiredSignatureError:
        logger.warning("Expired token attempted access.")
        return False
    except jwt.InvalidTokenError:
        logger.warning("Invalid token attempted access.")
        return False

@app.websocket("/api/v30/firehose")
async def stix_firehose(websocket: WebSocket, token: str = Query(None)):
    """
    The main WebSocket endpoint. 
    Connection Example: ws://api.cyberdudebivash.com/api/v30/firehose?token=YOUR_JWT
    """
    if not token or not verify_enterprise_token(token):
        await websocket.close(code=1008) # Policy Violation
        logger.warning("Connection rejected: Invalid or missing Enterprise Token.")
        return

    await manager.connect(websocket)
    
    # Send an initial connection success payload
    await websocket.send_json({
        "status": "connected",
        "message": "CYBERDUDEBIVASH APEX Firehose Active. Awaiting intelligence...",
        "tier": "ENTERPRISE"
    })

    try:
        # Keep the connection alive
        while True:
            # We use a ping-pong to keep the socket from dropping
            await websocket.receive_text() 
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def watch_stix_directory():
    """
    Autonomous Background Task: Watches data/stix/ for new files.
    When the Dark Swarm or Legacy Scraper generates a new file, it instantly broadcasts it.
    """
    logger.info(f"Sovereign File Watcher initialized on directory: {MANIFEST_DIR}")
    os.makedirs(MANIFEST_DIR, exist_ok=True)
    
    # Store the latest modification time we've seen
    last_mod_time = time.time()

    while True:
        try:
            # Scan for the newest JSON file in the STIX directory
            list_of_files = glob.glob(f"{MANIFEST_DIR}/*.json")
            list_of_files = [f for f in list_of_files if not f.endswith("feed_manifest.json")]

            if list_of_files:
                latest_file = max(list_of_files, key=os.path.getmtime)
                file_mod_time = os.path.getmtime(latest_file)

                # If the file is newer than our last check, broadcast it!
                if file_mod_time > last_mod_time:
                    logger.info(f"New STIX Intelligence Detected: {latest_file}. Broadcasting to Enterprise Grid!")
                    with open(latest_file, 'r') as f:
                        payload = json.load(f)
                    
                    # Wrap the raw STIX in our APEX envelope
                    broadcast_payload = {
                        "event_type": "NEW_THREAT_INTEL",
                        "timestamp": file_mod_time,
                        "source": "CDB-APEX-CORTEX",
                        "stix_bundle": payload
                    }
                    
                    await manager.broadcast(broadcast_payload)
                    last_mod_time = file_mod_time

        except Exception as e:
            logger.error(f"Error in directory watcher: {e}")

        # Polling interval: 1 second (Ultra-low latency)
        await asyncio.sleep(1)


@app.on_event("startup")
async def startup_event():
    """Ignite the background directory watcher when the server starts."""
    asyncio.create_task(watch_stix_directory())

if __name__ == "__main__":
    logger.info("Igniting APEX Enterprise Firehose on Port 8001...")
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")