#!/usr/bin/env python3
"""
apex_purple_swarm.py — CyberDudeBivash v30.0 (APEX PURPLE SWARM)
Author: CYBERGOD / TECH GOD
Description: Autonomous Breach & Attack Simulation (BAS). Generates safe, 
             benign atomic test scripts based on live threat intel to 
             validate SIEM and SOAR defenses.
Compliance: 0 REGRESSION. Safe execution only. Generates harmless artifacts.
"""

import os
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="[APEX-PURPLE-SWARM] %(asctime)s - %(message)s")

class ApexPurpleSwarm:
    def __init__(self):
        self.manifest_path = "data/stix/feed_manifest.json"
        self.sim_dir = "data/simulations"
        os.makedirs(self.sim_dir, exist_ok=True)

    def generate_benign_simulation(self, threat: dict) -> tuple:
        """Generates a harmless Windows Batch script to trigger SIEM rules without real payload."""
        safe_title = "".join(x for x in threat.get('title', 'threat') if x.isalnum() or x in " -_").replace(" ", "_")[:30]
        iocs = threat.get("ioc_counts", {})
        
        # We extract an IP to simulate a benign connection attempt (or fallback to localhost)
        target_ip = iocs.get("ipv4", ["127.0.0.1"])[0] if iocs.get("ipv4") else "127.0.0.1"

        bat_content = f"""@echo off
:: ==============================================================================
:: CYBERDUDEBIVASH APEX PURPLE SWARM - AUTONOMOUS BAS
:: Target Threat: {threat.get('title', 'Unknown')}
:: Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC
:: WARNING: This is a SAFE simulation script. It contains NO malicious payload.
:: Usage: Run this in a sandbox to trigger the APEX Sigma/SOAR detections.
:: ==============================================================================

echo [APEX] Initiating safe behavioral simulation...

:: 1. Simulate C2 Beaconing (Benign Ping to trigger network telemetry)
echo [APEX] Simulating external connection to IOC...
ping {target_ip} -n 1 > nul

:: 2. Simulate File Drop (Benign text file creation)
echo [APEX] Dropping benign test artifact...
echo "CDB_APEX_BENIGN_TEST_STRING_MATCH_ME" > %TEMP%\\apex_test_artifact.txt

:: 3. Simulate Privilege Escalation attempt (Harmless whoami)
echo [APEX] Triggering simulated execution behavior...
whoami /priv > nul

echo [APEX] Simulation complete. 
echo [APEX] Check your Splunk/CrowdStrike dashboard. If APEX SOAR is active, this was detected.
pause
"""
        return safe_title, bat_content

    def execute_swarm(self):
        logging.info("Igniting APEX Purple Swarm BAS Engine...")
        
        if not os.path.exists(self.manifest_path):
            logging.warning("Feed manifest not found. Awaiting data ingestion...")
            return

        try:
            with open(self.manifest_path, 'r') as f:
                threats = json.load(f)
        except Exception as e:
            logging.error(f"Failed to read manifest: {e}")
            return

        sims_generated = 0
        for threat in threats[:3]:  # Generate simulations for the top 3 active threats
            title, script = self.generate_benign_simulation(threat)
            if script:
                file_path = os.path.join(self.sim_dir, f"apex_sim_{title}.bat")
                with open(file_path, 'w') as f:
                    f.write(script)
                sims_generated += 1
                logging.info(f"⚡ Forged Benign Attack Simulation: apex_sim_{title}.bat")

        logging.info(f"Purple Swarm cycle complete. Generated {sims_generated} safe simulations.")

if __name__ == "__main__":
    swarm = ApexPurpleSwarm()
    swarm.execute_swarm()