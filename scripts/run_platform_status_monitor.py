#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/run_platform_status_monitor.py
# Extracted from status-monitor.yml (RULE 5 compliance - no inline Python)
# Runs PlatformStatusMonitor or writes a fallback status file.
# =============================================================================
import sys
import os
import json
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.getcwd())

Path("data/status").mkdir(parents=True, exist_ok=True)

try:
    from agent.monitoring.status_page import PlatformStatusMonitor
    monitor = PlatformStatusMonitor()
    status = monitor.run()
    print(f"Platform: {status.get('status', 'UNKNOWN')}")
except Exception as e:
    print(f"Status monitor fallback: {e}")
    fallback = {
        "version": "101.0.0",
        "platform": "CYBERDUDEBIVASH SENTINEL APEX",
        "status": "MONITORING",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    tmp = "data/status/status.json.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(fallback, f, indent=2)
    os.replace(tmp, "data/status/status.json")
    print("Fallback status.json written.")
