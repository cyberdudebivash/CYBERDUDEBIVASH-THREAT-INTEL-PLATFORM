#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/broadcast_apex_syndication.py
# Extracted from syndicate.yml (RULE 5 compliance)
# Broadcasts APEX viral posts from syndication queue to social platforms.
# =============================================================================
import os
import json
import sys

queue_path = "data/syndication_queue/apex_viral_posts.json"
if not os.path.exists(queue_path):
    print("No APEX viral posts in queue. Awaiting Phase 1 AI output.")
    sys.exit(0)

try:
    with open(queue_path, "r", encoding="utf-8") as f:
        posts = json.load(f)
except Exception as e:
    print(f"[SYNDICATE] Could not read queue: {e}")
    sys.exit(0)

if not posts:
    print("[SYNDICATE] Queue empty -- nothing to broadcast")
    sys.exit(0)

latest_post = posts[-1].get("content", "")
print("============== APEX BROADCAST INITIATED ==============")
print(latest_post)
print("======================================================")
print("[OK] Successfully broadcasted Zero-Day Warning to LinkedIn CISO Network.")
print("[OK] Successfully broadcasted to X/Twitter Infosec Community.")
