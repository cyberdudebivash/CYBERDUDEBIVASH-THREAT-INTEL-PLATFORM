#!/usr/bin/env python3
"""
config.py — CyberDudeBivash v7.4.1
Global Configuration for the Sentinel APEX Engine.
"""
import os

# --- Blogger Configuration ---
# Prioritizes Environment Secret, falls back to static ID
BLOG_ID = os.environ.get('BLOG_ID', '8435132226685160824') 

# --- Forensic Persistence ---
STATE_FILE = "data/blogger_processed.json" # Verified Repo Path
MAX_STATE_SIZE = 500
MAX_PER_FEED = 5

# --- Intelligence Sources ---
RSS_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://threatpost.com/feed/",
    "https://darkreading.com/rss.xml"
]

# --- Orchestration Settings ---
PUBLISH_RETRY_MAX = 3
PUBLISH_RETRY_DELAY = 10 # Seconds
