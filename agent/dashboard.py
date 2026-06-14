"""
CDB-SENTINEL Threat Intelligence Dashboard v2.0
Streamlit-based operational dashboard for the CyberDudeBivash platform.
(C) 2026 CyberDudeBivash Pvt Ltd - All rights reserved.
"""

import streamlit as st
import json
import logging
import os

st.set_page_config(
    page_title="CDB-SENTINEL Dashboard",
    page_icon="?",
    layout="wide",
)

st.title("? CDB-SENTINEL Threat Intelligence Dashboard")
st.caption("CyberDudeBivash Pvt. Ltd. - Automated Threat Intel Platform")

st.divider()

col1, col2, col3 = st.columns(3)

# State file stats
state_file = "data/blogger_processed.json"
processed_count = 0
if os.path.exists(state_file):
    try:
        file_size = os.path.getsize(state_file)
        if file_size > 50 * 1024 * 1024:  # 50 MB guard — prevent UI stall on oversized state
            logging.warning("dashboard: state file too large (%d bytes), skipping load", file_size)
        else:
            with open(state_file, "r") as f:
                data = json.load(f)
                processed_count = len(data) if isinstance(data, list) else 0
    except Exception as e:
        logging.warning("dashboard: could not read state file %s: %s", state_file, e)

col1.metric("Processed Items", processed_count)
col2.metric("Intel Sources", "8 RSS Feeds")
col3.metric("Pipeline Status", "Active ?")

st.divider()

st.subheader("Quick Actions")

if st.button("? Fetch Latest Intel", use_container_width=True):
    with st.spinner("Fetching from global threat feeds..."):
        try:
            from agent.sentinel_blogger import fetch_latest_intel
            intel = fetch_latest_intel()
            st.success(f"Fetched {len(intel)} new intel items")
            if intel:
                st.json(intel[:3])
        except Exception as e:
            st.error(f"Error: {e}")

if st.button("? Generate & Publish Report", use_container_width=True):
    with st.spinner("Generating premium threat report..."):
        try:
            from agent.sentinel_blogger import fetch_latest_intel, generate_premium_report, publish_to_blogger
            from agent.blogger_auth import get_blogger_service

            intel = fetch_latest_intel()
            if intel:
                title, content = generate_premium_report(intel)
                service = get_blogger_service()
                url = publish_to_blogger(title, content, service)
                st.success(f"? Published: {url}")
            else:
                st.warning("No new intel to publish")
        except Exception as e:
            st.error(f"Error: {e}")

st.divider()
st.caption("(C) 2026 CyberDudeBivash Pvt. Ltd. - Bhubaneswar, India")
