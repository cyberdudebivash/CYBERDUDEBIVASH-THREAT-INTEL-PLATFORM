import streamlit as st
from sentinel_blogger import fetch_latest_intel, generate_premium_report, publish_to_blogger, get_blogger_service

st.title("CYBERDUDEBIVASH Threat Intel Dashboard")

if st.button("Fetch Latest Intel"):
  intel = fetch_latest_intel()
  st.json(intel)

if st.button("Generate & Publish Report"):
  intel = fetch_latest_intel()
  if intel:
      title, content = generate_premium_report(intel)
      service = get_blogger_service()
      url = publish_to_blogger(title, content, service)
      st.success(f"Published: {url}")
  else:
      st.warning("No new intel to publish")
