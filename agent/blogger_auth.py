#!/usr/bin/env python3
"""
blogger_auth.py — CyberDudeBivash v7.2.1
Final Production Version: Corrected OAuth2 Refresh Flow.
"""
import os
import logging
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

logger = logging.getLogger("CDB-AUTH")

def get_blogger_credentials():
    """Maps GitHub Secrets to Google Credentials with explicit refresh."""
    # Terms aligned with repository secrets
    rt = os.environ.get('REFRESH_TOKEN')
    cid = os.environ.get('CLIENT_ID')
    cs = os.environ.get('CLIENT_SECRET')

    if rt and cid and cs:
        logger.info("✓ Mapped Environment Secrets detected.")
        creds = Credentials(
            token=None,  # Access token will be generated on refresh
            refresh_token=rt,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=cid,
            client_secret=cs,
        )
        
        # Mandatory refresh for stateless environments
        try:
            creds.refresh(Request())
            return creds
        except Exception as e:
            logger.error(f"OAuth Refresh Failure: {e}")
            raise

    logger.critical("✖ CRITICAL: Missing REFRESH_TOKEN, CLIENT_ID, or CLIENT_SECRET.")
    raise ValueError("Missing Blogger OAuth secrets: REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET.")

def get_blogger_service():
    """Initializes the Blogger V3 API Service."""
    creds = get_blogger_credentials()
    return build('blogger', 'v3', credentials=creds)
