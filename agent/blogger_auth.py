#!/usr/bin/env python3
"""
blogger_auth.py — CyberDudeBivash v7.2
Stateless OAuth2 Authentication for Google Blogger API.
"""
import os
import logging
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

logger = logging.getLogger("CDB-AUTH")

def get_blogger_credentials():
    """Retrieves credentials from Environment Secrets (Production) or local storage (Dev)."""
    # 1. Align with your GitHub Repository Secrets
    refresh_token = os.environ.get('REFRESH_TOKEN')
    client_id = os.environ.get('CLIENT_ID')
    client_secret = os.environ.get('CLIENT_SECRET')

    if refresh_token and client_id and client_secret:
        logger.info("✓ Utilizing GitHub Environment Secrets for Authentication.")
        creds = Credentials(
            None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
        )
        # Refresh the token to ensure validity
        if creds.expired:
            creds.refresh(Request())
        return creds
    
    # 2. Fallback to local credential files for development
    token_path = 'token.json'
    if os.path.exists(token_path):
        logger.info("✓ Utilizing local token.json for Authentication.")
        return Credentials.from_authorized_user_file(token_path)
    
    # 3. Critical Failure if no secrets are found
    raise ValueError("CRITICAL: Missing Blogger OAuth secrets: REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET.")

def get_blogger_service():
    """Initializes the Blogger V3 Service."""
    try:
        creds = get_blogger_credentials()
        return build('blogger', 'v3', credentials=creds)
    except Exception as e:
        logger.error(f"Failed to initialize Blogger Service: {e}")
        raise
