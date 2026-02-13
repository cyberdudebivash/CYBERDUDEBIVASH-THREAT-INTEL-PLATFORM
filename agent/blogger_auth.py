"""
Centralized Blogger OAuth Authentication
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import os
import logging

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

logger = logging.getLogger("CDB-AUTH")


def get_blogger_credentials() -> Credentials:
    """
    Build OAuth2 credentials from environment variables.
    Required: REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET
    """
    refresh_token = os.getenv("REFRESH_TOKEN")
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")

    missing = [
        name for name, val in [
            ("REFRESH_TOKEN", refresh_token),
            ("CLIENT_ID", client_id),
            ("CLIENT_SECRET", client_secret),
        ] if not val
    ]

    if missing:
        raise ValueError(
            f"Missing Blogger OAuth secrets: {', '.join(missing)}. "
            "Set these as environment variables or GitHub Secrets."
        )

    creds = Credentials(
        None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=["https://www.googleapis.com/auth/blogger"],
    )
    creds.refresh(Request())
    logger.info("Blogger credentials refreshed successfully")
    return creds


def get_blogger_service():
    """Build authenticated Blogger API v3 service."""
    creds = get_blogger_credentials()
    service = build("blogger", "v3", credentials=creds, cache_discovery=False)
    logger.info("Blogger API service initialized")
    return service
