# agent/blogger_auth.py
# Centralized Blogger OAuth authentication – CYBERDUDEBIVASH Authority
# Copyright (c) 2026 CYBERDUDEBIVASH PVT LTD – All rights reserved.

import os
import logging
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

logger = logging.getLogger('CYBERDUDEBIVASH_AUTH')

def get_blogger_credentials():
    refresh_token = os.getenv('REFRESH_TOKEN')
    client_id = os.getenv('CLIENT_ID')
    client_secret = os.getenv('CLIENT_SECRET')
    if not all([refresh_token, client_id, client_secret]):
        raise ValueError("Missing Blogger OAuth secrets (REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET)")

    creds = Credentials(
        None,
        refresh_token=refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=client_id,
        client_secret=client_secret,
        scopes=['https://www.googleapis.com/auth/blogger']
    )
    creds.refresh(Request())
    logger.info("Blogger credentials refreshed successfully")
    return creds

def get_blogger_service():
    creds = get_blogger_credentials()
    service = build('blogger', 'v3', credentials=creds)
    logger.info("Blogger service built successfully")
    return service
