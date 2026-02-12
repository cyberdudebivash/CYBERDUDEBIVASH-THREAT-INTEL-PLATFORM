import os
import logging
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

logger = logging.getLogger('CYBERDUDEBIVASH_AUTH')

def get_blogger_credentials():
    refresh_token = os.getenv('REFRESH_TOKEN')
    client_id = os.getenv('CLIENT_ID')
    client_secret = os.getenv('CLIENT_SECRET')
    if not all([refresh_token, client_id, client_secret]):
        raise ValueError("Missing Blogger OAuth secrets")

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
