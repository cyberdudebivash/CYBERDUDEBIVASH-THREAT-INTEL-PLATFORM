from pathlib import Path
import os

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# =========================
# Path Configuration
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
CREDS_DIR = BASE_DIR / "credentials"

CREDENTIALS_FILE = CREDS_DIR / "credentials.json"
TOKEN_FILE = CREDS_DIR / "token.json"

SCOPES = ["https://www.googleapis.com/auth/blogger"]


# =========================
# Auth Logic
# =========================

def get_blogger_service():
    creds = None

    # =========================
    # CI / GitHub Actions Mode
    # =========================
    if os.getenv("GITHUB_ACTIONS") == "true":

        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        refresh_token = os.getenv("GOOGLE_REFRESH_TOKEN")

        if not client_id or not client_secret or not refresh_token:
            raise RuntimeError(
                "❌ Missing Google OAuth secrets. "
                "Ensure GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, "
                "and GOOGLE_REFRESH_TOKEN are set in GitHub Actions."
            )

        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
            scopes=SCOPES,
        )

        creds.refresh(Request())

    # =========================
    # Local / Dev Mode
    # =========================
    else:
        if TOKEN_FILE.exists():
            creds = Credentials.from_authorized_user_file(
                TOKEN_FILE, SCOPES
            )

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE,
                SCOPES
            )
            creds = flow.run_local_server(port=0)
            TOKEN_FILE.write_text(creds.to_json())

    service = build(
        "blogger",
        "v3",
        credentials=creds,
        cache_discovery=False
    )

    return service
