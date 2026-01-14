"""
Handles Gmail OAuth flow and returns an authorized googleapiclient service.
Requires credentials.json (OAuth client) placed in same directory.
Produces token.json after first successful run.
"""

import os
import logging

# Try to import Google API libraries, but don't fail if they're not installed
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False
    Request = Credentials = InstalledAppFlow = build = None

logger = logging.getLogger("auth_handler")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")
TOKEN_FILE = os.path.join(os.path.dirname(__file__), "token.json")


def get_gmail_service():
    """
    Returns an authorized googleapiclient discovery service for Gmail.
    The function performs an installed-app OAuth flow and caches token.json.
    If you want to run headless, set the environment variable 'OAUTHLIB_INSECURE_TRANSPORT=1'
    (only for local testing).
    """
    if not GOOGLE_LIBS_AVAILABLE:
        logger.error("Google API libraries not installed")
        raise ImportError("Google API libraries are required but not installed")
    
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                raise FileNotFoundError("credentials.json not found in project folder.")
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds, cache_discovery=False)
    logger.info("[AUTH] Gmail API service created successfully.")
    return service
