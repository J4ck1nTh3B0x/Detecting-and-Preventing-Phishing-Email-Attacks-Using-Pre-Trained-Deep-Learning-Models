"""
User authentication module using Google Sign-In OAuth 2.0.
Handles user login/logout separate from Gmail API authentication.
"""

import os
import json
import logging
from functools import wraps
from flask import session, redirect, url_for, request
try:
    from google_auth_oauthlib.flow import Flow  # type: ignore[import-not-found]
    from google.oauth2.credentials import Credentials  # type: ignore[import-not-found]
    from google.auth.transport.requests import Request  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    Flow = None  # type: ignore[assignment]
    Credentials = None  # type: ignore[assignment]
    Request = None  # type: ignore[assignment]

logger = logging.getLogger("user_auth")

# OAuth 2.0 settings for user authentication
# These scopes are for user profile info AND Gmail access
USER_AUTH_SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.readonly'
]

# Path to OAuth credentials (can be same as Gmail credentials.json)
CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")

# Store user tokens (in production, consider using a database)
USER_TOKENS_DIR = os.path.join(os.path.dirname(__file__), "cache", "user_tokens")
os.makedirs(USER_TOKENS_DIR, exist_ok=True)

# This will be set by Flask app
_oauth_config = None
_redirect_uri = None


def init_oauth_config(client_secrets_file=None, redirect_uri=None):
    """
    Initialize OAuth configuration.
    Should be called once when Flask app starts.
    """
    global _oauth_config, _redirect_uri
    
    secrets_file = client_secrets_file or CREDENTIALS_FILE
    _redirect_uri = redirect_uri or "http://localhost:8080/auth/callback"
    
    if not os.path.exists(secrets_file):
        logger.warning(f"OAuth credentials file not found: {secrets_file}")
        logger.warning("User login will not work until credentials.json is configured.")
        return False
    
    try:
        with open(secrets_file, 'r') as f:
            client_config = json.load(f)
        
        # Support both web and installed app client types
        if 'web' in client_config:
            client_id = client_config['web']['client_id']
            client_secret = client_config['web']['client_secret']
            _oauth_config = {
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': _redirect_uri
            }
        elif 'installed' in client_config:
            # Fallback to installed app config (for development)
            client_id = client_config['installed']['client_id']
            client_secret = client_config['installed']['client_secret']
            _oauth_config = {
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': _redirect_uri
            }
        else:
            logger.error("Invalid credentials.json format. Expected 'web' or 'installed' key.")
            return False
        
        logger.info(f"OAuth configuration initialized successfully")
        logger.info(f"Redirect URI: {_redirect_uri}")
        logger.info(f"Make sure this exact URI is authorized in Google Cloud Console:")
        logger.info(f"  {_redirect_uri}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize OAuth config: {e}")
        return False


def get_authorization_url():
    """
    Generate the Google OAuth authorization URL for user login.
    Forces re-consent to ensure all required scopes are granted.
    """
    if not _oauth_config:
        raise RuntimeError("OAuth not initialized. Call init_oauth_config() first.")

    logger.info(f"Generating OAuth authorization URL with redirect URI: {_oauth_config['redirect_uri']}")
    logger.info(f"Requested scopes: {USER_AUTH_SCOPES}")

    if Flow is None:
        raise RuntimeError("Google auth libraries not available in this environment")

    flow = Flow.from_client_config(
        {
            'web': {
                'client_id': _oauth_config['client_id'],
                'client_secret': _oauth_config['client_secret'],
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [_oauth_config['redirect_uri']]
            }
        },
        scopes=USER_AUTH_SCOPES,
        redirect_uri=_oauth_config['redirect_uri']
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Always force consent to ensure all scopes are granted
    )

    return authorization_url, state


def get_user_info_from_code(code, state):
    """
    Exchange authorization code for user credentials and fetch user info.
    Returns (user_info_dict, credentials) or (None, None) on error.
    """
    if not _oauth_config:
        return None, None
    
    try:
        if Flow is None:
            raise RuntimeError("Google auth libraries not available in this environment")

        flow = Flow.from_client_config(
            {
                'web': {
                    'client_id': _oauth_config['client_id'],
                    'client_secret': _oauth_config['client_secret'],
                    'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                    'token_uri': 'https://oauth2.googleapis.com/token',
                    'redirect_uris': [_oauth_config['redirect_uri']]
                }
            },
            scopes=USER_AUTH_SCOPES,
            redirect_uri=_oauth_config['redirect_uri']
        )
        
        # Some Google OAuth setups may return additional scopes (e.g. gmail.readonly)
        # even if we requested only basic profile scopes.
        # oauthlib treats scope mismatches as exceptions. We temporarily patch
        # the validation to allow extra scopes.
        import oauthlib.oauth2.rfc6749.parameters as oauth_params  # type: ignore[import-not-found]

        # Store original function
        original_validate = oauth_params.validate_token_parameters

        # Create a patched version that ignores scope mismatches
        def patched_validate_token_parameters(params):
            # Remove scope validation by not checking granted vs requested scopes
            required_keys = ['access_token']
            missing = [key for key in required_keys if key not in params]
            if missing:
                raise ValueError(f'Missing required parameter(s): {missing}')

            # Don't validate scopes - just ensure access_token exists
            return params

        # Temporarily replace the validation function
        oauth_params.validate_token_parameters = patched_validate_token_parameters

        try:
            flow.fetch_token(code=code, include_client_id=True)
        finally:
            # Restore original function
            oauth_params.validate_token_parameters = original_validate

        credentials = flow.credentials
        
        # Fetch user info from Google
        import requests
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        
        if userinfo_response.status_code != 200:
            logger.error(f"Failed to fetch user info: {userinfo_response.status_code}")
            return None, None
        
        user_info = userinfo_response.json()
        
        # Store credentials for the user (for refresh token)
        user_email = user_info.get('email', 'unknown')
        token_file = os.path.join(USER_TOKENS_DIR, f"{user_email}.json")
        with open(token_file, 'w') as f:
            json.dump({
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': credentials.scopes
            }, f)
        
        return user_info, credentials
        
    except Exception as e:
        logger.exception(f"Error exchanging code for token: {e}")
        return None, None


def get_user_info_from_session():
    """
    Get user info from Flask session.
    Returns user_info dict or None if not logged in.
    """
    if 'user_email' in session and 'user_name' in session:
        return {
            'email': session.get('user_email'),
            'name': session.get('user_name'),
            'picture': session.get('user_picture')
        }
    return None


def is_logged_in():
    """
    Check if user is logged in.
    """
    return 'user_email' in session


def login_required(f):
    """
    Decorator to require user login for a route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def _cleanup_user_data(user_email):
    """
    Clean up all user data stored on the device.
    Removes OAuth tokens, preferences, sync state, and cached emails.
    """
    import shutil

    # 1. Remove user's OAuth token file
    token_file = os.path.join(USER_TOKENS_DIR, f"{user_email}.json")
    if os.path.exists(token_file):
        try:
            os.remove(token_file)
            logger.info(f"Removed OAuth token file for {user_email}")
        except Exception as e:
            logger.error(f"Failed to remove token file {token_file}: {e}")

    # 2. Remove user preferences
    prefs_file = os.path.join(os.path.dirname(__file__), "user_prefs.json")
    if os.path.exists(prefs_file):
        try:
            # Load existing prefs and remove user's entry
            with open(prefs_file, 'r', encoding='utf-8') as f:
                prefs = json.load(f)

            if user_email in prefs:
                del prefs[user_email]
                with open(prefs_file, 'w', encoding='utf-8') as f:
                    json.dump(prefs, f, indent=2, ensure_ascii=False)
                logger.info(f"Removed preferences for {user_email}")
        except Exception as e:
            logger.error(f"Failed to cleanup preferences for {user_email}: {e}")

    # 3. Remove user's sync state
    sync_state_file = os.path.join(os.path.dirname(__file__), "cache", "sync_state.json")
    if os.path.exists(sync_state_file):
        try:
            with open(sync_state_file, 'r') as f:
                all_states = json.load(f)

            if user_email in all_states:
                del all_states[user_email]
                with open(sync_state_file, 'w') as f:
                    json.dump(all_states, f, indent=2)
                logger.info(f"Removed sync state for {user_email}")
        except Exception as e:
            logger.error(f"Failed to cleanup sync state for {user_email}: {e}")

    # 4. Clear all cached emails and manual overrides
    # This is aggressive but ensures complete cleanup of user data
    try:
        # Import here to avoid circular imports
        import email_cache

        # Clear manual overrides table
        conn = email_cache.get_db()
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM email_overrides")
            cur.execute("DELETE FROM emails")
            conn.commit()
            logger.info("Cleared all cached emails and manual overrides")
        except Exception as e:
            logger.error(f"Failed to clear email cache: {e}")
        finally:
            conn.close()

        # Also remove any physical cache files that might exist
        cache_dirs = [
            os.path.join(os.path.dirname(__file__), "cache", "emails"),
            os.path.join(os.path.dirname(__file__), "cache", "threat_intel"),
        ]
        for cache_dir in cache_dirs:
            if os.path.exists(cache_dir):
                try:
                    shutil.rmtree(cache_dir)
                    logger.info(f"Removed cache directory: {cache_dir}")
                except Exception as e:
                    logger.error(f"Failed to remove cache directory {cache_dir}: {e}")

    except Exception as e:
        logger.error(f"Failed to clear email cache: {e}")


def logout_user():
    """
    Log out the current user by clearing session and cleaning all user data.
    """
    # Get user email before clearing session
    user_email = session.get('user_email')

    # Clear session first
    session.clear()
    logger.info("User session cleared")

    # Clean up all user data from device
    if user_email:
        try:
            _cleanup_user_data(user_email)
            logger.info(f"All user data cleaned for {user_email}")
        except Exception as e:
            logger.error(f"Failed to cleanup user data for {user_email}: {e}")
    else:
        logger.warning("No user email found in session during logout")
