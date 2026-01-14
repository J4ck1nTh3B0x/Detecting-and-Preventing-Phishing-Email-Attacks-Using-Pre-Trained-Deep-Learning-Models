"""
Configuration settings for the phishing email detection system.
"""
import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).parent.absolute()

# Model paths
MODEL_DIR = BASE_DIR / "phishing_mail_detect_model"
MODEL_PATH = MODEL_DIR / "pytorch_model.bin"
CONFIG_PATH = MODEL_DIR / "config.json"
TOKENIZER_PATH = MODEL_DIR / "tokenizer.json"

# Cache directories
CACHE_DIR = BASE_DIR / "cache"
EMAIL_CACHE_DIR = CACHE_DIR / "emails"
THREAT_INTEL_CACHE = CACHE_DIR / "threat_intel.json"

# Ensure required directories exist
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(EMAIL_CACHE_DIR, exist_ok=True)

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout',
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': CACHE_DIR / 'app.log',
            'maxBytes': 10 * 1024 * 1024,  # 10MB
            'backupCount': 5,
            'formatter': 'standard',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True
        },
        'app': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False
        },
        'background_sync': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False
        },
        'phishing_detector': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False
        },
    }
}

# Email processing settings
MAX_EMAIL_SIZE = 25 * 1024 * 1024  # 25MB
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB

# Security settings
ALLOWED_FILE_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
    'zip', 'rar', '7z', 'gz', 'tar'
}

# Heuristics settings
HOMOGRAPH_SIMILARITY_THRESHOLD = float(os.getenv('HOMOGRAPH_SIMILARITY_THRESHOLD', '0.80'))
REQUEST_TIMEOUT = float(os.getenv('REQUEST_TIMEOUT', '5.0'))
STRICT_MODEL_ONLY_ENV = os.getenv('STRICT_MODEL_ONLY', 'false').lower() in ('true', '1', 'yes')

# Web server settings
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', '8080'))
DEBUG = os.getenv('DEBUG', 'false').lower() in ('true', '1', 'yes')

# Gmail API settings
GMAIL_CREDENTIALS_FILE = os.getenv('GMAIL_CREDENTIALS_FILE', 'credentials.json')
GMAIL_TOKEN_FILE = os.getenv('GMAIL_TOKEN_FILE', 'token.json')
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# User Authentication OAuth settings
OAUTH_CREDENTIALS_FILE = os.getenv('OAUTH_CREDENTIALS_FILE', 'credentials.json')  # Can be same as Gmail credentials
OAUTH_REDIRECT_URI = os.getenv('OAUTH_REDIRECT_URI', None)  # Auto-detected if not set
USER_AUTH_SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

# Update model path in trainer state if it exists
try:
    trainer_state_path = MODEL_DIR / 'trainer_state.json'
    if trainer_state_path.exists():
        import json
        with open(trainer_state_path, 'r+', encoding='utf-8') as f:
            state = json.load(f)
            if 'best_model_checkpoint' in state:
                # Update only the parent directory, keep the checkpoint name
                checkpoint_name = os.path.basename(state['best_model_checkpoint'])
                state['best_model_checkpoint'] = str(MODEL_DIR / checkpoint_name)
                f.seek(0)
                json.dump(state, f, indent=2)
                f.truncate()
except Exception as e:
    import logging
    logging.getLogger(__name__).warning(f"Could not update trainer state: {e}")

# Export commonly used paths and settings
__all__ = [
    'BASE_DIR', 'MODEL_DIR', 'CACHE_DIR', 'EMAIL_CACHE_DIR', 'THREAT_INTEL_CACHE',
    'LOGGING', 'MAX_EMAIL_SIZE', 'MAX_ATTACHMENT_SIZE', 'ALLOWED_FILE_EXTENSIONS',
    'HOMOGRAPH_SIMILARITY_THRESHOLD', 'REQUEST_TIMEOUT', 'STRICT_MODEL_ONLY_ENV',
    'HOST', 'PORT', 'DEBUG', 'GMAIL_CREDENTIALS_FILE', 'GMAIL_TOKEN_FILE', 'GMAIL_SCOPES'
]
