"""
Configuration and constants for heuristics module.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Heuristics configuration
HOMOGRAPH_SIMILARITY_THRESHOLD = float(os.getenv("HOMOGRAPH_SIMILARITY_THRESHOLD", "0.80"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "5.0"))
STRICT_MODEL_ONLY_ENV = os.getenv("STRICT_MODEL_ONLY", "false").lower() in ("true", "1", "yes")

# Logging configuration
logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'heuristics': {
            'handlers': ['default'],
            'level': 'INFO',
            'propagate': True
        }
    }
}
