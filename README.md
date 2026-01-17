# Gmail Phishing Detection System - Complete Setup Guide

A comprehensive Flask-based web application that connects to Gmail via OAuth2, analyzes emails for phishing attempts using machine learning models, and provides a clean inbox-style interface to review messages, attachments, and security signals.

## What You Need Before Starting

### Required Software & Accounts

1. **Python 3.11+** (Python 3.11+ recommended)
2. **Git** for cloning the repository
3. **Google Cloud Console Account** (free) - for Gmail API access
4. **Stable internet connection** for API calls and email syncing
5. **4GB+ RAM** (8GB+ recommended for large email volumes)
6. **1GB+ free disk space** for email cache and models

### Required Files (Download Separately)

The application requires several pre-trained model files that must be downloaded separately:

1. **ML Model Files** (`phishing_mail_detect_model/` directory):
   - `config.json`
   - `model.safetensors` OR `pytorch_model.bin`
   - `tokenizer.json` OR `tokenizer_config.json`
   - `vocab.txt`
   - `special_tokens_map.json`

2. **Brand Database** (`brands.json`):
   - Local brand/domain lookup database

3. **Intelligence Feeds** (optional but recommended):
   - VirusTotal API key (free tier available)
   - Google Safe Browsing API key (free)

## Step-by-Step Setup Instructions

### Step 1: Download and Install Python Dependencies

```bash
# Clone the repository
git clone <repository-url>
cd gmail-phishing-detection

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install all required packages
pip install -r requirements.txt

# Verify installation
python -c "import flask, transformers, googleapiclient, torch; print('Core dependencies installed')"
```

**Expected output:** `Core dependencies installed`

If you get import errors, check your Python version:
```bash
python --version  # Should be 3.11 or higher
```

### Step 2: Set Up Google Cloud Console (Critical - Required)

#### 2.1 Create Google Cloud Project

1. Go to [https://console.cloud.google.com/](https://console.cloud.google.com/)
2. Click **CREATE PROJECT**
3. Enter project name: `Gmail Phishing Detector`
4. Wait for project creation (may take a few minutes)

#### 2.2 Enable Gmail API

1. In the left sidebar, go to **APIs & Services** → **Library**
2. Search for "Gmail API"
3. Click on **Gmail API** in the results
4. Click **ENABLE**

#### 2.3 Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **+ CREATE CREDENTIALS** → **OAuth 2.0 Client IDs**
3. Choose **Web application** as application type
4. Name: `Gmail Phishing Detector Web App`
5. **Authorized redirect URIs** - Add these EXACT URIs:
   ```
   http://localhost:8080/auth/callback
   http://127.0.0.1:8080/auth/callback
   ```
   WARNING: These URIs must match exactly, including the port number

6. Click **CREATE**
7. **Download the JSON file** and save it as `credentials.json` in your project root directory

#### 2.4 Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Choose **External** user type
3. Fill in app information:
   - **App name**: `Gmail Phishing Detector`
   - **User support email**: your email address
   - **Developer contact information**: your email address
4. Add scopes (these should auto-populate):
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/userinfo.profile`
5. Add your email as a test user if prompted
6. Click **SAVE AND CONTINUE** through all screens

### Step 3: Download Required Model Files

The application requires pre-trained machine learning models. You need to obtain these files:

#### Option A: Download from Official Source (Recommended)
```bash
# Check if model directory exists
ls -la phishing_mail_detect_model/

# If missing, create directory and download files
mkdir -p phishing_mail_detect_model
# Download model files from your model repository/hosting service
# (You'll need to provide the actual download URLs)
```

#### Option B: Use Included Models (If Available)
```bash
# Check what model files are already present
ls -la phishing_mail_detect_model/
ls -la final_model/
```

**Required Model Files:**
- `phishing_mail_detect_model/config.json`
- `phishing_mail_detect_model/model.safetensors` OR `pytorch_model.bin`
- `phishing_mail_detect_model/tokenizer.json` OR `tokenizer_config.json`
- `phishing_mail_detect_model/vocab.txt`
- `phishing_mail_detect_model/special_tokens_map.json`

**Verify model files:**
```bash
python -c "
from pathlib import Path
model_dir = Path('phishing_mail_detect_model')
required = ['config.json', 'vocab.txt']
optional = ['model.safetensors', 'pytorch_model.bin', 'tokenizer.json', 'tokenizer_config.json']

print('Checking model files...')
for file in required:
    if (model_dir / file).exists():
        print(f'[OK] {file} - Found')
    else:
        print(f'[MISSING] {file} - MISSING (Required)')

for file in optional:
    if (model_dir / file).exists():
        print(f'[OK] {file} - Found')
    else:
        print(f'[WARNING] {file} - Missing (Optional)')
"
```

### Step 4: Configure Environment Variables

```bash
# Copy the sample environment file
cp .env.sample .env

# Edit the .env file with your settings
# Use any text editor (notepad, nano, vim, etc.)
```

**Essential .env Configuration:**

```env
# === BASIC SETTINGS (Required) ===
FLASK_ENV=development
PYTHONUNBUFFERED=1

# === GOOGLE OAUTH (Required for login) ===
OAUTHLIB_INSECURE_TRANSPORT=1

# === APPLICATION SECURITY (Generate secure random keys) ===
APP_SECRET_KEY=your_secure_random_string_here_generate_new_one
FLASK_SECRET_KEY=your_secure_random_string_here_generate_new_one

# === SYNC SETTINGS ===
SYNC_INTERVAL=300
SYNC_MAX_FETCH_RESULTS=-1
SYNC_PARALLELISM=4

# === OPTIONAL: Threat Intelligence APIs ===
# VIRUSTOTAL_API_KEY=your_virustotal_api_key
# GOOGLE_SAFEBROWSING_API_KEY=your_safebrowsing_api_key

# === UI SETTINGS ===
HIDE_PHISH_MAYBE_PHISH_INBOX=false
SHOW_PHISH_WARNING=true
ALLOW_DISMISS_PHISH_WARNING=false
```

**Generate secure random keys:**
```bash
# Linux/Mac:
python -c "import secrets; print(secrets.token_hex(32))"

# Windows PowerShell:
python -c "import secrets; print(secrets.token_hex(32))"
```

### Step 5: Set Up Brand Database (Optional but Recommended)

```bash
# Check if brands.json exists
ls -la brands.json

# If missing, create a basic one or download from your source
# The app will work without this but brand detection will be limited
```

### Step 6: Initialize Database

```bash
# The database will auto-create on first run, but you can pre-initialize it
python -c "from email_cache import init_db; init_db(); print('Database initialized')"

# Verify database creation
ls -la emails.db

# Check database contents (after first run)
python check_db.py
```

### Step 7: Test the Application Startup

```bash
# Test that all imports work
python -c "
try:
    from app import app
    from phishing_detector import PhishingDetector
    from email_cache import init_db
    from user_auth import init_oauth_config
    print('All core modules imported successfully')
except Exception as e:
    print(f'Import error: {e}')
"

# Test model loading
python -c "
try:
    from phishing_detector import PhishingDetector
    detector = PhishingDetector()
    detector.load_model('./phishing_mail_detect_model')
    print('ML model loaded successfully')
except Exception as e:
    print(f'Model loading error: {e}')
"
```

### Step 8: Start the Application

```bash
# Start the Flask application
python app.py
```

**Expected output:**
```
INFO: Starting app...
INFO: Application services initialized successfully
INFO: OAuth configuration initialized successfully
INFO: Redirect URI: http://localhost:8080/auth/callback
INFO: [SYNC] Continuous sync thread started...
INFO:  * Running on http://0.0.0.0:8080/
```

### Step 9: First Login and Setup

1. **Open your browser** to `http://localhost:8080`
2. **Click "Sign in with Google"**
3. **Grant permissions** when prompted:
   - Read access to your Gmail messages
   - Access to your basic profile information
4. **Wait for initial sync** - this may take several minutes for large inboxes
5. **Review your emails** in the inbox interface

### Step 10: Verify Everything Works

```bash
# Check that emails are being processed
python check_db.py

# View application logs
tail -f cache/app.log

# Test API endpoints
curl http://localhost:8080/api/health
```

## Troubleshooting Common Issues

### "redirect_uri_mismatch" Error

**Problem:** OAuth redirect URI doesn't match Google Cloud Console settings

**Solutions:**
1. Verify exact URIs in Google Cloud Console:
   - `http://localhost:8080/auth/callback`
   - `http://127.0.0.1:8080/auth/callback`
2. Clear browser cache and cookies
3. Restart the application
4. Check that `OAUTHLIB_INSECURE_TRANSPORT=1` is set in `.env`

### "credentials.json not found" Error

**Problem:** OAuth credentials file is missing or in wrong location

**Solutions:**
1. Verify `credentials.json` exists in project root
2. Check file permissions: `ls -la credentials.json`
3. Download fresh credentials from Google Cloud Console

### "Model loading failed" Error

**Problem:** Machine learning model files are missing or corrupted

**Solutions:**
1. Verify all required model files exist:
   ```bash
   ls -la phishing_mail_detect_model/
   ```
2. Check file sizes (should not be empty)
3. Try alternative model location if available

### Database Errors

**Problem:** SQLite database issues

**Solutions:**
1. Delete corrupted database: `rm emails.db`
2. Reinitialize: `python -c "from email_cache import init_db; init_db()"`
3. Check disk space: `df -h`
4. Check file permissions on project directory

### Sync Not Working

**Problem:** Emails not syncing from Gmail

**Solutions:**
1. Verify Gmail API is enabled in Google Cloud Console
2. Check OAuth scopes include Gmail readonly access
3. Review application logs: `tail -f cache/app.log`
4. Test Gmail API manually:
   ```bash
   python -c "
   from gmail_utils import get_service
   service = get_service()
   if service:
       print('Gmail API connection successful')
   else:
       print('Gmail API connection failed')
   "
   ```

### Import Errors

**Problem:** Python modules not installing correctly

**Solutions:**
1. Verify Python version: `python --version`
2. Reinstall requirements: `pip install -r requirements.txt --force-reinstall`
3. Check virtual environment: `which python`
4. Update pip: `pip install --upgrade pip`

### Memory Errors

**Problem:** Application crashes with memory issues

**Solutions:**
1. Reduce sync parallelism: Set `SYNC_PARALLELISM=2` in `.env`
2. Increase system memory or use smaller batch sizes
3. Monitor memory usage: `python -c "import psutil; print(f'Memory: {psutil.virtual_memory().percent}%')"`

## Testing Your Setup

### Run Test Scripts

```bash
# Test database functionality
python tests/test_db.py

# Test cache operations
python tests/test_cache.py

# Test environment variables
python tests/test_env_check.py

# Test full sync process (use with caution)
python tests/test_full_sync.py
```

### Manual Verification Steps

1. **Check application startup logs** for any warnings/errors
2. **Verify database creation** with `python check_db.py`
3. **Test OAuth flow** by attempting login
4. **Monitor sync progress** in application logs
5. **Verify email processing** by checking processed email count

## Updating the Application

When updating to new versions:

```bash
# Backup your configuration
cp .env .env.backup
cp emails.db emails_backup.db

# Pull latest changes
git pull

# Update dependencies
pip install -r requirements.txt

# Check for database migrations
python -c "from email_cache import init_db; init_db()"

# Restart application
python app.py
```

## Getting Help

If you encounter issues not covered here:

1. **Check the application logs**: `tail -f cache/app.log`
2. **Run diagnostic scripts**: `python check_db.py`
3. **Verify your configuration**: Compare `.env` with `.env.sample`
4. **Test individual components** using the test scripts in `tests/`
5. **Check GitHub issues** for similar problems

## Success Checklist

- [ ] Python 3.11+ installed and virtual environment created
- [ ] All dependencies installed from `requirements.txt`
- [ ] Google Cloud Console project created and Gmail API enabled
- [ ] OAuth 2.0 credentials downloaded as `credentials.json`
- [ ] Redirect URIs configured exactly in Google Cloud Console
- [ ] Environment variables configured in `.env` file
- [ ] ML model files downloaded to `phishing_mail_detect_model/`
- [ ] Database initialized successfully
- [ ] Application starts without errors on `http://localhost:8080`
- [ ] OAuth login flow works correctly
- [ ] Email sync begins automatically after login
- [ ] Emails appear in the web interface with analysis results

## Detailed Setup Guide

### System Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python**: 3.11+ (3.11+ recommended)
- **Memory**: 4GB+ RAM (8GB+ recommended for large email volumes)
- **Storage**: 1GB+ free space for email cache and models
- **Network**: Stable internet connection for Gmail API and threat intelligence

### Python Environment Setup

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import flask, transformers, googleapiclient; print('All dependencies installed successfully')"
```

### Google Cloud Console Configuration

#### Step-by-Step OAuth Setup

1. **Create Project**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Click **CREATE PROJECT**
   - Enter project name (e.g., "Gmail Phishing Detector")
   - Wait for project creation

2. **Enable Gmail API**:
   - In the left sidebar, go to **APIs & Services** → **Library**
   - Search for "Gmail API"
   - Click on **Gmail API**
   - Click **ENABLE**

3. **Create OAuth Credentials**:
   - Go to **APIs & Services** → **Credentials**
   - Click **+ CREATE CREDENTIALS** → **OAuth 2.0 Client IDs**
   - Choose **Web application**
   - Name: "Gmail Phishing Detector"
   - Authorized redirect URIs:
     - `http://localhost:8080/auth/callback` (development)
     - `https://yourdomain.com/auth/callback` (production)
   - Click **CREATE**
   - Download the JSON file and save as `credentials.json` in project root

4. **Configure OAuth Consent Screen**:
   - Go to **APIs & Services** → **OAuth consent screen**
   - Choose **External** user type
   - Fill in app information:
     - App name: "Gmail Phishing Detector"
     - User support email: your email
     - Developer contact: your email
   - Add scopes:
     - `https://www.googleapis.com/auth/gmail.readonly`
     - `https://www.googleapis.com/auth/userinfo.email`
     - `https://www.googleapis.com/auth/userinfo.profile`
   - Add test users if needed

### Environment Configuration

#### Required Environment Variables

```env
# OAuth Configuration
OAUTHLIB_INSECURE_TRANSPORT=1  # Remove in production

# Application Security
APP_SECRET_KEY=your_secure_random_string_here
FLASK_ENV=development

# Sync Settings
SYNC_INTERVAL=300  # Seconds between sync operations
SYNC_MAX_FETCH_RESULTS=-1  # -1 = fetch all, or set limit
```

#### Optional Environment Variables

```env
# Threat Intelligence
VIRUSTOTAL_API_KEY=your_api_key
GOOGLE_SAFEBROWSING_API_KEY=your_api_key

# UI Customization
SHOW_LINK_TABLE=true
HIDE_PHISH_MAYBE_PHISH_INBOX=false
SHOW_PHISH_WARNING=true
ALLOW_DISMISS_PHISH_WARNING=false

# Performance Tuning
SYNC_PARALLELISM=4
REQUEST_TIMEOUT=5.0
HOMOGRAPH_SIMILARITY_THRESHOLD=0.80
```

### Database Setup

The application uses SQLite for email caching. The database is automatically created on first run, but you can manually initialize it:

```bash
# Initialize database
python -c "from email_cache import init_db; init_db()"

# Check database creation
ls -la emails.db
```

### Model Setup

The phishing detection uses a fine-tuned transformer model. Ensure the model directory contains:

```
phishing_mail_detect_model/
├── config.json
├── model.safetensors
├── tokenizer.json
├── tokenizer_config.json
├── vocab.txt
└── special_tokens_map.json
```

If the model files are missing, the application will fall back to heuristic-based detection only.

### Running the Application

#### Development Mode

```bash
# Basic startup
python app.py

# With custom host/port
HOST=0.0.0.0 PORT=8080 python app.py

# Debug mode
DEBUG=true python app.py
```

#### Production Deployment

For production deployment, consider:

1. **Use a production WSGI server**:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8080 app:app
   ```

2. **Set production environment**:
   ```env
   FLASK_ENV=production
   OAUTHLIB_INSECURE_TRANSPORT=0  # Remove this line
   APP_SECRET_KEY=generate_a_secure_random_key
   ```

3. **Configure HTTPS** and update OAuth redirect URIs accordingly

### Troubleshooting

#### Common Issues

**"redirect_uri_mismatch" Error**
- Ensure the exact redirect URI is added in Google Cloud Console
- Check for trailing slashes and correct protocol (http/https)

**"credentials.json not found"**
- Verify the file exists in the project root
- Check file permissions

**Model Loading Errors**
- Ensure all model files are present in `phishing_mail_detect_model/`
- Check available disk space and memory

**Database Errors**
- Delete `emails.db` and restart (will rebuild cache)
- Check file permissions on the database file

**Sync Not Working**
- Verify Gmail API is enabled in Google Cloud Console
- Check OAuth scopes include Gmail read access
- Review application logs for detailed error messages

#### Logs and Debugging

```bash
# View application logs
tail -f cache/app.log

# Enable debug logging
echo "LOG_LEVEL=DEBUG" >> .env

# Check database integrity
python check_db.py
```

### API Keys and External Services

#### VirusTotal Integration (Optional)

1. Sign up at [VirusTotal](https://virustotal.com)
2. Get your free API key
3. Add to `.env`:
   ```env
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

#### Google Safe Browsing (Optional)

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Enable Safe Browsing API
3. Create API key
4. Add to `.env`:
   ```env
   GOOGLE_SAFEBROWSING_API_KEY=your_api_key_here
   ```

### Backup and Data Management

```bash
# Backup user data
cp emails.db emails_backup.db
cp user_prefs.json user_prefs_backup.json

# Clear all cached data (logout required)
rm -rf cache/emails/
rm emails.db
```

## Usage Guide

Once running, access the web interface at `http://localhost:8080`:

1. **Login** with your Google account
2. **Filter** by safety status (Safe, Phish, Maybe Phish, Unknown)
3. **Search** emails by content
4. **Inspect** individual emails for detailed analysis
5. **Override** classifications manually if needed

## Architecture Overview

## Core Python Modules

- **app.py**
  - Creates the Flask app, configures security headers and Jinja filters.
  - Initializes cache directories and the SQLite email cache via `email_cache.init_db`.
  - Loads the phishing detection model (`PhishingDetector`) and starts `background_sync.start_continuous_sync()`.
  - Implements all main routes:
    - `GET /` inbox with pagination, search (`q`), and label filters (`safe`, `phish`, `maybephish`, `unknown`).
    - `GET /message/<msg_id>` full message details (HTML/text bodies, model prediction, explanation, SPF/DKIM/DMARC, threat‑intel, attachment analysis).
    - `GET /email_html/<msg_id>`, `/raw/<msg_id>`, `/render/<msg_id>`, `/original/<msg_id>`, `/render_body/<msg_id>` for different raw/rendered views.
    - `GET /download/<msg_id>`, `/download_attachment/<msg_id>/<attachment_id>`, `/preview_attachment/<msg_id>/<attachment_id>` for exporting and previewing.
    - API endpoints: `/api/sync_status`, `/api/force_sync`, `/api/health`, `/api/rescan/<msg_id>`, `/api/override_label/<msg_id>`, `/api/clear_override/<msg_id>`, `/api/live_status`, `/api/inbox_data`, `/api/get_theme`, `/api/set_theme`.
  - Manages per-user theme via cookies/session and exposes `theme` into all templates.
  - Adds CSP and security headers for safer rendering of email content and previews.

- **config.py**
  - Central configuration: base paths, model paths, cache directories.
  - Logging configuration dictionary used by multiple modules.
  - Size limits (`MAX_EMAIL_SIZE`, `MAX_ATTACHMENT_SIZE`), allowed file extensions.
  - Timeouts and thresholds (homograph similarity, HTTP request timeout, `STRICT_MODEL_ONLY_ENV`).
  - Web server host/port/debug flags and Gmail credential filenames/scopes.

- **gmail_utils.py**
  - Wraps Gmail API through `auth_handler.get_gmail_service()`.
  - Implements client‑side rate limiting and exponential backoff for API calls.
  - Extracts URLs from plain text and HTML, normalizes and de‑obfuscates them.
  - Cleans HTML to model‑friendly text (`clean_html_for_text`).
  - Parses MIME messages into text and HTML bodies, keeping inline images available for rendering.
  - `fetch_all_messages()` uses parallel workers to download emails, parse bodies, extract links, and collect basic attachment metadata.
  - Provides helpers for decoding Gmail base64 and fetching attachment bytes.

- **phishing_detector.py**
  - Defines the `PhishingDetector` class using HuggingFace transformers and PyTorch.
  - Loads a local fine‑tuned classification model from `./phishing_mail_detect_model`.
  - Uses sliding‑window inference for long texts and aggregates per‑chunk phishing probabilities.
  - Applies post‑processing thresholds to produce `safe`, `maybephish`, or `phish` labels, plus a natural‑language explanation.

- **background_sync.py**
  - Runs a continuous sync loop in a background thread.
  - Uses `gmail_utils.fetch_all_messages()` to retrieve messages, then processes each one with `process_single_email`.
  - `process_single_email` combines:
    - Model prediction (`PhishingDetector`).
    - Heuristics (`heuristics.analyze_email_links_and_content` and `heuristics.score_heuristics`).
    - Authentication checks (`auth_checks.verify_message_auth` for SPF/DKIM/DMARC).
    - Threat intelligence enrichment (`threat_intel.intel_enrich`).
  - Writes unified results into the SQLite cache via `email_cache.cache_email`.
  - Maintains `sync_status` for `/api/sync_status` and drives optional local re‑evaluation of cached messages.

- **email_cache.py** (not shown here but used everywhere)
  - Manages the SQLite database of emails and overrides.
  - Typical responsibilities (from usage): initializing DB, caching/updating emails, fetching paginated inbox data, retrieving raw bodies and HTML, tracking manual overrides, and global counters.

- **file_analyzer.py**
  - Analyzes attachment bytes for risky extensions, mismatched file signatures, and suspicious content patterns.
  - Uses python‑magic / signatures to infer MIME types and olefile to detect Office macros.
  - Exposes `analyze_attachments` for `app.py` to generate per‑attachment verdicts and risk scores.

- **threat_intel.py**
  - Provides URL threat‑intel enrichment (`intel_enrich`) and brand resolution (`resolve_brand`).
  - Uses a rate‑limited optional external brand‑resolve API and a local `intelligence` brand list/cache as fallback.
  - Caches results under `intelligence/cache/brand_resolve_cache.json` using `live_config` for automatic reloading.

- **heuristics.py**
  - Rule‑based scoring and link/content analysis used alongside the model.
  - Supplies helpers like `_get_whitelist_emails` and `analyze_email_links_and_content` to short‑circuit certain emails (e.g. whitelisted senders, empty messages).

- **auth_handler.py / auth_checks.py**
  - Handle Gmail OAuth2 flow and construction of an authenticated Gmail service.
  - Perform SPF/DKIM/DMARC checks for message authentication.

- **attachment_preview.py**
  - Renders previews for attachments via `/preview_attachment/...` using the same Gmail and cache utilities.

- **intelligence/**
  - `brandlist.py`, `heuristics/`, `feeds/`, `scheduler/`, `cache/`, `live_config.py` provide:
    - Brand, domain, and whois feeds.
    - Scheduled update scripts to refresh local threat‑intel data.
    - A small file‑watcher based config/cache system used by `threat_intel`.

## Frontend (templates + static)

- **templates/**
  - `layout.html` – base layout and shared Chrome.
  - `index.html` – inbox view with filters, stats, and pagination.
  - `message.html` – detailed email view including predictions, explanations, links, attachments, and analysis results.
  - `original.html`, `raw.html`, `render.html` – different views of raw/decoded/rendered email content.

- **static/style.css**
  - Global styling for the inbox, message view, and theme (light/dark) support.

- **static/js/**
  - `inbox.js` – inbox interactions, pagination, polling `/api/inbox_data` and `/api/live_status`.
  - `message.js` – message‑detail interactions, rescan actions, previews, and UI updates.
  - `safe_click.js` – safer link‑click handling.
  - `split_view.js` – split‑pane behavior for inbox/message layout.
  - `theme.js` – toggling and persisting theme via `/api/get_theme` and `/api/set_theme`.

## Setup and Running

- **Python**: 3.11 recommended.
- **Install dependencies** in this folder:

```bash
pip install -r requirements.txt
```

- **Gmail credentials**:
  - Create OAuth2 client in Google Cloud Console for the Gmail API.
  - Download credentials JSON and save it as `credentials.json` in this folder (or adjust `config.GMAIL_CREDENTIALS_FILE`).
  - First run of the app will perform OAuth and write `token.json`.

- **Model files**:
  - Place a fine‑tuned transformers classification model under `phishing_mail_detect_model/` (or adjust the path).
  - `PhishingDetector.load_model("./phishing_mail_detect_model")` loads this at startup; if it fails, code is designed to fall back to safer handling and/or heuristics.

- **Environment variables** (optional, via `.env` or OS env):
  - Web server: `HOST`, `PORT`, `DEBUG`.
  - Sync: `SYNC_INTERVAL`, `SYNC_MAX_FETCH_RESULTS`, `SYNC_PARALLELISM`, `LOCAL_RECHECK_INTERVAL`.
  - Threat‑intel: `BRAND_RESOLVE_API_URL`, `BRAND_RESOLVE_TIMEOUT`, `BRAND_RESOLVE_RETRIES`, `BRAND_RESOLVE_RATE_CAPACITY`, `BRAND_RESOLVE_RATE_PERIOD`, `BRAND_FUZZY_THRESHOLD`.
  - Analysis toggles: `STRICT_MODEL_ONLY`, `SHOW_LINK_TABLE`, `HIDE_PHISH_MAYBE_PHISH_INBOX`, `SHOW_PHISH_WARNING`, `ALLOW_DISMISS_PHISH_WARNING`.
  - VirusTotal (hash‑only lookups on attachments): `VT_API_KEY` or `VIRUSTOTAL_API_KEY`.

- **Run**:

```bash
python app.py
```

The app starts Flask on the configured host/port (default `0.0.0.0:8080`) and immediately starts background Gmail sync.

## Final Project Map

High‑level structure based on the actual files under this folder:

```text
GMAIL_THINGY_/
├── .env / .env.sample
├── .gitignore
├── __init__.py
├── app.py
├── app_state.json
├── all_imports.txt
├── attachment_preview.py
├── auth_checks.py
├── auth_handler.py
├── background_sync.py
├── brandlist.py
├── brands.json
├── cache/
│   └── emails/ (SQLite cache + JSON cache files, created at runtime)
├── client_secret.json (or credentials template)
├── config.py
├── cred.json / credentials.json / token.json
├── document_utils.py
├── email_cache.py
├── emails.db (SQLite database file, created at runtime)
├── file_analyzer.py
├── final_model/
├── gmail_utils.py
├── heuristics.py
├── intelligence/
│   ├── __init__.py
│   ├── brandlist.py
│   ├── cache/
│   │   ├── brands.json
│   │   ├── threat.json
│   │   └── whois.json
│   ├── feeds/
│   │   ├── update_brands.py
│   │   ├── update_threat_domains.py
│   │   └── update_whois.py
│   ├── heuristics/
│   │   └── (link/content heuristics modules)
│   ├── live_config.py
│   └── scheduler/
│       ├── run_all.py
│       └── (scheduling helpers)
├── phishing_detector.py
├── phishing_mail_detect_model/
│   └── (transformers model + tokenizer files)
├── README.md (this file)
├── settings.json
├── static/
│   ├── style.css
│   └── js/
│       ├── inbox.js
│       ├── message.js
│       ├── safe_click.js
│       ├── split_view.js
│       └── theme.js
├── templates/
│   ├── index.html
│   ├── layout.html
│   ├── message.html
│   ├── original.html
│   ├── raw.html
│   └── render.html
├── threat_intel.py
└── requirements.txt
```

This map describes the main runtime pieces (Flask app, Gmail integration, phishing and attachment analysis, intelligence feeds) and how they are laid out on disk so you can navigate or extend the project easily.
