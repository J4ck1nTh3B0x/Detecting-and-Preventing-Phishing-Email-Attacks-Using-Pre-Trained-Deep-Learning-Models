"""
run_all.py
Unified scheduler to update brand list, threat domains, and WHOIS data.
Now shows live progress for each feed module.
"""

import subprocess
import logging
import time
import sys
from pathlib import Path

try:
    from intelligence.feeds.update_whois import update_whois
    WHOIS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"WHOIS module not available: {e}")
    WHOIS_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("scheduler")

# Root directory references
BASE_DIR = Path(__file__).resolve().parent.parent
FEEDS_DIR = BASE_DIR / "feeds"

def run_script(script_name: str, label: str):
    """Run a feed script in /feeds with progress and error handling."""
    script_path = FEEDS_DIR / script_name
    if not script_path.exists():
        log.warning(f"[SCHEDULER] Skipping {label}: {script_path.name} not found.")
        return False

    log.info(f"[SCHEDULER] Starting {label} update...")
    start_time = time.time()

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(FEEDS_DIR),
            capture_output=True,
            text=True,
            timeout=1800
        )
        duration = round(time.time() - start_time, 2)
        if result.returncode == 0:
            log.info(f"[SCHEDULER] {label} update finished successfully in {duration}s.")
        else:
            log.error(f"[SCHEDULER] {label} update failed (code {result.returncode}).")
            log.error(result.stderr or result.stdout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log.error(f"[SCHEDULER] {label} update timed out.")
        return False
    except Exception as e:
        log.error(f"[SCHEDULER] Error running {label}: {e}")
        return False

def run_whois_inline():
    """Inline WHOIS updater with progress output."""
    if not WHOIS_AVAILABLE:
        log.warning("[SCHEDULER] WHOIS update skipped - module not available")
        return
        
    try:
        log.info("[SCHEDULER] Starting WHOIS update (inline mode)...")
        updated, failed, total = update_whois()
        log.info("[SCHEDULER] WHOIS update done — Updated=%d, Failed=%d, Total=%d", 
                updated, failed, total)
    except Exception as e:
        log.error("[SCHEDULER] WHOIS update failed: %s", str(e))

def main():
    log.info("[SCHEDULER] === Running all intelligence feed updates ===")
    if run_script("update_brands.py", "Brand list"):
        log.info("[SCHEDULER] Brand update complete.")
    if run_script("update_threat_domains.py", "Threat domain list"):
        log.info("[SCHEDULER] Threat domain update complete.")
    run_whois_inline()
    log.info("[SCHEDULER] === All updates finished ===")

if __name__ == "__main__":
    main()
