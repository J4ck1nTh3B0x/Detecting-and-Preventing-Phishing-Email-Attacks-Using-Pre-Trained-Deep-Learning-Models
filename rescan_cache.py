#!/usr/bin/env python3
"""
rescan_cache.py

Scan the local email cache and run phishing detection for any cached message
that does not yet have a stored prediction. Saves results back to the DB.

Usage:
    python rescan_cache.py
"""

import time
import sys
import argparse

from email_cache import get_cached_emails, get_cached_email
import background_sync


def main(limit=100000, sleep_between=0.05, model_path="phishing_mail_detect_model"):
    print("Starting rescan of cached emails for phishing predictions...")
    # Processing will reuse background_sync.process_single_email(),
    # which internally loads/uses the model and all heuristics/bypass logic.

    # Fetch all cached emails (returns summary dicts)
    all_cached = get_cached_emails(limit=limit)
    total = len(all_cached)
    if total == 0:
        print("No cached emails found. Exiting.")
        return

    pending = []
    for item in all_cached:
        if not item.get("prediction_label"):
            pending.append(item["id"])

    print(f"Total cached: {total}. Pending (no prediction): {len(pending)}")
    if not pending:
        print("Nothing to do. All cached messages already have predictions.")
        return

    for idx, msg_id in enumerate(pending, start=1):
        try:
            cached = get_cached_email(msg_id)
            if not cached:
                print(f"[{idx}/{len(pending)}] {msg_id} - not found in cache, skipping.")
                continue

            result = background_sync.process_single_email(cached)
            label = result.get("label")
            score = float(result.get("score", 0.0))
            print(f"[{idx}/{len(pending)}] {msg_id} -> {label} (score={score:.4f})")
            time.sleep(sleep_between)
        except KeyboardInterrupt:
            print("Interrupted by user. Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"[ERROR] Failed processing {msg_id}: {e}")

    print("Rescan complete. You can view results in your app or DB.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rescan cached emails and run phishing detector.")
    parser.add_argument("--limit", type=int, default=100000, help="Max number of cached emails to query")
    parser.add_argument("--sleep", type=float, default=0.05, help="Sleep seconds between predictions")
    parser.add_argument("--model-path", type=str, default="phishing_mail_detect_model", help="Path to model folder (if present)")
    args = parser.parse_args()
    main(limit=args.limit, sleep_between=args.sleep, model_path=args.model_path)
