#!/usr/bin/env python3
"""Compare Gmail messages with cached messages"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmail_utils import get_service
import email_cache

def compare_gmail_cache():
    service = get_service()
    if not service:
        print("ERROR: Gmail service not available")
        return
    
    print("Getting Gmail message IDs...")
    gmail_ids = set()
    try:
        response = service.users().messages().list(
            userId="me", 
            includeSpamTrash=True,
            maxResults=500
        ).execute()
        messages = response.get("messages", [])
        for msg in messages:
            gmail_ids.add(msg["id"])
        print(f"Gmail reports {len(gmail_ids)} messages")
    except Exception as e:
        print(f"ERROR getting Gmail messages: {e}")
        return
    
    print("Getting cached message IDs...")
    try:
        cached_ids = set(email_cache.get_all_msg_ids())
        print(f"Cache has {len(cached_ids)} messages")
    except Exception as e:
        print(f"ERROR getting cached messages: {e}")
        return
    
    # Compare
    missing_in_cache = gmail_ids - cached_ids
    extra_in_cache = cached_ids - gmail_ids
    
    print(f"\n--- COMPARISON ---")
    print(f"Missing in cache: {len(missing_in_cache)} messages")
    print(f"Extra in cache: {len(extra_in_cache)} messages")
    
    if missing_in_cache:
        print(f"\nMissing message IDs (first 10):")
        for i, msg_id in enumerate(list(missing_in_cache)[:10]):
            print(f"  {msg_id}")
        if len(missing_in_cache) > 10:
            print(f"  ... and {len(missing_in_cache) - 10} more")
    
    if extra_in_cache:
        print(f"\nExtra message IDs in cache (first 10):")
        for i, msg_id in enumerate(list(extra_in_cache)[:10]):
            print(f"  {msg_id}")
        if len(extra_in_cache) > 10:
            print(f"  ... and {len(extra_in_cache) - 10} more")

if __name__ == "__main__":
    compare_gmail_cache()
