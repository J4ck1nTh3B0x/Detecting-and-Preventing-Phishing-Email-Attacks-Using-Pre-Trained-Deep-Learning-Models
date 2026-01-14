"""
Live configuration and data file monitoring for real-time updates.

This module provides a centralized way to monitor and access configuration files
that should be reloaded automatically when changed on disk.
"""
import json
import csv
import logging
import os
import time
import threading
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Callable, TypeVar, Generic, Union
from dataclasses import dataclass, field
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

log = logging.getLogger("live_config")

T = TypeVar('T')

@dataclass
class FileCache(Generic[T]):
    """Generic file cache with modification tracking."""
    path: Path
    last_modified: float = 0
    last_checked: float = 0
    data: T = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _callbacks: List[Callable[[T], None]] = field(default_factory=list)

    def add_callback(self, callback: Callable[[T], None]):
        """Register a callback to be called when the file changes."""
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[T], None]):
        """Remove a previously registered callback."""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def _notify_callbacks(self):
        """Notify all registered callbacks with the current data."""
        with self._lock:
            for callback in self._callbacks:
                try:
                    callback(self.data)
                except Exception as e:
                    log.error(f"Error in callback: {e}")

class ConfigFileHandler(FileSystemEventHandler):
    """Watch for changes to configuration files and update caches."""
    def __init__(self, caches: Dict[Path, FileCache]):
        self.caches = caches
        self.last_handled: Dict[Path, float] = {}
        self.debounce_sec = 1.0  # Debounce time in seconds

    def on_modified(self, event):
        if not event.is_directory:
            path = Path(event.src_path)
            current_time = time.time()
            
            # Skip if we've handled this recently
            last_handled = self.last_handled.get(path, 0)
            if current_time - last_handled < self.debounce_sec:
                return
            
            self.last_handled[path] = current_time
            
            if path in self.caches:
                log.info(f"Detected change to {path}, reloading...")
                cache = self.caches[path]
                try:
                    self._load_file(cache)
                    log.info(f"Successfully reloaded {path}")
                except Exception as e:
                    log.error(f"Failed to reload {path}: {e}")

    @staticmethod
    def _load_file(cache: FileCache):
        """Load a file based on its extension."""
        if not cache.path.exists():
            log.warning(f"File not found: {cache.path}")
            return

        mtime = cache.path.stat().st_mtime
        if mtime <= cache.last_modified and cache.data:
            return  # No changes

        # Read the file based on its extension
        if cache.path.suffix.lower() == '.json':
            with open(cache.path, 'r', encoding='utf-8') as f:
                cache.data = json.load(f)
        elif cache.path.suffix.lower() == '.csv':
            with open(cache.path, 'r', encoding='utf-8') as f:
                cache.data = list(csv.DictReader(f))
        else:
            with open(cache.path, 'r', encoding='utf-8') as f:
                cache.data = f.read()

        cache.last_modified = mtime
        cache.last_checked = time.time()
        cache._notify_callbacks()

# Global file caches
_caches: Dict[Path, FileCache] = {}
_observer = None

# Initialize the file watcher
def _init_watcher():
    global _observer
    if _observer is not None:
        return

    try:
        _observer = Observer()
        handler = ConfigFileHandler(_caches)
        
        # Watch the parent directories of all cache files
        watch_dirs = set(path.parent for path in _caches.keys())
        for watch_dir in watch_dirs:
            if watch_dir.exists():
                _observer.schedule(handler, str(watch_dir), recursive=False)
        
        _observer.daemon = True
        _observer.start()
        log.info("Started live config file watcher")
    except Exception as e:
        log.error(f"Failed to start file watcher: {e}")

def _stop_watcher():
    global _observer
    if _observer:
        try:
            _observer.stop()
            _observer.join()
            _observer = None
        except Exception as e:
            log.error(f"Error stopping file watcher: {e}")

# Register cleanup on exit
import atexit
atexit.register(_stop_watcher)

def get_file_cache(path: Union[str, Path], default: Any = None) -> FileCache:
    """Get or create a file cache for the given path."""
    path = Path(path).resolve()
    
    if path not in _caches:
        _caches[path] = FileCache[Any](path=path, data=default)
        # Start the watcher if this is the first cache
        if len(_caches) == 1:
            _init_watcher()
    
    return _caches[path]

def load_file(path: Union[str, Path], default: Any = None, force_reload: bool = False) -> Any:
    """Load a file with automatic reloading when changed."""
    cache = get_file_cache(path, default)
    
    # Load the file if needed
    if force_reload or not cache.data:
        ConfigFileHandler._load_file(cache)
    
    return cache.data

def watch_file(path: Union[str, Path], callback: Callable[[Any], None], default: Any = None):
    """Watch a file for changes and call the callback when it changes."""
    cache = get_file_cache(path, default)
    cache.add_callback(callback)
    
    # Initial load if needed
    if not cache.data:
        ConfigFileHandler._load_file(cache)
    
    return lambda: cache.remove_callback(callback)  # Returns an unregister function

# Common file caches for quick access
BRANDS_JSON = Path(__file__).parent / "cache" / "brands.json"
THREAT_JSON = Path(__file__).parent / "cache" / "threat.json"
WHITELIST_CSV = Path(__file__).parent / "cache" / "whitelist.csv"
VT_CACHE_JSON = Path(__file__).parent / "cache" / "vt_cache.json"
GSB_CACHE_JSON = Path(__file__).parent / "cache" / "gsb_cache.json"

# Initialize caches for known files
for path in [BRANDS_JSON, THREAT_JSON, WHITELIST_CSV, VT_CACHE_JSON, GSB_CACHE_JSON]:
    if path.exists():
        get_file_cache(path)
