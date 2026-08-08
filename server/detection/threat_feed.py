"""
server/detection/threat_feed.py – USB VID:PID threat feed for known-malicious devices.

The feed is a set of "vendor_id:product_id" strings (lower-case hex, e.g.
``"0781:5567"``).  Two sources are supported:

1. **Local file** (``ITDN_THREAT_FEED_PATH``): a plain-text file with one
   VID:PID per line.  Lines starting with ``#`` are treated as comments.
   This file is re-read on every call to :func:`reload` so operators can
   update it in place without restarting the server.

2. **Remote URL** (``ITDN_THREAT_FEED_URL``): the feed is fetched once on
   first use (lazy) and cached in memory.  A background-refresh can be
   triggered by calling :func:`reload`.  The remote feed must return a
   newline-delimited list of VID:PID strings (comments with ``#`` are
   stripped).

Both sources are merged; device IDs present in either are considered
malicious.

Usage::

    from server.detection.threat_feed import is_known_malicious

    if is_known_malicious("0781:5567"):
        ...
"""

from __future__ import annotations

import logging
import threading
import urllib.error
import urllib.request
from typing import Set

from server.config import THREAT_FEED_PATH, THREAT_FEED_URL

logger = logging.getLogger(__name__)

_feed_lock = threading.Lock()
_known_malicious: Set[str] = set()
_loaded = False


def _normalise(vid_pid: str) -> str:
    return vid_pid.strip().lower()


def _parse_lines(text: str) -> Set[str]:
    result: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) == 2:
            result.add(_normalise(line))
        else:
            logger.debug("threat_feed: skipping malformed line: %r", line)
    return result


def _load_local(path: str) -> Set[str]:
    if not path:
        return set()
    try:
        with open(path, encoding="utf-8") as fh:
            return _parse_lines(fh.read())
    except OSError:
        logger.warning("threat_feed: could not read local feed file: %s", path)
        return set()


def _load_remote(url: str) -> Set[str]:
    if not url:
        return set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ITDN-ThreatFeed/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            content = resp.read().decode("utf-8", errors="replace")
        logger.info("threat_feed: loaded %d bytes from %s", len(content), url)
        return _parse_lines(content)
    except (urllib.error.URLError, OSError):
        logger.warning("threat_feed: failed to fetch remote feed from %s", url)
        return set()


def reload() -> int:
    """Re-load the threat feed from all configured sources.

    Returns the total number of distinct VID:PID entries now in the feed.
    """
    global _known_malicious, _loaded
    local = _load_local(THREAT_FEED_PATH)
    remote = _load_remote(THREAT_FEED_URL)
    combined = local | remote
    with _feed_lock:
        _known_malicious = combined
        _loaded = True
    logger.info("threat_feed: %d known-malicious VID:PID entries loaded", len(combined))
    return len(combined)


def _ensure_loaded() -> None:
    global _loaded
    if not _loaded:
        reload()


def is_known_malicious(device_id: str) -> bool:
    """Return True if *device_id* appears in the malicious-device threat feed."""
    _ensure_loaded()
    with _feed_lock:
        return _normalise(device_id) in _known_malicious


def add_entry(vid_pid: str) -> None:
    """Programmatically add a VID:PID to the in-memory feed (useful in tests)."""
    _ensure_loaded()
    with _feed_lock:
        _known_malicious.add(_normalise(vid_pid))


def get_feed() -> Set[str]:
    """Return a copy of the current in-memory feed."""
    _ensure_loaded()
    with _feed_lock:
        return set(_known_malicious)
