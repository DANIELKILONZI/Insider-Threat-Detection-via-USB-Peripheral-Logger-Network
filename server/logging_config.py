"""
server/logging_config.py – Configure structured JSON logging for the server.

Call ``setup_logging()`` once at process startup (before any module imports
that call ``logging.getLogger``).

JSON fields emitted per record
--------------------------------
``asctime``     ISO-8601 timestamp
``levelname``   DEBUG / INFO / WARNING / ERROR / CRITICAL
``name``        Logger name (module path)
``message``     Formatted log message
``exc_info``    Exception traceback (only when an exception is attached)

Environment variables
---------------------
``ITDN_LOG_LEVEL``   Root log level; default ``INFO``.
``ITDN_LOG_JSON``    Set to ``"false"`` to fall back to plain-text format
                     (useful in local development).
"""

from __future__ import annotations

import logging
import os


def setup_logging() -> None:
    """Configure the root logger.

    Uses ``pythonjsonlogger.jsonlogger.JsonFormatter`` when available
    (and ``ITDN_LOG_JSON`` is not ``"false"``); falls back to the
    standard text formatter so the server starts even if
    ``python-json-logger`` is not installed.
    """
    level_name = os.environ.get("ITDN_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    use_json = os.environ.get("ITDN_LOG_JSON", "true").lower() != "false"

    handler = logging.StreamHandler()

    if use_json:
        try:
            try:
                from pythonjsonlogger.json import JsonFormatter  # python-json-logger >= 3
            except ImportError:
                from pythonjsonlogger.jsonlogger import JsonFormatter  # type: ignore[no-redef]  # python-json-logger 2.x

            handler.setFormatter(
                JsonFormatter(
                    fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                )
            )
        except ImportError:
            # python-json-logger not installed; use plain text
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
