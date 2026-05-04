"""
agent/logging_config.py – Configure structured JSON logging for the agent.

Mirrors ``server/logging_config.py``; kept separate so the agent can be
deployed without the server package.

Environment variables
---------------------
``ITDN_LOG_LEVEL``   Root log level; default ``INFO``.
``ITDN_LOG_JSON``    Set to ``"false"`` to use plain-text format.
"""

from __future__ import annotations

import logging
import os


def setup_logging() -> None:
    """Configure the root logger with JSON or plain-text output."""
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
