"""
server/app.py – Application factory for the ITDN central server.

Endpoints live in :mod:`server.routers`, one blueprint per concern; this module
only wires them together, initialises the database, and starts background
workers.  See ``server/routers/<name>.py`` for the request/response contract of
each endpoint group, or the REST API Reference section of the README.

Run directly with ``python -m server.app``.
"""

from __future__ import annotations

import logging
import os

from flask import Flask

import server.database as db
from server.logging_config import setup_logging
from server.metrics import METRICS
from server.routers import ALL_BLUEPRINTS

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Build the Flask app: register blueprints, init the DB, start workers."""
    setup_logging()

    app = Flask(__name__)
    for blueprint in ALL_BLUEPRINTS:
        app.register_blueprint(blueprint)

    db.init_db()
    # Register active-alert gauge callback
    METRICS.set_active_alert_callback(
        lambda: len(db.list_alerts(acknowledged=False, limit=100_000))
    )
    # Start background retention worker (runs once per day)
    _start_retention_worker()
    return app


def _start_retention_worker() -> None:
    """Start a daemon thread that periodically purges old records."""
    import threading as _threading
    import time as _time
    from server.config import RETENTION_DAYS

    def _worker() -> None:
        _INTERVAL = 86400  # run daily
        while True:
            _time.sleep(_INTERVAL)
            try:
                counts = db.purge_old_records(RETENTION_DAYS)
                logger.info("Retention purge: %s (retention=%d days)", counts, RETENTION_DAYS)
            except Exception:  # pylint: disable=broad-except
                logger.exception("Retention purge failed")

    t = _threading.Thread(target=_worker, daemon=True, name="retention-worker")
    t.start()


if __name__ == "__main__":
    from server.config import SERVER_HOST, SERVER_PORT, TLS_CERT, TLS_KEY

    _app = create_app()
    ssl_ctx = None
    if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
        import ssl as _ssl

        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        logger.info("TLS enabled with cert %s", TLS_CERT)
    else:
        logger.warning("TLS certificates not found – running in plain HTTP mode (dev only)")

    _app.run(host=SERVER_HOST, port=SERVER_PORT, ssl_context=ssl_ctx)
