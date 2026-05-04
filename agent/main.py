"""
agent/main.py – Entry point for the ITDN endpoint agent.

Starts the USB monitor, Bluetooth monitor (optional), local audit logger,
and the secure event transport thread.  Runs until a SIGTERM / SIGINT is
received.
"""

from __future__ import annotations

import logging
import os
import signal
import sys

from agent.logging_config import setup_logging

setup_logging()

logger = logging.getLogger(__name__)


def main() -> None:
    from agent.config import BT_MONITOR_ENABLED, HOSTNAME
    from agent.logger import LocalAuditLogger
    from agent.transport import EventTransport
    from agent.usb_monitor import USBMonitor

    audit_logger = LocalAuditLogger()
    transport = EventTransport()

    def handle_event(event: dict) -> None:
        try:
            audit_logger.write(event)
        except OSError:
            pass
        transport.enqueue(event)

    monitors = []
    usb_monitor = USBMonitor(callback=handle_event)
    monitors.append(usb_monitor)

    if BT_MONITOR_ENABLED:
        from agent.bt_monitor import BTMonitor

        bt_monitor = BTMonitor(callback=handle_event)
        monitors.append(bt_monitor)

    transport.start()

    from agent.anchor_scheduler import AnchorScheduler
    from agent.integrity import IntegrityChecker
    anchor_scheduler = AnchorScheduler(audit_logger, transport)
    anchor_scheduler.start()

    checker = IntegrityChecker()
    try:
        is_trusted = checker.check_with_server(transport)
        if not is_trusted:
            logger.warning("Agent integrity check: hash mismatch or not registered (continuing)")
        else:
            logger.info("Agent integrity check passed")
    except Exception:
        logger.warning("Agent integrity check could not complete (continuing)")

    for m in monitors:
        m.start()

    logger.info("ITDN agent running on host '%s'. Press Ctrl-C to stop.", HOSTNAME)

    stop_event = __import__("threading").Event()

    def _shutdown(signum, frame):  # noqa: ANN001
        logger.info("Received signal %s – shutting down…", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    stop_event.wait()

    for m in monitors:
        m.stop()
    anchor_scheduler.stop()
    transport.stop()

    logger.info("Audit chain head: %s", audit_logger.chain_head)
    logger.info("ITDN agent stopped cleanly.")


if __name__ == "__main__":
    main()
