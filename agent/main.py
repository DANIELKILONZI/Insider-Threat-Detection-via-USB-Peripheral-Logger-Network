"""Agent entry point — starts monitors, chains events, sends to server."""
from __future__ import annotations

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone

from agent.chain import EventChain
from agent.config import AgentConfig
from agent.integrity import compute_binary_hash, verify_integrity
from agent.transport import AgentTransport
from shared.schema import NormalizedEvent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


async def monitor_loop(
    agent_id: str,
    event_queue: asyncio.Queue,
    stop_event: asyncio.Event,
) -> None:
    """Run USB/BT monitors in threads; push events onto queue."""
    import concurrent.futures
    import threading

    loop = asyncio.get_event_loop()

    def _usb_worker():
        try:
            from agent.monitor.usb_monitor import USBMonitor

            mon = USBMonitor(agent_id=agent_id)
            for event in mon.monitor():
                if stop_event.is_set():
                    break
                asyncio.run_coroutine_threadsafe(event_queue.put(event), loop)
        except ImportError as exc:
            logger.warning("USB monitor unavailable: %s", exc)
        except Exception as exc:
            logger.error("USB monitor error: %s", exc)

    def _bt_worker():
        try:
            from agent.monitor.bt_monitor import BTMonitor

            mon = BTMonitor(agent_id=agent_id)
            for event in mon.monitor():
                if stop_event.is_set():
                    break
                asyncio.run_coroutine_threadsafe(event_queue.put(event), loop)
        except ImportError as exc:
            logger.warning("BT monitor unavailable: %s", exc)
        except Exception as exc:
            logger.error("BT monitor error: %s", exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_usb_worker),
            pool.submit(_bt_worker),
        ]
        while not stop_event.is_set():
            await asyncio.sleep(1)
        for f in futures:
            f.cancel()


async def main() -> None:
    cfg = AgentConfig()
    chain = EventChain(db_path=cfg.chain_db_path)
    transport = AgentTransport(
        server_url=cfg.server_url,
        api_key=cfg.api_key,
        cert_path=cfg.cert_path,
        key_path=cfg.key_path,
        ca_cert_path=cfg.ca_cert_path,
    )

    # Integrity check
    trusted_hash = transport.get_trusted_hash(cfg.agent_id)
    if trusted_hash:
        if not verify_integrity(trusted_hash):
            logger.critical("Binary integrity check FAILED — aborting startup.")
            sys.exit(1)
    else:
        logger.info("No trusted hash registered; skipping integrity check.")

    stop_event = asyncio.Event()
    event_queue: asyncio.Queue = asyncio.Queue()

    def _shutdown(signum, frame):
        logger.info("Shutdown signal received.")
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    last_anchor = datetime.now(timezone.utc)

    async def _send_loop():
        nonlocal last_anchor
        while not stop_event.is_set():
            try:
                event: NormalizedEvent = await asyncio.wait_for(
                    event_queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                # Periodic anchor
                now = datetime.now(timezone.utc)
                if (now - last_anchor).total_seconds() >= cfg.anchor_interval:
                    head = chain.get_chain_head()
                    if head:
                        transport.send_anchor(cfg.agent_id, head, now)
                        logger.info("Sent anchor: %s", head[:16])
                    last_anchor = now
                continue

            event_hash = chain.add_event(event)
            ok = transport.send_event(event)
            logger.info(
                "Event %s hash=%s sent=%s", event.action, event_hash[:12], ok
            )

    await asyncio.gather(
        monitor_loop(cfg.agent_id, event_queue, stop_event),
        _send_loop(),
    )

    transport.close()
    logger.info("Agent stopped.")


if __name__ == "__main__":
    asyncio.run(main())
