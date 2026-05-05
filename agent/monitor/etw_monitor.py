"""Windows ETW USB monitor.

Subscribes to the ``Microsoft-Windows-USB-USBHUB3-Performancecounters``
ETW provider (and the generic ``Microsoft-Windows-Kernel-PnP`` provider as
a fallback) to yield :class:`~shared.schema.NormalizedEvent` objects for
USB connect / disconnect events on Windows.

Dependencies (Windows only):
    pip install pywintrace  # or pyetw

This module imports gracefully on non-Windows systems so that the agent
code-base can be imported in tests on Linux/macOS without errors.
"""
from __future__ import annotations

import logging
import platform
from datetime import datetime, timezone
from typing import Iterator

from shared.schema import NormalizedEvent

logger = logging.getLogger(__name__)

# Well-known ETW provider GUIDs
_USBHUB3_GUID = "{9C6A6AC9-FAA3-41FF-AE4E-E27C62A3DA9B}"
_KERNEL_PNP_GUID = "{9C205A39-1250-487D-ABD7-E831C6290539}"


class ETWMonitor:
    """Yields NormalizedEvent objects for USB events via Windows ETW.

    Usage::

        monitor = ETWMonitor(agent_id="my-agent", actor="DOMAIN\\\\user")
        for event in monitor.monitor():
            transport.post_event(event)
    """

    def __init__(self, agent_id: str, actor: str = "system") -> None:
        self.agent_id = agent_id
        self.actor = actor

    # ------------------------------------------------------------------
    def _make_event(self, action: str, device_id: str, raw: dict) -> NormalizedEvent:
        return NormalizedEvent(
            agent_id=self.agent_id,
            actor=self.actor,
            device_id=device_id,
            action=action,
            source_type="usb",
            raw=raw,
            confidence=0.95,
        )

    # ------------------------------------------------------------------
    def monitor(self) -> Iterator[NormalizedEvent]:
        """Block and yield USB events from ETW. Raises ImportError on non-Windows."""
        if platform.system() != "Windows":
            raise ImportError(
                "ETW monitoring is only available on Windows. "
                "Use pyudev on Linux or ioreg on macOS."
            )

        try:
            import etw  # type: ignore  # pywintrace
            from etw import EventConsumer, EventProvider  # type: ignore
        except ImportError:
            try:
                import pyetw as etw  # type: ignore
                from pyetw import EventConsumer, EventProvider  # type: ignore
            except ImportError as exc:
                raise ImportError(
                    "A Windows ETW library is required. "
                    "Install one of: pywintrace or pyetw\n"
                    "  pip install pywintrace"
                ) from exc

        queue: list[NormalizedEvent] = []

        def _on_event(record) -> None:  # type: ignore[override]
            try:
                props = getattr(record, "Properties", {}) or {}
                device_desc = (
                    props.get("DeviceDescription")
                    or props.get("DeviceId")
                    or props.get("InstanceId")
                    or "unknown"
                )
                # Normalise to VID:PID if present
                device_id = _extract_vid_pid(str(device_desc))
                event_id = getattr(record, "EventId", 0)
                # PnP event IDs: 400 = device arrival, 401 = device removal
                if event_id in (400,):
                    action = "connect"
                elif event_id in (401,):
                    action = "disconnect"
                else:
                    action = "event"
                raw = {
                    "event_id": event_id,
                    "device_desc": device_desc,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "props": {k: str(v) for k, v in props.items()},
                }
                queue.append(self._make_event(action, device_id, raw))
            except Exception:
                logger.exception("ETW callback error")

        # Start the ETW session
        providers = [
            EventProvider(_USBHUB3_GUID, callback=_on_event),
            EventProvider(_KERNEL_PNP_GUID, callback=_on_event),
        ]
        consumer = EventConsumer(providers)
        consumer.start()
        logger.info("ETW USB monitor started (providers: USBHUB3, Kernel-PnP)")

        try:
            while True:
                if queue:
                    yield queue.pop(0)
                else:
                    import time
                    time.sleep(0.05)
        finally:
            consumer.stop()


# ---------------------------------------------------------------------------
def _extract_vid_pid(device_desc: str) -> str:
    """Extract VID:PID from a PnP instance ID string like USB\\VID_0781&PID_5567\\…"""
    import re

    m = re.search(r"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})", device_desc, re.IGNORECASE)
    if m:
        return f"{m.group(1).lower()}:{m.group(2).lower()}"
    return device_desc[:256]
