"""USB device monitor using pyudev (Linux). Stubs for other platforms."""
from __future__ import annotations

import logging
import platform
from datetime import datetime, timezone
from typing import Iterator

from shared.schema import NormalizedEvent

logger = logging.getLogger(__name__)

# USB mass-storage class VID:PID patterns (partial list)
MASS_STORAGE_CLASSES = {"08"}  # USB class 0x08 = Mass Storage


class USBMonitor:
    """Yields NormalizedEvent objects for USB connect/disconnect events."""

    def __init__(self, agent_id: str, actor: str = "system") -> None:
        self.agent_id = agent_id
        self.actor = actor

    def _make_event(self, action: str, device_id: str, raw: dict) -> NormalizedEvent:
        return NormalizedEvent(
            agent_id=self.agent_id,
            actor=self.actor,
            device_id=device_id,
            action=action,
            source_type="usb",
            raw=raw,
        )

    def monitor(self) -> Iterator[NormalizedEvent]:
        """Block and yield events. Raises ImportError on non-Linux."""
        if platform.system() != "Linux":
            raise ImportError(
                "pyudev USB monitoring is only available on Linux. "
                "Use ETW on Windows or ioreg on macOS."
            )
        try:
            import pyudev  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "pyudev is required for USB monitoring on Linux. "
                "Install with: pip install pyudev"
            ) from exc

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="usb")

        for device in iter(monitor.poll, None):
            if device.action not in ("add", "remove"):
                continue
            vid = device.get("ID_VENDOR_ID", "")
            pid = device.get("ID_MODEL_ID", "")
            device_id = f"{vid}:{pid}" if vid and pid else device.sys_name
            usb_class = device.get("ID_USB_CLASS_FROM_DATABASE", "")
            action = "connect" if device.action == "add" else "disconnect"
            raw = {
                "sys_name": device.sys_name,
                "vid": vid,
                "pid": pid,
                "manufacturer": device.get("ID_VENDOR", ""),
                "product": device.get("ID_MODEL", ""),
                "serial": device.get("ID_SERIAL_SHORT", ""),
                "usb_class": usb_class,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            confidence = 0.9 if (action == "connect") else 1.0
            yield NormalizedEvent(
                agent_id=self.agent_id,
                actor=self.actor,
                device_id=device_id,
                action=action,
                source_type="usb",
                raw=raw,
                confidence=confidence,
            )
