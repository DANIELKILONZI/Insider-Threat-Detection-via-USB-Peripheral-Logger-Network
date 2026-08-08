"""
agent/monitor/bt_monitor.py – Bluetooth device event monitor.

Detects nearby / newly-paired Bluetooth devices by polling *bluetoothctl* (on
Linux) or the Windows Bluetooth APIs (via WMI) at a configurable interval.
Paired devices that weren't present in the previous snapshot trigger a
"connected" event; devices that disappear trigger a "disconnected" event.

Event schema matches agent/monitor/usb_monitor.py so both sources can be handled by
the same downstream pipeline.
"""

from __future__ import annotations

import datetime
import logging
import platform
import re
import subprocess
import threading
import time
from typing import Callable, Dict, Optional

from agent.config import HOSTNAME, POLL_INTERVAL

logger = logging.getLogger(__name__)

EventDict = Dict[str, object]
EventCallback = Callable[[EventDict], None]


def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_bt_event(
    event_type: str,
    device_id: str,
    name: str,
    address: str,
) -> EventDict:
    return {
        "event_type": event_type,
        "peripheral_type": "bluetooth",
        "device_id": device_id,
        "serial": address,
        "manufacturer": "",
        "product": name,
        "bus_path": f"bt://{address}",
        "timestamp": _utcnow(),
        "hostname": HOSTNAME,
        "transfer_bytes": 0,
    }


# ---------------------------------------------------------------------------
# Platform-specific enumeration
# ---------------------------------------------------------------------------

_BT_DEVICE_RE = re.compile(r"Device\s+([0-9A-Fa-f:]{17})\s+(.+)")


def _list_linux_bt_devices() -> Dict[str, EventDict]:
    """
    Use *bluetoothctl devices* to enumerate known/paired Bluetooth devices.
    Returns {mac_address: event_dict}.
    """
    devices: Dict[str, EventDict] = {}
    try:
        result = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            m = _BT_DEVICE_RE.search(line)
            if m:
                address, name = m.group(1), m.group(2).strip()
                device_id = f"bt:{address}"
                devices[address] = _build_bt_event("connected", device_id, name, address)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        logger.debug("bluetoothctl not available; Bluetooth monitoring disabled")
    return devices


def _list_windows_bt_devices() -> Dict[str, EventDict]:
    devices: Dict[str, EventDict] = {}
    try:
        import wmi  # noqa: PLC0415

        c = wmi.WMI()
        for dev in c.Win32_PnPEntity():
            if "Bluetooth" in (dev.PNPClass or ""):
                address = dev.PNPDeviceID or dev.Name or "unknown"
                name = dev.Name or ""
                device_id = f"bt:{address}"
                devices[address] = _build_bt_event("connected", device_id, name, address)
    except Exception:  # pylint: disable=broad-except
        logger.exception("WMI Bluetooth enumeration failed")
    return devices


def _snapshot_bt_devices() -> Dict[str, EventDict]:
    system = platform.system()
    if system == "Linux":
        return _list_linux_bt_devices()
    if system == "Windows":
        return _list_windows_bt_devices()
    return {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class BTMonitor:
    """
    Background thread that polls for Bluetooth device changes and invokes
    *callback* on connect/disconnect events.
    """

    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="bt-monitor",
        )
        self._thread.start()
        logger.info("BTMonitor thread started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("BTMonitor thread stopped")

    def _loop(self) -> None:
        previous: Dict[str, EventDict] = _snapshot_bt_devices()
        while not self._stop.is_set():
            time.sleep(POLL_INTERVAL)
            current = _snapshot_bt_devices()

            for addr, evt in current.items():
                if addr not in previous:
                    logger.debug("Bluetooth connected: %s", evt["device_id"])
                    self._callback(evt)

            for addr, evt in previous.items():
                if addr not in current:
                    disconnect_evt = dict(evt)
                    disconnect_evt["event_type"] = "disconnected"
                    disconnect_evt["timestamp"] = _utcnow()
                    logger.debug("Bluetooth disconnected: %s", disconnect_evt["device_id"])
                    self._callback(disconnect_evt)

            previous = current
