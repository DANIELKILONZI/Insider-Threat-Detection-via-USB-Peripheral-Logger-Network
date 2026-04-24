"""
agent/usb_monitor.py – Cross-platform USB device event monitor.

On Linux the monitor uses the *pyudev* library to listen for kernel udev
events in real-time (zero polling latency).  On all other platforms it falls
back to a periodic scan of the system's device tree so that unit tests and
Windows/macOS deployments still work without pyudev.

Each event is returned as a plain ``dict`` with the following keys:

    event_type  : "connected" | "disconnected"
    device_id   : "<vendor_id>:<product_id>"
    serial      : serial-number string (may be empty)
    manufacturer: manufacturer string (may be empty)
    product     : product/model string (may be empty)
    bus_path    : sysfs path or logical path
    timestamp   : ISO-8601 UTC string
    hostname    : reporting host
    transfer_bytes : cumulative bytes transferred since connection (0 on
                     connect; populated on disconnect via /sys counters)
"""

from __future__ import annotations

import datetime
import logging
import platform
import re
import threading
import time
from typing import Callable, Dict, Generator, Optional

from agent.config import HOSTNAME, POLL_INTERVAL

logger = logging.getLogger(__name__)

EventDict = Dict[str, object]
EventCallback = Callable[[EventDict], None]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_sysfs_attr(path: str) -> str:
    """Read a sysfs attribute file, returning empty string on failure."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _build_event(
    event_type: str,
    device_id: str,
    serial: str,
    manufacturer: str,
    product: str,
    bus_path: str,
    transfer_bytes: int = 0,
) -> EventDict:
    return {
        "event_type": event_type,
        "device_id": device_id,
        "serial": serial,
        "manufacturer": manufacturer,
        "product": product,
        "bus_path": bus_path,
        "timestamp": _utcnow(),
        "hostname": HOSTNAME,
        "transfer_bytes": transfer_bytes,
    }


# ---------------------------------------------------------------------------
# Linux udev-based monitor
# ---------------------------------------------------------------------------

def _read_udev_device(device) -> EventDict:  # type: ignore[type-arg]
    """Convert a pyudev Device object into our event dict."""
    vendor_id = device.get("ID_VENDOR_ID", "0000")
    product_id = device.get("ID_MODEL_ID", "0000")
    device_id = f"{vendor_id}:{product_id}"

    serial = device.get("ID_SERIAL_SHORT", "") or device.get("ID_SERIAL", "")
    manufacturer = device.get("ID_VENDOR", "") or device.get("ID_VENDOR_FROM_DATABASE", "")
    product = device.get("ID_MODEL", "") or device.get("ID_MODEL_FROM_DATABASE", "")
    bus_path = device.sys_path or ""

    # Try to read transfer counters from sysfs statistics
    tx_bytes = 0
    stats_path = f"{bus_path}/statistics/bytes"
    raw = _parse_sysfs_attr(stats_path)
    if raw.isdigit():
        tx_bytes = int(raw)

    return _build_event("connected", device_id, serial, manufacturer, product, bus_path, tx_bytes)


def _udev_monitor_loop(callback: EventCallback, stop_event: threading.Event) -> None:
    """Blocking loop that dispatches udev USB events to *callback*."""
    try:
        import pyudev  # noqa: PLC0415
    except ImportError:
        logger.warning("pyudev not available; falling back to poll-based USB monitor")
        _poll_monitor_loop(callback, stop_event)
        return

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="usb")

    logger.info("USB monitor started (udev mode)")

    for action, device in monitor:
        if stop_event.is_set():
            break
        try:
            if action == "add":
                evt = _read_udev_device(device)
                evt["event_type"] = "connected"
                callback(evt)
            elif action == "remove":
                vendor_id = device.get("ID_VENDOR_ID", "0000")
                product_id = device.get("ID_MODEL_ID", "0000")
                device_id = f"{vendor_id}:{product_id}"
                serial = device.get("ID_SERIAL_SHORT", "") or device.get("ID_SERIAL", "")
                evt = _build_event(
                    "disconnected",
                    device_id,
                    serial,
                    device.get("ID_VENDOR", ""),
                    device.get("ID_MODEL", ""),
                    device.sys_path or "",
                )
                callback(evt)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Error processing udev event")


# ---------------------------------------------------------------------------
# Fallback: poll /sys/bus/usb/devices (Linux without pyudev) or enumerate
# via WMI (Windows) – uses a simple snapshot-diff approach.
# ---------------------------------------------------------------------------

def _list_linux_usb_devices() -> Dict[str, EventDict]:
    """Return a snapshot {sysfs_path: event_dict} from /sys/bus/usb/devices."""
    import glob as _glob

    devices: Dict[str, EventDict] = {}
    for dev_path in _glob.glob("/sys/bus/usb/devices/*/"):
        vendor_id = _parse_sysfs_attr(f"{dev_path}idVendor") or "0000"
        product_id = _parse_sysfs_attr(f"{dev_path}idProduct") or "0000"
        if vendor_id == "0000" and product_id == "0000":
            continue  # hub or root hub without IDs
        device_id = f"{vendor_id}:{product_id}"
        serial = _parse_sysfs_attr(f"{dev_path}serial")
        manufacturer = _parse_sysfs_attr(f"{dev_path}manufacturer")
        product = _parse_sysfs_attr(f"{dev_path}product")
        devices[dev_path] = _build_event(
            "connected", device_id, serial, manufacturer, product, dev_path
        )
    return devices


def _list_windows_usb_devices() -> Dict[str, EventDict]:
    """Return a snapshot using WMI (Windows only)."""
    devices: Dict[str, EventDict] = {}
    try:
        import wmi  # noqa: PLC0415

        c = wmi.WMI()
        for disk in c.Win32_DiskDrive():
            if "USB" in (disk.InterfaceType or ""):
                device_id = disk.PNPDeviceID or disk.DeviceID or "unknown"
                devices[device_id] = _build_event(
                    "connected",
                    device_id,
                    disk.SerialNumber or "",
                    disk.Manufacturer or "",
                    disk.Model or "",
                    disk.DeviceID or "",
                )
    except Exception:  # pylint: disable=broad-except
        logger.exception("WMI USB enumeration failed")
    return devices


def _snapshot_devices() -> Dict[str, EventDict]:
    system = platform.system()
    if system == "Linux":
        return _list_linux_usb_devices()
    if system == "Windows":
        return _list_windows_usb_devices()
    return {}


def _poll_monitor_loop(callback: EventCallback, stop_event: threading.Event) -> None:
    """Polling-based monitor: detects connect/disconnect by diffing snapshots."""
    logger.info("USB monitor started (poll mode, interval=%.1fs)", POLL_INTERVAL)
    previous: Dict[str, EventDict] = _snapshot_devices()

    while not stop_event.is_set():
        time.sleep(POLL_INTERVAL)
        current = _snapshot_devices()

        # Newly connected
        for path, evt in current.items():
            if path not in previous:
                logger.debug("USB connected: %s", evt["device_id"])
                callback(evt)

        # Disconnected
        for path, evt in previous.items():
            if path not in current:
                disconnect_evt = dict(evt)
                disconnect_evt["event_type"] = "disconnected"
                disconnect_evt["timestamp"] = _utcnow()
                logger.debug("USB disconnected: %s", disconnect_evt["device_id"])
                callback(disconnect_evt)

        previous = current


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class USBMonitor:
    """
    Starts a background thread that calls *callback* for every USB event.

    Usage::

        monitor = USBMonitor(callback=my_handler)
        monitor.start()
        …
        monitor.stop()
    """

    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        system = platform.system()
        if system == "Linux":
            target = _udev_monitor_loop
        else:
            target = _poll_monitor_loop
        self._thread = threading.Thread(
            target=target,
            args=(self._callback, self._stop),
            daemon=True,
            name="usb-monitor",
        )
        self._thread.start()
        logger.info("USBMonitor thread started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("USBMonitor thread stopped")
