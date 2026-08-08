"""
agent/monitor/etw_monitor.py – Windows ETW-based USB event source.

Subscribes to the ``Microsoft-Windows-USB-USBHUB3`` and ``Microsoft-Windows-
Kernel-PnP`` ETW providers and dispatches connect/disconnect events.

Why ETW rather than WMI
-----------------------
The WMI backend in :mod:`agent.monitor.usb_monitor` watches
``__InstanceCreationEvent``/``__InstanceDeletionEvent`` and then re-enumerates
the full device tree.  That re-enumeration means a device plugged and unplugged
between polls can be missed entirely, and every event costs a full WMI query.
ETW delivers kernel PnP notifications as they happen, so short-lived devices —
exactly the ones that matter for exfiltration — are not lost.

ETW is therefore preferred on Windows, with WMI and then polling as fallbacks.
This module imports cleanly on every platform so the agent code base stays
importable in tests on Linux and macOS; the platform check happens at
:func:`etw_monitor_loop` call time, not at import.

Dependencies (Windows only)::

    pip install pywintrace     # or: pip install pyetw
"""

from __future__ import annotations

import logging
import platform
import re
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from agent.monitor.usb_monitor import EventCallback

logger = logging.getLogger(__name__)

# Well-known ETW provider GUIDs
USBHUB3_GUID = "{9C6A6AC9-FAA3-41FF-AE4E-E27C62A3DA9B}"
KERNEL_PNP_GUID = "{9C205A39-1250-487D-ABD7-E831C6290539}"

# Kernel-PnP event IDs
_EVENT_DEVICE_ARRIVAL = 400
_EVENT_DEVICE_REMOVAL = 401

_VID_PID_RE = re.compile(r"VID_([0-9A-F]{4}).*?PID_([0-9A-F]{4})", re.IGNORECASE)


def _extract_vid_pid(device_desc: str) -> str:
    """Reduce a PnP instance ID to ``vid:pid``.

    ``USB\\VID_0781&PID_5567\\4C530001`` becomes ``0781:5567``.  Strings with no
    recognisable VID/PID pair are passed through, truncated to a bounded length
    so a malformed identifier cannot blow up the event payload.
    """
    match = _VID_PID_RE.search(device_desc)
    if match:
        return f"{match.group(1).lower()}:{match.group(2).lower()}"
    return device_desc[:256]


def is_available() -> bool:
    """True when this host can actually run an ETW session."""
    if platform.system() != "Windows":
        return False
    return _load_etw() is not None


def _load_etw():
    """Return an (EventConsumer, EventProvider) pair, or None if unavailable."""
    try:
        from etw import EventConsumer, EventProvider  # type: ignore
        return EventConsumer, EventProvider
    except ImportError:
        pass
    try:
        from pyetw import EventConsumer, EventProvider  # type: ignore
        return EventConsumer, EventProvider
    except ImportError:
        return None


def etw_monitor_loop(callback: "EventCallback", stop_event: threading.Event) -> None:
    """Blocking loop dispatching ETW USB events to *callback*.

    Matches the signature of the other ``*_monitor_loop`` functions in
    :mod:`agent.monitor.usb_monitor` so it can be used as a thread target.

    Falls back to the WMI monitor when ETW is unusable, so a Windows host
    without ``pywintrace`` still collects events rather than going silent.
    """
    from agent.monitor.usb_monitor import _build_event, _wmi_event_monitor_loop

    if platform.system() != "Windows":
        raise ImportError(
            "ETW monitoring is only available on Windows. "
            "Use udev/eBPF on Linux."
        )

    loaded = _load_etw()
    if loaded is None:
        logger.warning(
            "No ETW library available (install pywintrace or pyetw); "
            "falling back to the WMI monitor"
        )
        _wmi_event_monitor_loop(callback, stop_event)
        return

    EventConsumer, EventProvider = loaded

    def _on_event(record) -> None:
        try:
            props = getattr(record, "Properties", {}) or {}
            device_desc = (
                props.get("DeviceDescription")
                or props.get("DeviceId")
                or props.get("InstanceId")
                or "unknown"
            )
            event_id = getattr(record, "EventId", 0)
            if event_id == _EVENT_DEVICE_ARRIVAL:
                event_type = "connected"
            elif event_id == _EVENT_DEVICE_REMOVAL:
                event_type = "disconnected"
            else:
                return  # not a PnP arrival/removal – nothing to report

            device_desc = str(device_desc)
            callback(
                _build_event(
                    event_type=event_type,
                    device_id=_extract_vid_pid(device_desc),
                    serial=str(props.get("SerialNumber", "")),
                    manufacturer=str(props.get("Manufacturer", "")),
                    product=str(props.get("DeviceDescription", "")),
                    bus_path=device_desc,
                )
            )
        except Exception:  # pylint: disable=broad-except
            # A malformed record must never kill the ETW session.
            logger.exception("ETW callback error")

    consumer = EventConsumer(
        [
            EventProvider(USBHUB3_GUID, callback=_on_event),
            EventProvider(KERNEL_PNP_GUID, callback=_on_event),
        ]
    )
    consumer.start()
    logger.info("USB monitor started (ETW mode: USBHUB3, Kernel-PnP)")
    try:
        # Events arrive on the consumer's own threads via _on_event; this thread
        # only needs to stay alive until asked to stop.
        stop_event.wait()
    finally:
        consumer.stop()
        logger.info("ETW session stopped")
