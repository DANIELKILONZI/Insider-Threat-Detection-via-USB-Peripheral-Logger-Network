"""
agent/ebpf_monitor.py – eBPF-based USB monitor using BCC (BPF Compiler Collection).

Falls back to udev monitoring if BCC is unavailable.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

EventDict = Dict[str, object]
EventCallback = Callable[[EventDict], None]

_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/usb.h>

BPF_PERF_OUTPUT(usb_events);

struct usb_event_t {
    u32 pid;
    char comm[16];
};

int kprobe__usb_submit_urb(struct pt_regs *ctx, struct urb *urb) {
    struct usb_event_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    usb_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


class EBPFUSBMonitor:
    """
    USB monitor using BCC eBPF kprobe on usb_submit_urb.

    Mirrors the USBMonitor API: start() / stop().
    Falls back gracefully to udev/poll if BCC is unavailable.
    """

    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._bcc_available = False
        try:
            import bcc  # type: ignore  # noqa: F401
            self._bcc_available = True
        except ImportError:
            logger.debug("BCC not available; EBPFUSBMonitor will use udev fallback")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        if self._bcc_available:
            target = self._ebpf_loop
            self._thread = threading.Thread(
                target=target,
                args=(self._callback, self._stop),
                daemon=True,
                name="ebpf-usb-monitor",
            )
        else:
            from agent.usb_monitor import _udev_monitor_loop
            self._thread = threading.Thread(
                target=_udev_monitor_loop,
                args=(self._callback, self._stop),
                daemon=True,
                name="ebpf-usb-monitor",
            )
        self._thread.start()
        mode = "eBPF" if self._bcc_available else "udev fallback"
        logger.info("EBPFUSBMonitor started (%s)", mode)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("EBPFUSBMonitor stopped")

    def _ebpf_loop(self, callback: EventCallback, stop_event: threading.Event) -> None:
        """Run BCC eBPF program and dispatch events."""
        import datetime
        from agent.config import HOSTNAME

        try:
            from bcc import BPF  # type: ignore

            bpf = BPF(text=_BPF_PROGRAM)

            def _handle_event(cpu, data, size):
                event = bpf["usb_events"].event(data)
                evt: EventDict = {
                    "event_type": "connected",
                    "device_id": "ebpf:unknown",
                    "serial": "",
                    "manufacturer": "",
                    "product": "",
                    "bus_path": f"ebpf:pid={event.pid}",
                    "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "hostname": HOSTNAME,
                    "transfer_bytes": 0,
                }
                callback(evt)

            bpf["usb_events"].open_perf_buffer(_handle_event)
            logger.info("eBPF kprobe on usb_submit_urb active")

            while not stop_event.is_set():
                try:
                    bpf.perf_buffer_poll(timeout=200)
                except KeyboardInterrupt:
                    break
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("eBPF loop failed: %s – falling back to udev", exc)
            from agent.usb_monitor import _udev_monitor_loop
            _udev_monitor_loop(callback, stop_event)
