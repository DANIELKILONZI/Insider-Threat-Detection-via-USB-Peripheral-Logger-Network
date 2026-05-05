"""eBPF telemetry monitor for Linux using BCC.

Attaches kprobes to usb_submit_urb and hci_event_packet.
Falls back with ImportError if BCC is not installed.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterator

from shared.schema import NormalizedEvent

logger = logging.getLogger(__name__)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/usb.h>

BPF_PERF_OUTPUT(usb_events);
BPF_PERF_OUTPUT(bt_events);

struct usb_data_t {
    u32 pid;
    u64 timestamp;
    char comm[16];
};

int kprobe__usb_submit_urb(struct pt_regs *ctx) {
    struct usb_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    usb_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__hci_event_packet(struct pt_regs *ctx) {
    struct usb_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bt_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


class EBPFMonitor:
    """Monitor USB and BT events at the kernel level via eBPF (BCC)."""

    def __init__(self, agent_id: str, actor: str = "kernel") -> None:
        self.agent_id = agent_id
        self.actor = actor
        self._events: list = []

    def monitor(self) -> Iterator[NormalizedEvent]:
        """Load eBPF program and yield events. Requires root + BCC."""
        try:
            from bcc import BPF  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "BCC is required for eBPF monitoring. "
                "Install BCC tools: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
            ) from exc

        b = BPF(text=BPF_PROGRAM)

        def handle_usb(cpu, data, size):
            event = b["usb_events"].event(data)
            ts = datetime.now(timezone.utc)
            self._events.append(
                NormalizedEvent(
                    agent_id=self.agent_id,
                    actor=event.comm.decode("utf-8", errors="replace"),
                    device_id=f"ebpf:usb:{event.pid}",
                    action="connect",
                    source_type="usb",
                    raw={"pid": event.pid, "ktime_ns": event.timestamp},
                    confidence=1.0,
                    timestamp=ts,
                )
            )

        def handle_bt(cpu, data, size):
            event = b["bt_events"].event(data)
            ts = datetime.now(timezone.utc)
            self._events.append(
                NormalizedEvent(
                    agent_id=self.agent_id,
                    actor=event.comm.decode("utf-8", errors="replace"),
                    device_id=f"ebpf:bt:{event.pid}",
                    action="scan",
                    source_type="bluetooth",
                    raw={"pid": event.pid, "ktime_ns": event.timestamp},
                    confidence=1.0,
                    timestamp=ts,
                )
            )

        b["usb_events"].open_perf_buffer(handle_usb)
        b["bt_events"].open_perf_buffer(handle_bt)

        while True:
            b.perf_buffer_poll(timeout=200)
            while self._events:
                yield self._events.pop(0)
