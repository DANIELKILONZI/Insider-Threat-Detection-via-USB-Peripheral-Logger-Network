"""
tests/test_etw_monitor.py – Windows ETW USB backend.

Covers the parts that are testable off-Windows: the module must import on any
platform (the agent code base is developed and tested on Linux), VID:PID
parsing, and the backend-selection precedence in
:func:`agent.monitor.usb_monitor._select_backend`.

The ETW session itself needs a Windows kernel and is not exercised here.
"""

from __future__ import annotations

import platform
import threading

import pytest

from agent.monitor import etw_monitor
from agent.monitor.etw_monitor import _extract_vid_pid


# ── Import and platform guard ────────────────────────────────────────────────

def test_module_imports_on_any_platform():
    """Import must not require Windows — the suite runs on Linux."""
    assert etw_monitor is not None


@pytest.mark.skipif(platform.system() == "Windows", reason="non-Windows behaviour")
def test_loop_raises_on_non_windows():
    with pytest.raises(ImportError, match="Windows"):
        etw_monitor.etw_monitor_loop(lambda _e: None, threading.Event())


@pytest.mark.skipif(platform.system() == "Windows", reason="non-Windows behaviour")
def test_is_available_false_off_windows():
    assert etw_monitor.is_available() is False


# ── VID:PID extraction ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "instance_id, expected",
    [
        (r"USB\VID_0781&PID_5567\4C530001", "0781:5567"),
        (r"USB\vid_dead&pid_beef\001", "dead:beef"),           # case-insensitive
        (r"USB\VID_ABCD&PID_1234", "abcd:1234"),               # no serial segment
        ("UnknownDeviceString", "UnknownDeviceString"),        # passthrough
        ("", ""),
    ],
)
def test_extract_vid_pid(instance_id, expected):
    assert _extract_vid_pid(instance_id) == expected


def test_extract_vid_pid_truncates_unparseable_input():
    """An unparseable identifier is bounded, so it cannot bloat the payload."""
    assert len(_extract_vid_pid("X" * 5000)) == 256


# ── Backend selection ────────────────────────────────────────────────────────

def _select(monkeypatch, system: str, etw_ok: bool):
    from agent.monitor import usb_monitor

    monkeypatch.setattr(usb_monitor.platform, "system", lambda: system)
    monkeypatch.setattr(etw_monitor, "is_available", lambda: etw_ok)
    return usb_monitor._select_backend()


def test_linux_uses_udev(monkeypatch):
    from agent.monitor import usb_monitor

    assert _select(monkeypatch, "Linux", False) is usb_monitor._udev_monitor_loop


def test_windows_prefers_etw(monkeypatch):
    assert _select(monkeypatch, "Windows", True) is etw_monitor.etw_monitor_loop


def test_windows_falls_back_to_wmi_without_etw(monkeypatch):
    from agent.monitor import usb_monitor

    assert _select(monkeypatch, "Windows", False) is usb_monitor._wmi_event_monitor_loop


def test_other_platforms_poll(monkeypatch):
    from agent.monitor import usb_monitor

    assert _select(monkeypatch, "Darwin", False) is usb_monitor._poll_monitor_loop
