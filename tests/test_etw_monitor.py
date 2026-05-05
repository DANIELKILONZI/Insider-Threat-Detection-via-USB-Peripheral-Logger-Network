"""Tests for ETW monitor (import & platform guard, VID:PID extraction)."""
import pytest


def test_etw_monitor_importable():
    """Module must import on any platform without errors."""
    from agent.monitor import etw_monitor  # noqa: F401


def test_etw_monitor_raises_on_non_windows():
    """monitor() must raise ImportError when not on Windows."""
    from agent.monitor.etw_monitor import ETWMonitor
    import platform

    if platform.system() == "Windows":
        pytest.skip("This test is for non-Windows platforms only")

    m = ETWMonitor(agent_id="test-agent")
    with pytest.raises(ImportError, match="Windows"):
        next(m.monitor())


def test_extract_vid_pid_from_pnp_string():
    from agent.monitor.etw_monitor import _extract_vid_pid

    result = _extract_vid_pid(r"USB\VID_0781&PID_5567\123456")
    assert result == "0781:5567"


def test_extract_vid_pid_fallback():
    from agent.monitor.etw_monitor import _extract_vid_pid

    result = _extract_vid_pid("UnknownDeviceString")
    assert result == "UnknownDeviceString"


def test_extract_vid_pid_case_insensitive():
    from agent.monitor.etw_monitor import _extract_vid_pid

    result = _extract_vid_pid(r"USB\vid_DEAD&pid_BEEF\001")
    assert result == "dead:beef"
