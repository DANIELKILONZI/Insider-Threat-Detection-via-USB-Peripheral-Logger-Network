"""
deploy/agent-windows-service.py – Windows service wrapper for the ITDN agent.

Install:
    python agent-windows-service.py install
    python agent-windows-service.py start

Requires: pywin32 (pip install pywin32)
"""

from __future__ import annotations

import sys
import os

try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    import win32api

    class ITDNAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "ITDNAgent"
        _svc_display_name_ = "ITDN Endpoint Agent"
        _svc_description_ = "Insider Threat Detection Network – USB/BT peripheral logger."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._process = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            if self._process:
                self._process.terminate()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            import subprocess
            python_exe = sys.executable
            work_dir = os.environ.get("ITDN_WORKDIR", r"C:\Program Files\ITDN")
            self._process = subprocess.Popen(
                [python_exe, "-m", "agent.main"],
                cwd=work_dir,
            )
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ""),
            )

    if __name__ == "__main__":
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(ITDNAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(ITDNAgentService)

except ImportError:
    print("pywin32 is not installed. Install with: pip install pywin32", file=sys.stderr)
    sys.exit(1)
