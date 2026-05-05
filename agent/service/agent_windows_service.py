"""
Windows Service wrapper for the Insider Threat Detection Agent.

Installation with NSSM (recommended):
    nssm install InsiderThreatAgent "C:\\Python311\\python.exe" "-m agent.main"
    nssm set InsiderThreatAgent AppDirectory "C:\\opt\\insider-threat-agent"
    nssm set InsiderThreatAgent AppRestartDelay 5000
    nssm start InsiderThreatAgent

Alternatively, install as a native Windows Service using pywin32:
    python agent\\service\\agent_windows_service.py install
    python agent\\service\\agent_windows_service.py start
"""
import sys

try:
    import servicemanager  # type: ignore
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore

    class InsiderThreatAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "InsiderThreatAgent"
        _svc_display_name_ = "Insider Threat Detection Agent"
        _svc_description_ = (
            "Monitors USB/Bluetooth events for insider threat detection."
        )

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
            import subprocess

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self._process = subprocess.Popen(
                [sys.executable, "-m", "agent.main"],
                cwd="C:\\opt\\insider-threat-agent",
            )
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

    if __name__ == "__main__":
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(InsiderThreatAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(InsiderThreatAgentService)

except ImportError:
    # pywin32 not available (non-Windows platform)
    pass
