"""
agent.monitor – Event sources that observe peripheral activity on an endpoint.

Every monitor follows the same contract: construct with ``callback=``, then
``start()`` a daemon thread that invokes the callback with one plain event
dict per observation, and ``stop()`` to join it.  The event schema is defined
in :mod:`agent.monitor.usb_monitor`.

  ``usb_monitor``   USB via Linux udev, Windows ETW/WMI, or polling fallback
  ``bt_monitor``    Bluetooth via bluetoothctl (Linux) or WMI (Windows)
  ``ebpf_monitor``  kernel-level USB capture via BCC on supported Linux kernels
  ``etw_monitor``   Windows ETW backend used by ``usb_monitor``
"""
