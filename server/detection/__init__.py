"""
server.detection – Decides whether activity is suspicious.

Everything here answers "is this event or pattern a problem?" and is free of
HTTP and persistence concerns: rules take an event plus a database handle and
return :class:`~server.detection.rules.Alert` objects.

  ``rules``         6-rule anomaly detection engine
  ``rule_config``   runtime-adjustable rule thresholds
  ``anomaly``       z-score statistical anomaly detector
  ``attack_graph``  lateral-movement graph builder
  ``honeypot``      honeypot VID matching
  ``threat_feed``   known-bad device identifier feed

Submodules are imported directly (``from server.detection.rules import
evaluate``); this package intentionally re-exports nothing, so that importing
one detector never drags in the others.
"""
