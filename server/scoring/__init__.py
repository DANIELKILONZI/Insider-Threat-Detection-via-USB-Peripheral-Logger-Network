"""
server.scoring – Quantifies how bad detected activity is.

Where :mod:`server.detection` answers "is this suspicious?", this package
answers "how much should we care?" — turning alerts and observed history into
per-host risk numbers and behavioural baselines.

  ``risk_scoring``  per-host cumulative risk score, weighted by alert severity
  ``baseline``      per-host known-device profiling
"""
