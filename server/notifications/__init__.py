"""
server.notifications – Delivers alerts and events to the outside world.

Every sink here is best-effort and must never raise into the ingest path: a
failing SMTP server or unreachable SIEM degrades notification, not collection.

  ``notifiers``          email and Slack alert delivery, severity-gated
  ``splunk_forwarder``   Splunk HTTP Event Collector client
  ``es_forwarder``       Elasticsearch Bulk API client
"""
