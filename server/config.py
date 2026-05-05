"""Server configuration via environment variables."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerConfig(BaseSettings):
    database_url: str = "sqlite+aiosqlite:///./threatdb.db"
    ca_cert_path: str = "ca/ca.crt"
    ca_key_path: str = "ca/ca.key"
    server_cert_path: str = "ca/server.crt"
    server_key_path: str = "ca/server.key"
    require_mtls: bool = False
    api_key: str = "changeme"
    risk_threshold: float = 80.0
    anomaly_contamination: float = 0.1
    rolling_window_seconds: int = 3600
    host: str = "0.0.0.0"
    port: int = 8443
    # Notification sinks (comma-separated; supported: email, slack, syslog)
    notification_sinks: str = ""
    # Email sink
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = "alerts@threat-detection.local"
    smtp_to: str = ""  # comma-separated recipients
    # Slack sink
    slack_webhook_url: str = ""
    # Syslog/SIEM sink
    syslog_host: str = "localhost"
    syslog_port: int = 514
    # Rate limiting
    rate_limit_requests: int = 200
    rate_limit_window_seconds: int = 60

    model_config = SettingsConfigDict(env_prefix="SERVER_")


config = ServerConfig()
