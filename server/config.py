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

    model_config = SettingsConfigDict(env_prefix="SERVER_")


config = ServerConfig()
