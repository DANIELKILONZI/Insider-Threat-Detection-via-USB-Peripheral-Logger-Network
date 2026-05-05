"""Agent configuration via environment variables."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentConfig(BaseSettings):
    agent_id: str = "agent-001"
    server_url: str = "https://localhost:8443"
    api_key: str = ""
    cert_path: str = ""
    key_path: str = ""
    ca_cert_path: str = ""
    chain_db_path: str = "chain.db"
    poll_interval: int = 5
    anchor_interval: int = 300
    off_hours_start: int = 18
    off_hours_end: int = 8

    model_config = SettingsConfigDict(env_prefix="AGENT_")


config = AgentConfig()
