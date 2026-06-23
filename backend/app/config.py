from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PhishGuard AI"
    max_email_bytes: int = Field(default=250_000, ge=10_000, le=2_000_000)
    model_path: str = "models/phishguard-v2.joblib"
    allowed_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:8080,http://127.0.0.1:8080"
    )
    log_level: str = "INFO"
    api_key: str = ""
    trusted_hosts: str = "localhost,127.0.0.1,testserver"
    mailbox_host: str = ""
    mailbox_port: int = Field(default=993, ge=1, le=65_535)
    mailbox_username: str = ""
    mailbox_password: str = ""
    mailbox_oauth2_token: str = ""
    mailbox_folder: str = "INBOX"
    mailbox_poll_seconds: int = Field(default=300, ge=30, le=86_400)
    mailbox_max_messages: int = Field(default=25, ge=1, le=250)
    mailbox_alert_threshold: float = Field(default=70.0, ge=0.0, le=100.0)
    mailbox_state_path: str = "/tmp/phishguard-mailbox-state.json"
    mailbox_alert_path: str = "/tmp/phishguard-alerts.jsonl"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="PHISHGUARD_")

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def hosts(self) -> list[str]:
        return [host.strip() for host in self.trusted_hosts.split(",") if host.strip()]


settings = Settings()
