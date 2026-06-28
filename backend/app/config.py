from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PhishGuard AI"
    max_email_bytes: int = Field(default=250_000, ge=10_000, le=2_000_000)
    model_path: str = "models/phishguard-v3.joblib"
    allowed_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080"
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
    mailbox_history_path: str = "/tmp/phishguard-mailbox-history.jsonl"
    suspicious_threshold: float = Field(default=35.0, ge=1.0, le=99.0)
    likely_phishing_threshold: float = Field(default=70.0, ge=1.0, le=99.0)
    rate_limit_requests: int = Field(default=120, ge=10, le=10_000)
    rate_limit_window_seconds: int = Field(default=60, ge=10, le=3_600)
    database_enabled: bool = True
    database_url: str = "sqlite:////tmp/phishguard.sqlite3"
    database_path: str = "/tmp/phishguard.sqlite3"
    store_email_bodies: bool = False
    scan_retention_days: int = Field(default=30, ge=1, le=365)
    auth_mode: str = "demo-headers"
    threat_intel_enabled: bool = False
    threat_intel_providers: str = "google_safe_browsing,virustotal,urlhaus"
    trusted_domains: str = ""
    trusted_senders: str = ""
    protected_brands: str = "microsoft,google,apple,paypal,amazon,netflix,docusign,dropbox"
    max_attachment_bytes: int = Field(default=2_000_000, ge=10_000, le=10_000_000)
    feedback_path: str = "/tmp/phishguard-feedback.jsonl"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="PHISHGUARD_")

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def hosts(self) -> list[str]:
        return [host.strip() for host in self.trusted_hosts.split(",") if host.strip()]

    @property
    def trusted_domain_list(self) -> list[str]:
        return [
            domain.strip().lower().lstrip("@") for domain in self.trusted_domains.split(",") if domain.strip()
        ]

    @property
    def trusted_sender_list(self) -> list[str]:
        return [sender.strip().lower() for sender in self.trusted_senders.split(",") if sender.strip()]

    @property
    def protected_brand_list(self) -> list[str]:
        return [brand.strip().lower() for brand in self.protected_brands.split(",") if brand.strip()]

    @property
    def threat_intel_provider_list(self) -> list[str]:
        return [
            provider.strip().lower()
            for provider in self.threat_intel_providers.split(",")
            if provider.strip()
        ]


settings = Settings()
