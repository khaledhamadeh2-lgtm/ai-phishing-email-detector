from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PhishGuard AI"
    max_email_bytes: int = 250_000
    model_path: str = "models/phishguard-v1.joblib"
    allowed_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:8080,http://127.0.0.1:8080"
    )
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="PHISHGUARD_")

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


settings = Settings()
