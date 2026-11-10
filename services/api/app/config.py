from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"

    database_url: str = (
        "postgresql+psycopg://ai_soc:change_me@127.0.0.1:5432/ai_soc"
    )

    # Wazuh Indexer integration
    wazuh_indexer_url: str | None = None
    wazuh_indexer_username: str | None = None
    wazuh_indexer_password: str | None = None
    wazuh_indexer_ca: str | None = None
    wazuh_indexer_timeout: float = 15.0
    # Operator-owned configuration; empty means incremental sync is disabled.
    wazuh_sync_scopes: dict[str, dict] = Field(default_factory=dict, max_length=100)
    wazuh_sync_lease_seconds: int = Field(default=120, ge=30, le=900, strict=True)
    wazuh_scheduler_enabled: bool = False
    wazuh_scheduler_jobs: dict[str, dict] = Field(default_factory=dict, max_length=100)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
