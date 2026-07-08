"""Central settings, loaded from environment / .env (prefix AISOC_)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AISOC_", env_file=".env", extra="ignore")

    # Wazuh Indexer (OpenSearch)
    indexer_url: str = "https://localhost:9200"
    indexer_user: str = "admin"
    indexer_password: str = ""
    # Lab uses self-signed certs; never disable verification outside the lab
    indexer_verify_certs: bool = False

    # Ollama (local LLM). The single active model — 7b for dev/iteration,
    # set AISOC_OLLAMA_MODEL=qwen2.5:14b-instruct in .env for the demo.
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b-instruct"

    # API backend (consumed by the dashboard)
    api_base_url: str = "http://localhost:8000"

    # Feature engineering
    window_minutes: int = 10


settings = Settings()
