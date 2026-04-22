from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Security Module"
    app_env: str = "dev"
    api_prefix: str = "/api/v1"

    # Risk thresholds
    block_threshold: float = 0.80
    safe_mode_threshold: float = 0.50

    # Limits
    max_prompt_chars: int = 4000

    # LLM
    llm_mode: str = "mock"  # mock | real
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()