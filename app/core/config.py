from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Security Module"
    app_env: str = "dev"
    api_prefix: str = "/api/v1"

    # Risk thresholds
    block_threshold: float = 0.80
    safe_mode_threshold: float = 0.50
    base_risk: float = 0.05
    long_prompt_chars: int = 2000
    long_prompt_risk: float = 0.10
    non_alnum_ratio_threshold: float = 0.35
    non_alnum_ratio_risk: float = 0.10
    multi_term_threshold: int = 3
    multi_term_bonus: float = 0.10
    hard_block_reasons: list[str] = [
        "SYSTEM_PROMPT_EXFILTRATION",
        "POLICY_EVASION",
        "ROLE_OVERRIDE",
        "SECURITY_BYPASS_REQUEST",
    ]
    safe_mode_reasons: list[str] = [
        "INJECTION_PATTERN_DETECTED",
        "OBFUSCATED_INJECTION_PATTERN",
        "ROLE_LABELS_PRESENT",
        "ENCODING_OBFUSCATION_HINTS",
        "INSTRUCTION_OVERRIDE",
        "JAILBREAK_KEYWORD",
    ]

    # Limits
    max_prompt_chars: int = 4000

    # LLM
    llm_mode: str = "mock"  # mock | real
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    rules_path: str = "app/security/rules.json"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
