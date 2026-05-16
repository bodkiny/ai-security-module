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
        "SYSTEM_PROMPT_TRANSLATION",
        "MODEL_WEIGHTS_EXFILTRATION",
        "CHILD_EXPLOITATION_REQUEST",
        "WEAPON_INSTRUCTIONS_REQUEST",
        "SENSITIVE_DATA_EXFILTRATION",
        "SECRET_LEAK_REQUEST",
        "DESTRUCTIVE_COMMAND_REQUEST",
        "POLICY_EVASION",
        "ROLE_OVERRIDE",
        "SECURITY_BYPASS_REQUEST",
    ]
    safe_mode_reasons: list[str] = [
        "INJECTION_PATTERN_DETECTED",
        "OBFUSCATED_INJECTION_PATTERN",
        "OBFUSCATION_NORMALIZED",
        "ROLE_LABELS_PRESENT",
        "ENCODING_OBFUSCATION_HINTS",
        "INSTRUCTION_OVERRIDE",
        "INSTRUCTION_IGNORE_FOLLOWING",
        "INSTRUCTION_IGNORE_RULES",
        "INSTRUCTION_IGNORE_CONTEXT",
        "SYSTEM_PROMPT_TRANSLATION",
        "SYSTEM_INSTRUCTION_FORMATTING",
        "FORCE_MODEL_BEHAVIOR",
        "RESEARCH_BYPASS_JUSTIFICATION",
        "UNAUTHORIZED_INFO_REQUEST",
        "UNRESTRICTED_MODE",
        "SAFETY_BYPASS_REQUEST",
        "CODE_EXECUTION_REQUEST",
        "DESTRUCTIVE_COMMAND_REQUEST",
        "SENSITIVE_DATA_EXFILTRATION",
        "SECRET_LEAK_REQUEST",
        "UNCONDITIONAL_OBEDIENCE",
        "WEAPON_INSTRUCTIONS_REQUEST",
        "MARKET_MANIPULATION_REQUEST",
        "ECONOMIC_SABOTAGE_REQUEST",
        "JAILBREAK_KEYWORD",
        "INSTRUCTION_HIERARCHY_MANIPULATION",
        "ROLE_JSON_OVERRIDE",
        "PWNED_MARKER",
        "DATA_EXFILTRATION_GOAL",
        "COMMAND_EXECUTION_REQUEST",
        "EMOJI_SMUGGLING_SUSPECTED",
        "HIDDEN_UNICODE_MARKERS",
        "VARIATION_SELECTOR_EXCESS",
        "BYTE_DECODE_INSTRUCTION",
        "LOWEST_BYTE_PATTERN",
        "HIDDEN_TEXT_DECODING",
    ]

    # Limits
    max_prompt_chars: int = 4000

    # LLM
    llm_mode: str = "mock"  # mock | openai
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_timeout_s: float = 20.0
    rules_path: str = "app/security/rules.json"

    # Rate limiting (Redis)
    redis_url: str = "redis://localhost:6379/0"
    rate_limit_window_s: int = 60
    rate_limit_requests: int = 20
    rate_limit_burst_window_s: int = 5
    rate_limit_burst_requests: int = 5
    rate_limit_fail_open: bool = True
    rate_limit_enforce_ip: bool = False
    rate_limit_trust_proxy_headers: bool = False

    # Audit storage (Postgres)
    postgres_dsn: str = "postgresql://app:app@localhost:5432/ai_security"
    postgres_connect_timeout_s: int = 2
    audit_store_enabled: bool = True
    audit_store_fail_open: bool = True
    audit_store_init_retries: int = 10
    audit_store_init_retry_delay_s: float = 1.0
    audit_store_pool_min_size: int = 1
    audit_store_pool_max_size: int = 5
    audit_store_pool_timeout_s: float = 1.0
    monitoring_enabled: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
