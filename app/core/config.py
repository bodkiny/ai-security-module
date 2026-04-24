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
