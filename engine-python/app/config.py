"""Engine configuration."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with env override support."""

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # Analyzer toggles
    enable_prompt_injection: bool = True
    enable_obfuscation_advanced: bool = True
    enable_content_risk: bool = True

    # Scoring thresholds
    prompt_injection_weight: int = 60
    obfuscation_advanced_weight: int = 70
    content_risk_weight: int = 30

    # Request limits
    max_body_bytes: int = 1_048_576  # 1MB
    request_timeout_seconds: int = 5

    model_config = {"env_prefix": "HIPPO_ML_"}


settings = Settings()
