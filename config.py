"""Application settings. Everything configurable lives here and is read from env."""
from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- App ---------------------------------------------------------------
    APP_NAME: str = "SentinelAI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api/v1"

    # --- Security ----------------------------------------------------------
    SECRET_KEY: str = Field(default="change-me-in-production-please-use-openssl-rand")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # --- Database ----------------------------------------------------------
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "sentinelai"

    # --- CORS --------------------------------------------------------------
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"

    # --- Gemini / LangChain ------------------------------------------------
    GOOGLE_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"
    GEMINI_TEMPERATURE: float = 0.15
    GEMINI_MAX_OUTPUT_TOKENS: int = 2048
    LLM_TIMEOUT_SECONDS: int = 25

    # --- Detection engine --------------------------------------------------
    # Fusion weights. Rules dominate on purpose: deterministic, explainable, fast.
    WEIGHT_RULES: float = 0.40
    WEIGHT_SIMILARITY: float = 0.25
    WEIGHT_STRUCTURAL: float = 0.15
    WEIGHT_LLM: float = 0.20

    RISK_THRESHOLD_CRITICAL: int = 80
    RISK_THRESHOLD_HIGH: int = 60
    RISK_THRESHOLD_SUSPICIOUS: int = 35

    # --- Rate limiting -----------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 60
    # Analysis is stricter because each call can trigger a Gemini request.
    ANALYZE_RATE_LIMIT_PER_MINUTE: int = 20

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def llm_enabled(self) -> bool:
        return bool(self.GOOGLE_API_KEY)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
