from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # General
    PROJECT_NAME: str = "Step Auth as Service"
    API_V1_PREFIX: str = "/v1"
    ENVIRONMENT: str = "development"

    # CORS — list of allowed origins, comma-separated in the env var
    # (e.g. "https://app.example.com,https://admin.example.com"). Empty = no origin allowed.
    # `NoDecode` disables the JSON pre-parsing that pydantic-settings applies by default to complex
    # types (list/dict): without it, an env value "a,b,c" would be passed to json.loads and raise
    # an error before the validator below could split it.
    ALLOWED_ORIGINS: Annotated[list[str], NoDecode] = ["http://localhost:3000"]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def _split_allowed_origins(cls, value):
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    # Platform frontend (for User password reset links).
    # Empty = forgot-password returns the raw token instead of a link.
    FRONTEND_URL: str = "http://localhost:3000/auth/reset-password"

    # This API's own public base URL, used to build absolute asset URLs
    # (e.g. the logo embedded in transactional emails).
    API_BASE_URL: str = "http://localhost:8000"

    # Database
    DATABASE_URL: str

    # Redis (OTP + JWT blacklist)
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT — two distinct secrets, one per actor type
    JWT_SECRET_USERS: str = "change-me-users-secret"
    JWT_SECRET_END_USERS: str = "change-me-end-users-secret"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 1440

    # OTP
    OTP_TTL_SECONDS: int = 300
    OTP_LENGTH: int = 6
    OTP_MAX_ATTEMPTS: int = 5

    # App tokens (random secrets, not JWTs)
    APP_TOKEN_BYTES: int = 32
    APP_TOKEN_PREFIX: str = "app_live_"

    # Transactional email via the Brevo HTTP API. Outbound SMTP (ports 25/465/587) is blocked by
    # most PaaS (Railway, Render…) to fight spam; the HTTPS API goes over port 443, never filtered.
    # An empty `BREVO_API_KEY` = dev mode: the OTP / reset link is printed to the logs instead of
    # being actually sent.
    BREVO_API_KEY: str = ""
    BREVO_API_URL: str = "https://api.brevo.com/v3/smtp/email"
    EMAIL_FROM: str = "no-reply@step.dev"
    EMAIL_FROM_NAME: str = "Step"


settings = Settings()
