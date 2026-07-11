from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # General
    PROJECT_NAME: str = "Step Auth as Service"
    API_V1_PREFIX: str = "/v1"
    ENVIRONMENT: str = "development"

    # CORS — liste d'origines autorisées, séparées par des virgules dans l'env
    # (ex: "https://app.example.com,https://admin.example.com"). Vide = aucune origine autorisée.
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]

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

    # SMTP
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "no-reply@step.dev"
    SMTP_USE_TLS: bool = True


settings = Settings()
