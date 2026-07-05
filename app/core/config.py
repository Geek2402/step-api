from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # General
    PROJECT_NAME: str = "Step Auth as Service"
    API_V1_PREFIX: str = "/v1"
    ENVIRONMENT: str = "development"

    # Platform frontend (for User password reset links).
    # Empty = forgot-password returns the raw token instead of a link.
    FRONTEND_URL: str = ""

    # Database
    DATABASE_URL: str

    # Redis (OTP + JWT blacklist)
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT — two distinct secrets, one per actor type
    JWT_SECRET_USERS: str = "change-me-users-secret"
    JWT_SECRET_END_USERS: str = "change-me-end-users-secret"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 30

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
