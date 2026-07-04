from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Général
    PROJECT_NAME: str = "Step Auth as Service"
    API_V1_PREFIX: str = "/v1"
    ENVIRONMENT: str = "development"

    # Base de données
    DATABASE_URL: str

    # Redis (OTP + blacklist JWT)
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT — deux secrets distincts, un par type d'acteur
    JWT_SECRET_USERS: str = "change-me-users-secret"
    JWT_SECRET_END_USERS: str = "change-me-end-users-secret"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 30

    # OTP
    OTP_TTL_SECONDS: int = 300
    OTP_LENGTH: int = 6
    OTP_MAX_ATTEMPTS: int = 5

    # Tokens d'application (secrets aléatoires, pas des JWT)
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
