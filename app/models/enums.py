from enum import Enum


class ActorType(str, Enum):
    """Qui est à l'origine d'un événement d'audit."""

    USER = "user"
    END_USER = "end_user"
    APP = "app"  # authentification par X-App-Token sans identité User/EndUser établie
    SYSTEM = "system"


class AuditEventType(str, Enum):
    """Catalogue complet des événements tracés dans AuditLog."""

    # ---------- User : authentification ----------
    USER_REGISTERED = "user_registered"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_OTP_REQUESTED = "user_otp_requested"
    USER_OTP_VERIFY_FAILED = "user_otp_verify_failed"
    USER_LOGIN_SUCCESS = "user_login_success"
    USER_LOGOUT = "user_logout"
    USER_PASSWORD_RESET_REQUESTED = "user_password_reset_requested"
    USER_PASSWORD_RESET_FAILED = "user_password_reset_failed"
    USER_PASSWORD_RESET_COMPLETED = "user_password_reset_completed"

    # ---------- User : CRUD ----------
    USER_READ = "user_read"
    USER_LIST = "user_list"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"
    USER_PROMOTED_ADMIN = "user_promoted_admin"
    USER_DEMOTED_ADMIN = "user_demoted_admin"

    # ---------- EndUser : authentification ----------
    END_USER_REGISTERED = "end_user_registered"
    END_USER_LOGIN_FAILED = "end_user_login_failed"
    END_USER_OTP_REQUESTED = "end_user_otp_requested"
    END_USER_OTP_VERIFY_FAILED = "end_user_otp_verify_failed"
    END_USER_LOGIN_SUCCESS = "end_user_login_success"
    END_USER_LOGOUT = "end_user_logout"
    END_USER_PASSWORD_RESET_REQUESTED = "end_user_password_reset_requested"
    END_USER_PASSWORD_RESET_FAILED = "end_user_password_reset_failed"
    END_USER_PASSWORD_RESET_COMPLETED = "end_user_password_reset_completed"

    # ---------- EndUser : CRUD ----------
    END_USER_READ = "end_user_read"
    END_USER_LIST = "end_user_list"
    END_USER_UPDATED = "end_user_updated"
    END_USER_DELETED = "end_user_deleted"
    END_USER_ACTIVATED = "end_user_activated"
    END_USER_DEACTIVATED = "end_user_deactivated"

    # ---------- App : CRUD ----------
    APP_CREATED = "app_created"
    APP_READ = "app_read"
    APP_LIST = "app_list"
    APP_UPDATED = "app_updated"
    APP_DELETED = "app_deleted"
    APP_ACTIVATED = "app_activated"
    APP_DEACTIVATED = "app_deactivated"
    APP_TOKEN_ROTATED = "app_token_rotated"

    # ---------- Sécurité transverse ----------
    APP_TOKEN_INVALID = "app_token_invalid"
    RATE_LIMIT_TRIGGERED = "rate_limit_triggered"
    ACCESS_DENIED = "access_denied"

    # ---------- Audit trail lui-même ----------
    AUDIT_LOG_LIST = "audit_log_list"
