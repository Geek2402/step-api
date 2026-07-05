import aiosmtplib
from email.message import EmailMessage

from app.core.config import settings


async def send_otp_email(to_email: str, code: str, purpose: str) -> None:
    message = EmailMessage()
    message["From"] = settings.SMTP_FROM
    message["To"] = to_email
    message["Subject"] = "Your verification code"
    message.set_content(
        f"Your verification code ({purpose}) is: {code}\n"
        f"It expires in {settings.OTP_TTL_SECONDS // 60} minutes.\n\n"
        "If you did not request this, please ignore this email."
    )

    if not settings.SMTP_USER:
        # Dev mode without SMTP configured: log instead of sending
        print(f"[DEV] OTP for {to_email} ({purpose}): {code}")
        return

    await aiosmtplib.send(
        message,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_USE_TLS,
    )


async def send_reset_password_email(to_email: str, reset_value: str, ttl_minutes: int) -> None:
    """reset_value is either a full link (if a frontend is configured) or the raw token."""
    message = EmailMessage()
    message["From"] = settings.SMTP_FROM
    message["To"] = to_email
    message["Subject"] = "Password reset"
    message.set_content(
        f"Here is your password reset link/token:\n\n{reset_value}\n\n"
        f"It expires in {ttl_minutes} minutes.\n\n"
        "If you did not request this, please ignore this email."
    )

    if not settings.SMTP_USER:
        print(f"[DEV] Password reset for {to_email}: {reset_value}")
        return

    await aiosmtplib.send(
        message,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_USE_TLS,
    )

