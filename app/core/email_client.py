import aiosmtplib
from email.message import EmailMessage

from app.core.config import settings


async def send_otp_email(to_email: str, code: str, purpose: str) -> None:
    message = EmailMessage()
    message["From"] = settings.SMTP_FROM
    message["To"] = to_email
    message["Subject"] = "Votre code de vérification"
    message.set_content(
        f"Votre code de vérification ({purpose}) est : {code}\n"
        f"Il expire dans {settings.OTP_TTL_SECONDS // 60} minutes.\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
    )

    if not settings.SMTP_USER:
        # Mode dev sans SMTP configuré : on log au lieu d'envoyer
        print(f"[DEV] OTP pour {to_email} ({purpose}): {code}")
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
    """reset_value est soit un lien complet (si un frontend est configuré), soit le token brut."""
    message = EmailMessage()
    message["From"] = settings.SMTP_FROM
    message["To"] = to_email
    message["Subject"] = "Réinitialisation de votre mot de passe"
    message.set_content(
        f"Voici votre lien/jeton de réinitialisation de mot de passe :\n\n{reset_value}\n\n"
        f"Il expire dans {ttl_minutes} minutes.\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
    )

    if not settings.SMTP_USER:
        print(f"[DEV] Reset password pour {to_email} : {reset_value}")
        return

    await aiosmtplib.send(
        message,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_USE_TLS,
    )

