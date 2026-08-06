import httpx

from app.core.config import settings


async def _send_email(to_email: str, subject: str, text_content: str, html_content: str) -> None:
    """Sends a transactional email through the Brevo HTTP API.

    When no API key is configured (local/dev mode), the content is simply logged instead of being
    sent, so development does not depend on an external service. Any transport or non-2xx error
    propagates to the caller, which wraps it into an EmailDeliveryError.
    """
    if not settings.BREVO_API_KEY:
        # Dev mode without an email provider configured: log instead of sending.
        print(f"[DEV] Email to {to_email} | {subject}\n{text_content}")
        return

    payload = {
        "sender": {"name": settings.EMAIL_FROM_NAME, "email": settings.EMAIL_FROM},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": text_content,
        "htmlContent": html_content,
    }
    headers = {
        "api-key": settings.BREVO_API_KEY,
        "accept": "application/json",
        "content-type": "application/json",
    }
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(settings.BREVO_API_URL, json=payload, headers=headers)
        response.raise_for_status()


def _otp_email_html(to_email: str, code: str, ttl_minutes: int) -> str:
    """Builds the OTP verification email body, styled after Step's design system.
    Email clients can't read CSS custom properties (or oklch()), so every color
    here is the resolved hex value of the matching `--step-*` token in `globals.css`.
    """
    logo_url = f"{settings.API_BASE_URL}/static/logo.png"
    spaced_code = " ".join(code)

    return f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background-color:#0a0b0f;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0a0b0f;">
      <tr>
        <td align="center" style="padding:40px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0"
                 style="max-width:480px;width:100%;background-color:#0e0f16;border:1px solid #23252e;
                        border-radius:14px;overflow:hidden;">
            <tr>
              <td style="padding:28px 32px;text-align:center;border-bottom:1px solid #1c1d24;">
                <img src="{logo_url}" alt="Step" width="120" style="display:block;margin:0 auto;border:0;" />
              </td>
            </tr>
            <tr>
              <td style="padding:32px;">
                <h1 style="margin:0 0 10px 0;font-family:'Space Grotesk',Arial,sans-serif;font-size:20px;
                           font-weight:700;color:#F5F6FA;">
                  Votre code de vérification
                </h1>
                <p style="margin:0 0 24px 0;font-family:Arial,sans-serif;font-size:14px;line-height:1.6;color:#AEB1C2;">
                  Voici le code à saisir pour vous connecter avec
                  <strong style="color:#F0F1F5;">{to_email}</strong>.
                </p>
                <div style="margin:0 0 28px 0;padding:18px;background-color:#0a0b0f;border:1px solid #23252e;
                            border-radius:10px;text-align:center;">
                  <span style="font-family:'JetBrains Mono',Consolas,monospace;font-size:32px;font-weight:700;
                               letter-spacing:8px;color:#F5F6FA;">
                    {spaced_code}
                  </span>
                </div>
                <p style="margin:0;font-family:Arial,sans-serif;font-size:12.5px;color:#6B6E7D;">
                  Ce code expire dans {ttl_minutes} minutes. Si vous n'êtes pas à l'origine de cette demande,
                  ignorez simplement cet email.
                </p>
              </td>
            </tr>
            <tr>
              <td style="padding:20px 32px 28px 32px;border-top:1px solid #1c1d24;">
                <p style="margin:0;font-family:Arial,sans-serif;font-size:13px;line-height:1.6;color:#7D8091;">
                  Here is the code to sign in with <strong style="color:#AEB1C2;">{to_email}</strong>. It expires
                  in {ttl_minutes} minutes. If you didn't request this, you can safely ignore this email.
                </p>
              </td>
            </tr>
          </table>
          <p style="margin:20px 0 0 0;font-family:Arial,sans-serif;font-size:12px;color:#5C5F6D;">
            Step &mdash; Auth as a Service
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""


async def send_otp_email(to_email: str, code: str, purpose: str) -> None:
    ttl_minutes = settings.OTP_TTL_SECONDS // 60
    text_content = (
        f"Your verification code is: {code}\n"
        f"It expires in {ttl_minutes} minutes.\n\n"
        "If you did not request this, please ignore this email."
    )
    await _send_email(
        to_email,
        "Votre code de vérification — Step",
        text_content,
        _otp_email_html(to_email, code, ttl_minutes),
    )


def _reset_password_html(to_email: str, reset_value: str, ttl_minutes: int) -> str:
    """Builds the password reset email body, styled after Step's design system.
    Email clients can't read CSS custom properties (or oklch()), so every color
    here is the resolved hex value of the matching `--step-*` token in `globals.css`.
    """
    logo_url = f"{settings.API_BASE_URL}/static/logo.png"
    is_link = reset_value.startswith("http://") or reset_value.startswith("https://")

    if is_link:
        action_html = f"""
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto 28px auto;">
                  <tr>
                    <td style="border-radius:10px;background:linear-gradient(135deg,#6D6AF0,#A855F7);">
                      <a href="{reset_value}"
                         style="display:inline-block;padding:14px 28px;font-family:'Space Grotesk',Arial,sans-serif;
                                font-size:15px;font-weight:600;color:#0a0b0f;text-decoration:none;border-radius:10px;">
                        Réinitialiser mon mot de passe &rarr;
                      </a>
                    </td>
                  </tr>
                </table>"""
    else:
        action_html = f"""
                <div style="margin:0 0 28px 0;padding:16px;background-color:#0a0b0f;border:1px solid #23252e;
                            border-radius:10px;font-family:'JetBrains Mono',Consolas,monospace;font-size:14px;
                            color:#F0F1F5;word-break:break-all;text-align:center;">
                  {reset_value}
                </div>"""

    return f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background-color:#0a0b0f;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0a0b0f;">
      <tr>
        <td align="center" style="padding:40px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0"
                 style="max-width:480px;width:100%;background-color:#0e0f16;border:1px solid #23252e;
                        border-radius:14px;overflow:hidden;">
            <tr>
              <td style="padding:28px 32px;text-align:center;border-bottom:1px solid #1c1d24;">
                <img src="{logo_url}" alt="Step" width="120" style="display:block;margin:0 auto;border:0;" />
              </td>
            </tr>
            <tr>
              <td style="padding:32px;">
                <h1 style="margin:0 0 10px 0;font-family:'Space Grotesk',Arial,sans-serif;font-size:20px;
                           font-weight:700;color:#F5F6FA;">
                  Réinitialisation de mot de passe
                </h1>
                <p style="margin:0 0 24px 0;font-family:Arial,sans-serif;font-size:14px;line-height:1.6;color:#AEB1C2;">
                  Vous avez demandé la réinitialisation du mot de passe associé à
                  <strong style="color:#F0F1F5;">{to_email}</strong>. Cliquez sur le bouton ci-dessous pour
                  choisir un nouveau mot de passe.
                </p>
                {action_html}
                <p style="margin:0;font-family:Arial,sans-serif;font-size:12.5px;color:#6B6E7D;">
                  Ce lien expire dans {ttl_minutes} minutes. Si vous n'êtes pas à l'origine de cette demande,
                  ignorez simplement cet email.
                </p>
              </td>
            </tr>
            <tr>
              <td style="padding:20px 32px 28px 32px;border-top:1px solid #1c1d24;">
                <p style="margin:0;font-family:Arial,sans-serif;font-size:13px;line-height:1.6;color:#7D8091;">
                  You requested a password reset for <strong style="color:#AEB1C2;">{to_email}</strong>. Use the
                  button above to set a new password. This link expires in {ttl_minutes} minutes. If you didn't
                  request this, you can safely ignore this email.
                </p>
              </td>
            </tr>
          </table>
          <p style="margin:20px 0 0 0;font-family:Arial,sans-serif;font-size:12px;color:#5C5F6D;">
            Step &mdash; Auth as a Service
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""


async def send_reset_password_email(to_email: str, reset_value: str, ttl_minutes: int) -> None:
    """reset_value is either a full link (if a frontend is configured) or the raw token."""
    text_content = (
        f"Here is your password reset link/token:\n\n{reset_value}\n\n"
        f"It expires in {ttl_minutes} minutes.\n\n"
        "If you did not request this, please ignore this email."
    )
    await _send_email(
        to_email,
        "Réinitialisation de mot de passe — Step",
        text_content,
        _reset_password_html(to_email, reset_value, ttl_minutes),
    )

