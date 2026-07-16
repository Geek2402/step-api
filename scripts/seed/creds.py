import sys
from getpass import getpass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import decode_token

from . import http
from .db_checks import get_user_by_email
from .otp import resolve_otp
from .state import AccountSession

MAX_ATTEMPTS = 5


def _prompt_credentials(role_label: str) -> tuple[str, str]:
    email = input(f"Email for the existing {role_label} account: ").strip()
    password = getpass(f"Password for {email}: ")
    return email, password


async def verify_account(
    base_url: str, redis, session: AsyncSession, role_label: str, expect_admin: bool
) -> AccountSession:
    """Real login flow (email+password -> OTP -> verify-otp) against the running API, for
    an operator-supplied admin/dev account. Stops the whole script (sys.exit) if credentials
    don't check out after 5 attempts, the account is disabled, or the role doesn't match."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        email, password = _prompt_credentials(role_label)
        if not email or not password:
            print(f"[{attempt}/{MAX_ATTEMPTS}] Email and password are required. Go create the "
                  f"{role_label} account first if it doesn't exist yet.")
            continue

        status, body = http.request(
            "POST", f"{base_url}/users/auth/login", {"email": email, "password": password}
        )
        if status == 401:
            print(f"[{attempt}/{MAX_ATTEMPTS}] Login failed (wrong credentials or unknown account). Try again.")
            continue
        if status == 403:
            print(f"The '{role_label}' account exists but is deactivated. Reactivate it first, then re-run.")
            sys.exit(1)
        if status == 429:
            print(f"Rate-limited by the API itself for '{email}'. Wait 15 minutes or use a different account.")
            sys.exit(1)
        if status != 200:
            print(f"[{attempt}/{MAX_ATTEMPTS}] Unexpected response ({status}: {body}). Try again.")
            continue

        user = await get_user_by_email(session, email)
        if user is None:
            print(f"[{attempt}/{MAX_ATTEMPTS}] Could not find this user in the database right after login. Try again.")
            continue

        code = await resolve_otp(redis, "user", str(user.id))
        status, body = http.request(
            "POST", f"{base_url}/users/auth/verify-otp", {"email": email, "code": code}
        )
        if status != 200:
            print(f"[{attempt}/{MAX_ATTEMPTS}] OTP verification unexpectedly failed ({status}: {body}). Try again.")
            continue

        token = body["access_token"]
        payload = decode_token(token, settings.JWT_SECRET_USERS)
        if payload["is_admin"] != expect_admin:
            expected_role = "admin" if expect_admin else "non-admin (dev)"
            print(
                f"Role mismatch for '{email}': expected a {expected_role} account, "
                f"but is_admin={payload['is_admin']}. Stopping."
            )
            sys.exit(1)

        return AccountSession(
            email=email,
            actor_id=user.id,
            token=token,
            jti=payload["jti"],
            kind="user",
            is_admin=expect_admin,
        )

    print(f"{MAX_ATTEMPTS} failed attempts for the {role_label} account. Stopping.")
    sys.exit(1)
