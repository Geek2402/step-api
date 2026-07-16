import uuid

from app.core.config import settings
from app.core.security import decode_token

from . import http
from .config import pick_names, render_email
from .db_checks import get_end_user_by_app_and_email, get_user_by_email
from .otp import resolve_otp, resolve_reset_token
from .state import AccountSession, SeedRunSessions, SeedState

WRONG_PASSWORD = "WrongPassword!Zzz"
FIXTURE_USER_PASSWORD = "SeedFixture!2026x"


def _wrong_code(real: str) -> str:
    return "000000" if real != "000000" else "111111"


async def _ensure_app_token(base_url: str, owner_headers: dict, state: SeedState, owner: str, index: int) -> str:
    token = state.get_app_token(owner, index)
    if token is not None:
        return token
    app_id = state.get_app_id(owner, index)
    status, body = http.request("POST", f"{base_url}/apps/{app_id}/rotate-token", None, owner_headers)
    if status != 200:
        raise RuntimeError(f"Failed to rotate token for App {app_id} ({status}: {body})")
    state.set_app_token(owner, index, body["token"])
    return body["token"]


async def run_audit_flow(base_url: str, redis, session, sessions: SeedRunSessions, state: SeedState, seed_data: dict) -> None:
    print("Generating audit-log activity across all 44 event types...")
    admin_headers = http.auth_header(sessions.admin.token)
    dev_headers = http.auth_header(sessions.dev.token)

    admin_app0_token = await _ensure_app_token(base_url, admin_headers, state, "admin", 0)
    dev_app0_token = await _ensure_app_token(base_url, dev_headers, state, "dev", 0)
    admin_app0_id = state.get_app_id("admin", 0)
    dev_app0_id = state.get_app_id("dev", 0)

    # ---------- 1. fx_user: full User-auth lifecycle + CRUD + rate-limit + delete ----------
    print("  fx_user: register + full auth lifecycle...")
    fx_email = seed_data["fixture_user_email"]
    status, body = http.request(
        "POST", f"{base_url}/users",
        {"first_name": "Seed", "last_name": "Fixture", "email": fx_email, "password": FIXTURE_USER_PASSWORD},
    )
    if status == 409:
        # Leftover from a previous interrupted run — reuse it rather than failing.
        fx_user = await get_user_by_email(session, fx_email)
        fx_user_id = fx_user.id
    elif status == 201:
        fx_user_id = uuid.UUID(body["id"])
    else:
        raise RuntimeError(f"Failed to create fixture User ({status}: {body})")

    # USER_LOGIN_FAILED (wrong password)
    http.request("POST", f"{base_url}/users/auth/login", {"email": fx_email, "password": WRONG_PASSWORD})

    # USER_OTP_REQUESTED
    status, body = http.request(
        "POST", f"{base_url}/users/auth/login", {"email": fx_email, "password": FIXTURE_USER_PASSWORD}
    )
    if status != 200:
        raise RuntimeError(f"fx_user login failed ({status}: {body})")

    real_code = await resolve_otp(redis, "user", str(fx_user_id))

    # USER_OTP_VERIFY_FAILED (wrong code)
    http.request(
        "POST", f"{base_url}/users/auth/verify-otp", {"email": fx_email, "code": _wrong_code(real_code)}
    )

    # USER_LOGIN_SUCCESS
    status, body = http.request(
        "POST", f"{base_url}/users/auth/verify-otp", {"email": fx_email, "code": real_code}
    )
    if status != 200:
        raise RuntimeError(f"fx_user OTP verification failed ({status}: {body})")
    fx_token = body["access_token"]
    fx_payload = decode_token(fx_token, settings.JWT_SECRET_USERS)
    fx_session = AccountSession(
        email=fx_email, actor_id=fx_user_id, token=fx_token, jti=fx_payload["jti"], kind="user"
    )
    sessions.track(fx_session)
    fx_headers = http.auth_header(fx_token)

    # USER_LOGOUT
    http.request("POST", f"{base_url}/users/auth/logout", None, fx_headers)
    fx_session.blacklisted = True

    # USER_PASSWORD_RESET_REQUESTED
    http.request("POST", f"{base_url}/users/auth/forgot-password", {"email": fx_email})
    real_reset_token = await resolve_reset_token(redis, "user", fx_email)

    # USER_PASSWORD_RESET_FAILED (tampered token)
    http.request(
        "POST", f"{base_url}/users/auth/reset-password",
        {"email": fx_email, "token": real_reset_token + "tampered", "new_password": FIXTURE_USER_PASSWORD},
    )

    # USER_PASSWORD_RESET_COMPLETED
    status, body = http.request(
        "POST", f"{base_url}/users/auth/reset-password",
        {"email": fx_email, "token": real_reset_token, "new_password": FIXTURE_USER_PASSWORD},
    )
    if status != 200:
        raise RuntimeError(f"fx_user password reset failed ({status}: {body})")

    print("  fx_user: CRUD lifecycle (as admin)...")
    # USER_UPDATED
    http.request(
        "PATCH", f"{base_url}/users/{fx_user_id}", {"last_name": "Fixture-Updated"}, admin_headers
    )
    # USER_DEACTIVATED / USER_ACTIVATED
    http.request("POST", f"{base_url}/users/{fx_user_id}/deactivate", None, admin_headers)
    http.request("POST", f"{base_url}/users/{fx_user_id}/activate", None, admin_headers)
    # USER_PROMOTED_ADMIN / USER_DEMOTED_ADMIN
    http.request("POST", f"{base_url}/users/{fx_user_id}/promote-admin", None, admin_headers)
    http.request("POST", f"{base_url}/users/{fx_user_id}/demote-admin", None, admin_headers)

    print("  fx_user: tripping the User-side rate limiter (last action for this identity)...")
    # 5 wrong passwords + 1 more -> the 6th sees the 429 (RATE_LIMIT_TRIGGERED); the first
    # 5 also produce additional USER_LOGIN_FAILED entries, which is harmless.
    for _ in range(6):
        http.request("POST", f"{base_url}/users/auth/login", {"email": fx_email, "password": WRONG_PASSWORD})

    # USER_DELETED (last step of fx_user's lifecycle)
    http.request("DELETE", f"{base_url}/users/{fx_user_id}", None, admin_headers)

    # ---------- 2. Non-destructive User CRUD via the real accounts ----------
    print("  User CRUD via real admin/dev accounts...")
    http.request("GET", f"{base_url}/users/me", None, dev_headers)  # USER_READ
    http.request("GET", f"{base_url}/users", None, admin_headers)  # USER_LIST
    http.request("GET", f"{base_url}/users", None, dev_headers)  # 403 -> ACCESS_DENIED

    # ---------- 3. eu_dev: full EndUser-auth lifecycle + rate-limit (under dev_app0) ----------
    print("  eu_dev: full EndUser-auth lifecycle...")
    eu_dev_email = render_email(seed_data, "dev", 0, 0)
    dev_app_headers = http.app_token_header(dev_app0_token)

    # END_USER_LOGIN_FAILED (wrong password)
    http.request(
        "POST", f"{base_url}/end-users/auth/login",
        {"email": eu_dev_email, "password": WRONG_PASSWORD}, dev_app_headers,
    )
    # END_USER_OTP_REQUESTED
    status, body = http.request(
        "POST", f"{base_url}/end-users/auth/login",
        {"email": eu_dev_email, "password": seed_data["default_password"]}, dev_app_headers,
    )
    if status != 200:
        raise RuntimeError(f"eu_dev login failed ({status}: {body})")

    eu_dev = await get_end_user_by_app_and_email(session, dev_app0_id, eu_dev_email)
    real_code = await resolve_otp(redis, "end_user", str(eu_dev.id))

    # END_USER_OTP_VERIFY_FAILED
    http.request(
        "POST", f"{base_url}/end-users/auth/verify-otp",
        {"email": eu_dev_email, "code": _wrong_code(real_code)}, dev_app_headers,
    )
    # END_USER_LOGIN_SUCCESS
    status, body = http.request(
        "POST", f"{base_url}/end-users/auth/verify-otp",
        {"email": eu_dev_email, "code": real_code}, dev_app_headers,
    )
    if status != 200:
        raise RuntimeError(f"eu_dev OTP verification failed ({status}: {body})")
    eu_dev_token = body["access_token"]
    eu_dev_payload = decode_token(eu_dev_token, settings.JWT_SECRET_END_USERS)
    eu_dev_session = AccountSession(
        email=eu_dev_email, actor_id=eu_dev.id, token=eu_dev_token, jti=eu_dev_payload["jti"], kind="end_user",
        app_token=dev_app0_token,
    )
    sessions.track(eu_dev_session)
    eu_dev_headers = {**dev_app_headers, **http.auth_header(eu_dev_token)}

    # END_USER_READ (self)
    http.request("GET", f"{base_url}/end-users/me", None, eu_dev_headers)

    # END_USER_LOGOUT
    http.request("POST", f"{base_url}/end-users/auth/logout", None, eu_dev_headers)
    eu_dev_session.blacklisted = True

    # END_USER_PASSWORD_RESET_REQUESTED
    http.request(
        "POST", f"{base_url}/end-users/auth/forgot-password", {"email": eu_dev_email}, dev_app_headers
    )
    identifier = f"{dev_app0_id}:{eu_dev_email}"
    real_reset_token = await resolve_reset_token(redis, "end_user", identifier)

    # END_USER_PASSWORD_RESET_FAILED
    http.request(
        "POST", f"{base_url}/end-users/auth/reset-password",
        {"email": eu_dev_email, "token": real_reset_token + "tampered", "new_password": seed_data["default_password"]},
        dev_app_headers,
    )
    # END_USER_PASSWORD_RESET_COMPLETED
    status, body = http.request(
        "POST", f"{base_url}/end-users/auth/reset-password",
        {"email": eu_dev_email, "token": real_reset_token, "new_password": seed_data["default_password"]},
        dev_app_headers,
    )
    if status != 200:
        raise RuntimeError(f"eu_dev password reset failed ({status}: {body})")

    print("  eu_dev: CRUD via dev (owner)...")
    dev_owner_headers = {**dev_app_headers, **dev_headers}
    http.request("GET", f"{base_url}/end-users/{eu_dev.id}", None, dev_owner_headers)  # END_USER_READ (owner)
    http.request("GET", f"{base_url}/end-users", None, dev_owner_headers)  # END_USER_LIST
    http.request("POST", f"{base_url}/end-users/{eu_dev.id}/deactivate", None, dev_owner_headers)  # END_USER_DEACTIVATED
    http.request("POST", f"{base_url}/end-users/{eu_dev.id}/activate", None, dev_owner_headers)  # END_USER_ACTIVATED

    print("  eu_dev: tripping the EndUser-side rate limiter (last action for this identity)...")
    for _ in range(6):
        http.request(
            "POST", f"{base_url}/end-users/auth/login",
            {"email": eu_dev_email, "password": WRONG_PASSWORD}, dev_app_headers,
        )

    # ---------- 4. eu_admin: EndUser CRUD demo (update, delete+recreate) under admin_app0 ----------
    print("  eu_admin: CRUD demo (update, delete+recreate) under admin_app0...")
    eu_admin_email = render_email(seed_data, "admin", 0, 0)
    admin_app_headers = http.app_token_header(admin_app0_token)
    admin_owner_headers = {**admin_app_headers, **admin_headers}

    eu_admin = await get_end_user_by_app_and_email(session, admin_app0_id, eu_admin_email)
    http.request(
        "PATCH", f"{base_url}/end-users/{eu_admin.id}", {"last_name": "Updated"}, admin_owner_headers
    )  # END_USER_UPDATED
    http.request("DELETE", f"{base_url}/end-users/{eu_admin.id}", None, admin_owner_headers)  # END_USER_DELETED

    # Recreate immediately with the original deterministic identity, restoring the
    # 50-per-app invariant within this same run.
    first, last = pick_names(seed_data, 0)
    status, body = http.request(
        "POST", f"{base_url}/end-users",
        {"first_name": first, "last_name": last, "email": eu_admin_email, "password": seed_data["default_password"]},
        admin_app_headers,
    )
    if status != 201:
        raise RuntimeError(f"Failed to recreate eu_admin after delete demo ({status}: {body})")

    # ---------- 5. App-level demo on admin_app0 (owned by admin) ----------
    print("  App CRUD demo on admin_app0...")
    http.request("GET", f"{base_url}/apps/{admin_app0_id}", None, admin_headers)  # APP_READ
    http.request("GET", f"{base_url}/apps/{dev_app0_id}", None, dev_headers)  # APP_READ (dev's own)
    http.request("GET", f"{base_url}/apps", None, admin_headers)  # APP_LIST
    http.request(
        "PATCH", f"{base_url}/apps/{admin_app0_id}",
        {"frontend_url": "https://admin-app-00-updated.seed.local"}, admin_headers,
    )  # APP_UPDATED (name never touched)
    http.request("POST", f"{base_url}/apps/{admin_app0_id}/deactivate", None, admin_headers)  # APP_DEACTIVATED
    http.request("POST", f"{base_url}/apps/{admin_app0_id}/activate", None, admin_headers)  # APP_ACTIVATED
    status, body = http.request(
        "POST", f"{base_url}/apps/{admin_app0_id}/rotate-token", None, admin_headers
    )  # APP_TOKEN_ROTATED
    if status == 200:
        state.set_app_token("admin", 0, body["token"])

    # ---------- 6. Fictive Apps: create + delete only ----------
    print("  fx_app_admin / fx_app_dev: create + delete demo...")
    fx_app_name_admin = seed_data["fixture_app_name_template"].format(owner="admin")
    fx_app_name_dev = seed_data["fixture_app_name_template"].format(owner="dev")

    status, body = http.request(
        "POST", f"{base_url}/apps", {"name": fx_app_name_admin, "frontend_url": None}, admin_headers
    )  # APP_CREATED
    fx_app_admin_id = body["id"]
    status, body = http.request(
        "POST", f"{base_url}/apps", {"name": fx_app_name_dev, "frontend_url": None}, dev_headers
    )  # APP_CREATED
    fx_app_dev_id = body["id"]

    http.request("DELETE", f"{base_url}/apps/{fx_app_admin_id}", None, admin_headers)  # APP_DELETED
    http.request("DELETE", f"{base_url}/apps/{fx_app_dev_id}", None, dev_headers)  # APP_DELETED

    # ---------- 7. Cross-cutting, no dedicated actor ----------
    print("  Cross-cutting events (invalid app token)...")
    http.request(
        "GET", f"{base_url}/apps/by-token", None,
        {"X-App-Token": "app_live_" + "0" * 43},
    )  # APP_TOKEN_INVALID

    # ---------- 8. Audit trail itself, done last so it captures everything above ----------
    print("  AUDIT_LOG_LIST (as admin)...")
    http.request("GET", f"{base_url}/audit-logs", None, admin_headers)

    print("Audit-log activity generation complete (44/44 event types exercised).")
