"""
End-to-end test script for the Step API.

Starts its own uvicorn instance (dedicated port, SMTP mode disabled so that
OTP / reset tokens are printed in the logs instead of being sent by real
email), runs a large battery of HTTP tests covering all routes, security
protocols (isolated User/EndUser JWTs, blacklist on logout, deactivated
accounts, owner/admin permissions), brute-force protection (rate limiting on
login routes), and error handling (404/409/422/401/403/429).

Requirements:
- PostgreSQL and Redis running, migrations applied (`alembic upgrade head`).
- Project dependencies installed (`pip install -r requirements.txt`).
- Run this script from the project root, with the same Python interpreter
  as the project venv (it imports app.core.config and asyncpg).

Usage:
    python test_app.py

Output:
- Results printed in real time in the terminal.
- Full summary written to test_report.md at the project root.
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent

HOST = "127.0.0.1"
PORT = 8321
BASE_URL = f"http://{HOST}:{PORT}"
API = f"{BASE_URL}/v1"

REPORT_PATH = ROOT / "test_report.md"


# ==================== Terminal colors ====================

class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# ==================== Results ====================

results = []  # [{section, name, passed, detail}]
current_section = {"name": ""}


def section(title):
    current_section["name"] = title
    print(f"\n{C.BOLD}{C.CYAN}=== {title} ==={C.RESET}", flush=True)


def check(name, condition, detail=""):
    passed = bool(condition)
    results.append({"section": current_section["name"], "name": name, "passed": passed, "detail": detail})
    tag = f"{C.GREEN}PASS{C.RESET}" if passed else f"{C.RED}FAIL{C.RESET}"
    line = f"  [{tag}] {name}"
    if detail and not passed:
        line += f"\n         -> {detail}"
    print(line, flush=True)
    return passed


def info(message):
    print(f"  {C.YELLOW}i{C.RESET} {message}", flush=True)


# ==================== Minimal HTTP client (stdlib) ====================

def http(method, path, json_body=None, headers=None, base=API):
    url = base + path
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(json_body).encode() if json_body is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            return resp.status, _parse(body), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return e.code, _parse(body), dict(e.headers)
    except urllib.error.URLError as e:
        return None, str(e), {}


def _parse(body):
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def app_token_header(token):
    return {"X-App-Token": token}


def unique_email(prefix):
    # Real domain (mailinator.com) to pass Pydantic's EmailStr validation —
    # no email is actually sent (SMTP_USER="" forces dev mode server-side).
    return f"{prefix}.{uuid.uuid4().hex[:10]}@mailinator.com"


# ==================== Server (subprocess + log capture) ====================

server_proc = None
server_log_lines = []
server_log_lock = threading.Lock()


def _pump_output(pipe):
    for line in iter(pipe.readline, ""):
        with server_log_lock:
            server_log_lines.append(line.rstrip())
        print(f"{C.YELLOW}[server]{C.RESET} {line.rstrip()}", flush=True)
    pipe.close()


def _find_python() -> str:
    """Uses the project's venv interpreter if it exists (where fastapi/uvicorn
    are installed), otherwise falls back to the one running this script."""
    candidates = [
        ROOT.parent / "env" / "Scripts" / "python.exe",
        ROOT.parent / "env" / "bin" / "python",
        ROOT / "venv" / "Scripts" / "python.exe",
        ROOT / "venv" / "bin" / "python",
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


def start_server():
    global server_proc
    env = os.environ.copy()
    env["SMTP_USER"] = ""  # force dev mode: OTP/reset printed in logs, no real email
    env["PYTHONUNBUFFERED"] = "1"  # otherwise the server's print() calls stay buffered in the pipe
    python = _find_python()
    print(f"{C.CYAN}Interpreter used for the server: {python}{C.RESET}", flush=True)
    cmd = [python, "-m", "uvicorn", "app.main:app", "--host", HOST, "--port", str(PORT)]
    server_proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    threading.Thread(target=_pump_output, args=(server_proc.stdout,), daemon=True).start()

    print(f"{C.CYAN}Starting test server on {BASE_URL} ...{C.RESET}", flush=True)
    for _ in range(60):
        status, _, _ = http("GET", "/health", base=BASE_URL)
        if status == 200:
            print(f"{C.GREEN}Server ready.{C.RESET}", flush=True)
            return
        time.sleep(0.5)
    raise RuntimeError(
        "Test server did not start in time. Check that PostgreSQL/Redis are "
        "running and migrations are applied (alembic upgrade head)."
    )


def stop_server():
    if server_proc is None:
        return
    server_proc.terminate()
    try:
        server_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server_proc.kill()


def log_cursor():
    with server_log_lock:
        return len(server_log_lines)


def wait_for_marker(marker, after_index, timeout=5):
    """Looks for a '[DEV] ... marker ... : VALUE' line appearing after after_index
    and returns the line's final value (OTP code or reset token)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with server_log_lock:
            lines = server_log_lines[after_index:]
        for line in lines:
            if "[DEV]" in line and marker in line:
                m = re.search(r":\s*(\S+)\s*$", line)
                if m:
                    return m.group(1)
        time.sleep(0.2)
    return None


# ==================== Admin bootstrap (direct DB access) ====================
# No route allows creating the first admin (promote-admin is restricted to
# admins): we flip is_admin=True directly in the database to bootstrap the
# admin-only route tests. This is not a bypass under test — it's a documented
# bootstrap prerequisite.

def _read_database_url() -> str:
    """Reads DATABASE_URL directly from .env (regex), so as not to depend on
    pydantic-settings in the interpreter running this script."""
    env_path = ROOT / ".env"
    text = env_path.read_text(encoding="utf-8")
    m = re.search(r"^DATABASE_URL=(.+)$", text, re.MULTILINE)
    if not m:
        raise RuntimeError("DATABASE_URL not found in .env")
    return m.group(1).strip()


async def _promote_admin_db(email: str) -> None:
    import asyncpg

    dsn = _read_database_url().replace("postgresql+asyncpg", "postgresql")
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("UPDATE users SET is_admin = true WHERE email = $1", email)
    finally:
        await conn.close()


def promote_admin_via_db(email: str) -> None:
    asyncio.run(_promote_admin_db(email))


# ==================== Business flow helpers ====================

def register_user(prefix="user"):
    email = unique_email(prefix)
    password = "Sup3r$ecret!"
    status, payload, _ = http("POST", "/users", {
        "first_name": "Test",
        "last_name": prefix.capitalize(),
        "email": email,
        "password": password,
    })
    return status, payload, email, password


def login_and_verify_user(email, password):
    """Full login -> OTP (captured from the logs) -> verify-otp flow. Returns (status, payload)."""
    idx = log_cursor()
    status, payload, _ = http("POST", "/users/auth/login", {"email": email, "password": password})
    if status != 200:
        return status, payload
    code = wait_for_marker(f"[DEV] OTP for {email} (", idx)
    if code is None:
        return None, "OTP not found in server logs"
    status, payload, _ = http("POST", "/users/auth/verify-otp", {"email": email, "code": code})
    return status, payload


def register_end_user(app_token, prefix="enduser"):
    email = unique_email(prefix)
    password = "Sup3r$ecret!"
    status, payload, _ = http("POST", "/end-users", {
        "first_name": "Test",
        "last_name": prefix.capitalize(),
        "email": email,
        "password": password,
    }, headers=app_token_header(app_token))
    return status, payload, email, password


def login_and_verify_end_user(app_token, email, password):
    idx = log_cursor()
    status, payload, _ = http(
        "POST", "/end-users/auth/login", {"email": email, "password": password},
        headers=app_token_header(app_token),
    )
    if status != 200:
        return status, payload
    code = wait_for_marker(f"[DEV] OTP for {email} (", idx)
    if code is None:
        return None, "OTP not found in server logs"
    status, payload, _ = http(
        "POST", "/end-users/auth/verify-otp", {"email": email, "code": code},
        headers=app_token_header(app_token),
    )
    return status, payload


# ==================== Test suites ====================

created_user_ids = []
created_app_ids = []


def test_health_and_docs():
    section("Health check & Swagger documentation")

    status, payload, _ = http("GET", "/health", base=BASE_URL)
    check("GET /health -> 200", status == 200 and payload == {"status": "ok"}, f"status={status} body={payload}")

    status, _, _ = http("GET", "/docs", base=BASE_URL)
    check("GET /docs (public) -> 200", status == 200, f"status={status}")

    status, _, _ = http("GET", "/docs/admin", base=BASE_URL)
    check("GET /docs/admin -> 200", status == 200, f"status={status}")

    status, payload, _ = http("GET", "/openapi-public.json", base=BASE_URL)
    ok = status == 200 and isinstance(payload, dict) and "paths" in payload
    check("GET /openapi-public.json -> 200 valid", ok, f"status={status}")
    if ok:
        paths = payload["paths"]
        has_end_user_route = any("/end-users" in p for p in paths)
        has_user_auth_route = any(p.endswith("/users/auth/login") for p in paths)
        check("public doc contains end-user routes", has_end_user_route)
        check("public doc does NOT contain user-auth routes (isolation)", not has_user_auth_route)

    status, payload, _ = http("GET", "/openapi-admin.json", base=BASE_URL)
    ok = status == 200 and isinstance(payload, dict) and "paths" in payload
    check("GET /openapi-admin.json -> 200 valid", ok, f"status={status}")
    if ok:
        has_admin_route = any(p.endswith("/users/auth/login") for p in payload["paths"])
        check("admin doc contains all routes", has_admin_route)


def test_users_crud_and_errors():
    section("Users CRUD + errors")

    status, payload, email, password = register_user("alice")
    ok = check("POST /users (register) -> 201", status == 201, f"status={status} body={payload}")
    if not ok:
        return None
    user_id = payload["id"]
    created_user_ids.append(user_id)

    status, payload, _ = http("POST", "/users", {
        "first_name": "Alice", "last_name": "Dup", "email": email, "password": password,
    })
    check("POST /users duplicate email -> 409", status == 409, f"status={status} body={payload}")

    status, payload, _ = http("POST", "/users", {
        "first_name": "X", "last_name": "Y", "email": "not-an-email", "password": "x",
    })
    check("POST /users invalid email -> 422", status == 422, f"status={status} body={payload}")

    status, payload = login_and_verify_user(email, password)
    ok = check("login + verify-otp (correct password) -> 200 + token", status == 200 and payload and "access_token" in payload, f"status={status} body={payload}")
    if not ok:
        return None
    token = payload["access_token"]

    status, payload, _ = http("GET", "/users/me", headers=bearer(token))
    check("GET /users/me with token -> 200, correct email", status == 200 and payload.get("email") == email, f"status={status} body={payload}")

    status, _, _ = http("GET", "/users/me")
    check("GET /users/me without token -> 401", status == 401, f"status={status}")

    status, payload, _ = http("PATCH", f"/users/{user_id}", {"first_name": "AliceUpdated"}, headers=bearer(token))
    check("PATCH /users/{self} -> 200, first_name updated", status == 200 and payload.get("first_name") == "AliceUpdated", f"status={status} body={payload}")

    status, _, _ = http("GET", "/users", headers=bearer(token))
    check("GET /users (list) as non-admin -> 403", status == 403, f"status={status}")

    status, _, _ = http("POST", f"/users/{user_id}/promote-admin", headers=bearer(token))
    check("POST /users/{id}/promote-admin as non-admin -> 403", status == 403, f"status={status}")

    status, payload, email2, password2 = register_user("bob")
    check("register a 2nd user -> 201", status == 201, f"status={status}")
    user2_id = payload["id"] if status == 201 else None
    if user2_id:
        created_user_ids.append(user2_id)
        status, _, _ = http("GET", f"/users/{user2_id}", headers=bearer(token))
        check("GET /users/{other_id} by an unrelated non-admin -> 403", status == 403, f"status={status}")

    status, _, _ = http("GET", "/users/00000000-0000-0000-0000-000000000000", headers=bearer(token))
    check("GET /users/{nonexistent uuid} by a non-admin -> 403 (permission before existence)", status == 403, f"status={status}")

    status, _, _ = http("GET", "/users/not-a-uuid", headers=bearer(token))
    check("GET /users/{invalid uuid} -> 422", status == 422, f"status={status}")

    # forgot / reset password
    idx = log_cursor()
    status, payload, _ = http("POST", "/users/auth/forgot-password", {"email": email})
    check("POST /users/auth/forgot-password (existing email) -> 200", status == 200, f"status={status}")
    reset_token = wait_for_marker(f"[DEV] Password reset for {email}:", idx)
    check("reset token found in logs", reset_token is not None)

    status, _, _ = http("POST", "/users/auth/forgot-password", {"email": unique_email("ghost")})
    check("forgot-password (nonexistent email) -> 200 (neutral message, no leak)", status == 200, f"status={status}")

    if reset_token:
        status, _, _ = http("POST", "/users/auth/reset-password", {"email": email, "token": "wrong-token", "new_password": "NewPass123!"})
        check("reset-password with wrong token -> 400", status == 400, f"status={status}")

        new_password = "NewPass123!"
        status, _, _ = http("POST", "/users/auth/reset-password", {"email": email, "token": reset_token, "new_password": new_password})
        check("reset-password with the correct token -> 200", status == 200, f"status={status}")

        status, _ = login_and_verify_user(email, new_password)
        check("login with the new password -> 200", status == 200, f"status={status}")

        status, _ = login_and_verify_user(email, password)
        check("login with the old password -> 401 (password changed)", status == 401, f"status={status}")
        password = new_password

    # logout + blacklist
    status, _, _ = http("POST", "/users/auth/logout", headers=bearer(token))
    check("POST /users/auth/logout -> 200", status == 200, f"status={status}")

    status, _, _ = http("GET", "/users/me", headers=bearer(token))
    check("GET /users/me with revoked token (post-logout) -> 401", status == 401, f"status={status}")

    return {
        "user_a": {"id": user_id, "email": email, "password": password},
        "user_b": {"id": user2_id, "email": email2, "password": password2} if user2_id else None,
    }


def test_admin_flows():
    section("Admin bootstrap + admin-only routes")

    status, payload, admin_email, admin_password = register_user("admin")
    ok = check("register future admin -> 201", status == 201, f"status={status}")
    if not ok:
        return None
    admin_id = payload["id"]
    # Not added to created_user_ids: cleanup() deletes the admin separately, last,
    # so as not to invalidate its own token before cleanup finishes.

    promote_admin_via_db(admin_email)
    info(f"is_admin=true set in the database for {admin_email} (bootstrap, outside the API)")

    status, payload = login_and_verify_user(admin_email, admin_password)
    ok = check("admin login -> 200 + token", status == 200 and payload and "access_token" in payload, f"status={status} body={payload}")
    if not ok:
        return None
    admin_token = payload["access_token"]
    check("JWT correctly reflects is_admin=true", payload["user"]["is_admin"] is True)

    status, payload, _ = http("GET", "/users", headers=bearer(admin_token))
    check(
        "GET /users (paginated list) as admin -> 200",
        status == 200 and isinstance(payload, dict) and isinstance(payload.get("items"), list) and "total" in payload,
        f"status={status} body={payload}",
    )

    status, _, _ = http("GET", "/users/00000000-0000-0000-0000-000000000000", headers=bearer(admin_token))
    check("GET /users/{nonexistent uuid} as admin -> 404", status == 404, f"status={status}")

    # throwaway user for activate/deactivate/promote/demote/delete
    status, payload, thr_email, thr_password = register_user("throwaway")
    thr_id = payload["id"] if status == 201 else None
    if thr_id:
        created_user_ids.append(thr_id)

        status, _ = login_and_verify_user(thr_email, thr_password)
        check("normal login before deactivation -> 200", status == 200)

        status, payload, _ = http("POST", f"/users/{thr_id}/deactivate", headers=bearer(admin_token))
        check("POST /users/{id}/deactivate (admin) -> 200", status == 200 and payload.get("is_active") is False, f"status={status}")

        status, payload, _ = http("POST", "/users/auth/login", {"email": thr_email, "password": thr_password})
        check("login of a deactivated account -> 403", status == 403, f"status={status} body={payload}")

        status, payload, _ = http("POST", f"/users/{thr_id}/activate", headers=bearer(admin_token))
        check("POST /users/{id}/activate (admin) -> 200", status == 200 and payload.get("is_active") is True, f"status={status}")

        status, payload, _ = http("POST", f"/users/{thr_id}/promote-admin", headers=bearer(admin_token))
        check("POST /users/{id}/promote-admin (admin) -> 200", status == 200 and payload.get("is_admin") is True, f"status={status}")

        status, payload, _ = http("POST", f"/users/{thr_id}/demote-admin", headers=bearer(admin_token))
        check("POST /users/{id}/demote-admin (admin) -> 200", status == 200 and payload.get("is_admin") is False, f"status={status}")

        status, _, _ = http("DELETE", f"/users/{thr_id}", headers=bearer(admin_token))
        check("DELETE /users/{id} (admin) -> 204", status == 204, f"status={status}")
        created_user_ids.remove(thr_id)

        status, _, _ = http("GET", f"/users/{thr_id}", headers=bearer(admin_token))
        check("GET /users/{id} after deletion -> 404", status == 404, f"status={status}")

    return {"id": admin_id, "email": admin_email, "password": admin_password, "token": admin_token}


def test_apps_crud(users_ctx, admin_ctx):
    section("Apps CRUD (owner/admin permissions)")

    user_a = users_ctx["user_a"]
    status, payload = login_and_verify_user(user_a["email"], user_a["password"])
    ok = check("re-login user A (fresh token after previous logout) -> 200", status == 200)
    if not ok:
        return None
    token_a = payload["access_token"]

    status, payload, _ = http("POST", "/apps", {"name": "App EndUsers Test"}, headers=bearer(token_a))
    ok = check("POST /apps (creation) -> 201 + plaintext token", status == 201 and "token" in payload, f"status={status} body={payload}")
    if not ok:
        return None
    app_id = payload["id"]
    app_token = payload["token"]
    created_app_ids.append(app_id)

    status, payload, _ = http("GET", "/apps", headers=bearer(token_a))
    check(
        "GET /apps (owner) -> 200, contains the created app",
        status == 200 and any(a["id"] == app_id for a in payload.get("items", [])),
        f"status={status}",
    )

    user_b = users_ctx.get("user_b")
    if user_b:
        status, payload = login_and_verify_user(user_b["email"], user_b["password"])
        if status == 200:
            token_b = payload["access_token"]
            status, payload, _ = http("GET", "/apps", headers=bearer(token_b))
            check(
                "GET /apps (other user, not owner) -> 200, empty list",
                status == 200 and payload.get("items") == [] and payload.get("total") == 0,
                f"status={status} body={payload}",
            )

            status, _, _ = http("GET", f"/apps/{app_id}", headers=bearer(token_b))
            check("GET /apps/{id} by a non-owner non-admin -> 404", status == 404, f"status={status}")

            status, _, _ = http("PATCH", f"/apps/{app_id}", {"name": "Hacked"}, headers=bearer(token_b))
            check("PATCH /apps/{id} by a non-owner -> 404", status == 404, f"status={status}")

            status, _, _ = http("DELETE", f"/apps/{app_id}", headers=bearer(token_b))
            check("DELETE /apps/{id} by a non-owner -> 404", status == 404, f"status={status}")

    status, payload, _ = http("PATCH", f"/apps/{app_id}", {"name": "App EndUsers Test (renamed)"}, headers=bearer(token_a))
    check("PATCH /apps/{id} by the owner -> 200, name updated", status == 200 and payload.get("name") == "App EndUsers Test (renamed)", f"status={status}")

    admin_token = admin_ctx["token"] if admin_ctx else None
    if admin_token:
        status, payload, _ = http("GET", "/apps", headers=bearer(admin_token))
        check(
            "GET /apps (admin, no filter) -> 200, contains all apps",
            status == 200 and any(a["id"] == app_id for a in payload.get("items", [])),
            f"status={status}",
        )

        status, payload, _ = http("GET", "/apps?mine=true", headers=bearer(admin_token))
        check(
            "GET /apps?mine=true (admin) -> 200, does not contain others' apps",
            status == 200 and not any(a["id"] == app_id for a in payload.get("items", [])),
            f"status={status}",
        )

        status, payload, _ = http("GET", "/apps?limit=1", headers=bearer(admin_token))
        check(
            "GET /apps?limit=1 -> 200, respects the limit and returns the real total",
            status == 200 and len(payload.get("items", [])) == 1 and payload.get("limit") == 1 and payload.get("total", 0) >= 1,
            f"status={status} body={payload}",
        )

    # Disposable app for destructive tests (rotate/deactivate/delete)
    status, payload, _ = http("POST", "/apps", {"name": "App Perm Test"}, headers=bearer(token_a))
    ok = check("POST /apps (2nd disposable app) -> 201", status == 201, f"status={status}")
    disposable_app_id = payload["id"] if ok else None
    disposable_app_token = payload["token"] if ok else None
    if disposable_app_id:
        created_app_ids.append(disposable_app_id)

        status, payload, _ = http("POST", f"/apps/{disposable_app_id}/rotate-token", headers=bearer(token_a))
        ok = check("POST /apps/{id}/rotate-token -> 200, new token", status == 200 and payload.get("token") != disposable_app_token, f"status={status}")
        old_token = disposable_app_token
        if ok:
            disposable_app_token = payload["token"]

        status, _, _ = http("POST", "/end-users", {
            "first_name": "X", "last_name": "Y", "email": unique_email("ru"), "password": "Aa1!aaaa",
        }, headers=app_token_header(old_token))
        check("old app token revoked after rotate-token -> 401", status == 401, f"status={status}")

        status, payload, _ = http("POST", f"/apps/{disposable_app_id}/deactivate", headers=bearer(token_a))
        check("POST /apps/{id}/deactivate -> 200", status == 200 and payload.get("is_active") is False, f"status={status}")

        status, _, _ = http("POST", "/end-users", {
            "first_name": "X", "last_name": "Y", "email": unique_email("da"), "password": "Aa1!aaaa",
        }, headers=app_token_header(disposable_app_token))
        check("token of a deactivated app -> 401", status == 401, f"status={status}")

        status, payload, _ = http("POST", f"/apps/{disposable_app_id}/activate", headers=bearer(token_a))
        check("POST /apps/{id}/activate -> 200", status == 200 and payload.get("is_active") is True, f"status={status}")

        status, _, _ = http("DELETE", f"/apps/{disposable_app_id}", headers=bearer(token_a))
        check("DELETE /apps/{id} (owner) -> 204 (real deletion)", status == 204, f"status={status}")
        created_app_ids.remove(disposable_app_id)

        status, _, _ = http("GET", f"/apps/{disposable_app_id}", headers=bearer(token_a))
        check("GET /apps/{id} after deletion -> 404", status == 404, f"status={status}")

    return {"app_id": app_id, "app_token": app_token, "owner_token": token_a}


def test_end_users_crud(apps_ctx, users_ctx, admin_ctx):
    section("EndUsers CRUD + auth (X-App-Token + owner/admin permissions)")

    if not apps_ctx:
        info("section skipped (no App available)")
        return

    app_token = apps_ctx["app_token"]
    owner_token = apps_ctx["owner_token"]
    admin_token = admin_ctx["token"] if admin_ctx else None

    status, _, _ = http("POST", "/end-users", {
        "first_name": "X", "last_name": "Y", "email": unique_email("noapp"), "password": "Aa1!aaaa",
    })
    check("POST /end-users without X-App-Token -> 401", status == 401, f"status={status}")

    status, payload, eu_email, eu_password = register_end_user(app_token, "carol")
    ok = check("POST /end-users (with X-App-Token) -> 201", status == 201, f"status={status} body={payload}")
    if not ok:
        return
    eu_id = payload["id"]

    status, _, _ = http("POST", "/end-users", {
        "first_name": "X", "last_name": "Y", "email": eu_email, "password": "Aa1!aaaa",
    }, headers=app_token_header(app_token))
    check("POST /end-users duplicate email (same app) -> 409", status == 409, f"status={status}")

    status, _, _ = http("GET", "/end-users", headers=app_token_header(app_token))
    check("GET /end-users (list) without User Bearer -> 401", status == 401, f"status={status}")

    status, payload, _ = http("GET", "/end-users", headers={**app_token_header(app_token), **bearer(owner_token)})
    check(
        "GET /end-users (paginated list) by the app owner -> 200",
        status == 200 and any(u["id"] == eu_id for u in payload.get("items", [])),
        f"status={status}",
    )

    user_b = users_ctx.get("user_b")
    if user_b:
        status, payload = login_and_verify_user(user_b["email"], user_b["password"])
        if status == 200:
            token_b = payload["access_token"]
            status, _, _ = http("GET", "/end-users", headers={**app_token_header(app_token), **bearer(token_b)})
            check("GET /end-users (list) by a non-owner non-admin user -> 403", status == 403, f"status={status}")

    status, payload = login_and_verify_end_user(app_token, eu_email, eu_password)
    ok = check("login + verify-otp end-user -> 200 + token", status == 200 and payload and "access_token" in payload, f"status={status} body={payload}")
    eu_token = payload["access_token"] if ok else None

    if eu_token:
        status, payload, _ = http("GET", "/end-users/me", headers={**app_token_header(app_token), **bearer(eu_token)})
        check("GET /end-users/me (self) -> 200", status == 200 and payload.get("email") == eu_email, f"status={status}")

        status, payload, _ = http("GET", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(eu_token)})
        check("GET /end-users/{id} by the end-user in question (self) -> 200", status == 200, f"status={status}")

        status, _, eu2_email, eu2_password = register_end_user(app_token, "dave")
        status2, payload2 = login_and_verify_end_user(app_token, eu2_email, eu2_password)
        if status2 == 200:
            other_eu_token = payload2["access_token"]
            status, _, _ = http("GET", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(other_eu_token)})
            check("GET /end-users/{id} by ANOTHER end-user -> 401", status == 401, f"status={status}")

    status, payload, _ = http("PATCH", f"/end-users/{eu_id}", {"first_name": "CarolUpdated"}, headers={**app_token_header(app_token), **bearer(owner_token)})
    check("PATCH /end-users/{id} by the app owner -> 200", status == 200 and payload.get("first_name") == "CarolUpdated", f"status={status}")

    if admin_token:
        status, payload, _ = http("PATCH", f"/end-users/{eu_id}", {"last_name": "ByAdmin"}, headers={**app_token_header(app_token), **bearer(admin_token)})
        check("PATCH /end-users/{id} by an admin -> 200", status == 200 and payload.get("last_name") == "ByAdmin", f"status={status}")

    status, payload, _ = http("POST", f"/end-users/{eu_id}/deactivate", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("POST /end-users/{id}/deactivate (owner) -> 200", status == 200 and payload.get("is_active") is False, f"status={status}")

    status, payload, _ = http("POST", "/end-users/auth/login", {"email": eu_email, "password": eu_password}, headers=app_token_header(app_token))
    check("login of a deactivated end-user -> 403", status == 403, f"status={status}")

    status, payload, _ = http("POST", f"/end-users/{eu_id}/activate", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("POST /end-users/{id}/activate (owner) -> 200", status == 200 and payload.get("is_active") is True, f"status={status}")

    # forgot / reset password end-user
    idx = log_cursor()
    status, _, _ = http("POST", "/end-users/auth/forgot-password", {"email": eu_email}, headers=app_token_header(app_token))
    check("POST /end-users/auth/forgot-password -> 200", status == 200, f"status={status}")
    reset_token = wait_for_marker(f"[DEV] Password reset for {eu_email}:", idx)
    check("end-user reset token found in logs", reset_token is not None)

    if reset_token:
        new_password = "NewPassword1!"
        status, _, _ = http("POST", "/end-users/auth/reset-password", {"email": eu_email, "token": "invalid", "new_password": new_password}, headers=app_token_header(app_token))
        check("reset-password end-user wrong token -> 400", status == 400, f"status={status}")

        status, _, _ = http("POST", "/end-users/auth/reset-password", {"email": eu_email, "token": reset_token, "new_password": new_password}, headers=app_token_header(app_token))
        check("reset-password end-user correct token -> 200", status == 200, f"status={status}")

        status, _ = login_and_verify_end_user(app_token, eu_email, new_password)
        check("login end-user with the new password -> 200", status == 200, f"status={status}")
        eu_password = new_password

    # logout + blacklist end-user
    status, payload = login_and_verify_end_user(app_token, eu_email, eu_password)
    if status == 200:
        fresh_token = payload["access_token"]
        status, _, _ = http("POST", "/end-users/auth/logout", headers={**app_token_header(app_token), **bearer(fresh_token)})
        check("POST /end-users/auth/logout -> 200", status == 200, f"status={status}")

        status, _, _ = http("GET", "/end-users/me", headers={**app_token_header(app_token), **bearer(fresh_token)})
        check("GET /end-users/me with revoked token -> 401", status == 401, f"status={status}")

    status, _, _ = http("DELETE", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("DELETE /end-users/{id} (owner) -> 204", status == 204, f"status={status}")

    status, _, _ = http("GET", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("GET /end-users/{id} after deletion -> 404", status == 404, f"status={status}")


def test_cross_jwt_isolation(users_ctx, apps_ctx):
    section("JWT isolation (User vs EndUser)")

    if not apps_ctx:
        info("section skipped (no App available)")
        return

    user_a = users_ctx["user_a"]
    status, payload = login_and_verify_user(user_a["email"], user_a["password"])
    if status != 200:
        info("could not re-login user A for this test")
        return
    user_token = payload["access_token"]

    status, _, _ = http("GET", "/end-users/me", headers={**app_token_header(apps_ctx["app_token"]), **bearer(user_token)})
    check("User JWT used on an EndUser route -> 401", status == 401, f"status={status}")

    status, payload, eu_email, eu_password = register_end_user(apps_ctx["app_token"], "erin")
    if status != 201:
        return
    status, payload = login_and_verify_end_user(apps_ctx["app_token"], eu_email, eu_password)
    if status != 200:
        return
    eu_token = payload["access_token"]

    status, _, _ = http("GET", "/users/me", headers=bearer(eu_token))
    check("EndUser JWT used on a User route -> 401", status == 401, f"status={status}")


def test_brute_force():
    section("Brute-force / rate limiting (login)")

    email = unique_email("bruteforce")
    password = "CorrectHorseBattery1!"
    status, payload, email, password2 = register_user("bruteforce")
    if status != 201:
        info("could not create the account for the brute-force test")
        return
    password = password2

    got_429 = False
    retry_after_present = False
    attempts = 0
    for attempts in range(1, 26):
        status, payload, headers = http("POST", "/users/auth/login", {"email": email, "password": "wrong-password"})
        if status == 429:
            got_429 = True
            retry_after_present = any(k.lower() == "retry-after" for k in headers)
            break
        if status != 401:
            break

    check(f"User login brute-force: 429 obtained after {attempts} attempt(s)", got_429, f"last status={status} body={payload}")
    check("Retry-After header present on the 429 response", retry_after_present)

    if got_429:
        status, _, _ = http("POST", "/users/auth/login", {"email": email, "password": password})
        check("further attempt (even with the correct password) still blocked -> 429", status == 429, f"status={status}")

    # Brute-force on the EndUser side (requires an App)
    status, payload, _ = http("POST", "/users", {
        "first_name": "Owner", "last_name": "BF", "email": unique_email("owner-bf"), "password": "Aa1!aaaaaa",
    })
    if status != 201:
        return
    owner_email = payload["email"]
    status, payload = login_and_verify_user(owner_email, "Aa1!aaaaaa")
    if status != 200:
        return
    owner_token = payload["access_token"]

    status, payload, _ = http("POST", "/apps", {"name": "App BruteForce Test"}, headers=bearer(owner_token))
    if status != 201:
        return
    app_id = payload["id"]
    app_token = payload["token"]
    created_app_ids.append(app_id)

    status, payload, eu_email, _ = register_end_user(app_token, "bfenduser")
    if status != 201:
        return

    got_429 = False
    attempts = 0
    for attempts in range(1, 26):
        status, payload, headers = http(
            "POST", "/end-users/auth/login", {"email": eu_email, "password": "wrong-password"},
            headers=app_token_header(app_token),
        )
        if status == 429:
            got_429 = True
            break
        if status != 401:
            break

    check(f"EndUser login brute-force: 429 obtained after {attempts} attempt(s)", got_429, f"last status={status} body={payload}")


def test_audit_logs(apps_ctx, users_ctx, admin_ctx):
    section("Audit logs (read-only, admin / owner)")

    if not admin_ctx or not apps_ctx:
        info("section skipped (admin or App unavailable)")
        return

    admin_token = admin_ctx["token"]
    owner_token = apps_ctx["owner_token"]
    app_id = apps_ctx["app_id"]

    status, _, _ = http("POST", "/audit-logs", {})
    check("POST /audit-logs -> 405 (no write route, only GET exists)", status == 405, f"status={status}")

    status, payload, _ = http("GET", "/audit-logs", headers=bearer(owner_token))
    check("GET /audit-logs (non-admin) -> 403", status == 403, f"status={status}")

    status, payload, _ = http("GET", "/audit-logs", headers=bearer(admin_token))
    ok = check(
        "GET /audit-logs (admin) -> 200, paginated and non-empty",
        status == 200 and isinstance(payload.get("items"), list) and payload.get("total", 0) > 0,
        f"status={status} body={payload}",
    )
    if ok:
        check(
            "entries do have actor_type/event_type/created_at",
            all({"actor_type", "event_type", "created_at"} <= set(item.keys()) for item in payload["items"]),
        )

    status, payload, _ = http("GET", "/audit-logs?event_type=app_created", headers=bearer(admin_token))
    check(
        "GET /audit-logs?event_type=app_created -> 200, only that type",
        status == 200 and all(item["event_type"] == "app_created" for item in payload.get("items", [])),
        f"status={status}",
    )

    status, payload, _ = http("GET", "/audit-logs?event_type=not-a-valid-event", headers=bearer(admin_token))
    check("GET /audit-logs?event_type=invalid -> 422", status == 422, f"status={status}")

    status, payload, _ = http("GET", f"/audit-logs/apps/{app_id}", headers=bearer(owner_token))
    ok = check(
        "GET /audit-logs/apps/{id} (owner) -> 200, only this app",
        status == 200 and all(item.get("app_id") == app_id for item in payload.get("items", [])),
        f"status={status} body={payload}",
    )

    status, payload, _ = http("GET", f"/audit-logs/apps/{app_id}", headers=bearer(admin_token))
    check("GET /audit-logs/apps/{id} (admin) -> 200", status == 200, f"status={status}")

    user_b = users_ctx.get("user_b")
    if user_b:
        status, payload = login_and_verify_user(user_b["email"], user_b["password"])
        if status == 200:
            token_b = payload["access_token"]
            status, _, _ = http("GET", f"/audit-logs/apps/{app_id}", headers=bearer(token_b))
            check("GET /audit-logs/apps/{id} by a non-owner non-admin -> 404", status == 404, f"status={status}")

    status, _, _ = http("GET", "/audit-logs/apps/00000000-0000-0000-0000-000000000000", headers=bearer(admin_token))
    check("GET /audit-logs/apps/{nonexistent uuid} (admin) -> 404", status == 404, f"status={status}")


def cleanup(admin_ctx):
    section("Cleanup")
    admin_token = admin_ctx["token"] if admin_ctx else None
    if not admin_token:
        info("no admin token available, partial cleanup")
        return

    for app_id in list(created_app_ids):
        status, _, _ = http("DELETE", f"/apps/{app_id}", headers=bearer(admin_token))
        info(f"deleted app {app_id} -> {status}")

    for user_id in list(created_user_ids):
        status, _, _ = http("DELETE", f"/users/{user_id}", headers=bearer(admin_token))
        info(f"deleted user {user_id} -> {status}")

    if admin_ctx:
        status, _, _ = http("DELETE", f"/users/{admin_ctx['id']}", headers=bearer(admin_token))
        info(f"deleted admin {admin_ctx['id']} -> {status}")


# ==================== Report ====================

def write_report():
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    lines = []
    lines.append(f"# Test Report — Step API")
    lines.append("")
    lines.append(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"**Total: {total} | Passed: {passed} | Failed: {failed}**")
    lines.append("")

    by_section = {}
    for r in results:
        by_section.setdefault(r["section"], []).append(r)

    for sec, items in by_section.items():
        sec_passed = sum(1 for i in items if i["passed"])
        lines.append(f"## {sec} ({sec_passed}/{len(items)})")
        lines.append("")
        for i in items:
            mark = "✅" if i["passed"] else "❌"
            lines.append(f"- {mark} {i['name']}")
            if not i["passed"] and i["detail"]:
                lines.append(f"  - detail: `{i['detail']}`")
        lines.append("")

    if failed:
        lines.append("## Failure summary")
        lines.append("")
        for r in results:
            if not r["passed"]:
                lines.append(f"- **{r['section']}** :: {r['name']} — `{r['detail']}`")
        lines.append("")

    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    return total, passed, failed


# ==================== Main ====================

def main():
    start_server()
    admin_ctx = None
    try:
        test_health_and_docs()
        users_ctx = test_users_crud_and_errors()
        if users_ctx is None:
            users_ctx = {"user_a": None, "user_b": None}
        admin_ctx = test_admin_flows()
        apps_ctx = test_apps_crud(users_ctx, admin_ctx) if users_ctx.get("user_a") else None
        test_end_users_crud(apps_ctx, users_ctx, admin_ctx)
        test_cross_jwt_isolation(users_ctx, apps_ctx)
        test_brute_force()
        test_audit_logs(apps_ctx, users_ctx, admin_ctx)
    finally:
        cleanup(admin_ctx)
        stop_server()

    total, passed, failed = write_report()

    print()
    print(f"{C.BOLD}{'=' * 60}{C.RESET}")
    color = C.GREEN if failed == 0 else C.RED
    print(f"{color}{C.BOLD}Total: {total} | Passed: {passed} | Failed: {failed}{C.RESET}")
    print(f"Full report: {REPORT_PATH}")
    print(f"{C.BOLD}{'=' * 60}{C.RESET}")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_server()
        print("\nInterrupted by user.")
        sys.exit(130)
    except Exception as exc:
        stop_server()
        print(f"\n{C.RED}Fatal error: {exc}{C.RESET}")
        raise
