"""
Script de test end-to-end pour l'API Step.

Lance sa propre instance uvicorn (port dédié, mode SMTP désactivé pour que
les OTP / tokens de reset soient affichés dans les logs au lieu d'être
envoyés par email réel), exécute une large batterie de tests HTTP couvrant
toutes les routes, les protocoles de sécurité (JWT isolés User/EndUser,
blacklist au logout, comptes désactivés, permissions owner/admin), le
brute-force (rate limiting sur les routes de login) et la gestion d'erreurs
(404/409/422/401/403/429).

Prérequis :
- PostgreSQL et Redis démarrés, migrations appliquées (`alembic upgrade head`).
- Dépendances du projet installées (`pip install -r requirements.txt`).
- Lancer ce script depuis la racine du projet, avec le même interpréteur
  Python que le venv du projet (il importe app.core.config et asyncpg).

Usage :
    python test_app.py

Sortie :
- Résultats affichés en temps réel dans le terminal.
- Récap complet écrit dans test_report.md à la racine du projet.
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


# ==================== Couleurs terminal ====================

class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# ==================== Résultats ====================

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


# ==================== Client HTTP minimal (stdlib) ====================

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
    # Domaine réel (mailinator.com) pour passer la validation EmailStr de Pydantic —
    # aucun email n'est réellement envoyé (SMTP_USER="" force le mode dev côté serveur).
    return f"{prefix}.{uuid.uuid4().hex[:10]}@mailinator.com"


# ==================== Serveur (subprocess + capture des logs) ====================

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
    """Utilise l'interpréteur du venv du projet s'il existe (là où fastapi/uvicorn
    sont installés), sinon retombe sur celui qui exécute ce script."""
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
    env["SMTP_USER"] = ""  # force le mode dev : OTP/reset affichés dans les logs, pas d'email réel
    env["PYTHONUNBUFFERED"] = "1"  # sinon les print() du serveur restent bufferisés dans le pipe
    python = _find_python()
    print(f"{C.CYAN}Interpréteur utilisé pour le serveur : {python}{C.RESET}", flush=True)
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

    print(f"{C.CYAN}Démarrage du serveur de test sur {BASE_URL} ...{C.RESET}", flush=True)
    for _ in range(60):
        status, _, _ = http("GET", "/health", base=BASE_URL)
        if status == 200:
            print(f"{C.GREEN}Serveur prêt.{C.RESET}", flush=True)
            return
        time.sleep(0.5)
    raise RuntimeError(
        "Le serveur de test n'a pas démarré à temps. Vérifiez que PostgreSQL/Redis "
        "tournent et que les migrations sont appliquées (alembic upgrade head)."
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
    """Cherche une ligne '[DEV] ... marker ... : VALEUR' apparue après after_index
    et retourne la valeur finale de la ligne (code OTP ou token de reset)."""
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


# ==================== Bootstrap admin (accès direct DB) ====================
# Aucune route ne permet de créer le premier admin (promote-admin est réservé
# aux admins) : on bascule is_admin=True directement en base pour amorcer les
# tests des routes admin-only. Ce n'est pas un contournement testé — c'est un
# prérequis d'amorçage, documenté comme tel.

def _read_database_url() -> str:
    """Lit DATABASE_URL depuis .env directement (regex), pour ne pas dépendre de
    pydantic-settings dans l'interpréteur qui exécute ce script."""
    env_path = ROOT / ".env"
    text = env_path.read_text(encoding="utf-8")
    m = re.search(r"^DATABASE_URL=(.+)$", text, re.MULTILINE)
    if not m:
        raise RuntimeError("DATABASE_URL introuvable dans .env")
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


# ==================== Helpers de flow métier ====================

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
    """Flow complet login -> OTP (capturé dans les logs) -> verify-otp. Retourne (status, payload)."""
    idx = log_cursor()
    status, payload, _ = http("POST", "/users/auth/login", {"email": email, "password": password})
    if status != 200:
        return status, payload
    code = wait_for_marker(f"[DEV] OTP pour {email} (", idx)
    if code is None:
        return None, "OTP introuvable dans les logs serveur"
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
    code = wait_for_marker(f"[DEV] OTP pour {email} (", idx)
    if code is None:
        return None, "OTP introuvable dans les logs serveur"
    status, payload, _ = http(
        "POST", "/end-users/auth/verify-otp", {"email": email, "code": code},
        headers=app_token_header(app_token),
    )
    return status, payload


# ==================== Suites de tests ====================

created_user_ids = []
created_app_ids = []


def test_health_and_docs():
    section("Health check & documentation Swagger")

    status, payload, _ = http("GET", "/health", base=BASE_URL)
    check("GET /health -> 200", status == 200 and payload == {"status": "ok"}, f"status={status} body={payload}")

    status, _, _ = http("GET", "/docs", base=BASE_URL)
    check("GET /docs (public) -> 200", status == 200, f"status={status}")

    status, _, _ = http("GET", "/docs/admin", base=BASE_URL)
    check("GET /docs/admin -> 200", status == 200, f"status={status}")

    status, payload, _ = http("GET", "/openapi-public.json", base=BASE_URL)
    ok = status == 200 and isinstance(payload, dict) and "paths" in payload
    check("GET /openapi-public.json -> 200 valide", ok, f"status={status}")
    if ok:
        paths = payload["paths"]
        has_end_user_route = any("/end-users" in p for p in paths)
        has_user_auth_route = any(p.endswith("/users/auth/login") for p in paths)
        check("doc publique contient les routes end-user", has_end_user_route)
        check("doc publique NE contient PAS les routes user-auth (isolation)", not has_user_auth_route)

    status, payload, _ = http("GET", "/openapi-admin.json", base=BASE_URL)
    ok = status == 200 and isinstance(payload, dict) and "paths" in payload
    check("GET /openapi-admin.json -> 200 valide", ok, f"status={status}")
    if ok:
        has_admin_route = any(p.endswith("/users/auth/login") for p in payload["paths"])
        check("doc admin contient bien toutes les routes", has_admin_route)


def test_users_crud_and_errors():
    section("Users CRUD + erreurs")

    status, payload, email, password = register_user("alice")
    ok = check("POST /users (register) -> 201", status == 201, f"status={status} body={payload}")
    if not ok:
        return None
    user_id = payload["id"]
    created_user_ids.append(user_id)

    status, payload, _ = http("POST", "/users", {
        "first_name": "Alice", "last_name": "Dup", "email": email, "password": password,
    })
    check("POST /users email dupliqué -> 409", status == 409, f"status={status} body={payload}")

    status, payload, _ = http("POST", "/users", {
        "first_name": "X", "last_name": "Y", "email": "not-an-email", "password": "x",
    })
    check("POST /users email invalide -> 422", status == 422, f"status={status} body={payload}")

    status, payload = login_and_verify_user(email, password)
    ok = check("login + verify-otp (mot de passe correct) -> 200 + token", status == 200 and payload and "access_token" in payload, f"status={status} body={payload}")
    if not ok:
        return None
    token = payload["access_token"]

    status, payload, _ = http("GET", "/users/me", headers=bearer(token))
    check("GET /users/me avec token -> 200, email correct", status == 200 and payload.get("email") == email, f"status={status} body={payload}")

    status, _, _ = http("GET", "/users/me")
    check("GET /users/me sans token -> 401", status == 401, f"status={status}")

    status, payload, _ = http("PATCH", f"/users/{user_id}", {"first_name": "AliceUpdated"}, headers=bearer(token))
    check("PATCH /users/{self} -> 200, first_name mis à jour", status == 200 and payload.get("first_name") == "AliceUpdated", f"status={status} body={payload}")

    status, _, _ = http("GET", "/users", headers=bearer(token))
    check("GET /users (liste) en tant que non-admin -> 403", status == 403, f"status={status}")

    status, _, _ = http("POST", f"/users/{user_id}/promote-admin", headers=bearer(token))
    check("POST /users/{id}/promote-admin en tant que non-admin -> 403", status == 403, f"status={status}")

    status, payload, email2, password2 = register_user("bob")
    check("register d'un 2e user -> 201", status == 201, f"status={status}")
    user2_id = payload["id"] if status == 201 else None
    if user2_id:
        created_user_ids.append(user2_id)
        status, _, _ = http("GET", f"/users/{user2_id}", headers=bearer(token))
        check("GET /users/{other_id} par un non-admin non-concerné -> 403", status == 403, f"status={status}")

    status, _, _ = http("GET", "/users/00000000-0000-0000-0000-000000000000", headers=bearer(token))
    check("GET /users/{uuid inexistant} par un non-admin -> 403 (permission avant existence)", status == 403, f"status={status}")

    status, _, _ = http("GET", "/users/pas-un-uuid", headers=bearer(token))
    check("GET /users/{uuid invalide} -> 422", status == 422, f"status={status}")

    # forgot / reset password
    idx = log_cursor()
    status, payload, _ = http("POST", "/users/auth/forgot-password", {"email": email})
    check("POST /users/auth/forgot-password (email existant) -> 200", status == 200, f"status={status}")
    reset_token = wait_for_marker(f"[DEV] Reset password pour {email} :", idx)
    check("token de reset trouvé dans les logs", reset_token is not None)

    status, _, _ = http("POST", "/users/auth/forgot-password", {"email": unique_email("ghost")})
    check("forgot-password (email inexistant) -> 200 (message neutre, pas de fuite)", status == 200, f"status={status}")

    if reset_token:
        status, _, _ = http("POST", "/users/auth/reset-password", {"email": email, "token": "faux-token", "new_password": "Nouveau123!"})
        check("reset-password avec mauvais token -> 400", status == 400, f"status={status}")

        new_password = "Nouveau123!"
        status, _, _ = http("POST", "/users/auth/reset-password", {"email": email, "token": reset_token, "new_password": new_password})
        check("reset-password avec le bon token -> 200", status == 200, f"status={status}")

        status, _ = login_and_verify_user(email, new_password)
        check("login avec le nouveau mot de passe -> 200", status == 200, f"status={status}")

        status, _ = login_and_verify_user(email, password)
        check("login avec l'ancien mot de passe -> 401 (mot de passe changé)", status == 401, f"status={status}")
        password = new_password

    # logout + blacklist
    status, _, _ = http("POST", "/users/auth/logout", headers=bearer(token))
    check("POST /users/auth/logout -> 200", status == 200, f"status={status}")

    status, _, _ = http("GET", "/users/me", headers=bearer(token))
    check("GET /users/me avec token révoqué (post-logout) -> 401", status == 401, f"status={status}")

    return {
        "user_a": {"id": user_id, "email": email, "password": password},
        "user_b": {"id": user2_id, "email": email2, "password": password2} if user2_id else None,
    }


def test_admin_flows():
    section("Bootstrap admin + routes admin-only")

    status, payload, admin_email, admin_password = register_user("admin")
    ok = check("register du futur admin -> 201", status == 201, f"status={status}")
    if not ok:
        return None
    admin_id = payload["id"]
    # Pas ajouté à created_user_ids : cleanup() supprime l'admin séparément, en
    # dernier, pour ne pas invalider son propre token avant la fin du nettoyage.

    promote_admin_via_db(admin_email)
    info(f"is_admin=true positionné en base pour {admin_email} (amorçage, hors API)")

    status, payload = login_and_verify_user(admin_email, admin_password)
    ok = check("login admin -> 200 + token", status == 200 and payload and "access_token" in payload, f"status={status} body={payload}")
    if not ok:
        return None
    admin_token = payload["access_token"]
    check("le JWT reflète bien is_admin=true", payload["user"]["is_admin"] is True)

    status, payload, _ = http("GET", "/users", headers=bearer(admin_token))
    check(
        "GET /users (liste paginée) en tant qu'admin -> 200",
        status == 200 and isinstance(payload, dict) and isinstance(payload.get("items"), list) and "total" in payload,
        f"status={status} body={payload}",
    )

    status, _, _ = http("GET", "/users/00000000-0000-0000-0000-000000000000", headers=bearer(admin_token))
    check("GET /users/{uuid inexistant} en tant qu'admin -> 404", status == 404, f"status={status}")

    # throwaway user pour activate/deactivate/promote/demote/delete
    status, payload, thr_email, thr_password = register_user("throwaway")
    thr_id = payload["id"] if status == 201 else None
    if thr_id:
        created_user_ids.append(thr_id)

        status, _ = login_and_verify_user(thr_email, thr_password)
        check("login normal avant désactivation -> 200", status == 200)

        status, payload, _ = http("POST", f"/users/{thr_id}/deactivate", headers=bearer(admin_token))
        check("POST /users/{id}/deactivate (admin) -> 200", status == 200 and payload.get("is_active") is False, f"status={status}")

        status, payload, _ = http("POST", "/users/auth/login", {"email": thr_email, "password": thr_password})
        check("login d'un compte désactivé -> 403", status == 403, f"status={status} body={payload}")

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
        check("GET /users/{id} après suppression -> 404", status == 404, f"status={status}")

    return {"id": admin_id, "email": admin_email, "password": admin_password, "token": admin_token}


def test_apps_crud(users_ctx, admin_ctx):
    section("Apps CRUD (permissions owner/admin)")

    user_a = users_ctx["user_a"]
    status, payload = login_and_verify_user(user_a["email"], user_a["password"])
    ok = check("re-login user A (token frais après logout précédent) -> 200", status == 200)
    if not ok:
        return None
    token_a = payload["access_token"]

    status, payload, _ = http("POST", "/apps", {"name": "App EndUsers Test"}, headers=bearer(token_a))
    ok = check("POST /apps (création) -> 201 + token en clair", status == 201 and "token" in payload, f"status={status} body={payload}")
    if not ok:
        return None
    app_id = payload["id"]
    app_token = payload["token"]
    created_app_ids.append(app_id)

    status, payload, _ = http("GET", "/apps", headers=bearer(token_a))
    check(
        "GET /apps (owner) -> 200, contient l'app créée",
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
                "GET /apps (autre user, non owner) -> 200, liste vide",
                status == 200 and payload.get("items") == [] and payload.get("total") == 0,
                f"status={status} body={payload}",
            )

            status, _, _ = http("GET", f"/apps/{app_id}", headers=bearer(token_b))
            check("GET /apps/{id} par un non-owner non-admin -> 404", status == 404, f"status={status}")

            status, _, _ = http("PATCH", f"/apps/{app_id}", {"name": "Hacked"}, headers=bearer(token_b))
            check("PATCH /apps/{id} par un non-owner -> 404", status == 404, f"status={status}")

            status, _, _ = http("DELETE", f"/apps/{app_id}", headers=bearer(token_b))
            check("DELETE /apps/{id} par un non-owner -> 404", status == 404, f"status={status}")

    status, payload, _ = http("PATCH", f"/apps/{app_id}", {"name": "App EndUsers Test (renamed)"}, headers=bearer(token_a))
    check("PATCH /apps/{id} par le owner -> 200, nom mis à jour", status == 200 and payload.get("name") == "App EndUsers Test (renamed)", f"status={status}")

    admin_token = admin_ctx["token"] if admin_ctx else None
    if admin_token:
        status, payload, _ = http("GET", "/apps", headers=bearer(admin_token))
        check(
            "GET /apps (admin, sans filtre) -> 200, contient toutes les apps",
            status == 200 and any(a["id"] == app_id for a in payload.get("items", [])),
            f"status={status}",
        )

        status, payload, _ = http("GET", "/apps?mine=true", headers=bearer(admin_token))
        check(
            "GET /apps?mine=true (admin) -> 200, ne contient pas les apps d'autrui",
            status == 200 and not any(a["id"] == app_id for a in payload.get("items", [])),
            f"status={status}",
        )

        status, payload, _ = http("GET", "/apps?limit=1", headers=bearer(admin_token))
        check(
            "GET /apps?limit=1 -> 200, respecte la limite et renvoie le total réel",
            status == 200 and len(payload.get("items", [])) == 1 and payload.get("limit") == 1 and payload.get("total", 0) >= 1,
            f"status={status} body={payload}",
        )

    # App jetable pour les tests destructifs (rotate/deactivate/delete)
    status, payload, _ = http("POST", "/apps", {"name": "App Perm Test"}, headers=bearer(token_a))
    ok = check("POST /apps (2e app jetable) -> 201", status == 201, f"status={status}")
    disposable_app_id = payload["id"] if ok else None
    disposable_app_token = payload["token"] if ok else None
    if disposable_app_id:
        created_app_ids.append(disposable_app_id)

        status, payload, _ = http("POST", f"/apps/{disposable_app_id}/rotate-token", headers=bearer(token_a))
        ok = check("POST /apps/{id}/rotate-token -> 200, nouveau token", status == 200 and payload.get("token") != disposable_app_token, f"status={status}")
        old_token = disposable_app_token
        if ok:
            disposable_app_token = payload["token"]

        status, _, _ = http("POST", "/end-users", {
            "first_name": "X", "last_name": "Y", "email": unique_email("ru"), "password": "Aa1!aaaa",
        }, headers=app_token_header(old_token))
        check("ancien token d'app révoqué après rotate-token -> 401", status == 401, f"status={status}")

        status, payload, _ = http("POST", f"/apps/{disposable_app_id}/deactivate", headers=bearer(token_a))
        check("POST /apps/{id}/deactivate -> 200", status == 200 and payload.get("is_active") is False, f"status={status}")

        status, _, _ = http("POST", "/end-users", {
            "first_name": "X", "last_name": "Y", "email": unique_email("da"), "password": "Aa1!aaaa",
        }, headers=app_token_header(disposable_app_token))
        check("token d'une app désactivée -> 401", status == 401, f"status={status}")

        status, payload, _ = http("POST", f"/apps/{disposable_app_id}/activate", headers=bearer(token_a))
        check("POST /apps/{id}/activate -> 200", status == 200 and payload.get("is_active") is True, f"status={status}")

        status, _, _ = http("DELETE", f"/apps/{disposable_app_id}", headers=bearer(token_a))
        check("DELETE /apps/{id} (owner) -> 204 (suppression réelle)", status == 204, f"status={status}")
        created_app_ids.remove(disposable_app_id)

        status, _, _ = http("GET", f"/apps/{disposable_app_id}", headers=bearer(token_a))
        check("GET /apps/{id} après suppression -> 404", status == 404, f"status={status}")

    return {"app_id": app_id, "app_token": app_token, "owner_token": token_a}


def test_end_users_crud(apps_ctx, users_ctx, admin_ctx):
    section("EndUsers CRUD + auth (X-App-Token + permissions owner/admin)")

    if not apps_ctx:
        info("section ignorée (pas d'App disponible)")
        return

    app_token = apps_ctx["app_token"]
    owner_token = apps_ctx["owner_token"]
    admin_token = admin_ctx["token"] if admin_ctx else None

    status, _, _ = http("POST", "/end-users", {
        "first_name": "X", "last_name": "Y", "email": unique_email("noapp"), "password": "Aa1!aaaa",
    })
    check("POST /end-users sans X-App-Token -> 401", status == 401, f"status={status}")

    status, payload, eu_email, eu_password = register_end_user(app_token, "carol")
    ok = check("POST /end-users (avec X-App-Token) -> 201", status == 201, f"status={status} body={payload}")
    if not ok:
        return
    eu_id = payload["id"]

    status, _, _ = http("POST", "/end-users", {
        "first_name": "X", "last_name": "Y", "email": eu_email, "password": "Aa1!aaaa",
    }, headers=app_token_header(app_token))
    check("POST /end-users email dupliqué (même app) -> 409", status == 409, f"status={status}")

    status, _, _ = http("GET", "/end-users", headers=app_token_header(app_token))
    check("GET /end-users (liste) sans Bearer User -> 401", status == 401, f"status={status}")

    status, payload, _ = http("GET", "/end-users", headers={**app_token_header(app_token), **bearer(owner_token)})
    check(
        "GET /end-users (liste paginée) par le owner de l'app -> 200",
        status == 200 and any(u["id"] == eu_id for u in payload.get("items", [])),
        f"status={status}",
    )

    user_b = users_ctx.get("user_b")
    if user_b:
        status, payload = login_and_verify_user(user_b["email"], user_b["password"])
        if status == 200:
            token_b = payload["access_token"]
            status, _, _ = http("GET", "/end-users", headers={**app_token_header(app_token), **bearer(token_b)})
            check("GET /end-users (liste) par un user non-owner non-admin -> 403", status == 403, f"status={status}")

    status, payload = login_and_verify_end_user(app_token, eu_email, eu_password)
    ok = check("login + verify-otp end-user -> 200 + token", status == 200 and payload and "access_token" in payload, f"status={status} body={payload}")
    eu_token = payload["access_token"] if ok else None

    if eu_token:
        status, payload, _ = http("GET", "/end-users/me", headers={**app_token_header(app_token), **bearer(eu_token)})
        check("GET /end-users/me (self) -> 200", status == 200 and payload.get("email") == eu_email, f"status={status}")

        status, payload, _ = http("GET", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(eu_token)})
        check("GET /end-users/{id} par l'end-user concerné (self) -> 200", status == 200, f"status={status}")

        status, _, eu2_email, eu2_password = register_end_user(app_token, "dave")
        status2, payload2 = login_and_verify_end_user(app_token, eu2_email, eu2_password)
        if status2 == 200:
            other_eu_token = payload2["access_token"]
            status, _, _ = http("GET", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(other_eu_token)})
            check("GET /end-users/{id} par un AUTRE end-user -> 401", status == 401, f"status={status}")

    status, payload, _ = http("PATCH", f"/end-users/{eu_id}", {"first_name": "CarolUpdated"}, headers={**app_token_header(app_token), **bearer(owner_token)})
    check("PATCH /end-users/{id} par le owner de l'app -> 200", status == 200 and payload.get("first_name") == "CarolUpdated", f"status={status}")

    if admin_token:
        status, payload, _ = http("PATCH", f"/end-users/{eu_id}", {"last_name": "ByAdmin"}, headers={**app_token_header(app_token), **bearer(admin_token)})
        check("PATCH /end-users/{id} par un admin -> 200", status == 200 and payload.get("last_name") == "ByAdmin", f"status={status}")

    status, payload, _ = http("POST", f"/end-users/{eu_id}/deactivate", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("POST /end-users/{id}/deactivate (owner) -> 200", status == 200 and payload.get("is_active") is False, f"status={status}")

    status, payload, _ = http("POST", "/end-users/auth/login", {"email": eu_email, "password": eu_password}, headers=app_token_header(app_token))
    check("login end-user désactivé -> 403", status == 403, f"status={status}")

    status, payload, _ = http("POST", f"/end-users/{eu_id}/activate", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("POST /end-users/{id}/activate (owner) -> 200", status == 200 and payload.get("is_active") is True, f"status={status}")

    # forgot / reset password end-user
    idx = log_cursor()
    status, _, _ = http("POST", "/end-users/auth/forgot-password", {"email": eu_email}, headers=app_token_header(app_token))
    check("POST /end-users/auth/forgot-password -> 200", status == 200, f"status={status}")
    reset_token = wait_for_marker(f"[DEV] Reset password pour {eu_email} :", idx)
    check("token de reset end-user trouvé dans les logs", reset_token is not None)

    if reset_token:
        new_password = "NouveauMdp1!"
        status, _, _ = http("POST", "/end-users/auth/reset-password", {"email": eu_email, "token": "invalide", "new_password": new_password}, headers=app_token_header(app_token))
        check("reset-password end-user mauvais token -> 400", status == 400, f"status={status}")

        status, _, _ = http("POST", "/end-users/auth/reset-password", {"email": eu_email, "token": reset_token, "new_password": new_password}, headers=app_token_header(app_token))
        check("reset-password end-user bon token -> 200", status == 200, f"status={status}")

        status, _ = login_and_verify_end_user(app_token, eu_email, new_password)
        check("login end-user avec le nouveau mot de passe -> 200", status == 200, f"status={status}")
        eu_password = new_password

    # logout + blacklist end-user
    status, payload = login_and_verify_end_user(app_token, eu_email, eu_password)
    if status == 200:
        fresh_token = payload["access_token"]
        status, _, _ = http("POST", "/end-users/auth/logout", headers={**app_token_header(app_token), **bearer(fresh_token)})
        check("POST /end-users/auth/logout -> 200", status == 200, f"status={status}")

        status, _, _ = http("GET", "/end-users/me", headers={**app_token_header(app_token), **bearer(fresh_token)})
        check("GET /end-users/me avec token révoqué -> 401", status == 401, f"status={status}")

    status, _, _ = http("DELETE", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("DELETE /end-users/{id} (owner) -> 204", status == 204, f"status={status}")

    status, _, _ = http("GET", f"/end-users/{eu_id}", headers={**app_token_header(app_token), **bearer(owner_token)})
    check("GET /end-users/{id} après suppression -> 404", status == 404, f"status={status}")


def test_cross_jwt_isolation(users_ctx, apps_ctx):
    section("Isolation des JWT (User vs EndUser)")

    if not apps_ctx:
        info("section ignorée (pas d'App disponible)")
        return

    user_a = users_ctx["user_a"]
    status, payload = login_and_verify_user(user_a["email"], user_a["password"])
    if status != 200:
        info("impossible de relogger user A pour ce test")
        return
    user_token = payload["access_token"]

    status, _, _ = http("GET", "/end-users/me", headers={**app_token_header(apps_ctx["app_token"]), **bearer(user_token)})
    check("JWT User utilisé sur une route EndUser -> 401", status == 401, f"status={status}")

    status, payload, eu_email, eu_password = register_end_user(apps_ctx["app_token"], "erin")
    if status != 201:
        return
    status, payload = login_and_verify_end_user(apps_ctx["app_token"], eu_email, eu_password)
    if status != 200:
        return
    eu_token = payload["access_token"]

    status, _, _ = http("GET", "/users/me", headers=bearer(eu_token))
    check("JWT EndUser utilisé sur une route User -> 401", status == 401, f"status={status}")


def test_brute_force():
    section("Brute-force / rate limiting (login)")

    email = unique_email("bruteforce")
    password = "CorrectHorseBattery1!"
    status, payload, email, password2 = register_user("bruteforce")
    if status != 201:
        info("impossible de créer le compte pour le test de brute-force")
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

    check(f"brute-force login User : 429 obtenu après {attempts} tentative(s)", got_429, f"dernier status={status} body={payload}")
    check("header Retry-After présent sur la réponse 429", retry_after_present)

    if got_429:
        status, _, _ = http("POST", "/users/auth/login", {"email": email, "password": password})
        check("tentative supplémentaire (même avec le bon mot de passe) toujours bloquée -> 429", status == 429, f"status={status}")

    # Brute-force côté EndUser (nécessite une App)
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

    check(f"brute-force login EndUser : 429 obtenu après {attempts} tentative(s)", got_429, f"dernier status={status} body={payload}")


def test_audit_logs(apps_ctx, users_ctx, admin_ctx):
    section("Audit logs (lecture seule, admin / owner)")

    if not admin_ctx or not apps_ctx:
        info("section ignorée (admin ou App indisponible)")
        return

    admin_token = admin_ctx["token"]
    owner_token = apps_ctx["owner_token"]
    app_id = apps_ctx["app_id"]

    status, _, _ = http("POST", "/audit-logs", {})
    check("POST /audit-logs -> 405 (aucune route d'écriture, GET seul existe)", status == 405, f"status={status}")

    status, payload, _ = http("GET", "/audit-logs", headers=bearer(owner_token))
    check("GET /audit-logs (non-admin) -> 403", status == 403, f"status={status}")

    status, payload, _ = http("GET", "/audit-logs", headers=bearer(admin_token))
    ok = check(
        "GET /audit-logs (admin) -> 200, paginé et non vide",
        status == 200 and isinstance(payload.get("items"), list) and payload.get("total", 0) > 0,
        f"status={status} body={payload}",
    )
    if ok:
        check(
            "les entrées ont bien actor_type/event_type/created_at",
            all({"actor_type", "event_type", "created_at"} <= set(item.keys()) for item in payload["items"]),
        )

    status, payload, _ = http("GET", "/audit-logs?event_type=app_created", headers=bearer(admin_token))
    check(
        "GET /audit-logs?event_type=app_created -> 200, ne contient que ce type",
        status == 200 and all(item["event_type"] == "app_created" for item in payload.get("items", [])),
        f"status={status}",
    )

    status, payload, _ = http("GET", "/audit-logs?event_type=pas-un-event-valide", headers=bearer(admin_token))
    check("GET /audit-logs?event_type=invalide -> 422", status == 422, f"status={status}")

    status, payload, _ = http("GET", f"/audit-logs/apps/{app_id}", headers=bearer(owner_token))
    ok = check(
        "GET /audit-logs/apps/{id} (owner) -> 200, uniquement cette app",
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
            check("GET /audit-logs/apps/{id} par un non-owner non-admin -> 404", status == 404, f"status={status}")

    status, _, _ = http("GET", "/audit-logs/apps/00000000-0000-0000-0000-000000000000", headers=bearer(admin_token))
    check("GET /audit-logs/apps/{uuid inexistant} (admin) -> 404", status == 404, f"status={status}")


def cleanup(admin_ctx):
    section("Nettoyage")
    admin_token = admin_ctx["token"] if admin_ctx else None
    if not admin_token:
        info("pas de token admin disponible, nettoyage partiel")
        return

    for app_id in list(created_app_ids):
        status, _, _ = http("DELETE", f"/apps/{app_id}", headers=bearer(admin_token))
        info(f"suppression app {app_id} -> {status}")

    for user_id in list(created_user_ids):
        status, _, _ = http("DELETE", f"/users/{user_id}", headers=bearer(admin_token))
        info(f"suppression user {user_id} -> {status}")

    if admin_ctx:
        status, _, _ = http("DELETE", f"/users/{admin_ctx['id']}", headers=bearer(admin_token))
        info(f"suppression admin {admin_ctx['id']} -> {status}")


# ==================== Rapport ====================

def write_report():
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    lines = []
    lines.append(f"# Rapport de test — Step API")
    lines.append("")
    lines.append(f"Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"**Total : {total} | Réussis : {passed} | Échoués : {failed}**")
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
                lines.append(f"  - détail : `{i['detail']}`")
        lines.append("")

    if failed:
        lines.append("## Résumé des échecs")
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
    print(f"{color}{C.BOLD}Total : {total} | Réussis : {passed} | Échoués : {failed}{C.RESET}")
    print(f"Récap complet : {REPORT_PATH}")
    print(f"{C.BOLD}{'=' * 60}{C.RESET}")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_server()
        print("\nInterrompu par l'utilisateur.")
        sys.exit(130)
    except Exception as exc:
        stop_server()
        print(f"\n{C.RED}Erreur fatale : {exc}{C.RESET}")
        raise
