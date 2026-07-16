import uuid
from collections import defaultdict

from . import http
from .config import pick_names, render_email
from .state import SeedRunSessions, SeedState


async def create_missing_apps_and_end_users(
    base_url: str, sessions: SeedRunSessions, state: SeedState, seed_data: dict
) -> None:
    """Gap-aware: creates only the static Apps/EndUsers that scan_seed_state() found missing.
    Never touches an App/EndUser that already exists. Same code path whether the DB was
    completely empty or only partially seeded."""
    for owner in ("admin", "dev"):
        owner_session = sessions.admin if owner == "admin" else sessions.dev
        owner_headers = http.auth_header(owner_session.token)

        for index in state.apps_missing_for(owner):
            app_def = seed_data["apps"][owner][index]
            status, body = http.request(
                "POST",
                f"{base_url}/apps",
                {"name": app_def["name"], "frontend_url": app_def["frontend_url"]},
                owner_headers,
            )
            if status != 201:
                raise RuntimeError(f"Failed to create App '{app_def['name']}' ({status}: {body})")
            state.set_app_created(owner, index, uuid.UUID(body["id"]), body["token"])
            print(f"  created App '{app_def['name']}'")

        missing_by_app: dict[int, list[int]] = defaultdict(list)
        for app_index, eu_index in state.end_users_missing_for(owner):
            missing_by_app[app_index].append(eu_index)

        for app_index, eu_indices in missing_by_app.items():
            app_id = state.get_app_id(owner, app_index)
            app_token = state.get_app_token(owner, app_index)
            if app_token is None:
                # Plaintext tokens are only ever shown once, at creation/rotation — a
                # pre-existing App (from a previous run) has no known token in this
                # process, so rotate to obtain a usable one (harmless: also exercises
                # APP_TOKEN_ROTATED, and never touches the App's name identity).
                status, body = http.request(
                    "POST", f"{base_url}/apps/{app_id}/rotate-token", None, owner_headers
                )
                if status != 200:
                    raise RuntimeError(f"Failed to rotate token for App {app_id} ({status}: {body})")
                app_token = body["token"]
                state.set_app_token(owner, app_index, app_token)

            app_headers = http.app_token_header(app_token)
            for eu_index in eu_indices:
                first, last = pick_names(seed_data, eu_index)
                email = render_email(seed_data, owner, app_index, eu_index)
                status, body = http.request(
                    "POST",
                    f"{base_url}/end-users",
                    {
                        "first_name": first,
                        "last_name": last,
                        "email": email,
                        "password": seed_data["default_password"],
                    },
                    app_headers,
                )
                if status != 201:
                    raise RuntimeError(f"Failed to create EndUser '{email}' ({status}: {body})")
            print(f"  created {len(eu_indices)} EndUser(s) under App index {app_index} ({owner})")
