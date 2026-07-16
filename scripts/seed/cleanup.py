from . import http
from .state import SeedRunSessions


async def logout_everything(base_url: str, sessions: SeedRunSessions) -> None:
    """Logs out every session the script itself opened (admin, dev, and any fixture session
    whose own logout wasn't already part of the audit-flow demo)."""
    open_sessions = sessions.all_open_sessions()
    if not open_sessions:
        print("Nothing left to log out.")
        return

    print(f"Logging out {len(open_sessions)} session(s)...")
    for account in open_sessions:
        prefix = "/end-users/auth" if account.kind == "end_user" else "/users/auth"
        headers = http.auth_header(account.token)
        if account.kind == "end_user":
            headers.update(http.app_token_header(account.app_token))
        status, body = http.request("POST", f"{base_url}{prefix}/logout", None, headers)
        if status == 200:
            account.blacklisted = True
        else:
            print(f"  warning: logout failed for {account.email} ({status}: {body})")
