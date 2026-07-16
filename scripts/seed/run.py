import asyncio

from app.core.redis_client import redis_client
from app.db.session import AsyncSessionLocal

from . import audit_flow, bulk, cleanup, creds
from .config import BASE_URL, load_seed_data
from .db_checks import scan_seed_state
from .state import SeedRunSessions


def ask_yes_no(question: str) -> bool:
    while True:
        answer = input(f"{question} [y/n]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


async def main() -> None:
    seed_data = load_seed_data()
    sessions = SeedRunSessions()

    async with AsyncSessionLocal() as session:
        print("=== Step seed script ===")
        print(f"Target API: {BASE_URL}")
        print("The API server must already be running (uvicorn app.main:app).\n")

        print("--- Credential verification ---")
        sessions.admin = await creds.verify_account(BASE_URL, redis_client, session, "admin", expect_admin=True)
        print(f"Admin OK: {sessions.admin.email}")
        sessions.dev = await creds.verify_account(BASE_URL, redis_client, session, "dev", expect_admin=False)
        print(f"Dev OK: {sessions.dev.email}\n")

        print("--- Scanning existing seed data ---")
        state = await scan_seed_state(session, sessions.admin.actor_id, sessions.dev.actor_id, seed_data)
        total_apps = state.total_apps
        total_eus = state.total_end_users
        print(
            f"Apps: {state.apps_present_count}/{total_apps} present. "
            f"EndUsers: {state.end_users_present_count}/{total_eus} present.\n"
        )

        run_audit = False
        if state.is_complete:
            print("Seed data already fully present.")
            run_audit = ask_yes_no("Generate a fresh batch of audit-log activity anyway?")
        elif state.is_empty:
            print("No seed data found. Creating the 20 static Apps and 1000 EndUsers...")
            await bulk.create_missing_apps_and_end_users(BASE_URL, sessions, state, seed_data)
            print("Static seed data created.")
            run_audit = ask_yes_no("Also generate audit-log activity now?")
        else:
            print("Partial seed data found.")
            if ask_yes_no("Create the missing pieces?"):
                await bulk.create_missing_apps_and_end_users(BASE_URL, sessions, state, seed_data)
                print("Missing pieces created.")
                run_audit = ask_yes_no("Also generate audit-log activity now?")
            else:
                print("Stopping without creating anything further.")

        if run_audit:
            await audit_flow.run_audit_flow(BASE_URL, redis_client, session, sessions, state, seed_data)

        print("\n--- Cleanup ---")
        await cleanup.logout_everything(BASE_URL, sessions)

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
