import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.app import App
from app.models.end_user import EndUser
from app.models.user import User

from .config import render_email
from .state import SeedState


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_app_by_owner_and_name(session: AsyncSession, owner_id: uuid.UUID, name: str) -> App | None:
    result = await session.execute(select(App).where(App.owner_id == owner_id, App.name == name))
    return result.scalar_one_or_none()


async def get_end_user_by_app_and_email(session: AsyncSession, app_id: uuid.UUID, email: str) -> EndUser | None:
    result = await session.execute(select(EndUser).where(EndUser.app_id == app_id, EndUser.email == email))
    return result.scalar_one_or_none()


async def scan_seed_state(
    session: AsyncSession, admin_id: uuid.UUID, dev_id: uuid.UUID, seed_data: dict
) -> SeedState:
    """Read-only scan of the 20 static Apps + up to 1000 EndUsers described by seed_data.json,
    comparing against what's actually in the DB right now."""
    state = SeedState()
    owners = {"admin": admin_id, "dev": dev_id}

    for owner_label, owner_id in owners.items():
        for app_def in seed_data["apps"][owner_label]:
            app_row = await get_app_by_owner_and_name(session, owner_id, app_def["name"])
            state.record_app(owner_label, app_def["index"], app_row.id if app_row else None)

            if app_row is None:
                for eu_index in range(seed_data["end_users_per_app"]):
                    state.record_end_user_missing(owner_label, app_def["index"], eu_index)
                continue

            expected_emails = {
                eu_index: render_email(seed_data, owner_label, app_def["index"], eu_index)
                for eu_index in range(seed_data["end_users_per_app"])
            }
            result = await session.execute(
                select(EndUser.email).where(
                    EndUser.app_id == app_row.id, EndUser.email.in_(expected_emails.values())
                )
            )
            existing_emails = {row[0] for row in result.all()}
            for eu_index, email in expected_emails.items():
                if email in existing_emails:
                    state.record_end_user_present(owner_label, app_def["index"], eu_index)
                else:
                    state.record_end_user_missing(owner_label, app_def["index"], eu_index)

    return state
