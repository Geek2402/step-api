import uuid
from dataclasses import dataclass, field


class SeedState:
    """Result of scanning the DB for the 20 static Apps + 1000 EndUsers described by
    seed_data.json. Also doubles as a cache of known App tokens (plaintext tokens are only
    ever visible once, right after a create/rotate call)."""

    def __init__(self):
        self.app_ids: dict[tuple[str, int], uuid.UUID | None] = {}
        self.app_tokens: dict[tuple[str, int], str] = {}
        self.end_user_status: dict[tuple[str, int, int], bool] = {}

    def record_app(self, owner: str, index: int, app_id: uuid.UUID | None) -> None:
        self.app_ids[(owner, index)] = app_id

    def record_end_user_present(self, owner: str, app_index: int, eu_index: int) -> None:
        self.end_user_status[(owner, app_index, eu_index)] = True

    def record_end_user_missing(self, owner: str, app_index: int, eu_index: int) -> None:
        self.end_user_status[(owner, app_index, eu_index)] = False

    def set_app_created(self, owner: str, index: int, app_id: uuid.UUID, token: str) -> None:
        self.app_ids[(owner, index)] = app_id
        self.app_tokens[(owner, index)] = token

    def set_app_token(self, owner: str, index: int, token: str) -> None:
        self.app_tokens[(owner, index)] = token

    def get_app_id(self, owner: str, index: int) -> uuid.UUID | None:
        return self.app_ids.get((owner, index))

    def get_app_token(self, owner: str, index: int) -> str | None:
        return self.app_tokens.get((owner, index))

    @property
    def apps_missing(self) -> list[tuple[str, int]]:
        return [(owner, index) for (owner, index), app_id in self.app_ids.items() if app_id is None]

    @property
    def apps_present_count(self) -> int:
        return sum(1 for app_id in self.app_ids.values() if app_id is not None)

    @property
    def total_apps(self) -> int:
        return len(self.app_ids)

    @property
    def end_users_missing(self) -> list[tuple[str, int, int]]:
        return [key for key, present in self.end_user_status.items() if not present]

    @property
    def end_users_present_count(self) -> int:
        return sum(1 for present in self.end_user_status.values() if present)

    @property
    def total_end_users(self) -> int:
        return len(self.end_user_status)

    @property
    def is_complete(self) -> bool:
        return self.total_apps > 0 and not self.apps_missing and not self.end_users_missing

    @property
    def is_empty(self) -> bool:
        return self.apps_present_count == 0 and self.end_users_present_count == 0

    def apps_missing_for(self, owner: str) -> list[int]:
        return [index for (o, index) in self.apps_missing if o == owner]

    def end_users_missing_for(self, owner: str) -> list[tuple[int, int]]:
        return [(app_index, eu_index) for (o, app_index, eu_index) in self.end_users_missing if o == owner]


@dataclass
class AccountSession:
    """A logged-in identity the script itself created via the real HTTP API (User or EndUser),
    tracked so phase 4 can log everything out at the end."""

    email: str
    actor_id: uuid.UUID
    token: str
    jti: str
    kind: str  # "user" or "end_user"
    is_admin: bool = False
    blacklisted: bool = False
    app_token: str | None = None  # required alongside `token` to log out an "end_user" session


@dataclass
class SeedRunSessions:
    admin: AccountSession | None = None
    dev: AccountSession | None = None
    others: list[AccountSession] = field(default_factory=list)

    def track(self, session: AccountSession) -> None:
        self.others.append(session)

    def all_open_sessions(self) -> list[AccountSession]:
        sessions = []
        for session in (self.admin, self.dev, *self.others):
            if session is not None and not session.blacklisted:
                sessions.append(session)
        return sessions
