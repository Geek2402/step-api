import json
from pathlib import Path

from app.core.config import settings

SEED_DIR = Path(__file__).parent
BASE_URL = f"{settings.API_BASE_URL}{settings.API_V1_PREFIX}"


def load_seed_data() -> dict:
    with open(SEED_DIR / "seed_data.json", encoding="utf-8") as f:
        return json.load(f)


def render_email(seed_data: dict, owner: str, app_index: int, eu_index: int) -> str:
    return seed_data["end_user_email_template"].format(index=eu_index, owner=owner, app_index=app_index)


def pick_names(seed_data: dict, eu_index: int) -> tuple[str, str]:
    pool = seed_data["end_user_name_pool"]
    first_names = pool["first_names"]
    last_names = pool["last_names"]
    first = first_names[eu_index % len(first_names)]
    last = last_names[(eu_index // len(first_names)) % len(last_names)]
    return first, last
