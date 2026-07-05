import asyncio
import os
import sys
from logging.config import fileConfig

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection

from app.core.config import settings
from app.db.base import Base
from app.models import App, AuditLog, EndUser, User  # noqa: F401 — required for autogenerate

# Alembic config
config = context.config

# Configure logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for auto-generated migrations
target_metadata = Base.metadata

# DO NOT use config.set_main_option() because configparser
# interprets % as interpolation characters.
# We pass the URL directly to the engine instead.


def run_migrations_offline() -> None:
    """Offline mode: generates SQL without a DB connection."""
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Online mode: async migrations against PostgreSQL."""
    # We create the engine directly with the URL from settings
    # to avoid the % issue in configparser
    from sqlalchemy.ext.asyncio import create_async_engine
    connectable = create_async_engine(
        settings.DATABASE_URL,
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
