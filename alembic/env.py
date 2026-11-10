"""Alembic environment: uses the LeakLens settings database URL + metadata.

Fresh database:  alembic upgrade head
Existing database created by create_all: alembic stamp head  (records the
baseline without touching existing tables; future migrations then apply
normally with alembic upgrade head).
"""
from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from backend.app.core.config import settings
from backend.app.database.db import Base
import backend.app.models.entities  # noqa: F401  (register all tables)

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=settings.database_url, target_metadata=target_metadata,
                      literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(settings.database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
