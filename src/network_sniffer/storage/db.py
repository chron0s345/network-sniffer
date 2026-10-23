"""Datenbank-Engine, Sessions und Migrationen."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session

from network_sniffer.config import Settings

DB_FILE_NAME = "network-sniffer.db"
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def database_url(settings: Settings) -> str:
    return f"sqlite:///{(settings.data_dir / DB_FILE_NAME).as_posix()}"


def _apply_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA secure_delete=ON")
    finally:
        cursor.close()


def create_db_engine(settings: Settings) -> Engine:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        database_url(settings),
        connect_args={"check_same_thread": False},
    )
    event.listen(engine, "connect", _apply_sqlite_pragmas)
    return engine


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", MIGRATIONS_DIR.as_posix())
    return config


def run_migrations(engine: Engine) -> None:
    """Bringt das Schema beim Start auf ``head`` (Updates ohne manuellen Schritt)."""
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session
