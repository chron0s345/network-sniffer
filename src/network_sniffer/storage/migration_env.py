"""Logik der Alembic-Umgebung (``migrations/env.py`` ruft nur ``run(context)`` auf).

Liegt als normales Modul im Paket, damit sie importierbar und testbar ist; Alembic lädt ``env.py``
außerhalb des Import-Systems.

Zur Laufzeit übergibt ``storage.db.run_migrations`` eine offene Verbindung. Über die Alembic-CLI
wird die Datenbank aus den Settings (``NS_DATA_DIR``) bestimmt.
"""

from logging.config import fileConfig
from typing import Any

from sqlalchemy.engine import Connection

from network_sniffer.config import load_settings
from network_sniffer.storage.db import create_db_engine, database_url
from network_sniffer.storage.models import Base

target_metadata = Base.metadata


def _configure_and_run(context: Any, **options: Any) -> None:
    context.configure(
        target_metadata=target_metadata,
        render_as_batch=True,  # SQLite kann ALTER TABLE nur eingeschränkt
        **options,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_offline(context: Any) -> None:
    url = context.config.get_main_option("sqlalchemy.url") or database_url(load_settings())
    _configure_and_run(context, url=url, literal_binds=True)


def _run_online(context: Any) -> None:
    connection: Connection | None = context.config.attributes.get("connection")
    if connection is not None:
        _configure_and_run(context, connection=connection)
        return
    engine = create_db_engine(load_settings())
    try:
        with engine.begin() as new_connection:
            _configure_and_run(context, connection=new_connection)
    finally:
        engine.dispose()


def run(context: Any) -> None:
    """Einstiegspunkt für ``env.py``; ``context`` ist ``alembic.context``."""
    if context.config.config_file_name is not None:
        fileConfig(context.config.config_file_name, disable_existing_loggers=False)
    if context.is_offline_mode():
        _run_offline(context)
    else:
        _run_online(context)
