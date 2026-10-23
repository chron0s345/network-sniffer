"""Datenbank-Basis: Migration auf leerer DB, Pragmas, Alembic-CLI-Pfade."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from network_sniffer.config import Settings
from network_sniffer.storage.db import (
    DB_FILE_NAME,
    alembic_config,
    create_db_engine,
    database_url,
    run_migrations,
)


def test_migration_creates_settings_table_on_empty_database(settings: Settings) -> None:
    engine = create_db_engine(settings)
    try:
        run_migrations(engine)

        inspector = inspect(engine)
        assert "settings" in inspector.get_table_names()
        columns = {column["name"] for column in inspector.get_columns("settings")}
        assert columns == {"key", "value", "updated_at"}
        with engine.connect() as connection:
            head = ScriptDirectory.from_config(alembic_config()).get_current_head()
            current = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert current == head == "0001"
    finally:
        engine.dispose()


def test_migrations_are_idempotent(settings: Settings) -> None:
    engine = create_db_engine(settings)
    try:
        run_migrations(engine)
        run_migrations(engine)
        with engine.connect() as connection:
            rows = connection.execute(text("SELECT count(*) FROM alembic_version")).scalar()
        assert rows == 1
    finally:
        engine.dispose()


def test_settings_table_stores_json_values(settings: Settings) -> None:
    engine = create_db_engine(settings)
    try:
        run_migrations(engine)
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO settings (key, value) VALUES (:key, :value)"),
                {"key": "retention", "value": '{"days": 30}'},
            )
            row = connection.execute(
                text("SELECT value, updated_at FROM settings WHERE key = 'retention'")
            ).one()
        assert row.value == '{"days": 30}'
        assert row.updated_at is not None
    finally:
        engine.dispose()


def test_engine_sets_sqlite_pragmas_and_creates_data_dir(tmp_path: Path) -> None:
    data_dir = tmp_path / "nested" / "data"
    engine = create_db_engine(Settings(_env_file=None, data_dir=data_dir))
    try:
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA journal_mode")).scalar() == "wal"
            assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
            assert connection.execute(text("PRAGMA secure_delete")).scalar() == 1
        assert (data_dir / DB_FILE_NAME).is_file()
    finally:
        engine.dispose()


def test_database_url_points_into_data_dir(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path)

    assert database_url(settings) == f"sqlite:///{(tmp_path / DB_FILE_NAME).as_posix()}"


def test_app_start_migrates_database(client: object, settings: Settings) -> None:
    engine = create_db_engine(settings)
    try:
        assert "settings" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_alembic_cli_path_uses_settings_from_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Ohne übergebene Verbindung (wie bei `alembic upgrade head`) kommt die DB aus NS_DATA_DIR.
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))

    command.upgrade(alembic_config(), "head")

    engine = create_db_engine(Settings(_env_file=None, data_dir=tmp_path))
    try:
        assert "settings" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_alembic_ini_of_repository_migrates_and_models_match_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Weg der Entwickler-Befehle (`uv run alembic ...`): alembic.ini im Repo-Wurzelverzeichnis.
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))
    ini = Path(__file__).resolve().parents[2] / "alembic.ini"
    config = Config(str(ini))

    command.upgrade(config, "head")
    # Modelle und Migrationen stimmen überein (sonst wirft `check` eine Ausnahme).
    command.check(config)


def test_alembic_offline_mode_renders_sql(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))

    command.upgrade(alembic_config(), "head", sql=True)

    output = capsys.readouterr().out
    assert "CREATE TABLE settings" in output


def test_downgrade_removes_settings_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))
    config = alembic_config()
    command.upgrade(config, "head")

    command.downgrade(config, "base")

    engine = create_db_engine(Settings(_env_file=None, data_dir=tmp_path))
    try:
        assert "settings" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()
