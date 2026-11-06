"""KAN-37 AC6: kein voreingestelltes Benutzerkonto, kein Default-Passwort."""

import re
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from network_sniffer.config import Settings
from network_sniffer.storage.db import create_db_engine, run_migrations
from network_sniffer.storage.models import User

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_ac6_migrations_create_no_user(settings: Settings) -> None:
    engine = create_db_engine(settings)
    try:
        run_migrations(engine)
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(User)) == 0
    finally:
        engine.dispose()


def test_ac6_app_start_creates_no_user(client) -> None:
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(User)) == 0


def test_ac6_settings_have_no_user_or_password_defaults() -> None:
    suspicious = re.compile(r"pass|user|admin|login", re.IGNORECASE)
    fields = {name for name in Settings.model_fields if suspicious.search(name)}

    assert fields == set()


def test_ac6_env_example_has_no_account_or_password_values() -> None:
    content = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    assignments = [
        line for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]

    assert not [line for line in assignments if re.search(r"PASS|USER|ADMIN", line, re.I)]


def test_ac6_migrations_contain_no_insert_into_users() -> None:
    versions = PROJECT_ROOT / "src" / "network_sniffer" / "migrations" / "versions"
    for script in versions.glob("*.py"):
        text = script.read_text(encoding="utf-8").lower()
        assert "bulk_insert" not in text
        assert "insert into users" not in text
