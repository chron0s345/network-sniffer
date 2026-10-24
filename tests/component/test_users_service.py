"""KAN-37: Anlage des ersten Admins (Service) und Ausschluss weiterer Setups."""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from conftest import synthetic_password
from sqlalchemy import Engine, func, inspect, select
from sqlalchemy.orm import Session

from network_sniffer.config import Settings
from network_sniffer.security.passwords import PasswordPolicyError, Passwords
from network_sniffer.services.users import (
    SetupAlreadyCompletedError,
    UsernameError,
    create_initial_admin,
    normalize_username,
    users_exist,
    validate_username,
)
from network_sniffer.storage.db import create_db_engine, run_migrations
from network_sniffer.storage.models import Role, User

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


@pytest.fixture
def engine(settings: Settings) -> Iterator[Engine]:
    engine = create_db_engine(settings)
    run_migrations(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def passwords() -> Passwords:
    return Passwords(time_cost=1, memory_cost_kib=8, parallelism=1)


def _create(session: Session, passwords: Passwords, username: str = "Admin.Eins") -> object:
    return create_initial_admin(
        session,
        username=username,
        password=synthetic_password(),
        passwords=passwords,
        clock=FixedClock(),
    )


def test_ac2_creates_admin_with_normalized_username_and_timestamps(
    engine: Engine, passwords: Passwords
) -> None:
    with Session(engine) as session:
        created = _create(session, passwords, username="  Admin.Eins  ")

    with Session(engine) as session:
        user = session.scalars(select(User)).one()
    assert created.id == user.id  # type: ignore[attr-defined]
    assert user.username == "Admin.Eins"
    assert user.username_normalized == "admin.eins"
    assert user.role == Role.ADMIN
    assert user.password_hash.startswith("$argon2id$")
    assert user.created_at.replace(tzinfo=UTC) == NOW
    assert user.updated_at.replace(tzinfo=UTC) == NOW


def test_ac4_second_initial_admin_is_refused(engine: Engine, passwords: Passwords) -> None:
    with Session(engine) as session:
        _create(session, passwords)

    with Session(engine) as session, pytest.raises(SetupAlreadyCompletedError):
        _create(session, passwords, username="zweiter")

    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(User)) == 1


def test_ac4_conditional_insert_refuses_when_user_appears_after_check(
    engine: Engine, passwords: Passwords, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Race: Prüfung sieht keinen Benutzer, ein paralleles Setup legt ihn vor dem INSERT an.
    import network_sniffer.services.users as users_module

    monkeypatch.setattr(users_module, "users_exist", lambda _session: False)
    with Session(engine) as session:
        _create(session, passwords)

    with Session(engine) as session, pytest.raises(SetupAlreadyCompletedError):
        _create(session, passwords, username="parallel")

    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(User)) == 1


def test_ac5_short_password_creates_no_user(engine: Engine, passwords: Passwords) -> None:
    with Session(engine) as session, pytest.raises(PasswordPolicyError):
        create_initial_admin(
            session, username="admin", password="a" * 11, passwords=passwords, clock=FixedClock()
        )
        assert not users_exist(session)


def test_users_exist(engine: Engine, passwords: Passwords) -> None:
    with Session(engine) as session:
        assert users_exist(session) is False
        _create(session, passwords)
        assert users_exist(session) is True


@pytest.mark.parametrize("username", ["ab", "a" * 65, "mit leer", "a/b", "<x>", "", "   "])
def test_invalid_usernames_are_rejected(username: str) -> None:
    with pytest.raises(UsernameError):
        validate_username(username)


@pytest.mark.parametrize("username", ["abc", "jörg.müller", "admin@pc", "a_b-c", "a" * 64])
def test_valid_usernames_are_accepted(username: str) -> None:
    assert validate_username(username) == username


def test_username_normalization_is_case_insensitive() -> None:
    assert normalize_username("ADMIN") == normalize_username("admin")
    assert normalize_username("Straße") == normalize_username("STRASSE")


def test_users_table_has_role_check_and_unique_username(engine: Engine) -> None:
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("users")}
    assert columns == {
        "id",
        "username",
        "username_normalized",
        "password_hash",
        "role",
        "is_active",
        "must_change_password",
        "created_at",
        "updated_at",
    }
    unique = [u["column_names"] for u in inspector.get_unique_constraints("users")]
    assert ["username_normalized"] in unique
    checks = [c["sqltext"] for c in inspector.get_check_constraints("users")]
    assert any("admin" in text and "analyst" in text for text in checks)
