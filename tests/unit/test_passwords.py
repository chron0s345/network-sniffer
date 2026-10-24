"""KAN-37: Argon2id-Hashing und Passwort-Richtlinie."""

import pytest
from conftest import synthetic_password

from network_sniffer.config import Settings
from network_sniffer.security.passwords import (
    PASSWORD_MAX_LENGTH,
    PasswordPolicyError,
    Passwords,
    validate_password_policy,
)


@pytest.fixture
def passwords() -> Passwords:
    return Passwords(time_cost=1, memory_cost_kib=8, parallelism=1)


def test_ac2_hash_is_argon2id_and_verifies(passwords: Passwords) -> None:
    password = synthetic_password()

    password_hash = passwords.hash(password)

    assert password_hash.startswith("$argon2id$")
    assert password not in password_hash
    assert passwords.verify(password_hash, password) is True
    assert passwords.verify(password_hash, password + "x") is False


def test_hashes_are_salted(passwords: Passwords) -> None:
    password = synthetic_password()

    assert passwords.hash(password) != passwords.hash(password)


def test_verify_returns_false_for_invalid_hash(passwords: Passwords) -> None:
    assert passwords.verify("kein-hash", synthetic_password()) is False


def test_needs_rehash_when_cost_parameters_change(passwords: Passwords) -> None:
    password_hash = passwords.hash(synthetic_password())
    stronger = Passwords(time_cost=2, memory_cost_kib=16, parallelism=1)

    assert passwords.needs_rehash(password_hash) is False
    assert stronger.needs_rehash(password_hash) is True


def test_cost_parameters_come_from_settings() -> None:
    settings = Settings(
        _env_file=None, argon2_time_cost=2, argon2_memory_cost_kib=32, argon2_parallelism=2
    )

    password_hash = Passwords.from_settings(settings).hash(synthetic_password())

    assert "m=32,t=2,p=2" in password_hash


def test_default_cost_parameters_follow_rfc9106() -> None:
    settings = Settings(_env_file=None)

    assert (settings.argon2_time_cost, settings.argon2_memory_cost_kib) == (3, 65536)
    assert settings.argon2_parallelism == 4


def test_settings_reject_too_little_memory_for_parallelism() -> None:
    with pytest.raises(ValueError, match="NS_ARGON2_MEMORY_COST_KIB"):
        Settings(_env_file=None, argon2_memory_cost_kib=8, argon2_parallelism=2)


@pytest.mark.parametrize("length", [0, 1, 11])
def test_ac5_passwords_shorter_than_12_characters_are_rejected(length: int) -> None:
    with pytest.raises(PasswordPolicyError) as excinfo:
        validate_password_policy("a" * length)

    assert str(excinfo.value) == "Passwort muss mindestens 12 Zeichen haben"


@pytest.mark.parametrize("length", [12, 64, PASSWORD_MAX_LENGTH])
def test_ac5_passwords_with_12_or_more_characters_are_accepted(length: int) -> None:
    validate_password_policy("a" * length)


def test_ac5_unicode_characters_count_as_characters() -> None:
    validate_password_policy("ä" * 12)


def test_overlong_passwords_are_rejected() -> None:
    with pytest.raises(PasswordPolicyError, match="höchstens"):
        validate_password_policy("a" * (PASSWORD_MAX_LENGTH + 1))
