"""Passwort-Hashing (Argon2id über argon2-cffi) und Passwort-Richtlinie."""

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

from network_sniffer.config import Settings

PASSWORD_MIN_LENGTH = 12
# Obergrenze gegen Rechenlast durch riesige Eingaben (Argon2 verarbeitet beliebige Längen).
PASSWORD_MAX_LENGTH = 1024
PASSWORD_TOO_SHORT_MESSAGE = f"Passwort muss mindestens {PASSWORD_MIN_LENGTH} Zeichen haben"
PASSWORD_TOO_LONG_MESSAGE = f"Passwort darf höchstens {PASSWORD_MAX_LENGTH} Zeichen haben"


class PasswordPolicyError(ValueError):
    """Passwort erfüllt die Richtlinie nicht; die Nachricht ist für Benutzer bestimmt."""


def validate_password_policy(password: str) -> None:
    """Prüft die Richtlinie (KAN-37, wiederverwendet von KAN-40/KAN-41)."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise PasswordPolicyError(PASSWORD_TOO_SHORT_MESSAGE)
    if len(password) > PASSWORD_MAX_LENGTH:
        raise PasswordPolicyError(PASSWORD_TOO_LONG_MESSAGE)


class Passwords:
    """Hasht und prüft Passwörter mit Argon2id; Kostenparameter aus den Settings."""

    def __init__(self, time_cost: int, memory_cost_kib: int, parallelism: int) -> None:
        self._hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            type=Type.ID,
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> "Passwords":
        return cls(
            time_cost=settings.argon2_time_cost,
            memory_cost_kib=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
        )

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)
