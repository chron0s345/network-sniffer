"""Benutzer: Ersteinrichtung des ersten Admins (KAN-37)."""

import re
import unicodedata
from dataclasses import dataclass

from sqlalchemy import exists, insert, literal, select
from sqlalchemy.orm import Session

from network_sniffer.clock import Clock
from network_sniffer.security.passwords import Passwords, validate_password_policy
from network_sniffer.storage.models import USERNAME_MAX_LENGTH, Role, User

USERNAME_MIN_LENGTH = 3
# Buchstaben/Ziffern (auch Umlaute), Unterstrich, Punkt, Bindestrich, @ - keine Leer-/Steuerzeichen.
_USERNAME_PATTERN = re.compile(r"[\w.@-]+")
USERNAME_INVALID_MESSAGE = (
    f"Benutzername muss {USERNAME_MIN_LENGTH} bis {USERNAME_MAX_LENGTH} Zeichen lang sein und "
    "darf nur Buchstaben, Ziffern sowie . _ - @ enthalten"
)


class UsernameError(ValueError):
    """Benutzername ist ungültig; die Nachricht ist für Benutzer bestimmt."""


class SetupAlreadyCompletedError(Exception):
    """Es existiert bereits ein Benutzer - die Ersteinrichtung ist nicht mehr möglich."""


@dataclass(frozen=True)
class CreatedUser:
    id: int
    username: str
    role: Role


def normalize_username(username: str) -> str:
    return unicodedata.normalize("NFKC", username).casefold()


def validate_username(username: str) -> str:
    """Bereinigter Benutzername (ohne Rand-Leerzeichen, NFKC); sonst ``UsernameError``."""
    cleaned = unicodedata.normalize("NFKC", username.strip())
    if not (
        USERNAME_MIN_LENGTH <= len(cleaned) <= USERNAME_MAX_LENGTH
        and _USERNAME_PATTERN.fullmatch(cleaned)
    ):
        raise UsernameError(USERNAME_INVALID_MESSAGE)
    return cleaned


def users_exist(session: Session) -> bool:
    return bool(session.scalar(select(exists().where(User.id.is_not(None)))))


def create_initial_admin(
    session: Session,
    *,
    username: str,
    password: str,
    passwords: Passwords,
    clock: Clock,
) -> CreatedUser:
    """Legt den ersten Admin an - nur, solange kein Benutzer existiert.

    Prüfung und Anlage sind **ein** ``INSERT ... SELECT ... WHERE NOT EXISTS``: SQLite nimmt die
    Schreibsperre zu Beginn der Anweisung, damit kann von zwei gleichzeitigen Setups (Web, API, CLI,
    auch aus verschiedenen Prozessen) nur eines einen Benutzer anlegen.
    """
    cleaned = validate_username(username)
    validate_password_policy(password)
    if users_exist(session):
        raise SetupAlreadyCompletedError
    session.rollback()  # frischer Snapshot: die Anlage beginnt eine neue Transaktion
    password_hash = passwords.hash(password)
    now = clock.now()
    values = {
        "username": cleaned,
        "username_normalized": normalize_username(cleaned),
        "password_hash": password_hash,
        "role": Role.ADMIN.value,
        "is_active": True,
        "must_change_password": False,
        "created_at": now,
        "updated_at": now,
    }
    columns = list(values)
    source = select(
        *(literal(value, User.__table__.c[name].type) for name, value in values.items())
    )
    statement = insert(User).from_select(
        columns, source.where(~exists().where(User.id.is_not(None)))
    )
    result = session.execute(statement)
    if result.rowcount != 1:
        session.rollback()
        raise SetupAlreadyCompletedError
    session.commit()
    user_id = session.scalars(
        select(User.id).where(User.username_normalized == values["username_normalized"])
    ).one()
    return CreatedUser(id=user_id, username=cleaned, role=Role.ADMIN)
