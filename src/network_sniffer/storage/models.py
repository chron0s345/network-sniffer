"""SQLAlchemy-Modelle."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

USERNAME_MAX_LENGTH = 64


class Base(DeclarativeBase):
    pass


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"


class Setting(Base):
    """Generische Einstellungen als Schlüssel/Wert (JSON), z. B. Aufbewahrung, Capture-Zustand."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )


class User(Base):
    """Benutzerkonto. Kein voreingestelltes Konto - der erste Admin entsteht per Setup (KAN-37)."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin', 'analyst')", name="ck_users_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(USERNAME_MAX_LENGTH), nullable=False)
    # Eindeutigkeit ohne Rücksicht auf Groß-/Kleinschreibung (NFKC + casefold).
    username_normalized: Mapped[str] = mapped_column(
        String(USERNAME_MAX_LENGTH), nullable=False, unique=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
