"""Zeitabstraktion: Uhrzeit nur über ``Clock``, immer in UTC.

Tests stellen die Uhr mit time-machine (``SystemClock`` nutzt ``datetime.now``).
"""

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Aktuelle Zeit, zeitzonenbehaftet in UTC."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
