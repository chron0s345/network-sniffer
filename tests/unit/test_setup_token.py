"""KAN-37: Lebenszyklus des Setup-Tokens (Security-Empfehlung aus dem Review von KAN-10)."""

from datetime import UTC, datetime, timedelta

import time_machine

from network_sniffer.clock import SystemClock
from network_sniffer.security.setup import SetupState, SetupTokenManager, is_setup_exempt

START = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


class FixedClock:
    def __init__(self, now: datetime) -> None:
        self.current = now

    def now(self) -> datetime:
        return self.current


def _manager(clock: FixedClock | None = None, minutes: int = 60) -> SetupTokenManager:
    return SetupTokenManager(clock or FixedClock(START), timedelta(minutes=minutes))


def test_ac1_token_has_at_least_128_bit_and_is_random() -> None:
    manager = _manager()

    tokens = {manager.issue() for _ in range(20)}

    assert len(tokens) == 20
    assert all(len(t) == 43 for t in tokens)  # 32 Byte = 256 Bit, Base64url


def test_ac2_token_is_stored_only_as_hash() -> None:
    manager = _manager()
    token = manager.issue()

    state = vars(manager)
    assert all(token not in repr(value) for value in state.values())
    assert isinstance(manager._digest, bytes)
    assert len(manager._digest) == 32  # SHA-256


def test_ac2_token_verifies_until_invalidated() -> None:
    manager = _manager()
    token = manager.issue()

    assert manager.verify(token) is True
    manager.invalidate()

    assert manager.verify(token) is False
    assert manager.is_active is False
    assert manager.expires_at is None


def test_ac3_wrong_empty_and_missing_tokens_are_rejected() -> None:
    manager = _manager()
    token = manager.issue()

    assert manager.verify(None) is False
    assert manager.verify("") is False
    assert manager.verify(token + "x") is False
    assert manager.verify(token.upper() if token != token.upper() else token.lower()) is False


def test_ac3_no_token_is_valid_before_issue() -> None:
    assert _manager().verify("irgendwas") is False


def test_ac3_token_expires_after_ttl() -> None:
    clock = FixedClock(START)
    manager = _manager(clock, minutes=60)
    token = manager.issue()
    assert manager.expires_at == START + timedelta(minutes=60)

    clock.current = START + timedelta(minutes=59, seconds=59)
    assert manager.verify(token) is True

    clock.current = START + timedelta(minutes=60)
    assert manager.verify(token) is False
    assert manager.is_active is False


def test_ac3_system_clock_is_controllable_with_time_machine() -> None:
    with time_machine.travel(START, tick=False) as traveller:
        manager = SetupTokenManager(SystemClock(), timedelta(minutes=10))
        token = manager.issue()
        traveller.shift(timedelta(minutes=11))

        assert manager.verify(token) is False


def test_ac4_mark_completed_invalidates_token() -> None:
    manager = _manager()
    token = manager.issue()
    state = SetupState(manager)

    state.mark_completed()

    assert manager.verify(token) is False
    assert state.is_completed(lambda: None) is True  # type: ignore[arg-type, return-value]


def test_ac1_exempt_paths() -> None:
    assert is_setup_exempt("/setup")
    assert is_setup_exempt("/api/setup")
    assert is_setup_exempt("/api/health")
    assert is_setup_exempt("/static/style.css")
    assert not is_setup_exempt("/")
    assert not is_setup_exempt("/setup/other")
    assert not is_setup_exempt("/staticx")
    assert not is_setup_exempt("/api/findings")
