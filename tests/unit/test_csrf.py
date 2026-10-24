"""KAN-37: signiertes Double-Submit-Cookie für das Setup-Formular."""

from pydantic import SecretStr

from network_sniffer.config import Settings
from network_sniffer.security.csrf import CsrfProtection

KEY_MATERIAL = "k" * 40


def test_csrf_token_validates_when_cookie_and_field_match() -> None:
    csrf = CsrfProtection(b"\x01" * 32)
    token = csrf.issue()

    assert csrf.validate(token, token) is True


def test_csrf_rejects_mismatch_missing_and_unsigned_values() -> None:
    csrf = CsrfProtection(b"\x01" * 32)
    token, other = csrf.issue(), csrf.issue()

    assert csrf.validate(token, other) is False
    assert csrf.validate(None, token) is False
    assert csrf.validate(token, None) is False
    assert csrf.validate("a.b", "a.b") is False
    assert csrf.validate("ohne-punkt", "ohne-punkt") is False
    assert csrf.validate("ä.b", "ä.b") is False
    assert csrf.validate("ä.b", token) is False


def test_csrf_token_from_other_key_is_rejected() -> None:
    token = CsrfProtection(b"\x01" * 32).issue()

    assert CsrfProtection(b"\x02" * 32).validate(token, token) is False


def test_csrf_key_is_derived_from_secret_key_when_set() -> None:
    settings = Settings(_env_file=None, secret_key=SecretStr(KEY_MATERIAL))
    token = CsrfProtection.from_settings(settings).issue()

    # Gleicher NS_SECRET_KEY (z. B. nach Neustart) -> Token bleibt gültig.
    assert CsrfProtection.from_settings(settings).validate(token, token) is True


def test_csrf_key_is_random_per_process_without_secret_key() -> None:
    settings = Settings(_env_file=None)
    token = CsrfProtection.from_settings(settings).issue()

    assert CsrfProtection.from_settings(settings).validate(token, token) is False
