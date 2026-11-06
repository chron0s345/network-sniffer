"""Kommandozeile: ``network-sniffer [serve | create-admin --username <name>] [--version]``."""

import argparse
import getpass
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

import uvicorn
from pydantic import ValidationError
from sqlalchemy.orm import Session

from network_sniffer import __version__
from network_sniffer.clock import SystemClock
from network_sniffer.config import ConfigurationError, Settings, load_settings
from network_sniffer.logging_config import build_log_config
from network_sniffer.main import create_app
from network_sniffer.security.passwords import PasswordPolicyError, Passwords
from network_sniffer.services.users import (
    SetupAlreadyCompletedError,
    UsernameError,
    create_initial_admin,
    users_exist,
)
from network_sniffer.storage.db import create_db_engine, run_migrations

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_CONFIGURATION = 2

ALREADY_SET_UP_MESSAGE = (
    "Es existiert bereits ein Benutzer - create-admin ist nur bei der Ersteinrichtung möglich."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-sniffer",
        description="Defensive Data-Leak-Erkennung im Netzwerkverkehr des eigenen PCs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("serve", help="Dashboard und API starten (Standard)")
    create_admin = subparsers.add_parser(
        "create-admin",
        help="Ersten Administrator anlegen (nur solange kein Benutzer existiert)",
        description=(
            "Legt den ersten Administrator an. Das Passwort wird interaktiv abgefragt oder mit "
            "--password-stdin aus der Standardeingabe gelesen - nie als Argument."
        ),
    )
    create_admin.add_argument("--username", required=True, help="Benutzername des Admins")
    create_admin.add_argument(
        "--password-stdin",
        action="store_true",
        help="Passwort aus der ersten Zeile der Standardeingabe lesen (für Skripte)",
    )
    return parser


def format_validation_error(exc: ValidationError) -> str:
    lines = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"])
        prefix = f"NS_{location.upper()}: " if location else ""
        lines.append(f"  - {prefix}{error['msg']}")
    return "\n".join(lines)


def _report_configuration_error(details: str) -> int:
    print(f"Konfigurationsfehler, Start abgebrochen:\n{details}", file=sys.stderr)
    return EXIT_CONFIGURATION


def _load_settings_or_report() -> Settings | int:
    try:
        return load_settings()
    except ValidationError as exc:
        return _report_configuration_error(format_validation_error(exc))


def serve() -> int:
    settings = _load_settings_or_report()
    if isinstance(settings, int):
        return settings
    try:
        tls_options = settings.tls_options()
    except ConfigurationError as exc:
        return _report_configuration_error(f"  - {exc}")
    uvicorn.run(
        create_app(settings),
        host=settings.bind_host,
        port=settings.port,
        log_config=build_log_config(),
        proxy_headers=False,
        server_header=False,
        # Setup-Token und Sitzungszustand sind prozesslokal: genau ein Worker.
        workers=1,
        **tls_options,
    )
    return EXIT_OK


def read_password(
    from_stdin: bool,
    stdin: TextIO | None = None,
    prompt: Callable[[str], str] | None = None,
) -> str | None:
    """Passwort aus stdin (erste Zeile) oder interaktiv mit Wiederholung.

    ``None``, wenn die interaktiven Eingaben voneinander abweichen.
    """
    if from_stdin:
        return (stdin or sys.stdin).readline().rstrip("\r\n")
    prompt = prompt or getpass.getpass
    password = prompt("Passwort: ")
    if password != prompt("Passwort wiederholen: "):
        return None
    return password


def create_admin(
    username: str,
    password_stdin: bool,
    prompt: Callable[[str], str] | None = None,
) -> int:
    settings = _load_settings_or_report()
    if isinstance(settings, int):
        return settings
    engine = create_db_engine(settings)
    try:
        run_migrations(engine)
        with Session(engine) as session:
            if users_exist(session):
                print(ALREADY_SET_UP_MESSAGE, file=sys.stderr)
                return EXIT_FAILURE
            password = read_password(password_stdin, prompt=prompt)
            if password is None:
                print("Passwörter stimmen nicht überein.", file=sys.stderr)
                return EXIT_FAILURE
            try:
                user = create_initial_admin(
                    session,
                    username=username,
                    password=password,
                    passwords=Passwords.from_settings(settings),
                    clock=SystemClock(),
                )
            except (UsernameError, PasswordPolicyError) as exc:
                print(str(exc), file=sys.stderr)
                return EXIT_FAILURE
            except SetupAlreadyCompletedError:
                print(ALREADY_SET_UP_MESSAGE, file=sys.stderr)
                return EXIT_FAILURE
    finally:
        engine.dispose()
    print(f"Administrator {user.username!r} angelegt.")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "create-admin":
        return create_admin(args.username, args.password_stdin)
    # Standardbefehl ist "serve" (auch ohne Angabe).
    return serve()


if __name__ == "__main__":
    sys.exit(main())
