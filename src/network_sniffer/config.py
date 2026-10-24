"""Konfiguration über Umgebungsvariablen mit Präfix ``NS_`` (pydantic-settings)."""

import ipaddress
import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_PORT = 8765
SERVICE_ENV_FILE_NAME = "network-sniffer.env"
SECRET_KEY_MIN_LENGTH = 32


class ConfigurationError(ValueError):
    """Konfiguration ist formal gültig, aber beim Start nicht verwendbar (z. B. fehlende Datei)."""


def default_data_dir() -> Path:
    """Windows: ``%ProgramData%\\network-sniffer``, sonst ``./data``."""
    if sys.platform == "win32":
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(program_data) / "network-sniffer"
    return Path("data")


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def format_host(host: str, port: int) -> str:
    """Host-Header-Form ``host:port`` (IPv6 in eckigen Klammern), kleingeschrieben."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}".lower()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: Path = Field(default_factory=default_data_dir)
    bind_host: str = "127.0.0.1"
    port: int = Field(default=DEFAULT_PORT, ge=1, le=65535)
    # Pflicht ab KAN-15 (Fingerabdrücke/Sitzungen); bis dahin optional.
    secret_key: SecretStr | None = None
    capture_source: Literal["npcap", "replay", "none"] = "npcap"
    tls_cert: Path | None = None
    tls_key: Path | None = None
    # Erlaubte Host-Header (Schutz vor DNS-Rebinding). None = Standard aus Host/Port.
    allowed_hosts: list[str] | None = None
    # Gültigkeit des Setup-Tokens der Ersteinrichtung (KAN-37); danach neues Token nur per Neustart.
    setup_token_ttl_minutes: int = Field(default=60, ge=1, le=1440)
    # Kostenparameter für Argon2id (Standard: RFC 9106, Profil wenig Speicher; Tests: niedrig).
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost_kib: int = Field(default=65536, ge=8)
    argon2_parallelism: int = Field(default=4, ge=1)

    @field_validator("secret_key", mode="before")
    @classmethod
    def _empty_secret_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and value.strip() == "":
            return None
        return value

    @field_validator("secret_key")
    @classmethod
    def _secret_key_min_length(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < SECRET_KEY_MIN_LENGTH:
            raise ValueError(
                f"NS_SECRET_KEY muss mindestens {SECRET_KEY_MIN_LENGTH} Zeichen lang sein"
            )
        return value

    @model_validator(mode="after")
    def _argon2_memory_fits_parallelism(self) -> "Settings":
        # Argon2 verlangt mindestens 8 KiB Speicher je Lane.
        if self.argon2_memory_cost_kib < 8 * self.argon2_parallelism:
            raise ValueError(
                "NS_ARGON2_MEMORY_COST_KIB muss mindestens 8 * NS_ARGON2_PARALLELISM sein"
            )
        return self

    @model_validator(mode="after")
    def _refuse_non_loopback_without_tls(self) -> "Settings":
        if not is_loopback_host(self.bind_host) and not (self.tls_cert and self.tls_key):
            raise ValueError(
                f"NS_BIND_HOST={self.bind_host} ist keine Loopback-Adresse. Eine Freigabe ins Netz "
                "ist nur mit NS_TLS_CERT und NS_TLS_KEY erlaubt - Start verweigert."
            )
        return self

    def tls_options(self) -> dict[str, str]:
        """Argumente ``ssl_certfile``/``ssl_keyfile`` für Uvicorn; leer, wenn kein TLS konfiguriert.

        Prüfung erst beim Start (nicht bei der Validierung): Dann müssen die Dateien existieren.
        """
        if self.tls_cert is None and self.tls_key is None:
            return {}
        if self.tls_cert is None or self.tls_key is None:
            raise ConfigurationError("NS_TLS_CERT und NS_TLS_KEY müssen gemeinsam gesetzt sein")
        for name, path in (("NS_TLS_CERT", self.tls_cert), ("NS_TLS_KEY", self.tls_key)):
            if not path.is_file():
                raise ConfigurationError(f"{name}: Datei {path} existiert nicht")
        return {"ssl_certfile": str(self.tls_cert), "ssl_keyfile": str(self.tls_key)}

    @property
    def effective_allowed_hosts(self) -> frozenset[str]:
        if self.allowed_hosts is not None:
            return frozenset(host.strip().lower() for host in self.allowed_hosts if host.strip())
        return frozenset(
            {
                format_host("127.0.0.1", self.port),
                format_host("localhost", self.port),
                format_host(self.bind_host, self.port),
            }
        )


def load_settings() -> Settings:
    """Lädt Settings aus Umgebung, ``.env`` und ``<NS_DATA_DIR>/network-sniffer.env``.

    Vorrang: Umgebungsvariablen > ``.env`` im Arbeitsverzeichnis > Datei im Datenverzeichnis.
    """
    settings = Settings()
    service_env = settings.data_dir / SERVICE_ENV_FILE_NAME
    if service_env.is_file():
        return Settings(_env_file=(service_env, ".env"))
    return settings
