"""Alembic-Umgebung - die Logik liegt in ``network_sniffer.storage.migration_env``."""

from alembic import context

from network_sniffer.storage.migration_env import run

run(context)
