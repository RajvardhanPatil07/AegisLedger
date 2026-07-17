"""Operator command line entrypoint."""

from __future__ import annotations

import argparse
import os


def _alembic_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


def migrate() -> None:
    from alembic import command
    from alembic.config import Config

    database_url = os.getenv("AEGIS_DATABASE_URL")
    if not database_url:
        raise RuntimeError("AEGIS_DATABASE_URL is required for migrations")
    configuration = Config("alembic.ini")
    configuration.set_main_option("sqlalchemy.url", _alembic_url(database_url))
    command.upgrade(configuration, "head")


def serve() -> None:
    import uvicorn

    from .settings import Settings

    settings = Settings()  # type: ignore[call-arg]
    uvicorn.run(
        "aegisledger.main:create_application",
        factory=True,
        host=settings.api_host,
        port=settings.api_port,
        access_log=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegisledger")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("serve", help="start the authenticated proposal gateway")
    subcommands.add_parser("migrate", help="apply database migrations")
    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve()
    else:
        migrate()
