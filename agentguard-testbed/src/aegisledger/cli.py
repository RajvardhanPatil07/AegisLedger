"""Operator command line entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import UTC, datetime, timedelta

from .auth import Permission
from .service_accounts import (
    PostgresServiceAccountStore,
    ServiceAccountManager,
)


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


def issue_service_credential(
    manager: ServiceAccountManager,
    *,
    name: str,
    subject: str,
    permission_values: list[str],
    expires_in_days: int,
) -> dict[str, object]:
    if not 1 <= expires_in_days <= 365:
        raise ValueError("service credential lifetime must be between 1 and 365 days")
    issued = manager.issue(
        name=name,
        subject=subject,
        permissions={Permission(value) for value in permission_values},
        expires_at=datetime.now(UTC) + timedelta(days=expires_in_days),
    )
    return {
        "credential_id": str(issued.credential_id),
        "name": issued.name,
        "subject": issued.subject,
        "organization_id": issued.organization_id,
        "environment_id": issued.environment_id,
        "permissions": [permission.value for permission in sorted(issued.permissions)],
        "expires_at": issued.expires_at.isoformat() if issued.expires_at is not None else None,
        "token": issued.token,
    }


def revoke_service_credential(
    manager: ServiceAccountManager,
    credential_id: uuid.UUID,
) -> dict[str, object]:
    manager.revoke(credential_id)
    return {"credential_id": str(credential_id), "revoked": True}


def _service_account_manager_from_environment() -> ServiceAccountManager:
    database_url = os.getenv("AEGIS_DATABASE_URL")
    if not database_url:
        raise RuntimeError("AEGIS_DATABASE_URL is required for service-account operations")
    return ServiceAccountManager(
        PostgresServiceAccountStore(database_url),
        organization_id=os.getenv("AEGIS_ORGANIZATION_ID", "local"),
        environment_id=os.getenv("AEGIS_DEPLOYMENT_ENVIRONMENT_ID", "development"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegisledger")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("serve", help="start the authenticated proposal gateway")
    subcommands.add_parser("migrate", help="apply database migrations")
    service_account = subcommands.add_parser(
        "service-account", help="manage deployment-scoped agent credentials"
    )
    service_commands = service_account.add_subparsers(dest="service_command", required=True)
    create = service_commands.add_parser("create", help="issue a credential and print it once")
    create.add_argument("--name", required=True)
    create.add_argument("--subject", required=True)
    create.add_argument(
        "--permission",
        dest="permissions",
        action="append",
        choices=[permission.value for permission in Permission],
        required=True,
    )
    create.add_argument("--expires-in-days", type=int, default=90)
    revoke = service_commands.add_parser("revoke", help="revoke one credential")
    revoke.add_argument("credential_id", type=uuid.UUID)
    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve()
    elif arguments.command == "migrate":
        migrate()
    else:
        manager = _service_account_manager_from_environment()
        if arguments.service_command == "create":
            result = issue_service_credential(
                manager,
                name=arguments.name,
                subject=arguments.subject,
                permission_values=arguments.permissions,
                expires_in_days=arguments.expires_in_days,
            )
        else:
            result = revoke_service_credential(manager, arguments.credential_id)
        print(json.dumps(result, sort_keys=True))
