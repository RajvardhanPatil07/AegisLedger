import os

import pytest

from aegisledger.auth import AuthenticationError, Permission
from aegisledger.service_accounts import PostgresServiceAccountStore, ServiceAccountManager

DATABASE_URL = os.getenv("AEGIS_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration is opt-in")


def test_postgres_credentials_survive_manager_restart_and_revoke_durably():
    assert DATABASE_URL is not None
    store = PostgresServiceAccountStore(DATABASE_URL)
    first_manager = ServiceAccountManager(
        store,
        organization_id="integration",
        environment_id="test",
    )
    issued = first_manager.issue(
        name="postgres-agent",
        subject="postgres-agent",
        permissions={Permission.PROPOSALS_READ},
    )
    try:
        restarted_manager = ServiceAccountManager(
            PostgresServiceAccountStore(DATABASE_URL),
            organization_id="integration",
            environment_id="test",
        )

        principal = restarted_manager.authenticate(issued.token)

        assert principal.subject == "postgres-agent"
        assert principal.permissions == {Permission.PROPOSALS_READ}
        restarted_manager.revoke(issued.credential_id)
        with pytest.raises(AuthenticationError, match="invalid service credential"):
            first_manager.authenticate(issued.token)
    finally:
        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute(
                "DELETE FROM service_account_credentials WHERE credential_id=%s",
                (issued.credential_id,),
            )
