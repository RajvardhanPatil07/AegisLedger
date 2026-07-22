import uuid

from aegisledger.auth import AuthenticationError, Permission
from aegisledger.cli import issue_service_credential, revoke_service_credential
from aegisledger.service_accounts import MemoryServiceAccountStore, ServiceAccountManager


def test_operator_helpers_issue_and_revoke_a_scoped_service_credential():
    manager = ServiceAccountManager(
        MemoryServiceAccountStore(),
        organization_id="acme",
        environment_id="staging",
    )

    payload = issue_service_credential(
        manager,
        name="checkout-agent",
        subject="researcher",
        permission_values=[Permission.PROPOSALS_READ.value],
        expires_in_days=30,
    )

    assert payload["token"].startswith("agsa_")
    assert payload["organization_id"] == "acme"
    assert payload["environment_id"] == "staging"
    assert payload["permissions"] == ["proposals:read"]
    assert payload["expires_at"] is not None
    principal = manager.authenticate(payload["token"])
    assert principal.permissions == {Permission.PROPOSALS_READ}

    revoked = revoke_service_credential(manager, uuid.UUID(payload["credential_id"]))

    assert revoked == {"credential_id": payload["credential_id"], "revoked": True}
    try:
        manager.authenticate(payload["token"])
    except AuthenticationError:
        pass
    else:
        raise AssertionError("revoked operator credential remained usable")
