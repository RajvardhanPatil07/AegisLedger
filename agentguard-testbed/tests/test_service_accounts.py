from datetime import UTC, datetime, timedelta

import pytest

from aegisledger.auth import AuthenticationError, Permission, PrincipalKind
from aegisledger.service_accounts import MemoryServiceAccountStore, ServiceAccountManager


def manager(
    store: MemoryServiceAccountStore | None = None,
    *,
    organization_id: str = "acme",
    environment_id: str = "staging",
) -> ServiceAccountManager:
    return ServiceAccountManager(
        store or MemoryServiceAccountStore(),
        organization_id=organization_id,
        environment_id=environment_id,
    )


def test_issued_token_is_returned_once_while_only_its_digest_is_retained():
    accounts = manager()

    issued = accounts.issue(
        name="checkout-agent",
        subject="checkout-agent",
        permissions={Permission.PROPOSALS_READ, Permission.PROPOSALS_WRITE},
    )

    retained = accounts.store.get_by_key_id(issued.key_id)
    assert retained is not None
    assert issued.token.startswith("agsa_")
    assert issued.token not in repr(retained)
    assert retained.token_digest != issued.token
    assert len(retained.token_digest) == 64


def test_valid_token_maps_to_a_deployment_scoped_service_principal():
    accounts = manager()
    issued = accounts.issue(
        name="checkout-agent",
        subject="checkout-agent",
        permissions={Permission.PROPOSALS_WRITE},
    )

    principal = accounts.authenticate(issued.token)

    assert principal.subject == "checkout-agent"
    assert principal.kind is PrincipalKind.SERVICE
    assert principal.organization_id == "acme"
    assert principal.environment_id == "staging"
    assert principal.permissions == {Permission.PROPOSALS_WRITE}
    assert principal.roles == set()


@pytest.mark.parametrize("credential", ["not-a-service-token", "agsa_missing_parts"])
def test_malformed_tokens_fail_with_a_generic_authentication_error(credential: str):
    with pytest.raises(AuthenticationError, match="invalid service credential"):
        manager().authenticate(credential)


def test_wrong_expired_and_revoked_tokens_fail_closed():
    accounts = manager()
    issued = accounts.issue(
        name="checkout-agent",
        subject="checkout-agent",
        permissions={Permission.PROPOSALS_READ},
    )
    wrong_secret = issued.token[:-1] + ("A" if issued.token[-1] != "A" else "B")

    with pytest.raises(AuthenticationError, match="invalid service credential"):
        accounts.authenticate(wrong_secret)

    accounts.revoke(issued.credential_id)
    with pytest.raises(AuthenticationError, match="invalid service credential"):
        accounts.authenticate(issued.token)

    current_time = [datetime(2026, 1, 1, tzinfo=UTC)]
    expiring_accounts = ServiceAccountManager(
        MemoryServiceAccountStore(),
        organization_id="acme",
        environment_id="staging",
        clock=lambda: current_time[0],
    )
    expired = expiring_accounts.issue(
        name="expired-agent",
        subject="expired-agent",
        permissions={Permission.PROPOSALS_READ},
        expires_at=current_time[0] + timedelta(seconds=1),
    )
    current_time[0] += timedelta(seconds=2)
    with pytest.raises(AuthenticationError, match="invalid service credential"):
        expiring_accounts.authenticate(expired.token)


def test_credentials_cannot_cross_the_configured_deployment_scope():
    store = MemoryServiceAccountStore()
    acme = manager(store)
    other_environment = manager(store, organization_id="acme", environment_id="production")
    issued = acme.issue(
        name="checkout-agent",
        subject="checkout-agent",
        permissions={Permission.PROPOSALS_READ},
    )

    with pytest.raises(AuthenticationError, match="invalid service credential"):
        other_environment.authenticate(issued.token)
