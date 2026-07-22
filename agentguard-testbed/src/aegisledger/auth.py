"""OIDC authentication and centralized role vocabulary."""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Any

import jwt
from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    VIEWER = "viewer"
    RESEARCHER = "researcher"
    POLICY_ADMIN = "policy_admin"
    AUDITOR = "auditor"


class Permission(StrEnum):
    PROPOSALS_READ = "proposals:read"
    PROPOSALS_WRITE = "proposals:write"
    POLICIES_SIMULATE = "policies:simulate"
    ATTESTATIONS_VERIFY = "attestations:verify"


class PrincipalKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(min_length=1, max_length=256)
    roles: frozenset[Role]
    permissions: frozenset[Permission] = frozenset()
    kind: PrincipalKind = PrincipalKind.HUMAN
    organization_id: str = Field(default="local", min_length=1, max_length=128)
    environment_id: str = Field(default="development", min_length=1, max_length=128)


class OIDCConfigurationError(RuntimeError):
    pass


class AuthenticationError(PermissionError):
    pass


class OIDCAuthenticator:
    """Validate bearer JWTs against the configured issuer's JWKS endpoint."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        organization_id: str = "local",
        environment_id: str = "development",
    ) -> None:
        if not issuer.startswith("https://") and not issuer.startswith("http://localhost"):
            raise OIDCConfigurationError("OIDC issuer must use HTTPS outside localhost")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url
        self.organization_id = organization_id
        self.environment_id = environment_id
        self._jwks_client: jwt.PyJWKClient | None = None

    @classmethod
    def from_environment(
        cls,
        *,
        organization_id: str | None = None,
        environment_id: str | None = None,
    ) -> OIDCAuthenticator:
        required = {
            "issuer": os.getenv("AEGIS_OIDC_ISSUER"),
            "audience": os.getenv("AEGIS_OIDC_AUDIENCE"),
            "jwks_url": os.getenv("AEGIS_OIDC_JWKS_URL"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise OIDCConfigurationError(f"missing OIDC configuration: {', '.join(missing)}")
        issuer = required["issuer"]
        audience = required["audience"]
        jwks_url = required["jwks_url"]
        assert issuer is not None and audience is not None and jwks_url is not None
        resolved_organization = organization_id
        if resolved_organization is None:
            resolved_organization = os.getenv("AEGIS_ORGANIZATION_ID") or "local"
        resolved_environment = environment_id
        if resolved_environment is None:
            resolved_environment = (
                os.getenv("AEGIS_DEPLOYMENT_ENVIRONMENT_ID") or "development"
            )
        return cls(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            organization_id=resolved_organization,
            environment_id=resolved_environment,
        )

    def __call__(self, request: Request) -> Principal:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationError("bearer token required")
        try:
            if self._jwks_client is None:
                self._jwks_client = jwt.PyJWKClient(self.jwks_url)
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except Exception as exc:
            raise AuthenticationError("invalid bearer token") from exc

        raw_roles = set(claims.get("roles", []))
        raw_roles.update(claims.get("realm_access", {}).get("roles", []))
        roles = frozenset(Role(role) for role in raw_roles if role in {item.value for item in Role})
        return Principal(
            subject=claims["sub"],
            roles=roles,
            organization_id=self.organization_id,
            environment_id=self.environment_id,
        )
