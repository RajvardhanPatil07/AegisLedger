"""OIDC authentication and centralized role vocabulary."""
from __future__ import annotations

import os
from enum import Enum
from typing import Any

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field


class Role(str, Enum):
    VIEWER = "viewer"
    RESEARCHER = "researcher"
    POLICY_ADMIN = "policy_admin"
    AUDITOR = "auditor"


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(min_length=1, max_length=256)
    roles: frozenset[Role]


class OIDCConfigurationError(RuntimeError):
    pass


class AuthenticationError(PermissionError):
    pass


class OIDCAuthenticator:
    """Validate bearer JWTs against the configured issuer's JWKS endpoint."""

    def __init__(self, *, issuer: str, audience: str, jwks_url: str) -> None:
        if not issuer.startswith("https://") and not issuer.startswith("http://localhost"):
            raise OIDCConfigurationError("OIDC issuer must use HTTPS outside localhost")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url
        self._jwks_client = None

    @classmethod
    def from_environment(cls) -> "OIDCAuthenticator":
        required = {
            "issuer": os.getenv("AEGIS_OIDC_ISSUER"),
            "audience": os.getenv("AEGIS_OIDC_AUDIENCE"),
            "jwks_url": os.getenv("AEGIS_OIDC_JWKS_URL"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise OIDCConfigurationError(f"missing OIDC configuration: {', '.join(missing)}")
        return cls(**required)  # type: ignore[arg-type]

    def __call__(self, request: Request) -> Principal:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationError("bearer token required")
        try:
            import jwt

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
        return Principal(subject=claims["sub"], roles=roles)

