"""Validated runtime configuration loaded exclusively from environment variables."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    state_backend: Literal["memory", "postgres"] = "postgres"
    database_url: str | None = None
    policy_signing_seed: SecretStr
    policy_decision_lifetime_seconds: int = Field(default=30, gt=0, le=300)
    bootstrap_development_policy: bool = False
    development_policy_path: Path = Path("configs/policy.dev.json")
    allowed_build_measurements: Annotated[tuple[str, ...], NoDecode] = (
        "development-unmeasured",
    )
    experiment_output_root: Path = Path("artifacts/experiments")
    experiment_max_active_per_principal: int = Field(default=2, gt=0, le=32)
    rate_limit_requests: int = Field(default=120, gt=0, le=100_000)
    rate_limit_window_seconds: int = Field(default=60, gt=0, le=3_600)
    request_max_bytes: int = Field(default=1_000_000, gt=0, le=10_000_000)
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    service_name: str = "aegisledger-api"
    log_level: str = "INFO"
    otlp_endpoint: str | None = None
    signer_target: str | None = None
    signer_ca_path: Path | None = None
    signer_client_certificate_path: Path | None = None
    signer_client_private_key_path: Path | None = None
    signer_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    rpc_url: str | None = None
    rpc_chain_id: int = Field(default=31337, gt=0)
    rpc_authorization_header: SecretStr | None = None
    rpc_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    finality_confirmations: int = Field(default=2, gt=0, le=1_000)
    eip712_domain_separator: str = Field(default="0x" + "00" * 32, pattern=r"^0x[0-9a-f]{64}$")
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, gt=0, le=65535)

    @field_validator("allowed_build_measurements", mode="before")
    @classmethod
    def parse_measurements(cls, value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        if isinstance(value, (list, tuple)):
            return tuple(value)
        raise TypeError("allowed build measurements must be a CSV string or array")

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("unsupported log level")
        return normalized

    @model_validator(mode="after")
    def durable_production_state(self) -> Settings:
        if self.state_backend == "postgres" and not self.database_url:
            raise ValueError("postgres state requires AEGIS_DATABASE_URL")
        if self.environment == "production":
            if self.state_backend != "postgres":
                raise ValueError("production requires postgres state")
            if self.bootstrap_development_policy:
                raise ValueError("development policy bootstrap is forbidden in production")
            if not self.rpc_url:
                raise ValueError("production requires AEGIS_RPC_URL")
            if not self.signer_target:
                raise ValueError("production requires AEGIS_SIGNER_TARGET")
        signer_tls = (
            self.signer_ca_path,
            self.signer_client_certificate_path,
            self.signer_client_private_key_path,
        )
        if self.signer_target and any(value is None for value in signer_tls):
            raise ValueError("configured signer requires CA, client certificate, and private key")
        if not self.signer_target and any(value is not None for value in signer_tls):
            raise ValueError("signer TLS paths require AEGIS_SIGNER_TARGET")
        return self
