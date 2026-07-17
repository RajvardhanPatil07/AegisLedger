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
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    service_name: str = "aegisledger-api"
    log_level: str = "INFO"
    otlp_endpoint: str | None = None
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
        return self
